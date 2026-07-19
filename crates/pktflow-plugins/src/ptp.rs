//! PTP (IEEE 1588-2008 "PTPv2"): precision time synchronization — the
//! protocol that keeps data-center clocks aligned to sub-microsecond
//! error for distributed databases, market feeds, and telemetry. One
//! plugin covers both encapsulations: UDP 319 (event messages) / 320
//! (general messages) per Annex D, and raw Ethernet under EtherType
//! 0x88F7 per Annex F — same 34-byte common header either way (§13.3).
//!
//! Only the common header is decoded; the message-type-specific body
//! (origin timestamps, announce fields) is walked via the header's own
//! `messageLength` so `header_len` covers the whole PTP message without
//! decoding per-type layouts. Trailing bytes beyond `messageLength`
//! (Ethernet minimum-frame padding) stay untouched.
//!
//! Stream identity keys on the clock domain (§7.1), the shared-qualifier
//! group shape VRRP's `vrid` established (11.4): all masters and slaves
//! of one domain form one logical timing conversation, and the
//! `msg_type` rollup accumulates the Sync/Follow_Up/Delay_Req/Announce
//! mix that shows whether a domain is actually exchanging time or just
//! announcing.

use pktflow_core::{
    ByteReader, Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx,
    ParseError, ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId, StreamIdentity, Value,
};

const DOMAIN: FieldName = "domain";
const MSG_TYPE: FieldName = "msg_type";
const VERSION: FieldName = "version";
const SEQUENCE_ID: FieldName = "sequence_id";
const CLOCK_IDENTITY: FieldName = "clock_identity";
const SOURCE_PORT_ID: FieldName = "source_port_id";
const MESSAGE_LENGTH: FieldName = "message_length";
const FLAGS: FieldName = "flags";
const CORRECTION: FieldName = "correction";
const LOG_MESSAGE_INTERVAL: FieldName = "log_message_interval";

/// IEEE 1588-2008 §13.3.1: the fixed common header size.
const COMMON_HEADER_LEN: usize = 34;

/// §13.3.2.2: message types 4–7 and 14–15 are reserved in v2.
fn message_type_defined(msg_type: u8) -> bool {
    matches!(msg_type, 0..=3 | 8..=13)
}

static KEY: &[KeyField] = &[KeyField {
    a: DOMAIN,
    b: None, // shared qualifier: one stream per clock domain
}];
static ROLLUPS: &[RollupSpec] = &[RollupSpec {
    field: MSG_TYPE,
    kind: RollupKind::Accumulate,
}];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: ROLLUPS,
};

pub struct Ptp;

impl LayerPlugin for Ptp {
    fn name(&self) -> ProtocolName {
        "ptp"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let transport_type = r.u8()?;
        let msg_type = transport_type & 0x0F;
        if !message_type_defined(msg_type) {
            return Err(ParseError::Malformed("PTP: reserved message type"));
        }
        let version = r.u8()? & 0x0F;
        if version != 2 {
            return Err(ParseError::Malformed("PTP: version is not 2"));
        }
        let message_length = usize::from(r.u16_be()?);
        if message_length < COMMON_HEADER_LEN {
            return Err(ParseError::Malformed("PTP: length below common header"));
        }
        let domain = r.u8()?;
        let _reserved = r.u8()?;
        let flags = r.u16_be()?;
        let correction = r.u64_be()?;
        let _reserved2 = r.u32_be()?;
        let clock_identity = r.take(8)?;
        let source_port_id = r.u16_be()?;
        let sequence_id = r.u16_be()?;
        let _control = r.u8()?;
        let log_message_interval = r.u8()? as i8;
        // Message-type-specific body, covered by messageLength (module doc).
        r.take(message_length - COMMON_HEADER_LEN)?;

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(DOMAIN, Value::U64(u64::from(domain)));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(MSG_TYPE, Value::U64(u64::from(msg_type)));
            fields.insert(VERSION, Value::U64(u64::from(version)));
            fields.insert(SEQUENCE_ID, Value::U64(u64::from(sequence_id)));
            fields.insert(CLOCK_IDENTITY, Value::from(clock_identity));
        }
        if ctx.depth() >= Depth::Full {
            fields.insert(SOURCE_PORT_ID, Value::U64(u64::from(source_port_id)));
            fields.insert(MESSAGE_LENGTH, Value::U64(message_length as u64));
            fields.insert(FLAGS, Value::U64(u64::from(flags)));
            fields.insert(CORRECTION, Value::U64(correction));
            fields.insert(
                LOG_MESSAGE_INTERVAL,
                Value::I64(i64::from(log_message_interval)),
            );
        }

        Ok(ParsedLayer {
            header_len: message_length,
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[
            RouteId::UdpPort(319),      // Annex D event messages
            RouteId::UdpPort(320),      // Annex D general messages
            RouteId::EtherType(0x88F7), // Annex F raw Ethernet
        ]
    }

    fn stream_identity(&self) -> Option<&StreamIdentity> {
        Some(&IDENTITY)
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use pktflow_core::{LinkType, PacketMeta};

    use super::*;

    fn parse(bytes: &[u8]) -> Result<ParsedLayer, ParseError> {
        let meta = PacketMeta {
            timestamp: SystemTime::UNIX_EPOCH,
            caplen: bytes.len(),
            origlen: bytes.len(),
            link_type: LinkType::ETHERNET,
        };
        Ptp.parse(bytes, &ParseCtx::new(&[], Depth::Full, &meta))
    }

    /// §13.3 common header plus a `body_len`-byte type-specific body,
    /// with `messageLength` covering both.
    fn message(msg_type: u8, domain: u8, sequence_id: u16, body_len: usize) -> Vec<u8> {
        let total = COMMON_HEADER_LEN + body_len;
        let mut b = vec![msg_type, 0x02];
        b.extend_from_slice(&(total as u16).to_be_bytes());
        b.push(domain);
        b.push(0); // reserved
        b.extend_from_slice(&0x0200u16.to_be_bytes()); // flags: twoStepFlag
        b.extend_from_slice(&0u64.to_be_bytes()); // correction
        b.extend_from_slice(&0u32.to_be_bytes()); // reserved
        b.extend_from_slice(&[0x00, 0x1B, 0x19, 0xFF, 0xFE, 0x00, 0x01, 0x02]); // clock id
        b.extend_from_slice(&1u16.to_be_bytes()); // source port id
        b.extend_from_slice(&sequence_id.to_be_bytes());
        b.push(0); // control (Sync)
        b.push(0xFF); // logMessageInterval -1
        b.extend(std::iter::repeat_n(0u8, body_len));
        b
    }

    #[test]
    fn sync_message_parses_exactly() {
        // Sync (type 0) in domain 0 with its 10-byte originTimestamp body.
        let bytes = message(0, 0, 0x1234, 10);
        let parsed = parse(&bytes).expect("valid Sync");
        assert_eq!(parsed.header_len, 44);
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(DOMAIN), Some(&Value::U64(0)));
        assert_eq!(parsed.fields.get(MSG_TYPE), Some(&Value::U64(0)));
        assert_eq!(parsed.fields.get(VERSION), Some(&Value::U64(2)));
        assert_eq!(parsed.fields.get(SEQUENCE_ID), Some(&Value::U64(0x1234)));
        assert_eq!(
            parsed.fields.get(CLOCK_IDENTITY),
            Some(&Value::from(
                &[0x00, 0x1B, 0x19, 0xFF, 0xFE, 0x00, 0x01, 0x02][..]
            ))
        );
        assert_eq!(
            parsed.fields.get(LOG_MESSAGE_INTERVAL),
            Some(&Value::I64(-1))
        );
    }

    #[test]
    fn transport_specific_nibble_is_ignored_for_the_type() {
        // 802.1AS sets transportSpecific = 1; the type nibble still reads.
        let mut bytes = message(11, 5, 7, 0); // Announce, no body
        bytes[0] = 0x10 | 11;
        let parsed = parse(&bytes).expect("gPTP-flavored Announce");
        assert_eq!(parsed.fields.get(MSG_TYPE), Some(&Value::U64(11)));
        assert_eq!(parsed.fields.get(DOMAIN), Some(&Value::U64(5)));
    }

    #[test]
    fn ethernet_padding_beyond_message_length_stays_unread() {
        let mut bytes = message(1, 0, 1, 10); // Delay_Req
        bytes.extend_from_slice(&[0u8; 18]); // min-frame padding
        let parsed = parse(&bytes).expect("padded Delay_Req");
        assert_eq!(parsed.header_len, 44);
    }

    #[test]
    fn version_one_declines() {
        let mut bytes = message(0, 0, 1, 10);
        bytes[1] = 0x01;
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn reserved_message_type_declines() {
        let mut bytes = message(0, 0, 1, 10);
        bytes[0] = 0x04; // reserved in v2
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn undersized_message_length_declines() {
        let mut bytes = message(0, 0, 1, 0);
        bytes[2..4].copy_from_slice(&33u16.to_be_bytes());
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn truncated_messages_decline() {
        let bytes = message(0, 0, 1, 10);
        for n in 0..bytes.len() {
            assert!(parse(&bytes[..n]).is_err(), "prefix of {n} bytes");
        }
    }
}
