//! RTCP (11.10, RFC 3550 — same document as `rtp`): sender/receiver
//! reports, source description, bye. Same reachability stance as `rtp`
//! (D15 in full, see that module's doc) — no `claims()`, no `probe()`,
//! fixture-tested by feeding bytes directly to `parse()`.
//!
//! **First-packet-only, the same D7 stance `bgp`/`sctp`/DNS-over-TCP take
//! (06.6/11.6).** A UDP payload typically carries a *compound* RTCP
//! packet — several individual RTCP packets concatenated back to back
//! (§6.1 mandates at least SR/RR followed by SDES in every compound
//! packet sent). This plugin parses exactly the first one and reports
//! `header_len` as that packet's own self-describing `length` field, the
//! same "walk one message, name where it ends" honesty as everywhere
//! else in this task — it does not attempt to enumerate the rest of the
//! compound packet.
//!
//! ## Common header (RFC 3550 §6.4.1, §6.5)
//!
//! `V(2) | P(1) | RC/SC(5)` then `PacketType(1)` then `Length(2)` — the
//! packet's length in 32-bit words minus one, i.e. `(length + 1) * 4`
//! total octets. Every recognized packet type (SR/RR/SDES/BYE/APP) places
//! an SSRC (SR/RR/BYE/APP) or the first chunk's SSRC/CSRC (SDES) in the
//! four octets immediately following this 4-octet header — this plugin
//! reads that uniformly regardless of type. Recognized types are exactly
//! the domain spec's Tier-1 set (200-204); RTPFB/PSFB/XR (205-207) are a
//! Tier-2 extension, declined the same honest way an unrecognized method
//! declines elsewhere in this task.

use pktflow_core::{
    ByteReader, Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx,
    ParseError, ParsedLayer, ProtocolName, RollupKind, RollupSpec, StreamIdentity, Truncated,
    Value,
};

const SSRC: FieldName = "ssrc";
const PACKET_TYPE: FieldName = "packet_type";
const NTP_TIMESTAMP: FieldName = "ntp_timestamp";
const RTP_TIMESTAMP: FieldName = "rtp_timestamp";
const PACKET_COUNT: FieldName = "packet_count";
const OCTET_COUNT: FieldName = "octet_count";
const CNAME: FieldName = "cname";

const VERSION_MASK: u8 = 0xC0;
const VERSION_SHIFT: u32 = 6;
const RTCP_VERSION: u8 = 2;

const PT_SR: u8 = 200;
const PT_RR: u8 = 201;
const PT_SDES: u8 = 202;
const PT_BYE: u8 = 203;
const PT_APP: u8 = 204;

/// TS/RFC 3550 §6.5's SDES item type 1: CNAME.
const SDES_ITEM_CNAME: u8 = 1;
/// §6.5: a zero item type ends a chunk's item list.
const SDES_ITEM_END: u8 = 0;

static KEY: &[KeyField] = &[KeyField {
    a: SSRC,
    b: None, // shared (non-endpoint) qualifier, the rtp precedent
}];
static ROLLUPS: &[RollupSpec] = &[RollupSpec {
    field: PACKET_TYPE,
    kind: RollupKind::Accumulate,
}];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: ROLLUPS,
};

/// Walks a SDES chunk's items (§6.5) looking for `CNAME`, bounded strictly
/// to `region` (already sliced to this packet's own `header_len`).
fn find_cname(region: &[u8]) -> Option<String> {
    let mut r = ByteReader::new(region);
    loop {
        let ty = r.u8().ok()?;
        if ty == SDES_ITEM_END {
            return None;
        }
        let len = r.u8().ok()?;
        let value = r.take(usize::from(len)).ok()?;
        if ty == SDES_ITEM_CNAME {
            return Some(String::from_utf8_lossy(value).into_owned());
        }
    }
}

pub struct Rtcp;

impl LayerPlugin for Rtcp {
    fn name(&self) -> ProtocolName {
        "rtcp"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let b0 = r.u8()?;
        let version = (b0 & VERSION_MASK) >> VERSION_SHIFT;
        if version != RTCP_VERSION {
            return Err(ParseError::Malformed("RTCP: unsupported version"));
        }
        let packet_type = r.u8()?;
        if !matches!(packet_type, PT_SR | PT_RR | PT_SDES | PT_BYE | PT_APP) {
            return Err(ParseError::Malformed("RTCP: unrecognized packet type"));
        }
        let length_words = r.u16_be()?;
        let header_len = (usize::from(length_words) + 1) * 4;
        if bytes.len() < header_len {
            return Err(ParseError::Truncated(Truncated {
                needed: header_len,
                have: bytes.len(),
            }));
        }
        let ssrc = r.u32_be()?;

        let mut ntp_timestamp = None;
        let mut rtp_timestamp = None;
        let mut packet_count = None;
        let mut octet_count = None;
        let mut cname = None;
        match packet_type {
            PT_SR => {
                let ntp_msw = r.u32_be()?;
                let ntp_lsw = r.u32_be()?;
                ntp_timestamp = Some((u64::from(ntp_msw) << 32) | u64::from(ntp_lsw));
                rtp_timestamp = Some(r.u32_be()?);
                packet_count = Some(r.u32_be()?);
                octet_count = Some(r.u32_be()?);
            }
            PT_SDES => {
                // Bounded strictly to this packet's own header_len: never
                // reads into a sibling packet in the compound blob.
                let consumed = bytes.len() - r.remaining();
                cname = find_cname(&bytes[consumed..header_len]);
            }
            _ => {}
        }

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(SSRC, Value::U64(u64::from(ssrc)));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(PACKET_TYPE, Value::U64(u64::from(packet_type)));
        }
        if ctx.depth() >= Depth::Full {
            if let Some(v) = ntp_timestamp {
                fields.insert(NTP_TIMESTAMP, Value::U64(v));
            }
            if let Some(v) = rtp_timestamp {
                fields.insert(RTP_TIMESTAMP, Value::U64(u64::from(v)));
            }
            if let Some(v) = packet_count {
                fields.insert(PACKET_COUNT, Value::U64(u64::from(v)));
            }
            if let Some(v) = octet_count {
                fields.insert(OCTET_COUNT, Value::U64(u64::from(v)));
            }
            if let Some(v) = cname {
                fields.insert(CNAME, Value::from(v.as_str()));
            }
        }

        Ok(ParsedLayer {
            header_len,
            fields,
            hint: Hint::Terminal,
        })
    }

    // No claims(), no probe(): see module doc (D15).

    fn stream_identity(&self) -> Option<&StreamIdentity> {
        Some(&IDENTITY)
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use pktflow_core::{LinkType, PacketMeta};

    use super::*;

    fn meta(len: usize) -> PacketMeta {
        PacketMeta {
            timestamp: SystemTime::UNIX_EPOCH,
            caplen: len,
            origlen: len,
            link_type: LinkType::ETHERNET,
        }
    }

    fn ctx<'a>(depth: Depth, m: &'a PacketMeta) -> ParseCtx<'a> {
        ParseCtx::new(&[], depth, m)
    }

    fn parse_at(bytes: &[u8], depth: Depth) -> Result<ParsedLayer, ParseError> {
        let m = meta(bytes.len());
        Rtcp.parse(bytes, &ctx(depth, &m))
    }

    fn parse(bytes: &[u8]) -> Result<ParsedLayer, ParseError> {
        parse_at(bytes, Depth::Full)
    }

    /// A Sender Report (§6.4.1): SSRC, NTP/RTP timestamps, packet/octet
    /// counts, RC=0 (no report blocks).
    fn sender_report(ssrc: u32) -> Vec<u8> {
        let mut b = vec![0x80, PT_SR];
        b.extend_from_slice(&6u16.to_be_bytes()); // length: 7 words - 1
        b.extend_from_slice(&ssrc.to_be_bytes());
        b.extend_from_slice(&0x1234_5678u32.to_be_bytes()); // NTP MSW
        b.extend_from_slice(&0x9ABC_DEF0u32.to_be_bytes()); // NTP LSW
        b.extend_from_slice(&0x1111_2222u32.to_be_bytes()); // RTP timestamp
        b.extend_from_slice(&100u32.to_be_bytes()); // packet count
        b.extend_from_slice(&20000u32.to_be_bytes()); // octet count
        b
    }

    /// SDES (§6.5) with one chunk carrying a CNAME item, null-padded to a
    /// 32-bit boundary.
    fn sdes(ssrc: u32, cname: &str) -> Vec<u8> {
        let mut chunk = Vec::new();
        chunk.extend_from_slice(&ssrc.to_be_bytes());
        chunk.push(SDES_ITEM_CNAME);
        chunk.push(cname.len() as u8);
        chunk.extend_from_slice(cname.as_bytes());
        chunk.push(SDES_ITEM_END);
        while chunk.len() % 4 != 0 {
            chunk.push(0);
        }

        let mut b = vec![0x81, PT_SDES]; // RC(SC)=1
        b.extend_from_slice(&((chunk.len() / 4) as u16).to_be_bytes());
        b.extend_from_slice(&chunk);
        b
    }

    fn bye(ssrc: u32) -> Vec<u8> {
        let mut b = vec![0x81, PT_BYE]; // SC=1
        b.extend_from_slice(&1u16.to_be_bytes());
        b.extend_from_slice(&ssrc.to_be_bytes());
        b
    }

    #[test]
    fn sender_report_reports_all_sr_fields() {
        let bytes = sender_report(0x1234_5678);
        let parsed = parse(&bytes).expect("valid SR");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(SSRC), Some(&Value::U64(0x1234_5678)));
        assert_eq!(parsed.fields.get(PACKET_TYPE), Some(&Value::U64(200)));
        assert_eq!(
            parsed.fields.get(NTP_TIMESTAMP),
            Some(&Value::U64(0x1234_5678_9ABC_DEF0))
        );
        assert_eq!(
            parsed.fields.get(RTP_TIMESTAMP),
            Some(&Value::U64(0x1111_2222))
        );
        assert_eq!(parsed.fields.get(PACKET_COUNT), Some(&Value::U64(100)));
        assert_eq!(parsed.fields.get(OCTET_COUNT), Some(&Value::U64(20000)));
    }

    #[test]
    fn sdes_reports_cname() {
        let bytes = sdes(0xAABBCCDD, "alice@example.com");
        let parsed = parse(&bytes).expect("valid SDES");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.fields.get(PACKET_TYPE), Some(&Value::U64(202)));
        assert_eq!(
            parsed.fields.get(CNAME),
            Some(&Value::from("alice@example.com"))
        );
    }

    #[test]
    fn bye_has_no_full_fields_beyond_ssrc_and_type() {
        let bytes = bye(0x42);
        let parsed = parse(&bytes).expect("valid BYE");
        assert_eq!(parsed.fields.get(PACKET_TYPE), Some(&Value::U64(203)));
        assert_eq!(parsed.fields.get(NTP_TIMESTAMP), None);
        assert_eq!(parsed.fields.get(CNAME), None);
    }

    #[test]
    fn only_the_first_packet_of_a_compound_blob_is_parsed() {
        let mut compound = sender_report(1);
        compound.extend_from_slice(&sdes(1, "bob@example.com"));
        let parsed = parse(&compound).expect("valid compound RTCP blob");
        assert_eq!(parsed.header_len, sender_report(1).len());
        assert_eq!(parsed.fields.get(PACKET_TYPE), Some(&Value::U64(200)));
    }

    #[test]
    fn unrecognized_packet_type_declines() {
        let mut bytes = sender_report(1);
        bytes[1] = 205; // RTPFB, out of Tier-1 scope
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn wrong_version_declines() {
        let mut bytes = sender_report(1);
        bytes[0] = 0x40; // version 1
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn truncated_header_declines() {
        let bytes = sender_report(1);
        assert!(parse(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn length_field_exceeding_available_bytes_declines() {
        let mut bytes = sender_report(1);
        bytes[2..4].copy_from_slice(&50u16.to_be_bytes());
        assert!(matches!(parse(&bytes), Err(ParseError::Truncated(_))));
    }

    #[test]
    fn keys_depth_has_only_ssrc() {
        let bytes = sender_report(42);
        let parsed = parse_at(&bytes, Depth::Keys).expect("valid header");
        assert_eq!(parsed.fields.len(), 1);
        assert_eq!(parsed.fields.get(SSRC), Some(&Value::U64(42)));
    }

    #[test]
    fn structural_depth_omits_sr_fields() {
        let bytes = sender_report(42);
        let parsed = parse_at(&bytes, Depth::Structural).expect("valid header");
        assert_eq!(parsed.fields.get(NTP_TIMESTAMP), None);
        assert_eq!(parsed.fields.get(PACKET_TYPE), Some(&Value::U64(200)));
    }
}
