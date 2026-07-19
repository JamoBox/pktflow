//! BFD (RFC 5880/5881): Bidirectional Forwarding Detection — the
//! sub-second liveness protocol running underneath BGP/OSPF adjacencies in
//! leaf-spine fabrics. Control packets only: single-hop sessions on UDP
//! 3784 and multihop on UDP 4784 (RFC 5883). The echo port (3785) is
//! deliberately unclaimed — RFC 5880 §5 leaves the echo payload format
//! entirely up to the sender, so there is no header to parse there.
//!
//! A session is identified by its discriminator pair (§6.3): My
//! Discriminator is chosen locally, Your Discriminator echoes the peer's,
//! and the two swap roles per direction — exactly the endpoint-pair shape
//! `EndpointSort` canonicalizes, so both directions of a session fold into
//! one stream the same way TCP's port pair does. Early Down packets carry
//! Your Discriminator = 0 until the session learns its peer (§6.8.6);
//! those key as `{0, my_disc}`, which is correct — that *is* the
//! bring-up conversation.
//!
//! The `state` rollup accumulates the AdminDown/Down/Init/Up transitions
//! per stream: a session flapping between Up and Down is the exact signal
//! a fabric operator is looking for.
//!
//! `length` (§4.1) covers the whole control packet including the optional
//! authentication section (present when the A bit is set); the auth bytes
//! are walked for `header_len` honesty but not decoded — same stance
//! `esp` takes on its trailer.

use pktflow_core::{
    ByteReader, Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx,
    ParseError, ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId, StreamIdentity, Value,
};

const MY_DISCRIMINATOR: FieldName = "my_discriminator";
const YOUR_DISCRIMINATOR: FieldName = "your_discriminator";
const VERSION: FieldName = "version";
const DIAG: FieldName = "diag";
const STATE: FieldName = "state";
const FLAGS: FieldName = "flags";
const DETECT_MULT: FieldName = "detect_mult";
const LENGTH: FieldName = "length";
const DESIRED_MIN_TX: FieldName = "desired_min_tx";
const REQUIRED_MIN_RX: FieldName = "required_min_rx";
const REQUIRED_MIN_ECHO_RX: FieldName = "required_min_echo_rx";

/// RFC 5880 §4.1: mandatory section size; `length` may exceed it only for
/// the authentication section.
const MANDATORY_LEN: usize = 24;
/// A (Authentication Present) bit within the 6 flag bits.
const A_BIT: u8 = 0x04;

static KEY: &[KeyField] = &[KeyField {
    a: MY_DISCRIMINATOR,
    b: Some(YOUR_DISCRIMINATOR),
}];
static ROLLUPS: &[RollupSpec] = &[RollupSpec {
    field: STATE,
    kind: RollupKind::Accumulate,
}];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: ROLLUPS,
};

pub struct Bfd;

impl LayerPlugin for Bfd {
    fn name(&self) -> ProtocolName {
        "bfd"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let vers_diag = r.u8()?;
        let version = vers_diag >> 5;
        if version != 1 {
            return Err(ParseError::Malformed("BFD: version is not 1"));
        }
        let state_flags = r.u8()?;
        let flags = state_flags & 0x3F;
        let detect_mult = r.u8()?;
        if detect_mult == 0 {
            return Err(ParseError::Malformed("BFD: Detect Mult is zero"));
        }
        let length = usize::from(r.u8()?);
        // §6.8.6: >= 24, >= 26 when the auth section is present.
        let min_len = if flags & A_BIT != 0 {
            MANDATORY_LEN + 2
        } else {
            MANDATORY_LEN
        };
        if length < min_len {
            return Err(ParseError::Malformed("BFD: length below mandatory section"));
        }
        let my_discriminator = r.u32_be()?;
        if my_discriminator == 0 {
            return Err(ParseError::Malformed("BFD: My Discriminator is zero"));
        }
        let your_discriminator = r.u32_be()?;
        let desired_min_tx = r.u32_be()?;
        let required_min_rx = r.u32_be()?;
        let required_min_echo_rx = r.u32_be()?;
        // Optional authentication section: opaque, but part of the packet
        // `length` declares — walk it so header_len stays honest.
        r.take(length - MANDATORY_LEN)?;

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(MY_DISCRIMINATOR, Value::U64(u64::from(my_discriminator)));
            fields.insert(
                YOUR_DISCRIMINATOR,
                Value::U64(u64::from(your_discriminator)),
            );
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(VERSION, Value::U64(u64::from(version)));
            fields.insert(DIAG, Value::U64(u64::from(vers_diag & 0x1F)));
            fields.insert(STATE, Value::U64(u64::from(state_flags >> 6)));
            fields.insert(FLAGS, Value::U64(u64::from(flags)));
            fields.insert(DETECT_MULT, Value::U64(u64::from(detect_mult)));
            fields.insert(LENGTH, Value::U64(length as u64));
        }
        if ctx.depth() >= Depth::Full {
            fields.insert(DESIRED_MIN_TX, Value::U64(u64::from(desired_min_tx)));
            fields.insert(REQUIRED_MIN_RX, Value::U64(u64::from(required_min_rx)));
            fields.insert(
                REQUIRED_MIN_ECHO_RX,
                Value::U64(u64::from(required_min_echo_rx)),
            );
        }

        Ok(ParsedLayer {
            header_len: length,
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[
            RouteId::UdpPort(3784), // RFC 5881 single-hop control
            RouteId::UdpPort(4784), // RFC 5883 multihop control
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
        Bfd.parse(bytes, &ParseCtx::new(&[], Depth::Full, &meta))
    }

    /// RFC 5880 §4.1 control packet: version 1, the caller's state/flags,
    /// detect mult 3, 100ms intervals.
    fn control(state: u8, flags: u8, my_disc: u32, your_disc: u32) -> Vec<u8> {
        let mut b = vec![0x20, (state << 6) | flags, 3, 24];
        b.extend_from_slice(&my_disc.to_be_bytes());
        b.extend_from_slice(&your_disc.to_be_bytes());
        b.extend_from_slice(&100_000u32.to_be_bytes());
        b.extend_from_slice(&100_000u32.to_be_bytes());
        b.extend_from_slice(&0u32.to_be_bytes());
        b
    }

    #[test]
    fn up_packet_parses_exactly() {
        // Established session: state Up (3), my disc 7, your disc 9.
        let bytes = control(3, 0, 7, 9);
        let parsed = parse(&bytes).expect("valid Up control packet");
        assert_eq!(parsed.header_len, 24);
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(MY_DISCRIMINATOR), Some(&Value::U64(7)));
        assert_eq!(parsed.fields.get(YOUR_DISCRIMINATOR), Some(&Value::U64(9)));
        assert_eq!(parsed.fields.get(STATE), Some(&Value::U64(3)));
        assert_eq!(parsed.fields.get(DETECT_MULT), Some(&Value::U64(3)));
        assert_eq!(
            parsed.fields.get(DESIRED_MIN_TX),
            Some(&Value::U64(100_000))
        );
    }

    #[test]
    fn bring_up_with_zero_your_discriminator_parses() {
        // §6.8.6: Your Discriminator is 0 until the peer is learned.
        let bytes = control(1, 0, 7, 0);
        let parsed = parse(&bytes).expect("Down packet before peer learned");
        assert_eq!(parsed.fields.get(YOUR_DISCRIMINATOR), Some(&Value::U64(0)));
    }

    #[test]
    fn authentication_section_extends_header_len() {
        // A bit set, 8 extra auth bytes: length 32, all consumed.
        let mut bytes = control(3, A_BIT, 7, 9);
        bytes[3] = 32;
        bytes.extend_from_slice(&[1, 8, 2, 0, 0xDE, 0xAD, 0xBE, 0xEF]);
        let parsed = parse(&bytes).expect("authenticated control packet");
        assert_eq!(parsed.header_len, 32);
        assert_eq!(parsed.fields.get(LENGTH), Some(&Value::U64(32)));
    }

    #[test]
    fn zero_version_declines() {
        let mut bytes = control(3, 0, 7, 9);
        bytes[0] = 0x00; // version 0 (RFC 5880 obsoleted draft versions)
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn zero_detect_mult_declines() {
        let mut bytes = control(3, 0, 7, 9);
        bytes[2] = 0;
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn zero_my_discriminator_declines() {
        assert!(parse(&control(3, 0, 0, 9)).is_err());
    }

    #[test]
    fn undersized_length_declines() {
        let mut bytes = control(3, 0, 7, 9);
        bytes[3] = 23;
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn auth_bit_without_auth_bytes_declines() {
        // A set but length still 24: §6.8.6 requires >= 26.
        let bytes = control(3, A_BIT, 7, 9);
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn truncated_packets_decline() {
        let bytes = control(3, 0, 7, 9);
        for n in 0..bytes.len() {
            assert!(parse(&bytes[..n]).is_err(), "prefix of {n} bytes");
        }
    }
}
