//! RTP (11.10, RFC 3550) — **D15 applies in full**: RTP has no well-known
//! port; the port pair is negotiated inside SIP's (unparsed) SDP body.
//! UDP's hint is unconditionally `Candidates` (06.4), never `Unknown`, so
//! an ephemeral, unclaimed port pair **gates shut** rather than reaching
//! heuristic fallback — meaning a `probe()` here would never actually be
//! consulted. Giving `rtp` one anyway would be dishonest scaffolding (the
//! same reasoning UDP itself uses to justify having no `probe()`, 06.4).
//! This plugin is real, specified, and fixture-tested by feeding bytes
//! directly to `parse()` (09.1) — it is just not reachable via routing in
//! v1, ready the moment cross-stream port correlation (D15) exists.
//!
//! ## Header (RFC 3550 §5.1)
//! `V(2)+P(1)+X(1)+CC(4) | M(1)+PT(7) | sequence_number(16) | timestamp(32)
//! | SSRC(32) | CSRC list (CC * 32 bits)`. `header_len` covers the fixed
//! 12-byte header plus the CSRC list — the extension header (if `X` is
//! set) and the payload past it are not this Tier-1 entry's business
//! (unparsed remainder, D7); `padding`/`extension` bits are consumed for
//! validity but not surfaced as fields (not in 11.10's field table).

use pktflow_core::{
    ByteReader, Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx,
    ParseError, ParsedLayer, ProtocolName, RollupKind, RollupSpec, StreamIdentity, Value,
};

const SSRC: FieldName = "ssrc";
const VERSION: FieldName = "version";
const PAYLOAD_TYPE: FieldName = "payload_type";
const SEQUENCE_NUMBER: FieldName = "sequence_number";
const TIMESTAMP: FieldName = "timestamp";
const MARKER_BIT: FieldName = "marker_bit";
const CSRC_LIST: FieldName = "csrc_list";

/// RFC 3550 §5.1: the only version in use.
const RTP_VERSION: u8 = 2;
const FIXED_HEADER_LEN: usize = 12;

static KEY: &[KeyField] = &[KeyField { a: SSRC, b: None }];
static ROLLUPS: &[RollupSpec] = &[RollupSpec {
    field: PAYLOAD_TYPE,
    kind: RollupKind::Accumulate,
}];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: ROLLUPS,
};

pub struct Rtp;

impl LayerPlugin for Rtp {
    fn name(&self) -> ProtocolName {
        "rtp"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let byte0 = r.u8()?;
        let version = (byte0 & 0xC0) >> 6;
        if version != RTP_VERSION {
            return Err(ParseError::Malformed("unsupported RTP version"));
        }
        let cc = byte0 & 0x0F;
        let byte1 = r.u8()?;
        let marker_bit = byte1 & 0x80 != 0;
        let payload_type = byte1 & 0x7F;
        let sequence_number = r.u16_be()?;
        let timestamp = r.u32_be()?;
        let ssrc = r.u32_be()?;
        let mut csrc_list = Vec::with_capacity(usize::from(cc));
        for _ in 0..cc {
            csrc_list.push(Value::U64(u64::from(r.u32_be()?)));
        }
        let header_len = FIXED_HEADER_LEN + usize::from(cc) * 4;

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(SSRC, Value::U64(u64::from(ssrc)));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(VERSION, Value::U64(u64::from(version)));
            fields.insert(PAYLOAD_TYPE, Value::U64(u64::from(payload_type)));
            fields.insert(SEQUENCE_NUMBER, Value::U64(u64::from(sequence_number)));
            fields.insert(TIMESTAMP, Value::U64(u64::from(timestamp)));
            fields.insert(MARKER_BIT, Value::Bool(marker_bit));
        }
        if ctx.depth() >= Depth::Full {
            fields.insert(CSRC_LIST, Value::List(csrc_list));
        }

        Ok(ParsedLayer {
            header_len,
            fields,
            hint: Hint::Terminal,
        })
    }

    // No `claims()`, no probe (module doc): unreachable via routing in v1.

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

    fn ctx(depth: Depth, meta: &PacketMeta) -> ParseCtx<'_> {
        ParseCtx::new(&[], depth, meta)
    }

    fn frame(marker: bool, pt: u8, seq: u16, ts: u32, ssrc: u32, csrcs: &[u32]) -> Vec<u8> {
        let mut b = vec![0x80 | csrcs.len() as u8];
        b.push((u8::from(marker) << 7) | pt);
        b.extend_from_slice(&seq.to_be_bytes());
        b.extend_from_slice(&ts.to_be_bytes());
        b.extend_from_slice(&ssrc.to_be_bytes());
        for c in csrcs {
            b.extend_from_slice(&c.to_be_bytes());
        }
        b
    }

    #[test]
    fn basic_frame_parses_all_fields() {
        let bytes = frame(true, 0, 1000, 160_000, 0xDEAD_BEEF, &[]);
        let m = meta(bytes.len());
        let parsed = Rtp
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid RTP header");
        assert_eq!(parsed.header_len, 12);
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(SSRC), Some(&Value::U64(0xDEAD_BEEF)));
        assert_eq!(parsed.fields.get(VERSION), Some(&Value::U64(2)));
        assert_eq!(parsed.fields.get(PAYLOAD_TYPE), Some(&Value::U64(0)));
        assert_eq!(parsed.fields.get(SEQUENCE_NUMBER), Some(&Value::U64(1000)));
        assert_eq!(parsed.fields.get(TIMESTAMP), Some(&Value::U64(160_000)));
        assert_eq!(parsed.fields.get(MARKER_BIT), Some(&Value::Bool(true)));
    }

    #[test]
    fn csrc_list_extends_header_len() {
        let bytes = frame(false, 8, 1, 1, 0x1111_1111, &[0xAAAA_AAAA, 0xBBBB_BBBB]);
        let m = meta(bytes.len());
        let parsed = Rtp.parse(&bytes, &ctx(Depth::Full, &m)).expect("valid");
        assert_eq!(parsed.header_len, 12 + 8);
        assert_eq!(
            parsed.fields.get(CSRC_LIST),
            Some(&Value::List(vec![
                Value::U64(0xAAAA_AAAA),
                Value::U64(0xBBBB_BBBB)
            ]))
        );
    }

    #[test]
    fn depth_gates_ssrc_and_csrc_list() {
        let bytes = frame(false, 0, 1, 1, 1, &[0x22]);
        let m = meta(bytes.len());
        let keys = Rtp.parse(&bytes, &ctx(Depth::Keys, &m)).expect("valid");
        assert_eq!(keys.fields.get(SSRC), Some(&Value::U64(1)));
        assert_eq!(keys.fields.get(VERSION), None);

        let structural = Rtp
            .parse(&bytes, &ctx(Depth::Structural, &m))
            .expect("valid");
        assert_eq!(structural.fields.get(PAYLOAD_TYPE), Some(&Value::U64(0)));
        assert_eq!(structural.fields.get(CSRC_LIST), None);
    }

    #[test]
    fn wrong_version_declines() {
        let mut bytes = frame(false, 0, 1, 1, 1, &[]);
        bytes[0] = 0x00; // version 0
        let m = meta(bytes.len());
        assert!(Rtp.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn truncated_frames_decline_at_every_prefix() {
        let bytes = frame(true, 8, 1, 1, 1, &[0x1, 0x2]);
        let m = meta(bytes.len());
        let full = ctx(Depth::Full, &m);
        for n in 0..bytes.len() {
            assert!(
                Rtp.parse(&bytes[..n], &full).is_err(),
                "prefix of {n}/{} bytes must decline",
                bytes.len()
            );
        }
    }

    #[test]
    fn no_claims_declared() {
        assert!(Rtp.claims().is_empty());
        assert!(!Rtp.has_probe());
    }
}
