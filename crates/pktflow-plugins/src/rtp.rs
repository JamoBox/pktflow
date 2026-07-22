//! RTP (11.10, RFC 3550) — the VoIP/video media plane. **D15 applies in
//! full**: RTP has no well-known port; the port pair is negotiated inside
//! `sip`'s (unparsed, D7) SDP body. UDP's hint is unconditionally
//! `Candidates` (06.4), never `Unknown`, so an ephemeral, unclaimed port
//! pair gates shut rather than reaching heuristic fallback — a `probe()`
//! here would never actually be consulted, the same reasoning UDP itself
//! uses to justify having none. This plugin is real, specified, and
//! fixture-tested by feeding bytes directly to `parse()` (09.1) — not
//! reachable via routing in v1, ready the moment cross-stream port
//! correlation (D15) exists.
//!
//! ## Header (RFC 3550 §5.1)
//!
//! ```text
//! Octet 1: V(2) | P(1) | X(1) | CC(4)
//! Octet 2: M(1) | PT(7)
//! Octets 3-4: sequence number
//! Octets 5-8: timestamp
//! Octets 9-12: SSRC
//! CC * 4 octets: CSRC list
//! -- if X: 4-octet extension header (2-octet profile + 2-octet length in
//!    32-bit words) followed by that many words --
//! ```
//!
//! The header extension's *contents* are profile-defined and out of this
//! Tier-1 entry's field list; this plugin consumes exactly its length
//! (self-describing, so `header_len` stays honest) without decoding it —
//! the same bounded-skip stance `gtp_u`'s own extension-header chain
//! takes (11.15).

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

const VERSION_MASK: u8 = 0xC0;
const VERSION_SHIFT: u32 = 6;
const RTP_VERSION: u8 = 2;
const EXTENSION_BIT: u8 = 0x10;
const CC_MASK: u8 = 0x0F;
const MARKER_BIT_MASK: u8 = 0x80;
const PAYLOAD_TYPE_MASK: u8 = 0x7F;

static KEY: &[KeyField] = &[KeyField {
    a: SSRC,
    b: None, // shared (non-endpoint) qualifier: one stream per synchronization source
}];
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
        let b0 = r.u8()?;
        let version = (b0 & VERSION_MASK) >> VERSION_SHIFT;
        if version != RTP_VERSION {
            return Err(ParseError::Malformed("RTP: unsupported version"));
        }
        let extension = b0 & EXTENSION_BIT != 0;
        let cc = b0 & CC_MASK;

        let b1 = r.u8()?;
        let marker_bit = b1 & MARKER_BIT_MASK != 0;
        let payload_type = b1 & PAYLOAD_TYPE_MASK;

        let sequence_number = r.u16_be()?;
        let timestamp = r.u32_be()?;
        let ssrc = r.u32_be()?;

        let mut csrc_list = Vec::with_capacity(usize::from(cc));
        for _ in 0..cc {
            csrc_list.push(r.u32_be()?);
        }

        if extension {
            let _profile = r.u16_be()?;
            let ext_len_words = r.u16_be()?;
            let _ext_data = r.take(usize::from(ext_len_words) * 4)?;
        }
        let header_len = bytes.len() - r.remaining();

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
        if ctx.depth() >= Depth::Full && !csrc_list.is_empty() {
            fields.insert(
                CSRC_LIST,
                Value::List(
                    csrc_list
                        .into_iter()
                        .map(|c| Value::U64(u64::from(c)))
                        .collect(),
                ),
            );
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
        Rtp.parse(bytes, &ctx(depth, &m))
    }

    fn parse(bytes: &[u8]) -> Result<ParsedLayer, ParseError> {
        parse_at(bytes, Depth::Full)
    }

    /// V=2, no padding, no extension, CC=0, M=0, PT=0 (PCMU), plus a
    /// minimal payload stand-in.
    fn basic_frame(seq: u16, timestamp: u32, ssrc: u32, payload: &[u8]) -> Vec<u8> {
        let mut b = vec![0x80, 0x00];
        b.extend_from_slice(&seq.to_be_bytes());
        b.extend_from_slice(&timestamp.to_be_bytes());
        b.extend_from_slice(&ssrc.to_be_bytes());
        b.extend_from_slice(payload);
        b
    }

    #[test]
    fn basic_frame_reports_all_structural_fields() {
        let bytes = basic_frame(1000, 0xAABBCCDD, 0x1234_5678, &[0xFF; 4]);
        let parsed = parse(&bytes).expect("valid RTP frame");
        assert_eq!(parsed.header_len, 12);
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(SSRC), Some(&Value::U64(0x1234_5678)));
        assert_eq!(parsed.fields.get(VERSION), Some(&Value::U64(2)));
        assert_eq!(parsed.fields.get(PAYLOAD_TYPE), Some(&Value::U64(0)));
        assert_eq!(parsed.fields.get(SEQUENCE_NUMBER), Some(&Value::U64(1000)));
        assert_eq!(parsed.fields.get(TIMESTAMP), Some(&Value::U64(0xAABB_CCDD)));
        assert_eq!(parsed.fields.get(MARKER_BIT), Some(&Value::Bool(false)));
        assert_eq!(parsed.fields.get(CSRC_LIST), None);
    }

    #[test]
    fn marker_bit_and_payload_type_share_the_second_octet() {
        let mut bytes = basic_frame(1, 1, 1, &[]);
        bytes[1] = 0x80 | 8; // marker set, payload type 8 (PCMA)
        let parsed = parse(&bytes).expect("valid RTP frame");
        assert_eq!(parsed.fields.get(MARKER_BIT), Some(&Value::Bool(true)));
        assert_eq!(parsed.fields.get(PAYLOAD_TYPE), Some(&Value::U64(8)));
    }

    #[test]
    fn csrc_list_is_extracted_at_full_depth() {
        let mut bytes = vec![0x82, 0x00]; // CC=2
        bytes.extend_from_slice(&1u16.to_be_bytes());
        bytes.extend_from_slice(&2u32.to_be_bytes());
        bytes.extend_from_slice(&3u32.to_be_bytes()); // SSRC
        bytes.extend_from_slice(&0x1111_1111u32.to_be_bytes()); // CSRC 1
        bytes.extend_from_slice(&0x2222_2222u32.to_be_bytes()); // CSRC 2

        let parsed = parse(&bytes).expect("valid RTP frame with CSRC list");
        assert_eq!(parsed.header_len, 12 + 8);
        assert_eq!(
            parsed.fields.get(CSRC_LIST),
            Some(&Value::List(vec![
                Value::U64(0x1111_1111),
                Value::U64(0x2222_2222)
            ]))
        );
    }

    #[test]
    fn extension_header_is_skipped_and_header_len_accounts_for_it() {
        let mut bytes = vec![0x90, 0x00]; // X=1, CC=0
        bytes.extend_from_slice(&1u16.to_be_bytes());
        bytes.extend_from_slice(&2u32.to_be_bytes());
        bytes.extend_from_slice(&3u32.to_be_bytes()); // SSRC
        bytes.extend_from_slice(&0xBEEFu16.to_be_bytes()); // profile
        bytes.extend_from_slice(&1u16.to_be_bytes()); // 1 word of extension
        bytes.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // extension data
        bytes.extend_from_slice(&[0x01, 0x02]); // payload stand-in

        let parsed = parse(&bytes).expect("valid RTP frame with header extension");
        assert_eq!(parsed.header_len, 12 + 4 + 4);
    }

    #[test]
    fn wrong_version_declines() {
        let mut bytes = basic_frame(1, 1, 1, &[]);
        bytes[0] = 0x40; // version 1
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn truncated_header_declines() {
        let bytes = basic_frame(1, 1, 1, &[]);
        assert!(parse(&bytes[..11]).is_err());
    }

    #[test]
    fn keys_depth_has_only_ssrc() {
        let bytes = basic_frame(1, 1, 42, &[]);
        let parsed = parse_at(&bytes, Depth::Keys).expect("valid header");
        assert_eq!(parsed.fields.len(), 1);
        assert_eq!(parsed.fields.get(SSRC), Some(&Value::U64(42)));
    }

    #[test]
    fn structural_depth_omits_csrc_list() {
        let mut bytes = vec![0x81, 0x00]; // CC=1
        bytes.extend_from_slice(&1u16.to_be_bytes());
        bytes.extend_from_slice(&2u32.to_be_bytes());
        bytes.extend_from_slice(&3u32.to_be_bytes());
        bytes.extend_from_slice(&4u32.to_be_bytes());
        let parsed = parse_at(&bytes, Depth::Structural).expect("valid header");
        assert_eq!(parsed.fields.get(CSRC_LIST), None);
        assert_eq!(parsed.fields.get(SEQUENCE_NUMBER), Some(&Value::U64(1)));
    }
}
