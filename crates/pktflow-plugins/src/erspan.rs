//! ERSPAN (draft-foschiano-erspan): remote SPAN — mirrored traffic
//! shipped across the fabric inside GRE, how data-center switches feed
//! packet brokers and monitoring taps. One plugin covers both wire
//! versions, disambiguated the same way `vrrp` handles v2/v3 (11.4):
//!
//! - **Type II** (version 1, EtherType 0x88BE): 8-byte header —
//!   `ver(4) vlan(12) | cos(3) en(2) t(1) session(10) | resv(12) index(20)`
//!   — always followed by the mirrored Ethernet frame. GRE carries it
//!   with the S bit set, which `gre` already walks.
//! - **Type III** (version 2, EtherType 0x22EB): 12-byte header with a
//!   hardware timestamp and security group tag, plus an optional 8-byte
//!   platform subheader when the O bit is set. Its `ft` field names the
//!   mirrored frame's type: 0 = Ethernet (dispatch by name, the VXLAN
//!   shape), anything else (2 = IP) has no single fixed inner protocol —
//!   [`Hint::Unknown`] lets the gated heuristics score it.
//!
//! Stream identity keys on the session id — the mirror session the
//! operator configured is exactly the conversation worth aggregating,
//! one stream per session under the GRE tunnel (the 06.5
//! shared-qualifier shape).

use pktflow_core::{
    ByteReader, Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx,
    ParseError, ParsedLayer, ProtocolName, RouteId, StreamIdentity, Value,
};

const SESSION_ID: FieldName = "session_id";
const VERSION: FieldName = "version";
const VLAN: FieldName = "vlan";
const COS: FieldName = "cos";
const TRUNCATED: FieldName = "truncated";
const INDEX: FieldName = "index";
const TIMESTAMP: FieldName = "timestamp";
const SGT: FieldName = "sgt";
const FRAME_TYPE: FieldName = "frame_type";

static KEY: &[KeyField] = &[KeyField {
    a: SESSION_ID,
    b: None, // shared qualifier: one stream per mirror session
}];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: &[],
};

pub struct Erspan;

impl LayerPlugin for Erspan {
    fn name(&self) -> ProtocolName {
        "erspan"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let ver_vlan = r.u16_be()?;
        let version = ver_vlan >> 12;
        let word2 = r.u16_be()?;
        let session_id = u64::from(word2 & 0x03FF);
        let cos = u64::from(word2 >> 13);
        let truncated = word2 & 0x0400 != 0;

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(SESSION_ID, Value::U64(session_id));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(VERSION, Value::U64(u64::from(version)));
            fields.insert(VLAN, Value::U64(u64::from(ver_vlan & 0x0FFF)));
            fields.insert(COS, Value::U64(cos));
        }

        let (header_len, hint) = match version {
            1 => {
                // Type II: reserved(12) | index(20), then the mirrored frame.
                let index = r.u32_be()? & 0x000F_FFFF;
                if ctx.depth() >= Depth::Full {
                    fields.insert(INDEX, Value::U64(u64::from(index)));
                }
                (8, Hint::ByProtocol("ethernet"))
            }
            2 => {
                // Type III: timestamp, SGT, then the P/FT/HW/D/Gra/O word.
                let timestamp = r.u32_be()?;
                let sgt = r.u16_be()?;
                let last = r.u16_be()?;
                let frame_type = (last >> 10) & 0x1F;
                let mut len = 12;
                if last & 0x0001 != 0 {
                    // O bit: opaque platform-specific subheader.
                    r.take(8)?;
                    len += 8;
                }
                if ctx.depth() >= Depth::Full {
                    fields.insert(TIMESTAMP, Value::U64(u64::from(timestamp)));
                    fields.insert(SGT, Value::U64(u64::from(sgt)));
                    fields.insert(FRAME_TYPE, Value::U64(u64::from(frame_type)));
                }
                let hint = if frame_type == 0 {
                    Hint::ByProtocol("ethernet")
                } else {
                    Hint::Unknown
                };
                (len, hint)
            }
            _ => return Err(ParseError::Malformed("ERSPAN: unknown version")),
        };
        if ctx.depth() >= Depth::Full {
            fields.insert(TRUNCATED, Value::Bool(truncated));
        }

        Ok(ParsedLayer {
            header_len,
            fields,
            hint,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[
            RouteId::EtherType(0x88BE), // Type II
            RouteId::EtherType(0x22EB), // Type III
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
        Erspan.parse(bytes, &ParseCtx::new(&[], Depth::Full, &meta))
    }

    /// Type II header: VLAN 100, CoS 3, session 42, index 7.
    fn type_ii() -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&(0x1000u16 | 100).to_be_bytes());
        b.extend_from_slice(&(0x6000u16 | 42).to_be_bytes());
        b.extend_from_slice(&7u32.to_be_bytes());
        b
    }

    /// Type III header: session 42, hardware timestamp, SGT, the
    /// caller's frame type, optional platform subheader.
    fn type_iii(frame_type: u16, subheader: bool) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&(0x2000u16 | 100).to_be_bytes());
        b.extend_from_slice(&(0x6000u16 | 42).to_be_bytes());
        b.extend_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
        b.extend_from_slice(&0x0005u16.to_be_bytes());
        b.extend_from_slice(&((frame_type << 10) | u16::from(subheader)).to_be_bytes());
        if subheader {
            b.extend_from_slice(&[0xAA; 8]);
        }
        b
    }

    #[test]
    fn type_ii_parses_and_wraps_ethernet() {
        let parsed = parse(&type_ii()).expect("valid Type II header");
        assert_eq!(parsed.header_len, 8);
        assert_eq!(parsed.hint, Hint::ByProtocol("ethernet"));
        assert_eq!(parsed.fields.get(SESSION_ID), Some(&Value::U64(42)));
        assert_eq!(parsed.fields.get(VERSION), Some(&Value::U64(1)));
        assert_eq!(parsed.fields.get(VLAN), Some(&Value::U64(100)));
        assert_eq!(parsed.fields.get(COS), Some(&Value::U64(3)));
        assert_eq!(parsed.fields.get(INDEX), Some(&Value::U64(7)));
        assert_eq!(parsed.fields.get(TRUNCATED), Some(&Value::Bool(false)));
    }

    #[test]
    fn type_iii_ethernet_frame_dispatches_by_name() {
        let parsed = parse(&type_iii(0, false)).expect("valid Type III header");
        assert_eq!(parsed.header_len, 12);
        assert_eq!(parsed.hint, Hint::ByProtocol("ethernet"));
        assert_eq!(parsed.fields.get(TIMESTAMP), Some(&Value::U64(0xDEAD_BEEF)));
        assert_eq!(parsed.fields.get(SGT), Some(&Value::U64(5)));
        assert_eq!(parsed.fields.get(FRAME_TYPE), Some(&Value::U64(0)));
    }

    #[test]
    fn type_iii_ip_frame_defers_to_heuristics() {
        let parsed = parse(&type_iii(2, false)).expect("valid Type III header");
        assert_eq!(parsed.hint, Hint::Unknown);
    }

    #[test]
    fn type_iii_subheader_extends_header_len() {
        let parsed = parse(&type_iii(0, true)).expect("Type III with subheader");
        assert_eq!(parsed.header_len, 20);
    }

    #[test]
    fn unknown_version_declines() {
        let mut bytes = type_ii();
        bytes[0] = 0x30; // version 3
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn truncated_headers_decline() {
        for bytes in [type_ii(), type_iii(0, true)] {
            for n in 0..bytes.len() {
                assert!(parse(&bytes[..n]).is_err(), "prefix of {n} bytes");
            }
        }
    }
}
