//! Geneve (11.5, RFC 8926 — *Generic Network Virtualization Encapsulation*
//! §3). Like GRE (06.5), `protocol_type` *is* an EtherType value by
//! protocol design, so `Hint::Route` needs no translation table — the same
//! coincidental-reuse pattern GRE established, Geneve's own flavor.
//!
//! The fixed 8-byte header is followed by `opt_len` 4-byte words of
//! variable-length options (RFC 8926 §3.5); v1 captures that region as raw
//! bytes at `Full` depth without decoding the per-option Class/Type/Length
//! TLV structure (11.5's spec: "not decoded in v1").

use pktflow_core::{
    ByteReader, Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx,
    ParseError, ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId, StreamIdentity, Value,
};

const VNI: FieldName = "vni";
const VERSION: FieldName = "version";
const OPT_LEN: FieldName = "opt_len";
const O_BIT: FieldName = "o_bit";
const C_BIT: FieldName = "c_bit";
const PROTOCOL_TYPE: FieldName = "protocol_type";
const OPTIONS: FieldName = "options";

/// RFC 8926 §3: "The current version number is 0." Any other value is a
/// future/incompatible header shape this plugin cannot interpret.
const SUPPORTED_VERSION: u8 = 0;

/// Byte 1: bit 7 is the O (Control packet) flag.
const O_FLAG: u8 = 0x80;
/// Byte 1: bit 6 is the C (Critical Options Present) flag.
const C_FLAG: u8 = 0x40;

static KEY: &[KeyField] = &[KeyField {
    a: VNI,
    b: None, // shared qualifier: one stream per VNI, the VXLAN precedent
}];
static ROLLUPS: &[RollupSpec] = &[RollupSpec {
    field: PROTOCOL_TYPE,
    kind: RollupKind::Accumulate,
}];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: ROLLUPS,
};

pub struct Geneve;

impl LayerPlugin for Geneve {
    fn name(&self) -> ProtocolName {
        "geneve"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);

        let ver_optlen = r.u8()?;
        let version = ver_optlen >> 6;
        if version != SUPPORTED_VERSION {
            return Err(ParseError::Malformed("Geneve version is not 0"));
        }
        // Opt Len counts 4-byte words (RFC 8926 §3), max 63 -> 252 bytes.
        let opt_len = ver_optlen & 0x3F;

        let flags = r.u8()?;
        let o_bit = flags & O_FLAG != 0;
        let c_bit = flags & C_FLAG != 0;

        let protocol_type = r.u16_be()?;

        let vni_bytes = r.take(3)?;
        let vni = vni_bytes
            .iter()
            .fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
        let _reserved = r.u8()?;

        // Always consumed (truncation must decline regardless of depth),
        // stored only at Full — same shape as ipfix's raw Set bytes.
        let options = r.take(usize::from(opt_len) * 4)?;

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(VNI, Value::U64(vni));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(VERSION, Value::U64(u64::from(version)));
            fields.insert(OPT_LEN, Value::U64(u64::from(opt_len)));
            fields.insert(O_BIT, Value::Bool(o_bit));
            fields.insert(C_BIT, Value::Bool(c_bit));
            fields.insert(PROTOCOL_TYPE, Value::U64(u64::from(protocol_type)));
        }
        if ctx.depth() >= Depth::Full {
            fields.insert(OPTIONS, Value::from(options));
        }

        Ok(ParsedLayer {
            header_len: 8 + usize::from(opt_len) * 4,
            fields,
            hint: Hint::Route(RouteId::EtherType(protocol_type)),
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::UdpPort(6081)]
    }

    // No probe: like GRE/VXLAN, tunnels are explicit-only (06.5).

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
        Geneve.parse(bytes, &ParseCtx::new(&[], Depth::Full, &meta))
    }

    /// A Geneve header with `opt_len` 4-byte option words, VNI 5001,
    /// protocol_type IPv4 (0x0800).
    fn header(opt_len: u8, o: bool, c: bool) -> Vec<u8> {
        let mut flags = 0u8;
        if o {
            flags |= O_FLAG;
        }
        if c {
            flags |= C_FLAG;
        }
        let mut h = vec![opt_len & 0x3F, flags];
        h.extend_from_slice(&0x0800u16.to_be_bytes());
        h.extend_from_slice(&5001u32.to_be_bytes()[1..4]); // VNI
        h.push(0); // reserved
        h.extend(std::iter::repeat_n(0xAB, usize::from(opt_len) * 4));
        h
    }

    #[test]
    fn bare_header_no_options_parses() {
        let bytes = header(0, false, false);
        let parsed = parse(&bytes).expect("valid header");
        assert_eq!(parsed.header_len, 8);
        assert_eq!(parsed.fields.get(VNI), Some(&Value::U64(5001)));
        assert_eq!(parsed.fields.get(VERSION), Some(&Value::U64(0)));
        assert_eq!(parsed.fields.get(OPT_LEN), Some(&Value::U64(0)));
        assert_eq!(parsed.fields.get(O_BIT), Some(&Value::Bool(false)));
        assert_eq!(parsed.fields.get(C_BIT), Some(&Value::Bool(false)));
        assert_eq!(parsed.fields.get(PROTOCOL_TYPE), Some(&Value::U64(0x0800)));
        assert_eq!(parsed.fields.get(OPTIONS), Some(&Value::from(&b""[..])));
        assert_eq!(parsed.hint, Hint::Route(RouteId::EtherType(0x0800)));
    }

    #[test]
    fn options_present_are_captured_raw_and_header_len_grows() {
        let bytes = header(3, true, true);
        let parsed = parse(&bytes).expect("valid header with options");
        assert_eq!(parsed.header_len, 8 + 12);
        assert_eq!(parsed.fields.get(OPT_LEN), Some(&Value::U64(3)));
        assert_eq!(parsed.fields.get(O_BIT), Some(&Value::Bool(true)));
        assert_eq!(parsed.fields.get(C_BIT), Some(&Value::Bool(true)));
        assert_eq!(
            parsed.fields.get(OPTIONS),
            Some(&Value::from(&[0xABu8; 12][..]))
        );
    }

    #[test]
    fn truncated_options_decline() {
        let bytes = header(3, false, false);
        assert!(parse(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn truncated_fixed_header_declines() {
        let bytes = header(0, false, false);
        for cut in 0..8 {
            assert!(parse(&bytes[..cut]).is_err(), "cut at {cut}");
        }
    }

    #[test]
    fn nonzero_version_declines() {
        let mut bytes = header(0, false, false);
        bytes[0] |= 0x40; // version = 1
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn depth_gating_hides_fields_below_full() {
        let bytes = header(1, false, false);
        let meta = PacketMeta {
            timestamp: SystemTime::UNIX_EPOCH,
            caplen: bytes.len(),
            origlen: bytes.len(),
            link_type: LinkType::ETHERNET,
        };

        let keys_only = Geneve
            .parse(&bytes, &ParseCtx::new(&[], Depth::Keys, &meta))
            .expect("valid header");
        assert_eq!(keys_only.fields.get(VNI), Some(&Value::U64(5001)));
        assert_eq!(keys_only.fields.get(VERSION), None);
        assert_eq!(keys_only.fields.get(OPTIONS), None);
        // header_len must stay correct regardless of depth: downstream
        // offset math cannot depend on how much was requested.
        assert_eq!(keys_only.header_len, 12);

        let structural = Geneve
            .parse(&bytes, &ParseCtx::new(&[], Depth::Structural, &meta))
            .expect("valid header");
        assert_eq!(
            structural.fields.get(PROTOCOL_TYPE),
            Some(&Value::U64(0x0800))
        );
        assert_eq!(structural.fields.get(OPTIONS), None);
    }
}
