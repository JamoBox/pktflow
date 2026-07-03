//! IPv4 (06.3, RFC 791): IP conversations, the raw-IP entry probe, and
//! fragment-safe routing.

use pktflow_core::{
    ByteReader, Canonicalize, Confidence, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin,
    ParseCtx, ParseError, ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId,
    StreamIdentity, Value,
};

const SRC_ADDR: FieldName = "src_addr";
const DST_ADDR: FieldName = "dst_addr";
const PROTOCOL: FieldName = "protocol";
const TTL: FieldName = "ttl";
const TOTAL_LEN: FieldName = "total_len";
const FLAGS: FieldName = "flags";
const FRAG_OFFSET: FieldName = "frag_offset";
const IHL: FieldName = "ihl";
const DSCP: FieldName = "dscp";
const ECN: FieldName = "ecn";
const ID: FieldName = "id";
const CHECKSUM: FieldName = "checksum";
const OPTIONS: FieldName = "options";

static KEY: &[KeyField] = &[KeyField {
    a: SRC_ADDR,
    b: Some(DST_ADDR),
}];
static ROLLUPS: &[RollupSpec] = &[RollupSpec {
    field: PROTOCOL,
    kind: RollupKind::Accumulate,
}];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: ROLLUPS,
};

/// RFC 1071 internet checksum over `header`; a valid IPv4 header sums to 0.
pub fn internet_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = header.chunks_exact(2);
    for pair in &mut chunks {
        sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
    }
    if let [last] = chunks.remainder() {
        sum += u32::from(u16::from_be_bytes([*last, 0]));
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

pub struct Ipv4;

impl LayerPlugin for Ipv4 {
    fn name(&self) -> ProtocolName {
        "ipv4"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let ver_ihl = r.u8()?;
        if ver_ihl >> 4 != 4 {
            return Err(ParseError::Malformed("version nibble is not 4"));
        }
        let ihl = u64::from(ver_ihl & 0x0F);
        if ihl < 5 {
            return Err(ParseError::Malformed("IHL below 5"));
        }
        let header_len = (ihl * 4) as usize;
        let dscp_ecn = r.u8()?;
        let total_len = r.u16_be()?;
        let id = r.u16_be()?;
        let flags_frag = r.u16_be()?;
        let ttl = r.u8()?;
        let protocol = r.u8()?;
        let checksum = r.u16_be()?;
        let src = r.take(4)?;
        let dst = r.take(4)?;
        let options = r.take(header_len - 20)?;

        let frag_offset = flags_frag & 0x1FFF;
        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(SRC_ADDR, Value::from(src));
            fields.insert(DST_ADDR, Value::from(dst));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(PROTOCOL, Value::U64(u64::from(protocol)));
            fields.insert(TTL, Value::U64(u64::from(ttl)));
            fields.insert(TOTAL_LEN, Value::U64(u64::from(total_len)));
            fields.insert(FLAGS, Value::U64(u64::from(flags_frag >> 13)));
            fields.insert(FRAG_OFFSET, Value::U64(u64::from(frag_offset)));
            fields.insert(IHL, Value::U64(ihl));
        }
        if ctx.depth() >= Depth::Full {
            fields.insert(DSCP, Value::U64(u64::from(dscp_ecn >> 2)));
            fields.insert(ECN, Value::U64(u64::from(dscp_ecn & 0x03)));
            fields.insert(ID, Value::U64(u64::from(id)));
            fields.insert(CHECKSUM, Value::U64(u64::from(checksum)));
            if !options.is_empty() {
                fields.insert(OPTIONS, Value::from(options));
            }
        }

        // A non-first fragment carries no transport header; reassembly is
        // out of scope (D7), so this layer is definitively last.
        let hint = if frag_offset > 0 {
            Hint::Terminal
        } else {
            Hint::Route(RouteId::IpProtocol(protocol))
        };
        Ok(ParsedLayer {
            header_len,
            fields,
            hint,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[
            RouteId::EtherType(0x0800),
            RouteId::IpProtocol(4 /* IP-in-IP */),
        ]
    }

    fn has_probe(&self) -> bool {
        true
    }

    /// Raw-IP entry identification (04.2): structural invariants plus the
    /// header checksum — random or corrupted bytes score nothing.
    fn probe(&self, bytes: &[u8], _ctx: &ParseCtx) -> Option<Confidence> {
        let first = *bytes.first()?;
        if first >> 4 != 4 || first & 0x0F < 5 {
            return None;
        }
        let header_len = usize::from(first & 0x0F) * 4;
        let header = bytes.get(..header_len)?;
        let total_len = u16::from_be_bytes([*bytes.get(2)?, *bytes.get(3)?]);
        if usize::from(total_len) > bytes.len() || usize::from(total_len) < header_len {
            return None;
        }
        (internet_checksum(header) == 0).then(|| Confidence::new(90))
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

    /// Hand-assembled per RFC 791: DF flag, TTL 64, TCP inside,
    /// 10.0.0.1 -> 10.0.0.2, checksum computed to be valid.
    pub(crate) fn header(protocol: u8) -> Vec<u8> {
        let mut h = vec![
            0x45, 0x00, // v4, IHL 5, DSCP/ECN 0
            0x00, 0x3C, // total_len 60
            0x1C, 0x46, // id
            0x40, 0x00, // DF, offset 0
            0x40, protocol, // ttl 64
            0x00, 0x00, // checksum placeholder
            10, 0, 0, 1, //
            10, 0, 0, 2,
        ];
        let ck = internet_checksum(&h);
        h[10..12].copy_from_slice(&ck.to_be_bytes());
        h
    }

    fn parse(bytes: &[u8]) -> Result<ParsedLayer, ParseError> {
        let meta = PacketMeta {
            timestamp: SystemTime::UNIX_EPOCH,
            caplen: bytes.len(),
            origlen: bytes.len(),
            link_type: LinkType::ETHERNET,
        };
        Ipv4.parse(bytes, &ParseCtx::new(&[], Depth::Full, &meta))
    }

    #[test]
    fn parses_the_fixture_header() {
        let parsed = parse(&header(6)).expect("valid header");
        assert_eq!(parsed.header_len, 20);
        assert_eq!(
            parsed.fields.get(SRC_ADDR),
            Some(&Value::from(&[10, 0, 0, 1][..]))
        );
        assert_eq!(parsed.fields.get(PROTOCOL), Some(&Value::U64(6)));
        assert_eq!(parsed.fields.get(FLAGS), Some(&Value::U64(2)));
        assert_eq!(parsed.hint, Hint::Route(RouteId::IpProtocol(6)));
    }

    #[test]
    fn options_are_consumed_into_header_len() {
        // IHL 6: four option bytes (NOP NOP NOP EOL), checksum refreshed.
        let mut h = header(6);
        h[0] = 0x46;
        h.extend_from_slice(&[0x01, 0x01, 0x01, 0x00]);
        h[10..12].copy_from_slice(&[0, 0]);
        let ck = internet_checksum(&h);
        h[10..12].copy_from_slice(&ck.to_be_bytes());

        let parsed = parse(&h).expect("valid header");
        assert_eq!(parsed.header_len, 24);
        assert_eq!(
            parsed.fields.get(OPTIONS),
            Some(&Value::from(&[0x01, 0x01, 0x01, 0x00][..]))
        );
    }

    #[test]
    fn non_first_fragment_is_terminal() {
        let mut h = header(6);
        h[6..8].copy_from_slice(&0x00B9u16.to_be_bytes()); // offset 185
        let parsed = parse(&h).expect("valid header");
        assert_eq!(parsed.hint, Hint::Terminal);
    }

    #[test]
    fn broken_checksum_scores_no_probe() {
        let meta = PacketMeta {
            timestamp: SystemTime::UNIX_EPOCH,
            caplen: 20,
            origlen: 20,
            link_type: LinkType::ETHERNET,
        };
        let ctx = ParseCtx::new(&[], Depth::Full, &meta);
        // total_len must match the header-only buffer for the probe's
        // length sanity check; then refresh the checksum.
        let mut good = header(6);
        good[2..4].copy_from_slice(&20u16.to_be_bytes());
        good[10..12].copy_from_slice(&[0, 0]);
        let ck = internet_checksum(&good);
        good[10..12].copy_from_slice(&ck.to_be_bytes());
        assert!(Ipv4.probe(&good, &ctx).is_some());

        let mut broken = good;
        broken[11] ^= 0xFF;
        assert_eq!(Ipv4.probe(&broken, &ctx), None);
    }
}
