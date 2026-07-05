//! IPv6 (06.3, RFC 8200): fixed 40-byte header plus a bounded extension
//! header walk — the chain is part of this layer's `header_len`.

use pktflow_core::{
    ByteReader, Canonicalize, Confidence, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin,
    ParseCtx, ParseError, ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId,
    StreamIdentity, Value,
};

const SRC_ADDR: FieldName = "src_addr";
const DST_ADDR: FieldName = "dst_addr";
const NEXT_HEADER: FieldName = "next_header";
const HOP_LIMIT: FieldName = "hop_limit";
const PAYLOAD_LEN: FieldName = "payload_len";
const TRAFFIC_CLASS: FieldName = "traffic_class";
const FLOW_LABEL: FieldName = "flow_label";

/// Hostile chains must terminate: more than this many extension headers is
/// a malformed packet, not a deeper one (06.3).
const MAX_EXT_HEADERS: usize = 8;

static KEY: &[KeyField] = &[KeyField {
    a: SRC_ADDR,
    b: Some(DST_ADDR),
}];
static ROLLUPS: &[RollupSpec] = &[RollupSpec {
    field: NEXT_HEADER,
    kind: RollupKind::Accumulate,
}];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: ROLLUPS,
};

pub struct Ipv6;

impl LayerPlugin for Ipv6 {
    fn name(&self) -> ProtocolName {
        "ipv6"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let ver_tc_fl = r.u32_be()?;
        if ver_tc_fl >> 28 != 6 {
            return Err(ParseError::Malformed("version nibble is not 6"));
        }
        let payload_len = r.u16_be()?;
        let mut next_header = r.u8()?;
        let hop_limit = r.u8()?;
        let src = r.take(16)?;
        let dst = r.take(16)?;

        // Walk Hop-by-Hop / Routing / Fragment / Destination-Options into
        // this layer (RFC 8200 §4); the final next-header value routes.
        let mut header_len = 40usize;
        let mut fragment_offset = 0u16;
        let mut ext_count = 0usize;
        while matches!(next_header, 0 | 43 | 44 | 60) {
            ext_count += 1;
            if ext_count > MAX_EXT_HEADERS {
                return Err(ParseError::Malformed("extension header chain too long"));
            }
            if next_header == 44 {
                // Fragment header: fixed 8 bytes.
                let inner_next = r.u8()?;
                let _reserved = r.u8()?;
                let offset_flags = r.u16_be()?;
                let _identification = r.u32_be()?;
                fragment_offset = offset_flags >> 3;
                next_header = inner_next;
                header_len += 8;
            } else {
                let inner_next = r.u8()?;
                let hdr_ext_len = r.u8()?;
                let ext_len = (usize::from(hdr_ext_len) + 1) * 8;
                let _body = r.take(ext_len - 2)?;
                next_header = inner_next;
                header_len += ext_len;
            }
        }

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(SRC_ADDR, Value::from(src));
            fields.insert(DST_ADDR, Value::from(dst));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(NEXT_HEADER, Value::U64(u64::from(next_header)));
            fields.insert(HOP_LIMIT, Value::U64(u64::from(hop_limit)));
            fields.insert(PAYLOAD_LEN, Value::U64(u64::from(payload_len)));
        }
        if ctx.depth() >= Depth::Full {
            fields.insert(
                TRAFFIC_CLASS,
                Value::U64(u64::from((ver_tc_fl >> 20) & 0xFF)),
            );
            fields.insert(FLOW_LABEL, Value::U64(u64::from(ver_tc_fl & 0xF_FFFF)));
        }

        // Non-first fragment: no transport header follows (as ipv4, D7).
        let hint = if fragment_offset > 0 {
            Hint::Terminal
        } else {
            Hint::Route(RouteId::IpProtocol(next_header))
        };
        Ok(ParsedLayer {
            header_len,
            fields,
            hint,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[
            RouteId::EtherType(0x86DD),
            RouteId::IpProtocol(41 /* 6-in-4 */),
        ]
    }

    fn has_probe(&self) -> bool {
        true
    }

    fn probe(&self, bytes: &[u8], _ctx: &ParseCtx) -> Option<Confidence> {
        let first = *bytes.first()?;
        if first >> 4 != 6 || bytes.len() < 40 {
            return None;
        }
        let payload_len = u16::from_be_bytes([*bytes.get(4)?, *bytes.get(5)?]);
        (40 + usize::from(payload_len) <= bytes.len()).then(|| Confidence::new(75))
    }

    fn stream_identity(&self) -> Option<&StreamIdentity> {
        Some(&IDENTITY)
    }
}
