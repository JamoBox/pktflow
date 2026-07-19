//! Ethernet II (06.2): the capture entry point. MAC conversations are
//! FR-21's first demonstration.

use pktflow_core::{
    ByteReader, Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx,
    ParseError, ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId, StreamIdentity, Value,
};

const SRC_MAC: FieldName = "src_mac";
const DST_MAC: FieldName = "dst_mac";
const ETHERTYPE: FieldName = "ethertype";

/// Values below this in the type/length slot are 802.3 lengths, not
/// EtherTypes (IEEE 802.3-2018 §3.2.6).
const MIN_ETHERTYPE: u16 = 0x0600;

static KEY: &[KeyField] = &[KeyField {
    a: SRC_MAC,
    b: Some(DST_MAC),
}];
static ROLLUPS: &[RollupSpec] = &[RollupSpec {
    field: ETHERTYPE,
    kind: RollupKind::Accumulate, // protocols seen inside this MAC pair
}];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: ROLLUPS,
};

pub struct Ethernet;

impl LayerPlugin for Ethernet {
    fn name(&self) -> ProtocolName {
        "ethernet"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let dst = r.take(6)?;
        let src = r.take(6)?;
        let ethertype = r.u16_be()?;

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(SRC_MAC, Value::from(src));
            fields.insert(DST_MAC, Value::from(dst));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(ETHERTYPE, Value::U64(u64::from(ethertype)));
        }

        // Below 0x0600 the type/length slot is deterministically an 802.3
        // length (IEEE 802.3-2018 §3.2.6), never a real EtherType: the
        // frame is always LLC-framed, so this names a route rather than
        // guessing (`llc`, 11.1, claims `eth_llc_frame`).
        let hint = if ethertype >= MIN_ETHERTYPE {
            Hint::Route(RouteId::EtherType(ethertype))
        } else {
            Hint::Route(RouteId::Custom {
                space: "eth_llc_frame",
                id: 0,
            })
        };
        Ok(ParsedLayer {
            header_len: 14,
            fields,
            hint,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::LinkType(1 /* DLT_EN10MB */)]
    }

    // No probe: the link entry is explicit by link type (06.2).

    fn stream_identity(&self) -> Option<&StreamIdentity> {
        Some(&IDENTITY)
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use pktflow_core::{LinkType, PacketMeta};

    use super::*;

    // Ethernet II frame header, IEEE 802.3 layout (dst, src, type):
    // dst 00:1b:44:11:3a:b7, src 00:1a:2b:3c:4d:5e, EtherType 0x0800.
    const FRAME: [u8; 14] = [
        0x00, 0x1B, 0x44, 0x11, 0x3A, 0xB7, // dst
        0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E, // src
        0x08, 0x00, // IPv4
    ];

    fn parse(bytes: &[u8]) -> Result<ParsedLayer, ParseError> {
        let meta = PacketMeta {
            timestamp: SystemTime::UNIX_EPOCH,
            caplen: bytes.len(),
            origlen: bytes.len(),
            link_type: LinkType::ETHERNET,
        };
        Ethernet.parse(bytes, &ParseCtx::new(&[], Depth::Full, &meta))
    }

    #[test]
    fn parses_the_fixture_frame() {
        let parsed = parse(&FRAME).expect("valid frame");
        assert_eq!(parsed.header_len, 14);
        assert_eq!(
            parsed.fields.get(SRC_MAC),
            Some(&Value::from(&FRAME[6..12]))
        );
        assert_eq!(parsed.fields.get(DST_MAC), Some(&Value::from(&FRAME[..6])));
        assert_eq!(parsed.fields.get(ETHERTYPE), Some(&Value::U64(0x0800)));
        assert_eq!(parsed.hint, Hint::Route(RouteId::EtherType(0x0800)));
    }

    #[test]
    fn truncated_at_13_bytes_declines() {
        assert!(parse(&FRAME[..13]).is_err());
    }

    #[test]
    fn ieee_802_3_length_field_routes_to_the_llc_frame_space() {
        let mut frame = FRAME;
        frame[12] = 0x00;
        frame[13] = 0x2E; // 46: a length, not an EtherType
        assert_eq!(
            parse(&frame).expect("parses").hint,
            Hint::Route(RouteId::Custom {
                space: "eth_llc_frame",
                id: 0
            })
        );
    }
}
