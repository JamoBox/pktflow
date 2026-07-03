//! 802.1Q VLAN (06.2): the canonical identity-less pass-through layer —
//! a tag qualifies the MAC conversation rather than forming its own
//! stream (02.4). QinQ stacks parse as two vlan layers naturally.

use pktflow_core::{
    ByteReader, Depth, FieldMap, FieldName, Hint, LayerPlugin, ParseCtx, ParseError, ParsedLayer,
    ProtocolName, RouteId, StreamIdentity, Value,
};

// Extracted at Keys for cross-layer readers; harmless without identity.
const VLAN_ID: FieldName = "vlan_id";
const PCP: FieldName = "pcp";
const DEI: FieldName = "dei";
const ETHERTYPE: FieldName = "ethertype";

pub struct Vlan;

impl LayerPlugin for Vlan {
    fn name(&self) -> ProtocolName {
        "vlan"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        // The TPID was the outer layer's ethertype; the 4-byte tag body is
        // TCI (pcp:3 dei:1 vid:12) + the inner ethertype.
        let tci = r.u16_be()?;
        let inner_ethertype = r.u16_be()?;

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(VLAN_ID, Value::U64(u64::from(tci & 0x0FFF)));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(PCP, Value::U64(u64::from(tci >> 13)));
            fields.insert(DEI, Value::Bool((tci >> 12) & 1 == 1));
            fields.insert(ETHERTYPE, Value::U64(u64::from(inner_ethertype)));
        }

        // Route on the inner ethertype — including 0x8100 again, which is
        // exactly how QinQ stacks with zero special-casing.
        Ok(ParsedLayer {
            header_len: 4,
            fields,
            hint: Hint::Route(RouteId::EtherType(inner_ethertype)),
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[
            RouteId::EtherType(0x8100),
            RouteId::EtherType(0x88A8), // QinQ S-tag
        ]
    }

    /// Identity-less by design (06.2): per-VLAN conversation splitting is
    /// a v2 decision; the tag rides on the MAC conversation.
    fn stream_identity(&self) -> Option<&StreamIdentity> {
        None
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use pktflow_core::{LinkType, PacketMeta};

    use super::*;

    // 802.1Q tag body: pcp=5, dei=0, vid=100, inner EtherType IPv4.
    // TCI = 0b101_0_000001100100 = 0xA064.
    const TAG: [u8; 4] = [0xA0, 0x64, 0x08, 0x00];

    fn parse(bytes: &[u8]) -> Result<ParsedLayer, ParseError> {
        let meta = PacketMeta {
            timestamp: SystemTime::UNIX_EPOCH,
            caplen: bytes.len(),
            origlen: bytes.len(),
            link_type: LinkType::ETHERNET,
        };
        Vlan.parse(bytes, &ParseCtx::new(&[], Depth::Full, &meta))
    }

    #[test]
    fn parses_the_fixture_tag() {
        let parsed = parse(&TAG).expect("valid tag");
        assert_eq!(parsed.header_len, 4);
        assert_eq!(parsed.fields.get(VLAN_ID), Some(&Value::U64(100)));
        assert_eq!(parsed.fields.get(PCP), Some(&Value::U64(5)));
        assert_eq!(parsed.fields.get(DEI), Some(&Value::Bool(false)));
        assert_eq!(parsed.fields.get(ETHERTYPE), Some(&Value::U64(0x0800)));
        assert_eq!(parsed.hint, Hint::Route(RouteId::EtherType(0x0800)));
    }

    #[test]
    fn truncated_mid_tag_declines() {
        // The 06.2 "17 bytes total" case: eth took 14, the tag has 3 left.
        assert!(parse(&TAG[..3]).is_err());
    }
}
