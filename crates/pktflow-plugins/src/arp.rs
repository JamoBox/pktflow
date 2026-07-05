//! ARP (06.3, RFC 826): request/reply chatter, not a conversation —
//! identity-less and terminal. Its packets count into the parent MAC
//! conversation; per-MAC ARP summaries are a documented v1 non-goal.

use pktflow_core::{
    ByteReader, Depth, FieldMap, FieldName, Hint, LayerPlugin, ParseCtx, ParseError, ParsedLayer,
    ProtocolName, RouteId, StreamIdentity, Value,
};

const OPCODE: FieldName = "opcode";
const SENDER_MAC: FieldName = "sender_mac";
const SENDER_IP: FieldName = "sender_ip";
const TARGET_MAC: FieldName = "target_mac";
const TARGET_IP: FieldName = "target_ip";

pub struct Arp;

impl LayerPlugin for Arp {
    fn name(&self) -> ProtocolName {
        "arp"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let _htype = r.u16_be()?;
        let _ptype = r.u16_be()?;
        let hlen = r.u8()?;
        let plen = r.u8()?;
        if hlen == 0 || plen == 0 {
            return Err(ParseError::Malformed("zero address length"));
        }
        let opcode = r.u16_be()?;
        let sender_mac = r.take(usize::from(hlen))?;
        let sender_ip = r.take(usize::from(plen))?;
        let target_mac = r.take(usize::from(hlen))?;
        let target_ip = r.take(usize::from(plen))?;

        // Structural floor: no identity, so no Keys tier exists (06.3).
        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Structural {
            fields.insert(OPCODE, Value::U64(u64::from(opcode)));
            fields.insert(SENDER_MAC, Value::from(sender_mac));
            fields.insert(SENDER_IP, Value::from(sender_ip));
            fields.insert(TARGET_MAC, Value::from(target_mac));
            fields.insert(TARGET_IP, Value::from(target_ip));
        }

        Ok(ParsedLayer {
            header_len: 8 + 2 * (usize::from(hlen) + usize::from(plen)),
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::EtherType(0x0806)]
    }

    fn stream_identity(&self) -> Option<&StreamIdentity> {
        None
    }
}
