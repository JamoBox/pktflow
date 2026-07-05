//! IGMP (06.3, RFC 2236): terminal, identity-less group-management
//! chatter riding on the IP conversation.

use pktflow_core::{
    ByteReader, Depth, FieldMap, FieldName, Hint, LayerPlugin, ParseCtx, ParseError, ParsedLayer,
    ProtocolName, RouteId, StreamIdentity, Value,
};

const TYPE: FieldName = "type";
const MAX_RESP: FieldName = "max_resp";
const GROUP_ADDR: FieldName = "group_addr";

pub struct Igmp;

impl LayerPlugin for Igmp {
    fn name(&self) -> ProtocolName {
        "igmp"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let igmp_type = r.u8()?;
        let max_resp = r.u8()?;
        let _checksum = r.u16_be()?;
        let group = r.take(4)?;

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Structural {
            fields.insert(TYPE, Value::U64(u64::from(igmp_type)));
            fields.insert(MAX_RESP, Value::U64(u64::from(max_resp)));
            fields.insert(GROUP_ADDR, Value::from(group));
        }

        Ok(ParsedLayer {
            header_len: 8,
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::IpProtocol(2)]
    }

    fn stream_identity(&self) -> Option<&StreamIdentity> {
        None
    }
}
