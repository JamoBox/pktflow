//! ICMPv4 (06.3, RFC 792): terminal — the payload quotes the offending
//! packet, and parsing quoted packets is v2. The parent IP conversation
//! carries the stats.

use pktflow_core::{
    ByteReader, Depth, FieldMap, FieldName, Hint, LayerPlugin, ParseCtx, ParseError, ParsedLayer,
    ProtocolName, RouteId, StreamIdentity, Value,
};

const TYPE: FieldName = "type";
const CODE: FieldName = "code";
const REST_OF_HEADER: FieldName = "rest_of_header";

pub struct Icmpv4;

impl LayerPlugin for Icmpv4 {
    fn name(&self) -> ProtocolName {
        "icmpv4"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let icmp_type = r.u8()?;
        let code = r.u8()?;
        let _checksum = r.u16_be()?;
        let rest = r.take(4)?;

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Structural {
            fields.insert(TYPE, Value::U64(u64::from(icmp_type)));
            fields.insert(CODE, Value::U64(u64::from(code)));
        }
        if ctx.depth() >= Depth::Full {
            fields.insert(REST_OF_HEADER, Value::from(rest));
        }

        Ok(ParsedLayer {
            header_len: 8,
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::IpProtocol(1)]
    }

    fn stream_identity(&self) -> Option<&StreamIdentity> {
        None
    }
}
