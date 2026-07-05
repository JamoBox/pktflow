//! UDP (06.4, RFC 768): streams with candidate-port routing. This is the
//! gate's front line — unclaimed ports stop dissection (03.4), which is
//! exactly what keeps encrypted payloads from fabricating streams.

use pktflow_core::{
    ByteReader, Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx,
    ParseError, ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId, StreamIdentity, Value,
};
use smallvec::SmallVec;

const SRC_PORT: FieldName = "src_port";
const DST_PORT: FieldName = "dst_port";
const LENGTH: FieldName = "length";
const CHECKSUM: FieldName = "checksum";

static KEY: &[KeyField] = &[KeyField {
    a: SRC_PORT,
    b: Some(DST_PORT),
}];
static ROLLUPS: &[RollupSpec] = &[RollupSpec {
    field: LENGTH,
    kind: RollupKind::Sample,
}];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None, // UDP has no session semantics
    rollups: ROLLUPS,
};

pub struct Udp;

impl LayerPlugin for Udp {
    fn name(&self) -> ProtocolName {
        "udp"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let src_port = r.u16_be()?;
        let dst_port = r.u16_be()?;
        let length = r.u16_be()?;
        let checksum = r.u16_be()?;

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(SRC_PORT, Value::U64(u64::from(src_port)));
            fields.insert(DST_PORT, Value::U64(u64::from(dst_port)));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(LENGTH, Value::U64(u64::from(length)));
        }
        if ctx.depth() >= Depth::Full {
            fields.insert(CHECKSUM, Value::U64(u64::from(checksum)));
        }

        Ok(ParsedLayer {
            header_len: 8,
            fields,
            hint: Hint::Candidates(SmallVec::from_slice(&[
                RouteId::UdpPort(dst_port),
                RouteId::UdpPort(src_port),
            ])),
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::IpProtocol(17)]
    }

    // No probe: UDP is 8 unguessable bytes; heuristically claiming it
    // would undermine the gate (06.4).

    fn stream_identity(&self) -> Option<&StreamIdentity> {
        Some(&IDENTITY)
    }
}
