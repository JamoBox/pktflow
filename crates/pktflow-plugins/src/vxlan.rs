//! VXLAN (06.5, RFC 7348): the inner protocol is *fixed* — always an
//! Ethernet frame — so this is the `ByProtocol` direct-by-name dispatch
//! demonstration (Hint kind 3, FR-11).

use pktflow_core::{
    ByteReader, Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx,
    ParseError, ParsedLayer, ProtocolName, RouteId, StreamIdentity, Value,
};

const VNI: FieldName = "vni";
const FLAGS: FieldName = "flags";

/// RFC 7348 §5: the I flag must be set for a valid VNI.
const I_BIT: u8 = 0x08;

static KEY: &[KeyField] = &[KeyField {
    a: VNI,
    b: None, // shared qualifier: one stream per VNI
}];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: &[],
};

pub struct Vxlan;

impl LayerPlugin for Vxlan {
    fn name(&self) -> ProtocolName {
        "vxlan"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let flags = r.u8()?;
        if flags & I_BIT == 0 {
            return Err(ParseError::Malformed("VXLAN I flag not set"));
        }
        let _reserved1 = r.take(3)?;
        let vni_bytes = r.take(3)?;
        let _reserved2 = r.u8()?;
        let vni = vni_bytes
            .iter()
            .fold(0u64, |acc, &b| (acc << 8) | u64::from(b));

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(VNI, Value::U64(vni));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(FLAGS, Value::U64(u64::from(flags)));
        }

        Ok(ParsedLayer {
            header_len: 8,
            fields,
            // VXLAN always wraps Ethernet: dispatch by name, no route
            // lookup at all.
            hint: Hint::ByProtocol("ethernet"),
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::UdpPort(4789)]
    }

    fn stream_identity(&self) -> Option<&StreamIdentity> {
        Some(&IDENTITY)
    }
}
