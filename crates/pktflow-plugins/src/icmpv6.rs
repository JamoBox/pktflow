//! ICMPv6 (11.3, RFC 4443 §2.1): the dispatch layer. Basic error/echo types
//! (Destination Unreachable, Packet Too Big, Time Exceeded, Parameter
//! Problem, Echo Request/Reply) terminate here — same "payload quotes the
//! offending packet, parsing quoted packets is v2" stance as icmpv4
//! (06.3). Neighbor Discovery (RFC 4861) and MLD (RFC 2710 / RFC 3810)
//! message types are ICMPv6 types by definition, not separate IP
//! protocols, so they route onward by type via a plugin-defined
//! `icmpv6_type` space rather than a real IP-protocol number.

use pktflow_core::{
    ByteReader, Depth, FieldMap, FieldName, Hint, LayerPlugin, ParseCtx, ParseError, ParsedLayer,
    ProtocolName, RouteId, StreamIdentity, Value,
};

// `pub(crate)`: `ndp`/`mld` (11.3) re-read this via a cross-layer lookup
// (FR-17) instead of re-deciding their own dispatch.
pub(crate) const TYPE: FieldName = "type";
const CODE: FieldName = "code";
// `pub(crate)`: the dispatch targets (`ndp`, `mld`, 11.3) read this back
// via a cross-layer lookup (FR-17) rather than re-deciding their own
// dispatch — see ndp.rs's module doc.
pub(crate) const REST_OF_HEADER: FieldName = "rest_of_header";

/// The id space this plugin mints for NDP/MLD dispatch (11.3): ICMPv6
/// message types that are themselves distinct protocols, not a real IP
/// protocol number (there isn't one — RFC 4443/4861/2710/3810 all live
/// inside `IpProtocol(58)`).
pub(crate) const ICMPV6_TYPE_SPACE: &str = "icmpv6_type";

// RFC 4443 §3 (error messages).
const DESTINATION_UNREACHABLE: u8 = 1;
const PACKET_TOO_BIG: u8 = 2;
const TIME_EXCEEDED: u8 = 3;
const PARAMETER_PROBLEM: u8 = 4;
// RFC 4443 §4 (informational: echo).
const ECHO_REQUEST: u8 = 128;
const ECHO_REPLY: u8 = 129;
// RFC 2710 §3 / RFC 3810 §5 (MLDv1/v2, informational types reused as MLD).
pub(crate) const MLD_QUERY: u8 = 130;
pub(crate) const MLD_V1_REPORT: u8 = 131;
pub(crate) const MLD_DONE: u8 = 132;
pub(crate) const MLD_V2_REPORT: u8 = 143;
// RFC 4861 §4 (Neighbor Discovery, informational types reused as NDP).
// `pub(crate)`: shared with ndp.rs so the message-type space has one
// source of truth instead of two copies of the same magic numbers.
pub(crate) const ROUTER_SOLICITATION: u8 = 133;
pub(crate) const ROUTER_ADVERTISEMENT: u8 = 134;
pub(crate) const NEIGHBOR_SOLICITATION: u8 = 135;
pub(crate) const NEIGHBOR_ADVERTISEMENT: u8 = 136;
pub(crate) const REDIRECT: u8 = 137;

pub struct Icmpv6;

impl LayerPlugin for Icmpv6 {
    fn name(&self) -> ProtocolName {
        "icmpv6"
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

        let hint = match icmp_type {
            ROUTER_SOLICITATION
            | ROUTER_ADVERTISEMENT
            | NEIGHBOR_SOLICITATION
            | NEIGHBOR_ADVERTISEMENT
            | REDIRECT
            | MLD_QUERY
            | MLD_V1_REPORT
            | MLD_DONE
            | MLD_V2_REPORT => Hint::Route(RouteId::Custom {
                space: ICMPV6_TYPE_SPACE,
                id: u64::from(icmp_type),
            }),
            // Named error/echo types terminate here (icmpv4's stance, 06.3).
            DESTINATION_UNREACHABLE
            | PACKET_TOO_BIG
            | TIME_EXCEEDED
            | PARAMETER_PROBLEM
            | ECHO_REQUEST
            | ECHO_REPLY => Hint::Terminal,
            // Everything else RFC 4443 doesn't define a follow-on
            // dissector for terminates the same way.
            _ => Hint::Terminal,
        };

        Ok(ParsedLayer {
            header_len: 8,
            fields,
            hint,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::IpProtocol(58)]
    }

    fn stream_identity(&self) -> Option<&StreamIdentity> {
        None
    }
}
