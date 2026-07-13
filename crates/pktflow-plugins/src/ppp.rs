//! PPP (11.5, RFC 1661) — reached only from `pppoe`'s Session-Data
//! (`code == 0x00`) branch via `Hint::ByProtocol("ppp")`, never through the
//! router's route-id lookup (RFC 2516 §4.4: a PPPoE session's payload is a
//! PPP frame with HDLC framing/FCS and the Address/Control bytes already
//! stripped, so it starts directly at PPP's own Protocol field — this
//! plugin never needs to know PPPoE exists).
//!
//! **Protocol field encoding (RFC 1661 §2).** The field is one or two
//! octets. Every real (uncompressed) two-octet Protocol value has an even
//! high-order octet (network-layer `0x00xx`/`0x02xx`, NCP `0x80xx`, LCP/
//! auth `0xC0xx`/`0xC2xx` — RFC 1661 Appendix, IANA's PPP DLL Protocol
//! Numbers registry). When Protocol-Field-Compression is negotiated (only
//! ever legal for values `0x0000`-`0x00FF`, whose low-order octet is odd),
//! the high `0x00` octet is dropped and the single remaining octet is sent
//! alone. A receiver tells the two apart by the first octet's parity: odd
//! -> complete compressed 1-octet field; even -> a second octet follows
//! (RFC 1661 §2, "the octet ... is odd"). Both shapes appear in real
//! captures depending on whether the peers' LCP negotiation enabled PFC,
//! so this plugin decodes both rather than assuming the two-octet form.
//!
//! **Translation, not reuse (11.5's domain spec).** `protocol == 0x0021`
//! (IPv4, RFC 1332) and `== 0x0057` (IPv6, RFC 5072) each translate to the
//! matching `RouteId::EtherType` and hand off via `Hint::Route` — the
//! target route id is real (`ipv4`/`ipv6` already claim it, 06.3), but
//! nothing in *this* header literally contains an EtherType value the way
//! GRE/Geneve's `protocol_type` coincidentally does (06.5/11.5). This is
//! what lets `pppoe -> ppp -> ipv4` reuse 06.3's `ipv4` plugin completely
//! unmodified: `claims()` there never has to hear about PPP. Every other
//! Protocol value (LCP `0xC021`, PAP `0xC023`, CHAP `0xC223`, IPCP
//! `0x8021`, ...) is control/negotiation traffic outside this file's scope
//! (Tier 2, 11's README taxonomy) and stops `Terminal`.
//!
//! No stream identity: like `llc` (11.1), this is a pure translation
//! layer, not a conversation source.

use pktflow_core::{
    ByteReader, Depth, FieldMap, FieldName, Hint, LayerPlugin, ParseCtx, ParseError, ParsedLayer,
    ProtocolName, RouteId, StreamIdentity, Value,
};

const PROTOCOL: FieldName = "protocol";

/// RFC 1332: IP over PPP.
const PROTO_IP: u16 = 0x0021;
/// RFC 5072: IPv6 over PPP.
const PROTO_IPV6: u16 = 0x0057;

pub struct Ppp;

impl LayerPlugin for Ppp {
    fn name(&self) -> ProtocolName {
        "ppp"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let first = r.u8()?;
        let (protocol, header_len) = if first & 0x01 == 1 {
            // Compressed 1-octet form (§2): implicit high octet 0x00.
            (u16::from(first), 1)
        } else {
            let second = r.u8()?;
            (u16::from_be_bytes([first, second]), 2)
        };

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Structural {
            fields.insert(PROTOCOL, Value::U64(u64::from(protocol)));
        }

        let hint = match protocol {
            PROTO_IP => Hint::Route(RouteId::EtherType(0x0800)),
            PROTO_IPV6 => Hint::Route(RouteId::EtherType(0x86DD)),
            _ => Hint::Terminal,
        };

        Ok(ParsedLayer {
            header_len,
            fields,
            hint,
        })
    }

    // No `claims()` override: `ppp` is reached exclusively by name via
    // `pppoe`'s `Hint::ByProtocol("ppp")` (module doc), never through the
    // router's route-id lookup, so the default empty claim set is correct
    // — not an oversight (see `pppoe`'s Hint row, 11.5's domain spec).

    fn stream_identity(&self) -> Option<&StreamIdentity> {
        None
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use pktflow_core::{LinkType, PacketMeta};

    use super::*;

    fn meta(len: usize) -> PacketMeta {
        PacketMeta {
            timestamp: SystemTime::UNIX_EPOCH,
            caplen: len,
            origlen: len,
            link_type: LinkType::ETHERNET,
        }
    }

    fn ctx(depth: Depth, meta: &PacketMeta) -> ParseCtx<'_> {
        ParseCtx::new(&[], depth, meta)
    }

    #[test]
    fn uncompressed_ipv4_protocol_routes_to_ethertype_0800() {
        let bytes = [0x00, 0x21, 0xDE, 0xAD];
        let m = meta(bytes.len());
        let parsed = Ppp
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid PPP frame");
        assert_eq!(parsed.header_len, 2);
        assert_eq!(parsed.fields.get(PROTOCOL), Some(&Value::U64(0x0021)));
        assert_eq!(parsed.hint, Hint::Route(RouteId::EtherType(0x0800)));
    }

    #[test]
    fn uncompressed_ipv6_protocol_routes_to_ethertype_86dd() {
        let bytes = [0x00, 0x57, 0x60, 0x00];
        let m = meta(bytes.len());
        let parsed = Ppp
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid PPP frame");
        assert_eq!(parsed.header_len, 2);
        assert_eq!(parsed.hint, Hint::Route(RouteId::EtherType(0x86DD)));
    }

    #[test]
    fn lcp_protocol_stops_terminal() {
        let bytes = [0xC0, 0x21, 0x01, 0x00]; // LCP Configure-Request
        let m = meta(bytes.len());
        let parsed = Ppp
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid PPP frame");
        assert_eq!(parsed.fields.get(PROTOCOL), Some(&Value::U64(0xC021)));
        assert_eq!(parsed.hint, Hint::Terminal);
    }

    #[test]
    fn compressed_single_octet_ipv4_protocol_decodes_the_implicit_high_octet() {
        // PFC negotiated: 0x0021 sent as the single odd octet 0x21.
        let bytes = [0x21, 0xDE, 0xAD];
        let m = meta(bytes.len());
        let parsed = Ppp
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid compressed PPP frame");
        assert_eq!(parsed.header_len, 1);
        assert_eq!(parsed.fields.get(PROTOCOL), Some(&Value::U64(0x0021)));
        assert_eq!(parsed.hint, Hint::Route(RouteId::EtherType(0x0800)));
    }

    #[test]
    fn structural_depth_omits_protocol_field() {
        let bytes = [0x00, 0x21, 0xDE, 0xAD];
        let m = meta(bytes.len());
        let parsed = Ppp
            .parse(&bytes, &ctx(Depth::Keys, &m))
            .expect("valid PPP frame");
        assert_eq!(parsed.fields.get(PROTOCOL), None);
    }

    #[test]
    fn truncated_uncompressed_frame_declines() {
        // 0x00 alone: even octet, needs a second byte that isn't there.
        assert!(Ppp.parse(&[0x00], &ctx(Depth::Full, &meta(1))).is_err());
        assert!(Ppp.parse(&[], &ctx(Depth::Full, &meta(0))).is_err());
    }
}
