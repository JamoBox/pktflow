//! PPP (11.5, RFC 1661) — the payload shape carried by a PPPoE session
//! (RFC 2516 §4.4: PPPoE strips HDLC framing/FCS before handing off, so
//! the payload starts directly at PPP's own Protocol field). This plugin
//! only ever sees that trimmed shape; it is reached exclusively via
//! `pppoe`'s `Hint::ByProtocol("ppp")` (module doc there), never through
//! a route claim of its own — `claims()` stays empty, matching `llc`'s
//! translation-layer pattern (11.1).
//!
//! RFC 1661 §2: the Protocol field is normally two octets, but a sender
//! that negotiated Protocol-Field-Compression (RFC 1661 §6.5) may send a
//! single octet instead. The two forms are self-describing on the wire:
//! every valid two-octet value has an *even* high-order octet, and every
//! valid one-octet (compressed) value is *odd* — so the low bit of the
//! first octet alone tells this plugin which shape it's looking at, no
//! side channel required.
//!
//! `protocol == 0x0021` (IPv4, RFC 1332) and `protocol == 0x0057` (IPv6,
//! RFC 5072) are **translated**, not reused, into `ipv4`/`ipv6`'s real
//! `EtherType` routes (06.3) — `Hint::Route` only requires the *target*
//! id to be real, so those plugins need zero changes to work over PPP.
//! Every other Protocol value (LCP `0xC021`, PAP `0xC023`, CHAP `0xC223`,
//! and the rest of RFC 1661's control-protocol space) stops `Terminal`:
//! decoding those control protocols is Tier 2 (11.5's domain spec).

use pktflow_core::{
    ByteReader, Depth, FieldMap, FieldName, Hint, LayerPlugin, ParseCtx, ParseError, ParsedLayer,
    ProtocolName, RouteId, StreamIdentity, Value,
};

const PROTOCOL: FieldName = "protocol";

/// RFC 1332 §1 / RFC 5072 §1: the two Protocol values this plugin can
/// translate into an existing route.
const PROTOCOL_IPV4: u32 = 0x0021;
const PROTOCOL_IPV6: u32 = 0x0057;

pub struct Ppp;

impl LayerPlugin for Ppp {
    fn name(&self) -> ProtocolName {
        "ppp"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let first = r.u8()?;
        let protocol = if first & 0x01 == 1 {
            // Compressed one-octet form (RFC 1661 §6.5): the value *is*
            // the low-order octet, high-order octet implicitly 0x00.
            u32::from(first)
        } else {
            let second = r.u8()?;
            u32::from_be_bytes([0, 0, first, second])
        };

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Structural {
            fields.insert(PROTOCOL, Value::U64(u64::from(protocol)));
        }

        let hint = match protocol {
            PROTOCOL_IPV4 => Hint::Route(RouteId::EtherType(0x0800)),
            PROTOCOL_IPV6 => Hint::Route(RouteId::EtherType(0x86DD)),
            _ => Hint::Terminal,
        };

        Ok(ParsedLayer {
            header_len: bytes.len() - r.remaining(),
            fields,
            hint,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        // Reached only via `pppoe`'s `Hint::ByProtocol("ppp")` (module
        // doc) — no route id names this protocol.
        &[]
    }

    fn stream_identity(&self) -> Option<&StreamIdentity> {
        // A translation layer, like `llc` (11.1): it qualifies whatever
        // follows rather than forming its own conversation.
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

    fn ctx<'a>(depth: Depth, m: &'a PacketMeta) -> ParseCtx<'a> {
        ParseCtx::new(&[], depth, m)
    }

    #[test]
    fn uncompressed_ipv4_routes_to_the_real_ethertype() {
        let bytes = vec![0x00, 0x21, 0x45, 0x00]; // Protocol=0x0021, then a would-be IPv4 header
        let m = meta(bytes.len());
        let parsed = Ppp
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid PPP IPv4 frame");
        assert_eq!(parsed.header_len, 2);
        assert_eq!(parsed.hint, Hint::Route(RouteId::EtherType(0x0800)));
        assert_eq!(parsed.fields.get(PROTOCOL), Some(&Value::U64(0x0021)));
    }

    #[test]
    fn uncompressed_ipv6_routes_to_the_real_ethertype() {
        let bytes = vec![0x00, 0x57, 0x60, 0x00];
        let m = meta(bytes.len());
        let parsed = Ppp
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid PPP IPv6 frame");
        assert_eq!(parsed.header_len, 2);
        assert_eq!(parsed.hint, Hint::Route(RouteId::EtherType(0x86DD)));
        assert_eq!(parsed.fields.get(PROTOCOL), Some(&Value::U64(0x0057)));
    }

    #[test]
    fn compressed_single_octet_ipv4_is_recognized() {
        // RFC 1661 §6.5: PFC lets 0x0021 collapse to its odd low octet
        // alone, no high-order 0x00 octet transmitted.
        let bytes = vec![0x21, 0x45, 0x00];
        let m = meta(bytes.len());
        let parsed = Ppp
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid compressed PPP IPv4 frame");
        assert_eq!(parsed.header_len, 1);
        assert_eq!(parsed.hint, Hint::Route(RouteId::EtherType(0x0800)));
        assert_eq!(parsed.fields.get(PROTOCOL), Some(&Value::U64(0x0021)));
    }

    #[test]
    fn lcp_control_protocol_stops_terminal() {
        let bytes = vec![0xC0, 0x21, 0x01, 0x00]; // LCP Configure-Request, not decoded (Tier 2)
        let m = meta(bytes.len());
        let parsed = Ppp
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid PPP LCP frame");
        assert_eq!(parsed.header_len, 2);
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(PROTOCOL), Some(&Value::U64(0xC021)));
    }

    #[test]
    fn structural_field_absent_below_structural_depth() {
        let bytes = vec![0x00, 0x21];
        let m = meta(bytes.len());
        let parsed = Ppp.parse(&bytes, &ctx(Depth::Keys, &m)).expect("valid");
        assert!(parsed.fields.is_empty());
    }

    #[test]
    fn truncated_uncompressed_frame_declines() {
        // First octet even (0x00) commits this plugin to the two-octet
        // form; a lone first octet must decline, not guess at compression.
        let m = meta(1);
        assert!(Ppp.parse(&[0x00], &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn empty_input_declines() {
        let m = meta(0);
        assert!(Ppp.parse(&[], &ctx(Depth::Full, &m)).is_err());
    }
}
