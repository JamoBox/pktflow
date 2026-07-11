//! NDP — Neighbor Discovery Protocol (11.3, RFC 4861; SLAAC Prefix
//! Information option per RFC 4862 §5.5.3): IPv6's ARP-equivalent, riding
//! inside ICMPv6 as five message types (RFC 4861 §4) rather than a
//! distinct IP protocol. `icmpv6` (11.3) already reads and terminates the
//! common 8-byte ICMPv6 header (type/code/checksum/4-byte type-specific
//! word) before routing here by type, so this plugin's own `bytes` start
//! immediately *after* that word — for Router Solicitation and Neighbor
//! Solicitation that word is pure Reserved padding and nothing is lost,
//! but Router Advertisement's flags/router-lifetime and Neighbor
//! Advertisement's flags live *inside* the word icmpv6 already consumed.
//! This plugin reads those back via a cross-layer lookup of icmpv6's own
//! `rest_of_header` field (FR-17) instead of re-decoding bytes it no
//! longer has — the dispatching layer's own extraction becomes this
//! layer's input, the same "trusts the router's decision" stance 11.3
//! documents for `msg_type` itself.
//!
//! Same identity-less, request/reply-chatter stance as ARP (06.3): no
//! stream of its own, activity rolls up onto the parent IPv6 conversation.

use pktflow_core::{
    ByteReader, Depth, FieldMap, FieldName, Hint, LayerPlugin, ParseCtx, ParseError, ParsedLayer,
    ProtocolName, RouteId, StreamIdentity, Value,
};

use crate::icmpv6;

const MSG_TYPE: FieldName = "msg_type";
const FLAGS: FieldName = "flags";
const TARGET_ADDRESS: FieldName = "target_address";
const SOURCE_LINK_ADDR: FieldName = "source_link_addr";
const TARGET_LINK_ADDR: FieldName = "target_link_addr";
const PREFIX_INFO: FieldName = "prefix_info";
const ROUTER_LIFETIME: FieldName = "router_lifetime";
const REACHABLE_TIME: FieldName = "reachable_time";
const RETRANS_TIMER: FieldName = "retrans_timer";

/// RFC 4861 §4.6 option types this plugin extracts; Redirected Header (4)
/// and MTU (5) are walked (so `header_len` stays correct) but not
/// individually surfaced — not in 11.3's field list for `ndp`.
const OPT_SOURCE_LINK_ADDR: u8 = 1;
const OPT_TARGET_LINK_ADDR: u8 = 2;
const OPT_PREFIX_INFORMATION: u8 = 3;

/// icmpv6's `rest_of_header` word, re-read for the two message types that
/// pack extra data into it. `None` below `Depth::Full` — that's where
/// icmpv6 itself gates the field (see the module doc) — in which case
/// `flags`/`router_lifetime` are simply omitted below, same as any other
/// depth-gated field.
fn icmpv6_rest(ctx: &ParseCtx) -> Option<[u8; 4]> {
    match ctx.field("icmpv6", icmpv6::REST_OF_HEADER)? {
        Value::Bytes(b) => <[u8; 4]>::try_from(b.as_slice()).ok(),
        _ => None,
    }
}

/// The dispatching type, re-read from icmpv6's own `type` field rather
/// than re-decided here (11.3's cross-layer-read stance). `None` only
/// when icmpv6 itself hasn't extracted `type` yet (`ctx.depth()` below
/// `Structural`, e.g. `Depth::None`/`Keys` with aggregation disabled) —
/// see [`Ndp::parse`]'s fallback for that case.
fn icmpv6_msg_type(ctx: &ParseCtx) -> Option<u8> {
    match ctx.field("icmpv6", icmpv6::TYPE)? {
        Value::U64(t) => u8::try_from(*t).ok(),
        _ => None,
    }
}

pub struct Ndp;

impl LayerPlugin for Ndp {
    fn name(&self) -> ProtocolName {
        "ndp"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let Some(msg_type) = icmpv6_msg_type(ctx) else {
            // Can't tell RS from RA from NS from NA from Redirect apart
            // without icmpv6's `type` — each has a different fixed-field
            // layout ahead of its options, so guessing risks misreading a
            // fixed field as a bogus option TLV. Decline to subdivide
            // instead: consume the rest of the ICMPv6 message as one
            // opaque, still-terminal layer. `Depth::None`/`Keys` promise
            // routing + length, not fields (01.3), and this plugin has no
            // flow-key fields to lose by doing so.
            return Ok(ParsedLayer {
                header_len: bytes.len(),
                fields: FieldMap::new(),
                hint: Hint::Terminal,
            });
        };

        let mut r = ByteReader::new(bytes);

        // RFC 4861 §4.3/§4.4/§4.5: NS, NA, and Redirect all carry a
        // 16-byte Target Address right after the word icmpv6 consumed;
        // RS (§4.1) and RA (§4.2) don't name a target at all.
        let target_address = if matches!(
            msg_type,
            icmpv6::NEIGHBOR_SOLICITATION | icmpv6::NEIGHBOR_ADVERTISEMENT | icmpv6::REDIRECT
        ) {
            Some(r.take(16)?)
        } else {
            None
        };
        // Redirect (§4.5) alone adds a second 16-byte address (the new
        // first-hop Destination Address) — walked to keep `header_len`
        // correct; not in 11.3's field list for this plugin.
        if msg_type == icmpv6::REDIRECT {
            let _destination_address = r.take(16)?;
        }
        // RA (§4.2) alone adds Reachable Time then Retrans Timer, 4 bytes
        // each, before options.
        let ra_timers = if msg_type == icmpv6::ROUTER_ADVERTISEMENT {
            Some((r.u32_be()?, r.u32_be()?))
        } else {
            None
        };

        // Options walk (§4.6): type(1) + length(1, 8-octet units
        // including this header) + value. RFC 4861 requires a zero-length
        // option to be discarded (never valid, a possible attack
        // signature); this plugin declines the same way, except for an
        // all-zero (type 0, length 0) pair — since no assigned NDP option
        // is ever type 0, that pair is read the way CDP (11.1) reads its
        // own unterminated TLV walk: trailing Ethernet minimum-frame
        // padding, not a TLV. NDP has no self-describing total length or
        // explicit end marker of its own (RFC 4861 §4.6): the options
        // section is bounded by the enclosing ICMPv6 message, so a
        // capture truncated exactly on an option boundary is
        // indistinguishable from a legitimately shorter message — the
        // same limitation CDP documents for its own walk. The
        // conformance fixtures below route around it by testing the
        // exhaustive truncation sweep only against zero-option messages,
        // where every cut lands inside a fixed-size read.
        let mut header_len = bytes.len() - r.remaining();
        let mut source_link_addr = None;
        let mut target_link_addr = None;
        let mut prefix_info = None;
        while r.remaining() >= 2 {
            let before = r.remaining();
            let opt_type = r.u8()?;
            let opt_len = r.u8()?;
            if opt_type == 0 && opt_len == 0 {
                header_len = bytes.len() - before;
                break;
            }
            if opt_len == 0 {
                return Err(ParseError::Malformed(
                    "NDP: option length is zero (RFC 4861 §4.6)",
                ));
            }
            let value = r.take(usize::from(opt_len) * 8 - 2)?;
            match opt_type {
                OPT_SOURCE_LINK_ADDR if source_link_addr.is_none() => {
                    source_link_addr = Some(Value::from(value));
                }
                OPT_TARGET_LINK_ADDR if target_link_addr.is_none() => {
                    target_link_addr = Some(Value::from(value));
                }
                OPT_PREFIX_INFORMATION if prefix_info.is_none() => {
                    prefix_info = Some(Value::from(value));
                }
                _ => {}
            }
            header_len = bytes.len() - r.remaining();
        }

        // RA's M/O(+H/Prf) byte and NA's R/S/O byte both live inside the
        // word icmpv6 already consumed (see the module doc); RA's router
        // lifetime rides the same word's trailing 16 bits.
        let rest = icmpv6_rest(ctx);
        let flags = match msg_type {
            icmpv6::ROUTER_ADVERTISEMENT => rest.map(|w| u64::from(w[1])),
            icmpv6::NEIGHBOR_ADVERTISEMENT => rest.map(|w| u64::from(w[0])),
            _ => None,
        };
        let router_lifetime = (msg_type == icmpv6::ROUTER_ADVERTISEMENT)
            .then(|| rest.map(|w| u64::from(u16::from_be_bytes([w[2], w[3]]))))
            .flatten();

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Structural {
            fields.insert(MSG_TYPE, Value::U64(u64::from(msg_type)));
            if let Some(f) = flags {
                fields.insert(FLAGS, Value::U64(f));
            }
            if let Some(addr) = target_address {
                fields.insert(TARGET_ADDRESS, Value::from(addr));
            }
        }
        if ctx.depth() >= Depth::Full {
            if let Some(v) = source_link_addr {
                fields.insert(SOURCE_LINK_ADDR, v);
            }
            if let Some(v) = target_link_addr {
                fields.insert(TARGET_LINK_ADDR, v);
            }
            if let Some(v) = prefix_info {
                fields.insert(PREFIX_INFO, v);
            }
            if let Some(lifetime) = router_lifetime {
                fields.insert(ROUTER_LIFETIME, Value::U64(lifetime));
            }
            if let Some((reachable, retrans)) = ra_timers {
                fields.insert(REACHABLE_TIME, Value::U64(u64::from(reachable)));
                fields.insert(RETRANS_TIMER, Value::U64(u64::from(retrans)));
            }
        }

        Ok(ParsedLayer {
            header_len,
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[
            RouteId::Custom {
                space: icmpv6::ICMPV6_TYPE_SPACE,
                id: icmpv6::ROUTER_SOLICITATION as u64,
            },
            RouteId::Custom {
                space: icmpv6::ICMPV6_TYPE_SPACE,
                id: icmpv6::ROUTER_ADVERTISEMENT as u64,
            },
            RouteId::Custom {
                space: icmpv6::ICMPV6_TYPE_SPACE,
                id: icmpv6::NEIGHBOR_SOLICITATION as u64,
            },
            RouteId::Custom {
                space: icmpv6::ICMPV6_TYPE_SPACE,
                id: icmpv6::NEIGHBOR_ADVERTISEMENT as u64,
            },
            RouteId::Custom {
                space: icmpv6::ICMPV6_TYPE_SPACE,
                id: icmpv6::REDIRECT as u64,
            },
        ]
    }

    fn stream_identity(&self) -> Option<&StreamIdentity> {
        None
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use pktflow_core::{LayerRecord, LinkType, PacketMeta};

    use super::*;

    fn meta(len: usize) -> PacketMeta {
        PacketMeta {
            timestamp: SystemTime::UNIX_EPOCH,
            caplen: len,
            origlen: len,
            link_type: LinkType::ETHERNET,
        }
    }

    /// A synthetic icmpv6 predecessor layer carrying exactly `type` and
    /// (optionally) `rest_of_header`, mirroring what the real `icmpv6`
    /// plugin would have extracted at `Depth::Full`.
    fn icmpv6_layer(icmp_type: u8, rest: Option<[u8; 4]>) -> LayerRecord {
        let mut fields = FieldMap::new();
        fields.insert(icmpv6::TYPE, Value::U64(u64::from(icmp_type)));
        if let Some(r) = rest {
            fields.insert(icmpv6::REST_OF_HEADER, Value::from(&r[..]));
        }
        LayerRecord {
            protocol: "icmpv6",
            offset: 14 + 40, // eth + ipv6, not load-bearing here
            header_len: 8,
            fields,
        }
    }

    fn parse(
        icmp_type: u8,
        rest: Option<[u8; 4]>,
        bytes: &[u8],
    ) -> Result<ParsedLayer, ParseError> {
        let outer = vec![icmpv6_layer(icmp_type, rest)];
        let m = meta(bytes.len());
        Ndp.parse(bytes, &ParseCtx::new(&outer, Depth::Full, &m))
    }

    #[test]
    fn router_solicitation_has_no_fixed_fields() {
        // RFC 4861 §4.1: nothing but options after the Reserved word
        // icmpv6 already consumed. A bare RS (no options) is valid.
        let parsed = parse(icmpv6::ROUTER_SOLICITATION, None, &[]).expect("bare RS");
        assert_eq!(parsed.header_len, 0);
        assert_eq!(parsed.fields.get(MSG_TYPE), Some(&Value::U64(133)));
        assert_eq!(parsed.hint, Hint::Terminal);
    }

    #[test]
    fn router_advertisement_reads_flags_and_lifetime_from_icmpv6_rest() {
        // §4.2: cur_hop_limit=64, M+O set, router_lifetime=1800 (the same
        // byte pattern 11.3's icmpv6 conformance fixture uses) — all of
        // it inside the word icmpv6 already consumed, not in `bytes`.
        let rest = [0x40, 0xC0, 0x07, 0x08];
        let reachable_retrans = [0x00, 0x00, 0x1D, 0x4C, 0x00, 0x00, 0x03, 0xE8];
        let parsed =
            parse(icmpv6::ROUTER_ADVERTISEMENT, Some(rest), &reachable_retrans).expect("bare RA");
        assert_eq!(parsed.header_len, 8);
        assert_eq!(parsed.fields.get(MSG_TYPE), Some(&Value::U64(134)));
        assert_eq!(parsed.fields.get(FLAGS), Some(&Value::U64(0xC0)));
        assert_eq!(parsed.fields.get(ROUTER_LIFETIME), Some(&Value::U64(1800)));
        assert_eq!(parsed.fields.get(REACHABLE_TIME), Some(&Value::U64(7500)));
        assert_eq!(parsed.fields.get(RETRANS_TIMER), Some(&Value::U64(1000)));
        assert_eq!(parsed.fields.get(TARGET_ADDRESS), None);
    }

    #[test]
    fn neighbor_solicitation_reads_target_address() {
        let target = [
            0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        let parsed = parse(icmpv6::NEIGHBOR_SOLICITATION, None, &target).expect("bare NS");
        assert_eq!(parsed.header_len, 16);
        assert_eq!(
            parsed.fields.get(TARGET_ADDRESS),
            Some(&Value::from(&target[..]))
        );
        assert_eq!(parsed.fields.get(FLAGS), None);
    }

    #[test]
    fn neighbor_advertisement_solicited_vs_gratuitous_flags() {
        let target = [
            0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02,
        ];

        // §4.4: R=0 S=1 O=1 — solicited response to an NS.
        let solicited = parse(
            icmpv6::NEIGHBOR_ADVERTISEMENT,
            Some([0x60, 0, 0, 0]),
            &target,
        )
        .expect("solicited NA");
        assert_eq!(solicited.fields.get(FLAGS), Some(&Value::U64(0x60)));

        // Gratuitous NA: R=0 S=0 O=1 (unsolicited cache update).
        let gratuitous = parse(
            icmpv6::NEIGHBOR_ADVERTISEMENT,
            Some([0x20, 0, 0, 0]),
            &target,
        )
        .expect("gratuitous NA");
        assert_eq!(gratuitous.fields.get(FLAGS), Some(&Value::U64(0x20)));
        assert_ne!(solicited.fields.get(FLAGS), gratuitous.fields.get(FLAGS));
    }

    #[test]
    fn redirect_skips_destination_address_but_keeps_target() {
        let mut bytes = vec![0xAA; 16]; // target address
        bytes.extend_from_slice(&[0xBB; 16]); // destination address
        let parsed = parse(icmpv6::REDIRECT, None, &bytes).expect("bare redirect");
        assert_eq!(parsed.header_len, 32);
        assert_eq!(
            parsed.fields.get(TARGET_ADDRESS),
            Some(&Value::from(&[0xAAu8; 16][..]))
        );
    }

    #[test]
    fn options_walk_extracts_link_addr_and_prefix_info() {
        // RS + Source Link-Layer Address option (§4.6.1: type 1, length 1
        // == 8 octets total).
        let mut rs = vec![1, 1];
        rs.extend_from_slice(&[0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E]);
        let parsed = parse(icmpv6::ROUTER_SOLICITATION, None, &rs).expect("RS + SLLA");
        assert_eq!(parsed.header_len, 8);
        assert_eq!(
            parsed.fields.get(SOURCE_LINK_ADDR),
            Some(&Value::from(&[0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E][..]))
        );

        // RA + Prefix Information option (RFC 4862 §5.5.3 SLAAC shape:
        // type 3, length 4 == 32 octets total; prefix_len=64, L+A set,
        // valid=2592000s, preferred=604800s, reserved2=0,
        // prefix=2001:db8::/64).
        let mut prefix_opt = vec![3, 4, 64, 0xC0];
        prefix_opt.extend_from_slice(&0x0027_8D00u32.to_be_bytes()); // valid lifetime
        prefix_opt.extend_from_slice(&0x0009_3A80u32.to_be_bytes()); // preferred lifetime
        prefix_opt.extend_from_slice(&[0; 4]); // reserved2
        prefix_opt.extend_from_slice(&[0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let mut ra = vec![0; 8]; // reachable_time + retrans_timer
        ra.extend_from_slice(&prefix_opt);
        let parsed = parse(
            icmpv6::ROUTER_ADVERTISEMENT,
            Some([64, 0xC0, 0x07, 0x08]),
            &ra,
        )
        .expect("RA + PIO");
        assert_eq!(parsed.header_len, ra.len());
        assert_eq!(
            parsed.fields.get(PREFIX_INFO),
            Some(&Value::from(&prefix_opt[2..][..]))
        );
    }

    #[test]
    fn trailing_padding_after_a_real_option_is_harmless() {
        // Same convention as CDP (11.1): a type=0/length=0 pair after a
        // real option is Ethernet minimum-frame padding, not a TLV, and
        // header_len excludes it.
        let mut rs = vec![1, 1, 0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E];
        rs.extend_from_slice(&[0, 0, 0, 0]);
        let parsed = parse(icmpv6::ROUTER_SOLICITATION, None, &rs).expect("RS + SLLA + padding");
        assert_eq!(parsed.header_len, 8);
    }

    #[test]
    fn zero_length_non_padding_option_declines() {
        let bytes = [OPT_TARGET_LINK_ADDR, 0, 0, 0, 0, 0];
        assert!(parse(icmpv6::ROUTER_SOLICITATION, None, &bytes).is_err());
    }

    #[test]
    fn truncated_fixed_fields_decline() {
        // NS needs a 16-byte target address; 15 is truncated.
        assert!(parse(icmpv6::NEIGHBOR_SOLICITATION, None, &[0xAA; 15]).is_err());
        // RA needs reachable_time + retrans_timer (8 bytes); 7 is truncated.
        assert!(parse(icmpv6::ROUTER_ADVERTISEMENT, Some([0; 4]), &[0; 7]).is_err());
    }

    #[test]
    fn unknown_dispatch_type_is_declined_by_the_caller_never_reached_here() {
        // icmpv6 only routes types 133..137 here (11.3); this plugin
        // trusts that and doesn't re-validate `msg_type`'s range. Nothing
        // to assert — documents the boundary rather than testing it.
    }

    #[test]
    fn missing_cross_layer_type_falls_back_to_an_opaque_terminal_layer() {
        // `Depth::None`/`Keys` with aggregation off: icmpv6 hasn't
        // extracted `type` yet, so this plugin can't subdivide. It still
        // must not panic or misparse — everything left is consumed
        // opaquely.
        let empty_outer: Vec<LayerRecord> = Vec::new();
        let bytes = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
        let m = meta(bytes.len());
        let parsed = Ndp
            .parse(&bytes, &ParseCtx::new(&empty_outer, Depth::None, &m))
            .expect("opaque fallback still succeeds");
        assert_eq!(parsed.header_len, bytes.len());
        assert!(parsed.fields.iter().next().is_none());
        assert_eq!(parsed.hint, Hint::Terminal);
    }
}
