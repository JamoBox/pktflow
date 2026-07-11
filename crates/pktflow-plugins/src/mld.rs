//! MLD — Multicast Listener Discovery (11.3: MLDv1 RFC 2710, MLDv2
//! RFC 3810 §5): IPv6's IGMP-equivalent (06.3's `igmp`), riding inside
//! ICMPv6 as four message types (Query 130, MLDv1 Report 131, Done 132,
//! MLDv2 Report 143) rather than a distinct IP protocol — the same
//! "message type, not protocol number" shape 11.3 already documents for
//! `ndp`. `icmpv6` (11.3) reads and terminates the common 8-byte ICMPv6
//! header (type/code/checksum/4-byte type-specific word) before routing
//! here by type, so this plugin's own `bytes` start immediately *after*
//! that word.
//!
//! For Query/MLDv1-Report/Done (RFC 2710 §3) that word is
//! `Maximum Response Delay` (16 bits) + `Reserved` (16 bits) — read back
//! via a cross-layer lookup of icmpv6's own `rest_of_header` (FR-17),
//! exactly ndp's stance for the fields packed into the word it no longer
//! has. For MLDv2 Report (RFC 3810 §5.2) the same word is `Reserved` +
//! `Nr of Mcast Address Records (M)`; only `M` is read back, there is no
//! response-delay concept on a report.
//!
//! Identity-less, mirroring IGMP exactly (06.3: "Identity: None") — group
//! membership chatter rolls up onto the parent IPv6 conversation, not a
//! stream of its own.

use pktflow_core::{
    ByteReader, Depth, FieldMap, FieldName, Hint, LayerPlugin, ParseCtx, ParseError, ParsedLayer,
    ProtocolName, RouteId, StreamIdentity, Value,
};

use crate::icmpv6;

const MSG_TYPE: FieldName = "msg_type";
const MAX_RESP_DELAY: FieldName = "max_resp_delay";
const MULTICAST_ADDR: FieldName = "multicast_addr";
const NUM_SOURCES: FieldName = "num_sources";
const SOURCE_ADDRS: FieldName = "source_addrs";

/// icmpv6's `rest_of_header` word, re-read for every message type here —
/// each interprets the same four bytes differently (see the module doc).
/// `None` below `Depth::Full`, mirroring ndp's `icmpv6_rest`.
fn icmpv6_rest(ctx: &ParseCtx) -> Option<[u8; 4]> {
    match ctx.field("icmpv6", icmpv6::REST_OF_HEADER)? {
        Value::Bytes(b) => <[u8; 4]>::try_from(b.as_slice()).ok(),
        _ => None,
    }
}

/// The dispatching type, re-read from icmpv6's own `type` field rather
/// than re-decided here (11.3's cross-layer-read stance, ndp's
/// `icmpv6_msg_type` precedent).
fn icmpv6_msg_type(ctx: &ParseCtx) -> Option<u8> {
    match ctx.field("icmpv6", icmpv6::TYPE)? {
        Value::U64(t) => u8::try_from(*t).ok(),
        _ => None,
    }
}

pub struct Mld;

impl LayerPlugin for Mld {
    fn name(&self) -> ProtocolName {
        "mld"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let Some(msg_type) = icmpv6_msg_type(ctx) else {
            // Same fallback as ndp (11.3): can't tell Query/Report/Done/
            // v2-Report apart without icmpv6's `type` (each has a
            // different layout ahead of any options), so decline to
            // subdivide rather than guess. `Depth::None`/`Keys` promise
            // routing + length, not fields (01.3), and this plugin has no
            // flow-key fields to lose by doing so.
            return Ok(ParsedLayer {
                header_len: bytes.len(),
                fields: FieldMap::new(),
                hint: Hint::Terminal,
            });
        };

        let mut r = ByteReader::new(bytes);
        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Structural {
            fields.insert(MSG_TYPE, Value::U64(u64::from(msg_type)));
        }

        if msg_type == icmpv6::MLD_V2_REPORT {
            // RFC 3810 §5.2: no per-message max-response-delay (the
            // shared word is Reserved + M, not a delay), so `max_resp_delay`
            // is simply omitted for this type — same as any other
            // depth/type-gated field elsewhere in this codebase.
            //
            // M multicast-address records follow, each a variable-length
            // TLV-like structure (record type(1), aux data len(1, in
            // 32-bit words), number of sources N(2), multicast address
            // (16), N source addresses (16 each), aux data). Every record
            // is walked so `header_len` stays correct regardless of M —
            // required to not misparse whatever follows in the packet —
            // but only the *first* record's `multicast_addr`/
            // `num_sources`/`source_addrs` are surfaced as fields, the
            // same "first occurrence wins, rest walked for length only"
            // stance ndp takes for repeated NDP options. A v2 ergonomics
            // follow-up (per-record `LayerRecord`s) is the same kind of
            // gap 03's IPv6-extension-headers Tier-2 note already
            // documents for a different protocol.
            let m = icmpv6_rest(ctx)
                .map(|w| u16::from_be_bytes([w[2], w[3]]))
                .unwrap_or(0);

            let mut first_multicast_addr = None;
            let mut first_num_sources = None;
            let mut first_source_addrs = None;
            for i in 0..m {
                let _record_type = r.u8()?;
                let aux_data_len = r.u8()?;
                let num_sources = r.u16_be()?;
                let addr = r.take(16)?;
                let mut sources = Vec::with_capacity(usize::from(num_sources));
                for _ in 0..num_sources {
                    sources.push(Value::from(r.take(16)?));
                }
                let _aux_data = r.take(usize::from(aux_data_len) * 4)?;
                if i == 0 {
                    first_multicast_addr = Some(Value::from(addr));
                    first_num_sources = Some(u64::from(num_sources));
                    first_source_addrs = Some(Value::List(sources));
                }
            }

            if ctx.depth() >= Depth::Structural {
                if let Some(v) = first_multicast_addr {
                    fields.insert(MULTICAST_ADDR, v);
                }
            }
            if ctx.depth() >= Depth::Full {
                if let Some(v) = first_num_sources {
                    fields.insert(NUM_SOURCES, Value::U64(v));
                }
                if let Some(v) = first_source_addrs {
                    fields.insert(SOURCE_ADDRS, v);
                }
            }
        } else {
            // Query (130), MLDv1 Report (131), Done (132) — RFC 2710 §3
            // all share one 16-byte body: just the Multicast Address (the
            // Maximum Response Delay ahead of it lives in the word icmpv6
            // already consumed). An MLDv2-capable querier (RFC 3810 §5.1)
            // extends a type-130 Query with four more fields (Resv/S/QRV
            // packed into one byte, QQIC, Number of Sources N, then N
            // source addresses) — walked here to keep `header_len`
            // correct when present, but not surfaced: Tier 1's field list
            // for this plugin names only `max_resp_delay`/`multicast_addr`
            // uniformly across Query/Report/Done, the same "walked, not
            // extracted" treatment ndp gives Redirect's second address.
            // A bare MLDv1 message (no trailing bytes) and an MLDv2 query
            // with a zero-source extension are both valid and both leave
            // nothing here to walk.
            let multicast_addr = r.take(16)?;
            if msg_type == icmpv6::MLD_QUERY && r.remaining() >= 4 {
                let _resv_s_qrv = r.u8()?;
                let _qqic = r.u8()?;
                let n = r.u16_be()?;
                let _sources = r.take(usize::from(n) * 16)?;
            }

            if ctx.depth() >= Depth::Structural {
                let max_resp_delay = icmpv6_rest(ctx).map(|w| u16::from_be_bytes([w[0], w[1]]));
                if let Some(delay) = max_resp_delay {
                    fields.insert(MAX_RESP_DELAY, Value::U64(u64::from(delay)));
                }
                fields.insert(MULTICAST_ADDR, Value::from(multicast_addr));
            }
        }

        Ok(ParsedLayer {
            header_len: bytes.len() - r.remaining(),
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[
            RouteId::Custom {
                space: icmpv6::ICMPV6_TYPE_SPACE,
                id: icmpv6::MLD_QUERY as u64,
            },
            RouteId::Custom {
                space: icmpv6::ICMPV6_TYPE_SPACE,
                id: icmpv6::MLD_V1_REPORT as u64,
            },
            RouteId::Custom {
                space: icmpv6::ICMPV6_TYPE_SPACE,
                id: icmpv6::MLD_DONE as u64,
            },
            RouteId::Custom {
                space: icmpv6::ICMPV6_TYPE_SPACE,
                id: icmpv6::MLD_V2_REPORT as u64,
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
    /// plugin would have extracted at `Depth::Full` (ndp.rs's own test
    /// helper, same shape).
    fn icmpv6_layer(icmp_type: u8, rest: Option<[u8; 4]>) -> LayerRecord {
        let mut fields = FieldMap::new();
        fields.insert(icmpv6::TYPE, Value::U64(u64::from(icmp_type)));
        if let Some(r) = rest {
            fields.insert(icmpv6::REST_OF_HEADER, Value::from(&r[..]));
        }
        LayerRecord {
            protocol: "icmpv6",
            offset: 14 + 40,
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
        Mld.parse(bytes, &ParseCtx::new(&outer, Depth::Full, &m))
    }

    #[test]
    fn v1_query_reads_max_resp_delay_and_multicast_addr() {
        // RFC 2710 §3: max resp delay 10000ms (0x2710), reserved 0 — the
        // 11.3 conformance fixture's own MLD Query byte pattern.
        let group = [0xFF, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let parsed =
            parse(icmpv6::MLD_QUERY, Some([0x27, 0x10, 0, 0]), &group).expect("bare v1 query");
        assert_eq!(parsed.header_len, 16);
        assert_eq!(parsed.fields.get(MSG_TYPE), Some(&Value::U64(130)));
        assert_eq!(parsed.fields.get(MAX_RESP_DELAY), Some(&Value::U64(10000)));
        assert_eq!(
            parsed.fields.get(MULTICAST_ADDR),
            Some(&Value::from(&group[..]))
        );
        assert_eq!(parsed.fields.get(NUM_SOURCES), None);
        assert_eq!(parsed.hint, Hint::Terminal);
    }

    #[test]
    fn v1_report_and_done_share_the_query_shape() {
        let group = [0xFF, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        for (t, expected) in [(icmpv6::MLD_V1_REPORT, 131u64), (icmpv6::MLD_DONE, 132u64)] {
            let parsed = parse(t, Some([0, 0, 0, 0]), &group).expect("v1 report/done");
            assert_eq!(parsed.header_len, 16);
            assert_eq!(parsed.fields.get(MSG_TYPE), Some(&Value::U64(expected)));
            assert_eq!(parsed.fields.get(MAX_RESP_DELAY), Some(&Value::U64(0)));
            assert_eq!(
                parsed.fields.get(MULTICAST_ADDR),
                Some(&Value::from(&group[..]))
            );
        }
    }

    #[test]
    fn v2_query_extension_is_walked_but_not_surfaced() {
        // RFC 3810 §5.1: S=1 QRV=2 (0x22), QQIC=125, N=1 source.
        let group = [0xFF, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let mut bytes = group.to_vec();
        bytes.extend_from_slice(&[0x22, 125, 0x00, 0x01]);
        bytes.extend_from_slice(&[0xAA; 16]); // one source address
        let parsed = parse(icmpv6::MLD_QUERY, Some([0x27, 0x10, 0, 0]), &bytes).expect("v2 query");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(
            parsed.fields.get(MULTICAST_ADDR),
            Some(&Value::from(&group[..]))
        );
        // Tier 1 doesn't ask for S/QRV/QQIC/source-list on Query.
        assert_eq!(parsed.fields.get(NUM_SOURCES), None);
    }

    #[test]
    fn v2_report_single_record_surfaces_sources() {
        // RFC 3810 §5.2: M=1 (icmpv6's rest_of_header), one record —
        // MODE_IS_EXCLUDE(2), aux_data_len=0, N=2 sources.
        let mut record = vec![2u8, 0, 0x00, 0x02];
        record.extend_from_slice(&[0xFF, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        record.extend_from_slice(&[0x11; 16]);
        record.extend_from_slice(&[0x22; 16]);
        let parsed = parse(icmpv6::MLD_V2_REPORT, Some([0, 0, 0, 1]), &record)
            .expect("v2 report, one record");
        assert_eq!(parsed.header_len, record.len());
        assert_eq!(parsed.fields.get(MSG_TYPE), Some(&Value::U64(143)));
        assert_eq!(parsed.fields.get(MAX_RESP_DELAY), None);
        assert_eq!(
            parsed.fields.get(MULTICAST_ADDR),
            Some(&Value::from(
                &[0xFFu8, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1][..]
            ))
        );
        assert_eq!(parsed.fields.get(NUM_SOURCES), Some(&Value::U64(2)));
        assert_eq!(
            parsed.fields.get(SOURCE_ADDRS),
            Some(&Value::List(vec![
                Value::from(&[0x11u8; 16][..]),
                Value::from(&[0x22u8; 16][..]),
            ]))
        );
    }

    #[test]
    fn v2_report_walks_every_record_for_header_len_but_keeps_only_the_first() {
        // Two records: record 0 (group ::1, 0 sources), record 1 (group
        // ::2, 1 source) — header_len must cover both, fields must come
        // from record 0 only (11.3's "first occurrence wins" stance).
        let mut r0 = vec![1u8, 0, 0x00, 0x00];
        r0.extend_from_slice(&[0xFF, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let mut r1 = vec![1u8, 0, 0x00, 0x01];
        r1.extend_from_slice(&[0xFF, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        r1.extend_from_slice(&[0x33; 16]);
        let mut bytes = r0.clone();
        bytes.extend_from_slice(&r1);

        let parsed = parse(icmpv6::MLD_V2_REPORT, Some([0, 0, 0, 2]), &bytes)
            .expect("v2 report, two records");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(
            parsed.fields.get(MULTICAST_ADDR),
            Some(&Value::from(
                &[0xFFu8, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1][..]
            ))
        );
        assert_eq!(parsed.fields.get(NUM_SOURCES), Some(&Value::U64(0)));
    }

    #[test]
    fn v2_report_zero_records_is_a_valid_empty_report() {
        let parsed =
            parse(icmpv6::MLD_V2_REPORT, Some([0, 0, 0, 0]), &[]).expect("empty v2 report");
        assert_eq!(parsed.header_len, 0);
        assert_eq!(parsed.fields.get(MSG_TYPE), Some(&Value::U64(143)));
        assert_eq!(parsed.fields.get(MULTICAST_ADDR), None);
        assert_eq!(parsed.fields.get(NUM_SOURCES), None);
    }

    #[test]
    fn truncated_fixed_fields_decline() {
        // Query/Report/Done need a 16-byte multicast address; 15 is short.
        assert!(parse(icmpv6::MLD_QUERY, Some([0; 4]), &[0xAA; 15]).is_err());
        // A v2 report record needs at least 4 bytes before its address.
        assert!(parse(icmpv6::MLD_V2_REPORT, Some([0, 0, 0, 1]), &[1, 0, 0]).is_err());
        // ...and the address itself must be complete.
        assert!(parse(
            icmpv6::MLD_V2_REPORT,
            Some([0, 0, 0, 1]),
            &[1, 0, 0, 0, 0xAA]
        )
        .is_err());
    }

    #[test]
    fn missing_cross_layer_type_falls_back_to_an_opaque_terminal_layer() {
        let empty_outer: Vec<LayerRecord> = Vec::new();
        let bytes = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
        let m = meta(bytes.len());
        let parsed = Mld
            .parse(&bytes, &ParseCtx::new(&empty_outer, Depth::None, &m))
            .expect("opaque fallback still succeeds");
        assert_eq!(parsed.header_len, bytes.len());
        assert!(parsed.fields.iter().next().is_none());
        assert_eq!(parsed.hint, Hint::Terminal);
    }
}
