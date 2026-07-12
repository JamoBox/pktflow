//! IPv6 control-plane dispatch (11.3): `icmpv6` routes nine message types
//! onward to `ndp` (five) and `mld` (four) by a plugin-defined
//! `icmpv6_type` space rather than a real IP protocol, and both targets
//! read some of their own fields back from `icmpv6`'s already-consumed
//! bytes via a cross-layer lookup (FR-17). `ndp.rs`/`mld.rs`'s own unit
//! tests exercise that lookup against synthetic `ParseCtx`s; these tests
//! exercise it through the real engine, so the cross-layer read is
//! verified against actual plugin ordering, not just a hand-built
//! fixture.

use std::sync::Arc;
use std::time::SystemTime;

use pktflow_core::{LinkType, PacketMeta, ParseOpts, StopReason, Value};
use pktflow_flows::{Aggregator, AggregatorConfig};
use pktflow_plugins::default_engine;

fn meta(len: usize) -> PacketMeta {
    PacketMeta {
        timestamp: SystemTime::UNIX_EPOCH,
        caplen: len,
        origlen: len,
        link_type: LinkType::ETHERNET,
    }
}

const MAC_A: [u8; 6] = [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E];
// RFC 2464 §7 multicast mapping for the well-known NDP scopes this suite
// uses: ff02::1 (all-nodes) and ff02::2 (all-routers).
const ALL_NODES_MAC: [u8; 6] = [0x33, 0x33, 0x00, 0x00, 0x00, 0x01];
const ALL_ROUTERS_MAC: [u8; 6] = [0x33, 0x33, 0x00, 0x00, 0x00, 0x02];
const LINK_LOCAL_SRC: [u8; 16] = [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];
const ALL_NODES_DST: [u8; 16] = [0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];
const ALL_ROUTERS_DST: [u8; 16] = [0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02];
// RFC 3810 §5.2.14: MLDv2 Reports target the MLDv2-capable-routers group
// ff02::16, not the group(s) they're reporting on.
const MLDV2_ROUTERS_MAC: [u8; 6] = [0x33, 0x33, 0x00, 0x00, 0x00, 0x16];
const MLDV2_ROUTERS_DST: [u8; 16] = [0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x16];

fn eth(dst: [u8; 6], src: [u8; 6], ethertype: u16) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&dst);
    f.extend_from_slice(&src);
    f.extend_from_slice(&ethertype.to_be_bytes());
    f
}

/// RFC 8200 fixed header; `next_header` 58 = ICMPv6, hop limit 255 as
/// RFC 4861 §3.1 mandates for every NDP message (a receiver check this
/// codebase doesn't enforce, but real captures always carry it).
fn ipv6(payload_len: u16, src: [u8; 16], dst: [u8; 16]) -> Vec<u8> {
    let mut h = vec![0x60, 0, 0, 0];
    h.extend_from_slice(&payload_len.to_be_bytes());
    h.push(58);
    h.push(255);
    h.extend_from_slice(&src);
    h.extend_from_slice(&dst);
    h
}

/// RFC 4443 §2.1 common header: type, code 0, checksum filler (not
/// validated by this codebase — icmpv4 precedent), 4-byte type-specific
/// word.
fn icmpv6(icmp_type: u8, rest: [u8; 4]) -> Vec<u8> {
    let mut h = vec![icmp_type, 0, 0xBE, 0xEF];
    h.extend_from_slice(&rest);
    h
}

/// Walks the single root-to-leaf chain, returning protocols in order
/// (tunnels.rs' helper, duplicated here — no shared test-support module).
fn chain(packet: &pktflow_core::DissectedPacket) -> Vec<pktflow_core::ProtocolName> {
    packet.layers.iter().map(|l| l.protocol).collect()
}

#[test]
fn ra_cross_layer_flags_and_lifetime_survive_the_real_dispatch_chain() {
    // RFC 4861 §4.2: cur_hop_limit=64, M+O set, router_lifetime=1800s —
    // all three packed into the 4-byte word `icmpv6` consumes as its own
    // `rest_of_header`, none of it present in `ndp`'s own `bytes`.
    let mut body = icmpv6(134, [0x40, 0xC0, 0x07, 0x08]);
    body.extend_from_slice(&[0x00, 0x00, 0x1D, 0x4C, 0x00, 0x00, 0x03, 0xE8]); // reachable=7500ms, retrans=1000ms

    let mut pkt = eth(ALL_NODES_MAC, MAC_A, 0x86DD);
    pkt.extend_from_slice(&ipv6(body.len() as u16, LINK_LOCAL_SRC, ALL_NODES_DST));
    pkt.extend_from_slice(&body);

    let engine = Arc::new(default_engine());
    let m = meta(pkt.len());
    let packet = engine.dissect(&pkt, m, ParseOpts::default());

    assert_eq!(chain(&packet), ["ethernet", "ipv6", "icmpv6", "ndp"]);
    assert_eq!(packet.stop, StopReason::Complete);

    let ndp = packet.layers.last().expect("ndp layer");
    assert_eq!(ndp.fields.get("msg_type"), Some(&Value::U64(134)));
    // Both values below live inside icmpv6's rest_of_header, not ndp's
    // own bytes — this is the cross-layer read (FR-17) under real
    // dispatch, not a hand-built ParseCtx.
    assert_eq!(ndp.fields.get("flags"), Some(&Value::U64(0xC0)));
    assert_eq!(ndp.fields.get("router_lifetime"), Some(&Value::U64(1800)));
    // These two live in ndp's own bytes and don't exercise the
    // cross-layer path, but confirm the fixed-field offsets are right
    // given the word before them was consumed by a different plugin.
    assert_eq!(ndp.fields.get("reachable_time"), Some(&Value::U64(7500)));
    assert_eq!(ndp.fields.get("retrans_timer"), Some(&Value::U64(1000)));

    // Identity-less (11.3): ethernet and ipv6 each form their own stream
    // (06.2/06.3), but icmpv6/ndp add no third — same stance as ARP
    // (06.3), verified here as "no more streams than the two IP/MAC
    // layers below them", not a bare count that would also pass by
    // accident if either of *those* silently lost its stream.
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());
    agg.ingest(&packet);
    let protocols: std::collections::BTreeSet<_> = agg.streams().map(|s| s.protocol).collect();
    assert_eq!(
        protocols,
        std::collections::BTreeSet::from(["ethernet", "ipv6"]),
        "icmpv6/ndp form no stream of their own"
    );
    assert_eq!(agg.len(), 2);
}

#[test]
fn all_five_ndp_types_dispatch_from_icmpv6_by_type() {
    // (icmp_type, rest_of_header, ndp's own trailing bytes) — every
    // dispatch target 11.3 names (RFC 4861 §4.1-§4.5), each far enough
    // from the others' byte layout that a wrong offset would show up as
    // either a decode failure or a wrong field, not a silent pass.
    let ns_na_target = [
        0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
    ];
    let mut redirect_body = vec![0xAAu8; 16];
    redirect_body.extend_from_slice(&[0xBB; 16]);
    // RFC 4861 §4.6.1 Source Link-Layer Address option (type 1, length 1
    // == 8 octets total): a bare RS with an empty ICMPv6 body never
    // reaches `ndp` at all — an empty remaining payload stops dissection
    // at `Complete` before the router even looks at the hint (03.4) — so
    // this fixture, like real RS traffic, carries the option most
    // implementations attach anyway (letting the router learn the
    // sender's link-layer address without a separate NS/NA round trip).
    let mut rs_slla = vec![1, 1];
    rs_slla.extend_from_slice(&MAC_A);

    // RS alone is a host->all-routers beacon (RFC 4861 §4.1); every other
    // type here targets/replies on the all-nodes scope.
    let cases: [(u8, [u8; 4], Vec<u8>); 5] = [
        (133, [0, 0, 0, 0], rs_slla),                  // RS
        (134, [0x40, 0xC0, 0x07, 0x08], vec![0; 8]),   // RA
        (135, [0, 0, 0, 0], ns_na_target.to_vec()),    // NS
        (136, [0xE0, 0, 0, 0], ns_na_target.to_vec()), // NA
        (137, [0, 0, 0, 0], redirect_body.clone()),    // Redirect
    ];

    let engine = Arc::new(default_engine());
    for (icmp_type, rest, extra) in cases {
        let mut body = icmpv6(icmp_type, rest);
        body.extend_from_slice(&extra);

        let (dst_mac, dst_ip) = if icmp_type == 133 {
            (ALL_ROUTERS_MAC, ALL_ROUTERS_DST)
        } else {
            (ALL_NODES_MAC, ALL_NODES_DST)
        };
        let mut pkt = eth(dst_mac, MAC_A, 0x86DD);
        pkt.extend_from_slice(&ipv6(body.len() as u16, LINK_LOCAL_SRC, dst_ip));
        pkt.extend_from_slice(&body);

        let m = meta(pkt.len());
        let packet = engine.dissect(&pkt, m, ParseOpts::default());
        assert_eq!(
            chain(&packet),
            ["ethernet", "ipv6", "icmpv6", "ndp"],
            "type {icmp_type}"
        );
        let ndp = packet.layers.last().expect("ndp layer");
        assert_eq!(
            ndp.fields.get("msg_type"),
            Some(&Value::U64(u64::from(icmp_type))),
            "type {icmp_type}"
        );
    }
}

#[test]
fn all_four_mld_types_dispatch_from_icmpv6_by_type() {
    // Query/v1-Report/Done (RFC 2710 §3) share one 16-byte multicast-
    // address body; the group being queried/reported is arbitrary here
    // (ff05::123, a site-local multicast group), distinct enough from the
    // all-nodes/all-routers scopes used elsewhere in this file that a
    // wrong offset would show up as a wrong field, not a silent pass.
    let group: [u8; 16] = [0xFF, 0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x23];

    // (icmp_type, rest_of_header, mld's own trailing bytes, dst mac, dst ip).
    type Case = (u8, [u8; 4], Vec<u8>, [u8; 6], [u8; 16]);
    let cases: [Case; 3] = [
        // RFC 2710 §3 Query: max resp delay 10000ms, sent to all-nodes.
        (
            130,
            [0x27, 0x10, 0, 0],
            group.to_vec(),
            ALL_NODES_MAC,
            ALL_NODES_DST,
        ),
        // RFC 2710 §4 Report: sent to the group being reported, not
        // all-nodes — this suite reuses ALL_NODES_DST purely as a valid
        // IPv6 multicast destination, not as protocol-accurate scoping.
        (
            131,
            [0, 0, 0, 0],
            group.to_vec(),
            ALL_NODES_MAC,
            ALL_NODES_DST,
        ),
        // RFC 2710 §5 Done: sent to the all-routers group.
        (
            132,
            [0, 0, 0, 0],
            group.to_vec(),
            ALL_ROUTERS_MAC,
            ALL_ROUTERS_DST,
        ),
    ];

    let engine = Arc::new(default_engine());
    for (icmp_type, rest, extra, dst_mac, dst_ip) in cases {
        let mut body = icmpv6(icmp_type, rest);
        body.extend_from_slice(&extra);

        let mut pkt = eth(dst_mac, MAC_A, 0x86DD);
        pkt.extend_from_slice(&ipv6(body.len() as u16, LINK_LOCAL_SRC, dst_ip));
        pkt.extend_from_slice(&body);

        let m = meta(pkt.len());
        let packet = engine.dissect(&pkt, m, ParseOpts::default());
        assert_eq!(
            chain(&packet),
            ["ethernet", "ipv6", "icmpv6", "mld"],
            "type {icmp_type}"
        );
        let mld = packet.layers.last().expect("mld layer");
        assert_eq!(
            mld.fields.get("msg_type"),
            Some(&Value::U64(u64::from(icmp_type))),
            "type {icmp_type}"
        );
        assert_eq!(
            mld.fields.get("multicast_addr"),
            Some(&Value::from(&group[..])),
            "type {icmp_type}"
        );
    }

    // RFC 3810 §5.2 MLDv2 Report: two multicast address records
    // (MODE_IS_EXCLUDE, 0 sources each) — verifies the real M-record walk
    // (cross-layer read of icmpv6's rest_of_header for M) end to end, not
    // just the first-record-only synthetic fixture mld.rs's unit tests use.
    let group_2: [u8; 16] = [0xFF, 0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x04, 0x56];
    let mut record_1 = vec![2u8, 0, 0x00, 0x00];
    record_1.extend_from_slice(&group);
    let mut record_2 = vec![2u8, 0, 0x00, 0x00];
    record_2.extend_from_slice(&group_2);
    let mut v2_body = icmpv6(143, [0, 0, 0, 2]); // M=2
    v2_body.extend_from_slice(&record_1);
    v2_body.extend_from_slice(&record_2);

    let mut pkt = eth(MLDV2_ROUTERS_MAC, MAC_A, 0x86DD);
    pkt.extend_from_slice(&ipv6(
        v2_body.len() as u16,
        LINK_LOCAL_SRC,
        MLDV2_ROUTERS_DST,
    ));
    pkt.extend_from_slice(&v2_body);

    let m = meta(pkt.len());
    let packet = engine.dissect(&pkt, m, ParseOpts::default());
    assert_eq!(chain(&packet), ["ethernet", "ipv6", "icmpv6", "mld"]);
    let mld = packet.layers.last().expect("mld layer");
    assert_eq!(mld.fields.get("msg_type"), Some(&Value::U64(143)));
    // First record only (mld.rs's documented "first occurrence wins, rest
    // walked for length only" stance) — but header_len must still cover
    // both records, verified indirectly: dissection reaches `Complete`
    // below, which it wouldn't if `mld` under-consumed the second record
    // and left trailing bytes the router then tried (and failed) to route.
    assert_eq!(
        mld.fields.get("multicast_addr"),
        Some(&Value::from(&group[..]))
    );
    assert_eq!(packet.stop, StopReason::Complete);
}
