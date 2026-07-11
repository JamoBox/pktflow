//! VRRP group-beacon stream behavior (11.4, RFC 5798/RFC 3768): the same
//! shared-qualifier key shape GRE's `key`/VXLAN's `vni` established (06.5),
//! exercised here through the real engine and `Aggregator` rather than
//! synthetic `ParseCtx`s.
//!
//! A real master-election sequence changes the *speaker's* source IP
//! (physical router A hands off to physical router B), which under 05.3's
//! nearest-outer rule means a different outer `ipv4` parent per speaker —
//! by construction (`store.rs`'s `(parent, protocol, key)` index) that's
//! two distinct raw stream nodes, one per speaker, each with the same
//! VRID key. D10's merged view (`at_layer_merged`) is exactly the
//! mechanism that folds same-key nodes across parents into one logical
//! row, so that's what "one group stream regardless of which physical
//! router currently holds master" is verified against here — the same
//! folding real deployments rely on to see one VRID as one thing.
//! Same-outer, two-VRIDs independence (the other half of 11.4's
//! acceptance criterion) instead uses raw `at_layer`, mirroring 06.5's
//! two-VNIs-one-outer-stream test shape exactly (single outer
//! conversation, two shared-qualifier keys).
//!
//! `ospf`'s own end-to-end case at the bottom of this file verifies the
//! opposite shape: Hello is a periodic multicast beacon, not a
//! conversation (11.4's domain spec, same stance `stp`/`lldp`/`cdp`
//! already establish, 11.1), so it declares no identity at all and must
//! contribute its activity to its parent `ipv4` stream rather than
//! forming an `ospf` stream of its own.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use pktflow_core::{LayerPlugin, LinkType, PacketMeta, ParseOpts, RollupKind};
use pktflow_flows::rollup::Rollup;
use pktflow_flows::{Aggregator, AggregatorConfig};
use pktflow_plugins::default_engine;
use pktflow_plugins::ipv4::internet_checksum;

fn meta(len: usize, ms: u64) -> PacketMeta {
    PacketMeta {
        timestamp: SystemTime::UNIX_EPOCH + Duration::from_millis(ms),
        caplen: len,
        origlen: len,
        link_type: LinkType::ETHERNET,
    }
}

fn eth(src_last_octet: u8) -> Vec<u8> {
    // VRRP's own multicast MAC (00-00-5E-00-01-{VRID}, RFC 5798 §7.3) isn't
    // needed for stream identity (the shared-qualifier key ignores MACs
    // entirely) — a source MAC that merely varies per speaker is enough to
    // route through `ethernet`.
    let mut f = vec![0x01, 0x00, 0x5E, 0x00, 0x00, 0x12];
    f.extend_from_slice(&[0x00, 0x1A, 0x2B, 0x3C, 0x4D, src_last_octet]);
    f.extend_from_slice(&0x0800u16.to_be_bytes());
    f
}

fn ipv4(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
    let mut h = vec![
        0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 112, 0, 0,
    ];
    h.extend_from_slice(&src);
    h.extend_from_slice(&dst);
    let ck = internet_checksum(&h);
    h[10..12].copy_from_slice(&ck.to_be_bytes());
    h
}

/// A VRRPv3 advertisement (RFC 5798 §5.2): one virtual IP, whatever
/// `priority` the caller wants to observe changing across the sequence.
fn vrrp(vrid: u8, priority: u8, virtual_ip: [u8; 4]) -> Vec<u8> {
    let mut b = vec![0x31, vrid, priority, 1, 0x00, 100, 0x00, 0x00];
    b.extend_from_slice(&virtual_ip);
    b
}

fn frame(speaker: [u8; 4], vrid: u8, priority: u8, virtual_ip: [u8; 4]) -> Vec<u8> {
    let mut f = eth(speaker[3]);
    f.extend_from_slice(&ipv4(speaker, [224, 0, 0, 18])); // RFC 5798 §5.2.2 VRRP group
    f.extend_from_slice(&vrrp(vrid, priority, virtual_ip));
    f
}

#[test]
fn master_election_sequence_folds_into_one_group_stream() {
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    let router_a = [192, 168, 1, 1];
    let router_b = [192, 168, 1, 2];
    let virtual_ip = [192, 168, 1, 254];

    // Router A starts master (priority 100), then fails over: its
    // priority drops to 0 (RFC 5798 §6.4.2's Master "release" signal), and
    // backup router B takes over at its own configured priority (90).
    let sequence = [
        (router_a, 100u8, 0u64),
        (router_a, 100, 10),
        (router_a, 0, 20), // master relinquishing
        (router_b, 90, 30),
        (router_b, 90, 40),
    ];

    for (speaker, priority, ms) in sequence {
        let f = frame(speaker, 51, priority, virtual_ip);
        agg.ingest(&engine.dissect(&f, meta(f.len(), ms), ParseOpts::default()));
    }

    // Two raw nodes (one per speaker's outer ipv4 parent)...
    let raw = agg.at_layer("vrrp");
    assert_eq!(
        raw.len(),
        2,
        "one raw node per speaker's outer conversation"
    );

    // ...but D10's merged view folds them into one logical VRID-51 group,
    // with every advertisement's stats counted regardless of speaker.
    let merged = agg.at_layer_merged("vrrp");
    assert_eq!(
        merged.len(),
        1,
        "one VRRP group for VRID 51 regardless of which physical router is speaking"
    );
    let group = &merged[0];
    assert_eq!(
        group.stats[0].packets + group.stats[1].packets,
        5,
        "every advertisement in the sequence counted"
    );
    assert_eq!(group.nodes.len(), 2, "folded from both speakers' raw nodes");

    // Each raw node's own priority rollup still shows that speaker's
    // slice of the sequence (rollups aren't merged across parents — only
    // stats are, per D10) — router A's node saw the relinquish (100 -> 0),
    // router B's saw its steady 90.
    let router_a_node = raw
        .iter()
        .find(|s| {
            s.rollups
                .get("priority")
                .is_some_and(|r| matches!(r, Rollup::Accumulate { count, .. } if *count == 3))
        })
        .expect("router A's node (3 advertisements)");
    let Rollup::Accumulate { values, .. } = router_a_node
        .rollups
        .get("priority")
        .expect("priority rollup declared")
    else {
        panic!("priority rollup must be Accumulate");
    };
    assert!(values.contains(&pktflow_core::Value::U64(100)));
    assert!(
        values.contains(&pktflow_core::Value::U64(0)),
        "relinquish priority observed"
    );
}

#[test]
fn two_vrids_on_one_segment_are_independent_streams() {
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    for (ms, vrid, virtual_last_octet) in [(0u64, 10u8, 253u8), (1, 20, 254)] {
        let f = frame(
            [192, 168, 1, 1],
            vrid,
            100,
            [192, 168, 1, virtual_last_octet],
        );
        agg.ingest(&engine.dissect(&f, meta(f.len(), ms), ParseOpts::default()));
    }

    let outer_ip = agg.at_layer("ipv4")[0];
    let groups = agg.at_layer("vrrp");
    assert_eq!(
        groups.len(),
        2,
        "one stream per VRID (shared-qualifier key)"
    );
    assert!(groups.iter().all(|g| g.parent == Some(outer_ip.id)));
    assert_ne!(groups[0].key, groups[1].key);
}

#[test]
fn rollup_kind_is_accumulate_on_priority() {
    // Sanity check on the plugin's declared identity, guarding against a
    // silent rollup-kind regression that the two tests above wouldn't
    // otherwise pinpoint.
    let identity = pktflow_plugins::vrrp::Vrrp
        .stream_identity()
        .expect("vrrp declares a stream identity");
    assert_eq!(identity.rollups.len(), 1);
    assert_eq!(identity.rollups[0].field, "priority");
    assert_eq!(identity.rollups[0].kind, RollupKind::Accumulate);
}

/// HSRP (RFC 2281): the same group-beacon pattern as VRRP above, keyed on
/// the standby group number instead of a VRID, riding on UDP/1985 to
/// 224.0.0.2 instead of directly on IP protocol 112 — so unlike `vrrp`'s
/// stream (parented directly on its outer `ipv4`), `hsrp`'s parent is the
/// `udp` flow carrying it (same shape as DNS-under-UDP, 06.6).
fn ipv4_udp_hsrp(src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut h = vec![
        0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 17, 0, 0,
    ];
    h.extend_from_slice(&src);
    h.extend_from_slice(&dst);
    let ck = internet_checksum(&h);
    h[10..12].copy_from_slice(&ck.to_be_bytes());
    h.extend_from_slice(&1985u16.to_be_bytes()); // src port
    h.extend_from_slice(&1985u16.to_be_bytes()); // dst port
    h.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    h.extend_from_slice(&[0, 0]); // UDP checksum optional over IPv4, RFC 768
    h.extend_from_slice(payload);
    h
}

/// An HSRP Hello (RFC 2281 §5): whatever `state`/`priority` the caller
/// wants to observe changing across a master-election-like sequence.
fn hsrp(group: u8, state: u8, priority: u8, virtual_ip: [u8; 4]) -> Vec<u8> {
    let mut b = vec![0, 0, state, 3, 10, priority, group, 0];
    b.extend_from_slice(b"cisco\0\0\0");
    b.extend_from_slice(&virtual_ip);
    b
}

fn hsrp_frame(
    speaker: [u8; 4],
    group: u8,
    state: u8,
    priority: u8,
    virtual_ip: [u8; 4],
) -> Vec<u8> {
    let hsrp_bytes = hsrp(group, state, priority, virtual_ip);
    let mut f = eth(speaker[3]);
    f.extend_from_slice(&ipv4_udp_hsrp(speaker, [224, 0, 0, 2], &hsrp_bytes));
    f
}

#[test]
fn hsrp_active_router_failover_folds_into_one_group_stream() {
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    let router_a = [192, 168, 1, 1];
    let router_b = [192, 168, 1, 2];
    let virtual_ip = [192, 168, 1, 254];

    // Router A is Active (state 16), then resigns (its own advertised
    // state drops to Speak, RFC 2281 §3's Resign transition) while backup
    // router B takes over as Active at its own configured priority.
    const ACTIVE: u8 = 16;
    const SPEAK: u8 = 4;
    let sequence = [
        (router_a, ACTIVE, 100u8, 0u64),
        (router_a, ACTIVE, 100, 10),
        (router_a, SPEAK, 100, 20), // resigning
        (router_b, ACTIVE, 90, 30),
        (router_b, ACTIVE, 90, 40),
    ];

    for (speaker, state, priority, ms) in sequence {
        let f = hsrp_frame(speaker, 1, state, priority, virtual_ip);
        agg.ingest(&engine.dissect(&f, meta(f.len(), ms), ParseOpts::default()));
    }

    // Two raw nodes (one per speaker's outer ipv4 parent)...
    let raw = agg.at_layer("hsrp");
    assert_eq!(
        raw.len(),
        2,
        "one raw node per speaker's outer conversation"
    );

    // ...but the merged view folds them into one logical group-1 stream,
    // with every advertisement's stats counted regardless of speaker.
    let merged = agg.at_layer_merged("hsrp");
    assert_eq!(
        merged.len(),
        1,
        "one HSRP group for group 1 regardless of which physical router is Active"
    );
    let group = &merged[0];
    assert_eq!(
        group.stats[0].packets + group.stats[1].packets,
        5,
        "every advertisement in the sequence counted"
    );
    assert_eq!(group.nodes.len(), 2, "folded from both speakers' raw nodes");
}

#[test]
fn two_hsrp_groups_on_one_segment_are_independent_streams() {
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    for (ms, group, virtual_last_octet) in [(0u64, 1u8, 253u8), (1, 2, 254)] {
        let f = hsrp_frame(
            [192, 168, 1, 1],
            group,
            16,
            100,
            [192, 168, 1, virtual_last_octet],
        );
        agg.ingest(&engine.dissect(&f, meta(f.len(), ms), ParseOpts::default()));
    }

    let outer_udp = agg.at_layer("udp")[0];
    let groups = agg.at_layer("hsrp");
    assert_eq!(
        groups.len(),
        2,
        "one stream per group number (shared-qualifier key)"
    );
    assert!(groups.iter().all(|g| g.parent == Some(outer_udp.id)));
    assert_ne!(groups[0].key, groups[1].key);
}

#[test]
fn hsrp_rollups_are_accumulate_on_state_and_priority() {
    let identity = pktflow_plugins::hsrp::Hsrp
        .stream_identity()
        .expect("hsrp declares a stream identity");
    assert_eq!(identity.rollups.len(), 2);
    assert_eq!(identity.rollups[0].field, "state");
    assert_eq!(identity.rollups[0].kind, RollupKind::Accumulate);
    assert_eq!(identity.rollups[1].field, "priority");
    assert_eq!(identity.rollups[1].kind, RollupKind::Accumulate);
}

/// A minimal OSPFv2 Hello (RFC 2328 A.3.1/A.3.2): common header (version
/// 2, router/area ids, no authentication) plus a bare Hello body (no
/// neighbors yet — this is the first Hello of an adjacency forming).
fn ospf_hello(router_id: [u8; 4]) -> Vec<u8> {
    let mut b = vec![2, 1, 0, 0]; // version 2, type 1 (Hello), length placeholder
    b.extend_from_slice(&router_id);
    b.extend_from_slice(&[0, 0, 0, 0]); // area_id: backbone
    b.extend_from_slice(&[0, 0]); // checksum
    b.extend_from_slice(&[0, 0]); // AuType: none
    b.extend_from_slice(&[0; 8]); // Authentication
    b.extend_from_slice(&[255, 255, 255, 0]); // network_mask
    b.extend_from_slice(&10u16.to_be_bytes()); // hello_interval
    b.push(0x02); // options
    b.push(1); // rtr_pri
    b.extend_from_slice(&40u32.to_be_bytes()); // router_dead_interval
    b.extend_from_slice(&[0, 0, 0, 0]); // designated_router: none yet
    b.extend_from_slice(&[0, 0, 0, 0]); // backup_designated_router: none yet
    let len = u16::try_from(b.len()).expect("fixture fits in u16");
    b[2..4].copy_from_slice(&len.to_be_bytes());
    b
}

/// RFC 2328 A.3.1: OSPF rides directly on IP protocol 89, no UDP/TCP
/// framing.
fn ipv4_ospf(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
    let mut h = vec![
        0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 89, 0, 0,
    ];
    h.extend_from_slice(&src);
    h.extend_from_slice(&dst);
    let ck = internet_checksum(&h);
    h[10..12].copy_from_slice(&ck.to_be_bytes());
    h
}

#[test]
fn ospf_hello_is_identity_less_and_contributes_to_its_parent_ip_conversation() {
    // RFC 2328 Appendix A "AllSPFRouters", 224.0.0.5, with its standard
    // IPv4-multicast-to-MAC mapping 01:00:5E + low 23 bits of the group.
    const ALL_SPF_ROUTERS_MAC: [u8; 6] = [0x01, 0x00, 0x5E, 0x00, 0x00, 0x05];
    const ALL_SPF_ROUTERS_IP: [u8; 4] = [224, 0, 0, 5];

    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    let speaker = [192, 168, 1, 1];
    let mut f = vec![];
    f.extend_from_slice(&ALL_SPF_ROUTERS_MAC);
    f.extend_from_slice(&[0x00, 0x1A, 0x2B, 0x3C, 0x4D, speaker[3]]);
    f.extend_from_slice(&0x0800u16.to_be_bytes());
    f.extend_from_slice(&ipv4_ospf(speaker, ALL_SPF_ROUTERS_IP));
    f.extend_from_slice(&ospf_hello(speaker));

    let m = meta(f.len(), 0);
    let packet = engine.dissect(&f, m, ParseOpts::default());
    let protocols: Vec<_> = packet.layers.iter().map(|l| l.protocol).collect();
    assert_eq!(protocols, ["ethernet", "ipv4", "ospf"]);

    agg.ingest(&packet);
    // Same beacon shape as stp/lldp/cdp (11.1) and vlan's identity-less
    // bridging (06.2): ethernet + ipv4 each still form their own stream,
    // ospf contributes to the ipv4 conversation rather than forming one
    // of its own.
    assert_eq!(agg.len(), 2, "ospf forms no stream of its own");
    let eth_stream = agg.at_layer("ethernet")[0];
    let ip_stream = agg.at_layer("ipv4")[0];
    assert_eq!(ip_stream.parent, Some(eth_stream.id), "bridged across ospf");
    assert!(agg.at_layer("ospf").is_empty(), "no ospf stream of its own");
}

#[test]
fn ospf_declares_no_stream_identity() {
    assert!(pktflow_plugins::ospf::Ospf.stream_identity().is_none());
}
