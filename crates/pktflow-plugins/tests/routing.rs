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
