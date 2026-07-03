//! Query API (05.7, FR-7): list, fetch, traverse, snapshot — with
//! determinism as the load-bearing property (PRD §7).

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use pktflow_core::{
    Canonicalize, DissectedPacket, Engine, FieldMap, KeyField, LayerPlugin, LayerRecord, LinkType,
    PacketMeta, ParseCtx, ParseError, ParsedLayer, ProtocolName, StopReason, StreamIdentity, Value,
};
use pktflow_flows::{Aggregator, AggregatorConfig, AggregatorSnapshot};

struct PairProto(ProtocolName);

static PAIR_KEY: &[KeyField] = &[KeyField {
    a: "src",
    b: Some("dst"),
}];
static PAIR_IDENTITY: StreamIdentity = StreamIdentity {
    key: PAIR_KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: &[],
};

impl LayerPlugin for PairProto {
    fn name(&self) -> ProtocolName {
        self.0
    }

    fn parse(&self, _bytes: &[u8], _ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        Err(ParseError::Malformed("ingest-only"))
    }

    fn stream_identity(&self) -> Option<&StreamIdentity> {
        Some(&PAIR_IDENTITY)
    }
}

fn engine() -> Arc<Engine> {
    Arc::new(
        Engine::builder()
            .plugin(PairProto("eth"))
            .plugin(PairProto("ipv4"))
            .build()
            .expect("valid registry"),
    )
}

fn layer(protocol: ProtocolName, src: u64, dst: u64) -> LayerRecord {
    let mut fields = FieldMap::new();
    fields.insert("src", Value::U64(src));
    fields.insert("dst", Value::U64(dst));
    LayerRecord {
        protocol,
        offset: 0,
        header_len: 0,
        fields,
    }
}

fn packet(layers: Vec<LayerRecord>, ms: u64) -> DissectedPacket {
    DissectedPacket {
        meta: PacketMeta {
            timestamp: SystemTime::UNIX_EPOCH + Duration::from_millis(ms),
            caplen: 64,
            origlen: 64,
            link_type: LinkType::ETHERNET,
        },
        layers,
        stop: StopReason::Complete,
        opaque_len: 0,
    }
}

/// A little capture with repeated keys, two protocols, and interleaving.
fn run_fixture() -> Aggregator {
    let mut agg = Aggregator::new(&engine(), AggregatorConfig::default());
    for (i, (esrc, edst, isrc, idst)) in [
        (1u64, 2u64, 10u64, 20u64),
        (3, 4, 10, 20), // same ip pair, different mac parent
        (1, 2, 30, 40),
        (3, 4, 10, 20), // repeat traffic
        (5, 6, 10, 20), // third parent for the same ip pair
    ]
    .iter()
    .enumerate()
    {
        agg.ingest(&packet(
            vec![layer("eth", *esrc, *edst), layer("ipv4", *isrc, *idst)],
            i as u64,
        ));
    }
    agg
}

#[test]
fn identical_runs_are_identical_in_order_and_snapshot() {
    let a = run_fixture();
    let b = run_fixture();

    let order = |agg: &Aggregator, protocol: &str| -> Vec<(u64, ProtocolName)> {
        agg.at_layer(protocol)
            .iter()
            .map(|s| (s.created_seq, s.protocol))
            .collect()
    };
    assert_eq!(order(&a, "eth"), order(&b, "eth"));
    assert_eq!(order(&a, "ipv4"), order(&b, "ipv4"));

    // "Serialized" via the Debug form: byte-identical across runs.
    assert_eq!(format!("{:?}", a.snapshot()), format!("{:?}", b.snapshot()));
}

#[test]
fn merged_view_folds_same_key_across_parents() {
    let agg = run_fixture();

    // Three eth parents carry the same ip pair (10, 20); one carries (30, 40).
    let merged = agg.at_layer_merged("ipv4");
    assert_eq!(merged.len(), 2, "two distinct ip keys");

    let folded = &merged[0]; // first-created key = (10, 20)
    assert_eq!(folded.nodes.len(), 3, "three node back-references");
    let summed: u64 = folded.stats[0].packets + folded.stats[1].packets;
    assert_eq!(summed, 4, "4 of the 5 packets carried this ip pair");

    // Back-references resolve to per-node detail (rollup drill-down path).
    let per_node: u64 = folded
        .nodes
        .iter()
        .map(|&id| {
            let s = agg.stream(id).expect("node resolves");
            s.stats[0].packets + s.stats[1].packets
        })
        .sum();
    assert_eq!(per_node, summed, "merged stats are exactly the node sum");

    let single = &merged[1];
    assert_eq!(single.nodes.len(), 1);
}

#[test]
fn traversal_and_summary() {
    let agg = run_fixture();

    let root_protocols: Vec<_> = agg.roots().map(|r| r.protocol).collect();
    assert_eq!(root_protocols, ["eth", "eth", "eth"]);

    // children() in creation order, resolving to real streams.
    let first_root = agg.roots().next().expect("root");
    let children: Vec<_> = agg.children(first_root.id).map(|c| c.protocol).collect();
    assert_eq!(children, ["ipv4", "ipv4"], "two ip conversations under it");

    let summary = agg.summary();
    assert_eq!(summary.packets, 5);
    assert_eq!(summary.streams_created, 7); // 3 eth + 4 ipv4 nodes
    assert_eq!(summary.streams_live, 7);
    let per_protocol: Vec<_> = summary
        .per_protocol
        .iter()
        .map(|c| (c.protocol, c.ever, c.live))
        .collect();
    assert_eq!(per_protocol, [("eth", 3, 3), ("ipv4", 4, 4)]);
    // All fixture packets stopped Complete → Clean.
    assert_eq!(summary.stop_classes[0].1, 5);
}

#[test]
fn snapshot_is_deep_and_send_sync() {
    fn assert_send_sync<T: Send + Sync>(_: &T) {}

    let mut agg = run_fixture();
    let snapshot = agg.snapshot();
    assert_send_sync(&snapshot);

    let packets_before = snapshot.summary.packets;
    let streams_before = snapshot.streams.len();
    let first_stats_before = snapshot.streams[0].stats;

    // Mutate the aggregator afterward…
    for i in 0..10 {
        agg.ingest(&packet(
            vec![layer("eth", 1, 2), layer("ipv4", 10, 20)],
            100 + i,
        ));
    }
    assert_eq!(agg.summary().packets, packets_before + 10);

    // …the snapshot is unmoved.
    assert_eq!(snapshot.summary.packets, packets_before);
    assert_eq!(snapshot.streams.len(), streams_before);
    assert_eq!(snapshot.streams[0].stats, first_stats_before);

    // And it can cross threads (D5's consumer story).
    let handle = std::thread::spawn(move || -> AggregatorSnapshot { snapshot });
    let snapshot = handle.join().expect("thread returns the snapshot");
    assert_eq!(snapshot.summary.packets, packets_before);
}
