//! 09.2 `ExpectedStreams`: pairs a fixture's `CaptureBuilder` with the
//! stream tree it must produce through the *real* engine + aggregator —
//! bytes in, protocol hierarchy out. Deliberately separate from
//! `json_output.rs`'s schema/text checks: this validates tree
//! correctness against the in-process `Aggregator`, not the CLI's
//! text/JSON rendering.

use std::sync::Arc;

use pktflow_core::{LinkType, PacketMeta, ParseOpts};
use pktflow_flows::{Aggregator, AggregatorConfig, AggregatorSnapshot, Stream, StreamId};
use pktflow_testkit::CaptureBuilder;

/// One node's expectations: protocol, per-direction packet counts
/// (`dir_index` order: `[a_to_b, b_to_a]`), and children in creation
/// order. Only what a fixture cares about — not a full-field snapshot.
pub struct ExpectedStream {
    pub protocol: &'static str,
    pub packets: [u64; 2],
    pub children: Vec<ExpectedStream>,
}

impl ExpectedStream {
    pub fn new(protocol: &'static str, packets: [u64; 2]) -> Self {
        Self {
            protocol,
            packets,
            children: Vec::new(),
        }
    }

    pub fn child(mut self, child: ExpectedStream) -> Self {
        self.children.push(child);
        self
    }
}

/// Runs a capture through the default engine + a fresh aggregator
/// (no eviction), returning the resulting snapshot.
pub fn run(capture: &CaptureBuilder) -> AggregatorSnapshot {
    run_with_config(capture, AggregatorConfig::default())
}

pub fn run_with_config(capture: &CaptureBuilder, config: AggregatorConfig) -> AggregatorSnapshot {
    let engine = Arc::new(pktflow_plugins::default_engine());
    let mut agg = Aggregator::new(&engine, config);
    for (ts, bytes) in capture.clone().packets() {
        let meta = PacketMeta {
            timestamp: ts,
            caplen: bytes.len(),
            origlen: bytes.len(),
            link_type: LinkType::ETHERNET,
        };
        let dissected = engine.dissect(&bytes, meta, ParseOpts::default());
        agg.ingest(&dissected);
    }
    agg.snapshot()
}

fn find(snapshot: &AggregatorSnapshot, id: StreamId) -> &Stream {
    snapshot
        .streams
        .iter()
        .find(|s| s.id == id)
        .expect("live stream id from snapshot.roots/children")
}

/// Asserts `snapshot`'s root-to-leaf stream tree matches `expected`, in
/// creation order.
pub fn assert_tree(snapshot: &AggregatorSnapshot, expected: &[ExpectedStream]) {
    let root_protocols: Vec<_> = snapshot
        .roots
        .iter()
        .map(|id| find(snapshot, *id).protocol)
        .collect();
    assert_eq!(
        snapshot.roots.len(),
        expected.len(),
        "root count: got {root_protocols:?}, want {} roots",
        expected.len()
    );
    for (id, exp) in snapshot.roots.iter().zip(expected) {
        assert_node(snapshot, *id, exp, "root");
    }
}

fn assert_node(snapshot: &AggregatorSnapshot, id: StreamId, expected: &ExpectedStream, path: &str) {
    let stream = find(snapshot, id);
    assert_eq!(stream.protocol, expected.protocol, "protocol at {path}");
    let packets = stream.stats.map(|d| d.packets);
    assert_eq!(
        packets, expected.packets,
        "packet counts at {path}>{} ",
        expected.protocol
    );
    let child_protocols: Vec<_> = stream
        .children
        .iter()
        .map(|c| find(snapshot, *c).protocol)
        .collect();
    assert_eq!(
        stream.children.len(),
        expected.children.len(),
        "child count at {path}>{}: got {child_protocols:?}",
        expected.protocol
    );
    for (i, (child_id, child_exp)) in stream.children.iter().zip(&expected.children).enumerate() {
        assert_node(
            snapshot,
            *child_id,
            child_exp,
            &format!("{path}>{}[{i}]", expected.protocol),
        );
    }
}
