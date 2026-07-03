//! Full-pipeline proof with zero real-protocol involvement (06.1): a
//! synthetic PKTT-in-PKTT capture dissects through the default engine and
//! aggregates into a nested stream — the CLI view (08) reads this same
//! query API.

use std::sync::Arc;
use std::time::SystemTime;

use pktflow_core::{LinkType, PacketMeta, ParseOpts, StopReason};
use pktflow_flows::{Aggregator, AggregatorConfig};
use pktflow_plugins::default_engine;

#[test]
fn pktt_in_pktt_nests_a_stream() {
    let engine = Arc::new(default_engine());

    // Outer PKTT (type=1: wraps another PKTT) carrying an inner terminal
    // PKTT frame.
    let bytes: Vec<u8> = vec![
        0x00, 0x0A, 0x00, 0x0B, 0x00, 0x01, 0x00, 0x10, // outer: 10 -> 11
        0x00, 0x01, 0x00, 0x02, 0x00, 0x02, 0x00, 0x08, // inner: 1 -> 2
    ];
    let meta = PacketMeta {
        timestamp: SystemTime::UNIX_EPOCH,
        caplen: bytes.len(),
        origlen: bytes.len(),
        link_type: LinkType::ETHERNET,
    };
    // PKTT claims a custom space, not a link type: force the entry.
    let opts = ParseOpts {
        entry: Some("template"),
        ..ParseOpts::default()
    };

    let packet = engine.dissect(&bytes, meta, opts);
    let protocols: Vec<_> = packet.layers.iter().map(|l| l.protocol).collect();
    assert_eq!(protocols, ["template", "template"]);
    assert_eq!(packet.stop, StopReason::Complete);

    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());
    agg.ingest(&packet);

    // One root PKTT conversation with one nested PKTT conversation.
    let roots: Vec<_> = agg.roots().collect();
    assert_eq!(roots.len(), 1);
    let outer = roots[0];
    assert_eq!(outer.protocol, "template");
    let children: Vec<_> = agg.children(outer.id).collect();
    assert_eq!(children.len(), 1, "inner PKTT nests under the outer");
    assert_eq!(children[0].protocol, "template");
    assert_eq!(children[0].parent, Some(outer.id));

    // The declared Accumulate rollup on `type` recorded the outer's value.
    let type_rollup = outer.rollups.get("type").expect("declared rollup");
    match type_rollup {
        pktflow_flows::Rollup::Accumulate { values, count, .. } => {
            assert_eq!(*count, 1);
            assert_eq!(values.as_slice(), [pktflow_core::Value::U64(1)]);
        }
        other => panic!("wrong rollup kind: {other:?}"),
    }
}
