//! Flow hierarchy (05.3, FR-4/FR-8, D10): parent-scoped nesting falling
//! out of per-packet layer order — no tunnel special-casing anywhere.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use pktflow_core::{
    Canonicalize, DissectedPacket, Engine, FieldMap, KeyField, LayerPlugin, LayerRecord, LinkType,
    PacketMeta, ParseCtx, ParseError, ParsedLayer, ProtocolName, StopReason, StreamIdentity, Value,
};
use pktflow_flows::{Aggregator, AggregatorConfig, StreamId};
use proptest::prelude::*;

/// Identity-declaring ingest-only plugin with an endpoint pair key.
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

/// Tunnel-ish plugin keyed on a single shared (non-directional) id —
/// the GRE-key/VXLAN-VNI shape.
struct TunnelProto(ProtocolName);

static TUNNEL_KEY: &[KeyField] = &[KeyField {
    a: "tunnel_id",
    b: None,
}];
static TUNNEL_IDENTITY: StreamIdentity = StreamIdentity {
    key: TUNNEL_KEY,
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

impl LayerPlugin for TunnelProto {
    fn name(&self) -> ProtocolName {
        self.0
    }

    fn parse(&self, _bytes: &[u8], _ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        Err(ParseError::Malformed("ingest-only"))
    }

    fn stream_identity(&self) -> Option<&StreamIdentity> {
        Some(&TUNNEL_IDENTITY)
    }
}

fn engine() -> Arc<Engine> {
    Arc::new(
        Engine::builder()
            .plugin(PairProto("eth"))
            .plugin(PairProto("ipv4"))
            .plugin(PairProto("tcp"))
            .plugin(TunnelProto("gre"))
            .plugin(TunnelProto("vxlan"))
            .build()
            .expect("valid registry"),
    )
}

fn pair_layer(protocol: ProtocolName, src: u64, dst: u64) -> LayerRecord {
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

fn tunnel_layer(protocol: ProtocolName, id: u64) -> LayerRecord {
    let mut fields = FieldMap::new();
    fields.insert("tunnel_id", Value::U64(id));
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

/// Walks a root-to-leaf chain asserting one child at each level, returning
/// the protocol path.
fn single_chain(agg: &Aggregator) -> Vec<ProtocolName> {
    let root_ids: Vec<StreamId> = agg.roots().map(|r| r.id).collect();
    assert_eq!(root_ids.len(), 1, "one root");
    let mut path = Vec::new();
    let mut cursor: Option<StreamId> = root_ids.first().copied();
    while let Some(id) = cursor {
        let stream = agg.get(id).expect("chain node exists");
        path.push(stream.protocol);
        assert!(
            stream.children.len() <= 1,
            "fixture chains have at most one child per node"
        );
        cursor = stream.children.first().copied();
    }
    path
}

#[test]
fn gre_fixture_nests_the_exact_chain() {
    let mut agg = Aggregator::new(&engine(), AggregatorConfig::default());
    // [eth, ipv4, gre, ipv4, tcp]: the inner ipv4 rides inside the tunnel.
    agg.ingest(&packet(
        vec![
            pair_layer("eth", 1, 2),
            pair_layer("ipv4", 10, 20),
            tunnel_layer("gre", 7),
            pair_layer("ipv4", 100, 200),
            pair_layer("tcp", 443, 55000),
        ],
        0,
    ));

    assert_eq!(single_chain(&agg), ["eth", "ipv4", "gre", "ipv4", "tcp"]);

    // Node-by-node: the two ipv4 nodes are distinct streams with distinct
    // parents (outer under eth, inner under gre) — D10, zero engine
    // knowledge of "tunnel".
    let ipv4_nodes: Vec<_> = agg.streams().filter(|s| s.protocol == "ipv4").collect();
    assert_eq!(ipv4_nodes.len(), 2);
    let parents: Vec<_> = ipv4_nodes
        .iter()
        .map(|s| {
            s.parent
                .and_then(|p| agg.get(p))
                .map(|p| p.protocol)
                .expect("parent exists")
        })
        .collect();
    assert_eq!(parents, ["eth", "gre"]);
}

#[test]
fn vxlan_fixture_nests_the_exact_chain() {
    let mut agg = Aggregator::new(&engine(), AggregatorConfig::default());
    // VXLAN wraps a full inner ethernet.
    agg.ingest(&packet(
        vec![
            pair_layer("eth", 1, 2),
            pair_layer("ipv4", 10, 20),
            tunnel_layer("vxlan", 5001),
            pair_layer("eth", 31, 32),
            pair_layer("ipv4", 100, 200),
        ],
        0,
    ));

    assert_eq!(single_chain(&agg), ["eth", "ipv4", "vxlan", "eth", "ipv4"]);
}

#[test]
fn consequence_1_same_port_pair_under_two_ip_conversations() {
    let mut agg = Aggregator::new(&engine(), AggregatorConfig::default());
    // Identical tcp key (ports only, 02.4) under two ip conversations.
    agg.ingest(&packet(
        vec![
            pair_layer("eth", 1, 2),
            pair_layer("ipv4", 10, 20),
            pair_layer("tcp", 443, 55000),
        ],
        0,
    ));
    agg.ingest(&packet(
        vec![
            pair_layer("eth", 1, 2),
            pair_layer("ipv4", 30, 40),
            pair_layer("tcp", 443, 55000),
        ],
        1,
    ));

    let tcp_nodes: Vec<_> = agg.streams().filter(|s| s.protocol == "tcp").collect();
    assert_eq!(tcp_nodes.len(), 2, "two distinct sessions (D10)");
    assert_ne!(tcp_nodes[0].parent, tcp_nodes[1].parent);
    assert_eq!(tcp_nodes[0].key, tcp_nodes[1].key, "same ports-only key");
}

#[test]
fn consequence_2_same_ip_pair_under_two_mac_conversations() {
    let mut agg = Aggregator::new(&engine(), AggregatorConfig::default());
    // Same ip pair before/after re-resolution to a new gateway MAC.
    agg.ingest(&packet(
        vec![pair_layer("eth", 1, 2), pair_layer("ipv4", 10, 20)],
        0,
    ));
    agg.ingest(&packet(
        vec![pair_layer("eth", 1, 3), pair_layer("ipv4", 10, 20)],
        1,
    ));

    let ip_nodes: Vec<_> = agg.streams().filter(|s| s.protocol == "ipv4").collect();
    assert_eq!(ip_nodes.len(), 2, "one node per MAC parent");
    assert_ne!(ip_nodes[0].parent, ip_nodes[1].parent);
    // A stream's parent never changed: both packets' ip layers landed on
    // their own nodes rather than re-parenting the first.
    assert_eq!(
        ip_nodes[0].stats[0].packets + ip_nodes[0].stats[1].packets,
        1
    );
}

proptest! {
    /// Hierarchy integrity over random synthetic captures: every
    /// non-root's parent exists, parent/child links are mutually
    /// consistent, and parent chains terminate (no cycles).
    #[test]
    fn hierarchy_integrity(
        capture in proptest::collection::vec(
            proptest::collection::vec((0usize..4, 0u64..4, 0u64..4), 1..5),
            1..40,
        )
    ) {
        const PROTOCOLS: [&str; 4] = ["eth", "ipv4", "gre", "tcp"];
        let mut agg = Aggregator::new(&engine(), AggregatorConfig::default());

        for (ms, stack) in capture.iter().enumerate() {
            let layers = stack
                .iter()
                .map(|&(proto, src, dst)| match PROTOCOLS[proto] {
                    "gre" => tunnel_layer("gre", src),
                    name => pair_layer(name, src, dst),
                })
                .collect();
            agg.ingest(&packet(layers, ms as u64));
        }

        let stream_count = agg.len();
        for stream in agg.streams() {
            match stream.parent {
                None => {
                    prop_assert!(
                        agg.roots().any(|r| r.id == stream.id),
                        "rootless non-child {:?}", stream.id
                    );
                }
                Some(parent_id) => {
                    let parent = agg.get(parent_id);
                    prop_assert!(parent.is_some(), "dangling parent {parent_id:?}");
                    if let Some(parent) = parent {
                        prop_assert!(
                            parent.children.contains(&stream.id),
                            "parent {:?} disowns child {:?}", parent_id, stream.id
                        );
                    }
                }
            }
            // Children agree their parent is this stream.
            for &child_id in &stream.children {
                let child = agg.get(child_id);
                prop_assert!(child.is_some());
                if let Some(child) = child {
                    prop_assert_eq!(child.parent, Some(stream.id));
                }
            }
            // No cycles: the parent chain must terminate within the
            // stream count.
            let mut hops = 0;
            let mut cursor = stream.parent;
            while let Some(id) = cursor {
                hops += 1;
                prop_assert!(hops <= stream_count, "parent cycle at {:?}", stream.id);
                cursor = agg.get(id).and_then(|s| s.parent);
            }
        }
    }
}
