//! Unknown-occurrence registry (10.2): ingest correctness, `max_groups` /
//! `samples_per_group` bounding, determinism, and independence from stream
//! eviction (05.6).

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use pktflow_core::{
    Canonicalize, Confidence, DissectedPacket, Engine, FieldMap, KeyField, LayerPlugin,
    LayerRecord, LinkType, PacketMeta, ParseCtx, ParseError, ParsedLayer, ProtocolName, RouteId,
    StopReason, StreamIdentity, UnknownContext, UnknownDiagnostics, Value,
};
use pktflow_flows::{
    Aggregator, AggregatorConfig, EndpointKey, EvictionPolicy, UnknownKey, UnknownRegistryConfig,
};
use smallvec::SmallVec;

static PAIR_KEY: &[KeyField] = &[KeyField {
    a: "src",
    b: Some("dst"),
}];

/// Identity-bearing test plugin; ingest never calls `parse`.
struct Keyed {
    name: ProtocolName,
    identity: StreamIdentity,
}

impl LayerPlugin for Keyed {
    fn name(&self) -> ProtocolName {
        self.name
    }

    fn parse(&self, _bytes: &[u8], _ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        Err(ParseError::Malformed("ingest-only test plugin"))
    }

    fn stream_identity(&self) -> Option<&StreamIdentity> {
        Some(&self.identity)
    }
}

fn keyed(name: ProtocolName) -> Keyed {
    Keyed {
        name,
        identity: StreamIdentity {
            key: PAIR_KEY,
            canonicalize: Canonicalize::EndpointSort,
            lifecycle: None,
            rollups: &[],
        },
    }
}

fn engine() -> Arc<Engine> {
    Arc::new(
        Engine::builder()
            .plugin(keyed("udp"))
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

fn near_misses(pairs: &[(ProtocolName, u8)]) -> SmallVec<[(ProtocolName, Confidence); 5]> {
    pairs
        .iter()
        .map(|&(n, c)| (n, Confidence::new(c)))
        .collect()
}

/// A packet whose dissection stops with `Hint::Candidates`-style
/// `UnclaimedRoute` right after a `udp` layer — the same shape 10.1's
/// integration tests use, with diagnostics attached.
fn unknown_packet(route: RouteId, sample: &[u8], ms: u64, src: u64, dst: u64) -> DissectedPacket {
    DissectedPacket {
        meta: PacketMeta {
            timestamp: SystemTime::UNIX_EPOCH + Duration::from_millis(ms),
            caplen: 64,
            origlen: 64,
            link_type: LinkType::ETHERNET,
        },
        layers: vec![layer("udp", src, dst)],
        stop: StopReason::UnclaimedRoute(route),
        opaque_len: sample.len(),
        unknown: Some(UnknownDiagnostics {
            context: UnknownContext::UnclaimedRoute {
                predecessor: "udp",
                route,
            },
            near_misses: near_misses(&[]),
            sample: sample.to_vec().into_boxed_slice(),
        }),
    }
}

fn aggregator(config: AggregatorConfig) -> Aggregator {
    Aggregator::new(&engine(), config)
}

#[test]
fn ingest_tracks_two_interleaved_shapes_correctly() {
    let mut agg = aggregator(AggregatorConfig::default());
    let a = RouteId::UdpPort(4433);
    let b = RouteId::UdpPort(9999);

    agg.ingest(&unknown_packet(a, &[0xAA; 10], 0, 1, 2));
    agg.ingest(&unknown_packet(b, &[0xBB; 20], 1, 1, 2));
    agg.ingest(&unknown_packet(a, &[0xAA; 30], 2, 1, 2));
    agg.ingest(&unknown_packet(b, &[0xBB; 5], 3, 1, 2));
    agg.ingest(&unknown_packet(a, &[0xAA; 15], 4, 1, 2));

    let key_a = UnknownKey {
        predecessor: "udp",
        route: Some(a),
    };
    let key_b = UnknownKey {
        predecessor: "udp",
        route: Some(b),
    };

    let group_a = agg.unknown_group(&key_a).expect("group a exists");
    assert_eq!(group_a.count, 3);
    assert_eq!(group_a.bytes_total, 10 + 30 + 15);
    assert_eq!(group_a.bytes_min, 10);
    assert_eq!(group_a.bytes_max, 30);
    assert_eq!(
        group_a.first_seen,
        SystemTime::UNIX_EPOCH + Duration::from_millis(0)
    );
    assert_eq!(
        group_a.last_seen,
        SystemTime::UNIX_EPOCH + Duration::from_millis(4)
    );

    let group_b = agg.unknown_group(&key_b).expect("group b exists");
    assert_eq!(group_b.count, 2);
    assert_eq!(group_b.bytes_total, 20 + 5);
    assert_eq!(group_b.bytes_min, 5);
    assert_eq!(group_b.bytes_max, 20);

    assert_eq!(agg.unknowns().len(), 2);
}

#[test]
fn endpoints_reuse_the_parent_streams_canonical_key() {
    let mut agg = aggregator(AggregatorConfig::default());
    agg.ingest(&unknown_packet(RouteId::UdpPort(4433), &[0x01], 0, 1, 2));

    let key = UnknownKey {
        predecessor: "udp",
        route: Some(RouteId::UdpPort(4433)),
    };
    let group = agg.unknown_group(&key).expect("group exists");
    assert_eq!(group.endpoints.len(), 1);
    let stream = agg
        .streams()
        .find(|s| s.protocol == "udp")
        .expect("udp stream");
    assert_eq!(
        group.endpoints[0],
        EndpointKey {
            protocol: "udp",
            key: stream.key.clone(),
        }
    );
}

#[test]
fn max_groups_evicts_exactly_k_coldest_groups() {
    let config = AggregatorConfig {
        unknown: UnknownRegistryConfig {
            max_groups: 3,
            samples_per_group: 5,
        },
        ..AggregatorConfig::default()
    };
    let mut agg = aggregator(config);
    for port in 0..5u16 {
        agg.ingest(&unknown_packet(
            RouteId::UdpPort(port),
            &[0x01],
            u64::from(port),
            1,
            2,
        ));
    }
    assert_eq!(agg.unknowns().len(), 3, "cap enforced");
    for port in [0u16, 1] {
        let key = UnknownKey {
            predecessor: "udp",
            route: Some(RouteId::UdpPort(port)),
        };
        assert!(
            agg.unknown_group(&key).is_none(),
            "coldest two groups evicted, samples gone with them"
        );
    }
    for port in [2u16, 3, 4] {
        let key = UnknownKey {
            predecessor: "udp",
            route: Some(RouteId::UdpPort(port)),
        };
        assert!(agg.unknown_group(&key).is_some());
    }
}

#[test]
fn samples_per_group_ring_keeps_recent_bytes_identical_to_source() {
    let config = AggregatorConfig {
        unknown: UnknownRegistryConfig {
            max_groups: 10,
            samples_per_group: 3,
        },
        ..AggregatorConfig::default()
    };
    let mut agg = aggregator(config);
    let route = RouteId::UdpPort(53);
    let samples: Vec<Vec<u8>> = (0..5u8).map(|i| vec![i; 6]).collect();
    for (i, sample) in samples.iter().enumerate() {
        agg.ingest(&unknown_packet(route, sample, i as u64, 1, 2));
    }
    let key = UnknownKey {
        predecessor: "udp",
        route: Some(route),
    };
    let group = agg.unknown_group(&key).expect("group exists");
    assert_eq!(group.samples.len(), 3);
    let kept: Vec<&[u8]> = group.samples.iter().map(|s| &**s).collect();
    assert_eq!(kept, [&samples[2][..], &samples[3][..], &samples[4][..]]);
}

#[test]
fn identical_runs_produce_identical_unknowns_ordering_and_contents() {
    let run = || {
        let mut agg = aggregator(AggregatorConfig::default());
        agg.ingest(&unknown_packet(RouteId::UdpPort(1), &[0x01], 0, 1, 2));
        agg.ingest(&unknown_packet(RouteId::UdpPort(2), &[0x02], 1, 3, 4));
        agg.ingest(&unknown_packet(RouteId::UdpPort(2), &[0x03], 2, 3, 4));
        agg.ingest(&unknown_packet(RouteId::UdpPort(3), &[0x04], 3, 5, 6));
        agg.unknowns()
            .into_iter()
            .map(|g| (g.key.clone(), g.count, g.bytes_total))
            .collect::<Vec<_>>()
    };
    assert_eq!(run(), run());
}

#[test]
fn unknown_group_survives_its_endpoint_streams_eviction() {
    let config = AggregatorConfig {
        eviction: EvictionPolicy::Live {
            idle_timeout: Duration::from_millis(5),
            close_linger: Duration::from_millis(5),
            max_streams: 100,
        },
        ..AggregatorConfig::default()
    };
    let mut agg = aggregator(config);
    let route = RouteId::UdpPort(4433);
    agg.ingest(&unknown_packet(route, &[0xAA], 0, 1, 2));

    let key = UnknownKey {
        predecessor: "udp",
        route: Some(route),
    };
    assert!(agg.unknown_group(&key).is_some(), "recorded on first sight");
    assert_eq!(agg.len(), 1, "the udp stream is live");

    // Advance the packet-time clock well past idle_timeout with an
    // unrelated packet so the sweep evicts the udp stream.
    agg.ingest(&unknown_packet(
        RouteId::UdpPort(9999),
        &[0xBB],
        1_000,
        9,
        10,
    ));

    assert!(
        agg.streams()
            .all(|s| s.protocol != "udp" || s.key_fields.get("src") != Some(&Value::U64(1))),
        "the original udp stream was evicted"
    );
    let group = agg
        .unknown_group(&key)
        .expect("the unknown group survives the stream's eviction (D11 independent lifetime)");
    assert_eq!(group.count, 1);
    assert_eq!(group.endpoints.len(), 1, "endpoint context retained too");
}
