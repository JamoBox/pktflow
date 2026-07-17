//! Memory bounds & eviction (05.6, D2): packet-time clock means every
//! test here is instant — no sleeps anywhere.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use pktflow_core::{
    Canonicalize, DissectedPacket, Engine, FieldMap, KeyField, LayerPlugin, LayerRecord,
    LifecycleSpec, LinkType, PacketDirection, PacketMeta, ParseCtx, ParseError, ParsedLayer,
    ProtocolName, StateName, StopReason, StreamIdentity, Value,
};
use pktflow_flows::{
    Aggregator, AggregatorConfig, CloseReason, EvictionPolicy, UnknownRegistryConfig,
};

static PAIR_KEY: &[KeyField] = &[KeyField {
    a: "src",
    b: Some("dst"),
}];

fn advance(fields: &FieldMap, state: StateName, _dir: PacketDirection) -> StateName {
    match fields.get("flag") {
        Some(Value::U64(9)) => "closed",
        _ => state,
    }
}

static SESSION_IDENTITY: StreamIdentity = StreamIdentity {
    key: PAIR_KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: Some(LifecycleSpec {
        initial: "open",
        advance,
        closed_states: &["closed"],
    }),
    rollups: &[],
};
static PLAIN_IDENTITY: StreamIdentity = StreamIdentity {
    key: PAIR_KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: &[],
};

struct Proto {
    name: ProtocolName,
    lifecycle: bool,
}

impl LayerPlugin for Proto {
    fn name(&self) -> ProtocolName {
        self.name
    }

    fn parse(&self, _bytes: &[u8], _ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        Err(ParseError::Malformed("ingest-only"))
    }

    fn stream_identity(&self) -> Option<&StreamIdentity> {
        Some(if self.lifecycle {
            &SESSION_IDENTITY
        } else {
            &PLAIN_IDENTITY
        })
    }
}

fn engine() -> Arc<Engine> {
    Arc::new(
        Engine::builder()
            .plugin(Proto {
                name: "eth",
                lifecycle: false,
            })
            .plugin(Proto {
                name: "session",
                lifecycle: true,
            })
            .build()
            .expect("valid registry"),
    )
}

type SinkLog = Arc<Mutex<Vec<(ProtocolName, CloseReason)>>>;

fn live_aggregator(max_streams: usize) -> (Aggregator, SinkLog) {
    let log: SinkLog = Arc::new(Mutex::new(Vec::new()));
    let log_clone = Arc::clone(&log);
    let config = AggregatorConfig {
        eviction: EvictionPolicy::Live {
            idle_timeout: Duration::from_secs(300),
            close_linger: Duration::from_secs(15),
            max_streams,
        },
        sink: Some(Box::new(move |evicted| {
            log_clone
                .lock()
                .expect("sink lock")
                .push((evicted.stream.protocol, evicted.reason));
        })),
        condense_threshold: pktflow_flows::DEFAULT_CONDENSE_THRESHOLD,
        rollup_series_default_cap: 1024,
        rollup_series_max_cap: None,
        unknown: UnknownRegistryConfig::default(),
    };
    (Aggregator::new(&engine(), config), log)
}

fn layer(protocol: ProtocolName, src: u64, dst: u64, flag: u64) -> LayerRecord {
    let mut fields = FieldMap::new();
    fields.insert("src", Value::U64(src));
    fields.insert("dst", Value::U64(dst));
    fields.insert("flag", Value::U64(flag));
    LayerRecord {
        protocol,
        offset: 0,
        header_len: 0,
        fields,
    }
}

fn packet(layers: Vec<LayerRecord>, secs: u64) -> DissectedPacket {
    DissectedPacket {
        meta: PacketMeta {
            timestamp: SystemTime::UNIX_EPOCH + Duration::from_secs(secs),
            caplen: 64,
            origlen: 64,
            link_type: LinkType::ETHERNET,
        },
        layers,
        stop: StopReason::Complete,
        opaque_len: 0,
        unknown: None,
    }
}

fn drained(log: &SinkLog) -> Vec<(ProtocolName, CloseReason)> {
    log.lock().expect("sink lock").clone()
}

#[test]
fn all_four_close_reasons_are_reachable() {
    // ProtocolClose: lifecycle closes at t=0; clock advances past the 15s
    // linger via an unrelated stream's packet.
    let (mut agg, log) = live_aggregator(1_000_000);
    agg.ingest(&packet(vec![layer("session", 1, 2, 9)], 0));
    agg.ingest(&packet(vec![layer("eth", 8, 9, 0)], 16));
    assert_eq!(drained(&log), vec![("session", CloseReason::ProtocolClose)]);

    // IdleTimeout: silent for 301s.
    let (mut agg, log) = live_aggregator(1_000_000);
    agg.ingest(&packet(vec![layer("eth", 1, 2, 0)], 0));
    agg.ingest(&packet(vec![layer("eth", 8, 9, 0)], 301));
    assert_eq!(drained(&log), vec![("eth", CloseReason::IdleTimeout)]);

    // LruEvicted: see the cap test below; CaptureEnd: finish().
    let (mut agg, log) = live_aggregator(1);
    agg.ingest(&packet(vec![layer("eth", 1, 2, 0)], 0));
    agg.ingest(&packet(vec![layer("eth", 3, 4, 0)], 1));
    assert_eq!(drained(&log), vec![("eth", CloseReason::LruEvicted)]);

    let (mut agg, log) = live_aggregator(1_000_000);
    agg.ingest(&packet(vec![layer("eth", 1, 2, 0)], 0));
    agg.finish();
    assert_eq!(drained(&log), vec![("eth", CloseReason::CaptureEnd)]);
}

#[test]
fn leaf_first_parent_survives_until_its_child_goes() {
    let (mut agg, log) = live_aggregator(1_000_000);
    // eth ▸ session, both silent from t=0; unrelated packet at t=301
    // sweeps them.
    agg.ingest(&packet(
        vec![layer("eth", 1, 2, 0), layer("session", 10, 20, 0)],
        0,
    ));
    agg.ingest(&packet(vec![layer("eth", 8, 9, 0)], 301));

    // Both fell, child strictly before parent — the parent was skipped
    // while its child lived and re-armed by the child's eviction.
    assert_eq!(
        drained(&log),
        vec![
            ("session", CloseReason::IdleTimeout),
            ("eth", CloseReason::IdleTimeout),
        ]
    );
    assert_eq!(agg.len(), 1, "only the fresh unrelated stream remains");
}

#[test]
fn max_streams_evicts_exactly_k_lru_leaves() {
    let (mut agg, log) = live_aggregator(3);
    // Five root leaves, oldest first (cap + k with k = 2).
    for i in 0..5u64 {
        agg.ingest(&packet(vec![layer("eth", i * 2 + 1, i * 2 + 2, 0)], i));
    }

    let evicted = drained(&log);
    assert_eq!(evicted.len(), 2, "exactly k evictions");
    assert!(evicted
        .iter()
        .all(|&(_, reason)| reason == CloseReason::LruEvicted));
    assert_eq!(agg.len(), 3);

    // The survivors are the three most recently updated.
    let survivors: Vec<u64> = {
        let mut firsts: Vec<_> = agg
            .streams()
            .map(|s| {
                s.first_seen
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .expect("epoch-based")
                    .as_secs()
            })
            .collect();
        firsts.sort_unstable();
        firsts
    };
    assert_eq!(survivors, [2, 3, 4]);
}

#[test]
fn post_eviction_recurrence_is_a_fresh_stream_and_old_handles_fail() {
    let (mut agg, _log) = live_aggregator(1_000_000);
    agg.ingest(&packet(vec![layer("eth", 1, 2, 0)], 0));
    let old_id = agg.streams().next().expect("stream").id;

    // Idle out, then the same key recurs.
    agg.ingest(&packet(vec![layer("eth", 8, 9, 0)], 301));
    assert!(agg.get(old_id).is_none(), "evicted");

    agg.ingest(&packet(vec![layer("eth", 1, 2, 0)], 302));
    let new_id = agg
        .streams()
        .find(|s| s.first_seen == SystemTime::UNIX_EPOCH + Duration::from_secs(302))
        .expect("recurred stream")
        .id;
    assert_ne!(old_id, new_id, "new generation, no ABA");
    assert!(agg.get(old_id).is_none(), "stale handle still fails");
    assert_eq!(agg.totals().streams_created, 3);
    // Aggregate counters survived the eviction (FR-27).
    assert_eq!(agg.totals().packets, 3);
}

#[test]
fn offline_finish_retains_closed_streams_for_the_final_report() {
    let log: SinkLog = Arc::new(Mutex::new(Vec::new()));
    let log_clone = Arc::clone(&log);
    let config = AggregatorConfig {
        eviction: EvictionPolicy::None,
        sink: Some(Box::new(move |evicted| {
            log_clone
                .lock()
                .expect("sink lock")
                .push((evicted.stream.protocol, evicted.reason));
        })),
        condense_threshold: pktflow_flows::DEFAULT_CONDENSE_THRESHOLD,
        rollup_series_default_cap: 1024,
        rollup_series_max_cap: None,
        unknown: UnknownRegistryConfig::default(),
    };
    let mut agg = Aggregator::new(&engine(), config);
    agg.ingest(&packet(
        vec![layer("eth", 1, 2, 0), layer("session", 10, 20, 0)],
        0,
    ));

    agg.finish();

    // Sink saw everything, children before parents.
    assert_eq!(
        drained(&log),
        vec![
            ("session", CloseReason::CaptureEnd),
            ("eth", CloseReason::CaptureEnd),
        ]
    );
    // Store still queryable: streams retained, marked closed.
    assert_eq!(agg.len(), 2);
    assert!(agg
        .streams()
        .all(|s| s.closed == Some(CloseReason::CaptureEnd)));
}
