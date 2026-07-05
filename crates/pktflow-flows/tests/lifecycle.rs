//! Lifecycle state (05.5, FR-6): protocol-defined session state machines,
//! engine-executed — one state variable per stream, plugin-owned pure
//! transition function.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use pktflow_core::{
    Canonicalize, DissectedPacket, Engine, FieldMap, KeyField, LayerPlugin, LayerRecord,
    LifecycleSpec, LinkType, PacketDirection, PacketMeta, ParseCtx, ParseError, ParsedLayer,
    ProtocolName, StateName, StopReason, StreamIdentity, Value,
};
use pktflow_flows::{Aggregator, AggregatorConfig};

static PAIR_KEY: &[KeyField] = &[KeyField {
    a: "src",
    b: Some("dst"),
}];

/// The test protocol's handshake machine. Directions matter: the SYN-ACK
/// counts only from the responder (BtoA), the final ACK only from the
/// initiator.
fn advance(fields: &FieldMap, state: StateName, dir: PacketDirection) -> StateName {
    let flag = match fields.get("flag") {
        Some(Value::U64(f)) => *f,
        // Pure and total: unrecognized input returns the state unchanged.
        _ => return state,
    };
    match (state, flag, dir) {
        ("new", 1, PacketDirection::AtoB) => "syn_sent",
        ("syn_sent", 2, PacketDirection::BtoA) => "half_open",
        ("half_open", 3, PacketDirection::AtoB) => "established",
        ("established", 9, _) => "closed",
        ("closed", 7, _) => "new", // modeled reopen — cancels eligibility
        _ => state,
    }
}

static SESSION_IDENTITY: StreamIdentity = StreamIdentity {
    key: PAIR_KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: Some(LifecycleSpec {
        initial: "new",
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

struct Session;
struct Plain;

impl LayerPlugin for Session {
    fn name(&self) -> ProtocolName {
        "session"
    }

    fn parse(&self, _bytes: &[u8], _ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        Err(ParseError::Malformed("ingest-only"))
    }

    fn stream_identity(&self) -> Option<&StreamIdentity> {
        Some(&SESSION_IDENTITY)
    }
}

impl LayerPlugin for Plain {
    fn name(&self) -> ProtocolName {
        "plain"
    }

    fn parse(&self, _bytes: &[u8], _ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        Err(ParseError::Malformed("ingest-only"))
    }

    fn stream_identity(&self) -> Option<&StreamIdentity> {
        Some(&PLAIN_IDENTITY)
    }
}

/// `src=1` sorts below `dst=2`, so client→server packets are AtoB.
fn pkt(protocol: ProtocolName, client_to_server: bool, flag: u64, ms: u64) -> DissectedPacket {
    let (src, dst) = if client_to_server { (1, 2) } else { (2, 1) };
    let mut fields = FieldMap::new();
    fields.insert("src", Value::U64(src));
    fields.insert("dst", Value::U64(dst));
    fields.insert("flag", Value::U64(flag));
    DissectedPacket {
        meta: PacketMeta {
            timestamp: SystemTime::UNIX_EPOCH + Duration::from_millis(ms),
            caplen: 64,
            origlen: 64,
            link_type: LinkType::ETHERNET,
        },
        layers: vec![LayerRecord {
            protocol,
            offset: 0,
            header_len: 0,
            fields,
        }],
        stop: StopReason::Complete,
        opaque_len: 0,
    }
}

fn aggregator() -> Aggregator {
    let engine = Arc::new(
        Engine::builder()
            .plugin(Session)
            .plugin(Plain)
            .build()
            .expect("valid registry"),
    );
    Aggregator::new(&engine, AggregatorConfig::default())
}

fn state_of(agg: &Aggregator) -> Option<StateName> {
    agg.streams().next().expect("one stream").state
}

#[test]
fn three_way_handshake_with_directions_honored() {
    let mut agg = aggregator();

    agg.ingest(&pkt("session", true, 1, 0)); // SYN →
    assert_eq!(state_of(&agg), Some("syn_sent"));

    // A SYN-ACK from the *wrong* direction must not advance the machine.
    agg.ingest(&pkt("session", true, 2, 1));
    assert_eq!(state_of(&agg), Some("syn_sent"), "direction honored");

    agg.ingest(&pkt("session", false, 2, 2)); // ← SYN-ACK
    assert_eq!(state_of(&agg), Some("half_open"));

    agg.ingest(&pkt("session", true, 3, 3)); // ACK →
    assert_eq!(state_of(&agg), Some("established"));

    let stream = agg.streams().next().expect("one stream");
    assert!(!stream.close_eligible);
    assert_eq!(stream.stats[0].packets + stream.stats[1].packets, 4);
}

#[test]
fn teardown_flips_close_eligibility_and_linger_packets_still_count() {
    let mut agg = aggregator();
    for (c2s, flag) in [(true, 1), (false, 2), (true, 3)] {
        agg.ingest(&pkt("session", c2s, flag, 0));
    }
    assert_eq!(state_of(&agg), Some("established"));

    agg.ingest(&pkt("session", true, 9, 10)); // teardown
    {
        let stream = agg.streams().next().expect("one stream");
        assert_eq!(stream.state, Some("closed"));
        assert!(stream.close_eligible, "closed state marks eligibility");
    }

    // Mid-linger straggler (late FIN-ACK/retransmit): still counted.
    agg.ingest(&pkt("session", false, 0, 11));
    {
        let stream = agg.streams().next().expect("one stream");
        assert_eq!(stream.stats[0].packets + stream.stats[1].packets, 5);
        assert_eq!(stream.state, Some("closed"));
        assert!(stream.close_eligible, "unrecognized input keeps state");
    }

    // A transition *out* of a closed state cancels eligibility.
    agg.ingest(&pkt("session", true, 7, 12));
    let stream = agg.streams().next().expect("one stream");
    assert_eq!(stream.state, Some("new"));
    assert!(!stream.close_eligible, "reopen cancels close-eligibility");
}

#[test]
fn no_lifecycle_plugin_has_no_state_ever() {
    let mut agg = aggregator();
    for flag in [1, 2, 3, 9] {
        agg.ingest(&pkt("plain", true, flag, 0));
    }
    let stream = agg.streams().next().expect("one stream");
    assert_eq!(stream.state, None, "FR-6 is opt-in");
    assert!(!stream.close_eligible);
    assert_eq!(stream.stats[0].packets, 4);
}
