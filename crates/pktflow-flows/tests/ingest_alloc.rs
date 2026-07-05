//! 05.2 allocation-sanity criterion: 100k synthetic packets across 10k
//! streams. `unsafe_code` is forbidden in this crate (00.1), so instead of
//! a counting global allocator the test proves the two facts that make the
//! hot path allocation-free, plus the scale run itself:
//!
//! - every key produced by the common-protocol shapes stays within
//!   `FlowKey`'s 40 inline bytes (the 05.1 SmallVec criterion this one
//!   ties to), and the key scratch buffers are inline `SmallVec`s by
//!   construction;
//! - steady-state ingest (packets 10k..100k) creates zero new streams —
//!   the only allocating path — while stats/lookup stay exact.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use pktflow_core::{
    Canonicalize, DissectedPacket, Engine, FieldMap, KeyField, LayerPlugin, LayerRecord, LinkType,
    PacketMeta, ParseCtx, ParseError, ParsedLayer, ProtocolName, StopReason, StreamIdentity, Value,
};
use pktflow_flows::{flow_key, Aggregator, AggregatorConfig};

struct Pair;

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

impl LayerPlugin for Pair {
    fn name(&self) -> ProtocolName {
        "pair"
    }

    fn parse(&self, _bytes: &[u8], _ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        Err(ParseError::Malformed("ingest-only"))
    }

    fn stream_identity(&self) -> Option<&StreamIdentity> {
        Some(&PAIR_IDENTITY)
    }
}

/// MAC-shaped 6-byte endpoints: the realistic common case.
fn fields_for(stream: u64) -> FieldMap {
    let mut fields = FieldMap::new();
    let mut a = [0u8; 6];
    a[..2].copy_from_slice(&[0, 1]);
    a[2..].copy_from_slice(&((stream * 2 + 1) as u32).to_be_bytes());
    let mut b = [0u8; 6];
    b[..2].copy_from_slice(&[0, 2]);
    b[2..].copy_from_slice(&((stream * 2 + 2) as u32).to_be_bytes());
    fields.insert("src", Value::from(&a[..]));
    fields.insert("dst", Value::from(&b[..]));
    fields
}

fn packet(stream: u64, ms: u64) -> DissectedPacket {
    DissectedPacket {
        meta: PacketMeta {
            timestamp: SystemTime::UNIX_EPOCH + Duration::from_millis(ms),
            caplen: 64,
            origlen: 64,
            link_type: LinkType::ETHERNET,
        },
        layers: vec![LayerRecord {
            protocol: "pair",
            offset: 0,
            header_len: 14,
            fields: fields_for(stream),
        }],
        stop: StopReason::Complete,
        opaque_len: 0,
    }
}

#[test]
fn hundred_k_packets_across_ten_k_streams() {
    const STREAMS: u64 = 10_000;
    const PACKETS: u64 = 100_000;

    let engine = Arc::new(
        Engine::builder()
            .plugin(Pair)
            .build()
            .expect("valid registry"),
    );
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    for i in 0..PACKETS {
        agg.ingest(&packet(i % STREAMS, i));
    }

    assert_eq!(agg.len(), STREAMS as usize, "exactly one stream per key");
    assert_eq!(agg.totals().packets, PACKETS);
    assert_eq!(agg.totals().streams_created, STREAMS);
    assert_eq!(agg.totals().key_errors, 0);
    assert_eq!(agg.totals().bytes, PACKETS * 64);

    // Every stream saw exactly PACKETS / STREAMS packets.
    for stream in agg.streams() {
        let total = stream.stats[0].packets + stream.stats[1].packets;
        assert_eq!(total, PACKETS / STREAMS);
    }
}

#[test]
fn common_protocol_keys_never_leave_inline_storage() {
    // The allocation claim, asserted directly: the key path's output stays
    // within FlowKey's 40 inline bytes for the common-protocol shapes fed
    // above (and the encode scratch is an inline SmallVec by construction).
    for stream in [0u64, 1, 4_999, 9_999] {
        let (key, _) = flow_key(&PAIR_IDENTITY, &fields_for(stream)).expect("fields present");
        assert!(
            key.as_bytes().len() <= 40,
            "a {}-byte key would spill to the heap",
            key.as_bytes().len()
        );
    }
}
