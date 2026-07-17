//! D8-shaped JSON projections shared by the CLI's batch/NDJSON output
//! and the web API — one record shape everywhere, so a consumer written
//! against `pktflow streams --format json` reads `pktflow serve`'s API
//! unchanged.

use std::time::SystemTime;

use pktflow_core::PacketDirection;
use pktflow_flows::{CloseReason, Rollup, Stream, StreamId};
use serde_json::{json, Value as Json};

use crate::fmt::{field_value_str, rfc3339};

/// `initiator` as D8's string enum.
pub fn direction_json(dir: PacketDirection) -> &'static str {
    match dir {
        PacketDirection::AtoB => "a_to_b",
        PacketDirection::BtoA => "b_to_a",
    }
}

/// `closed`'s close reason as D8's snake_case string enum (the text
/// renderer's hyphenated form is a display convention, not the wire
/// name).
pub fn close_reason_json(reason: CloseReason) -> &'static str {
    match reason {
        CloseReason::ProtocolClose => "protocol_close",
        CloseReason::IdleTimeout => "idle_timeout",
        CloseReason::LruEvicted => "lru_evicted",
        CloseReason::CaptureEnd => "capture_end",
    }
}

/// JSON projection of a field value (D8): numbers/bools/strings pass
/// through natively; byte shapes render per the FR-28 table so JSON
/// consumers get readable endpoints too (MACs/IPs as strings, unknown
/// bytes as hex strings) instead of raw byte arrays.
pub fn field_value_json(protocol: &str, name: &str, value: &pktflow_core::Value) -> Json {
    match value {
        pktflow_core::Value::U64(v) => json!(v),
        pktflow_core::Value::I64(v) => json!(v),
        pktflow_core::Value::Bool(v) => json!(v),
        pktflow_core::Value::Str(s) => json!(s.as_str()),
        pktflow_core::Value::Bytes(_) => json!(field_value_str(protocol, name, value)),
        pktflow_core::Value::List(items) => Json::Array(
            items
                .iter()
                .map(|v| field_value_json(protocol, name, v))
                .collect(),
        ),
        other => json!(format!("{other:?}")),
    }
}

/// Splits `key_fields` into `endpoint_a`/`endpoint_b` (paired
/// `src_*`/`dst_*` fields, ordered by `initiator` — field names keep
/// their original `src_`/`dst_` spelling, only the A/B *slot* they land
/// in depends on which side originated the creating packet) and `key`
/// (any remaining qualifier field, e.g. GRE's `key`, VXLAN's `vni`; the
/// constant `app` field is dropped as redundant with `protocol`).
pub fn endpoint_json(s: &Stream) -> (Json, Json, Json) {
    let mut a = serde_json::Map::new();
    let mut b = serde_json::Map::new();
    let mut key = serde_json::Map::new();
    for (name, value) in s.key_fields.iter() {
        if let Some(suffix) = name.strip_prefix("src_") {
            let dst_name = format!("dst_{suffix}");
            if let Some(dst_value) = s.key_fields.get(&dst_name) {
                let (a_name, a_value, b_name, b_value) = match s.initiator {
                    PacketDirection::AtoB => (*name, value, dst_name.as_str(), dst_value),
                    PacketDirection::BtoA => (dst_name.as_str(), dst_value, *name, value),
                };
                a.insert(
                    a_name.to_string(),
                    field_value_json(s.protocol, a_name, a_value),
                );
                b.insert(
                    b_name.to_string(),
                    field_value_json(s.protocol, b_name, b_value),
                );
                continue;
            }
        }
        if name.starts_with("dst_") && s.key_fields.get(&format!("src_{}", &name[4..])).is_some() {
            continue; // consumed with its src_ partner
        }
        if *name != "app" {
            key.insert(
                (*name).to_string(),
                field_value_json(s.protocol, name, value),
            );
        }
    }
    (Json::Object(a), Json::Object(b), Json::Object(key))
}

/// One rollup, D8-shaped: `{"kind": ..., ...}` per [`Rollup`] variant.
/// `base` is the owning stream's `first_seen` — series points store
/// timestamps as offsets from it (12.2).
pub fn rollup_json(base: SystemTime, protocol: &str, field: &str, rollup: &Rollup) -> Json {
    match rollup {
        Rollup::Accumulate {
            values,
            count,
            overflow,
        } => {
            let rendered: Vec<Json> = values
                .iter()
                .map(|v| json!(field_value_str(protocol, field, v)))
                .collect();
            json!({
                "kind": "accumulate",
                "values": rendered,
                "distinct": values.len(),
                "observations": count,
                "overflow": overflow,
            })
        }
        Rollup::Sample { first, last } => {
            let render = |v: &Option<pktflow_core::Value>| {
                v.as_ref().map(|v| field_value_str(protocol, field, v))
            };
            json!({ "kind": "sample", "first": render(first), "last": render(last) })
        }
        Rollup::Series {
            ring, truncated, ..
        } => {
            let points: Vec<Json> = ring
                .iter()
                .map(|p| {
                    json!({
                        "ts": rfc3339(p.ts(base)),
                        "dir": direction_json(p.dir),
                        "value": field_value_str(protocol, field, &p.value),
                    })
                })
                .collect();
            json!({ "kind": "series", "points": points, "truncated": truncated })
        }
    }
}

/// A stream record, D8-shaped: shared by the offline batch (`streams[]`),
/// NDJSON live events, and the web API. `seq_of` resolves a `StreamId` to
/// its display id (`created_seq`); a live poll resolves it via the current
/// snapshot/aggregator, while a `stream_closed` event (which only sees
/// the departing `Stream`, not a live aggregator reference) resolves it
/// via the CLI's running id table — this is why the lookup is a closure
/// rather than a `&HashMap<StreamId, &Stream>`.
pub fn stream_record(
    s: &Stream,
    seq_of: &impl Fn(StreamId) -> Option<u64>,
) -> serde_json::Map<String, Json> {
    let (endpoint_a, endpoint_b, key) = endpoint_json(s);
    let parent = s.parent.and_then(seq_of);
    let children: Vec<u64> = s.children.iter().filter_map(|c| seq_of(*c)).collect();
    let rollups: serde_json::Map<String, Json> = s
        .rollups
        .iter()
        .map(|(field, rollup)| {
            (
                (*field).to_string(),
                rollup_json(s.first_seen, s.protocol, field, rollup),
            )
        })
        .collect();

    let mut m = serde_json::Map::new();
    m.insert("id".into(), json!(s.created_seq));
    m.insert("protocol".into(), json!(s.protocol));
    m.insert("parent".into(), json!(parent));
    m.insert("children".into(), json!(children));
    m.insert("endpoint_a".into(), endpoint_a);
    m.insert("endpoint_b".into(), endpoint_b);
    m.insert("key".into(), key);
    m.insert("initiator".into(), json!(direction_json(s.initiator)));
    m.insert("state".into(), json!(s.state));
    m.insert("closed".into(), json!(s.closed.map(close_reason_json)));
    m.insert("first_seen".into(), json!(rfc3339(s.first_seen)));
    m.insert("last_seen".into(), json!(rfc3339(s.last_seen)));
    m.insert(
        "packets".into(),
        json!({ "a_to_b": s.stats[0].packets, "b_to_a": s.stats[1].packets }),
    );
    m.insert(
        "bytes".into(),
        json!({ "a_to_b": s.stats[0].bytes, "b_to_a": s.stats[1].bytes }),
    );
    m.insert("opaque_bytes".into(), json!(s.opaque_bytes));
    m.insert("rollups".into(), Json::Object(rollups));
    m
}
