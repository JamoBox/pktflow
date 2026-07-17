//! JSON projections for the web API — the same D8 stream records the CLI
//! emits (via `pktflow_view::json`), plus web-only envelopes: hub meta,
//! per-protocol byte totals for the charts, and unknown groups with their
//! retained sample bytes hex-encoded for the in-browser dump.

use pktflow_core::StopClass;
use pktflow_flows::{AggregatorSnapshot, UnknownGroup};
use pktflow_view::fmt::rfc3339;
use pktflow_view::json::stream_record;
use pktflow_view::query::matching_with_ancestors;
use pktflow_view::{by_id, SnapshotHub, StreamQuery};
use serde_json::{json, Value as Json};

/// JSON key for a stop class (D8 stable names, same as the CLI summary).
fn stop_class_key(class: StopClass) -> &'static str {
    match class {
        StopClass::Clean => "clean",
        StopClass::UnknownPayload => "unknown_payload",
        StopClass::Malformed => "malformed",
        StopClass::Suspicious => "suspicious",
    }
}

/// `/api/meta` and the `meta` object inside `/api/snapshot`.
pub fn meta_json(hub: &SnapshotHub) -> Json {
    json!({
        "pktflow": 1,
        "source": hub.source(),
        "mode": hub.mode(),
        "finished": hub.is_finished(),
        "generation": hub.generation(),
        "error": hub.error(),
    })
}

/// The SSE tick payload: enough for the header counters and for the
/// client to decide whether a full `/api/snapshot` refetch is due.
pub fn tick_json(hub: &SnapshotHub) -> Json {
    let snap = hub.latest();
    json!({
        "generation": hub.generation(),
        "finished": hub.is_finished(),
        "error": hub.error(),
        "packets": snap.summary.packets,
        "bytes": snap.summary.bytes,
        "streams_live": snap.summary.streams_live,
    })
}

fn summary_json(snapshot: &AggregatorSnapshot) -> Json {
    // Live per-protocol byte totals feed the protocol chart; `ever`
    // survives eviction, bytes are summed over live streams only —
    // maintained incrementally by the aggregator (12.1), not rescanned
    // here.
    let mut per_protocol: Vec<Json> = Vec::new();
    for p in &snapshot.summary.per_protocol {
        per_protocol.push(json!({
            "protocol": p.protocol,
            "ever": p.ever,
            "live": p.live,
            "bytes": p.bytes,
        }));
    }
    let mut stop_classes = serde_json::Map::new();
    for (class, count) in snapshot.summary.stop_classes {
        stop_classes.insert(stop_class_key(class).into(), json!(count));
    }
    json!({
        "packets": snapshot.summary.packets,
        "bytes": snapshot.summary.bytes,
        "streams_created": snapshot.summary.streams_created,
        "streams_live": snapshot.summary.streams_live,
        "flows_condensed": snapshot.summary.flows_condensed,
        "key_errors": snapshot.summary.key_errors,
        "per_protocol": per_protocol,
        "stop_classes": stop_classes,
    })
}

fn unknown_json(index: usize, g: &UnknownGroup) -> Json {
    let near_misses: Vec<Json> = g
        .near_misses
        .iter()
        .map(|(name, score)| json!({"protocol": name, "score": score.get()}))
        .collect();
    let endpoints: Vec<Json> = g
        .endpoints
        .iter()
        .map(|e| {
            let key_hex: String = e
                .key
                .as_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            json!({"protocol": e.protocol, "key": key_hex})
        })
        .collect();
    let samples: Vec<String> = g
        .samples
        .iter()
        .map(|s| s.iter().map(|b| format!("{b:02x}")).collect())
        .collect();
    json!({
        "selector": index + 1,
        "predecessor": g.key.predecessor,
        "route": g.key.route.map(|r| r.to_string()),
        "kind": match g.key.route {
            Some(_) => "unclaimed_route",
            None => "no_heuristic_winner",
        },
        "count": g.count,
        "bytes_total": g.bytes_total,
        "bytes_min": g.bytes_min,
        "bytes_max": g.bytes_max,
        "first_seen": rfc3339(g.first_seen),
        "last_seen": rfc3339(g.last_seen),
        "near_misses": near_misses,
        "endpoints": endpoints,
        "endpoints_overflow": g.endpoints_overflow,
        "samples": samples,
    })
}

/// `/api/snapshot`: the whole browsable state in one document — meta,
/// summary, the stream forest (D8 records + root ids), and the unknown
/// registry. The client refetches it only on a generation change.
pub fn snapshot_json(hub: &SnapshotHub) -> Json {
    let snap = hub.latest();
    let ids = by_id(&snap);
    let seq_of = |id| ids.get(&id).map(|s| s.created_seq);
    let streams: Vec<Json> = snap
        .streams
        .iter()
        .map(|s| Json::Object(stream_record(s, &seq_of)))
        .collect();
    let roots: Vec<u64> = snap
        .roots
        .iter()
        .filter_map(|id| ids.get(id).map(|s| s.created_seq))
        .collect();
    let unknowns: Vec<Json> = snap
        .unknowns
        .iter()
        .enumerate()
        .map(|(i, g)| unknown_json(i, g))
        .collect();
    json!({
        "pktflow": 1,
        "meta": meta_json(hub),
        "summary": summary_json(&snap),
        "roots": roots,
        "streams": streams,
        "unknowns": unknowns,
    })
}

/// `/api/search?q=…`: evaluate one query expression against the current
/// snapshot. `matches` are the streams the query selects; `visible` adds
/// every ancestor of a match so the client can keep results in their
/// hierarchy context. A parse failure comes back as `error` with both
/// lists null — the client keeps showing the unfiltered tree.
pub fn search_json(hub: &SnapshotHub, q: &str) -> Json {
    let base = |matches: Json, visible: Json, error: Json| {
        json!({
            "pktflow": 1,
            "query": q,
            "generation": hub.generation(),
            "matches": matches,
            "visible": visible,
            "error": error,
        })
    };
    if q.trim().is_empty() {
        return base(Json::Null, Json::Null, Json::Null);
    }
    let query = match StreamQuery::parse(q) {
        Ok(query) => query,
        Err(e) => return base(Json::Null, Json::Null, json!(e.to_string())),
    };
    let snap = hub.latest();
    let ids = by_id(&snap);
    let mut matches: Vec<u64> = snap
        .streams
        .iter()
        .filter(|s| query.matches(s, &ids))
        .map(|s| s.created_seq)
        .collect();
    matches.sort_unstable();
    let mut visible: Vec<u64> = matching_with_ancestors(&snap.streams, &ids, &query)
        .into_iter()
        .collect();
    visible.sort_unstable();
    base(json!(matches), json!(visible), Json::Null)
}

/// `/api/stream/{id}`: one D8 record by display id.
pub fn stream_json(hub: &SnapshotHub, seq: u64) -> Option<Json> {
    let snap = hub.latest();
    let ids = by_id(&snap);
    let seq_of = |id| ids.get(&id).map(|s| s.created_seq);
    snap.streams
        .iter()
        .find(|s| s.created_seq == seq)
        .map(|s| Json::Object(stream_record(s, &seq_of)))
}
