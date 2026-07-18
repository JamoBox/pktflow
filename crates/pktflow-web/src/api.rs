//! JSON projections for the web API — the same D8 stream records the CLI
//! emits (via `pktflow_view::json`), plus web-only envelopes: hub meta,
//! per-protocol byte totals for the charts, and unknown groups with their
//! retained sample bytes hex-encoded for the in-browser dump.

use std::collections::HashMap;

use pktflow_core::StopClass;
use pktflow_flows::{AggregatorSnapshot, UnknownGroup};
use pktflow_view::fmt::rfc3339;
use pktflow_view::json::stream_record;
use pktflow_view::{Scope, SnapshotHub, SnapshotIndex, SortKey, TimelineSpec, WindowSpec};
use serde_json::{json, Value as Json};

/// D17.4's size gate: `/api/snapshot` carries the whole forest only up
/// to this many live streams; beyond it the document sets
/// `"windowed": true` and clients drive `/api/streams`/`/api/timeline`.
pub const FULL_SNAPSHOT_MAX_STREAMS: usize = 20_000;

/// Server-side clamp on one window's `limit`.
const WINDOW_LIMIT_MAX: usize = 500;

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
        // 12.5: `{read, total}` over a file source, null otherwise.
        "progress": hub.progress().map(|(read, total)| json!({
            "read": read,
            "total": total,
        })),
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

/// `/api/snapshot`: the browsable state in one document — meta, summary,
/// the stream forest (D8 records + root ids), and the unknown registry.
/// The client refetches it only on a generation change. Above
/// [`FULL_SNAPSHOT_MAX_STREAMS`] the forest is omitted and
/// `"windowed": true` tells the client to drive `/api/streams` and
/// `/api/timeline` instead (12.4, D17.4).
pub fn snapshot_json(hub: &SnapshotHub, index: &SnapshotIndex) -> Json {
    let snap = index.snapshot();
    let unknowns: Vec<Json> = snap
        .unknowns
        .iter()
        .enumerate()
        .map(|(i, g)| unknown_json(i, g))
        .collect();
    let windowed = snap.streams.len() > FULL_SNAPSHOT_MAX_STREAMS;
    let mut doc = json!({
        "pktflow": 1,
        "meta": meta_json(hub),
        "summary": summary_json(snap),
        "windowed": windowed,
        "unknowns": unknowns,
    });
    if !windowed {
        let seq_of = |id| index.by_id(id).map(|s| s.created_seq);
        let streams: Vec<Json> = snap
            .streams
            .iter()
            .map(|s| Json::Object(stream_record(s, &seq_of)))
            .collect();
        let roots: Vec<u64> = snap.roots.iter().filter_map(|&id| seq_of(id)).collect();
        doc["streams"] = json!(streams);
        doc["roots"] = json!(roots);
    }
    doc
}

/// `GET /api/streams` (12.4): one window of D8 records —
/// `scope=roots|flat|children&of=SEQ`, `sort`, `order=asc|desc`,
/// `offset`, `limit` (clamped), `q`. Answers from the per-snapshot
/// index; response size is bounded by the window, never the capture.
pub fn streams_json(
    hub: &SnapshotHub,
    index: &SnapshotIndex,
    params: &HashMap<String, String>,
) -> Json {
    let get = |k: &str| params.get(k).map(String::as_str);
    let scope = match (get("scope").unwrap_or("roots"), get("of")) {
        ("flat", _) => Scope::Flat,
        ("children", Some(of)) => match of.parse() {
            Ok(seq) => Scope::ChildrenOf(seq),
            Err(_) => return json!({"error": "children scope needs a numeric ?of="}),
        },
        ("children", None) => return json!({"error": "children scope needs ?of=SEQ"}),
        _ => Scope::Roots,
    };
    let sort = get("sort")
        .and_then(SortKey::parse)
        .unwrap_or(SortKey::Bytes);
    let descending = get("order") != Some("asc");
    let offset = get("offset").and_then(|v| v.parse().ok()).unwrap_or(0);
    let limit = get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(200)
        .min(WINDOW_LIMIT_MAX);
    let window = index.window(&WindowSpec {
        scope,
        query: get("q"),
        sort,
        descending,
        offset,
        limit,
    });
    let seq_of = |id| index.by_id(id).map(|s| s.created_seq);
    let rows: Vec<Json> = window
        .rows
        .iter()
        .map(|s| Json::Object(stream_record(s, &seq_of)))
        .collect();
    json!({
        "pktflow": 1,
        "generation": hub.generation(),
        "total": window.total,
        "match_total": window.match_total,
        "rows": rows,
    })
}

/// `GET /api/timeline` (12.4): bounded time×lane density —
/// `bins`, `lanes`, `q`. O(bins × lanes) whatever the stream count.
pub fn timeline_json(
    hub: &SnapshotHub,
    index: &SnapshotIndex,
    params: &HashMap<String, String>,
) -> Json {
    let get = |k: &str| params.get(k).map(String::as_str);
    let spec = TimelineSpec {
        bins: get("bins").and_then(|v| v.parse().ok()).unwrap_or(800),
        lanes: get("lanes").and_then(|v| v.parse().ok()).unwrap_or(64),
        query: get("q"),
    };
    match index.timeline(&spec) {
        None => json!({
            "pktflow": 1,
            "generation": hub.generation(),
            "lanes": Json::Null,
        }),
        Some(bins) => {
            let lanes: Vec<Json> = bins
                .lanes
                .iter()
                .map(|l| json!({"seq": l.seq, "active": l.active}))
                .collect();
            json!({
                "pktflow": 1,
                "generation": hub.generation(),
                "start": rfc3339(bins.start),
                "end": rfc3339(bins.end),
                "lanes": lanes,
            })
        }
    }
}

/// `/api/search?q=…`: evaluate one query expression against the current
/// snapshot (served from the index's cached evaluation, 12.4).
/// `matches` are the streams the query selects; `visible` adds every
/// ancestor of a match so the client can keep results in their
/// hierarchy context. A parse failure comes back as `error` with both
/// lists null. Above the D17.4 gate the exhaustive id lists are
/// withheld (`matches`/`visible` null) and only `match_total` returns —
/// windowed clients page matches through `/api/streams?q=`.
pub fn search_json(hub: &SnapshotHub, index: &SnapshotIndex, q: &str) -> Json {
    let base = |matches: Json, visible: Json, total: Json, error: Json| {
        json!({
            "pktflow": 1,
            "query": q,
            "generation": hub.generation(),
            "matches": matches,
            "visible": visible,
            "match_total": total,
            "error": error,
        })
    };
    if q.trim().is_empty() {
        return base(Json::Null, Json::Null, Json::Null, Json::Null);
    }
    let Some(sets) = index.query_sets(q) else {
        let message = pktflow_view::StreamQuery::parse(q)
            .err()
            .map_or_else(|| "query error".into(), |e| e.to_string());
        return base(Json::Null, Json::Null, Json::Null, json!(message));
    };
    let (matches_set, visible_set) = (&sets.0, &sets.1);
    if index.snapshot().streams.len() > FULL_SNAPSHOT_MAX_STREAMS {
        return base(Json::Null, Json::Null, json!(matches_set.len()), Json::Null);
    }
    let mut matches: Vec<u64> = matches_set.iter().copied().collect();
    matches.sort_unstable();
    let mut visible: Vec<u64> = visible_set.iter().copied().collect();
    visible.sort_unstable();
    base(
        json!(matches),
        json!(visible),
        json!(matches.len()),
        Json::Null,
    )
}

/// `/api/stream/{id}`: one D8 record by display id (indexed lookup).
pub fn stream_json(index: &SnapshotIndex, seq: u64) -> Option<Json> {
    let seq_of = |id| index.by_id(id).map(|s| s.created_seq);
    index
        .by_seq(seq)
        .map(|s| Json::Object(stream_record(s, &seq_of)))
}
