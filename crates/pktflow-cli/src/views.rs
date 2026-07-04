//! First-cut view rendering for each subcommand. 08.2–08.4 own the final
//! line grammars and golden tests; 08.1 needs every lens functional with
//! clean stdout (JSON) / stderr (summary) separation.

use std::collections::HashMap;

use pktflow_capture::InterfaceInfo;
use pktflow_core::{DissectedPacket, StopReason};
use pktflow_flows::{AggregatorSnapshot, Stream, StreamId};
use serde_json::{json, Value as Json};

use crate::cli::SortOrder;
use crate::error::CliError;
use crate::render::{fields_str, human_bytes, human_duration, thousands, time_of_day, value_str};
use crate::run::RunOutcome;
use crate::summary::stop_class_key;

/// Id → stream lookup for tree walks within one snapshot.
fn by_id(snapshot: &AggregatorSnapshot) -> HashMap<StreamId, &Stream> {
    snapshot.streams.iter().map(|s| (s.id, s)).collect()
}

fn total_packets(s: &Stream) -> u64 {
    s.stats[0].packets + s.stats[1].packets
}

fn total_bytes(s: &Stream) -> u64 {
    s.stats[0].bytes + s.stats[1].bytes
}

fn sort_siblings(streams: &mut [&Stream], order: SortOrder) {
    match order {
        SortOrder::Bytes => streams.sort_by_key(|s| std::cmp::Reverse(total_bytes(s))),
        SortOrder::Packets => streams.sort_by_key(|s| std::cmp::Reverse(total_packets(s))),
        SortOrder::FirstSeen => streams.sort_by(|a, b| a.created_seq.cmp(&b.created_seq)),
        SortOrder::Duration => streams.sort_by(|a, b| {
            let da = a.last_seen.duration_since(a.first_seen).unwrap_or_default();
            let db = b.last_seen.duration_since(b.first_seen).unwrap_or_default();
            db.cmp(&da)
        }),
    }
}

fn stream_line(s: &Stream) -> String {
    let state = s.state.map(|st| format!("  [{st}]")).unwrap_or_default();
    let duration = s.last_seen.duration_since(s.first_seen).unwrap_or_default();
    format!(
        "#{} {}  {}{}   {} pkts   {}   {}",
        s.created_seq,
        s.protocol,
        fields_str(&s.key_fields),
        state,
        thousands(total_packets(s)),
        human_bytes(total_bytes(s)),
        human_duration(duration),
    )
}

/// The default lens: hierarchy tree, roots down (08.2 first cut).
pub fn streams_tree(snapshot: &AggregatorSnapshot, sort: SortOrder) -> String {
    let ids = by_id(snapshot);
    let mut out = String::new();
    let mut roots: Vec<&Stream> = snapshot
        .roots
        .iter()
        .filter_map(|id| ids.get(id).copied())
        .collect();
    sort_siblings(&mut roots, sort);
    for root in roots {
        render_subtree(root, &ids, 0, sort, &mut out);
    }
    out
}

fn render_subtree(
    s: &Stream,
    ids: &HashMap<StreamId, &Stream>,
    depth: usize,
    sort: SortOrder,
    out: &mut String,
) {
    out.push_str(&"  ".repeat(depth));
    out.push_str(&stream_line(s));
    out.push('\n');
    let mut children: Vec<&Stream> = s
        .children
        .iter()
        .filter_map(|id| ids.get(id).copied())
        .collect();
    sort_siblings(&mut children, sort);
    for child in children {
        render_subtree(child, ids, depth + 1, sort, out);
    }
}

/// `--layer PROTO` flat table (FR-24's literal form).
pub fn streams_flat(snapshot: &AggregatorSnapshot, protocol: &str) -> String {
    let mut out = String::new();
    for s in snapshot.streams.iter().filter(|s| s.protocol == protocol) {
        out.push_str(&stream_line(s));
        out.push('\n');
    }
    out
}

/// `--layer PROTO --merged`: the D10 fold, one row per key.
pub fn streams_merged(snapshot: &AggregatorSnapshot, protocol: &str) -> String {
    // Snapshot-side re-fold: group same-protocol streams by key.
    let mut order: Vec<&pktflow_core::FlowKey> = Vec::new();
    let mut groups: HashMap<&pktflow_core::FlowKey, Vec<&Stream>> = HashMap::new();
    for s in snapshot.streams.iter().filter(|s| s.protocol == protocol) {
        let slot = groups.entry(&s.key).or_default();
        if slot.is_empty() {
            order.push(&s.key);
        }
        slot.push(s);
    }
    let mut out = String::new();
    for key in order {
        let nodes = &groups[key];
        let first = nodes[0];
        let packets: u64 = nodes.iter().map(|s| total_packets(s)).sum();
        let bytes: u64 = nodes.iter().map(|s| total_bytes(s)).sum();
        let ids: Vec<String> = nodes
            .iter()
            .map(|s| format!("#{}", s.created_seq))
            .collect();
        out.push_str(&format!(
            "{}  {}   {} pkts   {}   nodes {}\n",
            first.protocol,
            fields_str(&first.key_fields),
            thousands(packets),
            human_bytes(bytes),
            ids.join(","),
        ));
    }
    out
}

/// Drill-down (08.3 first cut): `#id` selector only; key expressions
/// arrive with 08.3 proper.
pub fn stream_detail(snapshot: &AggregatorSnapshot, selector: &str) -> Result<String, CliError> {
    let Some(seq) = selector
        .strip_prefix('#')
        .and_then(|s| s.parse::<u64>().ok())
    else {
        return Err(CliError::Usage(format!(
            "unsupported selector {selector:?}: use #id from a streams view \
             (key expressions arrive with 08.3)"
        )));
    };
    let ids = by_id(snapshot);
    let Some(s) = snapshot.streams.iter().find(|s| s.created_seq == seq) else {
        return Err(CliError::Usage(format!("no stream #{seq} in this capture")));
    };

    let mut out = String::new();
    out.push_str(&stream_line(s));
    out.push('\n');

    // Lineage: walk parent links to root.
    let mut lineage = Vec::new();
    let mut cursor = s.parent;
    while let Some(pid) = cursor {
        let Some(parent) = ids.get(&pid) else { break };
        lineage.push(format!("{} #{}", parent.protocol, parent.created_seq));
        cursor = parent.parent;
    }
    if !lineage.is_empty() {
        lineage.reverse();
        out.push_str(&format!("lineage   {} ▸ this\n", lineage.join(" ▸ ")));
    }

    out.push_str(&format!(
        "totals    {} pkts / {}    A→B {} pkts / {}    B→A {} pkts / {}\n",
        thousands(total_packets(s)),
        human_bytes(total_bytes(s)),
        thousands(s.stats[0].packets),
        human_bytes(s.stats[0].bytes),
        thousands(s.stats[1].packets),
        human_bytes(s.stats[1].bytes),
    ));
    if s.opaque_bytes > 0 {
        out.push_str(&format!(
            "opaque    {} payload bytes beyond last parsed layer\n",
            thousands(s.opaque_bytes)
        ));
    }
    let children: Vec<String> = s
        .children
        .iter()
        .filter_map(|id| ids.get(id).copied())
        .map(|c| format!("{} #{}", c.protocol, c.created_seq))
        .collect();
    if !children.is_empty() {
        out.push_str(&format!("children  {}\n", children.join(", ")));
    }
    Ok(out)
}

/// One packets-mode line (08.4 first cut): index, timestamp, layer
/// chain, caplen, stop class with D9 detail.
pub fn packet_line(index: u64, pkt: &DissectedPacket) -> String {
    let chain: Vec<&str> = pkt.layers.iter().map(|l| l.protocol).collect();
    format!(
        "{}  {}  {}  {}  [{}]",
        index,
        time_of_day(pkt.meta.timestamp),
        chain.join(" ▸ "),
        human_bytes(pkt.meta.caplen as u64),
        stop_str(pkt.stop),
    )
}

/// D9's home: non-clean stops render with detail (08.4).
pub fn stop_str(stop: StopReason) -> String {
    match stop {
        StopReason::Complete => "complete".into(),
        StopReason::Terminal => "terminal".into(),
        StopReason::UnclaimedRoute(id) => format!("unclaimed: {id}"),
        StopReason::UnknownHint => "unknown".into(),
        StopReason::Truncated { needed, have } => {
            format!("truncated: needed {needed}, have {have}")
        }
        StopReason::PluginError => "plugin-error".into(),
        StopReason::DepthCap => "depth-cap".into(),
    }
}

/// NDJSON projection of one packet (08.5 first cut).
pub fn packet_json(index: u64, pkt: &DissectedPacket) -> Json {
    let layers: Vec<&str> = pkt.layers.iter().map(|l| l.protocol).collect();
    json!({
        "index": index,
        "layers": layers,
        "stop": stop_str(pkt.stop),
        "stop_class": stop_class_key(pkt.stop.class()),
        "caplen": pkt.meta.caplen,
        "opaque_len": pkt.opaque_len,
    })
}

/// The offline JSON envelope (D8): `{"pktflow": 1, …}`. The full stream
/// records grow additively in 08.5.
pub fn json_envelope(outcome: &RunOutcome) -> Json {
    let mut doc = json!({
        "pktflow": 1,
        "mode": outcome.mode,
        "source": outcome.source_name,
    });
    if let Some(snapshot) = &outcome.snapshot {
        let mut stop_classes = serde_json::Map::new();
        for (class, count) in snapshot.summary.stop_classes {
            if count > 0 {
                stop_classes.insert(stop_class_key(class).into(), json!(count));
            }
        }
        let mut per_protocol = serde_json::Map::new();
        for p in &snapshot.summary.per_protocol {
            per_protocol.insert(p.protocol.into(), json!(p.ever));
        }
        doc["summary"] = json!({
            "packets": snapshot.summary.packets,
            "bytes": snapshot.summary.bytes,
            "stop_classes": stop_classes,
            "streams": per_protocol,
            "capture_drops": outcome.report.stats.dropped_kernel
                + outcome.report.stats.dropped_iface,
        });
        let ids = by_id(snapshot);
        doc["streams"] = Json::Array(
            snapshot
                .streams
                .iter()
                .map(|s| stream_json(s, &ids))
                .collect(),
        );
    }
    doc
}

fn stream_json(s: &Stream, ids: &HashMap<StreamId, &Stream>) -> Json {
    let endpoints: serde_json::Map<String, Json> = s
        .key_fields
        .iter()
        .map(|(name, value)| ((*name).into(), json!(value_str(name, value))))
        .collect();
    let parent = s
        .parent
        .and_then(|pid| ids.get(&pid))
        .map(|p| p.created_seq);
    let children: Vec<u64> = s
        .children
        .iter()
        .filter_map(|cid| ids.get(cid))
        .map(|c| c.created_seq)
        .collect();
    json!({
        "id": s.created_seq,
        "protocol": s.protocol,
        "parent": parent,
        "children": children,
        "endpoints": endpoints,
        "state": s.state,
        "packets": { "a_to_b": s.stats[0].packets, "b_to_a": s.stats[1].packets },
        "bytes": { "a_to_b": s.stats[0].bytes, "b_to_a": s.stats[1].bytes },
        "opaque_bytes": s.opaque_bytes,
    })
}

/// FR-23 interface listing.
pub fn ifaces_text(interfaces: &[InterfaceInfo]) -> String {
    let mut out = String::new();
    for i in interfaces {
        let mut flags = Vec::new();
        if i.up {
            flags.push("up");
        }
        if i.loopback {
            flags.push("loopback");
        }
        let desc = i.description.as_deref().unwrap_or("");
        let addrs: Vec<String> = i.addrs.iter().map(|a| a.to_string()).collect();
        out.push_str(&format!(
            "{}  [{}]  {}  {}\n",
            i.name,
            flags.join(","),
            addrs.join(" "),
            desc,
        ));
    }
    out
}

pub fn ifaces_json(interfaces: &[InterfaceInfo]) -> Json {
    Json::Array(
        interfaces
            .iter()
            .map(|i| {
                let addrs: Vec<String> = i.addrs.iter().map(|a| a.to_string()).collect();
                json!({
                    "name": i.name,
                    "description": i.description,
                    "addrs": addrs,
                    "up": i.up,
                    "loopback": i.loopback,
                })
            })
            .collect(),
    )
}
