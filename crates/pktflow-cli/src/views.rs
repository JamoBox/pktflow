//! First-cut view rendering for each subcommand. 08.2–08.4 own the final
//! line grammars and golden tests; 08.1 needs every lens functional with
//! clean stdout (JSON) / stderr (summary) separation.

use std::collections::HashMap;

use pktflow_capture::InterfaceInfo;
use pktflow_core::{DissectedPacket, PacketDirection, StopReason};
use pktflow_flows::{AggregatorSnapshot, Stream, StreamId};
use serde_json::{json, Value as Json};

use crate::cli::SortOrder;
use crate::error::CliError;
use crate::render::{human_bytes, human_duration, thousands, time_of_day, value_str};
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

/// Rendered endpoint pair in canonical A ↔ B order (08.2 line grammar):
/// `key_fields` come from the creating packet, so `initiator` says which
/// side of each `src_*`/`dst_*` pair is endpoint A. Ports render with a
/// `:` prefix (their IP parent shows the addresses). Non-paired key
/// fields (`vni`, GRE `key`) render as `name=value`; the constant `app`
/// field is dropped — the protocol name already says it.
fn endpoints_str(s: &Stream) -> String {
    let mut a_side = Vec::new();
    let mut b_side = Vec::new();
    let mut extras = Vec::new();
    for (name, value) in s.key_fields.iter() {
        if let Some(suffix) = name.strip_prefix("src_") {
            let dst_name = format!("dst_{suffix}");
            if let Some(dst_value) = s.key_fields.get(&dst_name) {
                let mut src_str = value_str(name, value);
                let mut dst_str = value_str(&dst_name, dst_value);
                if suffix.ends_with("port") {
                    src_str = format!(":{src_str}");
                    dst_str = format!(":{dst_str}");
                }
                match s.initiator {
                    PacketDirection::AtoB => {
                        a_side.push(src_str);
                        b_side.push(dst_str);
                    }
                    PacketDirection::BtoA => {
                        a_side.push(dst_str);
                        b_side.push(src_str);
                    }
                }
                continue;
            }
        }
        if name.starts_with("dst_") && s.key_fields.get(&format!("src_{}", &name[4..])).is_some() {
            continue; // consumed with its src_ partner
        }
        if *name != "app" {
            extras.push(format!("{name}={}", value_str(name, value)));
        }
    }
    let mut out = String::new();
    if !a_side.is_empty() {
        out.push_str(&format!("{} ↔ {}", a_side.join(","), b_side.join(",")));
    }
    if !extras.is_empty() {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(&extras.join(" "));
    }
    out
}

/// One assembled row: label (tree prefix + identity) plus stat columns,
/// aligned table-wide before printing.
struct Row {
    label: String,
    pkts: String,
    bytes: String,
    tail: String,
}

fn stream_row(prefix: &str, s: &Stream, first_seen_col: bool) -> Row {
    let endpoints = endpoints_str(s);
    let state = s.state.map(|st| format!("   [{st}]")).unwrap_or_default();
    let mut label = format!("{prefix}{} #{}", s.protocol, s.created_seq);
    if !endpoints.is_empty() {
        label.push_str("  ");
        label.push_str(&endpoints);
    }
    label.push_str(&state);

    let duration = s.last_seen.duration_since(s.first_seen).unwrap_or_default();
    let mut tail = human_duration(duration);
    // The ▲/▼ split only means something for streams with two endpoints;
    // qualifier-keyed streams (dns, vxlan) have no B side to count.
    if endpoints.contains('↔') {
        tail.push_str(&format!(
            "   ▲{}/▼{}",
            thousands(s.stats[0].packets),
            thousands(s.stats[1].packets)
        ));
    }
    if first_seen_col {
        tail.push_str(&format!("   first {}", time_of_day(s.first_seen)));
    }
    Row {
        label,
        pkts: format!("{} pkts", thousands(total_packets(s))),
        bytes: human_bytes(total_bytes(s)),
        tail,
    }
}

fn render_rows(rows: &[Row]) -> String {
    let label_w = rows
        .iter()
        .map(|r| r.label.chars().count())
        .max()
        .unwrap_or(0);
    let pkts_w = rows
        .iter()
        .map(|r| r.pkts.chars().count())
        .max()
        .unwrap_or(0);
    let bytes_w = rows
        .iter()
        .map(|r| r.bytes.chars().count())
        .max()
        .unwrap_or(0);
    let mut out = String::new();
    for r in rows {
        let pad = label_w - r.label.chars().count();
        out.push_str(&format!(
            "{}{}   {:>pkts_w$}   {:>bytes_w$}   {}\n",
            r.label,
            " ".repeat(pad),
            r.pkts,
            r.bytes,
            r.tail,
        ));
    }
    out
}

/// The default lens (FR-24): the flow hierarchy, roots down, `├─`/`└─`
/// glyphs, one line per stream.
pub fn streams_tree(snapshot: &AggregatorSnapshot, sort: SortOrder) -> String {
    let ids = by_id(snapshot);
    let mut rows = Vec::new();
    let mut roots: Vec<&Stream> = snapshot
        .roots
        .iter()
        .filter_map(|id| ids.get(id).copied())
        .collect();
    sort_siblings(&mut roots, sort);
    for root in &roots {
        collect_subtree(root, &ids, "", sort, &mut rows);
    }
    render_rows(&rows)
}

fn collect_subtree(
    s: &Stream,
    ids: &HashMap<StreamId, &Stream>,
    prefix: &str,
    sort: SortOrder,
    rows: &mut Vec<Row>,
) {
    rows.push(stream_row(prefix, s, false));
    let mut children: Vec<&Stream> = s
        .children
        .iter()
        .filter_map(|id| ids.get(id).copied())
        .collect();
    sort_siblings(&mut children, sort);
    // Glyph prefixes: the label prefix ends with the branch glyph; child
    // subtrees continue with `│  ` under a `├─` and spaces under a `└─`.
    let bare = prefix.replace("├─ ", "│  ").replace("└─ ", "   ");
    let count = children.len();
    for (i, child) in children.into_iter().enumerate() {
        let last = i + 1 == count;
        let branch = if last { "└─ " } else { "├─ " };
        collect_subtree(child, ids, &format!("{bare}{branch}"), sort, rows);
    }
}

/// `--layer PROTO` flat table (FR-24's literal "list streams at a chosen
/// layer"): one row per node, `created_seq` order, plus first-seen.
pub fn streams_flat(snapshot: &AggregatorSnapshot, protocol: &str) -> String {
    let rows: Vec<Row> = snapshot
        .streams
        .iter()
        .filter(|s| s.protocol == protocol)
        .map(|s| stream_row("", s, true))
        .collect();
    render_rows(&rows)
}

/// `--layer PROTO --merged`: the D10 fold, one row per key with the
/// folded nodes' ids listed.
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
    let mut rows = Vec::new();
    for key in order {
        let nodes = &groups[key];
        let first = nodes[0];
        let packets: u64 = nodes.iter().map(|s| total_packets(s)).sum();
        let bytes: u64 = nodes.iter().map(|s| total_bytes(s)).sum();
        let ids: Vec<String> = nodes
            .iter()
            .map(|s| format!("#{}", s.created_seq))
            .collect();
        let endpoints = endpoints_str(first);
        let mut label = first.protocol.to_string();
        if !endpoints.is_empty() {
            label.push_str("  ");
            label.push_str(&endpoints);
        }
        rows.push(Row {
            label,
            pkts: format!("{} pkts", thousands(packets)),
            bytes: human_bytes(bytes),
            tail: format!("nodes {}", ids.join(",")),
        });
    }
    render_rows(&rows)
}

/// One `--watch` frame (08.2): ANSI clear+home, the tree capped to
/// `WATCH_MAX_ROWS`, footer = running totals. Snapshot-based — the
/// render side never touches the aggregator.
pub const WATCH_CLEAR: &str = "\x1b[2J\x1b[H";
const WATCH_MAX_ROWS: usize = 40;

pub fn watch_frame(snapshot: &AggregatorSnapshot, sort: SortOrder, source: &str) -> String {
    let tree = streams_tree(snapshot, sort);
    let mut body = String::new();
    let total_lines = tree.lines().count();
    for (i, line) in tree.lines().enumerate() {
        if i == WATCH_MAX_ROWS {
            body.push_str(&format!("… and {} more\n", total_lines - i));
            break;
        }
        body.push_str(line);
        body.push('\n');
    }
    format!(
        "{WATCH_CLEAR}{body}\nwatching {source} — packets {} · streams live {}\n",
        thousands(snapshot.summary.packets),
        snapshot.summary.streams_live,
    )
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
    let header = stream_row("", s, false);
    out.push_str(&format!(
        "{}   {} / {}   {}\n",
        header.label, header.pkts, header.bytes, header.tail
    ));

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
