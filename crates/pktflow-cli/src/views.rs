//! First-cut view rendering for each subcommand. 08.2–08.4 own the final
//! line grammars and golden tests; 08.1 needs every lens functional with
//! clean stdout (JSON) / stderr (summary) separation.

use std::collections::HashMap;
use std::time::SystemTime;

use pktflow_capture::InterfaceInfo;
use pktflow_core::{DissectedPacket, PacketDirection, StopReason};
use pktflow_flows::{AggregatorSnapshot, Rollup, SeriesPoint, Stream, StreamId};
use pktflow_view::json::{close_reason_json, stream_record};
use pktflow_view::query::matching_with_ancestors;
use pktflow_view::StreamQuery;
use pktflow_view::{
    by_id, child_chain_str, close_reason_str, endpoint_sides, endpoints_str, lineage_str,
    total_bytes, total_packets,
};
use serde_json::{json, Value as Json};

use crate::cli::SortOrder;
use crate::error::CliError;
use crate::render::{
    field_value_str, human_bytes, human_duration, thousands, time_of_day, value_str,
};
use crate::run::RunOutcome;
use crate::summary::stop_class_key;

fn sort_siblings(streams: &mut [&Stream], order: SortOrder) {
    match order {
        SortOrder::Bytes => streams.sort_by_key(|s| std::cmp::Reverse(total_bytes(s))),
        SortOrder::Packets => streams.sort_by_key(|s| std::cmp::Reverse(total_packets(s))),
        SortOrder::FirstSeen => streams.sort_by_key(|s| s.created_seq),
        SortOrder::Duration => streams.sort_by_key(|s| {
            std::cmp::Reverse(s.last_seen.duration_since(s.first_seen).unwrap_or_default())
        }),
    }
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
/// glyphs, one line per stream. A `--where` query narrows the tree to
/// matches plus their ancestors, so results keep their lineage context.
pub fn streams_tree(
    snapshot: &AggregatorSnapshot,
    sort: SortOrder,
    query: Option<&StreamQuery>,
) -> String {
    let ids = by_id(snapshot);
    let keep = query.map(|q| matching_with_ancestors(&snapshot.streams, &ids, q));
    let mut rows = Vec::new();
    let mut roots: Vec<&Stream> = snapshot
        .roots
        .iter()
        .filter_map(|id| ids.get(id).copied())
        .filter(|s| keep.as_ref().is_none_or(|k| k.contains(&s.created_seq)))
        .collect();
    sort_siblings(&mut roots, sort);
    for root in &roots {
        collect_subtree(root, &ids, "", sort, keep.as_ref(), &mut rows);
    }
    render_rows(&rows)
}

fn collect_subtree(
    s: &Stream,
    ids: &HashMap<StreamId, &Stream>,
    prefix: &str,
    sort: SortOrder,
    keep: Option<&std::collections::HashSet<u64>>,
    rows: &mut Vec<Row>,
) {
    rows.push(stream_row(prefix, s, false));
    let mut children: Vec<&Stream> = s
        .children
        .iter()
        .filter_map(|id| ids.get(id).copied())
        .filter(|c| keep.is_none_or(|k| k.contains(&c.created_seq)))
        .collect();
    sort_siblings(&mut children, sort);
    // Glyph prefixes: the label prefix ends with the branch glyph; child
    // subtrees continue with `│  ` under a `├─` and spaces under a `└─`.
    let bare = prefix.replace("├─ ", "│  ").replace("└─ ", "   ");
    let count = children.len();
    for (i, child) in children.into_iter().enumerate() {
        let last = i + 1 == count;
        let branch = if last { "└─ " } else { "├─ " };
        collect_subtree(child, ids, &format!("{bare}{branch}"), sort, keep, rows);
    }
}

/// `--layer PROTO` flat table (FR-24's literal "list streams at a chosen
/// layer"): one row per node, `created_seq` order, plus first-seen.
pub fn streams_flat(
    snapshot: &AggregatorSnapshot,
    protocol: &str,
    query: Option<&StreamQuery>,
) -> String {
    let ids = by_id(snapshot);
    let rows: Vec<Row> = snapshot
        .streams
        .iter()
        .filter(|s| s.protocol == protocol)
        .filter(|s| query.is_none_or(|q| q.matches(s, &ids)))
        .map(|s| stream_row("", s, true))
        .collect();
    render_rows(&rows)
}

/// `--layer PROTO --merged`: the D10 fold, one row per key with the
/// folded nodes' ids listed.
pub fn streams_merged(
    snapshot: &AggregatorSnapshot,
    protocol: &str,
    query: Option<&StreamQuery>,
) -> String {
    let ids = by_id(snapshot);
    // Snapshot-side re-fold: group same-protocol streams by key.
    let mut order: Vec<&pktflow_core::FlowKey> = Vec::new();
    let mut groups: HashMap<&pktflow_core::FlowKey, Vec<&Stream>> = HashMap::new();
    for s in snapshot
        .streams
        .iter()
        .filter(|s| s.protocol == protocol)
        .filter(|s| query.is_none_or(|q| q.matches(s, &ids)))
    {
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

/// One live-view frame (08.2, default unless `--batch`): ANSI
/// clear+home, the tree capped to
/// `WATCH_MAX_ROWS`, footer = running totals. Snapshot-based — the
/// render side never touches the aggregator.
pub const WATCH_CLEAR: &str = "\x1b[2J\x1b[H";
const WATCH_MAX_ROWS: usize = 40;

pub fn watch_frame(
    snapshot: &AggregatorSnapshot,
    sort: SortOrder,
    source: &str,
    query: Option<&StreamQuery>,
) -> String {
    let tree = streams_tree(snapshot, sort, query);
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

/// Resolves an 08.3 selector: `#id`, or a key expression
/// `PROTO A B` (endpoint pair, order-insensitive). Endpoints match this
/// layer's rendered values; `addr:port` composites also require the
/// address somewhere in the stream's ancestry. Missing and ambiguous
/// selectors are runtime errors (exit 1); ambiguity lists candidates.
pub fn resolve_selector<'a>(
    snapshot: &'a AggregatorSnapshot,
    selector: &str,
) -> Result<&'a Stream, CliError> {
    if let Some(rest) = selector.strip_prefix('#') {
        let Ok(seq) = rest.parse::<u64>() else {
            return Err(CliError::Usage(format!(
                "bad selector {selector:?}: #id takes a number from a streams view"
            )));
        };
        return snapshot
            .streams
            .iter()
            .map(|s| &**s)
            .find(|s| s.created_seq == seq)
            .ok_or_else(|| CliError::NotFound(format!("no stream #{seq} in this capture")));
    }

    let tokens: Vec<&str> = selector.split_whitespace().collect();
    let [proto, ep1, ep2] = tokens.as_slice() else {
        return Err(CliError::Usage(format!(
            "bad selector {selector:?}: use '#id' or 'PROTO ENDPOINT-A ENDPOINT-B'"
        )));
    };

    let ids = by_id(snapshot);
    let candidates: Vec<&Stream> = snapshot
        .streams
        .iter()
        .map(|s| &**s)
        .filter(|s| s.protocol == *proto)
        .filter(|s| {
            let (a, b, _) = endpoint_sides(s);
            let ancestors = ancestor_values(s, &ids);
            (token_matches(ep1, &a, &ancestors) && token_matches(ep2, &b, &ancestors))
                || (token_matches(ep1, &b, &ancestors) && token_matches(ep2, &a, &ancestors))
        })
        .collect();

    match candidates.as_slice() {
        [] => Err(CliError::NotFound(format!(
            "no {proto} stream matching {ep1} ↔ {ep2} in this capture"
        ))),
        [one] => Ok(one),
        many => {
            let mut msg = format!("selector {selector:?} is ambiguous across parents; candidates:");
            for s in many {
                let lineage = lineage_str(s, &ids);
                msg.push_str(&format!(
                    "\n  #{}  {} {}  (under {lineage})",
                    s.created_seq,
                    s.protocol,
                    endpoints_str(s),
                ));
            }
            Err(CliError::NotFound(msg))
        }
    }
}

/// Every rendered endpoint value in the stream's ancestry (both sides,
/// all levels) — the address pool `addr:port` composites match against.
fn ancestor_values(s: &Stream, ids: &HashMap<StreamId, &Stream>) -> Vec<String> {
    let mut values = Vec::new();
    let mut cursor = s.parent;
    while let Some(pid) = cursor {
        let Some(parent) = ids.get(&pid) else { break };
        let (a, b, _) = endpoint_sides(parent);
        values.push(a);
        values.push(b);
        cursor = parent.parent;
    }
    values
}

/// One endpoint token against one rendered side. `:`-prefixes are
/// optional in the token; `addr:port` requires the port at this layer
/// and the address in the ancestry.
fn token_matches(token: &str, side: &str, ancestors: &[String]) -> bool {
    let side_bare = side.strip_prefix(':').unwrap_or(side);
    let token_bare = token.strip_prefix(':').unwrap_or(token);
    if token_bare == side_bare {
        return true;
    }
    if let Some((addr, port)) = token_bare.rsplit_once(':') {
        return port == side_bare && ancestors.iter().any(|v| v == addr);
    }
    false
}

/// How many series points render before head/tail elision applies.
const SERIES_ELISION: usize = 20;

/// Drill-down (08.3): everything the aggregator knows about one stream,
/// section by section; empty sections are omitted.
pub fn stream_detail(
    snapshot: &AggregatorSnapshot,
    selector: &str,
    full_series: bool,
) -> Result<String, CliError> {
    let s = resolve_selector(snapshot, selector)?;
    let ids = by_id(snapshot);
    let mut out = String::new();

    // Header: identity + state, like a streams-view line without stats.
    let endpoints = endpoints_str(s);
    let state_tag = s.state.map(|st| format!("   [{st}]")).unwrap_or_default();
    out.push_str(&format!("{} #{}", s.protocol, s.created_seq));
    if !endpoints.is_empty() {
        out.push_str(&format!("   {endpoints}"));
    }
    out.push_str(&state_tag);
    out.push('\n');

    let lineage = lineage_str(s, &ids);
    if !lineage.is_empty() {
        out.push_str(&format!("lineage   {lineage} ▸ this\n"));
    }

    let duration = s.last_seen.duration_since(s.first_seen).unwrap_or_default();
    out.push_str(&format!(
        "timing    first {}  last {}  duration {}\n",
        time_of_day(s.first_seen),
        time_of_day(s.last_seen),
        human_duration(duration),
    ));

    out.push_str(&format!(
        "totals    {} pkts / {}    A→B {} pkts / {}    B→A {} pkts / {}\n",
        thousands(total_packets(s)),
        human_bytes(total_bytes(s)),
        thousands(s.stats[0].packets),
        human_bytes(s.stats[0].bytes),
        thousands(s.stats[1].packets),
        human_bytes(s.stats[1].bytes),
    ));

    let (a_side, b_side, _) = endpoint_sides(s);
    if !a_side.is_empty() {
        let (side, endpoint) = match s.initiator {
            PacketDirection::AtoB => ("A", &a_side),
            PacketDirection::BtoA => ("B", &b_side),
        };
        out.push_str(&format!("initiator {side} ({endpoint})\n"));
    }

    if let Some(state) = s.state {
        let closed = match s.closed {
            Some(reason) => close_reason_str(reason),
            None => "—",
        };
        out.push_str(&format!("state     {state}   (closed: {closed})\n"));
    }

    if s.opaque_bytes > 0 {
        out.push_str(&format!(
            "opaque    {} payload bytes beyond last parsed layer\n",
            thousands(s.opaque_bytes)
        ));
    }

    if !s.rollups.is_empty() {
        out.push_str("rollups\n");
        for (field, rollup) in s.rollups.iter() {
            out.push_str(&rollup_line(
                s.first_seen,
                s.protocol,
                field,
                rollup,
                full_series,
            ));
        }
    }

    let children: Vec<String> = s
        .children
        .iter()
        .filter_map(|id| ids.get(id).copied())
        .map(|c| child_chain_str(c, &ids))
        .collect();
    if !children.is_empty() {
        out.push_str(&format!("children  {}\n", children.join(", ")));
    }
    Ok(out)
}

/// One rollup line per kind (05.4 honesty markers included).
fn rollup_line(
    base: SystemTime,
    protocol: &str,
    field: &str,
    rollup: &Rollup,
    full_series: bool,
) -> String {
    match rollup {
        Rollup::Accumulate {
            values,
            count,
            overflow,
        } => {
            let rendered: Vec<String> = values
                .iter()
                .map(|v| field_value_str(protocol, field, v))
                .collect();
            let marker = if *overflow {
                format!(", ≥{} values", values.len())
            } else {
                String::new()
            };
            format!(
                "  {field}   {{{}}}   (accumulate, {} distinct / {} obs{marker})\n",
                rendered.join(", "),
                values.len(),
                thousands(*count),
            )
        }
        Rollup::Sample { first, last } => {
            let render = |v: &Option<pktflow_core::Value>| {
                v.as_ref()
                    .map(|v| field_value_str(protocol, field, v))
                    .unwrap_or_else(|| "—".into())
            };
            format!(
                "  {field}   {} → {}   (sample, first → last)\n",
                render(first),
                render(last),
            )
        }
        Rollup::Series {
            ring,
            cap: _,
            truncated,
        } => {
            let point = |p: &SeriesPoint| {
                let arrow = match p.dir {
                    PacketDirection::AtoB => "▲",
                    PacketDirection::BtoA => "▼",
                };
                format!(
                    "{} {arrow} {}",
                    time_of_day(p.ts(base)),
                    field_value_str(protocol, field, &p.value)
                )
            };
            let points: Vec<String> = if full_series || ring.len() <= SERIES_ELISION {
                ring.iter().map(point).collect()
            } else {
                let head = ring.iter().take(SERIES_ELISION / 2).map(point);
                let tail = ring.iter().skip(ring.len() - SERIES_ELISION / 2).map(point);
                head.chain(std::iter::once(format!(
                    "… {} elided …",
                    ring.len() - SERIES_ELISION
                )))
                .chain(tail)
                .collect()
            };
            let marker = if *truncated { "   (truncated)" } else { "" };
            format!("  {field}   series: {}{marker}\n", points.join(" · "))
        }
    }
}

/// One headline field from the innermost layer that offers one — a CLI
/// preference list, deliberately not part of the plugin trait (08.4).
const HEADLINE_FIELDS: [(&str, &str); 7] = [
    ("dns", "qname"),
    ("arp", "opcode"),
    ("tcp", "flags"),
    ("icmpv4", "type"),
    ("dhcp", "msg_type"),
    ("igmp", "type"),
    ("ntp", "mode"),
];

fn headline_str(pkt: &DissectedPacket) -> Option<String> {
    for layer in pkt.layers.iter().rev() {
        for (proto, field) in HEADLINE_FIELDS {
            if layer.protocol == proto {
                if let Some(value) = layer.fields.get(field) {
                    return Some(format!(
                        "{field}={}",
                        field_value_str(layer.protocol, field, value)
                    ));
                }
            }
        }
    }
    None
}

/// Innermost endpoints in source order — this is the per-packet view,
/// deliberately NOT canonicalized (direction arrows belong to streams).
/// Innermost address pair + innermost port pair compose `addr:port`.
fn packet_endpoints_str(pkt: &DissectedPacket) -> Option<String> {
    let mut addrs: Option<(String, String)> = None;
    let mut ports: Option<(String, String)> = None;
    let mut macs: Option<(String, String)> = None;
    for layer in &pkt.layers {
        let get = |n: &str| layer.fields.get(n);
        if let (Some(s), Some(d)) = (get("src_addr"), get("dst_addr")) {
            addrs = Some((value_str("src_addr", s), value_str("dst_addr", d)));
            ports = None; // ports bind to the innermost IP layer above them
        }
        if let (Some(s), Some(d)) = (get("src_port"), get("dst_port")) {
            ports = Some((value_str("src_port", s), value_str("dst_port", d)));
        }
        if let (Some(s), Some(d)) = (get("src_mac"), get("dst_mac")) {
            macs = Some((value_str("src_mac", s), value_str("dst_mac", d)));
        }
    }
    match (addrs, ports, macs) {
        (Some((sa, da)), Some((sp, dp)), _) => Some(format!("{sa}:{sp} → {da}:{dp}")),
        (Some((sa, da)), None, _) => Some(format!("{sa} → {da}")),
        (None, Some((sp, dp)), _) => Some(format!(":{sp} → :{dp}")),
        (None, None, Some((sm, dm))) => Some(format!("{sm} → {dm}")),
        (None, None, None) => None,
    }
}

/// One packets-mode line (08.4): index, timestamp, layer chain,
/// innermost endpoints (source order), headline field, caplen, stop.
pub fn packet_line(index: u64, pkt: &DissectedPacket) -> String {
    let chain: Vec<&str> = pkt.layers.iter().map(|l| l.protocol).collect();
    let mut out = format!(
        "{}  {}  {}",
        index,
        time_of_day(pkt.meta.timestamp),
        chain.join(" ▸ ")
    );
    if let Some(endpoints) = packet_endpoints_str(pkt) {
        out.push_str(&format!("  {endpoints}"));
    }
    if let Some(headline) = headline_str(pkt) {
        out.push_str(&format!("  {headline}"));
    }
    out.push_str(&format!(
        "  {}  [{}]",
        human_bytes(pkt.meta.caplen as u64),
        stop_str(pkt.stop),
    ));
    out
}

/// The full packets-mode entry per verbosity (08.4): base line; `-v`
/// adds per-layer field blocks with offsets and header lengths; `-vv`
/// adds a bounded hex dump of the unparsed payload and `via_heuristic`
/// markers (03.3). `tail_sample` is already capped by the producer
/// thread ([`crate::run::PacketEvent`]); `pkt.opaque_len` is the true
/// unparsed length.
pub fn packet_block(
    index: u64,
    pkt: &DissectedPacket,
    verbosity: u8,
    tail_sample: &[u8],
    heuristic: &[bool],
) -> String {
    let mut out = packet_line(index, pkt);
    out.push('\n');
    if verbosity == 0 {
        return out;
    }
    for (i, layer) in pkt.layers.iter().enumerate() {
        let marker = if verbosity >= 2 && heuristic.get(i).copied().unwrap_or(false) {
            "  (via heuristic)"
        } else {
            ""
        };
        out.push_str(&format!(
            "    {} @{} hdr {}{marker}",
            layer.protocol, layer.offset, layer.header_len
        ));
        if !layer.fields.is_empty() {
            let fields: Vec<String> = layer
                .fields
                .iter()
                .map(|(name, value)| {
                    format!("{name}={}", field_value_str(layer.protocol, name, value))
                })
                .collect();
            out.push_str(&format!(": {}", fields.join(" ")));
        }
        out.push('\n');
    }
    if verbosity >= 2 && pkt.opaque_len > 0 {
        let hex: Vec<String> = tail_sample.iter().map(|b| format!("{b:02x}")).collect();
        out.push_str(&format!(
            "    payload ({} of {} unparsed bytes): {}\n",
            tail_sample.len(),
            pkt.opaque_len,
            hex.join(" ")
        ));
    }
    out
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

/// The D8 summary object, shared by the offline envelope (nested under
/// `"summary"`) and the NDJSON `summary` event (flattened alongside
/// `"event"`).
fn summary_json(
    outcome: &RunOutcome,
    snapshot: &AggregatorSnapshot,
) -> serde_json::Map<String, Json> {
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
    let mut m = serde_json::Map::new();
    m.insert("packets".into(), json!(snapshot.summary.packets));
    m.insert("bytes".into(), json!(snapshot.summary.bytes));
    m.insert("stop_classes".into(), Json::Object(stop_classes));
    m.insert("streams".into(), Json::Object(per_protocol));
    m.insert(
        "capture_drops".into(),
        json!(outcome.report.stats.dropped_kernel + outcome.report.stats.dropped_iface),
    );
    m
}

/// The offline JSON envelope (D8): `{"pktflow": 1, …}`, schema
/// `schema/streams-v1.json`. A `--where` query filters `streams[]` to
/// matches only (the summary still describes the whole capture; id
/// references may point outside the filtered set).
pub fn json_envelope(outcome: &RunOutcome, query: Option<&StreamQuery>) -> Json {
    let mut doc = json!({
        "pktflow": 1,
        "mode": outcome.mode,
        "source": outcome.source_name,
    });
    if let Some(snapshot) = &outcome.snapshot {
        doc["summary"] = Json::Object(summary_json(outcome, snapshot));
        let ids = by_id(snapshot);
        let seq_of = |id: StreamId| ids.get(&id).map(|s| s.created_seq);
        doc["streams"] = Json::Array(
            snapshot
                .streams
                .iter()
                .filter(|s| query.is_none_or(|q| q.matches(s, &ids)))
                .map(|s| Json::Object(stream_record(s, &seq_of)))
                .collect(),
        );
    }
    doc
}

/// The default `--format json` NDJSON event tracker (08.5): `stream_new`
/// fires the first time a stream is observed; `stream_update` throttles
/// to ≥1 s per stream; `stream_closed` fires immediately from the
/// aggregator's eviction sink, which sees only the departing `Stream`
/// (no live aggregator reference) — `seq_by_id` is populated from every
/// poll so a close event can still resolve its parent's display id.
pub struct NdjsonTracker {
    last_poll: std::time::Instant,
    last_emitted: HashMap<StreamId, std::time::Instant>,
    seq_by_id: HashMap<StreamId, u64>,
}

impl Default for NdjsonTracker {
    fn default() -> Self {
        Self {
            last_poll: std::time::Instant::now() - std::time::Duration::from_secs(2),
            last_emitted: HashMap::new(),
            seq_by_id: HashMap::new(),
        }
    }
}

impl NdjsonTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Called after every ingest; throttles its own work to ~10/s so a
    /// high packet rate doesn't turn this into a per-packet cost.
    pub fn poll(&mut self, agg: &pktflow_flows::Aggregator) -> Vec<Json> {
        if self.last_poll.elapsed() < std::time::Duration::from_millis(100) {
            return Vec::new();
        }
        self.last_poll = std::time::Instant::now();

        // Two passes: populate every id's display number before
        // resolving any parent/children (order-independent within a poll).
        for s in agg.streams() {
            self.seq_by_id.insert(s.id, s.created_seq);
        }
        let seq_of = |id: StreamId| self.seq_by_id.get(&id).copied();

        let now = std::time::Instant::now();
        let mut events = Vec::new();
        for s in agg.streams() {
            let kind = match self.last_emitted.get(&s.id) {
                None => Some("stream_new"),
                Some(last) if now.duration_since(*last) >= std::time::Duration::from_secs(1) => {
                    Some("stream_update")
                }
                _ => None,
            };
            if let Some(kind) = kind {
                self.last_emitted.insert(s.id, now);
                let mut body = stream_record(s, &seq_of);
                body.insert("event".into(), json!(kind));
                events.push(Json::Object(body));
            }
        }
        events
    }

    /// Called from the aggregator's eviction sink: immediate, never
    /// throttled — a closure is a one-time event.
    pub fn on_evicted(&mut self, ev: &pktflow_flows::EvictedStream) -> Json {
        self.last_emitted.remove(&ev.stream.id);
        let seq_of = |id: StreamId| self.seq_by_id.get(&id).copied();
        let mut body = stream_record(&ev.stream, &seq_of);
        body.insert("event".into(), json!("stream_closed"));
        body.insert("close_reason".into(), json!(close_reason_json(ev.reason)));
        Json::Object(body)
    }

    /// The final line (08.1's graceful Ctrl-C path calls `finish()`
    /// before this ever runs, so it is always reachable).
    pub fn summary_event(outcome: &RunOutcome, snapshot: &AggregatorSnapshot) -> Json {
        let mut body = summary_json(outcome, snapshot);
        body.insert("event".into(), json!("summary"));
        Json::Object(body)
    }
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
