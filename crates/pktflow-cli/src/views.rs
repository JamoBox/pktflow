//! First-cut view rendering for each subcommand. 08.2–08.4 own the final
//! line grammars and golden tests; 08.1 needs every lens functional with
//! clean stdout (JSON) / stderr (summary) separation.

use std::collections::HashMap;

use pktflow_capture::InterfaceInfo;
use pktflow_core::{DissectedPacket, PacketDirection, StopReason};
use pktflow_flows::{AggregatorSnapshot, Rollup, SeriesPoint, Stream, StreamId};
use serde_json::{json, Value as Json};

use crate::cli::SortOrder;
use crate::error::CliError;
use crate::render::{
    field_value_str, human_bytes, human_duration, thousands, time_of_day, value_str,
};
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
        SortOrder::FirstSeen => streams.sort_by_key(|s| s.created_seq),
        SortOrder::Duration => streams.sort_by_key(|s| {
            std::cmp::Reverse(s.last_seen.duration_since(s.first_seen).unwrap_or_default())
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
    let (a_side, b_side, extras) = endpoint_sides(s);
    let mut out = String::new();
    if !a_side.is_empty() {
        out.push_str(&format!("{a_side} ↔ {b_side}"));
    }
    if !extras.is_empty() {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(&extras.join(" "));
    }
    out
}

/// The two rendered endpoint sides (canonical A, B) plus non-paired key
/// fields. Empty side strings = no endpoint pair (qualifier-keyed).
fn endpoint_sides(s: &Stream) -> (String, String, Vec<String>) {
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
    (a_side.join(","), b_side.join(","), extras)
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

fn lineage_str(s: &Stream, ids: &HashMap<StreamId, &Stream>) -> String {
    let mut lineage = Vec::new();
    let mut cursor = s.parent;
    while let Some(pid) = cursor {
        let Some(parent) = ids.get(&pid) else { break };
        let endpoints = endpoints_str(parent);
        let entry = if endpoints.is_empty() {
            format!("{} #{}", parent.protocol, parent.created_seq)
        } else {
            format!("{} #{} ({endpoints})", parent.protocol, parent.created_seq)
        };
        lineage.push(entry);
        cursor = parent.parent;
    }
    lineage.reverse();
    lineage.join(" ▸ ")
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
            out.push_str(&rollup_line(s.protocol, field, rollup, full_series));
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

fn close_reason_str(reason: pktflow_flows::CloseReason) -> &'static str {
    match reason {
        pktflow_flows::CloseReason::ProtocolClose => "protocol-close",
        pktflow_flows::CloseReason::IdleTimeout => "idle-timeout",
        pktflow_flows::CloseReason::LruEvicted => "lru-evicted",
        pktflow_flows::CloseReason::CaptureEnd => "capture-end",
    }
}

/// A child plus its single-child descendants: `ipv4 #3 (…) ▸ tcp #4 (…)`
/// — the inner stack of a tunnel visible from the drill-down.
fn child_chain_str(child: &Stream, ids: &HashMap<StreamId, &Stream>) -> String {
    let mut parts = Vec::new();
    let mut cursor = Some(child);
    while let Some(s) = cursor {
        let endpoints = endpoints_str(s);
        if endpoints.is_empty() {
            parts.push(format!("{} #{}", s.protocol, s.created_seq));
        } else {
            parts.push(format!("{} #{} ({endpoints})", s.protocol, s.created_seq));
        }
        cursor = match s.children.as_slice() {
            [only] => ids.get(only).copied(),
            _ => None,
        };
    }
    parts.join(" ▸ ")
}

/// One rollup line per kind (05.4 honesty markers included).
fn rollup_line(protocol: &str, field: &str, rollup: &Rollup, full_series: bool) -> String {
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
                    time_of_day(p.ts),
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
