//! Rendering: one `draw` per frame, entirely derived from the app state
//! plus the snapshot on screen. No hierarchy walking here — `tree` owns
//! that; no aggregator access ever (D5).

use std::collections::HashMap;

use pktflow_core::{PacketDirection, Value};
use pktflow_flows::{AggregatorSnapshot, Rollup, Stream, StreamId, UnknownGroup};
use pktflow_view::fmt::{hex_dump_lines, human_bytes, human_duration, thousands, time_of_day};
use pktflow_view::{
    by_id, child_chain_str, close_reason_str, endpoint_sides, endpoints_str, lineage_str,
    total_bytes, total_packets,
};
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{
    Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState, Tabs, Wrap,
};
use ratatui::Frame;

use crate::app::{App, Tab};
use crate::tree::{flatten, TreeRow};

/// What the event loop reads off the hub once per frame.
pub struct HubStatus {
    pub source: String,
    pub mode: &'static str,
    pub finished: bool,
    pub error: Option<String>,
    pub paused: bool,
}

const ACCENT: Color = Color::Cyan;
const DIM: Color = Color::DarkGray;

/// Deterministic protocol → color mapping, stable across frames.
fn proto_color(name: &str) -> Color {
    const PALETTE: [Color; 8] = [
        Color::Cyan,
        Color::Green,
        Color::Yellow,
        Color::Magenta,
        Color::Blue,
        Color::LightRed,
        Color::LightGreen,
        Color::LightMagenta,
    ];
    let mut h: usize = 0;
    for b in name.bytes() {
        h = h.wrapping_mul(31).wrapping_add(b as usize);
    }
    PALETTE[h % PALETTE.len()]
}

/// Unicode block sparkline over the raw values, normalized to the max.
fn spark_str(values: &[u64]) -> String {
    const BARS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    let max = values.iter().copied().max().unwrap_or(0).max(1);
    values
        .iter()
        .map(|v| BARS[((v * 7) / max) as usize])
        .collect()
}

/// Fixed-width two-tone ratio bar: `████░░░░`.
fn bar_str(numer: u64, denom: u64, width: usize) -> String {
    let denom = denom.max(1);
    let filled = ((numer as u128 * width as u128) / denom as u128) as usize;
    let filled = filled.min(width);
    format!("{}{}", "█".repeat(filled), "░".repeat(width - filled))
}

pub fn draw(frame: &mut Frame, app: &mut App, snapshot: &AggregatorSnapshot, status: &HubStatus) {
    let [header, tabs, body, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(3),
        Constraint::Length(1),
    ])
    .areas(frame.area());

    draw_header(frame, header, snapshot, status);
    draw_tabs(frame, tabs, app);
    match app.tab {
        Tab::Streams => draw_streams(frame, body, app, snapshot),
        Tab::Unknown => draw_unknown(frame, body, app, snapshot),
        Tab::Summary => draw_summary(frame, body, snapshot),
    }
    draw_footer(frame, footer, app, status);

    if app.unknown_open {
        draw_unknown_popup(frame, app, snapshot);
    }
    if app.help {
        draw_help(frame);
    }
}

fn draw_header(frame: &mut Frame, area: Rect, snapshot: &AggregatorSnapshot, status: &HubStatus) {
    let badge = match (status.mode, status.finished) {
        ("live", false) => Span::styled(" LIVE ", Style::new().fg(Color::Black).bg(Color::Red)),
        ("live", true) => Span::styled(" ENDED ", Style::new().fg(Color::Black).bg(DIM)),
        (_, false) => Span::styled(" READING ", Style::new().fg(Color::Black).bg(Color::Yellow)),
        (_, true) => Span::styled(" FILE ", Style::new().fg(Color::Black).bg(ACCENT)),
    };
    let s = &snapshot.summary;
    let line = Line::from(vec![
        Span::styled(
            " pktflow ",
            Style::new().fg(ACCENT).add_modifier(Modifier::BOLD),
        ),
        badge,
        Span::raw(" "),
        Span::styled(
            status.source.clone(),
            Style::new().add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(
                "   {} pkts · {} · {} streams ({} live)",
                thousands(s.packets),
                human_bytes(s.bytes),
                thousands(s.streams_created),
                thousands(s.streams_live),
            ),
            Style::new().fg(DIM),
        ),
        if status.paused {
            Span::styled("  ⏸ paused", Style::new().fg(Color::Yellow))
        } else {
            Span::raw("")
        },
    ]);
    frame.render_widget(Paragraph::new(line), area);
}

fn draw_tabs(frame: &mut Frame, area: Rect, app: &App) {
    let [left, right] =
        Layout::horizontal([Constraint::Min(30), Constraint::Length(40)]).areas(area);
    let titles = ["[1] Streams", "[2] Unknown", "[3] Summary"];
    let index = match app.tab {
        Tab::Streams => 0,
        Tab::Unknown => 1,
        Tab::Summary => 2,
    };
    frame.render_widget(
        Tabs::new(titles.iter().map(|t| Line::from(*t)))
            .select(index)
            .highlight_style(Style::new().fg(ACCENT).add_modifier(Modifier::BOLD))
            .style(Style::new().fg(DIM))
            .divider(" "),
        left,
    );
    let mut info = format!("sort: {} ", app.sort.label());
    if app.filter_editing || !app.filter.is_empty() {
        info.push_str(&format!(
            " /{}{}",
            app.filter,
            if app.filter_editing { "▌" } else { "" }
        ));
    }
    frame.render_widget(
        Paragraph::new(info)
            .alignment(Alignment::Right)
            .style(Style::new().fg(DIM)),
        right,
    );
}

fn draw_footer(frame: &mut Frame, area: Rect, app: &App, status: &HubStatus) {
    let text = if let Some(err) = &status.error {
        Line::from(Span::styled(
            format!(" error: {err}"),
            Style::new().fg(Color::Red).add_modifier(Modifier::BOLD),
        ))
    } else if app.filter_editing {
        Line::from(" type to filter · Enter keep · Esc clear ")
    } else {
        let hints = match app.tab {
            Tab::Streams => {
                " ↑↓ move · ←→ fold · Enter toggle · / filter · s sort · e/c un/fold all · J/K detail · Tab tab · ? help · q quit"
            }
            Tab::Unknown => " ↑↓ move · Enter drill-down · Tab tab · ? help · q quit",
            Tab::Summary => " Tab tab · ? help · q quit",
        };
        Line::from(Span::styled(hints, Style::new().fg(DIM)))
    };
    frame.render_widget(Paragraph::new(text), area);
}

fn draw_streams(frame: &mut Frame, area: Rect, app: &mut App, snapshot: &AggregatorSnapshot) {
    let rows = flatten(snapshot, app.sort, &app.collapsed, &app.filter);
    if rows.is_empty() {
        let msg = if snapshot.summary.packets == 0 {
            "waiting for packets…"
        } else {
            "no streams match the filter"
        };
        frame.render_widget(
            Paragraph::new(msg).style(Style::new().fg(DIM)).block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::new().fg(DIM)),
            ),
            area,
        );
        return;
    }

    let index = app.selected_index(&rows);
    // Re-anchor the selection every frame: live updates may have evicted
    // the selected stream or re-sorted it under a different row.
    if let Some(row) = rows.get(index) {
        app.selected = Some(row.stream.created_seq);
    }

    let [left, right] = Layout::horizontal([Constraint::Fill(3), Constraint::Fill(2)]).areas(area);

    let table_rows: Vec<Row> = rows.iter().map(|r| stream_table_row(r)).collect();
    let mut state = TableState::default().with_selected(Some(index));
    let table = Table::new(
        table_rows,
        [
            Constraint::Fill(1),
            Constraint::Length(11),
            Constraint::Length(9),
            Constraint::Length(9),
        ],
    )
    .header(
        Row::new(["STREAM", "PKTS", "BYTES", "DURATION"])
            .style(Style::new().fg(DIM).add_modifier(Modifier::BOLD)),
    )
    .row_highlight_style(
        Style::new()
            .bg(Color::Rgb(40, 48, 60))
            .add_modifier(Modifier::BOLD),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::new().fg(DIM))
            .title(Span::styled(
                format!(" streams ({}) ", rows.len()),
                Style::new().fg(ACCENT),
            )),
    );
    frame.render_stateful_widget(table, left, &mut state);

    let ids = by_id(snapshot);
    let detail: Text = match rows.get(index) {
        Some(row) => Text::from(detail_lines(row.stream, &ids)),
        None => Text::from("select a stream"),
    };
    let title = rows
        .get(index)
        .map(|r| format!(" {} #{} ", r.stream.protocol, r.stream.created_seq))
        .unwrap_or_else(|| " detail ".into());
    frame.render_widget(
        Paragraph::new(detail)
            .wrap(Wrap { trim: false })
            .scroll((app.detail_scroll, 0))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::new().fg(DIM))
                    .title(Span::styled(title, Style::new().fg(ACCENT))),
            ),
        right,
    );
}

fn stream_table_row<'a>(r: &TreeRow<'a>) -> Row<'a> {
    let s = r.stream;
    let fold = if r.has_children {
        if r.expanded {
            "▾ "
        } else {
            "▸ "
        }
    } else {
        "  "
    };
    let mut spans = vec![
        Span::styled(r.prefix.clone(), Style::new().fg(DIM)),
        Span::styled(fold, Style::new().fg(DIM)),
        Span::styled(
            s.protocol.to_string(),
            Style::new()
                .fg(proto_color(s.protocol))
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(format!(" #{}", s.created_seq), Style::new().fg(DIM)),
    ];
    let endpoints = endpoints_str(s);
    if !endpoints.is_empty() {
        spans.push(Span::raw(format!("  {endpoints}")));
    }
    if let Some(state) = s.state {
        spans.push(Span::styled(
            format!("  [{state}]"),
            Style::new().fg(Color::Yellow),
        ));
    }
    if s.closed.is_some() {
        spans.push(Span::styled("  ✕", Style::new().fg(DIM)));
    }
    let duration = s.last_seen.duration_since(s.first_seen).unwrap_or_default();
    Row::new(vec![
        Cell::from(Line::from(spans)),
        Cell::from(Line::from(thousands(total_packets(s))).alignment(Alignment::Right)),
        Cell::from(Line::from(human_bytes(total_bytes(s))).alignment(Alignment::Right)),
        Cell::from(Line::from(human_duration(duration)).alignment(Alignment::Right)),
    ])
}

fn kv<'a>(key: &'a str, value: String) -> Line<'a> {
    Line::from(vec![
        Span::styled(format!("{key:<10}"), Style::new().fg(DIM)),
        Span::raw(value),
    ])
}

/// The drill-down body: everything the aggregator knows about one stream.
fn detail_lines<'a>(s: &'a Stream, ids: &HashMap<StreamId, &'a Stream>) -> Vec<Line<'a>> {
    let mut lines = Vec::new();

    let mut head = vec![Span::styled(
        format!("{} #{}", s.protocol, s.created_seq),
        Style::new()
            .fg(proto_color(s.protocol))
            .add_modifier(Modifier::BOLD),
    )];
    let endpoints = endpoints_str(s);
    if !endpoints.is_empty() {
        head.push(Span::raw(format!("  {endpoints}")));
    }
    if let Some(state) = s.state {
        head.push(Span::styled(
            format!("  [{state}]"),
            Style::new().fg(Color::Yellow),
        ));
    }
    lines.push(Line::from(head));
    lines.push(Line::raw(""));

    let lineage = lineage_str(s, ids);
    if !lineage.is_empty() {
        lines.push(kv("lineage", format!("{lineage} ▸ this")));
    }

    let duration = s.last_seen.duration_since(s.first_seen).unwrap_or_default();
    lines.push(kv(
        "timing",
        format!(
            "first {}  last {}  ({})",
            time_of_day(s.first_seen),
            time_of_day(s.last_seen),
            human_duration(duration),
        ),
    ));
    lines.push(kv(
        "totals",
        format!(
            "{} pkts / {}",
            thousands(total_packets(s)),
            human_bytes(total_bytes(s))
        ),
    ));

    // Per-direction split with a ratio bar: the at-a-glance asymmetry.
    let (a, b, _) = endpoint_sides(s);
    let total = total_bytes(s);
    for (arrow, dir, side) in [
        ("▲", PacketDirection::AtoB, &a),
        ("▼", PacketDirection::BtoA, &b),
    ] {
        let st = s.stats[pktflow_flows::dir_index(dir)];
        let label = if side.is_empty() {
            arrow.to_string()
        } else {
            format!("{arrow} {side}")
        };
        lines.push(Line::from(vec![
            Span::styled("          ".to_string(), Style::new()),
            Span::styled(bar_str(st.bytes, total, 12), Style::new().fg(ACCENT)),
            Span::raw(format!(
                " {label}  {} pkts / {}",
                thousands(st.packets),
                human_bytes(st.bytes)
            )),
        ]));
    }

    if !a.is_empty() {
        let (side, endpoint) = match s.initiator {
            PacketDirection::AtoB => ("A", &a),
            PacketDirection::BtoA => ("B", &b),
        };
        lines.push(kv("initiator", format!("{side} ({endpoint})")));
    }
    if let Some(state) = s.state {
        let closed = s.closed.map(close_reason_str).unwrap_or("—");
        lines.push(kv("state", format!("{state}   (closed: {closed})")));
    } else if let Some(reason) = s.closed {
        lines.push(kv("closed", close_reason_str(reason).to_string()));
    }
    if s.opaque_bytes > 0 {
        lines.push(kv(
            "opaque",
            format!("{} unparsed payload bytes", thousands(s.opaque_bytes)),
        ));
    }

    if !s.rollups.is_empty() {
        lines.push(Line::raw(""));
        lines.push(Line::from(Span::styled(
            "rollups",
            Style::new().fg(ACCENT).add_modifier(Modifier::BOLD),
        )));
        for (field, rollup) in s.rollups.iter() {
            rollup_lines(s.protocol, field, rollup, &mut lines);
        }
    }

    let children: Vec<String> = s
        .children
        .iter()
        .filter_map(|id| ids.get(id).copied())
        .map(|c| child_chain_str(c, ids))
        .collect();
    if !children.is_empty() {
        lines.push(Line::raw(""));
        lines.push(Line::from(Span::styled(
            format!("children ({})", children.len()),
            Style::new().fg(ACCENT).add_modifier(Modifier::BOLD),
        )));
        for chain in children {
            lines.push(Line::raw(format!("  {chain}")));
        }
    }
    lines
}

fn rollup_lines(protocol: &str, field: &str, rollup: &Rollup, lines: &mut Vec<Line<'static>>) {
    use pktflow_view::fmt::field_value_str;
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
            let marker = if *overflow { " ≥cap" } else { "" };
            lines.push(Line::from(vec![
                Span::styled(format!("  {field}  "), Style::new().fg(DIM)),
                Span::raw(format!(
                    "{{{}}}  ({} distinct / {} obs{marker})",
                    rendered.join(", "),
                    values.len(),
                    thousands(*count),
                )),
            ]));
        }
        Rollup::Sample { first, last } => {
            let render = |v: &Option<Value>| {
                v.as_ref()
                    .map(|v| field_value_str(protocol, field, v))
                    .unwrap_or_else(|| "—".into())
            };
            lines.push(Line::from(vec![
                Span::styled(format!("  {field}  "), Style::new().fg(DIM)),
                Span::raw(format!(
                    "{} → {}  (first → last)",
                    render(first),
                    render(last)
                )),
            ]));
        }
        Rollup::Series {
            ring, truncated, ..
        } => {
            // Numeric series get a sparkline; other shapes list the tail.
            let numeric: Option<Vec<u64>> = ring
                .iter()
                .map(|p| match p.value {
                    Value::U64(v) => Some(v),
                    Value::I64(v) => u64::try_from(v).ok(),
                    _ => None,
                })
                .collect();
            let marker = if *truncated { " (truncated)" } else { "" };
            match numeric {
                Some(vals) if !vals.is_empty() => {
                    let min = vals.iter().copied().min().unwrap_or(0);
                    let max = vals.iter().copied().max().unwrap_or(0);
                    let window: Vec<u64> = vals.iter().rev().take(40).rev().copied().collect();
                    lines.push(Line::from(vec![
                        Span::styled(format!("  {field}  "), Style::new().fg(DIM)),
                        Span::styled(spark_str(&window), Style::new().fg(ACCENT)),
                        Span::raw(format!(
                            "  {} pts  min {min}  max {max}{marker}",
                            ring.len()
                        )),
                    ]));
                }
                _ => {
                    let tail: Vec<String> = ring
                        .iter()
                        .rev()
                        .take(5)
                        .rev()
                        .map(|p| {
                            let arrow = match p.dir {
                                PacketDirection::AtoB => "▲",
                                PacketDirection::BtoA => "▼",
                            };
                            format!(
                                "{} {arrow} {}",
                                time_of_day(p.ts),
                                field_value_str(protocol, field, &p.value)
                            )
                        })
                        .collect();
                    lines.push(Line::from(vec![
                        Span::styled(format!("  {field}  "), Style::new().fg(DIM)),
                        Span::raw(format!("{} pts{marker} · {}", ring.len(), tail.join(" · "))),
                    ]));
                }
            }
        }
    }
}

fn unknown_context(g: &UnknownGroup) -> String {
    match g.key.route {
        Some(route) => format!("{} → {route}", g.key.predecessor),
        None => g.key.predecessor.to_string(),
    }
}

fn unknown_kind(g: &UnknownGroup) -> &'static str {
    match g.key.route {
        Some(_) => "unclaimed route",
        None => "no heuristic winner",
    }
}

fn draw_unknown(frame: &mut Frame, area: Rect, app: &mut App, snapshot: &AggregatorSnapshot) {
    if snapshot.unknowns.is_empty() {
        frame.render_widget(
            Paragraph::new("no unknown protocols observed — every byte claimed 🎉")
                .style(Style::new().fg(DIM))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_style(Style::new().fg(DIM)),
                ),
            area,
        );
        return;
    }
    app.unknown_index = app.unknown_index.min(snapshot.unknowns.len() - 1);

    let rows: Vec<Row> = snapshot
        .unknowns
        .iter()
        .enumerate()
        .map(|(i, g)| {
            let near: Vec<String> = g
                .near_misses
                .iter()
                .take(3)
                .map(|(name, score)| format!("{name}({})", score.get()))
                .collect();
            Row::new(vec![
                Cell::from(format!("#{}", i + 1)),
                Cell::from(Span::styled(
                    unknown_context(g),
                    Style::new().fg(Color::Yellow),
                )),
                Cell::from(unknown_kind(g)),
                Cell::from(Line::from(thousands(g.count)).alignment(Alignment::Right)),
                Cell::from(Line::from(human_bytes(g.bytes_total)).alignment(Alignment::Right)),
                Cell::from(near.join(" · ")),
            ])
        })
        .collect();
    let mut state = TableState::default().with_selected(Some(app.unknown_index));
    let table = Table::new(
        rows,
        [
            Constraint::Length(4),
            Constraint::Fill(2),
            Constraint::Length(20),
            Constraint::Length(9),
            Constraint::Length(9),
            Constraint::Fill(2),
        ],
    )
    .header(
        Row::new(["#", "CONTEXT", "KIND", "COUNT", "BYTES", "NEAR MISSES"])
            .style(Style::new().fg(DIM).add_modifier(Modifier::BOLD)),
    )
    .row_highlight_style(
        Style::new()
            .bg(Color::Rgb(40, 48, 60))
            .add_modifier(Modifier::BOLD),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::new().fg(DIM))
            .title(Span::styled(
                format!(
                    " unknown traffic ({} groups) — Enter to drill in ",
                    snapshot.unknowns.len()
                ),
                Style::new().fg(ACCENT),
            )),
    );
    frame.render_stateful_widget(table, area, &mut state);
}

fn draw_unknown_popup(frame: &mut Frame, app: &App, snapshot: &AggregatorSnapshot) {
    let Some(g) = snapshot.unknowns.get(app.unknown_index) else {
        return;
    };
    let area = centered(frame.area(), 84, 80);
    frame.render_widget(Clear, area);

    let mut lines: Vec<Line> = Vec::new();
    lines.push(kv("context", unknown_context(g)));
    lines.push(kv("kind", unknown_kind(g).to_string()));
    lines.push(kv("count", thousands(g.count)));
    lines.push(kv(
        "bytes",
        format!(
            "total {}  min {}  max {}",
            human_bytes(g.bytes_total),
            human_bytes(u64::from(g.bytes_min)),
            human_bytes(u64::from(g.bytes_max)),
        ),
    ));
    lines.push(kv(
        "seen",
        format!(
            "first {}  last {}",
            time_of_day(g.first_seen),
            time_of_day(g.last_seen)
        ),
    ));

    if g.near_misses.is_empty() {
        lines.push(kv("near", "(none)".into()));
    } else {
        lines.push(Line::raw(""));
        lines.push(Line::from(Span::styled(
            "near misses",
            Style::new().fg(ACCENT).add_modifier(Modifier::BOLD),
        )));
        for (name, score) in &g.near_misses {
            let confidence = u64::from(score.get());
            lines.push(Line::from(vec![
                Span::raw(format!("  {name:<12} ")),
                Span::styled(bar_str(confidence, 100, 20), Style::new().fg(Color::Yellow)),
                Span::raw(format!(" {confidence}")),
            ]));
        }
    }

    lines.push(Line::raw(""));
    if g.samples.is_empty() {
        lines.push(Line::from(Span::styled(
            "samples (none retained)",
            Style::new().fg(DIM),
        )));
    } else {
        lines.push(Line::from(Span::styled(
            format!("samples ({} retained)", g.samples.len()),
            Style::new().fg(ACCENT).add_modifier(Modifier::BOLD),
        )));
        for (i, sample) in g.samples.iter().enumerate() {
            lines.push(Line::from(Span::styled(
                format!("  sample {}: {} bytes", i + 1, sample.len()),
                Style::new().fg(Color::Yellow),
            )));
            for hex in hex_dump_lines(sample) {
                lines.push(Line::raw(format!("    {hex}")));
            }
        }
    }
    lines.push(Line::raw(""));
    lines.push(Line::from(Span::styled(
        format!(
            "scaffold a plugin: pktflow unknown -r <capture> '#{}' --scaffold <name>",
            app.unknown_index + 1
        ),
        Style::new().fg(DIM),
    )));

    frame.render_widget(
        Paragraph::new(lines).scroll((app.popup_scroll, 0)).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::new().fg(Color::Yellow))
                .title(Span::styled(
                    format!(" unknown #{} — Esc to close ", app.unknown_index + 1),
                    Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                )),
        ),
        area,
    );
}

fn draw_summary(frame: &mut Frame, area: Rect, snapshot: &AggregatorSnapshot) {
    let [top, protocols] =
        Layout::vertical([Constraint::Length(6), Constraint::Min(4)]).areas(area);

    let s = &snapshot.summary;
    let mut totals = vec![
        kv("packets", thousands(s.packets)),
        kv("bytes", human_bytes(s.bytes)),
        kv(
            "streams",
            format!(
                "{} created · {} live",
                thousands(s.streams_created),
                thousands(s.streams_live)
            ),
        ),
    ];
    let classes: Vec<String> = s
        .stop_classes
        .iter()
        .filter(|(_, count)| *count > 0)
        .map(|(class, count)| format!("{class:?} {}", thousands(*count)))
        .collect();
    if !classes.is_empty() {
        totals.push(kv("dissect", classes.join(" · ")));
    }
    if s.key_errors > 0 {
        totals.push(kv("key errs", thousands(s.key_errors)));
    }
    frame.render_widget(
        Paragraph::new(totals).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::new().fg(DIM))
                .title(Span::styled(" capture totals ", Style::new().fg(ACCENT))),
        ),
        top,
    );

    // Per-protocol live bytes, computed from the snapshot's live streams.
    let mut bytes_by_proto: HashMap<&str, u64> = HashMap::new();
    for stream in &snapshot.streams {
        *bytes_by_proto.entry(stream.protocol).or_insert(0) += total_bytes(stream);
    }
    let max_bytes = bytes_by_proto.values().copied().max().unwrap_or(1);

    let rows: Vec<Row> = s
        .per_protocol
        .iter()
        .map(|p| {
            let bytes = bytes_by_proto.get(p.protocol).copied().unwrap_or(0);
            Row::new(vec![
                Cell::from(Span::styled(
                    p.protocol.to_string(),
                    Style::new()
                        .fg(proto_color(p.protocol))
                        .add_modifier(Modifier::BOLD),
                )),
                Cell::from(Line::from(thousands(p.ever)).alignment(Alignment::Right)),
                Cell::from(Line::from(thousands(p.live)).alignment(Alignment::Right)),
                Cell::from(Line::from(human_bytes(bytes)).alignment(Alignment::Right)),
                Cell::from(Span::styled(
                    bar_str(bytes, max_bytes, 30),
                    Style::new().fg(proto_color(p.protocol)),
                )),
            ])
        })
        .collect();
    frame.render_widget(
        Table::new(
            rows,
            [
                Constraint::Length(12),
                Constraint::Length(8),
                Constraint::Length(8),
                Constraint::Length(10),
                Constraint::Fill(1),
            ],
        )
        .header(
            Row::new(["PROTOCOL", "STREAMS", "LIVE", "BYTES", ""])
                .style(Style::new().fg(DIM).add_modifier(Modifier::BOLD)),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::new().fg(DIM))
                .title(Span::styled(" per protocol ", Style::new().fg(ACCENT))),
        ),
        protocols,
    );
}

fn draw_help(frame: &mut Frame) {
    let area = centered(frame.area(), 60, 70);
    frame.render_widget(Clear, area);
    let keys = [
        ("q / Ctrl-C", "quit"),
        ("1 / 2 / 3, Tab", "switch tab"),
        ("↑↓ / j k", "move selection"),
        ("← → / h l", "collapse / expand (h on leaf: jump to parent)"),
        ("Enter / Space", "toggle fold"),
        ("e / c", "expand all / collapse all"),
        ("s", "cycle sort (bytes → packets → first-seen → duration)"),
        ("/", "filter streams (protocol, endpoint, state)"),
        ("J / K", "scroll the detail pane"),
        ("p", "pause/resume live snapshot updates"),
        ("g / G", "jump to top / bottom"),
        ("?", "this help"),
    ];
    let mut lines: Vec<Line> = vec![Line::raw("")];
    for (key, what) in keys {
        lines.push(Line::from(vec![
            Span::styled(
                format!("  {key:<16}"),
                Style::new().fg(ACCENT).add_modifier(Modifier::BOLD),
            ),
            Span::raw(what),
        ]));
    }
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::new().fg(ACCENT))
                .title(Span::styled(
                    " keys — any key to close ",
                    Style::new().fg(ACCENT).add_modifier(Modifier::BOLD),
                )),
        ),
        area,
    );
}

/// A centered sub-rect sized as a percentage of the frame.
fn centered(area: Rect, percent_x: u16, percent_y: u16) -> Rect {
    let [_, mid_v, _] = Layout::vertical([
        Constraint::Percentage((100 - percent_y) / 2),
        Constraint::Percentage(percent_y),
        Constraint::Percentage((100 - percent_y) / 2),
    ])
    .areas(area);
    let [_, mid, _] = Layout::horizontal([
        Constraint::Percentage((100 - percent_x) / 2),
        Constraint::Percentage(percent_x),
        Constraint::Percentage((100 - percent_x) / 2),
    ])
    .areas(mid_v);
    mid
}
