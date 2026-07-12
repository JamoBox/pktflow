//! `pktflow-tui` — the interactive terminal UI.
//!
//! Browse the live (or replayed) stream hierarchy, drill into any stream
//! for its full rollup detail, and triage unknown traffic — all from one
//! full-screen session. Rendering reads only published
//! [`pktflow_flows::AggregatorSnapshot`]s via a [`SnapshotHub`]; the
//! aggregation thread stays the store's single writer (D5).

pub mod app;
pub mod tree;
mod ui;

use std::io;
use std::sync::Arc;
use std::time::Duration;

use pktflow_view::SnapshotHub;
use ratatui::crossterm::event::{self, Event, KeyEventKind};

/// Runs the TUI until the user quits. Enters the alternate screen and
/// raw mode; always restores the terminal, including on error. A
/// non-terminal stdout (pipe, CI) fails here with a plain error rather
/// than a panic.
pub fn run(hub: Arc<SnapshotHub>) -> io::Result<()> {
    let mut terminal = ratatui::try_init()?;
    let result = event_loop(&mut terminal, &hub);
    ratatui::restore();
    result
}

fn event_loop(terminal: &mut ratatui::DefaultTerminal, hub: &Arc<SnapshotHub>) -> io::Result<()> {
    let mut app = app::App::default();
    let mut seen_generation = u64::MAX; // force the first refresh
    let mut snapshot = hub.latest();
    while !app.quit {
        if !app.paused {
            let generation = hub.generation();
            if generation != seen_generation {
                seen_generation = generation;
                snapshot = hub.latest();
            }
        }
        let status = ui::HubStatus {
            source: hub.source().to_string(),
            mode: hub.mode(),
            finished: hub.is_finished(),
            error: hub.error(),
            paused: app.paused,
        };
        terminal.draw(|frame| ui::draw(frame, &mut app, &snapshot, &status))?;

        // 100 ms tick: snappy keys, ~10 fps refresh while live.
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Release {
                    app.on_key(key, &snapshot);
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    use pktflow_core::{
        Canonicalize, DissectedPacket, Engine, FieldMap, KeyField, LayerPlugin, LayerRecord,
        LinkType, PacketMeta, ParseCtx, ParseError, ParsedLayer, ProtocolName, StopReason,
        StreamIdentity, Value,
    };
    use pktflow_flows::{Aggregator, AggregatorConfig, AggregatorSnapshot};
    use ratatui::backend::TestBackend;
    use ratatui::crossterm::event::{KeyCode, KeyEvent};
    use ratatui::Terminal;

    use pktflow_view::StreamQuery;

    use crate::app::App;
    use crate::tree::{flatten, Sort};

    /// Identity-bearing test plugin; ingest never calls parse.
    struct Keyed {
        name: ProtocolName,
    }

    impl LayerPlugin for Keyed {
        fn name(&self) -> ProtocolName {
            self.name
        }

        fn parse(&self, _bytes: &[u8], _ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
            Err(ParseError::Malformed("ingest-only test plugin"))
        }

        fn stream_identity(&self) -> Option<&StreamIdentity> {
            static PAIR_KEY: &[KeyField] = &[KeyField {
                a: "src",
                b: Some("dst"),
            }];
            static IDENTITY: StreamIdentity = StreamIdentity {
                key: PAIR_KEY,
                canonicalize: Canonicalize::EndpointSort,
                lifecycle: None,
                rollups: &[],
            };
            Some(&IDENTITY)
        }
    }

    fn layer(protocol: ProtocolName, src: u64, dst: u64) -> LayerRecord {
        let mut fields = FieldMap::new();
        fields.insert("src", Value::U64(src));
        fields.insert("dst", Value::U64(dst));
        LayerRecord {
            protocol,
            offset: 0,
            header_len: 0,
            fields,
        }
    }

    fn packet(layers: Vec<LayerRecord>, ms: u64) -> DissectedPacket {
        DissectedPacket {
            meta: PacketMeta {
                timestamp: SystemTime::UNIX_EPOCH + Duration::from_millis(ms),
                caplen: 100,
                origlen: 100,
                link_type: LinkType::ETHERNET,
            },
            layers,
            stop: StopReason::Complete,
            opaque_len: 0,
            unknown: None,
        }
    }

    /// eth #0 ▸ ip #1, plus a second root eth #2 — enough hierarchy to
    /// exercise fold/filter/selection.
    fn snapshot() -> AggregatorSnapshot {
        let engine = Arc::new(
            Engine::builder()
                .plugin(Keyed { name: "eth" })
                .plugin(Keyed { name: "ip" })
                .build()
                .expect("valid registry"),
        );
        let mut agg = Aggregator::new(&engine, AggregatorConfig::default());
        agg.ingest(&packet(vec![layer("eth", 1, 2), layer("ip", 10, 20)], 0));
        agg.ingest(&packet(vec![layer("eth", 1, 2), layer("ip", 10, 20)], 5));
        agg.ingest(&packet(vec![layer("eth", 3, 4)], 9));
        agg.snapshot()
    }

    #[test]
    fn flatten_walks_roots_then_children_with_glyphs() {
        let snap = snapshot();
        let rows = flatten(&snap, Sort::FirstSeen, &Default::default(), None);
        let labels: Vec<(u64, &str)> = rows
            .iter()
            .map(|r| (r.stream.created_seq, r.stream.protocol))
            .collect();
        assert_eq!(labels, [(0, "eth"), (1, "ip"), (2, "eth")]);
        assert_eq!(rows[1].prefix, "└─ ");
        assert!(rows[0].has_children && rows[0].expanded);
    }

    #[test]
    fn collapse_hides_the_subtree_and_filter_reveals_it() {
        let snap = snapshot();
        let collapsed = std::iter::once(0).collect();
        let rows = flatten(&snap, Sort::FirstSeen, &collapsed, None);
        let seqs: Vec<u64> = rows.iter().map(|r| r.stream.created_seq).collect();
        assert_eq!(seqs, [0, 2], "collapsed root hides ip");

        // The query matches the ip child; its collapsed ancestor is
        // auto-expanded so the match is reachable.
        let query = StreamQuery::parse("proto == ip").expect("query parses");
        let rows = flatten(&snap, Sort::FirstSeen, &collapsed, Some(&query));
        let seqs: Vec<u64> = rows.iter().map(|r| r.stream.created_seq).collect();
        assert_eq!(seqs, [0, 1]);
    }

    #[test]
    fn keys_move_selection_and_toggle_folds() {
        let snap = Arc::new(snapshot());
        let mut app = App {
            sort: Sort::FirstSeen,
            ..App::default()
        };

        app.on_key(KeyEvent::from(KeyCode::Down), &snap);
        assert_eq!(app.selected, Some(1), "down from implicit row 0");
        app.on_key(KeyEvent::from(KeyCode::Char('h')), &snap);
        assert_eq!(app.selected, Some(0), "h on a leaf jumps to parent");
        app.on_key(KeyEvent::from(KeyCode::Enter), &snap);
        assert!(app.collapsed.contains(&0), "enter folds the parent");
        app.on_key(KeyEvent::from(KeyCode::Char('q')), &snap);
        assert!(app.quit);
    }

    #[test]
    fn frames_render_streams_unknown_and_summary_tabs() {
        let snap = Arc::new(snapshot());
        let mut app = App::default();
        let status = crate::ui::HubStatus {
            source: "test.pcap".into(),
            mode: "offline",
            finished: true,
            error: None,
            paused: false,
        };
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).expect("test terminal");

        for (key, expect) in [
            (None, "streams (3)"),
            (Some(KeyCode::Char('2')), "no unknown protocols observed"),
            (Some(KeyCode::Char('3')), "capture totals"),
            (Some(KeyCode::Char('?')), "any key to close"),
        ] {
            if let Some(code) = key {
                app.on_key(KeyEvent::from(code), &snap);
            }
            terminal
                .draw(|frame| crate::ui::draw(frame, &mut app, &snap, &status))
                .expect("draw");
            let rendered = format!("{:?}", terminal.backend().buffer());
            assert!(
                rendered.contains(expect),
                "expected {expect:?} in frame:\n{rendered}"
            );
        }
    }
}
