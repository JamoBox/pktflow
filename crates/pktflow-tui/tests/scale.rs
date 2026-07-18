//! 12.5's TUI budget on the fan-out shape: a keypress (flatten against
//! the 12.4 index + a full frame draw) must land in interactive time
//! even with the store uncondensed. `#[ignore]`d like the RSS ceilings —
//! a timing assertion belongs to the release-mode scheduled/manual tier
//! (`cargo test -p pktflow-tui --release --test scale -- --ignored`).

use std::sync::Arc;
use std::time::Instant;

use pktflow_core::{Depth, ParseOpts};
use pktflow_flows::{Aggregator, AggregatorConfig};
use pktflow_testkit::{fan_out_packets, FanOutSpec};
use pktflow_tui::app::App;
use pktflow_tui::ui::{draw, HubStatus};
use pktflow_view::SnapshotIndex;
use ratatui::backend::TestBackend;
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::Terminal;

#[test]
#[ignore = "release-mode timing budget — scheduled/manual tier"]
fn keypress_and_frame_stay_interactive_at_scale() {
    // 100k uncondensed streams: worse than the condensed reference
    // fixture the DoD names.
    let spec = FanOutSpec {
        anchors: 4,
        flows_per_anchor: 25_000,
        packets_per_flow: 1,
        payload_len: 16,
        seed: 0x00C0_FFEE,
    };
    let engine = Arc::new(pktflow_plugins::default_engine());
    let mut agg = Aggregator::new(
        &engine,
        AggregatorConfig {
            condense_threshold: 0,
            ..AggregatorConfig::default()
        },
    );
    let opts = ParseOpts {
        depth: Depth::Full,
        aggregation: true,
        ..ParseOpts::default()
    };
    for (ts, bytes) in fan_out_packets(&spec) {
        let meta = pktflow_core::PacketMeta {
            timestamp: ts,
            caplen: bytes.len(),
            origlen: bytes.len(),
            link_type: pktflow_core::LinkType::ETHERNET,
        };
        agg.ingest(&engine.dissect(&bytes, meta, opts));
    }
    let view = SnapshotIndex::new(Arc::new(agg.snapshot()));

    let mut app = App::default();
    let status = HubStatus {
        source: "scale.pcap".into(),
        mode: "offline",
        finished: true,
        error: None,
        paused: false,
    };
    let backend = TestBackend::new(160, 45);
    let mut terminal = Terminal::new(backend).expect("test terminal");

    // Warm the index facets once (first reader pays the lazy builds).
    app.on_key(KeyEvent::from(KeyCode::Down), &view);

    let rounds = 20u32;
    let started = Instant::now();
    for _ in 0..rounds {
        app.on_key(KeyEvent::from(KeyCode::Down), &view);
        terminal
            .draw(|frame| draw(frame, &mut app, &view, &status))
            .expect("draw");
    }
    let per_round = started.elapsed() / rounds;
    println!("keypress+frame: {per_round:?} per round");
    assert!(
        per_round.as_millis() < 50,
        "keypress+frame took {per_round:?} (budget 50 ms)"
    );
}
