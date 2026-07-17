//! 12.7: the fan-out corpus wired through the real dissect→aggregate
//! pipeline — fast shape checks per PR, and the `#[ignore]`d memory
//! ceiling the scheduled/manual tier runs in release mode
//! (`cargo test -p pktflow-cli --release --test scale -- --ignored`).

use std::sync::Arc;

use pktflow_core::{Depth, ParseOpts};
use pktflow_flows::{Aggregator, AggregatorConfig};
use pktflow_testkit::{fan_out_packets, write_pcap_streamed, FanOutSpec};

/// The task-12 reference fixture (benches/README.md): 1M flows / 3M
/// packets / 1,000,048 streams.
fn reference_spec() -> FanOutSpec {
    FanOutSpec {
        anchors: 8,
        flows_per_anchor: 125_000,
        packets_per_flow: 3,
        payload_len: 32,
        seed: 0xC0FF_EE,
    }
}

fn opts() -> ParseOpts {
    ParseOpts {
        depth: Depth::Full,
        aggregation: true,
        ..ParseOpts::default()
    }
}

fn ingest_fan_out(spec: &FanOutSpec, snapshot_every: usize) -> Aggregator {
    let engine = Arc::new(pktflow_plugins::default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());
    let mut held = None; // a reader holding the latest publish, like the hub
    for (i, (ts, bytes)) in fan_out_packets(spec).enumerate() {
        let meta = pktflow_core::PacketMeta {
            timestamp: ts,
            caplen: bytes.len(),
            origlen: bytes.len(),
            link_type: pktflow_core::LinkType::ETHERNET,
        };
        let pkt = engine.dissect(&bytes, meta, opts());
        agg.ingest(&pkt);
        if snapshot_every > 0 && i % snapshot_every == snapshot_every - 1 {
            held = Some(agg.snapshot());
        }
    }
    drop(held);
    agg
}

/// The exact stream shape a fan-out spec must produce: per anchor, one
/// eth + one ipv4 conversation per client slot, and one transport
/// stream per ephemeral flow.
#[test]
fn fan_out_aggregates_to_the_expected_stream_shape() {
    let spec = FanOutSpec {
        anchors: 2,
        flows_per_anchor: 100,
        packets_per_flow: 3,
        payload_len: 16,
        seed: 42,
    };
    let agg = ingest_fan_out(&spec, 64);

    let summary = agg.summary();
    assert_eq!(summary.packets, 600);
    assert_eq!(
        summary.streams_created,
        2 + 2 + 200,
        "one eth + one ipv4 per anchor, one transport stream per flow"
    );
    let by_proto = |name: &str| {
        summary
            .per_protocol
            .iter()
            .find(|p| p.protocol == name)
            .map_or(0, |p| p.ever)
    };
    assert_eq!(by_proto("ethernet"), 2);
    assert_eq!(by_proto("ipv4"), 2);
    assert_eq!(by_proto("tcp") + by_proto("udp"), 200);
    assert!(by_proto("tcp") > by_proto("udp"), "~75/25 mix");

    // Determinism across a re-run, snapshots included (PRD §7).
    let again = ingest_fan_out(&spec, 64);
    assert_eq!(
        format!("{:?}", agg.snapshot()),
        format!("{:?}", again.snapshot())
    );
}

/// Peak RSS (VmHWM) in kB — Linux-only, which is where CI runs this.
#[cfg(target_os = "linux")]
fn peak_rss_kb() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").expect("proc status");
    status
        .lines()
        .find_map(|l| l.strip_prefix("VmHWM:"))
        .and_then(|v| v.trim().trim_end_matches(" kB").trim().parse().ok())
        .expect("VmHWM present")
}

/// 12.7 memory ceiling: 1M flows / 3M packets through the pipeline with
/// hub-style periodic publishing. Budget recorded in benches/README.md
/// (task-12 section); fails on a 25% regression over it.
#[test]
#[ignore = "multi-minute, release-mode memory ceiling — scheduled/manual tier"]
#[cfg(target_os = "linux")]
fn hub_scale_rss_stays_under_budget() {
    // Measured 1,299,484 kB peak (benches/README.md task-12 section)
    // + 25% headroom. The pre-task baseline measured 2,606,092 kB.
    const BUDGET_KB: u64 = 1_625_000;
    let spec = reference_spec();
    let agg = ingest_fan_out(&spec, 262_144);
    assert_eq!(agg.summary().streams_created, 1_000_048);

    let peak = peak_rss_kb();
    println!("peak_rss_kb={peak} (budget {BUDGET_KB})");
    assert!(
        peak < BUDGET_KB,
        "peak RSS {peak} kB exceeds the recorded budget {BUDGET_KB} kB (>25% regression)"
    );
}

/// Fixture writer disguised as a test: streams the reference fixture to
/// the path in `PKTFLOW_SCALE_FIXTURE` (~330 MB pcap) for end-to-end
/// timing against the real binary. Never materializes it in memory.
#[test]
#[ignore = "fixture writer — set PKTFLOW_SCALE_FIXTURE to a target path"]
fn write_reference_fixture() {
    let Some(path) = std::env::var_os("PKTFLOW_SCALE_FIXTURE") else {
        return;
    };
    write_pcap_streamed(
        fan_out_packets(&reference_spec()),
        std::path::Path::new(&path),
    )
    .expect("write fixture pcap");
}

/// The `--batch`-equivalent reference for the task-12 "hub < 2× batch"
/// DoD line: same corpus, no periodic publishing. Reports; no budget of
/// its own (run each RSS test in its own process — VmHWM is per-process).
#[test]
#[ignore = "multi-minute, release-mode memory reference — scheduled/manual tier"]
#[cfg(target_os = "linux")]
fn batch_scale_rss_reference() {
    let spec = reference_spec();
    let agg = ingest_fan_out(&spec, 0);
    assert_eq!(agg.summary().streams_created, 1_000_048);
    println!("batch_peak_rss_kb={}", peak_rss_kb());
}
