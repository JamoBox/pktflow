//! 09.4 bench 4: peak RSS-delta ingesting a bulk distinct-flow corpus at
//! `max_streams: 100_000` — demonstrates the D2 eviction policy's
//! memory plateau and records a per-stream cost. Not a timing
//! benchmark (RSS doesn't compose under criterion's repeated-iteration
//! model the way latency does), so this target is `harness = false`
//! with its own `main()` rather than criterion's macros; `just bench`
//! still runs it alongside the others, and results belong in
//! `benches/README.md`.

use std::fs;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use pktflow_core::{Depth, LinkType, PacketMeta, ParseOpts};
use pktflow_flows::{Aggregator, AggregatorConfig, EvictionPolicy};
use pktflow_testkit::{pool_ipv4, pool_mac, PacketBuilder};

const MAX_STREAMS: usize = 100_000;
// Each packet here forms 3 stream layers (eth, ipv4, udp), all counted
// against `max_streams`, so the cap is actually reached around packet
// 33,334 — checkpoints span well before it, right around it, and a
// modest overshoot to demonstrate the plateau. LRU eviction is an
// O(live_count) scan per evicted packet (09.4 finding, see
// benches/README.md), so a checkpoint far past the cap gets expensive
// fast; this stays a few thousand packets past it, not tens of
// thousands.
const CHECKPOINTS: &[usize] = &[10_000, 25_000, 34_000, 37_000, 40_000];

fn vm_rss_kb() -> u64 {
    let status = fs::read_to_string("/proc/self/status").expect("read /proc/self/status");
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            return rest
                .trim()
                .trim_end_matches("kB")
                .trim()
                .parse()
                .expect("VmRSS is a number of kB");
        }
    }
    panic!("VmRSS not found in /proc/self/status (non-Linux host?)");
}

/// One packet, one brand-new distinct flow (unclaimed UDP port — cheap
/// to dissect, and every packet creates a fresh eth/ipv4/udp stream
/// chain rather than folding into an existing one).
fn distinct_flow_packet(i: u32) -> (SystemTime, Vec<u8>) {
    let a = pool_ipv4(10, i);
    let b = pool_ipv4(172, i);
    let (meta, bytes) = PacketBuilder::at_secs(u64::from(i))
        .eth(&pool_mac(1, i), &pool_mac(2, i))
        .ipv4(&a, &b)
        .udp(51000, 51001)
        .payload(32)
        .build();
    (meta.timestamp, bytes)
}

fn main() {
    let engine = Arc::new(pktflow_plugins::default_engine());
    let mut agg = Aggregator::new(
        &engine,
        AggregatorConfig {
            eviction: EvictionPolicy::Live {
                // "Never" idle-times-out for this run: long enough that
                // no checkpoint here reaches it, short enough that
                // `ts + idle_timeout` doesn't overflow `SystemTime`.
                idle_timeout: Duration::from_secs(365 * 24 * 3600 * 100),
                close_linger: Duration::from_secs(0),
                max_streams: MAX_STREAMS,
            },
            ..AggregatorConfig::default()
        },
    );
    let opts = ParseOpts {
        depth: Depth::Keys,
        ..ParseOpts::default()
    };

    let baseline_kb = vm_rss_kb();
    println!("aggregator_memory: baseline RSS = {baseline_kb} kB (max_streams = {MAX_STREAMS})");
    println!(
        "{:>10} {:>10} {:>12} {:>12} {:>14}",
        "packets", "live", "rss_kb", "delta_kb", "kb_per_stream"
    );

    let max_checkpoint = *CHECKPOINTS.last().expect("checkpoints nonempty");
    let mut next = 0usize;
    for i in 0..max_checkpoint as u32 {
        let (ts, bytes) = distinct_flow_packet(i);
        let meta = PacketMeta {
            timestamp: ts,
            caplen: bytes.len(),
            origlen: bytes.len(),
            link_type: LinkType::ETHERNET,
        };
        let dissected = engine.dissect(&bytes, meta, opts);
        agg.ingest(&dissected);

        if next < CHECKPOINTS.len() && (i as usize + 1) == CHECKPOINTS[next] {
            let live = agg.len();
            let rss_kb = vm_rss_kb();
            let delta_kb = rss_kb.saturating_sub(baseline_kb);
            let per_stream = delta_kb as f64 / live.max(1) as f64;
            println!(
                "{:>10} {:>10} {:>12} {:>12} {:>14.3}",
                i + 1,
                live,
                rss_kb,
                delta_kb,
                per_stream
            );
            next += 1;
        }
    }
}
