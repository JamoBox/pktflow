//! 12.7 scale benches over the fan-out corpus (D16/D17's target shape):
//! what publication costs at high stream cardinality, and what the hub
//! pipeline's publishing adds over a batch run. Gates 12.1's "publication
//! must not dominate ingest" and 12.2's "eviction is never a scan".

use std::hint::black_box;
use std::sync::Arc;
use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion};
use pktflow_core::{Depth, DissectedPacket, Engine, ParseOpts};
use pktflow_flows::{Aggregator, AggregatorConfig, EvictionPolicy};
use pktflow_testkit::{fan_out_packets, FanOutSpec};

fn opts() -> ParseOpts {
    ParseOpts {
        depth: Depth::Full, // rollups on — the GUI pipelines' depth
        aggregation: true,
        ..ParseOpts::default()
    }
}

fn spec(flows: usize, packets_per_flow: usize) -> FanOutSpec {
    FanOutSpec {
        anchors: 4,
        flows_per_anchor: flows / 4,
        packets_per_flow,
        payload_len: 32,
        seed: 0x00C0_FFEE,
    }
}

/// Dissect the whole corpus once; benches replay `DissectedPacket`s so
/// they measure aggregation/publication, not parsing.
fn dissect_corpus(engine: &Engine, spec: &FanOutSpec) -> Vec<DissectedPacket> {
    fan_out_packets(spec)
        .map(|(ts, bytes)| {
            let meta = pktflow_core::PacketMeta {
                timestamp: ts,
                caplen: bytes.len(),
                origlen: bytes.len(),
                link_type: pktflow_core::LinkType::ETHERNET,
            };
            engine.dissect(&bytes, meta, opts())
        })
        .collect()
}

/// Config for the COW/publish/LRU benches: condensation pinned OFF so
/// they keep measuring the raw per-stream machinery at the stated live
/// counts (the fan-out corpus would otherwise condense, 12.3);
/// `bench_condensation` covers the default-on path.
fn raw_config() -> AggregatorConfig {
    AggregatorConfig {
        condense_threshold: 0,
        ..AggregatorConfig::default()
    }
}

fn aggregator_over(engine: &Arc<Engine>, spec: &FanOutSpec) -> Aggregator {
    let mut agg = Aggregator::new(engine, raw_config());
    for pkt in dissect_corpus(engine, spec) {
        agg.ingest(&pkt);
    }
    agg
}

/// `snapshot()` at fan-out cardinality: all-shared republish (the
/// steady-state cost, D17.1 — pointer collection + sort + summary), and
/// the same with 1% of flows touched between snapshots (the COW copies
/// land in ingest; the publish itself must stay flat).
fn bench_snapshot_cow(c: &mut Criterion) {
    let engine = Arc::new(pktflow_plugins::default_engine());
    let mut group = c.benchmark_group("scale_snapshot_cow");
    group.sample_size(20);
    for &flows in &[100_000usize, 400_000] {
        let corpus_spec = spec(flows, 1);
        let mut agg = aggregator_over(&engine, &corpus_spec);
        let touch: Vec<DissectedPacket> = {
            let one_pct = FanOutSpec {
                flows_per_anchor: corpus_spec.flows_per_anchor / 100,
                ..corpus_spec
            };
            dissect_corpus(&engine, &one_pct)
        };

        let mut held = agg.snapshot(); // steady state: a reader holds the last publish
        group.bench_function(format!("{flows}_flows_shared_republish"), |b| {
            b.iter(|| {
                held = agg.snapshot();
                black_box(held.streams.len());
            })
        });
        group.bench_function(format!("{flows}_flows_1pct_touched"), |b| {
            b.iter(|| {
                for pkt in &touch {
                    agg.ingest(pkt); // COW copies happen here
                }
                held = agg.snapshot();
                black_box(held.streams.len());
            })
        });
    }
    group.finish();
}

/// The hub pipeline's cost over batch (12.1's < 10 % gate): the same
/// ingest with a periodic publish + held snapshot (what tui/serve do)
/// vs. none. 64k flows × 4 packets, publish every 8 192 packets ≈ the
/// 250 ms cadence at these rates.
fn bench_ingest_with_publish(c: &mut Criterion) {
    let engine = Arc::new(pktflow_plugins::default_engine());
    let corpus_spec = spec(65_536, 4);
    let corpus = dissect_corpus(&engine, &corpus_spec);

    let mut group = c.benchmark_group("scale_ingest_with_publish");
    group.sample_size(10);
    group.throughput(criterion::Throughput::Elements(corpus.len() as u64));
    group.bench_function("batch", |b| {
        b.iter(|| {
            let mut agg = Aggregator::new(&engine, raw_config());
            for pkt in &corpus {
                agg.ingest(pkt);
            }
            black_box(agg.snapshot().streams.len());
        })
    });
    group.bench_function("publish_every_8k", |b| {
        b.iter(|| {
            let mut agg = Aggregator::new(&engine, raw_config());
            let mut held = None;
            for (i, pkt) in corpus.iter().enumerate() {
                agg.ingest(pkt);
                if i % 8192 == 8191 {
                    held = Some(agg.snapshot());
                }
            }
            black_box(held.map(|s| s.streams.len()));
            black_box(agg.snapshot().streams.len());
        })
    });
    group.finish();
}

/// 12.2's LRU gate: live-mode ingest under a hard cap that forces an
/// eviction per packet — per-eviction cost must not grow with the live
/// set (it was a full scan before the lazy heap).
fn bench_lru_cap_churn(c: &mut Criterion) {
    let engine = Arc::new(pktflow_plugins::default_engine());
    let mut group = c.benchmark_group("scale_lru_cap_churn");
    group.sample_size(10);
    for &cap in &[10_000usize, 100_000] {
        // Enough distinct flows to keep the cap saturated and churning.
        let corpus_spec = spec(cap * 2, 1);
        let corpus = dissect_corpus(&engine, &corpus_spec);
        group.throughput(criterion::Throughput::Elements(corpus.len() as u64));
        group.bench_function(format!("cap_{cap}"), |b| {
            b.iter(|| {
                let mut agg = Aggregator::new(
                    &engine,
                    AggregatorConfig {
                        eviction: EvictionPolicy::Live {
                            idle_timeout: Duration::from_secs(3600),
                            close_linger: Duration::from_secs(3600),
                            max_streams: cap,
                        },
                        ..raw_config()
                    },
                );
                for pkt in &corpus {
                    agg.ingest(pkt);
                }
                black_box(agg.len());
            })
        });
    }
    group.finish();
}

/// D16 (12.3): ingest throughput and live-node count on the fan-out
/// corpus with the default threshold vs. `--no-condense` — what
/// condensation buys on the shape it exists for.
fn bench_condensation(c: &mut Criterion) {
    let engine = Arc::new(pktflow_plugins::default_engine());
    let corpus_spec = spec(65_536, 3);
    let corpus = dissect_corpus(&engine, &corpus_spec);

    let mut group = c.benchmark_group("scale_condensation");
    group.sample_size(10);
    group.throughput(criterion::Throughput::Elements(corpus.len() as u64));
    for (name, threshold) in [
        ("default_on", AggregatorConfig::default().condense_threshold),
        ("off", 0),
    ] {
        group.bench_function(name, |b| {
            b.iter(|| {
                let mut agg = Aggregator::new(
                    &engine,
                    AggregatorConfig {
                        condense_threshold: threshold,
                        ..AggregatorConfig::default()
                    },
                );
                for pkt in &corpus {
                    agg.ingest(pkt);
                }
                black_box(agg.len());
            })
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_snapshot_cow,
    bench_ingest_with_publish,
    bench_lru_cap_churn,
    bench_condensation
);
criterion_main!(benches);
