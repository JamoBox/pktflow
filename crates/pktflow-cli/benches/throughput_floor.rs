//! 09.4 bench 3: end-to-end packets/sec and MB/s at `Keys` depth +
//! aggregation — the acceptance-floor number (>= 500k packets/sec on a
//! developer-class machine; see `benches/README.md` for the recorded
//! figure and machine spec). Criterion tracks this relatively (the
//! scheduled CI job's 15% regression gate); the absolute floor is
//! human-reviewed since it's necessarily per-machine.

use std::hint::black_box;
use std::sync::{Arc, OnceLock};
use std::time::SystemTime;

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use pktflow_core::{Depth, Engine, LinkType, PacketMeta, ParseOpts};
use pktflow_flows::{Aggregator, AggregatorConfig};
use pktflow_testkit::mixed_capture;

const CORPUS_SIZE: usize = 200_000;

fn engine() -> &'static Arc<Engine> {
    static ENGINE: OnceLock<Arc<Engine>> = OnceLock::new();
    ENGINE.get_or_init(|| Arc::new(pktflow_plugins::default_engine()))
}

fn corpus() -> &'static Vec<(SystemTime, Vec<u8>)> {
    static CORPUS: OnceLock<Vec<(SystemTime, Vec<u8>)>> = OnceLock::new();
    CORPUS.get_or_init(|| mixed_capture(CORPUS_SIZE))
}

fn bench(c: &mut Criterion) {
    let packets = corpus();
    let total_bytes: u64 = packets.iter().map(|(_, b)| b.len() as u64).sum();

    let mut group = c.benchmark_group("throughput_floor");
    group.throughput(Throughput::Elements(CORPUS_SIZE as u64));
    group.bench_function("packets_per_sec", |b| {
        b.iter(|| {
            let engine = engine();
            let mut agg = Aggregator::new(engine, AggregatorConfig::default());
            let opts = ParseOpts {
                depth: Depth::Keys,
                ..ParseOpts::default()
            };
            for (ts, bytes) in packets {
                let meta = PacketMeta {
                    timestamp: *ts,
                    caplen: bytes.len(),
                    origlen: bytes.len(),
                    link_type: LinkType::ETHERNET,
                };
                let dissected = engine.dissect(bytes, meta, opts);
                agg.ingest(&dissected);
            }
            black_box(agg.snapshot());
        });
    });
    group.throughput(Throughput::Bytes(total_bytes));
    group.bench_function("mb_per_sec", |b| {
        b.iter(|| {
            let engine = engine();
            let mut agg = Aggregator::new(engine, AggregatorConfig::default());
            let opts = ParseOpts {
                depth: Depth::Keys,
                ..ParseOpts::default()
            };
            for (ts, bytes) in packets {
                let meta = PacketMeta {
                    timestamp: *ts,
                    caplen: bytes.len(),
                    origlen: bytes.len(),
                    link_type: LinkType::ETHERNET,
                };
                let dissected = engine.dissect(bytes, meta, opts);
                agg.ingest(&dissected);
            }
            black_box(agg.snapshot());
        });
    });
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
