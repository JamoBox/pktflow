//! 09.4 bench 2: the full dissect+aggregate pipeline at `Keys` vs
//! `Full` depth. The §8 metric: `Keys` must beat `Full` *materially*
//! (target >= 1.5x packets/sec) since that's the whole reason a caller
//! would ever ask for less than everything.

use std::hint::black_box;
use std::sync::{Arc, OnceLock};
use std::time::SystemTime;

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use pktflow_core::{Depth, Engine, LinkType, PacketMeta, ParseOpts};
use pktflow_flows::{Aggregator, AggregatorConfig};
use pktflow_testkit::mixed_capture;

const CORPUS_SIZE: usize = 100_000;

fn engine() -> &'static Arc<Engine> {
    static ENGINE: OnceLock<Arc<Engine>> = OnceLock::new();
    ENGINE.get_or_init(|| Arc::new(pktflow_plugins::default_engine()))
}

fn corpus() -> &'static Vec<(SystemTime, Vec<u8>)> {
    static CORPUS: OnceLock<Vec<(SystemTime, Vec<u8>)>> = OnceLock::new();
    CORPUS.get_or_init(|| mixed_capture(CORPUS_SIZE))
}

fn run_pipeline(depth: Depth) {
    let engine = engine();
    let mut agg = Aggregator::new(engine, AggregatorConfig::default());
    let opts = ParseOpts {
        depth,
        ..ParseOpts::default()
    };
    for (ts, bytes) in corpus() {
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
}

fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("dissect_aggregate");
    group.throughput(Throughput::Elements(CORPUS_SIZE as u64));
    group.bench_function("keys", |b| b.iter(|| run_pipeline(Depth::Keys)));
    group.bench_function("full", |b| b.iter(|| run_pipeline(Depth::Full)));
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
