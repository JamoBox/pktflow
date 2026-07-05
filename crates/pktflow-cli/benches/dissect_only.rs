//! 09.4 bench 1: `Engine::dissect` alone, at each `Depth`, no
//! aggregation — the baseline everything else is measured against.

use std::hint::black_box;
use std::sync::OnceLock;
use std::time::SystemTime;

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use pktflow_core::{Depth, Engine, LinkType, PacketMeta, ParseOpts};
use pktflow_testkit::mixed_capture;

const CORPUS_SIZE: usize = 100_000;

fn engine() -> &'static Engine {
    static ENGINE: OnceLock<Engine> = OnceLock::new();
    ENGINE.get_or_init(pktflow_plugins::default_engine)
}

fn corpus() -> &'static Vec<(SystemTime, Vec<u8>)> {
    static CORPUS: OnceLock<Vec<(SystemTime, Vec<u8>)>> = OnceLock::new();
    CORPUS.get_or_init(|| mixed_capture(CORPUS_SIZE))
}

fn bench(c: &mut Criterion) {
    let eng = engine();
    let packets = corpus();
    let mut group = c.benchmark_group("dissect_only");
    group.throughput(Throughput::Elements(CORPUS_SIZE as u64));
    for (depth, label) in [
        (Depth::None, "none"),
        (Depth::Keys, "keys"),
        (Depth::Structural, "structural"),
        (Depth::Full, "full"),
    ] {
        let opts = ParseOpts {
            depth,
            ..ParseOpts::default()
        };
        group.bench_function(label, |b| {
            b.iter(|| {
                for (ts, bytes) in packets {
                    let meta = PacketMeta {
                        timestamp: *ts,
                        caplen: bytes.len(),
                        origlen: bytes.len(),
                        link_type: LinkType::ETHERNET,
                    };
                    black_box(eng.dissect(black_box(bytes), meta, opts));
                }
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
