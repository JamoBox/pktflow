//! 10's Definition of Done: the default `streams`/`packets` paths pay
//! zero cost for `diagnose_unknown`'s existence when it's left off (the
//! default everywhere except `pktflow unknown`, 10.3). `off` here uses
//! the exact default `ParseOpts`; `on` is the same corpus with the flag
//! flipped, included only as a point of comparison — it is expected to
//! be slower (it runs a probing pass on every unknown stop), which is
//! the point: `off` must not carry any of that cost.

use std::hint::black_box;
use std::sync::OnceLock;
use std::time::SystemTime;

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use pktflow_core::{Engine, LinkType, PacketMeta, ParseOpts};
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
    let mut group = c.benchmark_group("unknown_diagnostics");
    group.throughput(Throughput::Elements(CORPUS_SIZE as u64));
    for (diagnose_unknown, label) in [(false, "off_default"), (true, "on_unknown_subcommand")] {
        let opts = ParseOpts {
            diagnose_unknown,
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
