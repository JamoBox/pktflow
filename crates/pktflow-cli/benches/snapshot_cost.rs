//! 09.4 bench 5: `snapshot()` latency at 10k/100k live streams (the
//! 05.7 accepted cost, now with a number attached; informs the v2
//! sharding decision).

use std::hint::black_box;
use std::sync::Arc;

use criterion::{criterion_group, criterion_main, Criterion};
use pktflow_core::{Depth, ParseOpts};
use pktflow_flows::{Aggregator, AggregatorConfig};
use pktflow_testkit::{pool_ipv4, pool_mac, PacketBuilder};

/// `live_streams` distinct eth/ipv4/udp chains, no eviction — the
/// simplest shape that reaches the target live-stream count.
fn build_aggregator(live_streams: u32) -> Aggregator {
    let engine = Arc::new(pktflow_plugins::default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());
    let opts = ParseOpts {
        depth: Depth::Keys,
        ..ParseOpts::default()
    };
    for i in 0..live_streams {
        let a = pool_ipv4(10, i);
        let b = pool_ipv4(172, i);
        let (meta, bytes) = PacketBuilder::at_secs(u64::from(i))
            .eth(&pool_mac(1, i), &pool_mac(2, i))
            .ipv4(&a, &b)
            .udp(51000, 51001)
            .payload(32)
            .build();
        let dissected = engine.dissect(&bytes, meta, opts);
        agg.ingest(&dissected);
    }
    agg
}

fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("snapshot_cost");
    for &n in &[10_000u32, 100_000u32] {
        let agg = build_aggregator(n);
        group.bench_function(format!("{n}_streams"), |b| {
            b.iter(|| black_box(agg.snapshot()));
        });
    }
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
