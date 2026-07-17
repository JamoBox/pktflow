# 12.7 — Scale fixtures & benchmarks

> Task: [12 Large-capture scale](README.md) · Depends on: 09.1, 09.4 · PRD: §8 success
> metrics, §7 · D16, D17

## Goal
The task's claims are measured, not asserted: a reproducible high-cardinality fixture
generator, benches that gate the D17 budgets, and recorded baselines so regressions are
visible per the existing 09.4 discipline.

## Specification

**Fixture generator** (pktflow-testkit): a deterministic (seeded) synthetic capture builder
for the fan-out shape this task targets:

```rust
pub struct FanOutSpec {
    pub anchors: usize,            // distinct (server addr, port) anchors
    pub flows_per_anchor: usize,   // ephemeral peers per anchor
    pub packets_per_flow: usize,   // small (3–10): the pathological case
    pub payload_len: usize,
    pub seed: u64,
}
// Streaming: multi-GB shapes never materialize in memory.
pub fn fan_out_packets(spec: &FanOutSpec) -> impl Iterator<Item = (SystemTime, Vec<u8>)>;
// Materialized for small specs: `.packets()` in-process, `.write_pcap()` to disk.
pub fn fan_out_capture(spec: &FanOutSpec) -> CaptureBuilder;
```

The **reference fixture** used by the task's Definition of done: ≥ 1 M total flows,
≥ 10 M packets, mixed TCP/UDP over a handful of anchors, generated on demand (never
committed — multi-GB artifacts stay out of the repo; the spec pins the `FanOutSpec` so the
bytes are reproducible).

**Benches** (criterion, joining the 09.4 set in `benches/`):

- `snapshot_cost`: `snapshot()` latency at 10 k / 100 k / 1 M live streams, cold and with
  1 % dirty — gates 12.1 (p99 budget recorded in `benches/README.md`).
- `ingest_with_publish`: hub-pipeline read of the reference fixture vs. `--batch` — gates
  the < 10 % publication-overhead DoD.
- `window_query`: `SnapshotIndex::window()` and `timeline()` latency at fixture scale,
  with and without a query — gates 12.4's < 100 ms.
- `condensation`: live node count and ingest throughput on the fan-out fixture with the
  D16 default vs. `--no-condense`.

**Memory ceilings**: `#[ignore]`d integration tests (run by the Docker/scheduled tier, like
the live-capture tests) reading the reference fixture through the hub pipeline and
asserting peak RSS (via `/proc/self/status` on Linux) against the recorded budget, batch
vs. hub, condensed vs. not.

**Baselines**: `benches/README.md` gains a task-12 section recording the pre-task numbers
(captured before 12.1 lands) and each sub-task's measured effect, so the DoD's "< 2× RSS,
< 10 % overhead" claims trace to committed measurements.

## Acceptance criteria

- [x] The fan-out generator is deterministic (same spec + seed ⇒ identical bytes, a
      different seed differs) and its output aggregates to the exactly-predicted stream
      shape through the real dissect→aggregate pipeline (unit + integration tests).
- [x] All four benches run under `just bench` and are wired into the scheduled bench
      workflow (`snapshot_cost`+`ingest_with_publish` as the `scale` bench, plus the
      LRU-churn, `condensation`, and `window_query` groups); budgets and baselines are
      recorded in `benches/README.md`.
- [x] The RSS ceiling test runs in the scheduled bench workflow (one process per
      measurement — VmHWM is process-wide) and fails on a 25 % regression over the
      recorded budget (1,625,000 kB; measured 1,299,492 kB, pre-task baseline
      2,606,092 kB).
- [ ] Every task-12 DoD number (README) is traceable to one of these benches or tests by
      name.
