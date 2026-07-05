# 09.4 — Benchmarks

> Task: [09 Validation](README.md) · Depends on: 09.2 · PRD: §7 performance, §8 "depth pays off"

## Goal
Measurements for the two quantitative promises — live-capture-viable throughput and the
extraction-depth payoff — plus memory verification for the eviction policy, and the profile
data that earlier specs deferred tuning decisions to.

## Specification

Criterion benches in `benches/` (offline only; no NIC in the loop), over a generated
1M-packet mixed capture (from the 09.2 builder: 70% TCP, 20% UDP+DNS, 5% tunnels, 5% noise):

1. **`dissect_only`** — packets/sec through `Engine::dissect` at each `Depth`, no
   aggregation. Baseline for everything.
2. **`dissect_aggregate`** — full pipeline at `Keys` vs `Full`. **The §8 metric:** `Keys`
   must beat `Full` *materially* — target ≥ 1.5× packets/sec, recorded either way; if the
   gap is smaller, the finding goes in the bench README (the metric asks whether depth pays,
   not for a predetermined answer — but < 1.2× should trigger a look at where `Full` cost
   actually lives).
3. **`throughput_floor`** — end-to-end packets/sec and MB/s at `Keys` + aggregation.
   Acceptance floor: ≥ 500k packets/sec on a developer-class machine (order-of-magnitude
   guard against regressions, tracked relatively in CI — absolute numbers are per-machine).
4. **`aggregator_memory`** — peak RSS-delta ingesting `lru_pressure` at `max_streams`
   100k: memory plateaus (bounded, D2) and per-stream cost is recorded (target
   ≤ ~1 KB/stream baseline without series rollups).
5. **`snapshot_cost`** — `snapshot()` latency at 10k/100k live streams (the 05.7 accepted
   cost, now with a number attached; informs the v2 sharding decision).

Deferred-tuning callbacks: results feed `PRIOR_BOOST`/`MIN_CONFIDENCE` review (03.3) and the
04.1 clone-vs-borrow revisit. Each of those specs cites this bench by name; the bench README
records the verdicts.

CI: benches compiled (`cargo bench --no-run`) per PR; a scheduled job runs them and posts
relative deltas; regressions > 15% flag red.

## Acceptance criteria
- [x] All five benches implemented and runnable via `just bench`.
- [x] Depth-payoff and throughput-floor results recorded in `benches/README.md` with
      machine specs; §8 metric conclusion stated explicitly.
- [x] Memory plateau demonstrated (graph or table in the README).
- [x] Scheduled CI bench job wired with the 15% regression gate.
