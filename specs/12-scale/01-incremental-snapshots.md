# 12.1 — Incremental snapshots & adaptive publish

> Task: [12 Large-capture scale](README.md) · Depends on: 05.7 · PRD: §7 "Performance",
> §7 "Determinism" · D5, D17.1, D17.2

## Goal
Publishing a snapshot costs deep work proportional to the streams *touched since the last
publish*, never a full clone of the live set — and publication can never dominate the
ingest thread, no matter how large the capture grows.

## Specification

**Structural sharing.** `AggregatorSnapshot::streams` becomes `Vec<Arc<Stream>>`. The
aggregator tracks, per slot, whether the stream mutated since the last publish, and keeps
the `Arc` it published last time:

```rust
struct Slot {
    generation: u32,
    stream: Option<Stream>,
    dirty: bool,                       // mutated since last snapshot()
    published: Option<Arc<Stream>>,    // what the previous snapshot carries
}

pub struct AggregatorSnapshot {
    pub streams: Vec<Arc<Stream>>,     // created_seq order, as before
    /* roots, summary, clock, unknowns unchanged */
}
```

`snapshot()` walks the slots once: a clean slot contributes its existing `Arc` (pointer
copy); a dirty slot clones the stream into a fresh `Arc`, caches it, and clears the flag.
Every mutation path (`ingest` stat updates, lifecycle transitions, rollup applies, child
attach, close/evict) sets `dirty`. Cost: O(live) pointer copies + O(dirty) clones per
publish. Eviction drops the slot's cached `Arc` with the slot.

**Incremental summary.** `summary()` may not scan streams at publish time. Per-protocol
*live* counts become maintained counters (increment on create, decrement on evict —
alongside the existing `created_per_protocol`), making `summary()` O(protocols). The web
layer's per-protocol byte totals move behind the same counters (bytes summed
incrementally), removing `api.rs`'s per-request rescan.

**Adaptive cadence.** The hub pipeline keeps the 250 ms floor but self-throttles: a publish
whose `snapshot()` call took `t` schedules the next no sooner than
`max(PUBLISH_INTERVAL, ADAPTIVE_FACTOR * t)` (factor ≈ 8). The first snapshot still ships
immediately; `finish()` always publishes a final complete snapshot. Staleness is visible,
bounded, and preferred over ingest stalls (D17.2).

**Determinism.** Sharing is an optimization of *copying*, not of content: a published
snapshot is value-equal to what a full deep copy would have produced (PRD §7). `Stream`
stays `Clone + PartialEq` so 09-suite equality assertions are unaffected.

**Out of scope.** Persistent/immutable tree structures for `roots`/`children`, and
sharding the aggregator (D5's door stays open, unopened).

## Acceptance criteria

- [ ] A snapshot taken after N ingests that touched only k streams deep-clones exactly k
      stream records; untouched records are pointer-identical (`Arc::ptr_eq`) with the
      previous snapshot's, proven by a unit test.
- [ ] Snapshots remain value-equal to a reference deep copy (property test over randomized
      ingest sequences), and two identical runs publish identical final snapshots.
- [ ] `summary()` performs no O(live-streams) scan (per-protocol live/byte counters are
      maintained incrementally and asserted against a recomputed ground truth in tests).
- [ ] On the 12.7 fixture, hub-pipeline read time is within 10 % of `--batch`, and
      `snapshot()` p99 measured by the 12.7 bench meets its budget.
- [ ] Eviction under `EvictionPolicy::Live` releases the cached `Arc` (no snapshot-cache
      leak: RSS plateaus on the 09.4 live-eviction bench).
