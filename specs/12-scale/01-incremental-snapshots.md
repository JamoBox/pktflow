# 12.1 — Incremental snapshots & adaptive publish

> Task: [12 Large-capture scale](README.md) · Depends on: 05.7 · PRD: §7 "Performance",
> §7 "Determinism" · D5, D17.1, D17.2

## Goal
Publishing a snapshot costs deep work proportional to the streams *touched since the last
publish*, never a full clone of the live set — and publication can never dominate the
ingest thread, no matter how large the capture grows.

## Specification

**Structural sharing (copy-on-write).** `AggregatorSnapshot::streams` becomes
`Vec<Arc<Stream>>`, and the store itself holds each stream behind the same handle —
mutation goes through `Arc::make_mut`, so the deep copy is paid lazily, by the first
mutation of a record some snapshot still shares, never in bulk at publish time:

```rust
struct Slot {
    generation: u32,
    stream: Option<Arc<Stream>>,       // COW: get_mut() = Arc::make_mut
}

pub struct AggregatorSnapshot {
    pub streams: Vec<Arc<Stream>>,     // created_seq order, as before
    /* roots, summary, clock, unknowns unchanged */
}
```

`snapshot()` collects `Arc` clones — O(live) pointer copies, zero deep clones, still
`&self`. Total deep-copy work between two publishes is exactly the set of records touched
in between, amortized into the ingest path (an untouched record has one owner and mutates
in place; the atomic ownership check is the only per-touch overhead). Nothing is stored
twice: there is no publish-side cache, so steady-state memory is aggregator state plus
only the *touched* records' old copies, held solely by the snapshots that still reference
them. Eviction drops the store's handle; the record frees when the last snapshot lets go.

> Shape note: an earlier draft of this spec sketched explicit per-slot `dirty` flags plus
> a `published` `Arc` cache. Implementation surfaced the `make_mut` form as strictly
> better (no double-store, no flag maintenance, `snapshot()` stays `&self`); the spec was
> updated in the same PR per Article II.

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

- [x] Between two snapshots, only the records touched in between are re-copied: untouched
      records are pointer-identical (`Arc::ptr_eq`) across consecutive snapshots, touched
      ones are not and the older snapshot keeps the pre-touch value — proven by a unit
      test. *(Criterion reworded from "snapshot deep-clones exactly k records" when the
      COW shape moved the k copies from publish time into the mutation path — the shared/
      copied split is the observable contract; where the copy happens is not.)*
- [x] Snapshots remain value-equal to a reference deep copy (seeded randomized ingest
      sequence test), and two identical runs publish identical final snapshots (existing
      05.7 determinism test, still passing).
- [x] `summary()` performs no O(live-streams) scan (per-protocol live/byte counters are
      maintained incrementally and asserted against a recomputed ground truth across
      evictions in tests).
- [ ] On the 12.7 fixture, hub-pipeline read time is within 10 % of `--batch`, and
      `snapshot()` p99 measured by the 12.7 bench meets its budget. *(Half proven:
      `snapshot()` republish measures 14.1 ms at 100k live streams vs. the 229.8 ms
      pre-task deep copy — 16×. The read-time gate stays open pre-condensation: the
      fan-out fixture's round-major interleaving touches every flow between any two
      publishes, so COW degrades to ~one clone per packet on this shape (+59 % measured,
      `benches/README.md`) — the very case D16/12.3 removes. Re-measure when 12.3
      lands.)*
- [x] Eviction under `EvictionPolicy::Live` releases the store's handle: once the last
      snapshot holding an evicted record drops, the record frees (weak-handle unit test).
      *(The RSS-plateau measurement lives with 12.7's memory-ceiling tests.)*
