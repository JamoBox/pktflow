# 12.2 — Stream memory diet & O(log n) LRU

> Task: [12 Large-capture scale](README.md) · Depends on: 05.2, 05.4, 05.6 · PRD: §7
> "Stateful memory discipline" · D2, D4

## Goal
Per-stream resident cost drops enough that a million small flows is a routine working set,
and the D2 hard cap stops costing O(live streams) per eviction.

## Specification

**Series clamp.** `AggregatorConfig` gains a cap *clamp* applied to every `Series` rollup,
including plugin-declared explicit caps (today TCP's `Series { cap: 1024 }` bypasses the
default entirely — `pktflow-plugins/src/tcp.rs:64`):

```rust
pub struct AggregatorConfig {
    /* … */
    pub rollup_series_default_cap: usize,      // unchanged (D4 default)
    pub rollup_series_max_cap: Option<usize>,  // clamp over declared caps; None = unclamped
}
```

Defaults: batch CLI runs stay unclamped (today's behavior); the hub pipelines behind `tui`
and `serve` clamp to 128 — an interactive browser does not need a thousand retained flag
transitions per flow, and a truncated ring already reports `truncated: true` (D4 honesty).
CLI override: `--series-cap N` (0 = unclamped) on the shared args, all modes.

**SeriesPoint shrink.** `SeriesPoint` stores its timestamp as a compact offset from the
stream's `first_seen` (`u32` milliseconds, saturating, plus the direction byte) instead of
a full `SystemTime`; the public accessor still yields `SystemTime` so formatting and JSON
are unchanged. Streams outliving the `u32` range keep correctness by saturating with an
explicit flag — a ~50-day single stream is a curiosity, not a target.

**Key deduplication.** The lookup index currently stores a second copy of every `FlowKey`
in its `(parent, protocol, FlowKey)` tuple (`store.rs:229`). The index switches to a
raw-entry / hashed-key scheme so the stream's own key is the only full copy retained
per stream (shape free; behavior identical, collision-safe via full-key compare on hit).

**O(log n) LRU.** `enforce_max_streams` replaces its full scan
(`store.rs:507-522`) with the lazy-heap pattern 05.6 already uses for expiry: a second
min-heap keyed by `(last_seen, created_seq, index, generation)`, entries re-pushed when
stale (a popped stream whose actual `last_seen` is newer than the entry's gets re-armed),
leaves-only as before. Amortized O(log n) per eviction, O(evicted + stale pops) per sweep,
identical eviction order to the scan (same key, same tiebreak — asserted by test).

**Out of scope.** Interning `key_fields` values across streams (superseded in practice by
12.3, which stops the duplicate-heavy population from existing at all), and any change to
what rollup kinds retain (D4 stands).

## Acceptance criteria

- [x] Clamped series honor `min(declared cap, clamp)` and set `truncated` on overflow;
      `--series-cap` reaches all modes; batch defaults are byte-identical to today's JSON
      output (goldens unchanged).
- [x] `SeriesPoint` is ≤ 16 bytes + value payload; accessors round-trip timestamps
      exactly within range and clamp at the ±292-year horizon (unit tests). *(Reworded
      from "saturate visibly": the signed 64-bit-nanosecond offset pushed the saturation
      horizon from ~50 days to ±292 years — unreachable for real captures, so a visible
      marker would be dead code.)*
- [x] The index holds no second `FlowKey` copy; collision safety is covered by a test
      that forces two different keys into one digest bucket and proves the full-key probe
      keeps them apart. *(Reworded from "equal hashes": preimages colliding under the
      deterministic SipHash digest aren't constructible on demand; forcing the bucket
      exercises the identical code path.)*
- [x] LRU eviction order under the heap is identical to the reference scan's pick on
      randomized workloads (oracle test: every `LruEvicted` stream was the
      `(last_seen, created_seq)` minimum among live leaves at its eviction), plus targeted
      tests for stale-entry re-push and becoming-a-leaf re-arm.
- [ ] The 12.7 live-cap bench shows per-eviction cost is no longer proportional to
      live-stream count. *(Split out of the previous criterion — it needs 12.7's bench.)*
- [ ] On the 12.7 fixture, hub-pipeline peak RSS improves by a measured, documented factor
      vs. the pre-task baseline (recorded in `benches/README.md`).
