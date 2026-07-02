# 05.7 — Query API

> Task: [05 Aggregator](README.md) · Depends on: 05.2–05.6 · PRD: FR-7, FR-24/25 (consumer) · D5, D10

## Goal
Read access for the CLI and library callers: list conversations at a layer, fetch one
stream's full picture, traverse the hierarchy, and snapshot for cross-thread consumers.

## Specification

```rust
impl Aggregator {
    pub fn stream(&self, id: StreamId) -> Option<&Stream>;
    pub fn roots(&self) -> impl Iterator<Item = &Stream>;
    pub fn children(&self, id: StreamId) -> impl Iterator<Item = &Stream>;

    /// All stream nodes of one protocol (FR-24's data source), deterministic order.
    pub fn at_layer(&self, protocol: &str) -> Vec<&Stream>;
    /// D10 merged view: same-key nodes folded across parents, stats summed lazily.
    pub fn at_layer_merged(&self, protocol: &str) -> Vec<MergedStreamView>;

    pub fn summary(&self) -> AggregateSummary;   // global counters (FR-27): packets, bytes,
                                                 // streams ever/live per protocol, stop-class counts
    pub fn snapshot(&self) -> AggregatorSnapshot; // deep, immutable copy for cross-thread reads
}
```

- **Ordering is explicit everywhere:** `at_layer` sorts by `created_seq`; `children` is
  creation order; nothing exposes hash-map iteration order (PRD §7 determinism — this is
  where it is won or lost).
- **`MergedStreamView`** answers "one row per IP pair" when the same key exists under
  several parents (D10): summed `DirStats`, min/max first/last-seen, `nodes: Vec<StreamId>`
  back-references. Direction folding across nodes uses key-canonical A/B (identical by
  construction, since same key ⇒ same canonical endpoints). Rollups are **not** merged in
  v1 (sets could, series can't meaningfully) — the view exposes per-node rollups through the
  back-references; drill-down (08.3) targets nodes, not merged rows.
- **Snapshots for live mode (D5):** the aggregation thread owns `Aggregator`; UI threads
  request `snapshot()` via the command channel at their refresh cadence. Snapshot cost is
  accepted for v1 (bounded by `max_streams`); measured in 09.4; sharded/incremental
  snapshots are the designated v2 lever.
- Filters (by endpoint value, time window, state) are **out of scope for the store** —
  callers filter the returned slices; keeps the API minimal until real usage shows hot
  filter paths.

## Acceptance criteria
- [ ] All methods implemented; determinism test: two identical runs produce identical
      `at_layer` orderings and identical serialized snapshots.
- [ ] Merged-view test over the 05.3 "same IP pair, two MAC parents" fixture: one merged
      row, two node back-references, summed stats.
- [ ] `snapshot()` is deep: mutating the aggregator afterward does not alter the snapshot
      (asserted), and the snapshot is `Send + Sync`.
