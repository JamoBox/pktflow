# 05.6 — Memory bounds & eviction

> Task: [05 Aggregator](README.md) · Depends on: 05.2, 05.5 · PRD: §7 "stateful memory discipline" · D2

## Goal
Bounded, predictable stream storage for long/live captures: the D2 hybrid policy (protocol
close + linger, idle timeout, LRU cap), with an emission sink so nothing is silently lost.

## Specification

```rust
pub struct AggregatorConfig {
    pub eviction: EvictionPolicy,
    pub sink: Option<Box<dyn FnMut(EvictedStream) + Send>>,
    pub rollup_series_default_cap: usize,   // D4 override point
}
pub enum EvictionPolicy {
    None,                                    // offline default (D2): flush at end only
    Live { idle_timeout: Duration,           // default 300 s
           close_linger: Duration,           // default 15 s after closed-state entry
           max_streams: usize },             // default 1_000_000
}
pub enum CloseReason { ProtocolClose, IdleTimeout, LruEvicted, CaptureEnd }
```

Mechanics:

- **Clock:** eviction time is **packet time** (`meta.timestamp`), not wall time — offline
  replay of a week-long capture must behave identically to having been live (determinism,
  PRD §7). The aggregator's clock advances monotonically with max(seen timestamps).
- **Sweep:** timeout checks run on ingest, amortized — an intrusive expiry wheel or a
  simple min-heap of `(deadline, StreamId, generation)`; chosen structure must make sweep
  O(evicted), not O(streams). No background thread (single-writer, D5).
- **Hierarchy constraint (D2):** never evict a stream with live children. Idle/LRU eviction
  targets leaves; a parent becomes eligible when its last child goes. `CaptureEnd`/
  `finish()` flushes bottom-up.
- **Aggregate survival:** global counters (total streams ever, per-protocol counts, packets,
  bytes) live outside stream records; eviction can't distort the end-of-run summary (FR-27).
- **Index removal:** evicted `(parent, protocol, key)` leaves the index; recurrence of the
  same key later creates a *new* stream (new `StreamId` generation) — correct semantics for
  "the conversation resumed after 10 minutes of silence".
- `finish(&mut self)` — explicit end-of-capture: closes all remaining streams with
  `CaptureEnd` through the sink, leaves the store queryable (closed streams retained in
  offline mode for the final report; live mode drops them post-sink).

## Acceptance criteria
- [ ] All four `CloseReason` paths reachable in tests with synthetic timestamped packets
      (no sleeps — packet-time clock makes eviction tests instant).
- [ ] Leaf-first constraint verified: parent with one live child survives idle timeout;
      falls after the child does.
- [ ] `max_streams` cap: inserting cap+k streams evicts exactly k least-recently-updated
      leaves, sink observes each with `LruEvicted`.
- [ ] Post-eviction key recurrence creates a fresh stream; stale `StreamId` handles fail
      generation checks (no ABA).
