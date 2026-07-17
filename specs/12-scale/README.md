# Task 12 — Large-capture scale

**Goal:** a multi-gigabyte, high-cardinality capture (millions of packets, hundreds of
thousands to millions of streams — e.g. one busy server pair fanning out across ephemeral
ports) is browsable in the TUI and web UI with cost proportional to *what changed and what
is on screen*, not to capture size. Today the GUI path degrades on exactly these captures;
this task removes each measured bottleneck without weakening determinism (PRD §7), the D5
single-writer model, or D2's eviction semantics.

**Depends on:** 05 (aggregator), 07 (capture I/O), 08 (CLI/front-ends), 09 (bench harness).
**PRD:** §7 "Stateful memory discipline", §7 "Performance", §5 use cases · D2, D4, D5,
**D16**, **D17** (both introduced by this task).

## Problem statement (measured bottlenecks)

Offline replay uses `EvictionPolicy::None` (D2): every stream stays live until capture end.
With a high-cardinality capture that interacts badly with five compounding costs:

1. **Snapshot deep copy on the hot path.** The hub pipeline publishes `agg.snapshot()`
   every 250 ms while reading (`pktflow-cli/src/run.rs:345,379-382`), and `snapshot()`
   clones every live stream — `FlowKey`, `key_fields`, `children`, `RollupSet` and all
   (`pktflow-flows/src/store.rs:725-735`). On an offline read the live set only grows, so
   total publish work is quadratic-ish in final stream count, and peak memory is a multiple
   of aggregator state (aggregator + snapshot under construction + published `Arc` + any
   reader-held previous snapshot). `summary()` adds a full O(streams) scan per publish
   (`store.rs:689-721`).
2. **The whole forest ships to the browser as one JSON document.** `/api/snapshot`
   serializes every stream record into a single `serde_json::Value` tree, then a string
   (`pktflow-web/src/api.rs:131-159`); the SPA refetches that document on every generation
   change (`assets/index.html` `refetch()`, driven by the 500 ms SSE tick), rebuilds
   `byId`/`kids` maps over all streams, and re-walks + re-sorts the full forest per render
   (`visibleRows()`), even though it only ever shows `MAX_TREE_ROWS = 2000` DOM rows. At
   hundreds of thousands of streams the JSON body reaches hundreds of MB and the tab dies
   in `JSON.parse` long before rendering matters.
3. **Per-stream state is heavier than the flows are.** Ephemeral-port fan-out means
   millions of nearly identical, short-lived flows, each carrying a full `Stream` node:
   `key_fields` `FieldMap`, an index entry duplicating the `FlowKey`, and rollup state — for
   TCP a `Series { cap: 1024 }` of `SeriesPoint`s (`pktflow-plugins/src/tcp.rs:57-64`), so
   retained series points grow with total TCP packets across a big capture.
4. **Per-request O(streams) work in the API layer.** `by_id` maps are rebuilt per request
   (`api.rs:133,186,203`), search scans all streams and returns full id lists, and the
   summary's per-protocol byte totals rescan every stream per snapshot fetch
   (`api.rs:54-60`).
5. **Uploads buffer the whole file in RAM.** `POST /api/upload` reads the body into
   `Bytes` with a 512 MB cap (`pktflow-web/src/lib.rs:45,200-233`) — a several-GB pcap
   cannot even reach the pipeline, and a large permitted one transiently doubles in memory.

Live mode has one adjacent defect worth fixing in the same pass: the D2 hard cap evicts by
scanning all live streams per eviction (`store.rs:507-522`, O(streams) each), which
degrades exactly when the cap is doing its job.

## Sub-tasks

- [x] [12.1 Incremental snapshots & adaptive publish](01-incremental-snapshots.md) — D17.1/.2 (PRD §7)
- [x] [12.2 Stream memory diet & O(log n) LRU](02-stream-memory-diet.md) — per-stream cost, cap mechanics (PRD §7)
- [x] [12.3 High-cardinality condensation](03-condensation.md) — D16 (PRD §7, §5)
- [ ] [12.4 Snapshot index & windowed view API](04-windowed-view-api.md) — D17.3/.4 (FR-7)
- [ ] [12.5 Web UI at scale](05-scalable-web-ui.md) — virtualized tree, canvas timeline, progress (§5)
- [x] [12.6 Streaming uploads](06-streaming-uploads.md) — multi-GB `POST /api/upload` (§5)
- [ ] [12.7 Scale fixtures & benchmarks](07-scale-benchmarks.md) — high-cardinality generator, regression gates (§8)

Recommended order: 12.7's fixture generator first (everything else is measured against it),
then 12.1 + 12.2 (pure back-end wins, no interface change), 12.3, then 12.4 → 12.5, with
12.6 independent after 12.4.

## Definition of done

On the 12.7 reference fixture (≥ 1 M flows, ≥ 10 M packets, ephemeral-port fan-out shape),
with default settings:

1. `pktflow serve -r FIXTURE` and `pktflow tui -r FIXTURE` stay responsive **while
   reading** and after: every API interaction answers in < 100 ms with a < 1 MB body; a TUI
   keypress renders its frame in < 50 ms.
2. Publication overhead on the aggregation thread is < 10 % of the equivalent
   `--batch` run's wall time; peak RSS of the hub pipeline is < 2× the `--batch` run's.
3. Browser heap and DOM size are viewport-bounded — opening the same capture with 10× the
   streams does not grow either by 10×.
4. Determinism holds: two runs over the fixture produce identical stream trees, identical
   condensed-group tallies, and identical final snapshots (PRD §7).
5. All existing task-05/08/09 acceptance criteria still pass; small captures (< the D17.4
   threshold) render through the unchanged full-snapshot path, pixel-for-pixel equivalent
   to today.
