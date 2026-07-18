# 12.4 — Snapshot index & windowed view API

> Task: [12 Large-capture scale](README.md) · Depends on: 05.7, 12.1 · PRD: FR-7, §7
> "Performance" · D5, D8, **D17.3**, **D17.4**

## Goal
Every reader-side lens answers from per-snapshot cached indexes and returns
viewport-sized windows: no API request, SSE tick, or TUI keypress does work or transfer
proportional to total stream count (D17.3), and the full-document snapshot survives only
below a size gate (D17.4).

## Specification

**`SnapshotIndex`** (pktflow-view, shared by web and TUI): built at most once per published
snapshot, lazily per facet, memoized against the hub generation:

```rust
pub struct SnapshotIndex { /* holds Arc<AggregatorSnapshot>; facets in OnceLocks */ }
impl SnapshotIndex {
    pub fn new(snap: Arc<AggregatorSnapshot>) -> Self;
    pub fn by_id(&self, id: StreamId) -> Option<&Stream>;            // replaces per-request by_id()
    pub fn by_seq(&self, seq: u64) -> Option<&Stream>;
    pub fn order(&self, sort: SortKey) -> &[u32];                     // bytes|packets|first|duration
    pub fn window(&self, w: &WindowSpec) -> WindowResult;             // filter+sort+offset/limit
    pub fn timeline(&self, t: &TimelineSpec) -> TimelineBins;         // bounded time×lane density
}
pub struct WindowSpec {
    pub scope: Scope,               // Roots | ChildrenOf(seq) | Flat
    pub query: Option<StreamQuery>, // 05.7 language, matches-with-ancestors semantics
    pub sort: SortKey, pub descending: bool,
    pub offset: usize, pub limit: usize,   // limit server-clamped (≤ 500)
}
pub struct WindowResult { pub total: usize, pub match_total: usize, pub rows: Vec<Row> }
```

Query evaluation over the full set happens once per (generation, query) — the match/visible
bitsets are cached in the index — so paging through results is O(window).

**Timeline binning.** `TimelineSpec { bins (≤ 2048), lanes (≤ 512), query }` →
per-lane arrays of per-bin activity (flow-count + bytes), lanes being the top-N rows of the
current sort with one aggregate "everything else" lane. The response size is
O(bins × lanes) regardless of stream count.

> Shape notes (Article II): `order()` returns a shared `Arc<Vec<u32>>`; the query cache
> is a single most-recent-expression slot (UIs re-issue one expression while paging);
> timeline lanes are the top streams of the byte order with one aggregated rest lane and
> per-bin *active counts* (bytes-per-bin attribution added when a consumer needs it); and
> above the gate `/api/search` returns `match_total` with null id lists — windowed
> clients page matches through `/api/streams?q=` rather than a special first-window
> shape. `by_id()` is a per-id indexed lookup; the map-shaped `id_map()` projection
> remains for the existing render helpers' signatures.

**Web endpoints** (all responses carry `generation` so the client can detect staleness):

- `GET /api/streams?scope=roots|flat|children&of=SEQ&sort=&order=&offset=&limit=&q=` →
  `WindowResult` as D8 records.
- `GET /api/timeline?bins=&lanes=&q=` → `TimelineBins`.
- `GET /api/snapshot` — unchanged below the gate; at
  `streams_live > FULL_SNAPSHOT_MAX_STREAMS` (default 20 000) it omits `streams`/`roots`
  and sets `"windowed": true`, telling the client to drive the endpoints above.
- `GET /api/search` — answered from the cached bitsets; above the gate it returns
  `match_total` plus a first window instead of exhaustive id lists.

**TUI.** `flatten()` and the timeline pane consume the same `SnapshotIndex` (one per
received snapshot) instead of re-walking and re-sorting the forest per keypress; row
windows come from `window()` with the pane height as the limit.

**Concurrency.** Index construction happens on reader threads (web workers / TUI render
thread), never the aggregation thread; the memo is `(generation, Arc<SnapshotIndex>)`
behind the existing hub access path, built by whichever reader arrives first (D5: readers
share, writer untouched).

## Acceptance criteria

- [x] Index facets build once per generation (order/query-memo `Arc::ptr_eq` tests; the
      `WebState` memo test proves one index per generation across handler calls), and all
      `/api/*` handlers plus TUI keypress paths are free of per-request `by_id()`-style
      full-set construction.
- [x] Windowed responses are deterministic, stable across pages (pages concatenate to
      exactly the full order — tested), and clamp `limit` server-side.
- [x] `/api/timeline` response size is bounded by bins × lanes and independent of stream
      count (unit-tested; benched at 400k uncondensed streams: 32 ms for 800×64).
- [x] Below the gate, `/api/snapshot` is byte-identical to today's document (modulo the
      added `windowed: false` and `match_total` keys); above it, `streams`/`roots` are
      omitted and the windowed endpoints carry every lens. *(The SPA's windowed mode is
      12.5; until it lands the page shows an explanatory empty state above the gate.)*
- [x] Interactive-time answers, bench-gated (`scale_window_query`, 400k uncondensed
      streams — worse than the condensed 12.7 fixture): flat mid-capture page 1.2 ms,
      queried page 33 ms, timeline 32 ms — all < 100 ms with window-bounded (< 1 MB)
      bodies.
