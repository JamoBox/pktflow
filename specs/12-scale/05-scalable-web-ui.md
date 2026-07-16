# 12.5 — Web UI at scale

> Task: [12 Large-capture scale](README.md) · Depends on: 12.4 · PRD: §5 use cases, §7
> "Performance" · D17.3, D17.4

## Goal
The embedded SPA renders a million-stream capture with a viewport-bounded working set:
windowed data intake, virtualized rows, a canvas timeline, and visible progress while a
big file is still being read.

## Specification

**Two intake modes, one UI.** Below the D17.4 gate the page works exactly as today (full
snapshot, client-side sort/fold/filter — no regression for the common small capture). When
`/api/snapshot` says `windowed: true` the page switches to server-driven mode:

- **Tree pane** becomes a virtual list: fixed row height, only viewport ± overscan rows in
  the DOM, scroll position mapped to `offset` windows of `/api/streams`. Fold state is
  per-node fetch (`scope=children&of=SEQ`) with client-side cache keyed by generation;
  sort and query changes are round-trips, debounced. Row markup/selection/keyboard behavior
  is unchanged from today.
- **Detail pane** keeps using `/api/stream/{id}` (already windowed by nature).
- **Timeline tab** draws from `/api/timeline` bins onto a `<canvas>` (one draw call set per
  lane, not one DOM/SVG node per stream); the scrubber/playhead filters by re-querying bins
  for the visible time window at the same bounded resolution. Lane click resolves back to a
  stream selection via the lane's `seq`.
- **Search box** shows `match_total` immediately and pages matches like the tree; the
  "matches + ancestors" presentation is preserved (the server already computes it, 12.4).

**Live refresh discipline.** On a generation tick the page refreshes *what is visible*: the
header counters from the tick payload itself, the current tree window, and the current
timeline window — never a full-forest refetch. Windows carry `generation`; a stale response
(older than the newest seen) is dropped, not rendered.

**Read progress.** While `meta.finished == false` over a file source, the header shows
read progress. The tick payload gains `progress: {bytes_read, bytes_total} | null`,
sourced from the capture layer (the file source knows its size and offset; the hub carries
the pair as atomics updated by the pump thread). Live captures report `null` and show the
existing LIVE badge.

**Budgets** (enforced by 12.7's browser-side checks where practical, code review where
not): DOM rows ≤ viewport + overscan; retained JS objects O(fetched windows), with the
window cache LRU-capped; no `JSON.parse` of a body > 1 MB in windowed mode.

## Acceptance criteria

- [ ] Small captures (below the gate) render pixel-for-pixel as today, still fully
      client-side after the initial snapshot fetch.
- [ ] In windowed mode, scrolling the tree keeps DOM row count constant and never fetches
      more than one window per scroll settle; fold/expand fetches only the touched node's
      children.
- [ ] The timeline renders the 12.7 fixture as canvas bins with response + draw under the
      12.7 budget; scrubbing re-queries at bounded resolution.
- [ ] During a large file read, header counters and progress advance while tree/timeline
      interactions stay responsive; stale-generation responses are provably discarded
      (test via delayed mock).
- [ ] Sort, query, fold, selection, drill-down, unknown triage, and upload flows all work
      in windowed mode (integration test against a served fixture via the existing
      router-level test harness).
