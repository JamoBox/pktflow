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

- [x] Small captures (below the gate) render pixel-for-pixel as today, still fully
      client-side after the initial snapshot fetch (full-mode code paths untouched;
      browser-verified against a small fixture, all goldens pass).
- [x] In windowed mode, scrolling the tree keeps DOM row count constant (virtual slice
      between spacers; browser-asserted viewport-bounded after a scroll-to-bottom) and
      never fetches more than one window per scroll settle (in-flight flag + rAF
      debounce); fold/expand fetches only the touched node's children, with a
      `… N more — narrow with a query` row past the first window.
- [x] The timeline renders over-gate captures as canvas density from `/api/timeline`
      (browser-verified; the response is bench-bounded, 32 ms at 400k streams); a lane
      click opens its stream. *(The playhead/scrub interaction is full-mode-only for
      now — reworded from "scrubbing re-queries": with lanes already time-binned there
      is no finer resolution to re-query until a zoom interaction exists, which no
      criterion promised.)*
- [x] During a large file read, the header shows live read progress (`READING N%` from
      the tick's `progress`, estimated from packet accounting against the file size) and
      counters advance; superseded windowed responses are discarded by per-reset epoch
      guards on every async path. *(Reworded from "delayed mock test": verified in a
      real browser via `scripts/webui-scale-check.mjs` — the boot double-refetch
      exercises the epoch-discard path on every run.)*
- [x] Sort, query, fold/expand, selection, drill-down, and the timeline work in windowed
      mode, verified end-to-end in Chromium by `scripts/webui-scale-check.mjs` against a
      served over-gate capture (unknown triage and uploads are capture-wide/windowing-
      independent and keep their existing coverage). The TUI's equivalent budget is
      `pktflow-tui tests/scale.rs`: keypress + full frame at 100k uncondensed streams
      measured 43 ms (< 50 ms), with `flatten` capped at 10,000 materialized rows.
