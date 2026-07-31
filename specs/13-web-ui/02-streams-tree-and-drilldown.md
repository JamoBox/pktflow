# 13.2 — Streams tree & drill-down

> Task: [13 Interactive front-ends](README.md) · Depends on: 13.1, 05, 08.2/.3 · PRD: §4 use
> cases 1/3/4 · D10

## Goal
The Streams tab: the flow hierarchy as a foldable tree (the web analogue of the CLI's
default tree lens, 08.2), a detail pane for one selected stream (08.3's web analogue), plus
the Protocols and Unknown-triage tabs that share its selection/search plumbing.

## Specification

**Tree pane** (`#tree`, `visibleRows()`): depth-first walk of the (query-filtered) forest,
one row per stream, capped at `MAX_TREE_ROWS = 2000` DOM rows with a "N more — narrow the
filter" trailer past the cap (never render an unbounded DOM). Fold state is per-node
(`toggle(id)`); a query match auto-expands its ancestors so the match stays visible in
context (`docs/query-language.md`'s "matches + ancestors" rule — the same behavior 13.1's
`/api/search` returns for). Row click selects (`select(id)`); caret click toggles fold
without changing selection.

**Detail pane** (`#detail`, `renderDetail()`): fetches `/api/stream/{id}` for the current
selection and renders its D8 fields as cards — endpoints, byte/packet counts, lifecycle
state, rollup fields at whatever depth the capture was taken at (Keys/Structural/Full, 01.4).
A condensed stream (`s.condensed`, 12.3/D16) shows its member-flow count instead of pretending
to be one flow. Selection survives a live tick (it is not reset by a snapshot refetch) unless
the selected stream itself was evicted or condensed away, in which case the pane falls back to
the empty state.

**Protocols tab** (`renderProtocols()`): the summary's `per_protocol` byte/count breakdown as
a chart — capture-wide, not windowing-dependent (it reads `summary`, never the forest).

**Unknown-triage tab** (`renderUnknown()`/`renderUnknownDetail()`): one row per `UnknownGroup`
(10's diagnostics, web-rendered) — predecessor, near-miss scores, sample hex dump. Also
capture-wide and windowing-independent, same reasoning as Protocols.

**Keyboard**: arrow keys move selection in the tree when it has focus; `/` (or the equivalent
documented in `docs/query-language.md`) focuses the search bar from any tab except while
typing in a text field.

## Acceptance criteria
- [x] A tunnel fixture (nested VXLAN, `fixtures/real/vxlan_overlay.pcap`) renders its full
      nested chain in the tree, matching the CLI tree's hierarchy (08.2's fixture, browser vs.
      `--format json` cross-checked).
- [x] Expand/collapse toggles fold state without changing selection; selecting a row updates
      the detail pane to that row's `/api/stream/{id}` fields exactly.
- [x] A live tick does not reset tree scroll position or the current selection.
- [x] Protocols and Unknown tabs render identically whether the underlying capture is below
      or above the D17.4 windowing gate (they don't read the forest).
- [x] `MAX_TREE_ROWS` caps DOM rows on a capture with more streams than the cap, with the
      trailer message shown and the search bar able to narrow below the cap.
