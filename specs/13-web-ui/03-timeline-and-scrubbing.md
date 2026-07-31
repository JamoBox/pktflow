# 13.3 — Timeline & scrubbing

> Task: [13 Interactive front-ends](README.md) · Depends on: 13.1, 13.2 · PRD: §4 use case 4
> · D17.3

## Goal
The Timeline tab: one lane per visible stream on a shared time axis, a draggable/playable
**playhead** that filters the rest of the UI by time, and — above the D17.4 windowing gate —
a bounded-resolution canvas view of the same axis (D17.3). This is the feature the regression
report that opened this task was about: full-mode scrubbing is intact, but windowed-mode
never got the "controls go away" half of 12.5's own descope decision, so it looks broken
instead of being honestly unavailable. That gap is this spec's Acceptance criteria below.

## Specification

**Full mode** (`S.windowed === false`, the common case — below `FULL_SNAPSHOT_MAX_STREAMS` =
20,000 streams, 13.1): `renderTimeline()` draws one `.tl-row`/`.tl-bar` DOM element per
visible stream (query-filtered, `MAX_TREE_ROWS`-capped like the tree, 13.2), spanning
`first_seen`→`last_seen` on the shared axis `[TL.start, TL.end]` (the min/max over all visible
streams). A bar is `unborn` (not yet started), `act` (spans the playhead), or `done` (already
ended), reclassified live as the playhead moves.

**The playhead** (`#tlScrub`, a `<input type=range>` 0–1000 mapping to fraction `f` of
`[TL.start, TL.end]`): dragging it, clicking the ruler (`#tlScroll .ticks`), pressing
←/→ (nudge, `TL_KEY_STEP` units) or **play** (`#tlPlay`, advances 5 units / 50 ms) all
converge on `updatePlayhead()`, which:
1. Updates the header's `#globalPlayheadTime` / `#globalPlayheadActive` indicator (visible
   from any tab, not just Timeline).
2. In-place restyles every `.tl-bar`/`.tl-row`'s `unborn`/`act`/`done` class and moves
   `#tlPh` — no re-render of the row list itself, so scrubbing stays smooth at any stream
   count the DOM already holds.
3. Recomputes `S.timeFilter` unless told to skip (`skipFilterUpdate`).

**Time-filter modes** (`#tlFilterMode`): `none` (no cross-tab effect), `point` (filters
Streams/Protocols/Unknown to whatever spans the playhead instant), `window` (filters to a
dragged `[start, end]` range, edited via `#tlRangeStartInput`/`EndInput` or the ruler drag;
in this mode the playhead is clamped inside `[minPct, maxPct]` and play loops within it rather
than running off the end). `isStreamInTimeWindow`/`isUnknownInTimeWindow` (13.2's Protocols/
Unknown tabs, and the Streams tree's counters) apply whichever mode is active.

**Windowed mode** (`S.windowed === true`, above the gate): `renderTimeline()` delegates to
`renderWinTimeline()`, which fetches `/api/timeline` (server-binned time×lane density, 13.1)
and draws it as one `<canvas>` (D17.3 — bounded cost regardless of stream count). Per D17.3
and 12.5's accepted acceptance criterion, **there is no finer time resolution to scrub to**
than the bins the server already returns — lanes are pre-binned, not per-packet. Scrubbing in
the fine-grained, per-stream sense of full mode is out of scope for windowed mode *until* a
zoom interaction exists to ask the server for a narrower bin range (untracked — a future
sub-task, not this one). Given that, windowed mode:
- Does **not** create `#tlPh`, does not set `TL.start`/`TL.end`, and does not restyle bars
  (there are no per-stream bar elements to restyle).
- **Must** put the toolbar into a visibly disabled state so the UI doesn't claim a capability
  it doesn't have: `#tlPlay`, `#tlScrub`, `#tlFilterMode`, and the range-control inputs are
  `disabled`, and the hint text swaps to state the limitation plainly instead of "drag or ←→
  to scrub." A lane click still resolves to a stream selection (`winSelect`, unaffected).
- The header's `#globalPlayheadTime`/`#globalPlayheadActive` indicator is blanked (`—`) or
  hidden rather than showing a value computed from an axis that was never set.

## Acceptance criteria
- [x] Full mode: dragging `#tlScrub` moves `#tlPh`, updates `#globalPlayheadTime`, and
      reclassifies bar state (`unborn`/`act`/`done`) correctly — browser-verified against a
      served fixture (Playwright: fill `#tlScrub`, dispatch `input`, assert `#tlPh.style.left`
      and bar classnames change).
- [x] Full mode: `point` and `window` filter modes correctly narrow the Streams tree count,
      Protocols chart, and Unknown-triage list to the selected time span; switching back to
      `none` restores the unfiltered counts.
- [x] Full mode: play advances the scrubber and loops/stops per the active filter mode's
      bounds; ← / → nudge the scrubber by a fixed step without needing focus on the slider.
- [x] **Windowed mode: `#tlPlay`, `#tlScrub`, `#tlFilterMode`, and the range inputs render
      `disabled`, and the hint text names the limitation, the first time the Timeline tab is
      opened on an over-gate capture** — `updateTimelineToolbar()` (called from `refetch()`
      on every generation and from `renderTimeline()`) drives this; the header playhead
      indicator blanks to `—` instead of computing a time off `TL.start`/`TL.end`, which are
      never set in windowed mode. Browser-verified (Playwright: force `S.windowed`, assert
      `disabled` on all four controls and the blanked header, then flip back and assert
      re-enablement); keyboard ←/→ nudge is also gated on `!S.windowed` so it can't mutate
      the scrubber while its control is disabled.
- [x] Windowed mode: the canvas renders lane density from `/api/timeline` and a lane click
      opens the corresponding stream (12.5's existing criterion, unchanged).
- [x] Crossing the D17.4 gate mid-capture (a live/growing offline read passes 20,000 streams
      while the Timeline tab is open) transitions the toolbar from enabled to disabled without
      a page reload.
