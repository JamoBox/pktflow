# Task 13 — Interactive front-ends (TUI & Web UI)

**Goal:** retrofit the spec this area never had. `pktflow-tui` and `pktflow-web` (commits
`1769837`, `54000a6`, `49af11d`, `94a32ea`, `ebd78a7`, `9f7693b`, `4add51e`) shipped
July 12–13 — after the [Constitution](../CONSTITUTION.md) was ratified (July 7–8) — with no
sub-task spec, no acceptance criteria, and no `D#` entry. Task 12 later specced the *scale*
behavior of the web UI (12.5) against this undocumented baseline, which is exactly backwards:
a delta spec cited a base that didn't exist to check it against. This task writes that base
down as it stands today, so behavior changes (including scale work) have something to be
reviewed against and something to regress detectably from.

This is a retrofit under Article II, not new design: it describes shipped behavior, corrects
it only where the spec-writing surfaced an actual bug (13.3 documents one — see its
Acceptance criteria), and leaves architecture choices already made (D17) alone.

**Depends on:** 05 (aggregator), 06 (reference plugins), 07 (capture I/O), 08 (CLI —
`pktflow-view`'s D8 JSON schema is shared, not reinvented here).
**Blocks:** none forward; 12.5 (web UI at scale) is a delta on top of 13.1–13.3 and its header
now says so.
**PRD:** §4 use cases (drill-down, timeline, search), §5 "Interactive front-ends" · D8 (schema
reuse), D10 (parent-scoped identity, drives fold/expand), D17 (scale contract 13 is a
baseline for, not a competitor to).

## Sub-tasks

- [x] [13.1 SPA shell & JSON API](01-spa-shell-and-api.md) — tabs, `/api/*` surface, live
      refresh (SSE tick) discipline, shared with the TUI's query language (54000a6)
- [x] [13.2 Streams tree & drill-down](02-streams-tree-and-drilldown.md) — tree pane, search,
      selection, detail pane, protocols/unknown-triage tabs
- [x] [13.3 Timeline & scrubbing](03-timeline-and-scrubbing.md) — playhead, scrub, play/pause,
      time-filter modes, and the full-mode/windowed-mode split (fixes the dead-controls
      regression this task was opened to explain)

## Definition of done

1. Every sub-task's acceptance criteria pass against a real `pktflow serve` (or `pktflow tui`
   where noted), browser/terminal-verified, not just code-read.
2. A future PR touching `crates/pktflow-web/src/assets/index.html` or `crates/pktflow-tui`
   names the sub-task spec(s) it satisfies (Constitution Article I) and updates them in the
   same PR if behavior changes (Article II) — this task exists so that's possible.
3. `specs/12-scale/05-scalable-web-ui.md` cites this task as its base instead of an implicit
   "as today."
