# Task 08 — CLI

**Goal:** the `pktflow` binary: stream/conversation views as the default lens (FR-24 — "not
per-packet"), drill-down, a retained per-packet debug mode, live watch, and text/JSON output.
The CLI is a thin composition of tasks 04–07; anything smarter than argument parsing and
rendering belongs in a library crate.

**Depends on:** 05, 06, 07. **Blocks:** 09 e2e.
**PRD:** FR-22–FR-28 · D2 (mode defaults), D8, D9.

## Sub-tasks

- [ ] [08.1 Command surface](01-command-surface.md) — clap tree, shared flags, exit codes
- [ ] [08.2 Streams view](02-streams-view.md) — the default lens (FR-24)
- [ ] [08.3 Drill-down](03-drilldown.md) — one stream in full (FR-25)
- [ ] [08.4 Packets mode](04-packets-mode.md) — debug lens (FR-26)
- [ ] [08.5 Rendering & JSON](05-rendering-json.md) — FR-28, D8 schema

A sixth lens, `pktflow unknown`, is specified separately as its own task since it also
requires new core capability beyond rendering: see [10 Developer diagnostics](../10-diagnostics/README.md).

## Definition of done

Every FR-22…28 demonstrable from the shipped binary against 09.2 fixtures; `--format json`
output is schema-stable and consumed by the 09.3 e2e suite; live mode runs on a real
interface on both OSes (manual checklist).
