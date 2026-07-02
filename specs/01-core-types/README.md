# Task 01 — Core types

**Goal:** the vocabulary of the dissection substrate — typed metadata values, layer records,
extraction depth, and the parse context plugins receive — defined once in `pktflow-core` and
used unchanged by every later task.

**Depends on:** 00. **Blocks:** 02–05.
**PRD:** §4.B, FR-10, FR-16, FR-17, FR-18.

## Sub-tasks

- [x] [01.1 Metadata values & field maps](01-metadata-values.md) — `Value`, `FieldMap` (FR-18)
- [x] [01.2 Layers & stacks](02-layers-and-stacks.md) — `LayerRecord`, `PacketView` (FR-10)
- [x] [01.3 Extraction depth](03-extraction-depth.md) — four levels + flow-key floor (FR-16)
- [ ] [01.4 Parse context](04-parse-context.md) — cross-layer lookup, innermost-wins (FR-17)

## Definition of done

All four types compile in `pktflow-core` with unit tests; the `LayerPlugin` trait of task 02
can be written against them with no further core changes; cross-layer lookup semantics proven
by a stacked-repeats test (e.g. two same-named layers → innermost returned).
