# Task 04 — Lazy parser

**Goal:** the layer-at-a-time iterator that walks one packet: resolve entry, parse a layer,
yield it, route the hint, repeat until a stop — with the stop's *reason* preserved. The
parser is the pump between capture (07) and aggregation (05).

**Depends on:** 03. **Blocks:** 05 (consumes its output), 08.
**PRD:** §4.B.2, FR-13, and D9 via stop reasons.

## Sub-tasks

- [x] [04.1 Lazy iterator](01-lazy-iterator.md) — `LayerIter`, one layer per `next()` (FR-13)
- [x] [04.2 Entry resolution](02-entry-resolution.md) — link-type route or heuristic first layer
- [x] [04.3 Stop reasons & dissect()](03-stop-reasons.md) — the eager convenience + D9 surface

## Definition of done

`engine.layers(bytes, meta)` yields lazily with borrow-based zero-copy over the capture
buffer; `engine.dissect(bytes, meta)` returns an owned `DissectedPacket` ready for the
aggregation channel; both agree layer-for-layer on all fixtures; every stop path yields the
correct `StopReason`.
