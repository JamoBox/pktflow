# Task 05 — Stream aggregator

**Goal:** the product. A long-lived aggregator consuming `DissectedPacket`s and maintaining
the evolving set of streams: canonicalized conversations at every identity-declaring layer,
nested into a browsable hierarchy, with per-stream metadata rollups, protocol-defined
lifecycle, bounded memory, and a query API. Everything before this task exists to feed it;
everything after presents it.

**Depends on:** 02 (identity declarations), 04 (input type). **Blocks:** 08, 09.
**PRD:** §4.A entire, FR-1 through FR-8 · D2, D3, D4, D5, D10.

## Sub-tasks

- [x] [05.1 Flow keys & canonicalization](01-flow-keys.md) — key building, D3 rule (FR-2, FR-3)
- [x] [05.2 Stream store](02-stream-store.md) — the single-writer state machine (FR-1)
- [ ] [05.3 Flow hierarchy](03-hierarchy.md) — parent-scoped nesting, tunnels (FR-4, FR-8)
- [x] [05.4 Metadata rollups](04-rollups.md) — accumulate/sample/series (FR-5)
- [ ] [05.5 Lifecycle state](05-lifecycle.md) — plugin-defined session state (FR-6)
- [ ] [05.6 Memory & eviction](06-memory-eviction.md) — D2 policy, sinks (PRD §7)
- [ ] [05.7 Query API](07-query-api.md) — list/get/traverse/snapshot (FR-7)

## Definition of done

A synthetic multi-packet capture (09.2) produces the exact expected stream tree: correct
conversation counts at each layer, both directions folded with per-direction stats, TCP
lifecycle transitions observed, tunneled inner streams nested under the tunnel, eviction
firing per policy, all reachable through the query API — deterministically across runs
(PRD §7). No item in this task's code mentions any concrete protocol.
