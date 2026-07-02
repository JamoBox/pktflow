# Task 03 — Router

**Goal:** turn hints into "which plugin parses next": namespaced route ids, a builder that
auto-wires plugin claims with manual overrides, a scored heuristic fallback with predecessor
prior, and the safety gate that stops rather than misidentifies.

**Depends on:** 02. **Blocks:** 04.
**PRD:** §4.B.3, §4.B.4, FR-12, FR-14, FR-15.

## Sub-tasks

- [ ] [03.1 Route identifiers](01-route-ids.md) — namespaced ids so EtherType 6 ≠ IP proto 6
- [ ] [03.2 Registry & builder](02-router-builder.md) — claims auto-install, overrides, pool (FR-12)
- [ ] [03.3 Heuristic fallback](03-heuristic-fallback.md) — probe scoring + prior + determinism (FR-14)
- [ ] [03.4 Gated termination](04-gated-termination.md) — the no-phantom-streams gate (FR-15)

## Definition of done

Router resolves every `Hint` variant per the 02.2 table; the PRD's motivating failure
(encrypted UDP payload cascading into TCP→IPv6→TCP) is reproduced as a test and stops at the
UDP layer; resolution is deterministic across runs and plugin registration orders.
