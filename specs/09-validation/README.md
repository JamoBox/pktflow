# Task 09 — Validation

**Goal:** the proof layer: a reusable plugin test kit, the synthetic + real fixture corpus,
end-to-end stream assertions against a reference tool, and the benchmarks that check the
PRD's performance claims. Much of it starts alongside task 06 (the kit) rather than after 08.

**Depends on:** all. 09.1 co-develops with 06.
**PRD:** §7 testability, §8 success metrics.

## Sub-tasks

- [x] [09.1 Plugin test kit](01-plugin-test-kit.md) — contract conformance per plugin
- [ ] [09.2 Fixture corpus](02-fixtures.md) — synthetic builder + curated captures
- [ ] [09.3 End-to-end stream tests](03-e2e.md) — expected trees + reference parity
- [ ] [09.4 Benchmarks](04-benchmarks.md) — depth payoff, throughput, memory

## Definition of done

Every PRD §8 success metric has a named, passing test or a recorded measurement:
time-to-new-protocol (rehearsal, 06), stream fidelity (09.3 parity), correct nesting (09.3),
no phantom streams (03.4 + 09.3), depth pays off (09.4).
