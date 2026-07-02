# Task 02 — Plugin contract

**Goal:** the single interface every protocol satisfies (PRD FR-9): required name + parse,
optional routing metadata (claims, predecessors, probe), and the **stream identity
declaration** that turns a dissector into a conversation source. This contract is the
product's extensibility promise — get it right and the engine never changes again.

**Depends on:** 01. **Blocks:** 03, 04, 05, 06.
**PRD:** §4.B.1, FR-9, FR-11, §4.A "protocol-defined, engine-aggregated".

## Sub-tasks

- [x] [02.1 `LayerPlugin` trait](01-plugin-trait.md) — name + parse, the required core
- [x] [02.2 Next-layer hints](02-hints.md) — all five hint kinds (FR-11)
- [ ] [02.3 Routing metadata](03-routing-metadata.md) — claims, predecessors, probe
- [ ] [02.4 Stream identity](04-stream-identity.md) — flow key, canonicalization, state, rollups

## Definition of done

A dummy plugin implementing only `name` + `parse` compiles and dissects; a second dummy
additionally declaring claims + stream identity compiles with no engine-side code specific to
it. Trait is object-safe (`dyn LayerPlugin`) and `Send + Sync`. The contract needs no changes
to implement any of the fourteen reference plugins in task 06 (this is the real test).
