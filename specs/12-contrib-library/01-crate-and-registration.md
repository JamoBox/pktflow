# 12.1 — Crate, features & registration

> Task: [12 Contrib library](README.md) · Depends on: 02–06 · PRD: FR-32 · D16

## Goal
The `pktflow-contrib` crate itself: an optional workspace member holding every task-12
plugin, compiled into a consumer only when explicitly asked for, feature-gated per domain,
and guaranteed never to collide with the standard library's routes or names. This sub-task
delivers no protocols — it delivers the place protocols go and the rules that keep the
default binary exactly as it was.

## Specification

### Crate layout

- `crates/pktflow-contrib`, workspace member. Runtime dependency: `pktflow-core` only —
  the same dependency posture as `pktflow-plugins`, keeping contrib pure-Rust and fuzzable.
  Dev-dependencies: `pktflow-plugins` (combined-engine collision test), `pktflow-flows` +
  `proptest` (09.1 kit, same as the stdlib's test setup).
- One file per protocol, `src/<name>.rs`, identical conventions to 06/11 (field-name
  constants at top, doc comment citing the D14 standard).

### Feature gating

One cargo feature per domain sub-task; a plugin's `mod` declaration and its registration
line are gated by the same feature, so every feature subset builds a consistent engine:

| Feature | Sub-task |
|---|---|
| `encap` | 12.2 |
| `netops` | 12.3 |
| `security` | 12.4 |
| `legacy-lan` | 12.5 |
| `remote-access` | 12.6 |
| `databases` | 12.7 |
| `messaging` | 12.8 |
| `media` | 12.9 |
| `storage` | 12.10 |
| `enterprise` | 12.11 |
| `voip` | 12.12 |
| `industrial` | 12.13 |
| `fabric` | 12.14 |
| `observability` | 12.15 |
| `gaming` | 12.16 |

`default = ["full"]`; `full` enables every domain. Consumers wanting a slice depend with
`default-features = false` plus the domains they need. `--no-default-features` alone must
still compile (an empty `register()` is valid, not an error).

### Registration surface

Shape sketch (names/signatures normative, bodies not):

```rust
// pktflow-contrib/src/lib.rs — the crate's single registration list (D16:
// PRD §8's "one file + one registration line" metric applies per crate).
pub fn register(builder: EngineBuilder) -> EngineBuilder {
    // one `.plugin(...)` line per protocol, each gated by its domain feature
}
```

Feeding it requires the stdlib's builder before it's sealed, so `pktflow-plugins` gains one
accessor (its only change in this task):

```rust
// pktflow-plugins/src/lib.rs
pub fn default_builder() -> EngineBuilder;   // the existing registration list, unsealed
pub fn default_engine() -> Engine;           // unchanged behavior: default_builder().build().expect(...)
```

`default_engine()`'s registered set is byte-for-byte what it is today — the accessor is a
refactor of where `.build()` happens, not a behavior change.

### Consumer opt-in

`pktflow-cli` (and via it the TUI/web frontends, which take an engine from the CLI layer)
gains a cargo feature `contrib`, **off by default**. When enabled, engine construction is
`pktflow_contrib::register(pktflow_plugins::default_builder()).build()`; when disabled,
`pktflow-contrib` is not in the dependency graph at all. A runtime toggle (enable/disable
contrib domains per invocation) is an explicit v2 non-goal — the boundary is compile-time.

### Collision guarantee

- A contrib plugin never claims a `RouteId` or plugin name the standard library claims —
  including routes in 06/11 specs not yet built (spec review enforces those; see D16).
- The built subset is enforced mechanically: a test in `pktflow-contrib` builds
  `register(default_builder()).build()` with **all** features enabled and asserts success —
  the registry's build-time validation (03.2) turns any collision into a test failure.
- `just ci` runs the workspace, so this test (and every contrib fixture test) is part of
  the ordinary gate; CI additionally builds the crate `--no-default-features` to hold the
  empty end of the feature matrix. Per-domain single-feature builds are a `just` recipe
  (`just contrib-features`) rather than a CI matrix — cheap to run when touching gating.

### Documentation

`docs/adding-a-protocol.md` gains a short "stdlib or contrib?" section: the D16 placement
rule, the feature table above, and the note that the end-to-end flow (new file + one
registration line) is identical in either crate.

## Acceptance criteria
- [ ] `pktflow-contrib` builds as a workspace member; `register(default_builder()).build()`
      with all features succeeds (collision-free against the full stdlib registration list),
      as a test inside the contrib crate.
- [ ] Feature matrix holds: crate compiles with `--no-default-features` (empty `register()`)
      and with `full`; `just contrib-features` builds each domain feature in isolation.
- [ ] `default_engine()`'s registered plugin set is unchanged by the `default_builder()`
      refactor (existing 06/11 tests pass untouched — no assertion edits).
- [ ] CLI built with `--features contrib` classifies a contrib-only fixture end-to-end
      (streams visible); the same capture through a default build stops with
      `StopReason::UnclaimedRoute` — the opt-in boundary proven in both directions.
- [ ] `docs/adding-a-protocol.md` documents the D16 placement rule and the feature table.
