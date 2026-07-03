# 04.3 — Stop reasons & `dissect()`

> Task: [04 Parser](README.md) · Depends on: 04.1, 04.2 · PRD: §9-Q9 · D9

## Goal
The eager convenience wrapper producing the owned `DissectedPacket`, and the canonical
`StopReason` enum — the error-surfacing currency (D9) that the CLI, summary counters, and
tests all read.

## Specification

```rust
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StopReason {
    Complete,                          // payload exhausted after last layer
    Terminal,                          // a plugin declared Hint::Terminal
    UnclaimedRoute(RouteId),           // the gate fired (03.4) — unsupported/encrypted next
    UnknownHint,                       // Hint::Unknown and heuristics found no winner
    Truncated { needed: u16, have: u16 }, // a plugin ran out of bytes mid-header
    PluginError,                       // routed/explicit plugin declined or lied (02.1 r3)
    DepthCap,                          // max_layers guard (04.1)
}
```

- `Copy` and boxed-nothing: stop reasons are per-packet hot-path data.
- Semantic grouping for reporting (08, D9): `Complete | Terminal` = *clean*;
  `UnclaimedRoute | UnknownHint` = *unknown payload*; `Truncated | PluginError` = *malformed*;
  `DepthCap` = *suspicious*. The grouping is a `StopReason::class() -> StopClass` method so
  the CLI and JSON never re-derive it.

```rust
impl Engine {
    /// Eager walk to completion: the aggregation pipeline's input producer.
    pub fn dissect(&self, bytes: &[u8], meta: PacketMeta, opts: ParseOpts) -> DissectedPacket;
}
```

`dissect` = `layers(...)` drained + `into_packet`: identical semantics by construction (one
implementation, two surfaces). `DissectedPacket.opaque_len` = remaining payload length at
stop; 0 on `Complete`.

## Acceptance criteria
- [x] Every `StopReason` variant reachable by at least one unit test (table in 03.4 provides
      the recipes) and carries the right values (`Truncated` needed/have, `UnclaimedRoute` id).
- [x] `dissect` and manual iterator drain produce identical `DissectedPacket`s on all 09.2
      fixtures (property: one implementation path).
- [x] `StopClass` mapping implemented and snapshot-tested (it is user-facing wording's anchor).
