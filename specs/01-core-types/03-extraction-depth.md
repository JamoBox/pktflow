# 01.3 — Extraction depth

> Task: [01 Core types](README.md) · Depends on: 01.1 · PRD: FR-16, §4.B.5

## Goal
The caller-set knob controlling how much metadata plugins extract per layer, with the
flow-key floor that stream aggregation requires.

## Specification

```rust
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Depth {
    None,        // parse for length + routing only; empty FieldMap
    Keys,        // flow-key/identity fields only (addresses, ports, ids)
    Structural,  // Keys + structural fields (lengths, flags, types, TTLs)
    Full,        // everything the plugin knows how to extract
}
```

- `Ord` is semantic: `Depth::Keys >= requested` style checks are how plugins branch.
- **Flow-key floor (FR-16):** the *effective* depth handed to plugins is
  `max(requested, Keys)` whenever stream aggregation is enabled. The clamp lives in the
  engine configuration (04.1), **not** in each plugin — plugins just honor the effective
  depth they receive.
- Contract on plugins: at a given depth a plugin must extract *at least* its declared
  flow-key fields (02.4) when depth ≥ `Keys`; the plugin test kit (09.1) verifies this for
  every registered plugin.
- Depth is per-parse-session, fixed for all layers of a packet (no per-layer depth in v1 —
  revisit only if profiling demands it).

## Acceptance criteria
- [x] `Depth` implemented with ordering tests (`None < Keys < Structural < Full`).
- [x] Engine-side clamp specified in the parser config and unit-tested: aggregation on +
      requested `None` ⇒ plugins observe `Keys`.
- [x] Doc comment states the plugin contract (flow-key fields present at ≥ `Keys`) that 09.1
      enforces mechanically.
