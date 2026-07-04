# 09.1 — Plugin test kit

> Task: [09 Validation](README.md) · Depends on: 02.* · PRD: §7 "plugins unit-testable in isolation"

## Goal
A generic conformance harness every plugin runs through: bytes → layer + fields + hint +
flow key, mechanically enforcing the contract rules of 01.3, 02.1, 02.4 so plugin review is
about protocol correctness, not contract compliance.

## Specification

`pktflow-plugins/tests/kit/` (or a `test-kit` feature in core), driven per plugin by a
declarative case:

```rust
pub struct ConformanceCase {
    pub plugin: Box<dyn LayerPlugin>,
    pub good: Vec<GoodPacket>,     // real header bytes + expected fields/hint/header_len per depth
    pub outer_ctx: Vec<LayerRecord>, // simulated outer layers where the plugin needs them
}
pub fn run_conformance(case: &ConformanceCase);
```

Checks per `good` sample (beyond the author's own expectations):

1. **Truncation sweep:** every prefix `bytes[..n]` for `n in 0..header_len` parses to
   `Err` — never panics, never a short success (00.2's promise, mechanized).
2. **Depth ladder:** parse at all four depths; assert field sets are monotonic
   (`None ⊆ Keys ⊆ Structural ⊆ Full`) and flow-key fields all present at ≥ `Keys` (01.3).
3. **Identity coherence (02.4):** every `KeyField`/`RollupSpec` name appears in the `Full`
   parse's fields; key builds without `KeyError`; involution holds (05.1 — a/b-swapped
   FieldMap gives same key, flipped direction).
4. **`header_len` honesty:** `≤ bytes.len()`; re-parsing `bytes[..header_len]` succeeds
   (header self-contained).
5. **Probe sanity** (if probing): probe(good bytes) ≥ `MIN_CONFIDENCE`; probe on 1k random
   buffers scores `None`/low ≥ 99% of the time (honesty, 02.3).
6. **Lifecycle totality** (if lifecycled): `advance` fuzzed with arbitrary FieldMaps ×
   states × directions — no panic, returns a state from the plugin's declared vocabulary.

Plus workspace-level fuzz targets (`cargo-fuzz`, run in scheduled CI, not per-PR): raw bytes
→ `Engine::dissect` with the full default engine; DNS name decoder standalone (06.6).

## Acceptance criteria
- [x] Kit implemented; all 15 reference plugins have a `ConformanceCase` and pass.
- [x] Kit failures produce actionable messages naming plugin, rule, and byte offset.
- [ ] Fuzz targets build and run clean for a 10-minute smoke locally; scheduled CI job wired.
- [x] Template plugin's tests (06.1) use the kit, so every copied plugin starts conformant.
