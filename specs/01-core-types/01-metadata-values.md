# 01.1 — Metadata values & field maps

> Task: [01 Core types](README.md) · Depends on: 00.2 · PRD: FR-18, §4.B "Metadata"

## Goal
A small typed value model for everything plugins extract, and an ordered named map of those
values per layer — cheap to build on the hot path, stable to render and serialize.

## Specification

```rust
pub enum Value {
    Bytes(SmallBytes),   // MAC addresses, opaque ids; SmallVec<[u8; 16]> — no heap ≤16 B
    U64(u64),
    I64(i64),
    Bool(bool),
    Str(CompactString),  // decoded names (DNS qname); must already be valid UTF-8
    List(Vec<Value>),    // ordered lists, e.g. VLAN tag stack, DNS answers
}
```

- Covers exactly FR-18's set; **non_exhaustive** so v2 can add (e.g.) `Ip(IpAddr)` without
  breaking plugins.
- `Value: Clone + PartialEq + Eq + Hash + Debug` — `Eq + Hash` are required because flow keys
  (05.1) are built from `Value`s. Consequence: **no float variant** in v1.
- Rendering (`Display`) is *not* implemented here — human-friendly rendering of MACs/IPs is a
  CLI concern (08.5) keyed off field names, keeping core presentation-free.

```rust
pub type FieldName = &'static str;              // plugins own their field-name constants
pub struct FieldMap { /* Vec<(FieldName, Value)> — insertion-ordered */ }
impl FieldMap {
    pub fn insert(&mut self, name: FieldName, v: Value);
    pub fn get(&self, name: &str) -> Option<&Value>;
    pub fn iter(&self) -> impl Iterator<Item = (&FieldName, &Value)>;
}
```

- Insertion-ordered `Vec` backing, linear `get`: layers carry ~3–20 fields, so a Vec beats a
  hash map on both speed and memory; order preserved for deterministic output (PRD §7).
- Duplicate insert of the same name replaces (last write wins); plugins should not rely on it.
- Field-name convention: `snake_case`, protocol-local (`src_port`, not `tcp.src_port` — the
  layer already scopes it).

## Acceptance criteria
- [ ] `Value` and `FieldMap` implemented with the bounds above; unit tests for replace-on-
      duplicate, ordering stability, and `Hash` consistency across equal values.
- [ ] No heap allocation for a `Bytes` value of ≤16 bytes (asserted via a test or documented
      by the chosen SmallVec bound).
- [ ] `serde::Serialize` implemented (behind a `serde` feature) producing stable JSON:
      `Bytes` as lowercase hex string, others as native JSON types.
