# 05.4 — Metadata rollups

> Task: [05 Aggregator](README.md) · Depends on: 05.2 · PRD: FR-5, §4.A "metadata accumulates" · D4

## Goal
Per-stream retention of plugin-nominated fields beyond baseline stats: accumulated sets,
first/last samples, and bounded time-ordered series — the "metadata stream" of the PRD.

## Specification

```rust
pub struct RollupSet { /* Vec<(FieldName, Rollup)> — one slot per declared RollupSpec */ }

pub enum Rollup {
    Accumulate {
        values: IndexSet<Value>,     // insertion-ordered distinct values
        count: u64,                  // total observations (incl. duplicates)
        overflow: bool,              // set hit cap (D4: 64); new distinct values dropped
    },
    Sample { first: Value, last: Value },
    Series {
        ring: VecDeque<SeriesPoint>, // cap from RollupSpec (D4 default 1024)
        truncated: bool,             // overwrote oldest at least once
    },
}
pub struct SeriesPoint { pub ts: SystemTime, pub dir: PacketDirection, pub value: Value }
```

Update path (inside 05.2's ingest, per stream-forming layer): for each `RollupSpec` in the
plugin's identity, if `layer.fields` contains the field, apply the kind's update. Absent
field on a given packet = no-op (fields can be depth-gated or conditional — e.g. DNS qname
only on queries).

- Caps are hard (D4): `Accumulate` stops admitting *new distinct* values at 64 but keeps
  counting; `Series` overwrites oldest. Both expose their flag so the UI/JSON can say
  "≥64 values" / "last 1024 shown" instead of lying by omission.
- `Value::List` observations in `Accumulate` are treated as atomic values (the set contains
  lists), not flattened — flattening is a plugin choice (emit elements as separate
  observations if that's the intent).
- Motivating uses (become 06 tests): TCP `flags` → `Accumulate` (set of flags seen, FR-5);
  DNS `qname` → `Accumulate` (query names observed in the stream, PRD §4.A); ICMP `type` →
  `Accumulate`; TCP `window` → `Series` for future analysis tooling; DHCP `msg_type` →
  `Series` (the DORA sequence is order-sensitive).

## Acceptance criteria
- [ ] Three kinds implemented with cap/flag semantics unit-tested at the boundaries
      (cap-1, cap, cap+1).
- [ ] Determinism: same packet sequence ⇒ identical rollup contents including set order
      (insertion-ordered set, PRD §7).
- [ ] Depth interaction test: at `Depth::Keys`, a `Structural`-only field simply never
      arrives → rollup stays empty, no error (documented behavior, not a bug).
