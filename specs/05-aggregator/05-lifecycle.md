# 05.5 — Lifecycle state

> Task: [05 Aggregator](README.md) · Depends on: 05.2 · PRD: FR-6, §4.A · D2 (close interplay)

## Goal
Protocol-defined session state machines, engine-executed: the aggregator holds one state
variable per stream and applies the plugin's pure transition function per packet.

## Specification

```rust
pub type StateName = &'static str;   // plugin-owned vocabulary, e.g. "syn_sent"
// from 02.4:
pub struct LifecycleSpec {
    pub initial: StateName,
    pub advance: fn(&FieldMap, StateName, PacketDirection) -> StateName,
    /// States that mean "this session ended" — feeds D2's protocol-close eviction.
    pub closed_states: &'static [StateName],
}
```

- On stream creation: `state = Some(spec.initial)` if the plugin has a `LifecycleSpec`,
  else `None` (plain conversations have no lifecycle — FR-6 is opt-in).
- Per packet: `state = advance(fields, state, dir)`. The function is pure and total —
  unrecognized input returns the current state unchanged (plugins must not panic; 09.1
  fuzzes `advance` with arbitrary FieldMaps).
- When the new state ∈ `closed_states`, the aggregator marks the stream close-eligible and
  starts D2's linger timer (live mode). Packets arriving during linger still update the
  stream (late FIN-ACKs, retransmits); a packet that advances state *out* of a closed state
  (plugin's choice — e.g. port reuse could be modeled as reopen in v2, but TCP v1 does not)
  cancels close-eligibility.
- **State history:** the current state is baseline; the *sequence* of states is retained
  only if the plugin also declares a `Series` rollup on a state-carrying field. Keeps the
  common case cheap while making "show me the handshake timeline" possible (PRD use case 2
  reads flags-series + current state).
- Engine knows no state names — `"established"` appears only in the TCP plugin (06.4) and
  its tests; the aggregator compares `StateName`s only against the plugin's own
  `closed_states` list.

## Acceptance criteria
- [ ] Lifecycle execution wired into ingest; synthetic 3-way-handshake fixture drives a test
      plugin through `new → half_open → established` with per-direction inputs honored.
- [ ] `closed_states` marking verified: teardown fixture flips close-eligibility; a
      mid-linger packet still updates stats.
- [ ] No-lifecycle plugins: `state == None` throughout, zero overhead on the ingest path
      (branch, not allocation).
