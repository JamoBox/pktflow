# 12.3 — High-cardinality condensation

> Task: [12 Large-capture scale](README.md) · Depends on: 05.2, 05.3, 12.1 · PRD: §7,
> §5 use cases · **D16**, D4, D10

## Goal
Ephemeral-port fan-out (one anchor endpoint × tens of thousands of peer ports) stops
producing one full stream node per flow: beyond a threshold, flows fold into one condensed
node per (parent, protocol, anchor endpoint) group, bounding stream count — and therefore
snapshot, JSON, and render cost — by design (D16).

## Specification

**Plugin declaration** (engine stays protocol-free):

```rust
pub struct StreamIdentity {
    /* … */
    pub condense: Option<CondenseSpec>,
}
pub struct CondenseSpec {
    /// The paired key fields whose values may vary within a condensed
    /// group (e.g. TCP/UDP: their src/dst port pair). All other key
    /// components must match for flows to share a group.
    pub ephemeral: &'static [KeyField],
}
```

TCP and UDP declare their port pair; no other 06-set plugin declares anything (and
therefore never condenses).

**Grouping.** A flow's *anchor* is the endpoint side whose (address-from-parent, stable
field values) repeats across the group — computed from field values, not canonical A/B
labels (D3 sorting must not split a group). Group key: `(parent, protocol, anchor-side
encoding of the non-ephemeral key components + the anchor's ephemeral value)`; the other
side's ephemeral value is the varying dimension. The aggregator keeps a per-(parent,
protocol) tally; while a group's expanded-flow count is ≤ K (`AggregatorConfig::
condense_threshold`, default 256), flows create ordinary streams. The flow that would be
K+1 creates (once) the group's **condensed node** and folds in; all later flows of the
group fold in directly — the index maps their would-be key to the condensed node, so
re-keyed recurrence is O(1).

**Condensed node semantics.** A condensed node is a `Stream` in the arena and the
hierarchy (a leaf; D10 parent-scoped as usual) flagged by a new field:

```rust
pub struct Stream {
    /* … */
    pub condensed: Option<CondensedInfo>,   // None = ordinary stream
}
pub struct CondensedInfo {
    pub member_flows: u64,
    pub ephemeral_field: FieldName,          // e.g. "src_port"/"dst_port" pair name
    pub distinct_ephemeral: u64,             // bounded-exact tally
    pub distinct_overflow: bool,             // D4-style honesty past the tally cap
    pub states: Vec<(StateName, u64)>,       // lifecycle histogram, if declared
}
```

Stats (`stats`, `opaque_bytes`, `first_seen`/`last_seen`) accumulate over all member flows.
`key_fields` carry the anchor side only. Rollups apply as normal (their D4 bounds are what
make this safe). The condensed node has no per-member children; a member flow's *inner*
layers (e.g. app protocol over one of the folded TCP flows) aggregate as children of the
condensed node, keyed as usual — nesting survives condensation.

**Lifecycle/eviction.** Member close transitions update the state histogram, not a state
machine. Under `EvictionPolicy::Live` a condensed node is idle/LRU-evictable like any leaf;
its eviction removes the group's index mappings, and recurrence starts a fresh count
(consistent with 05.6's re-keying rule).

**Determinism.** K counts in `created_seq` order: same input ⇒ same first-K expanded
streams, same condensed tallies (PRD §7).

**Configuration & surfaces.** `AggregatorConfig { condense_threshold: usize }` (0 =
disabled); CLI `--no-condense` / `--condense-threshold N` on the shared args. Query
language gains `condensed` as a boolean field; the anchor's fields match normally (`host ==
10.0.0.5 AND port == 443` still selects the group). D8 JSON records carry a `condensed`
object mirroring `CondensedInfo`; both UIs render the row as
`tcp  10.0.0.5:443 ↔ :*  ·  49,744 flows (48,102 ports) ≥…` with the tally in the
drill-down.

**Aggregate counters.** `streams_created` counts member flows (FR-27 truthfulness);
`streams_live` counts nodes. The summary gains `flows_condensed` so nothing is silently
absorbed.

## Acceptance criteria

- [ ] A synthetic fan-out capture (one anchor, K+N ephemeral peers) yields exactly K
      ordinary streams plus one condensed node with `member_flows == N+1`, correct summed
      stats, distinct-ephemeral tally, and state histogram; total live nodes stay bounded
      as N grows 10×.
- [ ] Two runs over the same fan-out capture produce identical expanded sets and identical
      condensed tallies (determinism test).
- [ ] Inner-protocol traffic over folded flows nests under the condensed node; `under ==`
      queries traverse it.
- [ ] `--no-condense` reproduces today's per-flow output exactly on the 09 fixtures;
      captures that never cross K are byte-identical to today in all modes by default.
- [ ] Query, JSON (D8), TUI, and web renderings of condensed rows match the spec'd shape;
      `flows_condensed` reconciles: `streams_created == expanded + Σ member_flows`.
- [ ] Eviction of a condensed node re-arms its group deterministically (unit test over the
      05.6 policy).
