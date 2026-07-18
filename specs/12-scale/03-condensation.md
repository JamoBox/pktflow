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
pub struct CondenseSpec {
    /// The paired key field whose values may vary within a condensed
    /// group (e.g. TCP/UDP: their src/dst port pair). All other key
    /// components must match for flows to share a group.
    pub ephemeral: KeyField,
}
// LayerPlugin gains a defaulted method, like claims()/probe():
fn condense(&self) -> Option<&'static CondenseSpec> { None }
```

TCP and UDP declare their port pair; no other 06-set plugin declares anything (and
therefore never condenses). The registry validates at build time (03.2) that a
declaration comes with an `EndpointSort` identity whose `key` contains the named pair.

> Shape notes (Article II): the draft put `condense` inside `StreamIdentity` as a
> `&'static [KeyField]` slice. Implementation surfaced the defaulted trait method (zero
> churn across the ~60 existing `StreamIdentity` statics, matching how `claims`/`probe`
> extend the contract) and exactly one pair (multiple ephemeral dimensions have no
> well-defined single anchor; nothing in the shipped set needs it).

**Grouping.** A flow's *anchor* is the endpoint side whose (address-from-parent, stable
field values) repeats across the group — computed from field values, not canonical A/B
labels (D3 sorting must not split a group). Group key: `(parent, protocol, encoding of
the non-ephemeral key components + the anchor side's value)` — the same encoding
whichever side the anchor appears on in a given packet. The other side's ephemeral value
is the varying dimension. Each expanded flow tallies *both* of its candidate anchors
(decremented on evict, so the count tracks live flows); while an anchor's count is < K
(`AggregatorConfig::condense_threshold`, default 256), flows create ordinary streams.
Once it reaches K, the next matching flow creates the group's **condensed node** and
folds in; later flows of the group fold on their index miss via the candidate lookup —
folded flows keep no per-member index entries (that would rebuild per-flow state), so
each of their packets pays one candidate computation + map probe instead.

**Condensed node semantics.** A condensed node is a `Stream` in the arena and the
hierarchy (a leaf; D10 parent-scoped as usual) flagged by a new field:

```rust
pub struct Stream {
    /* … */
    pub condensed: Option<Box<CondensedInfo>>,   // None = ordinary stream
}
pub struct CondensedInfo {
    pub member_flows: u64,          // distinct members; == the distinct-ephemeral tally
    pub ephemeral_field: FieldName, // the anchor-side pair name, e.g. "src_port"
    pub overflow: bool,             // D4-style honesty past the member-tally cap (65,536)
}
```

> Shape notes (Article II): within a group, the varying-side value *is* the member
> identity (anchor + varying value = the full flow key), so `member_flows` and the
> draft's `distinct_ephemeral` are the same number — merged. The draft's lifecycle
> histogram (`states`) is **deferred**: honest per-member transitions require per-member
> state, which is exactly the per-flow memory condensation exists to avoid; a condensed
> node reports member/stat tallies and applies rollups (D4-bounded) instead. The node's
> synthesized flow key is a sentinel byte plus the group's anchor encoding — no
> `EndpointSort` encoding starts with the sentinel, so it can never alias a real key.

Stats (`stats`, `opaque_bytes`, `first_seen`/`last_seen`) accumulate over all member flows.
`key_fields` carry the anchor side only. Rollups apply as normal (their D4 bounds are what
make this safe). The condensed node has no per-member children; a member flow's *inner*
layers (e.g. app protocol over one of the folded TCP flows) aggregate as children of the
condensed node, keyed as usual — nesting survives condensation.

**Lifecycle/eviction.** A condensed node carries no lifecycle state (see shape notes).
Under `EvictionPolicy::Live` a condensed node is idle/LRU-evictable like any leaf;
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

**Aggregate counters.** `streams_created` counts member flows (FR-27 truthfulness); the
condensed node itself adds to `streams_live` (it is a live node) but not to the created
counters — its members are what was created. The summary gains `flows_condensed` so
nothing is silently absorbed.

## Acceptance criteria

- [x] A synthetic fan-out capture (one anchor, K+N ephemeral peers) yields exactly K
      ordinary streams plus one condensed node with `member_flows == N`, correct summed
      stats with anchor-relative direction, and the member tally; total live nodes stay
      bounded as the fan-out grows (verified to 1M flows → 12,384 nodes end-to-end).
      *(N, not N+1: the K+1-th flow creates the node and is its first member; the state
      histogram left the shape — see the Article II note above.)*
- [x] Two runs over the same fan-out capture produce identical expanded sets and identical
      condensed tallies (determinism test over randomized input).
- [x] Inner-protocol traffic over folded flows nests under the condensed node — the
      hierarchy (and therefore ancestor traversal, `under ==` included) treats it as an
      ordinary parent.
- [x] `--no-condense` reproduces per-flow output exactly (binary-level test), and
      captures that never cross K are byte-identical to today in all modes by default
      (every pre-task golden passes unchanged).
- [x] Query (`condensed` flag), JSON (D8 + schema), TUI, and web renderings of condensed
      rows match the spec'd shape (`:443 ↔ :*  × 44,968 flows`); `flows_condensed`
      reconciles: `streams_created == expanded + Σ member_flows` (tested).
- [x] Eviction of a condensed node re-arms its group deterministically (unit test over the
      05.6 policy: recurrence starts a fresh expanded count).
