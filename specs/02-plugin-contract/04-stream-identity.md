# 02.4 — Stream identity declaration

> Task: [02 Plugin contract](README.md) · Depends on: 02.1 · PRD: §4.B.1 "new", FR-9, FR-2/3/5/6 · D3, D4

## Goal
The declaration that makes a dissector a conversation source: which fields form the flow
key, how to canonicalize direction, optional lifecycle semantics, optional rollup hints.
The plugin *declares*; the aggregator (05) does all grouping. This is the PRD's central
"protocol-defined, engine-aggregated" split.

## Specification

```rust
pub struct StreamIdentity {
    /// Endpoint description: the fields identifying each end of a stream of this protocol.
    /// One entry per key component; `b: None` for symmetric/non-directional components
    /// (e.g. VXLAN VNI, GRE key) that belong to the stream but not to an endpoint.
    pub key: &'static [KeyField],
    /// Direction rule. Default: D3 lexicographic endpoint ordering.
    pub canonicalize: Canonicalize,
    /// Optional lifecycle: how per-packet fields advance a session state machine (05.5).
    pub lifecycle: Option<LifecycleSpec>,
    /// Optional per-field retention beyond baseline stats (05.4).
    pub rollups: &'static [RollupSpec],
}

pub struct KeyField {
    pub a: FieldName,               // field naming endpoint-A's component, e.g. "src_mac"
    pub b: Option<FieldName>,       // endpoint-B's counterpart, e.g. "dst_mac"; None = shared
}

pub enum Canonicalize {
    /// D3: order endpoints lexicographically by their concatenated component bytes.
    EndpointSort,
    /// Protocol supplies its own rule (rare; escape hatch, must be deterministic).
    Custom(fn(&FieldMap) -> Result<(FlowKey, PacketDirection), KeyError>),
}

pub struct LifecycleSpec {
    pub initial: StateName,                                      // e.g. "new"
    pub advance: fn(&FieldMap, StateName, PacketDirection) -> StateName,
}

pub struct RollupSpec { pub field: FieldName, pub kind: RollupKind }
pub enum RollupKind {
    Accumulate,                     // bounded distinct-value set + count (D4)
    Sample,                         // first + last value
    Series { cap: usize },          // bounded time-ordered ring (D4 default cap 1024)
}
```

Rules:

- Every `KeyField` name must be a field the plugin extracts at depth ≥ `Keys` (01.3). The
  09.1 kit cross-checks declaration against actual parse output.
- **Examples** (normative for task 06): Ethernet → `[{src_mac, dst_mac}]`; IPv4 →
  `[{src_addr, dst_addr}]`; TCP → `[{src_port, dst_port}]` *(addresses come from the parent
  IP stream via hierarchy scoping, D10 — the TCP key does not re-embed IPs; the 5-tuple is
  the (IP-pair parent, port-pair, protocol) path in the tree)*; VXLAN → `[{vni, None}]`.
- `lifecycle.advance` is a pure function: (this packet's fields, current state, direction) →
  new state. The aggregator owns the state variable; the plugin owns the transition logic.
  TCP's flags→setup/established/teardown mapping (FR-6) is the reference implementation.
- A plugin returning `None` from `stream_identity()` dissects normally; its layer creates no
  stream and is skipped in hierarchy nesting (PRD §4.B.1) — e.g. VLAN contributes its tag as
  a rollup on the MAC conversation instead (06.2).

## Acceptance criteria
- [ ] Types implemented in `pktflow-core` (declaration) with construction validation where
      static (`Series { cap: 0 }` rejected).
- [ ] The 5-tuple-as-tree-path decision (TCP key = ports only) documented on `KeyField` —
      it is the design's least obvious consequence of D10.
- [ ] A test plugin declaring a 2-field endpoint key + `Sample` rollup round-trips through
      the (future) aggregator API types without engine-side protocol knowledge.
