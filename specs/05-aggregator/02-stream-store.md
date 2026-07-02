# 05.2 — Stream store

> Task: [05 Aggregator](README.md) · Depends on: 05.1 · PRD: FR-1, FR-5 baseline, §4.A "stateful over the capture" · D5, D10

## Goal
The long-lived, single-writer state: stream records, the lookup index, baseline stats, and
the per-packet ingest path that updates them — the aggregator's hot loop.

## Specification

```rust
pub struct Aggregator { /* config, arena, index, roots, clock, evictor, sink */ }

// stable handle; slotmap-style generational key (survives evictions without ABA)
pub struct StreamId(/* index + generation */);

pub struct Stream {
    pub id: StreamId,
    pub protocol: ProtocolName,
    pub key: FlowKey,
    pub key_fields: FieldMap,          // decoded endpoint fields for display (A-side, B-side)
    pub parent: Option<StreamId>,      // hierarchy (05.3)
    pub children: Vec<StreamId>,
    pub initiator: PacketDirection,    // direction of first packet (D3)
    pub first_seen: SystemTime,
    pub last_seen: SystemTime,
    pub stats: [DirStats; 2],          // indexed by PacketDirection
    pub opaque_bytes: u64,             // D9 accounting (innermost stream only)
    pub state: Option<StateName>,      // lifecycle (05.5)
    pub rollups: RollupSet,            // (05.4)
    pub closed: Option<CloseReason>,   // (05.6)
}
pub struct DirStats { pub packets: u64, pub bytes: u64 }  // bytes = origlen share, see below

impl Aggregator {
    pub fn new(engine: &Arc<Engine>, config: AggregatorConfig) -> Self;
    pub fn ingest(&mut self, pkt: &DissectedPacket);        // the one mutating entry point
    // queries in 05.7; eviction in 05.6
}
```

Ingest algorithm per packet:

```text
parent = None
for layer in pkt.layers (outermost → innermost):
    identity = engine.plugin(layer.protocol).stream_identity()
    if identity is None: continue                    # layer doesn't form streams (02.4)
    (key, dir) = build_key(layer, identity)          # 05.1; on KeyError: count + continue
    id = index.get_or_insert((parent, layer.protocol, key))   # D10 scoping
    stream = &mut arena[id]
    update: last_seen, stats[dir] += (1, pkt.meta.origlen), lifecycle (05.5), rollups (05.4)
    touch eviction order (05.6)
    parent = Some(id)
innermost = parent; if innermost: arena[innermost].opaque_bytes += pkt.opaque_len
```

Decisions:

- **Byte accounting:** every stream a packet belongs to counts the packet's full `origlen`
  (wire bytes). Per-layer payload accounting is a rollup a plugin can request, not baseline —
  matches how reference flow tools (Wireshark conversations) count, easing 09.3 parity.
- **Index:** `HashMap<(Option<StreamId>, ProtocolName, FlowKey), StreamId>` with a
  deterministic hasher seed (PRD §7 determinism — default RandomState would still be
  correct, but debugging and snapshot tests benefit from stable iteration; iteration order
  must anyway never leak into output: 05.7 sorts explicitly).
- **Single-writer** (D5): `&mut self` ingest, no locks. `Aggregator: Send` so it can move to
  the aggregation thread.
- Insertion order is recorded (`created_seq: u64` per stream) purely for deterministic
  sorting in queries — not exposed as a global ordering guarantee (keeps D5's sharding door open).

## Acceptance criteria
- [ ] Ingest implemented; a 2-packet A→B / B→A fixture yields one stream, `stats[AtoB] =
      stats[BtoA] = (1, len)`, `initiator = AtoB`.
- [ ] Identity-less middle layer (VLAN) correctly bridges: eth stream → ip stream parented
      to eth (VLAN skipped, parent chain intact).
- [ ] `opaque_bytes` lands on the innermost stream only.
- [ ] Ingest of 100k synthetic packets across 10k streams stays allocation-sane (no per-
      packet key heap allocation for common protocols — ties to 05.1 SmallVec criterion).
