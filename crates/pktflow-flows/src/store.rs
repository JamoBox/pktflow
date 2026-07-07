//! The stream store (05.2, FR-1, D5, D10): long-lived single-writer state —
//! stream records, the lookup index, baseline stats, and the per-packet
//! ingest path. This is the aggregator's hot loop.

use std::cmp::Reverse;
use std::collections::hash_map::DefaultHasher;
use std::collections::{BinaryHeap, HashMap};
use std::hash::BuildHasherDefault;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use pktflow_core::{
    DissectedPacket, Engine, FieldMap, FlowKey, PacketDirection, ProtocolName, StateName,
    StopClass, StreamIdentity,
};

use crate::key::flow_key;
use crate::rollup::RollupSet;

/// Deterministic hasher (PRD §7): correctness never depends on iteration
/// order (05.7 sorts explicitly), but debugging and snapshots benefit from
/// stability.
type DetHashMap<K, V> = HashMap<K, V, BuildHasherDefault<DefaultHasher>>;

/// Why a stream was closed/evicted (05.6, D2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CloseReason {
    ProtocolClose,
    IdleTimeout,
    LruEvicted,
    CaptureEnd,
}

/// The D2 hybrid policy, configured per run (mechanics land in 05.6).
pub enum EvictionPolicy {
    /// Offline default: no eviction; everything flushes at capture end.
    None,
    Live {
        idle_timeout: Duration,
        close_linger: Duration,
        max_streams: usize,
    },
}

/// A closed/evicted stream on its way to the sink (05.6).
pub struct EvictedStream {
    pub stream: Stream,
    pub reason: CloseReason,
}

pub struct AggregatorConfig {
    pub eviction: EvictionPolicy,
    /// Evicted/closed streams are emitted here before removal so callers
    /// can persist or count them (D2).
    pub sink: Option<Box<dyn FnMut(EvictedStream) + Send>>,
    /// D4 override point for `Series { cap: 0 }`-defaulted rollups.
    pub rollup_series_default_cap: usize,
}

impl Default for AggregatorConfig {
    fn default() -> Self {
        Self {
            eviction: EvictionPolicy::None,
            sink: None,
            rollup_series_default_cap: 1024,
        }
    }
}

/// Stable stream handle: slotmap-style index + generation, so a handle
/// held across an eviction fails the generation check instead of aliasing
/// a new stream (no ABA).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct StreamId {
    index: u32,
    generation: u32,
}

/// Per-direction baseline stats. `bytes` counts the packet's full wire
/// length (`origlen`) for every stream the packet belongs to — matching
/// how reference flow tools count (09.3 parity).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct DirStats {
    pub packets: u64,
    pub bytes: u64,
}

/// One conversation node (D10: unique per parent + protocol + key).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stream {
    pub id: StreamId,
    pub protocol: ProtocolName,
    pub key: FlowKey,
    /// Decoded endpoint fields for display (the key-named fields of the
    /// creating packet's layer).
    pub key_fields: FieldMap,
    pub parent: Option<StreamId>,
    /// Creation order (deterministic).
    pub children: Vec<StreamId>,
    /// Direction of the stream's first packet (D3) — not part of the key.
    pub initiator: PacketDirection,
    pub first_seen: SystemTime,
    pub last_seen: SystemTime,
    /// Indexed by [`dir_index`].
    pub stats: [DirStats; 2],
    /// D9 accounting: unparsed payload attributed to the innermost stream.
    pub opaque_bytes: u64,
    /// Lifecycle state (05.5); `None` = plain conversation, no lifecycle.
    pub state: Option<StateName>,
    pub rollups: RollupSet,
    pub closed: Option<CloseReason>,
    /// Entered a `closed_states` state; D2's linger applies (05.6).
    pub close_eligible: bool,
    /// Packet time of entry into a closed state — the linger deadline's
    /// anchor. Stragglers update stats without moving it (05.5/05.6).
    pub close_eligible_since: Option<SystemTime>,
    /// Insertion order for deterministic query sorting (05.7) — not a
    /// global ordering guarantee (keeps D5's sharding door open).
    pub created_seq: u64,
}

/// `stats` slot for a direction.
pub fn dir_index(dir: PacketDirection) -> usize {
    match dir {
        PacketDirection::AtoB => 0,
        PacketDirection::BtoA => 1,
    }
}

/// Fixed reporting order for stop classes (05.7 summary).
pub const STOP_CLASSES: [StopClass; 4] = [
    StopClass::Clean,
    StopClass::UnknownPayload,
    StopClass::Malformed,
    StopClass::Suspicious,
];

fn stop_class_index(class: StopClass) -> usize {
    match class {
        StopClass::Clean => 0,
        StopClass::UnknownPayload => 1,
        StopClass::Malformed => 2,
        StopClass::Suspicious => 3,
    }
}

/// D10 merged view row (05.7): same-key nodes folded across parents.
/// Rollups are not merged in v1 — drill down through `nodes`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MergedStreamView {
    pub protocol: ProtocolName,
    pub key: FlowKey,
    /// Display fields from the first node (identical canonical endpoints
    /// by construction — same key).
    pub key_fields: FieldMap,
    /// Summed per-direction stats across nodes.
    pub stats: [DirStats; 2],
    pub first_seen: SystemTime,
    pub last_seen: SystemTime,
    /// Back-references, creation order.
    pub nodes: Vec<StreamId>,
}

/// Per-protocol stream counts for the summary (FR-27).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ProtocolCounts {
    pub protocol: ProtocolName,
    pub ever: u64,
    pub live: u64,
}

/// Global counters (FR-27); eviction cannot distort these.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AggregateSummary {
    pub packets: u64,
    pub bytes: u64,
    pub streams_created: u64,
    pub streams_live: u64,
    pub key_errors: u64,
    /// Sorted by protocol name (deterministic).
    pub per_protocol: Vec<ProtocolCounts>,
    /// Packet counts in [`STOP_CLASSES`] order.
    pub stop_classes: [(StopClass, u64); 4],
}

/// Deep, immutable copy for cross-thread reads (D5): the aggregation
/// thread owns the `Aggregator`; UI threads consume snapshots.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregatorSnapshot {
    /// Every live stream, `created_seq` order.
    pub streams: Vec<Stream>,
    /// Root ids, creation order.
    pub roots: Vec<StreamId>,
    pub summary: AggregateSummary,
    pub clock: SystemTime,
}

struct Slot {
    generation: u32,
    stream: Option<Stream>,
}

/// Aggregate counters that survive eviction (FR-27): the end-of-run
/// summary cannot be distorted by memory bounds.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Totals {
    pub packets: u64,
    pub bytes: u64,
    pub streams_created: u64,
    /// Flow-key construction failures (05.1): plugin contract violations
    /// that 09.1 should have caught, counted, never fatal.
    pub key_errors: u64,
}

/// The single-writer stream aggregator (D5): exactly one thread mutates
/// it; `Send` so it can move to the aggregation thread.
pub struct Aggregator {
    engine: Arc<Engine>,
    config: AggregatorConfig,
    slots: Vec<Slot>,
    index: DetHashMap<(Option<StreamId>, ProtocolName, FlowKey), StreamId>,
    roots: Vec<StreamId>,
    totals: Totals,
    /// Packet-time clock: max seen timestamp (05.6 determinism).
    clock: SystemTime,
    next_seq: u64,
    /// D9 reporting: packets by stop class (04.3), in StopClass order.
    stop_classes: [u64; 4],
    /// Streams ever created per protocol (survives eviction, FR-27).
    created_per_protocol: DetHashMap<ProtocolName, u64>,
    /// Lazy expiry min-heap (05.6): entries carry the deadline known at
    /// push time; a popped entry whose stream has a later actual deadline
    /// is re-pushed, making the sweep O(evicted), not O(streams).
    expiry: BinaryHeap<Reverse<(SystemTime, u32, u32)>>,
    /// Recyclable slot indices (generation already bumped at evict).
    free: Vec<u32>,
    live_count: usize,
}

impl Aggregator {
    pub fn new(engine: &Arc<Engine>, config: AggregatorConfig) -> Self {
        Self {
            engine: Arc::clone(engine),
            config,
            slots: Vec::new(),
            index: DetHashMap::default(),
            roots: Vec::new(),
            totals: Totals::default(),
            clock: SystemTime::UNIX_EPOCH,
            next_seq: 0,
            stop_classes: [0; 4],
            created_per_protocol: DetHashMap::default(),
            expiry: BinaryHeap::new(),
            free: Vec::new(),
            live_count: 0,
        }
    }

    /// The one mutating entry point: fold one dissected packet into the
    /// store (the 05.2 ingest algorithm).
    pub fn ingest(&mut self, pkt: &DissectedPacket) {
        let ts = pkt.meta.timestamp;
        self.clock = self.clock.max(ts);
        self.totals.packets += 1;
        self.totals.bytes += pkt.meta.origlen as u64;
        self.stop_classes[stop_class_index(pkt.stop.class())] += 1;

        // Amortized timeout sweep (05.6): packet time only, no wall clock.
        self.sweep();

        // Local handle so plugin/identity borrows don't pin `self`.
        let engine = Arc::clone(&self.engine);

        let mut parent: Option<StreamId> = None;
        for layer in &pkt.layers {
            // A layer without a plugin or identity forms no stream and is
            // skipped in nesting (02.4) — the parent chain stays intact.
            let Some(plugin) = engine.plugin_by_name(layer.protocol) else {
                continue;
            };
            let Some(identity) = plugin.stream_identity() else {
                continue;
            };
            let (key, dir) = match flow_key(identity, &layer.fields) {
                Ok(kd) => kd,
                Err(_) => {
                    // Contract violation: count it, skip the layer, keep
                    // aggregating into parents (05.1).
                    self.totals.key_errors += 1;
                    continue;
                }
            };

            let id = self.get_or_insert(parent, key, identity, layer, dir, ts);
            let mut became_eligible = false;
            if let Some(stream) = self.get_mut(id) {
                stream.last_seen = ts;
                let slot = &mut stream.stats[dir_index(dir)];
                slot.packets += 1;
                slot.bytes += pkt.meta.origlen as u64;

                // Lifecycle (05.5): plugin-owned transition, engine-held state.
                if let (Some(spec), Some(current)) = (identity.lifecycle, stream.state) {
                    let next = (spec.advance)(&layer.fields, current, dir);
                    stream.state = Some(next);
                    let eligible = spec.closed_states.contains(&next);
                    if eligible && !stream.close_eligible {
                        // Linger anchors at closed-state entry (D2);
                        // stragglers won't move it.
                        stream.close_eligible_since = Some(ts);
                        became_eligible = true;
                    } else if !eligible {
                        stream.close_eligible_since = None;
                    }
                    stream.close_eligible = eligible;
                }

                stream.rollups.apply(&layer.fields, ts, dir);
            }
            // The linger deadline can undercut the standing idle entry, so
            // arm it eagerly; the lazy heap discards stale entries on pop.
            if became_eligible {
                if let EvictionPolicy::Live { close_linger, .. } = self.config.eviction {
                    self.expiry
                        .push(Reverse((ts + close_linger, id.index, id.generation)));
                }
            }
            parent = Some(id);
        }

        // D9: unparsed payload lands on the innermost real stream only.
        if let Some(innermost) = parent {
            if let Some(stream) = self.get_mut(innermost) {
                stream.opaque_bytes += pkt.opaque_len as u64;
            }
        }

        // Hard LRU cap (D2): evict least-recently-updated leaves.
        self.enforce_max_streams();
    }

    fn get_or_insert(
        &mut self,
        parent: Option<StreamId>,
        key: FlowKey,
        identity: &StreamIdentity,
        layer: &pktflow_core::LayerRecord,
        dir: PacketDirection,
        ts: SystemTime,
    ) -> StreamId {
        let protocol = layer.protocol;
        if let Some(&id) = self.index.get(&(parent, protocol, key.clone())) {
            return id;
        }

        // Decode the key-named endpoint fields for display.
        let mut key_fields = FieldMap::new();
        for kf in identity.key {
            for name in [Some(kf.a), kf.b].into_iter().flatten() {
                if let Some(v) = layer.fields.get(name) {
                    key_fields.insert(name, v.clone());
                }
            }
        }

        // Recycle an evicted slot (generation already bumped) or grow.
        let (index, generation) = match self.free.pop() {
            Some(index) => (
                index,
                self.slots
                    .get(index as usize)
                    .map_or(0, |slot| slot.generation),
            ),
            None => (u32::try_from(self.slots.len()).unwrap_or(u32::MAX), 0),
        };
        let id = StreamId { index, generation };
        let stream = Stream {
            id,
            protocol,
            key: key.clone(),
            key_fields,
            parent,
            children: Vec::new(),
            initiator: dir,
            first_seen: ts,
            last_seen: ts,
            stats: [DirStats::default(); 2],
            opaque_bytes: 0,
            state: identity.lifecycle.map(|l| l.initial),
            rollups: RollupSet::new(identity.rollups, self.config.rollup_series_default_cap),
            closed: None,
            close_eligible: false,
            close_eligible_since: None,
            created_seq: self.next_seq,
        };
        self.next_seq += 1;
        self.totals.streams_created += 1;
        *self.created_per_protocol.entry(protocol).or_insert(0) += 1;
        self.live_count += 1;
        match self.slots.get_mut(index as usize) {
            Some(slot) => slot.stream = Some(stream),
            None => self.slots.push(Slot {
                generation: 0,
                stream: Some(stream),
            }),
        }
        self.index.insert((parent, protocol, key), id);

        match parent.and_then(|p| self.get_mut(p)) {
            Some(parent_stream) => parent_stream.children.push(id),
            None => self.roots.push(id),
        }
        if let EvictionPolicy::Live { idle_timeout, .. } = self.config.eviction {
            self.expiry
                .push(Reverse((ts + idle_timeout, id.index, id.generation)));
        }
        id
    }

    /// A live stream's current expiry deadline under the Live policy:
    /// the earlier of `last_seen + idle` and `closed-entry + linger`.
    fn deadline_of(&self, id: StreamId) -> Option<SystemTime> {
        let EvictionPolicy::Live {
            idle_timeout,
            close_linger,
            ..
        } = self.config.eviction
        else {
            return None;
        };
        let stream = self.get(id)?;
        let idle = stream.last_seen + idle_timeout;
        Some(match stream.close_eligible_since {
            Some(entered) => idle.min(entered + close_linger),
            None => idle,
        })
    }

    /// Pops due expiry entries, evicting streams whose *actual* deadline
    /// has passed (packet time). Lazy heap: stale entries are re-pushed
    /// with the stream's real deadline, so work is O(evicted + stale
    /// pops), never O(streams). Parents with live children are skipped and
    /// re-armed by their last child's eviction (D2's leaf-first rule).
    fn sweep(&mut self) {
        let EvictionPolicy::Live { close_linger, .. } = self.config.eviction else {
            return;
        };
        let now = self.clock;
        while let Some(&Reverse((entry_deadline, index, generation))) = self.expiry.peek() {
            if entry_deadline > now {
                break;
            }
            self.expiry.pop();
            let id = StreamId { index, generation };
            let Some(actual) = self.deadline_of(id) else {
                continue; // evicted or recycled since this entry was pushed
            };
            if actual > now {
                self.expiry.push(Reverse((actual, index, generation)));
                continue;
            }
            let Some(stream) = self.get(id) else {
                continue;
            };
            if !stream.children.is_empty() {
                // Not a leaf: skipped, re-armed when its last child goes.
                continue;
            }
            let reason = match stream.close_eligible_since {
                Some(entered) if entered + close_linger <= now => CloseReason::ProtocolClose,
                _ => CloseReason::IdleTimeout,
            };
            self.evict(id, reason);
        }
    }

    /// D2's hard cap: while over `max_streams`, evict the
    /// least-recently-updated leaf (creation order breaks ties
    /// deterministically).
    fn enforce_max_streams(&mut self) {
        let EvictionPolicy::Live { max_streams, .. } = self.config.eviction else {
            return;
        };
        while self.live_count > max_streams {
            let lru = self
                .streams()
                .filter(|s| s.children.is_empty())
                .min_by_key(|s| (s.last_seen, s.created_seq))
                .map(|s| s.id);
            let Some(id) = lru else {
                return; // no leaves — cannot shrink further
            };
            self.evict(id, CloseReason::LruEvicted);
        }
    }

    /// Removes one live leaf: index entry gone (recurrence of the key
    /// creates a fresh stream), slot generation bumped (stale handles fail,
    /// no ABA), parent unlinked and re-armed for expiry, sink notified.
    fn evict(&mut self, id: StreamId, reason: CloseReason) {
        let Some(slot) = self.slots.get_mut(id.index as usize) else {
            return;
        };
        if slot.generation != id.generation {
            return;
        }
        let Some(mut stream) = slot.stream.take() else {
            return;
        };
        slot.generation = slot.generation.wrapping_add(1);
        self.free.push(id.index);
        self.live_count -= 1;

        self.index
            .remove(&(stream.parent, stream.protocol, stream.key.clone()));
        match stream.parent {
            Some(parent_id) => {
                if let Some(parent) = self.get_mut(parent_id) {
                    parent.children.retain(|c| *c != id);
                }
                // The parent may have just become an evictable leaf.
                if let Some(deadline) = self.deadline_of(parent_id) {
                    self.expiry
                        .push(Reverse((deadline, parent_id.index, parent_id.generation)));
                }
            }
            None => self.roots.retain(|r| *r != id),
        }

        stream.closed = Some(reason);
        if let Some(sink) = &mut self.config.sink {
            sink(EvictedStream { stream, reason });
        }
    }

    /// Explicit end-of-capture (05.6): closes every remaining stream with
    /// `CaptureEnd`, children before parents, through the sink. Offline
    /// (`EvictionPolicy::None`) retains the closed streams for the final
    /// report; live mode drops them post-sink.
    pub fn finish(&mut self) {
        // Bottom-up: deeper nodes first, creation order within a depth.
        let mut order: Vec<(usize, u64, StreamId)> = self
            .streams()
            .map(|s| {
                let mut depth = 0;
                let mut cursor = s.parent;
                while let Some(pid) = cursor {
                    depth += 1;
                    cursor = self.get(pid).and_then(|p| p.parent);
                }
                (depth, s.created_seq, s.id)
            })
            .collect();
        order.sort_by_key(|&(depth, seq, _)| (Reverse(depth), seq));

        let live = matches!(self.config.eviction, EvictionPolicy::Live { .. });
        for (_, _, id) in order {
            if live {
                self.evict(id, CloseReason::CaptureEnd);
            } else if let Some(stream) = self.get_mut(id) {
                stream.closed = Some(CloseReason::CaptureEnd);
                let copy = stream.clone();
                if let Some(sink) = &mut self.config.sink {
                    sink(EvictedStream {
                        stream: copy,
                        reason: CloseReason::CaptureEnd,
                    });
                }
            }
        }
    }

    /// Generation-checked lookup: a stale handle returns `None`, never a
    /// different stream (no ABA).
    pub fn get(&self, id: StreamId) -> Option<&Stream> {
        let slot = self.slots.get(id.index as usize)?;
        if slot.generation != id.generation {
            return None;
        }
        slot.stream.as_ref()
    }

    fn get_mut(&mut self, id: StreamId) -> Option<&mut Stream> {
        let slot = self.slots.get_mut(id.index as usize)?;
        if slot.generation != id.generation {
            return None;
        }
        slot.stream.as_mut()
    }

    /// Root streams (no parent), creation order (05.7).
    pub fn roots(&self) -> impl Iterator<Item = &Stream> {
        self.roots.iter().filter_map(|&id| self.get(id))
    }

    /// Live streams, arena order (queries sort explicitly, 05.7).
    pub fn streams(&self) -> impl Iterator<Item = &Stream> {
        self.slots.iter().filter_map(|s| s.stream.as_ref())
    }

    /// Live stream count.
    pub fn len(&self) -> usize {
        self.streams().count()
    }

    pub fn is_empty(&self) -> bool {
        self.streams().next().is_none()
    }

    /// Spec-named lookup (05.7); alias of [`Aggregator::get`].
    pub fn stream(&self, id: StreamId) -> Option<&Stream> {
        self.get(id)
    }

    /// A stream's children, creation order (05.7).
    pub fn children(&self, id: StreamId) -> impl Iterator<Item = &Stream> {
        self.get(id)
            .map(|s| s.children.as_slice())
            .unwrap_or(&[])
            .iter()
            .filter_map(|&child| self.get(child))
    }

    /// All stream nodes of one protocol (FR-24's data source), sorted by
    /// `created_seq` — never hash-map order (PRD §7).
    pub fn at_layer(&self, protocol: &str) -> Vec<&Stream> {
        let mut nodes: Vec<&Stream> = self.streams().filter(|s| s.protocol == protocol).collect();
        nodes.sort_by_key(|s| s.created_seq);
        nodes
    }

    /// D10 merged view (05.7): same-key nodes folded across parents,
    /// stats summed lazily; row order = first node's creation order.
    pub fn at_layer_merged(&self, protocol: &str) -> Vec<MergedStreamView> {
        let mut rows: Vec<MergedStreamView> = Vec::new();
        for node in self.at_layer(protocol) {
            match rows.iter_mut().find(|row| row.key == node.key) {
                Some(row) => {
                    for d in 0..2 {
                        row.stats[d].packets += node.stats[d].packets;
                        row.stats[d].bytes += node.stats[d].bytes;
                    }
                    row.first_seen = row.first_seen.min(node.first_seen);
                    row.last_seen = row.last_seen.max(node.last_seen);
                    row.nodes.push(node.id);
                }
                None => rows.push(MergedStreamView {
                    protocol: node.protocol,
                    key: node.key.clone(),
                    key_fields: node.key_fields.clone(),
                    stats: node.stats,
                    first_seen: node.first_seen,
                    last_seen: node.last_seen,
                    nodes: vec![node.id],
                }),
            }
        }
        rows
    }

    /// Global counters (FR-27), deterministic ordering throughout.
    pub fn summary(&self) -> AggregateSummary {
        let mut per_protocol: Vec<ProtocolCounts> = self
            .created_per_protocol
            .iter()
            .map(|(&protocol, &ever)| ProtocolCounts {
                protocol,
                ever,
                live: 0,
            })
            .collect();
        per_protocol.sort_by_key(|c| c.protocol);
        for stream in self.streams() {
            if let Some(counts) = per_protocol
                .iter_mut()
                .find(|c| c.protocol == stream.protocol)
            {
                counts.live += 1;
            }
        }
        let mut stop_classes = [(StopClass::Clean, 0); 4];
        for (slot, &class) in stop_classes.iter_mut().zip(STOP_CLASSES.iter()) {
            *slot = (class, self.stop_classes[stop_class_index(class)]);
        }
        AggregateSummary {
            packets: self.totals.packets,
            bytes: self.totals.bytes,
            streams_created: self.totals.streams_created,
            streams_live: self.live_count as u64,
            key_errors: self.totals.key_errors,
            per_protocol,
            stop_classes,
        }
    }

    /// Deep, immutable copy for cross-thread reads (05.7, D5). Cost is
    /// bounded by `max_streams`; measured in 09.4.
    pub fn snapshot(&self) -> AggregatorSnapshot {
        let mut streams: Vec<Stream> = self.streams().cloned().collect();
        streams.sort_by_key(|s| s.created_seq);
        AggregatorSnapshot {
            streams,
            roots: self.roots.clone(),
            summary: self.summary(),
            clock: self.clock,
        }
    }

    /// Aggregate counters (survive eviction, FR-27).
    pub fn totals(&self) -> Totals {
        self.totals
    }

    /// Current packet-time clock.
    pub fn clock(&self) -> SystemTime {
        self.clock
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use pktflow_core::{
        Canonicalize, KeyField, LayerPlugin, LayerRecord, LinkType, PacketMeta, ParseCtx,
        ParseError, ParsedLayer, StopReason, Value,
    };

    use super::*;

    // Aggregator moves to the aggregation thread (D5).
    const _: fn() = || {
        fn assert_send<T: Send>() {}
        assert_send::<Aggregator>();
    };

    /// Identity-bearing test plugin; ingest never calls parse.
    struct Keyed {
        name: ProtocolName,
        identity: Option<StreamIdentity>,
    }

    impl LayerPlugin for Keyed {
        fn name(&self) -> ProtocolName {
            self.name
        }

        fn parse(&self, _bytes: &[u8], _ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
            Err(ParseError::Malformed("ingest-only test plugin"))
        }

        fn stream_identity(&self) -> Option<&StreamIdentity> {
            self.identity.as_ref()
        }
    }

    static PAIR_KEY: &[KeyField] = &[KeyField {
        a: "src",
        b: Some("dst"),
    }];

    fn pair_identity() -> StreamIdentity {
        StreamIdentity {
            key: PAIR_KEY,
            canonicalize: Canonicalize::EndpointSort,
            lifecycle: None,
            rollups: &[],
        }
    }

    fn keyed(name: ProtocolName) -> Keyed {
        Keyed {
            name,
            identity: Some(pair_identity()),
        }
    }

    fn plain(name: ProtocolName) -> Keyed {
        Keyed {
            name,
            identity: None,
        }
    }

    fn engine() -> Arc<Engine> {
        Arc::new(
            Engine::builder()
                .plugin(keyed("eth"))
                .plugin(plain("vlan"))
                .plugin(keyed("ip"))
                .plugin(keyed("badkey"))
                .build()
                .expect("valid registry"),
        )
    }

    fn layer(protocol: ProtocolName, src: u64, dst: u64) -> LayerRecord {
        let mut fields = FieldMap::new();
        fields.insert("src", Value::U64(src));
        fields.insert("dst", Value::U64(dst));
        LayerRecord {
            protocol,
            offset: 0,
            header_len: 0,
            fields,
        }
    }

    fn packet(
        layers: Vec<LayerRecord>,
        origlen: usize,
        opaque_len: usize,
        ms: u64,
    ) -> DissectedPacket {
        DissectedPacket {
            meta: PacketMeta {
                timestamp: SystemTime::UNIX_EPOCH + Duration::from_millis(ms),
                caplen: origlen,
                origlen,
                link_type: LinkType::ETHERNET,
            },
            layers,
            stop: StopReason::Complete,
            opaque_len,
            unknown: None,
        }
    }

    fn aggregator() -> Aggregator {
        Aggregator::new(&engine(), AggregatorConfig::default())
    }

    #[test]
    fn two_packet_bidirectional_fixture_yields_one_stream() {
        let mut agg = aggregator();
        // 1 < 2 in the encoding, so src=1 is endpoint A: A→B first.
        agg.ingest(&packet(vec![layer("eth", 1, 2)], 60, 0, 0));
        agg.ingest(&packet(vec![layer("eth", 2, 1)], 60, 0, 1));

        assert_eq!(agg.len(), 1);
        let stream = agg.streams().next().expect("one stream");
        assert_eq!(stream.protocol, "eth");
        assert_eq!(stream.initiator, PacketDirection::AtoB);
        assert_eq!(
            stream.stats[dir_index(PacketDirection::AtoB)],
            DirStats {
                packets: 1,
                bytes: 60
            }
        );
        assert_eq!(
            stream.stats[dir_index(PacketDirection::BtoA)],
            DirStats {
                packets: 1,
                bytes: 60
            }
        );
        assert_eq!(agg.totals().packets, 2);
        assert_eq!(agg.totals().bytes, 120);
    }

    #[test]
    fn identity_less_vlan_bridges_the_parent_chain() {
        let mut agg = aggregator();
        agg.ingest(&packet(
            vec![layer("eth", 1, 2), layer("vlan", 0, 0), layer("ip", 10, 20)],
            100,
            0,
            0,
        ));

        assert_eq!(agg.len(), 2, "vlan forms no stream");
        let eth = agg
            .streams()
            .find(|s| s.protocol == "eth")
            .expect("eth stream");
        let ip = agg
            .streams()
            .find(|s| s.protocol == "ip")
            .expect("ip stream");
        assert_eq!(eth.parent, None);
        assert_eq!(ip.parent, Some(eth.id), "ip parented to eth across vlan");
        assert_eq!(eth.children, vec![ip.id]);
        let root_ids: Vec<_> = agg.roots().map(|r| r.id).collect();
        assert_eq!(root_ids, [eth.id]);
    }

    #[test]
    fn key_error_skips_layer_but_parents_still_update() {
        let mut agg = aggregator();
        // badkey's fields lack "dst" → MissingField; ip must still parent
        // to eth, and eth still counts the packet.
        let mut broken = layer("badkey", 5, 0);
        broken.fields = {
            let mut m = FieldMap::new();
            m.insert("src", Value::U64(5)); // no dst
            m
        };
        agg.ingest(&packet(
            vec![layer("eth", 1, 2), broken, layer("ip", 10, 20)],
            80,
            0,
            0,
        ));

        assert_eq!(agg.totals().key_errors, 1, "diagnostic counter bumped");
        assert_eq!(agg.len(), 2, "broken layer forms no stream");
        let eth = agg.streams().find(|s| s.protocol == "eth").expect("eth");
        let ip = agg.streams().find(|s| s.protocol == "ip").expect("ip");
        assert_eq!(eth.stats[0].packets + eth.stats[1].packets, 1);
        assert_eq!(ip.parent, Some(eth.id), "chain intact past the bad layer");
    }

    #[test]
    fn opaque_bytes_land_on_the_innermost_stream_only() {
        let mut agg = aggregator();
        agg.ingest(&packet(
            vec![layer("eth", 1, 2), layer("ip", 10, 20)],
            90,
            17,
            0,
        ));
        let eth = agg.streams().find(|s| s.protocol == "eth").expect("eth");
        let ip = agg.streams().find(|s| s.protocol == "ip").expect("ip");
        assert_eq!(eth.opaque_bytes, 0);
        assert_eq!(ip.opaque_bytes, 17);
    }

    #[test]
    fn d10_scoping_same_key_under_different_parents_is_two_nodes() {
        let mut agg = aggregator();
        // Same ip pair under two different eth conversations.
        agg.ingest(&packet(
            vec![layer("eth", 1, 2), layer("ip", 10, 20)],
            60,
            0,
            0,
        ));
        agg.ingest(&packet(
            vec![layer("eth", 3, 4), layer("ip", 10, 20)],
            60,
            0,
            1,
        ));

        let ip_nodes: Vec<_> = agg.streams().filter(|s| s.protocol == "ip").collect();
        assert_eq!(ip_nodes.len(), 2, "one ip node per parent (D10)");
        assert_ne!(ip_nodes[0].parent, ip_nodes[1].parent);
    }

    #[test]
    fn stale_stream_id_generation_fails_lookup() {
        let agg = aggregator();
        let bogus = StreamId {
            index: 0,
            generation: 7,
        };
        assert!(agg.get(bogus).is_none());
    }
}
