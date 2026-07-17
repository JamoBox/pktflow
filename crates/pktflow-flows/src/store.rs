//! The stream store (05.2, FR-1, D5, D10): long-lived single-writer state —
//! stream records, the lookup index, baseline stats, and the per-packet
//! ingest path. This is the aggregator's hot loop.

use std::cmp::Reverse;
use std::collections::hash_map::DefaultHasher;
use std::collections::{BinaryHeap, HashMap};
use std::hash::{BuildHasherDefault, Hash, Hasher};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use smallvec::SmallVec;

use pktflow_core::{
    CondenseSpec, DissectedPacket, Engine, FieldMap, FieldName, FlowKey, PacketDirection,
    ProtocolName, StateName, StopClass, StreamIdentity, Value,
};

use crate::key::{encode_value, flow_key, KeyBuf};
use crate::rollup::RollupSet;
use crate::unknown::{
    EndpointKey, UnknownGroup, UnknownKey, UnknownRegistry, UnknownRegistryConfig,
};

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
    /// D16 (12.3): live same-anchor flows beyond this fold into one
    /// condensed node. 0 disables condensation entirely.
    pub condense_threshold: usize,
    /// D4 override point for `Series { cap: 0 }`-defaulted rollups.
    pub rollup_series_default_cap: usize,
    /// 12.2: clamp applied over every series cap, including
    /// plugin-declared explicit ones; `None` = unclamped (today's
    /// behavior). Interactive front-ends set this — a browsable view
    /// doesn't need a thousand retained points per stream.
    pub rollup_series_max_cap: Option<usize>,
    /// 10.2/D11 bounding knobs for the unknown-occurrence registry.
    pub unknown: UnknownRegistryConfig,
}

impl Default for AggregatorConfig {
    fn default() -> Self {
        Self {
            eviction: EvictionPolicy::None,
            sink: None,
            condense_threshold: DEFAULT_CONDENSE_THRESHOLD,
            rollup_series_default_cap: 1024,
            rollup_series_max_cap: None,
            unknown: UnknownRegistryConfig::default(),
        }
    }
}

/// D16's default K: the number of live same-anchor flows a group shows
/// individually before further ones condense.
pub const DEFAULT_CONDENSE_THRESHOLD: usize = 256;

/// Cap on the distinct-member tally a condensed group keeps (a u64
/// digest per member): covers a full u16 port space exactly; beyond it
/// the node reports a lower bound with `overflow` set (D4 honesty).
const CONDENSE_MEMBER_CAP: usize = 65_536;

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

/// D16 (12.3): what a condensed node knows about its folded members.
/// A member flow is identified within its group by the varying side's
/// value, so the member count *is* the distinct-ephemeral tally.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CondensedInfo {
    /// Distinct member flows folded in — exact until `overflow`, a
    /// lower bound after.
    pub member_flows: u64,
    /// The varying pair's anchor-side field name (e.g. `"src_port"`) —
    /// the one key field a condensed node's `key_fields` carries.
    pub ephemeral_field: FieldName,
    /// The member tally hit [`CONDENSE_MEMBER_CAP`]; counts are lower
    /// bounds from here on (never silently wrong, D4).
    pub overflow: bool,
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
    /// D16 (12.3): `Some` = this node is a condensed group, not a
    /// single conversation. Boxed: ordinary streams pay one pointer.
    pub condensed: Option<Box<CondensedInfo>>,
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

/// Per-protocol stream counts for the summary (FR-27). `live` and
/// `bytes` are maintained incrementally (12.1/D17.1): `summary()` never
/// scans the live set.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ProtocolCounts {
    pub protocol: ProtocolName,
    pub ever: u64,
    pub live: u64,
    /// Stats bytes summed over live streams of this protocol (the web
    /// UI's protocol chart); opaque bytes excluded, matching
    /// `total_bytes`.
    pub bytes: u64,
}

/// Global counters (FR-27); eviction cannot distort these.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AggregateSummary {
    pub packets: u64,
    pub bytes: u64,
    pub streams_created: u64,
    pub streams_live: u64,
    /// D16: member flows folded into condensed nodes — included in
    /// `streams_created`, so nothing is silently absorbed
    /// (`streams_created == expanded creations + flows_condensed`).
    pub flows_condensed: u64,
    pub key_errors: u64,
    /// Sorted by protocol name (deterministic).
    pub per_protocol: Vec<ProtocolCounts>,
    /// Packet counts in [`STOP_CLASSES`] order.
    pub stop_classes: [(StopClass, u64); 4],
}

/// Immutable view for cross-thread reads (D5): the aggregation thread
/// owns the `Aggregator`; UI threads consume snapshots. Stream records
/// are structurally shared with the store (12.1/D17.1): consecutive
/// snapshots share every record untouched between them, and the store
/// pays a copy only when mutating a record a snapshot still holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregatorSnapshot {
    /// Every live stream, `created_seq` order.
    pub streams: Vec<Arc<Stream>>,
    /// Root ids, creation order.
    pub roots: Vec<StreamId>,
    pub summary: AggregateSummary,
    pub clock: SystemTime,
    /// 10.2's registry, [`Aggregator::unknowns`] order (`count` desc).
    pub unknowns: Vec<UnknownGroup>,
}

/// Streams live behind copy-on-write handles (12.1/D17.1): `snapshot()`
/// collects `Arc` clones, and `Arc::make_mut` on the mutation path pays
/// a deep copy only for a record some snapshot still shares.
struct Slot {
    generation: u32,
    stream: Option<Arc<Stream>>,
}

/// Aggregate counters that survive eviction (FR-27): the end-of-run
/// summary cannot be distorted by memory bounds.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Totals {
    pub packets: u64,
    pub bytes: u64,
    pub streams_created: u64,
    /// D16: member flows folded into condensed nodes (also counted in
    /// `streams_created`).
    pub flows_condensed: u64,
    /// Flow-key construction failures (05.1): plugin contract violations
    /// that 09.1 should have caught, counted, never fatal.
    pub key_errors: u64,
}

/// D16 group state, aggregator-side (never cloned into snapshots): one
/// entry per candidate anchor of a live expanded flow, plus the
/// member-digest set once the group condenses.
#[derive(Default)]
struct CondenseGroup {
    /// Live expanded flows this anchor is a side of; the trigger count.
    expanded: u32,
    /// The condensed node, once triggered (created lazily by the first
    /// flow to fold).
    node: Option<StreamId>,
    /// Digests of the varying-side values folded in (= member flows).
    members: std::collections::HashSet<u64, BuildHasherDefault<DefaultHasher>>,
}

/// Group key: parent scope + protocol + the anchor encoding (every
/// non-ephemeral key component, `identity.key` order with pairs
/// endpoint-sorted, then the anchor side's value).
type CondenseKey = (Option<StreamId>, ProtocolName, KeyBuf);

/// Sentinel first byte of a condensed node's synthesized flow key —
/// no `EndpointSort` encoding starts with it (value tags are
/// 0–5/255), so it can never alias a real flow's key.
const CONDENSED_KEY_SENTINEL: u8 = 0xFE;

/// One candidate anchor of a flow under a condense declaration: the
/// group encoding, what to display for it, the varying side's digest
/// (the member identity within the group), and the packet's direction
/// with A defined as the anchor side.
struct CondenseCandidate {
    anchor: KeyBuf,
    anchor_field: FieldName,
    anchor_value: Value,
    varying_digest: u64,
    fold_dir: PacketDirection,
}

fn value_encoding(v: &Value) -> KeyBuf {
    let mut out = KeyBuf::new();
    encode_value(v, &mut out);
    out
}

fn encoding_digest(buf: &KeyBuf) -> u64 {
    let mut hasher = DefaultHasher::default();
    buf.hash(&mut hasher);
    hasher.finish()
}

/// The flow's two candidate anchors (one per side of the ephemeral
/// pair; self-talk yields one). The anchor encoding is every
/// non-ephemeral key component (`identity.key` order, pairs
/// endpoint-sorted so it's direction-agnostic) followed by the anchor
/// side's value — the same encoding whichever side the anchor appears
/// on in a given packet. `None` if any key field is absent.
fn condense_candidates(
    identity: &StreamIdentity,
    spec: &CondenseSpec,
    fields: &FieldMap,
) -> Option<[Option<CondenseCandidate>; 2]> {
    let eph = spec.ephemeral;
    let b_name = eph.b?;
    let va = fields.get(eph.a)?;
    let vb = fields.get(b_name)?;

    let mut prefix = KeyBuf::new();
    for kf in identity.key {
        if kf.a == eph.a && kf.b == eph.b {
            continue;
        }
        match kf.b {
            None => encode_value(fields.get(kf.a)?, &mut prefix),
            Some(b) => {
                let ea = value_encoding(fields.get(kf.a)?);
                let eb = value_encoding(fields.get(b)?);
                let (lo, hi) = if ea <= eb { (&ea, &eb) } else { (&eb, &ea) };
                prefix.extend_from_slice(lo);
                prefix.extend_from_slice(hi);
            }
        }
    }

    let enc_a = value_encoding(va);
    let enc_b = value_encoding(vb);
    let mut anchor_a = prefix.clone();
    anchor_a.extend_from_slice(&enc_a);
    let first = CondenseCandidate {
        anchor: anchor_a,
        anchor_field: eph.a,
        anchor_value: va.clone(),
        varying_digest: encoding_digest(&enc_b),
        // The packet's source is the anchor: A (= anchor) sends.
        fold_dir: PacketDirection::AtoB,
    };
    let second = if enc_a == enc_b {
        None // self-talk: one group, direction pinned like D3 does
    } else {
        let mut anchor_b = prefix;
        anchor_b.extend_from_slice(&enc_b);
        Some(CondenseCandidate {
            anchor: anchor_b,
            anchor_field: b_name,
            anchor_value: vb.clone(),
            varying_digest: encoding_digest(&enc_a),
            // The packet's destination is the anchor: B → A.
            fold_dir: PacketDirection::BtoA,
        })
    };
    Some([Some(first), second])
}

/// The single-writer stream aggregator (D5): exactly one thread mutates
/// it; `Send` so it can move to the aggregation thread.
pub struct Aggregator {
    engine: Arc<Engine>,
    config: AggregatorConfig,
    slots: Vec<Slot>,
    /// Lookup index, keyed on a deterministic hash of the flow key
    /// instead of a second full copy (12.2); a hit compares the
    /// stream's own key, so hash collisions cost a probe, never a
    /// misattribution.
    index: DetHashMap<(Option<StreamId>, ProtocolName, u64), SmallVec<[StreamId; 1]>>,
    roots: Vec<StreamId>,
    totals: Totals,
    /// Packet-time clock: max seen timestamp (05.6 determinism).
    clock: SystemTime,
    next_seq: u64,
    /// D9 reporting: packets by stop class (04.3), in StopClass order.
    stop_classes: [u64; 4],
    /// Streams ever created per protocol (survives eviction, FR-27).
    created_per_protocol: DetHashMap<ProtocolName, u64>,
    /// Live streams per protocol, maintained on create/evict (12.1):
    /// `summary()` must not scan the live set.
    live_per_protocol: DetHashMap<ProtocolName, u64>,
    /// Stats bytes over live streams per protocol, maintained on
    /// ingest/evict (12.1) — feeds `ProtocolCounts::bytes`.
    live_bytes_per_protocol: DetHashMap<ProtocolName, u64>,
    /// Lazy expiry min-heap (05.6): entries carry the deadline known at
    /// push time; a popped entry whose stream has a later actual deadline
    /// is re-pushed, making the sweep O(evicted), not O(streams).
    expiry: BinaryHeap<Reverse<(SystemTime, u32, u32)>>,
    /// Lazy LRU min-heap (12.2): `(last_seen, created_seq, index,
    /// generation)` — the D2 hard cap's candidate order, same lazy
    /// discipline as `expiry` (stale entries re-pushed with accurate
    /// values, non-leaves discarded and re-armed by their last child's
    /// eviction), so `enforce_max_streams` is O(log n) amortized per
    /// eviction instead of a full scan.
    lru: BinaryHeap<Reverse<(SystemTime, u64, u32, u32)>>,
    /// Recyclable slot indices (generation already bumped at evict).
    free: Vec<u32>,
    live_count: usize,
    /// 10.2: capture-wide, independent of stream storage/eviction (D11).
    unknowns: UnknownRegistry,
    /// D16 (12.3): per-anchor fan-out tallies and condensed-group state.
    condense: DetHashMap<CondenseKey, CondenseGroup>,
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
            live_per_protocol: DetHashMap::default(),
            live_bytes_per_protocol: DetHashMap::default(),
            expiry: BinaryHeap::new(),
            lru: BinaryHeap::new(),
            free: Vec::new(),
            live_count: 0,
            unknowns: UnknownRegistry::new(),
            condense: DetHashMap::default(),
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
        // Amortized LRU-heap debris bound (12.2); O(1) when under limit.
        self.compact_lru();

        // Local handle so plugin/identity borrows don't pin `self`.
        let engine = Arc::clone(&self.engine);

        let mut parent: Option<StreamId> = None;
        // 10.2: the innermost identity-bearing layer's (protocol, key) at
        // the point dissection stopped — best-effort context for an
        // unknown occurrence, reusing the key already computed here rather
        // than re-deriving one.
        let mut last_endpoint: Option<EndpointKey> = None;
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

            last_endpoint = Some(EndpointKey {
                protocol: layer.protocol,
                key: key.clone(),
            });
            let (id, dir) =
                self.get_or_insert(parent, key, identity, plugin.condense(), layer, dir, ts);
            *self
                .live_bytes_per_protocol
                .entry(layer.protocol)
                .or_insert(0) += pkt.meta.origlen as u64;
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

                let base = stream.first_seen;
                stream.rollups.apply(&layer.fields, base, ts, dir);
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

        // 10.2: additive to this same ingest, not a separate pipeline stage.
        if let Some(diag) = &pkt.unknown {
            let bytes = u32::try_from(pkt.opaque_len).unwrap_or(u32::MAX);
            self.unknowns
                .ingest(diag, bytes, ts, last_endpoint, self.config.unknown);
        }

        // Hard LRU cap (D2): evict least-recently-updated leaves.
        self.enforce_max_streams();
    }

    /// D16 bookkeeping on eviction: an expanded flow's anchors lose a
    /// tally (empty pre-trigger groups are dropped); a condensed node's
    /// group is removed entirely — recurrence of the shape starts a
    /// fresh count, matching 05.6's re-keying rule.
    fn condense_evict(&mut self, stream: &Stream) {
        if self.config.condense_threshold == 0 {
            return;
        }
        if stream.condensed.is_some() {
            let ckey = (
                stream.parent,
                stream.protocol,
                KeyBuf::from_slice(&stream.key.as_bytes()[1..]),
            );
            self.condense.remove(&ckey);
            return;
        }
        let engine = Arc::clone(&self.engine);
        let Some(plugin) = engine.plugin_by_name(stream.protocol) else {
            return;
        };
        let Some(spec) = plugin.condense() else {
            return;
        };
        let Some(identity) = plugin.stream_identity() else {
            return;
        };
        // `key_fields` retains every key-named field, so the anchors
        // reconstruct exactly as they were tallied at creation.
        if let Some(candidates) = condense_candidates(identity, spec, &stream.key_fields) {
            for candidate in candidates.iter().flatten() {
                let ckey = (stream.parent, stream.protocol, candidate.anchor.clone());
                if let Some(group) = self.condense.get_mut(&ckey) {
                    group.expanded = group.expanded.saturating_sub(1);
                    if group.expanded == 0 && group.node.is_none() {
                        self.condense.remove(&ckey);
                    }
                }
            }
        }
    }

    /// Deterministic flow-key digest for the lookup index (12.2):
    /// `DefaultHasher` from `BuildHasherDefault` has fixed keys, so the
    /// digest is stable across runs (PRD §7).
    fn key_hash(key: &FlowKey) -> u64 {
        let mut hasher = DefaultHasher::default();
        key.hash(&mut hasher);
        hasher.finish()
    }

    /// Resolves a layer to its stream node: the fast index hit, the D16
    /// fold-in/trigger paths, or a fresh expanded stream. Returns the
    /// node plus the direction to attribute the packet with — the
    /// canonical per-flow `dir` normally, the anchor-relative direction
    /// (A = anchor side) when the packet folded into a condensed node.
    #[allow(clippy::too_many_arguments)]
    fn get_or_insert(
        &mut self,
        parent: Option<StreamId>,
        key: FlowKey,
        identity: &StreamIdentity,
        condense: Option<&CondenseSpec>,
        layer: &pktflow_core::LayerRecord,
        dir: PacketDirection,
        ts: SystemTime,
    ) -> (StreamId, PacketDirection) {
        let protocol = layer.protocol;
        let key_hash = Self::key_hash(&key);
        if let Some(bucket) = self.index.get(&(parent, protocol, key_hash)) {
            for &id in bucket {
                if self.get(id).is_some_and(|s| s.key == key) {
                    return (id, dir);
                }
            }
        }

        // D16: an index miss under a condense declaration checks the
        // flow's two candidate anchors before creating anything.
        if let Some(spec) = condense.filter(|_| self.config.condense_threshold > 0) {
            if let Some(candidates) = condense_candidates(identity, spec, &layer.fields) {
                for candidate in candidates.iter().flatten() {
                    if let Some(resolved) =
                        self.condense_fold(parent, protocol, identity, candidate, ts)
                    {
                        return resolved;
                    }
                }
                // Not folding: an ordinary expanded flow, tallied
                // toward both its anchors' thresholds.
                let id = self.create_stream(parent, key, identity, None, layer, dir, ts);
                for candidate in candidates.iter().flatten() {
                    self.condense
                        .entry((parent, protocol, candidate.anchor.clone()))
                        .or_default()
                        .expanded += 1;
                }
                return (id, dir);
            }
        }

        (
            self.create_stream(parent, key, identity, None, layer, dir, ts),
            dir,
        )
    }

    /// D16 fold path for one candidate anchor: folds the packet into
    /// the group's condensed node — creating the node lazily the first
    /// time a flow folds — or returns `None` if this anchor's group
    /// isn't over threshold.
    fn condense_fold(
        &mut self,
        parent: Option<StreamId>,
        protocol: ProtocolName,
        identity: &StreamIdentity,
        candidate: &CondenseCandidate,
        ts: SystemTime,
    ) -> Option<(StreamId, PacketDirection)> {
        let ckey = (parent, protocol, candidate.anchor.clone());
        let group = self.condense.get(&ckey)?;
        let triggered =
            group.node.is_some() || group.expanded as usize >= self.config.condense_threshold;
        if !triggered {
            return None;
        }

        let node_id = match group.node.filter(|&id| self.get(id).is_some()) {
            Some(id) => id,
            None => {
                // Synthesized identity: sentinel + the anchor encoding
                // (recoverable at evict for group cleanup). The node's
                // display fields carry the anchor side only.
                let mut key_bytes = KeyBuf::new();
                key_bytes.push(CONDENSED_KEY_SENTINEL);
                key_bytes.extend_from_slice(&candidate.anchor);
                let mut key_fields = FieldMap::new();
                key_fields.insert(candidate.anchor_field, candidate.anchor_value.clone());
                let condensed = Box::new(CondensedInfo {
                    member_flows: 0,
                    ephemeral_field: candidate.anchor_field,
                    overflow: false,
                });
                let id = self.create_stream_raw(
                    parent,
                    FlowKey::from_bytes(&key_bytes),
                    key_fields,
                    None, // no lifecycle on a condensed node
                    RollupSet::new(
                        identity.rollups,
                        self.config.rollup_series_default_cap,
                        self.config.rollup_series_max_cap,
                    ),
                    Some(condensed),
                    candidate.fold_dir,
                    protocol,
                    ts,
                );
                // The node is a group, not a conversation: it doesn't
                // count as a created flow itself (its members do).
                self.totals.streams_created -= 1;
                if let Some(ever) = self.created_per_protocol.get_mut(&protocol) {
                    *ever -= 1;
                }
                if let Some(group) = self.condense.get_mut(&ckey) {
                    group.node = Some(id);
                }
                id
            }
        };

        // Membership: the varying-side value identifies the member flow
        // within the group (bounded tally, D4-style overflow honesty).
        let mut new_member = false;
        let mut overflowed = false;
        if let Some(group) = self.condense.get_mut(&ckey) {
            if group.members.len() < CONDENSE_MEMBER_CAP {
                new_member = group.members.insert(candidate.varying_digest);
            } else if !group.members.contains(&candidate.varying_digest) {
                overflowed = true;
            }
        }
        if new_member {
            self.totals.streams_created += 1;
            self.totals.flows_condensed += 1;
            *self.created_per_protocol.entry(protocol).or_insert(0) += 1;
        }
        if new_member || overflowed {
            if let Some(stream) = self.get_mut(node_id) {
                if let Some(info) = stream.condensed.as_deref_mut() {
                    if new_member {
                        info.member_flows += 1;
                    }
                    info.overflow |= overflowed;
                }
            }
        }
        Some((node_id, candidate.fold_dir))
    }

    /// Creates an ordinary expanded stream for a layer (key display
    /// fields decoded from the layer, lifecycle/rollups per identity).
    #[allow(clippy::too_many_arguments)]
    fn create_stream(
        &mut self,
        parent: Option<StreamId>,
        key: FlowKey,
        identity: &StreamIdentity,
        condensed: Option<Box<CondensedInfo>>,
        layer: &pktflow_core::LayerRecord,
        dir: PacketDirection,
        ts: SystemTime,
    ) -> StreamId {
        // Decode the key-named endpoint fields for display.
        let mut key_fields = FieldMap::new();
        for kf in identity.key {
            for name in [Some(kf.a), kf.b].into_iter().flatten() {
                if let Some(v) = layer.fields.get(name) {
                    key_fields.insert(name, v.clone());
                }
            }
        }
        self.create_stream_raw(
            parent,
            key,
            key_fields,
            identity.lifecycle.map(|l| l.initial),
            RollupSet::new(
                identity.rollups,
                self.config.rollup_series_default_cap,
                self.config.rollup_series_max_cap,
            ),
            condensed,
            dir,
            layer.protocol,
            ts,
        )
    }

    /// The slot/index/hierarchy/counter mechanics shared by expanded
    /// and condensed node creation.
    #[allow(clippy::too_many_arguments)]
    fn create_stream_raw(
        &mut self,
        parent: Option<StreamId>,
        key: FlowKey,
        key_fields: FieldMap,
        state: Option<StateName>,
        rollups: RollupSet,
        condensed: Option<Box<CondensedInfo>>,
        dir: PacketDirection,
        protocol: ProtocolName,
        ts: SystemTime,
    ) -> StreamId {
        let key_hash = Self::key_hash(&key);
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
        let created_seq = self.next_seq;
        let stream = Stream {
            id,
            protocol,
            key,
            key_fields,
            parent,
            children: Vec::new(),
            initiator: dir,
            first_seen: ts,
            last_seen: ts,
            stats: [DirStats::default(); 2],
            opaque_bytes: 0,
            state,
            rollups,
            closed: None,
            close_eligible: false,
            close_eligible_since: None,
            created_seq,
            condensed,
        };
        self.next_seq += 1;
        self.totals.streams_created += 1;
        *self.created_per_protocol.entry(protocol).or_insert(0) += 1;
        *self.live_per_protocol.entry(protocol).or_insert(0) += 1;
        self.live_count += 1;
        match self.slots.get_mut(index as usize) {
            Some(slot) => slot.stream = Some(Arc::new(stream)),
            None => self.slots.push(Slot {
                generation: 0,
                stream: Some(Arc::new(stream)),
            }),
        }
        self.index
            .entry((parent, protocol, key_hash))
            .or_default()
            .push(id);

        match parent.and_then(|p| self.get_mut(p)) {
            Some(parent_stream) => parent_stream.children.push(id),
            None => self.roots.push(id),
        }
        if let EvictionPolicy::Live { idle_timeout, .. } = self.config.eviction {
            self.expiry
                .push(Reverse((ts + idle_timeout, id.index, id.generation)));
            self.lru
                .push(Reverse((ts, created_seq, id.index, id.generation)));
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
    /// deterministically). Candidates come from the lazy `lru` heap
    /// (12.2): a popped entry with stale ordering values is re-pushed
    /// with the stream's actual ones, dead and non-leaf entries are
    /// discarded (a stream is re-armed by its last child's eviction), so
    /// the pick is O(log n) amortized — never a scan of the live set.
    fn enforce_max_streams(&mut self) {
        let EvictionPolicy::Live { max_streams, .. } = self.config.eviction else {
            return;
        };
        while self.live_count > max_streams {
            let Some(Reverse((entry_seen, entry_seq, index, generation))) = self.lru.pop() else {
                return; // no leaf candidates — cannot shrink further
            };
            let id = StreamId { index, generation };
            let Some(stream) = self.get(id) else {
                continue; // evicted or recycled since this entry was pushed
            };
            if !stream.children.is_empty() {
                continue; // not a leaf: re-armed when its last child goes
            }
            let actual = (stream.last_seen, stream.created_seq);
            if actual != (entry_seen, entry_seq) {
                self.lru
                    .push(Reverse((actual.0, actual.1, index, generation)));
                continue;
            }
            self.evict(id, CloseReason::LruEvicted);
        }
    }

    /// Bounds the lazy LRU heap (12.2): discarded-entry debris (dead,
    /// non-leaf, superseded-stale) accumulates only until the heap
    /// doubles past the live set, then one O(live) rebuild from the
    /// current leaves clears it — amortized O(1) per ingest.
    fn compact_lru(&mut self) {
        if self.lru.len() <= 2 * self.live_count + 1024 {
            return;
        }
        self.lru = self
            .streams()
            .filter(|s| s.children.is_empty())
            .map(|s| Reverse((s.last_seen, s.created_seq, s.id.index, s.id.generation)))
            .collect();
    }

    /// Removes one live leaf: index entry gone (recurrence of the key
    /// creates a fresh stream), slot generation bumped (stale handles fail,
    /// no ABA), parent unlinked and re-armed for expiry, sink notified.
    /// The store's `Arc` is released here (12.1): a snapshot still holding
    /// the record keeps it alive; otherwise it frees now.
    fn evict(&mut self, id: StreamId, reason: CloseReason) {
        let Some(slot) = self.slots.get_mut(id.index as usize) else {
            return;
        };
        if slot.generation != id.generation {
            return;
        }
        let Some(shared) = slot.stream.take() else {
            return;
        };
        slot.generation = slot.generation.wrapping_add(1);
        self.free.push(id.index);
        self.live_count -= 1;
        if let Some(count) = self.live_per_protocol.get_mut(&shared.protocol) {
            *count = count.saturating_sub(1);
        }
        if let Some(bytes) = self.live_bytes_per_protocol.get_mut(&shared.protocol) {
            *bytes = bytes.saturating_sub(shared.stats[0].bytes + shared.stats[1].bytes);
        }
        let mut stream = Arc::unwrap_or_clone(shared);
        self.condense_evict(&stream);

        let bucket_key = (stream.parent, stream.protocol, Self::key_hash(&stream.key));
        if let Some(bucket) = self.index.get_mut(&bucket_key) {
            bucket.retain(|c| *c != id);
            if bucket.is_empty() {
                self.index.remove(&bucket_key);
            }
        }
        match stream.parent {
            Some(parent_id) => {
                if let Some(parent) = self.get_mut(parent_id) {
                    parent.children.retain(|c| *c != id);
                }
                // The parent may have just become an evictable leaf:
                // re-arm it for expiry and as an LRU candidate (its
                // heap entries may have been discarded while it had
                // children, 12.2).
                if let Some(deadline) = self.deadline_of(parent_id) {
                    self.expiry
                        .push(Reverse((deadline, parent_id.index, parent_id.generation)));
                }
                if let Some(parent) = self.get(parent_id) {
                    self.lru.push(Reverse((
                        parent.last_seen,
                        parent.created_seq,
                        parent_id.index,
                        parent_id.generation,
                    )));
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
        slot.stream.as_deref()
    }

    /// Copy-on-write mutation handle (12.1): pays a deep copy only when
    /// a snapshot still shares this record; exclusive records mutate in
    /// place.
    fn get_mut(&mut self, id: StreamId) -> Option<&mut Stream> {
        let slot = self.slots.get_mut(id.index as usize)?;
        if slot.generation != id.generation {
            return None;
        }
        slot.stream.as_mut().map(Arc::make_mut)
    }

    /// Root streams (no parent), creation order (05.7).
    pub fn roots(&self) -> impl Iterator<Item = &Stream> {
        self.roots.iter().filter_map(|&id| self.get(id))
    }

    /// Live streams, arena order (queries sort explicitly, 05.7).
    pub fn streams(&self) -> impl Iterator<Item = &Stream> {
        self.slots.iter().filter_map(|s| s.stream.as_deref())
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
    /// O(protocols), never O(streams) (12.1/D17.1): per-protocol live
    /// counts and bytes are maintained incrementally on create/ingest/
    /// evict.
    pub fn summary(&self) -> AggregateSummary {
        let mut per_protocol: Vec<ProtocolCounts> = self
            .created_per_protocol
            .iter()
            .map(|(&protocol, &ever)| ProtocolCounts {
                protocol,
                ever,
                live: self.live_per_protocol.get(&protocol).copied().unwrap_or(0),
                bytes: self
                    .live_bytes_per_protocol
                    .get(&protocol)
                    .copied()
                    .unwrap_or(0),
            })
            .collect();
        per_protocol.sort_by_key(|c| c.protocol);
        let mut stop_classes = [(StopClass::Clean, 0); 4];
        for (slot, &class) in stop_classes.iter_mut().zip(STOP_CLASSES.iter()) {
            *slot = (class, self.stop_classes[stop_class_index(class)]);
        }
        AggregateSummary {
            packets: self.totals.packets,
            bytes: self.totals.bytes,
            streams_created: self.totals.streams_created,
            streams_live: self.live_count as u64,
            flows_condensed: self.totals.flows_condensed,
            key_errors: self.totals.key_errors,
            per_protocol,
            stop_classes,
        }
    }

    /// Immutable view for cross-thread reads (05.7, D5). No deep copies
    /// (12.1/D17.1): the snapshot shares each record's `Arc` with the
    /// store; the copy for a record a snapshot still holds is paid
    /// lazily, on that record's next mutation. Cost here is O(live)
    /// pointer clones; measured in 09.4/12.7.
    pub fn snapshot(&self) -> AggregatorSnapshot {
        let mut streams: Vec<Arc<Stream>> =
            self.slots.iter().filter_map(|s| s.stream.clone()).collect();
        streams.sort_by_key(|s| s.created_seq);
        AggregatorSnapshot {
            streams,
            roots: self.roots.clone(),
            summary: self.summary(),
            clock: self.clock,
            unknowns: self.unknowns().into_iter().cloned().collect(),
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

    /// The unknown-occurrence registry (10.2), sorted by `count` descending
    /// with `UnknownKey` as a deterministic tiebreak.
    pub fn unknowns(&self) -> Vec<&UnknownGroup> {
        self.unknowns.groups()
    }

    /// One unknown group by its shape key (10.2).
    pub fn unknown_group(&self, key: &UnknownKey) -> Option<&UnknownGroup> {
        self.unknowns.group(key)
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
        condense: Option<&'static CondenseSpec>,
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

        fn condense(&self) -> Option<&'static CondenseSpec> {
            self.condense
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
            condense: None,
        }
    }

    fn plain(name: ProtocolName) -> Keyed {
        Keyed {
            name,
            identity: None,
            condense: None,
        }
    }

    /// A keyed plugin whose whole pair is ephemeral (like TCP/UDP's
    /// port pair under an IP parent).
    fn condensing(name: ProtocolName) -> Keyed {
        static COND: CondenseSpec = CondenseSpec {
            ephemeral: KeyField {
                a: "src",
                b: Some("dst"),
            },
        };
        Keyed {
            name,
            identity: Some(pair_identity()),
            condense: Some(&COND),
        }
    }

    fn engine() -> Arc<Engine> {
        Arc::new(
            Engine::builder()
                .plugin(keyed("eth"))
                .plugin(plain("vlan"))
                .plugin(keyed("ip"))
                .plugin(keyed("badkey"))
                .plugin(condensing("cond"))
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

    fn condensing_aggregator(threshold: usize) -> Aggregator {
        Aggregator::new(
            &engine(),
            AggregatorConfig {
                condense_threshold: threshold,
                ..AggregatorConfig::default()
            },
        )
    }

    // D16 (12.3): beyond K live same-anchor flows, further ones fold
    // into one condensed node — counts, stats direction, and totals
    // reconciliation.
    #[test]
    fn fan_out_condenses_beyond_threshold() {
        let mut agg = condensing_aggregator(4);
        // Ten flows fanning out to anchor 1000: src 1..=10, dst 1000.
        for i in 1..=10u64 {
            agg.ingest(&packet(vec![layer("cond", i, 1000)], 60, 0, i));
        }
        assert_eq!(agg.len(), 5, "4 expanded + 1 condensed node");
        let node = agg
            .streams()
            .find(|s| s.condensed.is_some())
            .expect("condensed node");
        let info = node.condensed.as_deref().expect("info");
        assert_eq!(info.member_flows, 6, "flows 5..=10 folded");
        assert!(!info.overflow);
        assert_eq!(info.ephemeral_field, "dst", "anchored on the dst side");
        assert_eq!(node.key_fields.get("dst"), Some(&Value::U64(1000)));
        // Members send toward the anchor: B→A with A = anchor.
        assert_eq!(node.stats[dir_index(PacketDirection::BtoA)].packets, 6);
        assert_eq!(node.stats[dir_index(PacketDirection::AtoB)].packets, 0);

        // A second packet of a folded flow updates stats, not members.
        agg.ingest(&packet(vec![layer("cond", 7, 1000)], 60, 0, 11));
        let node = agg
            .streams()
            .find(|s| s.condensed.is_some())
            .expect("condensed node");
        assert_eq!(node.condensed.as_deref().expect("info").member_flows, 6);
        assert_eq!(node.stats[dir_index(PacketDirection::BtoA)].packets, 7);
        // And the anchor answering flows A→B into the same node.
        agg.ingest(&packet(vec![layer("cond", 1000, 7)], 60, 0, 12));
        let node = agg
            .streams()
            .find(|s| s.condensed.is_some())
            .expect("condensed node");
        assert_eq!(node.stats[dir_index(PacketDirection::AtoB)].packets, 1);

        // FR-27 reconciliation: nothing silently absorbed.
        let summary = agg.summary();
        assert_eq!(summary.streams_created, 10, "member flows all count");
        assert_eq!(summary.flows_condensed, 6);
        assert_eq!(summary.streams_live, 5);
    }

    // D16: threshold 0 disables condensation — per-flow output exactly.
    #[test]
    fn condensation_disabled_is_per_flow() {
        let mut agg = condensing_aggregator(0);
        for i in 1..=10u64 {
            agg.ingest(&packet(vec![layer("cond", i, 1000)], 60, 0, i));
        }
        assert_eq!(agg.len(), 10);
        assert!(agg.streams().all(|s| s.condensed.is_none()));
        assert_eq!(agg.summary().flows_condensed, 0);
    }

    // D16: inner layers over folded flows nest under the condensed
    // node — tunnels survive condensation.
    #[test]
    fn condensed_node_hosts_inner_children() {
        let mut agg = condensing_aggregator(2);
        for i in 1..=5u64 {
            agg.ingest(&packet(
                vec![layer("cond", i, 1000), layer("ip", 50, 60)],
                60,
                0,
                i,
            ));
        }
        let node_id = agg
            .streams()
            .find(|s| s.condensed.is_some())
            .expect("condensed node")
            .id;
        let inner: Vec<&Stream> = agg.children(node_id).collect();
        assert_eq!(inner.len(), 1, "one inner ip conversation, D10-scoped");
        assert_eq!(inner[0].protocol, "ip");
        assert_eq!(
            inner[0].stats[0].packets + inner[0].stats[1].packets,
            3,
            "flows 3..=5's inner packets"
        );
    }

    // D16: same input ⇒ same expanded set, same condensed tallies.
    #[test]
    fn condensation_is_deterministic() {
        let run = || {
            let mut agg = condensing_aggregator(3);
            let mut rng: u64 = 0x452821e638d01377;
            for i in 0..200u64 {
                rng = rng
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                let src = 1 + (rng >> 33) % 40;
                agg.ingest(&packet(vec![layer("cond", src, 1000)], 60, 0, i));
            }
            agg.snapshot()
        };
        assert_eq!(format!("{:?}", run()), format!("{:?}", run()));
    }

    // D16: evicting a condensed node removes its group — recurrence of
    // the shape starts a fresh count (05.6's re-keying rule).
    #[test]
    fn condensed_node_eviction_resets_the_group() {
        let engine = engine();
        let mut agg = Aggregator::new(
            &engine,
            AggregatorConfig {
                condense_threshold: 2,
                eviction: EvictionPolicy::Live {
                    idle_timeout: Duration::from_millis(50),
                    close_linger: Duration::from_millis(50),
                    max_streams: 100,
                },
                ..AggregatorConfig::default()
            },
        );
        for i in 1..=4u64 {
            agg.ingest(&packet(vec![layer("cond", i, 1000)], 60, 0, i));
        }
        assert_eq!(agg.len(), 3, "2 expanded + node with 2 members");

        // Everything idles out…
        agg.ingest(&packet(vec![layer("cond", 999, 998)], 60, 0, 10_000));
        assert_eq!(agg.len(), 1, "only the fresh flow survives");

        // …and the shape starts over: expanded again, no stale fold.
        agg.ingest(&packet(vec![layer("cond", 50, 1000)], 60, 0, 10_001));
        let newest = agg
            .streams()
            .max_by_key(|s| s.created_seq)
            .expect("a stream");
        assert!(
            newest.condensed.is_none(),
            "fresh count after the group evicted"
        );
    }

    // 12.2: a stale LRU-heap entry (stream touched after arming) must
    // not get its stream evicted ahead of a genuinely colder one.
    #[test]
    fn lru_heap_repushes_stale_entries_instead_of_evicting() {
        let engine = engine();
        let mut agg = Aggregator::new(
            &engine,
            AggregatorConfig {
                eviction: EvictionPolicy::Live {
                    idle_timeout: Duration::from_secs(3600),
                    close_linger: Duration::from_secs(3600),
                    max_streams: 2,
                },
                ..AggregatorConfig::default()
            },
        );
        agg.ingest(&packet(vec![layer("eth", 1, 2)], 60, 0, 0)); // A @0
        agg.ingest(&packet(vec![layer("eth", 3, 4)], 60, 0, 1)); // B @1
        agg.ingest(&packet(vec![layer("eth", 1, 2)], 60, 0, 2)); // A touched @2
        agg.ingest(&packet(vec![layer("eth", 5, 6)], 60, 0, 3)); // C @3 → over cap

        let live: Vec<u64> = {
            let mut seqs: Vec<u64> = agg.streams().map(|s| s.created_seq).collect();
            seqs.sort_unstable();
            seqs
        };
        assert_eq!(live, [0, 2], "B (coldest, seq 1) evicted — not A");
    }

    // 12.2: a parent whose LRU entry was discarded while it had children
    // is re-armed by its last child's eviction, staying LRU-evictable.
    #[test]
    fn lru_heap_rearms_parents_that_become_leaves() {
        let engine = engine();
        let mut agg = Aggregator::new(
            &engine,
            AggregatorConfig {
                eviction: EvictionPolicy::Live {
                    idle_timeout: Duration::from_secs(3600),
                    close_linger: Duration::from_secs(3600),
                    max_streams: 1,
                },
                ..AggregatorConfig::default()
            },
        );
        // Parent+child @0: over cap → the ip leaf goes, eth survives as
        // a fresh leaf (its own heap entry was popped and discarded as a
        // non-leaf during that same enforcement pass).
        agg.ingest(&packet(
            vec![layer("eth", 1, 2), layer("ip", 10, 20)],
            60,
            0,
            0,
        ));
        assert_eq!(agg.len(), 1);
        assert_eq!(agg.streams().next().map(|s| s.protocol), Some("eth"));

        // A younger root @5 → the re-armed eth parent is the LRU leaf.
        agg.ingest(&packet(vec![layer("eth", 3, 4)], 60, 0, 5));
        assert_eq!(agg.len(), 1);
        let survivor = agg.streams().next().expect("one stream");
        assert_eq!(
            (survivor.protocol, survivor.last_seen),
            ("eth", SystemTime::UNIX_EPOCH + Duration::from_millis(5)),
            "the old parent was evicted via its re-armed entry"
        );
    }

    // 12.2: randomized oracle for the lazy LRU heap — every LruEvicted
    // stream must have been the (last_seen, created_seq) minimum among
    // live leaves at its eviction, exactly the reference scan's pick.
    #[test]
    fn lru_heap_always_evicts_the_reference_scans_pick() {
        let engine = engine();
        let log: std::sync::Arc<std::sync::Mutex<Vec<(SystemTime, u64)>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink_log = std::sync::Arc::clone(&log);
        let mut agg = Aggregator::new(
            &engine,
            AggregatorConfig {
                eviction: EvictionPolicy::Live {
                    idle_timeout: Duration::from_secs(3600), // LRU cap only
                    close_linger: Duration::from_secs(3600),
                    max_streams: 5,
                },
                sink: Some(Box::new(move |evicted| {
                    assert_eq!(evicted.reason, CloseReason::LruEvicted);
                    if let Ok(mut log) = sink_log.lock() {
                        log.push((evicted.stream.last_seen, evicted.stream.created_seq));
                    }
                })),
                ..AggregatorConfig::default()
            },
        );

        let mut rng: u64 = 0x082e_fa98_ec4e_6c89;
        let mut checked = 0;
        for i in 0..400u64 {
            rng = rng
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            // 12 distinct single-layer keys over a cap of 5: constant
            // churn, strictly increasing packet time. One ingest touches
            // one stream, so post-ingest live state is eviction-time
            // state.
            let pair = (rng >> 33) % 12;
            agg.ingest(&packet(
                vec![layer("eth", 100 + pair, 200 + pair)],
                60,
                0,
                i,
            ));
            assert!(agg.len() <= 5, "cap holds at packet {i}");

            let evicted: Vec<(SystemTime, u64)> = log
                .lock()
                .map(|mut l| l.drain(..).collect())
                .unwrap_or_default();
            for e in evicted {
                checked += 1;
                for s in agg.streams() {
                    assert!(
                        e < (s.last_seen, s.created_seq),
                        "packet {i}: evicted {e:?} was not the LRU minimum"
                    );
                }
            }
        }
        assert!(checked > 100, "churn actually exercised the cap");
    }

    // 12.2: the index keys on a key digest; two different keys forced
    // into one bucket still resolve to their own streams (full-key
    // compare on probe), never to each other's.
    #[test]
    fn index_hash_collisions_probe_by_full_key() {
        let mut agg = aggregator();
        agg.ingest(&packet(vec![layer("eth", 1, 2)], 60, 0, 0));
        agg.ingest(&packet(vec![layer("eth", 3, 4)], 60, 0, 1));

        // Force the two entries into one bucket, simulating a digest
        // collision (real DefaultHasher collisions aren't constructible
        // on demand; the probe path is what matters).
        let buckets: Vec<_> = agg.index.drain().collect();
        let merged: SmallVec<[StreamId; 2]> = buckets
            .iter()
            .flat_map(|(_, ids)| ids.iter().copied())
            .collect();
        let mut merged: SmallVec<[StreamId; 1]> = merged.into_iter().collect();
        merged.sort_by_key(|id| id.index);
        for (bkey, _) in buckets {
            agg.index.insert(bkey, merged.clone());
        }

        // Recurrence of each key must update its own stream, not the
        // bucket-mate, and create nothing new.
        agg.ingest(&packet(vec![layer("eth", 2, 1)], 60, 0, 2));
        agg.ingest(&packet(vec![layer("eth", 4, 3)], 60, 0, 3));
        assert_eq!(agg.len(), 2, "no phantom stream from a collision");
        for s in agg.streams() {
            assert_eq!(
                s.stats[0].packets + s.stats[1].packets,
                2,
                "each key hit its own stream"
            );
        }
    }

    // 12.1 (D17.1): consecutive snapshots share untouched records
    // pointer-for-pointer; only touched records get a fresh copy.
    #[test]
    fn snapshots_share_untouched_records() {
        let mut agg = aggregator();
        agg.ingest(&packet(vec![layer("eth", 1, 2)], 60, 0, 0));
        agg.ingest(&packet(vec![layer("eth", 3, 4)], 60, 0, 1));
        let before = agg.snapshot();

        // Touch only the (1,2) stream; (3,4) stays untouched.
        agg.ingest(&packet(vec![layer("eth", 2, 1)], 60, 0, 2));
        let after = agg.snapshot();

        assert_eq!(before.streams.len(), 2);
        assert_eq!(after.streams.len(), 2);
        let touched = 0; // created_seq order: (1,2) first
        let untouched = 1;
        assert!(
            Arc::ptr_eq(&before.streams[untouched], &after.streams[untouched]),
            "untouched record is shared, not recloned"
        );
        assert!(
            !Arc::ptr_eq(&before.streams[touched], &after.streams[touched]),
            "touched record was copied for the old snapshot's benefit"
        );
        // The old snapshot kept the pre-touch value; the new one moved on.
        assert_eq!(before.streams[touched].stats[0].packets, 1);
        assert_eq!(
            after.streams[touched].stats[0].packets + after.streams[touched].stats[1].packets,
            2
        );
    }

    // 12.1: a snapshot is value-equal to a from-scratch deep copy of the
    // live set, across a randomized ingest sequence.
    #[test]
    fn snapshot_matches_reference_deep_copy() {
        let mut agg = aggregator();
        let mut rng: u64 = 0x243f_6a88_85a3_08d3; // seeded LCG
        for i in 0..500u64 {
            rng = rng
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let a = 1 + (rng >> 33) % 8;
            let b = 1 + (rng >> 13) % 8;
            agg.ingest(&packet(
                vec![layer("eth", a, b), layer("ip", 10 + a, 20 + b)],
                60 + (i % 9) as usize,
                0,
                i,
            ));
            if i % 97 == 0 {
                let snap = agg.snapshot();
                let mut reference: Vec<Stream> = agg.streams().cloned().collect();
                reference.sort_by_key(|s| s.created_seq);
                let materialized: Vec<Stream> =
                    snap.streams.iter().map(|s| (**s).clone()).collect();
                assert_eq!(materialized, reference, "packet {i}");
            }
        }
    }

    // 12.1: per-protocol live/byte counters are maintained
    // incrementally; they must always equal a recomputation from the
    // live set — including across evictions.
    #[test]
    fn summary_counters_match_recomputation_across_eviction() {
        let engine = engine();
        let mut agg = Aggregator::new(
            &engine,
            AggregatorConfig {
                eviction: EvictionPolicy::Live {
                    idle_timeout: Duration::from_millis(40),
                    close_linger: Duration::from_millis(10),
                    max_streams: 6,
                },
                ..AggregatorConfig::default()
            },
        );
        let mut rng: u64 = 0x1319_8a2e_0370_7344;
        for i in 0..300u64 {
            rng = rng
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let a = 1 + (rng >> 33) % 10;
            let b = 1 + (rng >> 13) % 10;
            agg.ingest(&packet(
                vec![layer("eth", a, b), layer("ip", 10 + a, 20 + b)],
                40 + (i % 31) as usize,
                0,
                i * 7,
            ));

            let summary = agg.summary();
            for counts in &summary.per_protocol {
                let live = agg
                    .streams()
                    .filter(|s| s.protocol == counts.protocol)
                    .count() as u64;
                let bytes: u64 = agg
                    .streams()
                    .filter(|s| s.protocol == counts.protocol)
                    .map(|s| s.stats[0].bytes + s.stats[1].bytes)
                    .sum();
                assert_eq!(counts.live, live, "{} live at packet {i}", counts.protocol);
                assert_eq!(
                    counts.bytes, bytes,
                    "{} bytes at packet {i}",
                    counts.protocol
                );
            }
        }
    }

    // 12.1: eviction releases the store's handle — once the last
    // snapshot holding an evicted stream drops, the record is freed.
    #[test]
    fn eviction_releases_the_stores_arc() {
        let engine = engine();
        let mut agg = Aggregator::new(
            &engine,
            AggregatorConfig {
                eviction: EvictionPolicy::Live {
                    idle_timeout: Duration::from_millis(10),
                    close_linger: Duration::from_millis(10),
                    max_streams: 4,
                },
                ..AggregatorConfig::default()
            },
        );
        agg.ingest(&packet(vec![layer("eth", 1, 2)], 60, 0, 0));
        let snap = agg.snapshot();
        let weak = Arc::downgrade(&snap.streams[0]);

        agg.finish(); // live mode: evicts everything
        assert!(agg.is_empty());
        assert!(weak.upgrade().is_some(), "snapshot still holds the record");
        drop(snap);
        assert!(
            weak.upgrade().is_none(),
            "no lingering store-side Arc after eviction (12.1)"
        );
    }
}
