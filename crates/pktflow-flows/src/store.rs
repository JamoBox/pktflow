//! The stream store (05.2, FR-1, D5, D10): long-lived single-writer state —
//! stream records, the lookup index, baseline stats, and the per-packet
//! ingest path. This is the aggregator's hot loop.

use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::BuildHasherDefault;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use pktflow_core::{
    DissectedPacket, Engine, FieldMap, FlowKey, PacketDirection, ProtocolName, StateName,
    StreamIdentity,
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
        }
    }

    /// The one mutating entry point: fold one dissected packet into the
    /// store (the 05.2 ingest algorithm).
    pub fn ingest(&mut self, pkt: &DissectedPacket) {
        let ts = pkt.meta.timestamp;
        self.clock = self.clock.max(ts);
        self.totals.packets += 1;
        self.totals.bytes += pkt.meta.origlen as u64;

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
            if let Some(stream) = self.get_mut(id) {
                stream.last_seen = ts;
                let slot = &mut stream.stats[dir_index(dir)];
                slot.packets += 1;
                slot.bytes += pkt.meta.origlen as u64;

                // Lifecycle (05.5): plugin-owned transition, engine-held state.
                if let (Some(spec), Some(current)) = (identity.lifecycle, stream.state) {
                    let next = (spec.advance)(&layer.fields, current, dir);
                    stream.state = Some(next);
                    stream.close_eligible = spec.closed_states.contains(&next);
                }

                stream.rollups.apply(&layer.fields, ts, dir);
            }
            parent = Some(id);
        }

        // D9: unparsed payload lands on the innermost real stream only.
        if let Some(innermost) = parent {
            if let Some(stream) = self.get_mut(innermost) {
                stream.opaque_bytes += pkt.opaque_len as u64;
            }
        }
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

        let index = u32::try_from(self.slots.len()).unwrap_or(u32::MAX);
        let id = StreamId {
            index,
            generation: 0,
        };
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
            created_seq: self.next_seq,
        };
        self.next_seq += 1;
        self.totals.streams_created += 1;
        self.slots.push(Slot {
            generation: 0,
            stream: Some(stream),
        });
        self.index.insert((parent, protocol, key), id);

        match parent.and_then(|p| self.get_mut(p)) {
            Some(parent_stream) => parent_stream.children.push(id),
            None => self.roots.push(id),
        }
        id
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

    /// Root streams (no parent), creation order.
    pub fn roots(&self) -> &[StreamId] {
        &self.roots
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
        assert_eq!(agg.roots(), [eth.id]);
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
