//! The unknown-occurrence registry (10.2, FR-29, D11): a bounded, queryable,
//! capture-wide rollup of per-packet [`UnknownDiagnostics`] (10.1) — one row
//! per distinct *shape* of unknown, living beside the stream store but with
//! an independent lifetime (it does not share eviction with any `Stream`,
//! and is not attributed to one).

use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, VecDeque};
use std::hash::BuildHasherDefault;
use std::time::SystemTime;

use pktflow_core::{
    Confidence, FlowKey, ProtocolName, RouteId, UnknownContext, UnknownDiagnostics,
};
use smallvec::SmallVec;

use crate::rollup::ACCUMULATE_SET_CAP;

/// Deterministic hasher (PRD §7), same discipline as the stream store.
type DetHashMap<K, V> = HashMap<K, V, BuildHasherDefault<DefaultHasher>>;

/// The innermost successfully-parsed layer's canonicalized endpoint key at
/// the moment dissection stopped, when that layer declared a `StreamIdentity`
/// (02.4). Reused verbatim from whatever the parent stream already computed
/// (D10) — the registry never re-derives a key, and stays protocol-free.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct EndpointKey {
    pub protocol: ProtocolName,
    pub key: FlowKey,
}

/// Groups unknown occurrences by shape: same predecessor plus either the
/// same named-but-unclaimed route, or the same "heuristics exhausted" story
/// (`route: None`).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct UnknownKey {
    pub predecessor: ProtocolName,
    /// `Some` for `UnclaimedRoute`, `None` for `NoHeuristicWinner`.
    pub route: Option<RouteId>,
}

impl From<&UnknownContext> for UnknownKey {
    fn from(ctx: &UnknownContext) -> Self {
        match *ctx {
            UnknownContext::UnclaimedRoute { predecessor, route } => UnknownKey {
                predecessor,
                route: Some(route),
            },
            UnknownContext::NoHeuristicWinner { predecessor } => UnknownKey {
                predecessor,
                route: None,
            },
        }
    }
}

/// One distinct shape of unknown, rolled up across every occurrence seen.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct UnknownGroup {
    pub key: UnknownKey,
    pub count: u64,
    pub bytes_total: u64,
    pub bytes_min: u32,
    pub bytes_max: u32,
    pub first_seen: SystemTime,
    pub last_seen: SystemTime,
    /// Bounded like D4's `Accumulate` (cap [`ACCUMULATE_SET_CAP`]),
    /// insertion-ordered, deterministic.
    pub endpoints: Vec<EndpointKey>,
    pub endpoints_overflow: bool,
    /// Best-ever-seen ranked list for this group: the observation with the
    /// highest top score wins; ties go to the most recent observation.
    pub near_misses: SmallVec<[(ProtocolName, Confidence); 5]>,
    /// Bounded ring of full per-occurrence sample byte arrays,
    /// overwrite-oldest — 05.4's `Series` pattern, reused not reinvented.
    pub samples: VecDeque<Box<[u8]>>,
    /// Insertion order, the deterministic LRU tiebreak (mirrors `Stream`'s
    /// `created_seq`) — not part of the public contract, just ordering glue.
    seq: u64,
}

/// D11's bounding knobs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct UnknownRegistryConfig {
    /// LRU cap over last-updated group; default 500 (D11).
    pub max_groups: usize,
    /// Ring size per group; default 5 (D11).
    pub samples_per_group: usize,
}

impl Default for UnknownRegistryConfig {
    fn default() -> Self {
        Self {
            max_groups: 500,
            samples_per_group: 5,
        }
    }
}

/// The registry itself: owns every group, independent of stream storage.
#[derive(Debug, Default)]
pub(crate) struct UnknownRegistry {
    groups: DetHashMap<UnknownKey, UnknownGroup>,
    next_seq: u64,
}

impl UnknownRegistry {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Folds one packet's diagnostics in: updates (or inserts) the group
    /// keyed by `UnknownContext`, then enforces `max_groups`.
    pub(crate) fn ingest(
        &mut self,
        diag: &UnknownDiagnostics,
        bytes: u32,
        ts: SystemTime,
        endpoint: Option<EndpointKey>,
        config: UnknownRegistryConfig,
    ) {
        let key = UnknownKey::from(&diag.context);
        let seq = self.next_seq;
        self.next_seq += 1;

        let group = self
            .groups
            .entry(key.clone())
            .or_insert_with(|| UnknownGroup {
                key: key.clone(),
                count: 0,
                bytes_total: 0,
                bytes_min: u32::MAX,
                bytes_max: 0,
                first_seen: ts,
                last_seen: ts,
                endpoints: Vec::new(),
                endpoints_overflow: false,
                near_misses: SmallVec::new(),
                samples: VecDeque::new(),
                seq,
            });

        group.count += 1;
        group.bytes_total += u64::from(bytes);
        group.bytes_min = group.bytes_min.min(bytes);
        group.bytes_max = group.bytes_max.max(bytes);
        group.first_seen = group.first_seen.min(ts);
        group.last_seen = group.last_seen.max(ts);

        if let Some(ep) = endpoint {
            if !group.endpoints.contains(&ep) {
                if group.endpoints.len() < ACCUMULATE_SET_CAP {
                    group.endpoints.push(ep);
                } else {
                    group.endpoints_overflow = true;
                }
            }
        }

        let candidate_top = diag.near_misses.first().map(|&(_, c)| c.get());
        let current_top = group.near_misses.first().map(|&(_, c)| c.get());
        if candidate_top.is_some() && candidate_top >= current_top {
            group.near_misses = diag.near_misses.clone();
        }

        if group.samples.len() >= config.samples_per_group {
            group.samples.pop_front();
        }
        group.samples.push_back(diag.sample.clone());

        self.enforce_max_groups(config.max_groups);
    }

    /// While over the cap, evicts the group least-recently updated (packet
    /// time), `seq` breaking ties — same LRU discipline as 05.6's stream
    /// cap, applied here independently.
    fn enforce_max_groups(&mut self, max_groups: usize) {
        while self.groups.len() > max_groups {
            let coldest = self
                .groups
                .values()
                .min_by_key(|g| (g.last_seen, g.seq))
                .map(|g| g.key.clone());
            match coldest {
                Some(k) => {
                    self.groups.remove(&k);
                }
                None => break,
            }
        }
    }

    /// Sorted by `count` descending, `UnknownKey` as deterministic tiebreak
    /// — never hash-map order (PRD §7), same discipline as `at_layer`.
    pub(crate) fn groups(&self) -> Vec<&UnknownGroup> {
        let mut groups: Vec<&UnknownGroup> = self.groups.values().collect();
        groups.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.key.cmp(&b.key)));
        groups
    }

    pub(crate) fn group(&self, key: &UnknownKey) -> Option<&UnknownGroup> {
        self.groups.get(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx_route(predecessor: ProtocolName, route: RouteId) -> UnknownContext {
        UnknownContext::UnclaimedRoute { predecessor, route }
    }

    fn diag(context: UnknownContext, near_misses: &[(ProtocolName, u8)]) -> UnknownDiagnostics {
        UnknownDiagnostics {
            context,
            near_misses: near_misses
                .iter()
                .map(|&(n, c)| (n, Confidence::new(c)))
                .collect(),
            sample: vec![0xAB; 4].into_boxed_slice(),
        }
    }

    fn ts(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(secs)
    }

    #[test]
    fn ingest_updates_existing_group_and_creates_new_ones() {
        let mut reg = UnknownRegistry::new();
        let cfg = UnknownRegistryConfig::default();
        let a = ctx_route("udp", RouteId::UdpPort(4433));
        let b = UnknownContext::NoHeuristicWinner { predecessor: "eth" };

        reg.ingest(&diag(a, &[]), 10, ts(0), None, cfg);
        reg.ingest(&diag(b, &[]), 20, ts(1), None, cfg);
        reg.ingest(&diag(a, &[]), 30, ts(2), None, cfg);

        let a_key = UnknownKey::from(&a);
        let group_a = reg.group(&a_key).expect("group a exists");
        assert_eq!(group_a.count, 2);
        assert_eq!(group_a.bytes_total, 40);
        assert_eq!(group_a.bytes_min, 10);
        assert_eq!(group_a.bytes_max, 30);
        assert_eq!(group_a.first_seen, ts(0));
        assert_eq!(group_a.last_seen, ts(2));

        let b_key = UnknownKey::from(&b);
        let group_b = reg.group(&b_key).expect("group b exists");
        assert_eq!(group_b.count, 1);
        assert_eq!(group_b.bytes_total, 20);

        assert_eq!(reg.groups().len(), 2);
    }

    #[test]
    fn max_groups_evicts_exactly_the_coldest() {
        let mut reg = UnknownRegistry::new();
        let cfg = UnknownRegistryConfig {
            max_groups: 3,
            samples_per_group: 5,
        };
        for port in 0..5u16 {
            let ctx = ctx_route("udp", RouteId::UdpPort(port));
            reg.ingest(&diag(ctx, &[]), 1, ts(u64::from(port)), None, cfg);
        }
        // 5 distinct groups inserted, cap 3: the 2 coldest (ports 0, 1) evicted.
        assert_eq!(reg.groups().len(), 3);
        assert!(reg
            .group(&UnknownKey::from(&ctx_route("udp", RouteId::UdpPort(0))))
            .is_none());
        assert!(reg
            .group(&UnknownKey::from(&ctx_route("udp", RouteId::UdpPort(1))))
            .is_none());
        assert!(reg
            .group(&UnknownKey::from(&ctx_route("udp", RouteId::UdpPort(4))))
            .is_some());
    }

    #[test]
    fn samples_per_group_keeps_the_k_most_recent_byte_identical() {
        let mut reg = UnknownRegistry::new();
        let cfg = UnknownRegistryConfig {
            max_groups: 10,
            samples_per_group: 3,
        };
        let ctx = ctx_route("udp", RouteId::UdpPort(53));
        for i in 0..5u8 {
            let mut d = diag(ctx, &[]);
            d.sample = vec![i; 4].into_boxed_slice();
            reg.ingest(&d, 1, ts(u64::from(i)), None, cfg);
        }
        let group = reg.group(&UnknownKey::from(&ctx)).expect("group exists");
        assert_eq!(group.samples.len(), 3);
        let bytes: Vec<u8> = group.samples.iter().map(|s| s[0]).collect();
        assert_eq!(bytes, [2, 3, 4], "oldest two overwritten, ring order kept");
    }

    #[test]
    fn near_misses_keep_the_best_ever_seen_ties_to_most_recent() {
        let mut reg = UnknownRegistry::new();
        let cfg = UnknownRegistryConfig::default();
        let ctx = ctx_route("udp", RouteId::UdpPort(53));

        reg.ingest(&diag(ctx, &[("a", 40)]), 1, ts(0), None, cfg);
        reg.ingest(&diag(ctx, &[("b", 90)]), 1, ts(1), None, cfg);
        // Lower top score than the stored 90: must not overwrite.
        reg.ingest(&diag(ctx, &[("c", 20)]), 1, ts(2), None, cfg);
        let group = reg.group(&UnknownKey::from(&ctx)).expect("group exists");
        assert_eq!(group.near_misses.as_slice(), [("b", Confidence::new(90))]);

        // Tie at 90: most recent wins.
        reg.ingest(&diag(ctx, &[("d", 90)]), 1, ts(3), None, cfg);
        let group = reg.group(&UnknownKey::from(&ctx)).expect("group exists");
        assert_eq!(group.near_misses.as_slice(), [("d", Confidence::new(90))]);
    }

    #[test]
    fn endpoints_dedupe_and_cap_with_overflow_flag() {
        let mut reg = UnknownRegistry::new();
        let cfg = UnknownRegistryConfig::default();
        let ctx = ctx_route("udp", RouteId::UdpPort(53));

        for i in 0..(ACCUMULATE_SET_CAP + 2) {
            let ep = EndpointKey {
                protocol: "ip",
                key: FlowKey::from_bytes(&(i as u32).to_be_bytes()),
            };
            reg.ingest(&diag(ctx, &[]), 1, ts(i as u64), Some(ep), cfg);
        }
        let group = reg.group(&UnknownKey::from(&ctx)).expect("group exists");
        assert_eq!(group.endpoints.len(), ACCUMULATE_SET_CAP);
        assert!(group.endpoints_overflow);

        // A repeated endpoint never grows the set beyond the cap.
        let repeat_key = group.endpoints[0].clone();
        let before = group.endpoints.len();
        reg.ingest(&diag(ctx, &[]), 1, ts(999), Some(repeat_key), cfg);
        let group = reg.group(&UnknownKey::from(&ctx)).expect("group exists");
        assert_eq!(group.endpoints.len(), before);
    }

    #[test]
    fn groups_ordering_is_deterministic_across_identical_runs() {
        let run = || {
            let mut reg = UnknownRegistry::new();
            let cfg = UnknownRegistryConfig::default();
            reg.ingest(
                &diag(ctx_route("udp", RouteId::UdpPort(1)), &[]),
                1,
                ts(0),
                None,
                cfg,
            );
            reg.ingest(
                &diag(ctx_route("udp", RouteId::UdpPort(2)), &[]),
                1,
                ts(1),
                None,
                cfg,
            );
            reg.ingest(
                &diag(ctx_route("udp", RouteId::UdpPort(2)), &[]),
                1,
                ts(2),
                None,
                cfg,
            );
            reg.groups()
                .into_iter()
                .map(|g| g.key.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(run(), run());
    }
}
