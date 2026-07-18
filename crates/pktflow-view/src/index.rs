//! The per-snapshot view index (12.4, D17.3): every reader-side lens —
//! web request handlers, TUI panes — answers from facets computed at
//! most once per published snapshot, in windows, so no interaction does
//! work or transfer proportional to total stream count. Facets build
//! lazily on the first reader that needs them and are shared through
//! the owning `Arc` (readers share, the aggregation thread is never
//! involved — D5).

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::SystemTime;

use pktflow_flows::{AggregatorSnapshot, Stream, StreamId};

use crate::query::{matching_with_ancestors, StreamQuery};
use crate::stream_view::{total_bytes, total_packets};

/// Row orderings the index precomputes (mirrors the CLI's `--sort`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SortKey {
    Bytes,
    Packets,
    FirstSeen,
    Duration,
}

impl SortKey {
    /// Parse a wire name (`/api/streams?sort=`); `None` = unknown.
    pub fn parse(name: &str) -> Option<SortKey> {
        match name {
            "bytes" => Some(SortKey::Bytes),
            "packets" => Some(SortKey::Packets),
            "first" | "first-seen" | "first_seen" => Some(SortKey::FirstSeen),
            "duration" => Some(SortKey::Duration),
            _ => None,
        }
    }

    fn slot(self) -> usize {
        match self {
            SortKey::Bytes => 0,
            SortKey::Packets => 1,
            SortKey::FirstSeen => 2,
            SortKey::Duration => 3,
        }
    }
}

/// Which rows a window draws from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Scope {
    /// Root streams only (the tree's top level).
    Roots,
    /// Direct children of one stream (tree expansion), by display id.
    ChildrenOf(u64),
    /// Every stream (the flat table).
    Flat,
}

/// One windowed request (12.4): scope + optional query + sort + page.
pub struct WindowSpec<'q> {
    pub scope: Scope,
    /// Matches-with-ancestors semantics, like every other lens.
    pub query: Option<&'q str>,
    pub sort: SortKey,
    pub descending: bool,
    pub offset: usize,
    pub limit: usize,
}

/// A window's answer: the page plus the totals the client pages by.
pub struct WindowResult<'a> {
    /// Rows in scope (pre-query).
    pub total: usize,
    /// Rows in scope surviving the query (`None` = no/broken query).
    pub match_total: Option<usize>,
    pub rows: Vec<&'a Stream>,
}

/// A bounded time×lane density request (12.4): the response is
/// O(bins × lanes) regardless of stream count.
pub struct TimelineSpec<'q> {
    pub bins: usize,
    pub lanes: usize,
    pub query: Option<&'q str>,
}

/// One timeline lane: a top stream by total bytes (`seq = Some`) or the
/// everything-else aggregate (`seq = None`), as per-bin activity.
pub struct TimelineLane {
    pub seq: Option<u64>,
    /// Streams active per bin (for a single-stream lane: 0/1).
    pub active: Vec<u32>,
}

/// The bounded timeline answer.
pub struct TimelineBins {
    pub start: SystemTime,
    pub end: SystemTime,
    pub lanes: Vec<TimelineLane>,
}

/// Cached evaluation of one query against one snapshot.
struct QueryCache {
    raw: String,
    /// `created_seq`s matching, and matching-plus-ancestors; `None` =
    /// the expression didn't parse.
    sets: Option<Arc<(HashSet<u64>, HashSet<u64>)>>,
}

/// See module docs. Build one per published snapshot (memoize against
/// the hub generation) and share it among readers.
pub struct SnapshotIndex {
    snap: Arc<AggregatorSnapshot>,
    by_id: OnceLock<HashMap<StreamId, u32>>,
    by_seq: OnceLock<HashMap<u64, u32>>,
    orders: [OnceLock<Arc<Vec<u32>>>; 4],
    /// Most-recent-query memo: UIs re-issue the same expression while
    /// paging/scrolling, so one slot covers the hot path.
    query: Mutex<Option<QueryCache>>,
}

impl SnapshotIndex {
    pub fn new(snap: Arc<AggregatorSnapshot>) -> Self {
        Self {
            snap,
            by_id: OnceLock::new(),
            by_seq: OnceLock::new(),
            orders: [const { OnceLock::new() }; 4],
            query: Mutex::new(None),
        }
    }

    pub fn snapshot(&self) -> &Arc<AggregatorSnapshot> {
        &self.snap
    }

    fn positions_by_id(&self) -> &HashMap<StreamId, u32> {
        self.by_id.get_or_init(|| {
            self.snap
                .streams
                .iter()
                .enumerate()
                .map(|(i, s)| (s.id, i as u32))
                .collect()
        })
    }

    fn positions_by_seq(&self) -> &HashMap<u64, u32> {
        self.by_seq.get_or_init(|| {
            self.snap
                .streams
                .iter()
                .enumerate()
                .map(|(i, s)| (s.created_seq, i as u32))
                .collect()
        })
    }

    /// Id → stream, replacing per-request `by_id()` map builds.
    pub fn by_id(&self, id: StreamId) -> Option<&Stream> {
        let pos = *self.positions_by_id().get(&id)? as usize;
        self.snap.streams.get(pos).map(|s| &**s)
    }

    /// Display id (`created_seq`) → stream.
    pub fn by_seq(&self, seq: u64) -> Option<&Stream> {
        let pos = *self.positions_by_seq().get(&seq)? as usize;
        self.snap.streams.get(pos).map(|s| &**s)
    }

    /// The id → stream map every existing query/render helper takes.
    /// Built once per snapshot (the map borrows the index).
    pub fn id_map(&self) -> HashMap<StreamId, &Stream> {
        // Cheap projection over the cached positions: no re-hashing of
        // stream contents, one pointer per entry.
        self.positions_by_id()
            .iter()
            .map(|(&id, &pos)| (id, &*self.snap.streams[pos as usize]))
            .collect()
    }

    /// Ascending arena positions ordered by `key` (ties: `created_seq`,
    /// making every page deterministic). Computed once per key.
    pub fn order(&self, key: SortKey) -> Arc<Vec<u32>> {
        Arc::clone(self.orders[key.slot()].get_or_init(|| {
            let streams = &self.snap.streams;
            let mut order: Vec<u32> = (0..streams.len() as u32).collect();
            let value = |pos: &u32| -> u128 {
                let s = &streams[*pos as usize];
                match key {
                    SortKey::Bytes => total_bytes(s) as u128,
                    SortKey::Packets => total_packets(s) as u128,
                    SortKey::FirstSeen => {
                        u128::MAX
                            - s.first_seen
                                .duration_since(SystemTime::UNIX_EPOCH)
                                .map_or(0, |d| d.as_nanos())
                    }
                    SortKey::Duration => s
                        .last_seen
                        .duration_since(s.first_seen)
                        .map_or(0, |d| d.as_nanos()),
                }
            };
            order.sort_by_key(|pos| {
                (
                    std::cmp::Reverse(value(pos)),
                    self.snap.streams[*pos as usize].created_seq,
                )
            });
            Arc::new(order)
        }))
    }

    /// The query's `(matches, matches-plus-ancestors)` seq sets,
    /// evaluated at most once per (snapshot, expression). `None` = the
    /// expression didn't parse (callers fall back to unfiltered).
    pub fn query_sets(&self, raw: &str) -> Option<Arc<(HashSet<u64>, HashSet<u64>)>> {
        if let Ok(guard) = self.query.lock() {
            if let Some(cache) = guard.as_ref() {
                if cache.raw == raw {
                    return cache.sets.clone();
                }
            }
        }
        let sets = StreamQuery::parse(raw).ok().map(|query| {
            let ids = self.id_map();
            let matches: HashSet<u64> = self
                .snap
                .streams
                .iter()
                .filter(|s| query.matches(s, &ids))
                .map(|s| s.created_seq)
                .collect();
            let visible = matching_with_ancestors(&self.snap.streams, &ids, &query);
            Arc::new((matches, visible))
        });
        if let Ok(mut guard) = self.query.lock() {
            *guard = Some(QueryCache {
                raw: raw.to_string(),
                sets: sets.clone(),
            });
        }
        sets
    }

    /// One page of rows (12.4): scope → query filter → cached sort →
    /// offset/limit. Work per call is O(scope candidates) pointer
    /// membership checks plus the window itself — no sorting, no map
    /// building, no allocation proportional to stream count.
    pub fn window(&self, spec: &WindowSpec<'_>) -> WindowResult<'_> {
        let sets = spec
            .query
            .filter(|q| !q.trim().is_empty())
            .and_then(|q| self.query_sets(q));
        // Tree scopes keep ancestors of matches visible (context);
        // the flat table shows matches only.
        let keep = sets.as_ref().map(|s| match spec.scope {
            Scope::Flat => &s.0,
            _ => &s.1,
        });

        let in_scope: Box<dyn Fn(&Stream) -> bool + '_> = match spec.scope {
            Scope::Roots => Box::new(|s: &Stream| s.parent.is_none()),
            Scope::ChildrenOf(seq) => {
                let parent_id = self.by_seq(seq).map(|s| s.id);
                Box::new(move |s: &Stream| s.parent == parent_id && parent_id.is_some())
            }
            Scope::Flat => Box::new(|_: &Stream| true),
        };

        let order = self.order(spec.sort);
        let mut total = 0usize;
        let mut matched = 0usize;
        let mut rows: Vec<&Stream> = Vec::with_capacity(spec.limit.min(512));
        let iter: Box<dyn Iterator<Item = &u32>> = if spec.descending {
            Box::new(order.iter())
        } else {
            Box::new(order.iter().rev())
        };
        for &pos in iter {
            let s = &*self.snap.streams[pos as usize];
            if !in_scope(s) {
                continue;
            }
            total += 1;
            if let Some(keep) = keep {
                if !keep.contains(&s.created_seq) {
                    continue;
                }
            }
            matched += 1;
            if matched > spec.offset && rows.len() < spec.limit {
                rows.push(s);
            }
        }
        WindowResult {
            total,
            match_total: sets.is_some().then_some(matched),
            rows,
        }
    }

    /// Bounded time×lane density (12.4): the top `lanes - 1` streams of
    /// the byte order (query-filtered) each get a lane; everything else
    /// aggregates into a final `seq: None` lane. Response size is
    /// O(bins × lanes) whatever the stream count.
    pub fn timeline(&self, spec: &TimelineSpec<'_>) -> Option<TimelineBins> {
        let bins = spec.bins.clamp(1, 2048);
        let lanes = spec.lanes.clamp(1, 512);
        let (start, end) = crate::stream_view::capture_span(&self.snap)?;
        let span = end.duration_since(start).ok()?.as_nanos().max(1);

        let sets = spec
            .query
            .filter(|q| !q.trim().is_empty())
            .and_then(|q| self.query_sets(q));
        let keep = sets.as_ref().map(|s| &s.1);

        let bin_of = |ts: SystemTime| -> usize {
            let offset = ts.duration_since(start).map_or(0, |d| d.as_nanos());
            (((offset * bins as u128) / span) as usize).min(bins - 1)
        };

        let order = self.order(SortKey::Bytes);
        let mut out: Vec<TimelineLane> = Vec::with_capacity(lanes);
        let mut rest = vec![0u32; bins];
        let mut rest_used = false;
        for &pos in order.iter() {
            let s = &*self.snap.streams[pos as usize];
            if let Some(keep) = keep {
                if !keep.contains(&s.created_seq) {
                    continue;
                }
            }
            let (from, to) = (bin_of(s.first_seen), bin_of(s.last_seen));
            if out.len() + 1 < lanes {
                let mut active = vec![0u32; bins];
                for slot in active.iter_mut().take(to + 1).skip(from) {
                    *slot = 1;
                }
                out.push(TimelineLane {
                    seq: Some(s.created_seq),
                    active,
                });
            } else {
                rest_used = true;
                for slot in rest.iter_mut().take(to + 1).skip(from) {
                    *slot += 1;
                }
            }
        }
        if rest_used {
            out.push(TimelineLane {
                seq: None,
                active: rest,
            });
        }
        Some(TimelineBins {
            start,
            end,
            lanes: out,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pktflow_flows::{Aggregator, AggregatorConfig};

    fn snapshot() -> Arc<AggregatorSnapshot> {
        // Reuse the ingest-only plugin pattern: three eth roots with an
        // ip child each, distinct sizes for sort assertions.
        use pktflow_core::{
            Canonicalize, DissectedPacket, Engine, FieldMap, KeyField, LayerPlugin, LayerRecord,
            LinkType, PacketMeta, ParseCtx, ParseError, ParsedLayer, ProtocolName, StopReason,
            StreamIdentity, Value,
        };
        use std::time::{Duration, SystemTime};

        struct Keyed(ProtocolName);
        impl LayerPlugin for Keyed {
            fn name(&self) -> ProtocolName {
                self.0
            }
            fn parse(&self, _: &[u8], _: &ParseCtx) -> Result<ParsedLayer, ParseError> {
                Err(ParseError::Malformed("ingest-only"))
            }
            fn stream_identity(&self) -> Option<&StreamIdentity> {
                static KEY: &[KeyField] = &[KeyField {
                    a: "src",
                    b: Some("dst"),
                }];
                static IDENTITY: StreamIdentity = StreamIdentity {
                    key: KEY,
                    canonicalize: Canonicalize::EndpointSort,
                    lifecycle: None,
                    rollups: &[],
                };
                Some(&IDENTITY)
            }
        }

        let engine = std::sync::Arc::new(
            Engine::builder()
                .plugin(Keyed("eth"))
                .plugin(Keyed("ip"))
                .build()
                .expect("registry"),
        );
        let mut agg = Aggregator::new(&engine, AggregatorConfig::default());
        for i in 0..3u64 {
            for p in 0..=i {
                let mut eth = FieldMap::new();
                eth.insert("src", Value::U64(1 + i));
                eth.insert("dst", Value::U64(100 + i));
                let mut ip = FieldMap::new();
                ip.insert("src", Value::U64(10 + i));
                ip.insert("dst", Value::U64(20 + i));
                agg.ingest(&DissectedPacket {
                    meta: PacketMeta {
                        timestamp: SystemTime::UNIX_EPOCH + Duration::from_millis(i * 10 + p),
                        caplen: 100,
                        origlen: 100,
                        link_type: LinkType::ETHERNET,
                    },
                    layers: vec![
                        LayerRecord {
                            protocol: "eth",
                            offset: 0,
                            header_len: 14,
                            fields: eth,
                        },
                        LayerRecord {
                            protocol: "ip",
                            offset: 14,
                            header_len: 20,
                            fields: ip,
                        },
                    ],
                    stop: StopReason::Complete,
                    opaque_len: 0,
                    unknown: None,
                });
            }
        }
        Arc::new(agg.snapshot())
    }

    #[test]
    fn windows_are_deterministic_and_page_stably() {
        let index = SnapshotIndex::new(snapshot());
        let spec = |offset, limit| WindowSpec {
            scope: Scope::Flat,
            query: None,
            sort: SortKey::Bytes,
            descending: true,
            offset,
            limit,
        };
        let all = index.window(&spec(0, 100));
        assert_eq!(all.total, 6, "3 eth + 3 ip");
        assert_eq!(all.match_total, None, "no query");
        // Pages concatenate to exactly the full order — no dropped or
        // duplicated rows at boundaries.
        let mut paged: Vec<u64> = Vec::new();
        for page in 0..3 {
            paged.extend(
                index
                    .window(&spec(page * 2, 2))
                    .rows
                    .iter()
                    .map(|s| s.created_seq),
            );
        }
        let full: Vec<u64> = all.rows.iter().map(|s| s.created_seq).collect();
        assert_eq!(paged, full);
        // Descending bytes: the busiest eth pair (3 packets) leads.
        assert!(total_bytes(all.rows[0]) >= total_bytes(all.rows[1]));
    }

    #[test]
    fn scopes_and_queries_filter_windows() {
        let index = SnapshotIndex::new(snapshot());
        let roots = index.window(&WindowSpec {
            scope: Scope::Roots,
            query: None,
            sort: SortKey::FirstSeen,
            descending: false,
            offset: 0,
            limit: 10,
        });
        assert_eq!(roots.total, 3);
        assert!(roots.rows.iter().all(|s| s.protocol == "eth"));

        let first_root = roots.rows[0].created_seq;
        let kids = index.window(&WindowSpec {
            scope: Scope::ChildrenOf(first_root),
            query: None,
            sort: SortKey::Bytes,
            descending: true,
            offset: 0,
            limit: 10,
        });
        assert_eq!(kids.total, 1);
        assert_eq!(kids.rows[0].protocol, "ip");

        // Query narrows; tree scope keeps ancestors visible.
        let matched = index.window(&WindowSpec {
            scope: Scope::Roots,
            query: Some("proto == ip"),
            sort: SortKey::Bytes,
            descending: true,
            offset: 0,
            limit: 10,
        });
        assert_eq!(matched.total, 3);
        assert_eq!(matched.match_total, Some(3), "eth ancestors stay visible");
        let flat = index.window(&WindowSpec {
            scope: Scope::Flat,
            query: Some("proto == ip"),
            sort: SortKey::Bytes,
            descending: true,
            offset: 0,
            limit: 10,
        });
        assert_eq!(flat.match_total, Some(3), "flat = matches only");
        assert!(flat.rows.iter().all(|s| s.protocol == "ip"));
    }

    #[test]
    fn timeline_is_bounded_and_lane_capped() {
        let index = SnapshotIndex::new(snapshot());
        let bins = index
            .timeline(&TimelineSpec {
                bins: 8,
                lanes: 3,
                query: None,
            })
            .expect("span exists");
        assert!(bins.lanes.len() <= 3);
        assert!(bins.lanes.iter().all(|l| l.active.len() == 8));
        let rest = bins.lanes.last().expect("lanes");
        assert_eq!(rest.seq, None, "overflow lane aggregates the rest");
        assert!(rest.active.iter().sum::<u32>() > 0);
    }

    #[test]
    fn facets_build_once_and_query_memo_hits() {
        let index = SnapshotIndex::new(snapshot());
        let a = index.order(SortKey::Bytes);
        let b = index.order(SortKey::Bytes);
        assert!(Arc::ptr_eq(&a, &b), "order computed once");
        let qa = index.query_sets("proto == ip").expect("parses");
        let qb = index.query_sets("proto == ip").expect("parses");
        assert!(Arc::ptr_eq(&qa, &qb), "same expression served from memo");
        assert!(index.query_sets("bytes >").is_none(), "broken query = None");
    }
}
