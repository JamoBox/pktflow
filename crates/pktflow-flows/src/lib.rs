//! `pktflow-flows` — the stream aggregator (task 05).
//!
//! Flow keys, stream store, hierarchy, rollups, lifecycle, eviction, and
//! queries. Protocol-free and OS-free; never depends on `pktflow-plugins`.

pub mod key;
pub mod rollup;
pub mod store;
pub mod unknown;

pub use key::flow_key;
pub use rollup::{Rollup, RollupSet, SeriesPoint, ACCUMULATE_SET_CAP};
pub use store::{
    dir_index, AggregateSummary, Aggregator, AggregatorConfig, AggregatorSnapshot, CloseReason,
    CondensedInfo, DirStats, EvictedStream, EvictionPolicy, MergedStreamView, ProtocolCounts,
    Stream, StreamId, Totals, DEFAULT_CONDENSE_THRESHOLD, STOP_CLASSES,
};
pub use unknown::{EndpointKey, UnknownGroup, UnknownKey, UnknownRegistryConfig};
