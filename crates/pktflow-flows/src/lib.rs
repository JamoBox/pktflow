//! `pktflow-flows` — the stream aggregator (task 05).
//!
//! Flow keys, stream store, hierarchy, rollups, lifecycle, eviction, and
//! queries. Protocol-free and OS-free; never depends on `pktflow-plugins`.

pub mod key;
pub mod rollup;
pub mod store;

pub use key::flow_key;
pub use rollup::{Rollup, RollupSet, SeriesPoint, ACCUMULATE_SET_CAP};
pub use store::{
    dir_index, Aggregator, AggregatorConfig, CloseReason, DirStats, EvictedStream, EvictionPolicy,
    Stream, StreamId, Totals,
};
