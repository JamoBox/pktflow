//! `pktflow-flows` — the stream aggregator (task 05).
//!
//! Flow keys, stream store, hierarchy, rollups, lifecycle, eviction, and
//! queries. Protocol-free and OS-free; never depends on `pktflow-plugins`.

pub mod key;

pub use key::flow_key;
