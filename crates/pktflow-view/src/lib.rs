//! `pktflow-view` — the shared presentation layer.
//!
//! Everything a front-end (CLI, TUI, web) needs to *show* streams without
//! re-deriving it: FR-28 value formatting, canonical A ↔ B endpoint
//! rendering, D8-shaped JSON records, and the [`SnapshotHub`] that carries
//! live [`pktflow_flows::AggregatorSnapshot`]s from the single-writer
//! aggregation thread to any number of readers. Protocol-free and
//! UI-toolkit-free by construction.

pub mod fmt;
pub mod hub;
pub mod json;
pub mod query;
pub mod stream_view;

pub use hub::SnapshotHub;
pub use query::{QueryError, StreamQuery};
pub use stream_view::{
    by_id, child_chain_str, close_reason_str, endpoint_sides, endpoints_str, lineage_str,
    total_bytes, total_packets,
};
