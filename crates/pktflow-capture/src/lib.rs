//! `pktflow-capture` — pcap-backed packet sources (task 07).
//!
//! Live capture, offline `.pcap`/`.pcapng` replay, and interface enumeration.
//! The only crate (besides the CLI that links it) touching libpcap/Npcap.

pub mod error;

pub use error::CaptureError;
