//! `pktflow-capture` — pcap-backed packet sources (task 07).
//!
//! Live capture, offline `.pcap`/`.pcapng` replay, and interface enumeration.
//! The only crate (besides the CLI that links it) touching libpcap/Npcap.

pub mod error;
pub mod live;
pub mod offline;
pub mod source;

pub use error::{CaptureError, PERMISSION_REMEDIATION};
pub use live::{list_interfaces, InterfaceInfo, LiveConfig, LiveSource};
pub use offline::FileSource;
pub use source::{pump, CaptureStats, MockSource, PacketSource, PumpReport, RawPacket};
