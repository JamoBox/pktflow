//! `pktflow-capture` — pkttap and pktbaffle packet sources (task 07).
//!
//! Live capture, offline `.pcap`/`.pcapng` replay, and interface enumeration.

pub mod error;
pub mod live;
pub mod offline;
pub mod source;

pub use error::{map_pkttap_error, CaptureError, PERMISSION_REMEDIATION};
pub use live::{list_interfaces, InterfaceInfo, LiveConfig, LiveSource};
pub use offline::FileSource;
pub use source::{pump, CaptureStats, MockSource, PacketSource, PumpReport, RawPacket};
