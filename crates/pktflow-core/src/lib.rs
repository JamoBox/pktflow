//! `pktflow-core` — values, layers, plugin trait, router, and lazy parser.
//!
//! The protocol-free dissection substrate (tasks 01–04). Holds no protocol
//! knowledge, no capture dependency, and no OS conditionals.

pub mod bytes;
pub mod error;
pub mod packet;
pub mod route;
pub mod value;

pub use bytes::{ByteReader, Truncated};
pub use error::{ParseError, StopReason};
pub use packet::{DissectedPacket, LayerRecord, LinkType, PacketMeta, ProtocolName};
pub use route::RouteId;
pub use value::{FieldMap, FieldName, SmallBytes, Value};
