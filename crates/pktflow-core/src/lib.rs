//! `pktflow-core` — values, layers, plugin trait, router, and lazy parser.
//!
//! The protocol-free dissection substrate (tasks 01–04). Holds no protocol
//! knowledge, no capture dependency, and no OS conditionals.

pub mod bytes;
pub mod context;
pub mod depth;
pub mod diagnostics;
pub mod engine;
pub mod error;
pub mod packet;
pub mod parser;
pub mod plugin;
pub mod route;
pub mod router;
pub mod stream;
pub mod value;

pub use bytes::{ByteReader, Truncated};
pub use context::ParseCtx;
pub use depth::{Depth, ParseOpts};
pub use diagnostics::{UnknownContext, UnknownDiagnostics, SAMPLE_CAP};
pub use engine::{Engine, EngineBuilder, RegistryError};
pub use error::{ParseError, StopClass, StopReason};
pub use packet::{DissectedPacket, LayerRecord, LinkType, PacketMeta, ProtocolName};
pub use parser::{LayerIter, LayerStep};
pub use plugin::{Confidence, Hint, LayerPlugin, ParsedLayer};
pub use route::RouteId;
pub use router::{StepOutcome, MIN_CONFIDENCE, PRIOR_BOOST};
pub use stream::{
    Canonicalize, CondenseSpec, FlowKey, KeyError, KeyField, LifecycleSpec, PacketDirection,
    RollupKind, RollupSpec, StateName, StreamIdentity,
};
pub use value::{FieldMap, FieldName, SmallBytes, Value};
