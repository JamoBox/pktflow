//! Stream identity declaration types (02.4) and the flow-key vocabulary
//! they reference (05.1, 05.5).
//!
//! The plugin *declares*; the aggregator (05) does all grouping — the PRD's
//! central "protocol-defined, engine-aggregated" split. Declaration types
//! live here in core so plugins and the aggregator share one contract.

use smallvec::SmallVec;

use crate::value::{FieldMap, FieldName};

/// A canonical flow-key byte encoding (05.1). `Eq + Hash`; 40 inline bytes
/// cover an IPv6 pair + qualifiers without heap.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct FlowKey(SmallVec<[u8; 40]>);

impl FlowKey {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(SmallVec::from_slice(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Which way a packet travels relative to the canonical A/B endpoints (D3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PacketDirection {
    AtoB,
    BtoA,
}

/// Flow-key construction failure (05.1). Routine diagnostics, not a panic:
/// the layer forms no stream but the packet still counts into parents.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KeyError {
    /// The identity names a field the parse output does not carry — a
    /// plugin contract violation the 09.1 kit should have caught.
    #[error("flow-key field {0:?} missing from parse output")]
    MissingField(FieldName),
}

/// A plugin-owned lifecycle state label, e.g. `"syn_sent"` (05.5).
pub type StateName = &'static str;

/// One component of a stream's endpoint identity.
///
/// # The 5-tuple is a tree path, not a key (D10)
///
/// Keys are scoped to `(parent stream, protocol)`, so a key never re-embeds
/// its parent's fields. TCP's key is `[{src_port, dst_port}]` — ports only:
/// the addresses come from the parent IP stream via hierarchy scoping, and
/// the classic 5-tuple is the *(IP-pair parent, port-pair, protocol)* path
/// in the stream tree. This is the design's least obvious consequence of
/// D10.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct KeyField {
    /// Field naming endpoint-A's component, e.g. `"src_mac"`.
    pub a: FieldName,
    /// Endpoint-B's counterpart, e.g. `"dst_mac"`; `None` for symmetric /
    /// non-directional components (VXLAN VNI, GRE key) that belong to the
    /// stream but not to an endpoint.
    pub b: Option<FieldName>,
}

/// Direction rule for one protocol's streams.
#[derive(Clone, Copy, Debug)]
pub enum Canonicalize {
    /// D3: order endpoints lexicographically by their concatenated
    /// component bytes.
    EndpointSort,
    /// Protocol supplies its own rule (rare; escape hatch, must be
    /// deterministic — 09.1 spot-checks by running it twice per packet).
    Custom(fn(&FieldMap) -> Result<(FlowKey, PacketDirection), KeyError>),
}

/// How per-packet fields advance a session state machine (05.5).
///
/// The aggregator owns the state variable; the plugin owns the transition
/// logic. `advance` is a pure function: (this packet's fields, current
/// state, direction) → new state.
#[derive(Clone, Copy, Debug)]
pub struct LifecycleSpec {
    /// e.g. `"new"`.
    pub initial: StateName,
    pub advance: fn(&FieldMap, StateName, PacketDirection) -> StateName,
    /// States that mean the session is over (drives D2 close handling).
    pub closed_states: &'static [StateName],
}

/// Per-field retention beyond baseline stats (05.4, D4).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RollupSpec {
    pub field: FieldName,
    pub kind: RollupKind,
}

/// The three rollup kinds of D4.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RollupKind {
    /// Bounded distinct-value set + count.
    Accumulate,
    /// First + last value.
    Sample,
    /// Bounded time-ordered ring (D4 default cap 1024).
    Series { cap: usize },
}

/// The declaration that makes a dissector a conversation source (02.4).
///
/// A plugin returning `None` from `stream_identity()` dissects normally;
/// its layer creates no stream and is skipped in hierarchy nesting.
#[derive(Clone, Copy, Debug)]
pub struct StreamIdentity {
    /// One entry per key component. Every named field must be extracted by
    /// the plugin at depth ≥ `Keys` (01.3); the 09.1 kit cross-checks.
    pub key: &'static [KeyField],
    /// Direction rule. Default rule of D3 is [`Canonicalize::EndpointSort`].
    pub canonicalize: Canonicalize,
    /// Optional lifecycle: how per-packet fields advance a session state
    /// machine (05.5).
    pub lifecycle: Option<LifecycleSpec>,
    /// Optional per-field retention beyond baseline stats (05.4).
    pub rollups: &'static [RollupSpec],
}
