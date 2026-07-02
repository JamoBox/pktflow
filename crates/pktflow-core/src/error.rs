//! Error taxonomy for the dissection substrate (00.2, D9).

use crate::bytes::Truncated;
use crate::route::RouteId;

/// A plugin declined the bytes it was offered.
///
/// **Not** a program error — routine data ("these bytes are not my
/// protocol") and cheap by design: `Copy`, no allocation, no backtrace.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ParseError {
    /// The header needed more bytes than the input holds.
    #[error(transparent)]
    Truncated(#[from] Truncated),
    /// The bytes are structurally not this protocol.
    #[error("malformed: {0}")]
    Malformed(&'static str),
}

/// Why a packet's dissection ended (D9, full semantics in 04.3).
///
/// `Copy` and boxed-nothing: stop reasons are per-packet hot-path data.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StopReason {
    /// Payload exhausted after the last layer.
    Complete,
    /// A plugin declared `Hint::Terminal`.
    Terminal,
    /// The gate fired (03.4) — unsupported/encrypted next protocol.
    UnclaimedRoute(RouteId),
    /// `Hint::Unknown` and heuristics found no winner.
    UnknownHint,
    /// A plugin ran out of bytes mid-header.
    Truncated { needed: u16, have: u16 },
    /// Routed/explicit plugin declined or lied (02.1 r3).
    PluginError,
    /// `max_layers` guard (04.1).
    DepthCap,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Allocation-free by construction: a ParseError is Copy, so it can never
    // own a heap allocation or capture a backtrace.
    const _: fn() = || {
        fn assert_copy<T: Copy>() {}
        assert_copy::<ParseError>();
        assert_copy::<StopReason>();
    };

    #[test]
    fn parse_error_displays_without_allocating_context() {
        let truncated: ParseError = Truncated { needed: 4, have: 1 }.into();
        assert_eq!(
            truncated.to_string(),
            "truncated input: needed 4 bytes, have 1"
        );
        assert_eq!(
            ParseError::Malformed("bad checksum").to_string(),
            "malformed: bad checksum"
        );
    }

    #[test]
    fn unclaimed_route_carries_its_id() {
        let stop = StopReason::UnclaimedRoute(RouteId::IpProtocol(99));
        assert_eq!(stop, StopReason::UnclaimedRoute(RouteId::IpProtocol(99)));
        assert_ne!(stop, StopReason::UnclaimedRoute(RouteId::UdpPort(99)));
    }
}
