//! Extraction depth: the caller-set knob for how much metadata plugins
//! extract per layer, and the flow-key floor stream aggregation requires
//! (01.3, FR-16).

/// How much metadata a plugin extracts for one layer.
///
/// The ordering is semantic — plugins branch with comparisons like
/// `depth >= Depth::Keys`.
///
/// # Plugin contract (enforced mechanically by the test kit, 09.1)
///
/// Whenever the effective depth is ≥ [`Depth::Keys`], a plugin must extract
/// *at least* the flow-key fields it declares in its stream identity (02.4).
/// Stream aggregation is built on that guarantee.
///
/// Depth is per parse session: fixed for all layers of a packet (no
/// per-layer depth in v1).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Depth {
    /// Parse for length + routing only; empty `FieldMap`.
    None,
    /// Flow-key/identity fields only (addresses, ports, ids).
    Keys,
    /// `Keys` + structural fields (lengths, flags, types, TTLs).
    Structural,
    /// Everything the plugin knows how to extract.
    Full,
}

/// Per-parse-session options handed to the engine (04.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ParseOpts {
    /// Requested depth; the engine clamps it via [`ParseOpts::effective_depth`].
    pub depth: Depth,
    /// Enables the flow-key floor: streams cannot be keyed without key fields.
    pub aggregation: bool,
    /// Runaway guard — a hostile packet + a buggy plugin could
    /// self-encapsulate forever; hitting the cap is `StopReason::DepthCap`.
    pub max_layers: usize,
    /// Forced entry (04.2 tier 1): "these bytes start at this protocol"
    /// (tooling, tests, tunnel re-entry). Beats the link-type route. An
    /// unknown name is a caller bug surfaced at `layers()` call time.
    pub entry: Option<crate::packet::ProtocolName>,
    /// Opt-in for heuristic first-layer identification when no link-type
    /// route exists (04.2 tier 3). Default **false**: an unclaimed link
    /// type is a configuration gap the user should see, not silently
    /// guess around.
    pub allow_entry_heuristics: bool,
    /// Opt-in unknown-occurrence diagnostics (10.1, D11). Default
    /// **false** — off the hot path; every caller but `pktflow unknown`
    /// (10.3) leaves this unset so the feature's existence costs nothing.
    pub diagnose_unknown: bool,
}

impl Default for ParseOpts {
    fn default() -> Self {
        Self {
            depth: Depth::Full,
            aggregation: true,
            max_layers: 32,
            entry: None,
            allow_entry_heuristics: false,
            diagnose_unknown: false,
        }
    }
}

impl ParseOpts {
    /// The depth plugins actually observe.
    ///
    /// Flow-key floor (FR-16): with aggregation enabled this is
    /// `max(requested, Keys)` — the clamp lives here in the engine
    /// configuration, never in individual plugins, which simply honor the
    /// effective depth they receive.
    pub fn effective_depth(&self) -> Depth {
        if self.aggregation {
            self.depth.max(Depth::Keys)
        } else {
            self.depth
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn depth_ordering_is_none_keys_structural_full() {
        assert!(Depth::None < Depth::Keys);
        assert!(Depth::Keys < Depth::Structural);
        assert!(Depth::Structural < Depth::Full);
        // The comparison style plugins use.
        assert!(Depth::Structural >= Depth::Keys);
        assert!(Depth::None < Depth::Full);
    }

    #[test]
    fn aggregation_clamps_requested_none_to_keys() {
        let opts = ParseOpts {
            depth: Depth::None,
            aggregation: true,
            ..ParseOpts::default()
        };
        assert_eq!(opts.effective_depth(), Depth::Keys);
    }

    #[test]
    fn aggregation_leaves_deeper_requests_alone() {
        for depth in [Depth::Keys, Depth::Structural, Depth::Full] {
            let opts = ParseOpts {
                depth,
                aggregation: true,
                ..ParseOpts::default()
            };
            assert_eq!(opts.effective_depth(), depth);
        }
    }

    #[test]
    fn no_aggregation_means_no_floor() {
        let opts = ParseOpts {
            depth: Depth::None,
            aggregation: false,
            ..ParseOpts::default()
        };
        assert_eq!(opts.effective_depth(), Depth::None);
    }

    #[test]
    fn defaults_are_full_depth_with_aggregation_and_cap() {
        let opts = ParseOpts::default();
        assert_eq!(opts.depth, Depth::Full);
        assert!(opts.aggregation);
        assert_eq!(opts.max_layers, 32);
        assert_eq!(opts.entry, None);
        assert!(!opts.allow_entry_heuristics);
        assert!(!opts.diagnose_unknown);
    }
}
