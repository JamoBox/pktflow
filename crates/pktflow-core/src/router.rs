//! Hint resolution: gated termination (03.4) and heuristic fallback (03.3).
//!
//! The whole decision table lives in [`Engine::resolve_next`] — one place,
//! not spread across the parser. The safety property everything leans on:
//! when a header *names* what follows and we don't have it, **stop**.
//! Heuristics never run on a named-but-unclaimed route, because a
//! misidentified layer fabricates a bogus conversation (no phantom
//! streams, FR-15).
//!
//! **One documented exception (10.1, D11):** an opt-in diagnostic pass may
//! score the fallback pool's `probe()` against bytes at *any*
//! `StopClass::UnknownPayload` stop, including an unclaimed route this
//! table forbids from routing — purely to report near-miss confidence to a
//! developer. It never calls anything that yields a `LayerRecord`, so this
//! invariant is unaffected; see [`crate::diagnostics::UnknownContext`].

use crate::bytes::Truncated;
use crate::context::ParseCtx;
use crate::engine::Engine;
use crate::error::{ParseError, StopReason};
use crate::packet::ProtocolName;
use crate::plugin::{Hint, LayerPlugin, ParsedLayer};
use crate::route::RouteId;

/// Fixed boost a fallback candidate gets when the just-parsed layer is in
/// its `expected_predecessors` (the predecessor prior, FR-14). Engine
/// constant, not per-plugin, so tuning is central; v1 default, revisited
/// with 09.4 data.
pub const PRIOR_BOOST: u8 = 15;

/// Minimum (post-prior) score a fallback winner needs; weak guesses are
/// worse than stopping. Engine constant, v1 default.
pub const MIN_CONFIDENCE: u8 = 50;

/// The outcome of resolving one step: either the next parsed layer, or
/// why dissection stops.
pub enum StepOutcome {
    Layer {
        /// The plugin that parsed (its `name()`, for the `LayerRecord`).
        protocol: ProtocolName,
        parsed: ParsedLayer,
        /// True when the layer came via the fallback pool (03.3 —
        /// diagnostics, D9).
        via_heuristic: bool,
    },
    Stop(StopReason),
}

/// Maps a declined explicit `Route` parse per the 03.4 table: truncation
/// is reported as such, anything else is the plugin declining/lying.
pub(crate) fn route_failure(err: ParseError) -> StopReason {
    match err {
        ParseError::Truncated(Truncated { needed, have }) => StopReason::Truncated {
            needed: u16::try_from(needed).unwrap_or(u16::MAX),
            have: u16::try_from(have).unwrap_or(u16::MAX),
        },
        _ => StopReason::PluginError,
    }
}

/// Explicit-tier dispatch: parse via `p`, verifying rule 3, mapping
/// failures per the `Route` row (truncation reported as such). Shared by
/// `resolve_next` and entry resolution (04.2).
pub(crate) fn dispatch_explicit(p: &dyn LayerPlugin, bytes: &[u8], ctx: &ParseCtx) -> StepOutcome {
    match p.parse(bytes, ctx) {
        Ok(parsed) if parsed.header_len_ok(bytes.len()) => StepOutcome::Layer {
            protocol: p.name(),
            parsed,
            via_heuristic: false,
        },
        Ok(_) => StepOutcome::Stop(StopReason::PluginError),
        Err(e) => StepOutcome::Stop(route_failure(e)),
    }
}

impl Engine {
    /// The 03.4 decision table, row by row (normative). Called by the
    /// parser (04.1) after each layer with that layer's hint and the
    /// remaining payload.
    pub fn resolve_next(&self, hint: &Hint, bytes: &[u8], ctx: &ParseCtx) -> StepOutcome {
        // Row: remaining payload empty → Complete. (Terminal outranks it
        // only in wording; an empty payload stops either way.)
        if bytes.is_empty() {
            return StepOutcome::Stop(StopReason::Complete);
        }

        match hint {
            Hint::Terminal => StepOutcome::Stop(StopReason::Terminal),

            Hint::Route(id) => match self.plugin_for_route(*id) {
                // The gate: named but unclaimed → stop, heuristics forbidden.
                None => StepOutcome::Stop(StopReason::UnclaimedRoute(*id)),
                // Explicit route + failed parse = malformed/truncated, not
                // unknown: no fallback (handled inside dispatch_explicit).
                Some(p) => dispatch_explicit(p, bytes, ctx),
            },

            Hint::Candidates(ids) => {
                let claimed: Vec<(RouteId, &dyn LayerPlugin)> = ids
                    .iter()
                    .filter_map(|&id| self.plugin_for_route(id).map(|p| (id, p)))
                    .collect();
                if claimed.is_empty() {
                    // Same gate: every candidate id was named; none claimed.
                    return match ids.first() {
                        Some(&first) => StepOutcome::Stop(StopReason::UnclaimedRoute(first)),
                        // An empty candidate list is a plugin bug (choose
                        // the most explicit hint you can), not license to
                        // guess.
                        None => StepOutcome::Stop(StopReason::PluginError),
                    };
                }
                // Rank order; each plugin tried at most once on these
                // bytes (no re-selection, FR-15).
                for (_, p) in claimed {
                    if let Ok(parsed) = p.parse(bytes, ctx) {
                        if parsed.header_len_ok(bytes.len()) {
                            return StepOutcome::Layer {
                                protocol: p.name(),
                                parsed,
                                via_heuristic: false,
                            };
                        }
                    }
                }
                StepOutcome::Stop(StopReason::PluginError)
            }

            Hint::ByProtocol(name) => match self.plugin_by_name(name) {
                None => StepOutcome::Stop(StopReason::UnclaimedRoute(RouteId::Custom {
                    space: name,
                    id: 0,
                })),
                Some(p) => match p.parse(bytes, ctx) {
                    Ok(parsed) if parsed.header_len_ok(bytes.len()) => StepOutcome::Layer {
                        protocol: p.name(),
                        parsed,
                        via_heuristic: false,
                    },
                    _ => StepOutcome::Stop(StopReason::PluginError),
                },
            },

            // The only hint that opens the fallback pool (invariant 1).
            Hint::Unknown => match self.heuristic_fallback(bytes, ctx) {
                Some((protocol, parsed)) => StepOutcome::Layer {
                    protocol,
                    parsed,
                    via_heuristic: true,
                },
                None => StepOutcome::Stop(StopReason::UnknownHint),
            },
        }
    }

    /// Scores every fallback-pool plugin's `probe()` against `bytes`, prior
    /// boost applied, **unfiltered by `MIN_CONFIDENCE`**. Shared by
    /// [`Engine::heuristic_fallback`] (which then filters to the routing
    /// floor) and 10.1's diagnostic near-miss ranking (which deliberately
    /// doesn't) — one scoring pass, so the two can never disagree on a
    /// plugin's score for the same bytes.
    pub(crate) fn score_fallback_pool(
        &self,
        bytes: &[u8],
        ctx: &ParseCtx,
    ) -> Vec<(u8, &dyn LayerPlugin)> {
        let prev = ctx.prev().map(|l| l.protocol);

        // Pool order is registration order (03.2) — position doubles as
        // the deterministic tie-break.
        let mut scored: Vec<(u8, &dyn LayerPlugin)> = Vec::new();
        for p in self.fallback_pool() {
            let Some(confidence) = p.probe(bytes, ctx) else {
                continue;
            };
            let mut score = confidence.get();
            if prev.is_some_and(|prev| p.expected_predecessors().contains(&prev)) {
                score = score.saturating_add(PRIOR_BOOST).min(100);
            }
            scored.push((score, p));
        }
        scored
    }

    /// Heuristic fallback (03.3): probing plugins score the bytes, the
    /// predecessor prior weighs in, the best scorer that also *parses*
    /// wins. Deterministic: ties break by registration order, never map
    /// or pointer order. Also used for entry identification (04.2).
    pub fn heuristic_fallback(
        &self,
        bytes: &[u8],
        ctx: &ParseCtx,
    ) -> Option<(ProtocolName, ParsedLayer)> {
        // Below the floor a guess is worse than stopping — and a next-best
        // below the floor after a failed winner is no better.
        let mut candidates: Vec<(u8, &dyn LayerPlugin)> = self
            .score_fallback_pool(bytes, ctx)
            .into_iter()
            .filter(|&(score, _)| score >= MIN_CONFIDENCE)
            .collect();

        // Winner = max score, earliest registration on ties. A winner
        // whose parse fails is dropped and never re-offered these bytes
        // (FR-15); take the next-best until success or exhaustion.
        while !candidates.is_empty() {
            let mut best = 0;
            for (i, &(score, _)) in candidates.iter().enumerate() {
                // Strictly-greater keeps the earliest-registered on ties.
                if score > candidates[best].0 {
                    best = i;
                }
            }
            let (_, p) = candidates.remove(best);
            if let Ok(parsed) = p.parse(bytes, ctx) {
                if parsed.header_len_ok(bytes.len()) {
                    return Some((p.name(), parsed));
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::SystemTime;

    use smallvec::SmallVec;

    use super::*;
    use crate::depth::Depth;
    use crate::packet::{LayerRecord, LinkType, PacketMeta};
    use crate::plugin::Confidence;
    use crate::value::FieldMap;

    /// Probing plugin with a fixed confidence; counts parse calls and can
    /// be told to always decline.
    struct Prober {
        name: ProtocolName,
        confidence: u8,
        predecessors: &'static [ProtocolName],
        declines: bool,
        parse_calls: Arc<AtomicUsize>,
    }

    impl Prober {
        fn new(name: ProtocolName, confidence: u8) -> Self {
            Self {
                name,
                confidence,
                predecessors: &[],
                declines: false,
                parse_calls: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    impl LayerPlugin for Prober {
        fn name(&self) -> ProtocolName {
            self.name
        }

        fn parse(&self, bytes: &[u8], _ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
            self.parse_calls.fetch_add(1, Ordering::SeqCst);
            if self.declines || bytes.is_empty() {
                return Err(ParseError::Malformed("declined"));
            }
            Ok(ParsedLayer {
                header_len: 1,
                fields: FieldMap::new(),
                hint: Hint::Terminal,
            })
        }

        fn expected_predecessors(&self) -> &'static [ProtocolName] {
            self.predecessors
        }

        fn has_probe(&self) -> bool {
            true
        }

        fn probe(&self, _bytes: &[u8], _ctx: &ParseCtx) -> Option<Confidence> {
            Some(Confidence::new(self.confidence))
        }
    }

    /// Claiming, non-probing plugin that succeeds or declines on command.
    struct Claimer {
        name: ProtocolName,
        claims: &'static [RouteId],
        declines: bool,
    }

    impl LayerPlugin for Claimer {
        fn name(&self) -> ProtocolName {
            self.name
        }

        fn parse(&self, bytes: &[u8], _ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
            if self.declines {
                return Err(ParseError::Malformed("declined"));
            }
            if bytes.len() < 2 {
                return Err(ParseError::Truncated(Truncated {
                    needed: 2,
                    have: bytes.len(),
                }));
            }
            Ok(ParsedLayer {
                header_len: 2,
                fields: FieldMap::new(),
                hint: Hint::Terminal,
            })
        }

        fn claims(&self) -> &'static [RouteId] {
            self.claims
        }
    }

    fn meta() -> PacketMeta {
        PacketMeta {
            timestamp: SystemTime::UNIX_EPOCH,
            caplen: 8,
            origlen: 8,
            link_type: LinkType::ETHERNET,
        }
    }

    fn layer(protocol: ProtocolName) -> LayerRecord {
        LayerRecord {
            protocol,
            offset: 0,
            header_len: 0,
            fields: FieldMap::new(),
        }
    }

    const UDP_53: RouteId = RouteId::UdpPort(53);
    const UDP_99: RouteId = RouteId::UdpPort(99);
    const BYTES: &[u8] = &[0xAA, 0xBB, 0xCC, 0xDD];

    fn expect_layer(outcome: StepOutcome) -> (ProtocolName, bool) {
        match outcome {
            StepOutcome::Layer {
                protocol,
                via_heuristic,
                ..
            } => (protocol, via_heuristic),
            StepOutcome::Stop(reason) => panic!("expected a layer, stopped with {reason:?}"),
        }
    }

    fn expect_stop(outcome: StepOutcome) -> StopReason {
        match outcome {
            StepOutcome::Stop(reason) => reason,
            StepOutcome::Layer { protocol, .. } => panic!("expected a stop, parsed {protocol}"),
        }
    }

    // ---- 03.3: scoring, prior, tie-break, floor ----

    #[test]
    fn equal_scores_earlier_registration_wins_both_orders() {
        let m = meta();
        for (first, second, expected) in [("alpha", "beta", "alpha"), ("beta", "alpha", "beta")] {
            let engine = Engine::builder()
                .plugin(Prober::new(first, 60))
                .plugin(Prober::new(second, 60))
                .build()
                .expect("valid");
            let ctx = ParseCtx::new(&[], Depth::Full, &m);
            let (winner, via) = expect_layer(engine.resolve_next(&Hint::Unknown, BYTES, &ctx));
            assert_eq!(winner, expected, "registration order is the tie-break");
            assert!(via, "fallback layers are marked via_heuristic");
        }
    }

    #[test]
    fn predecessor_prior_boosts_past_a_higher_raw_probe() {
        let mut biased = Prober::new("biased", 45); // 45 + 15 = 60
        biased.predecessors = &["udp"];
        let engine = Engine::builder()
            .plugin(Prober::new("raw", 55))
            .plugin(biased)
            .build()
            .expect("valid");
        let m = meta();
        let prev = [layer("udp")];
        let ctx = ParseCtx::new(&prev, Depth::Full, &m);
        let (winner, _) = expect_layer(engine.resolve_next(&Hint::Unknown, BYTES, &ctx));
        assert_eq!(winner, "biased", "PRIOR_BOOST lifts 45 over a raw 55");

        // Without the matching predecessor the raw score wins.
        let ctx = ParseCtx::new(&[], Depth::Full, &m);
        let (winner, _) = expect_layer(engine.resolve_next(&Hint::Unknown, BYTES, &ctx));
        assert_eq!(winner, "raw");
    }

    #[test]
    fn failed_winner_is_dropped_next_best_runs_no_retry() {
        let mut flaky = Prober::new("flaky", 90);
        flaky.declines = true;
        let flaky_calls = Arc::clone(&flaky.parse_calls);
        let steady = Prober::new("steady", 60);
        let steady_calls = Arc::clone(&steady.parse_calls);

        let engine = Engine::builder()
            .plugin(flaky)
            .plugin(steady)
            .build()
            .expect("valid");
        let m = meta();
        let ctx = ParseCtx::new(&[], Depth::Full, &m);

        let (winner, _) = expect_layer(engine.resolve_next(&Hint::Unknown, BYTES, &ctx));
        assert_eq!(winner, "steady", "next-best runs after the winner declines");

        // FR-15: the failed winner was offered these bytes exactly once.
        assert_eq!(flaky_calls.load(Ordering::SeqCst), 1);
        assert_eq!(steady_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn all_candidates_below_the_floor_stop_with_no_layer() {
        let engine = Engine::builder()
            .plugin(Prober::new("weak", 30))
            .plugin(Prober::new("weaker", 49))
            .build()
            .expect("valid");
        let m = meta();
        let ctx = ParseCtx::new(&[], Depth::Full, &m);
        let reason = expect_stop(engine.resolve_next(&Hint::Unknown, BYTES, &ctx));
        assert_eq!(reason, StopReason::UnknownHint);
    }

    // ---- 03.4 decision-table rows exercised through resolve_next ----
    // (03.4's own criteria — fixture + proptest — land with 04.1/06.)

    #[test]
    fn terminal_and_empty_payload_rows() {
        let engine = Engine::builder().build().expect("valid");
        let m = meta();
        let ctx = ParseCtx::new(&[], Depth::Full, &m);
        assert_eq!(
            expect_stop(engine.resolve_next(&Hint::Terminal, BYTES, &ctx)),
            StopReason::Terminal
        );
        assert_eq!(
            expect_stop(engine.resolve_next(&Hint::Unknown, &[], &ctx)),
            StopReason::Complete
        );
    }

    #[test]
    fn route_rows_claimed_unclaimed_and_failures() {
        let engine = Engine::builder()
            .plugin(Claimer {
                name: "dns",
                claims: &[UDP_53],
                declines: false,
            })
            .build()
            .expect("valid");
        let m = meta();
        let ctx = ParseCtx::new(&[], Depth::Full, &m);

        // Claimed + parse ok → continue.
        let (proto, via) = expect_layer(engine.resolve_next(&Hint::Route(UDP_53), BYTES, &ctx));
        assert_eq!((proto, via), ("dns", false));

        // The gate: unclaimed named route stops, heuristics forbidden.
        assert_eq!(
            expect_stop(engine.resolve_next(&Hint::Route(UDP_99), BYTES, &ctx)),
            StopReason::UnclaimedRoute(UDP_99)
        );

        // Claimed but truncated input → Truncated with the plugin's counts.
        assert_eq!(
            expect_stop(engine.resolve_next(&Hint::Route(UDP_53), &[0x01], &ctx)),
            StopReason::Truncated { needed: 2, have: 1 }
        );

        // Claimed but declining (malformed) → PluginError, no fallback —
        // even with a probing plugin registered.
        let engine = Engine::builder()
            .plugin(Claimer {
                name: "dns",
                claims: &[UDP_53],
                declines: true,
            })
            .plugin(Prober::new("guesser", 100))
            .build()
            .expect("valid");
        assert_eq!(
            expect_stop(engine.resolve_next(&Hint::Route(UDP_53), BYTES, &ctx)),
            StopReason::PluginError
        );
    }

    #[test]
    fn candidates_rows() {
        let engine = Engine::builder()
            .plugin(Claimer {
                name: "declines",
                claims: &[UDP_53],
                declines: true,
            })
            .plugin(Claimer {
                name: "accepts",
                claims: &[UDP_99],
                declines: false,
            })
            .build()
            .expect("valid");
        let m = meta();
        let ctx = ParseCtx::new(&[], Depth::Full, &m);

        // First claimed candidate declines, second wins.
        let ids = SmallVec::from_slice(&[UDP_53, UDP_99]);
        let (proto, _) = expect_layer(engine.resolve_next(&Hint::Candidates(ids), BYTES, &ctx));
        assert_eq!(proto, "accepts");

        // None claimed → gate, reporting the first id.
        let ids = SmallVec::from_slice(&[RouteId::UdpPort(1), RouteId::UdpPort(2)]);
        assert_eq!(
            expect_stop(engine.resolve_next(&Hint::Candidates(ids), BYTES, &ctx)),
            StopReason::UnclaimedRoute(RouteId::UdpPort(1))
        );

        // All claimed candidates fail → PluginError.
        let ids = SmallVec::from_slice(&[UDP_53]);
        assert_eq!(
            expect_stop(engine.resolve_next(&Hint::Candidates(ids), BYTES, &ctx)),
            StopReason::PluginError
        );
    }

    #[test]
    fn by_protocol_rows() {
        let engine = Engine::builder()
            .plugin(Claimer {
                name: "ethernet",
                claims: &[],
                declines: false,
            })
            .build()
            .expect("valid");
        let m = meta();
        let ctx = ParseCtx::new(&[], Depth::Full, &m);

        let (proto, _) =
            expect_layer(engine.resolve_next(&Hint::ByProtocol("ethernet"), BYTES, &ctx));
        assert_eq!(proto, "ethernet");

        assert_eq!(
            expect_stop(engine.resolve_next(&Hint::ByProtocol("ghost"), BYTES, &ctx)),
            StopReason::UnclaimedRoute(RouteId::Custom {
                space: "ghost",
                id: 0
            })
        );
    }
}
