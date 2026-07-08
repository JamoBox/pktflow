//! Unknown-occurrence diagnostics (10.1, D11): what the bytes looked like
//! and which registered plugins came closest, captured only when dissection
//! safely stops on the unknown *and* a caller opts in
//! (`ParseOpts::diagnose_unknown`).
//!
//! This is a reporting-only side channel: it never feeds back into the
//! routing decision that already happened (03.4's no-phantom-streams gate
//! stays absolute — see the module doc on [`crate::router`]).

use smallvec::SmallVec;

use crate::context::ParseCtx;
use crate::engine::Engine;
use crate::error::{StopClass, StopReason};
use crate::packet::ProtocolName;
use crate::plugin::Confidence;
use crate::route::RouteId;

/// Bounded prefix length for [`UnknownDiagnostics::sample`] — larger than
/// packets-mode's 64-byte `-vv` peek (08.4) since this is the primary
/// artifact a developer works from.
pub const SAMPLE_CAP: usize = 256;

/// Why dissection stopped on the unknown — D9's `StopClass::UnknownPayload`,
/// split into its two distinct developer-facing stories.
///
/// **The one deliberate, documented crack in the no-phantom-streams gate
/// (03.4, cross-referenced there):** building the `UnclaimedRoute` variant
/// scores the fallback pool's `probe()` against bytes the gate forbids
/// heuristics from ever routing. The crack is narrow by construction — that
/// probing can only produce a `Confidence` number for a human to read here,
/// never a `LayerRecord` or continued dissection.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UnknownContext {
    /// `Hint::Route`/`Hint::Candidates` named something no plugin claims
    /// (03.4's gate fired).
    UnclaimedRoute {
        predecessor: ProtocolName,
        route: RouteId,
    },
    /// `Hint::Unknown` and the fallback pool produced no winner
    /// ≥ `MIN_CONFIDENCE` (03.3).
    NoHeuristicWinner { predecessor: ProtocolName },
}

/// Evidence captured at an unknown stop (opt-in, see the module doc).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct UnknownDiagnostics {
    pub context: UnknownContext,
    /// Ranked, best first, up to 5. A reporting-only score list — never
    /// used to pick a plugin or continue dissection.
    pub near_misses: SmallVec<[(ProtocolName, Confidence); 5]>,
    /// Bounded prefix of the exact byte slice dissection stopped at (the
    /// same slice that becomes `opaque_len`, D9).
    pub sample: Box<[u8]>,
}

impl Engine {
    /// Builds [`UnknownDiagnostics`] for a stop that just happened via
    /// [`Engine::resolve_next`]. `bytes` must be the exact remaining-payload
    /// slice offered to that resolution (the same slice `opaque_len`
    /// accounts for). `None` when `stop` isn't `StopClass::UnknownPayload`.
    pub(crate) fn diagnose_unknown(
        &self,
        stop: StopReason,
        bytes: &[u8],
        ctx: &ParseCtx,
    ) -> Option<UnknownDiagnostics> {
        let context = match stop {
            StopReason::UnclaimedRoute(route) => UnknownContext::UnclaimedRoute {
                predecessor: ctx.prev()?.protocol,
                route,
            },
            StopReason::UnknownHint => UnknownContext::NoHeuristicWinner {
                predecessor: ctx.prev()?.protocol,
            },
            _ => {
                debug_assert!(stop.class() != StopClass::UnknownPayload, "{stop:?}");
                return None;
            }
        };

        // Same scoring function 03.3's fallback winner search uses (shared,
        // not re-derived), just unfiltered by the routing floor — a
        // developer wants to see sub-`MIN_CONFIDENCE` near-misses too.
        let mut scored = self.score_fallback_pool(bytes, ctx);
        // Stable sort: ties keep registration order, so ranking is
        // deterministic for identical byte input without needing a
        // selection tie-break (this is reporting, not routing).
        scored.sort_by_key(|&(score, _)| std::cmp::Reverse(score));
        let near_misses = scored
            .into_iter()
            .take(5)
            .map(|(score, p)| (p.name(), Confidence::new(score)))
            .collect();

        let cap = bytes.len().min(SAMPLE_CAP);
        let sample = bytes[..cap].to_vec().into_boxed_slice();

        Some(UnknownDiagnostics {
            context,
            near_misses,
            sample,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::SystemTime;

    use super::*;
    use crate::depth::Depth;
    use crate::error::ParseError;
    use crate::packet::{LayerRecord, LinkType, PacketMeta};
    use crate::plugin::{LayerPlugin, ParsedLayer};
    use crate::value::FieldMap;

    /// Probing-only plugin: never claims a route, always declines to
    /// parse, counts every `probe()` call.
    struct Prober {
        name: ProtocolName,
        confidence: u8,
        calls: Arc<AtomicUsize>,
    }

    impl LayerPlugin for Prober {
        fn name(&self) -> ProtocolName {
            self.name
        }

        fn parse(&self, _bytes: &[u8], _ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
            Err(ParseError::Malformed("never routed"))
        }

        fn has_probe(&self) -> bool {
            true
        }

        fn probe(&self, _bytes: &[u8], _ctx: &ParseCtx) -> Option<Confidence> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Some(Confidence::new(self.confidence))
        }
    }

    fn prober(name: ProtocolName, confidence: u8) -> Prober {
        Prober {
            name,
            confidence,
            calls: Arc::new(AtomicUsize::new(0)),
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

    fn prev_layer(protocol: ProtocolName) -> LayerRecord {
        LayerRecord {
            protocol,
            offset: 0,
            header_len: 0,
            fields: FieldMap::new(),
        }
    }

    #[test]
    fn unclaimed_route_scores_the_full_pool_despite_no_claim() {
        let calls = Arc::new(AtomicUsize::new(0));
        let engine = Engine::builder()
            .plugin(Prober {
                name: "guess",
                confidence: 30,
                calls: Arc::clone(&calls),
            })
            .build()
            .expect("valid registry");
        let prev = [prev_layer("udp")];
        let m = meta();
        let ctx = ParseCtx::new(&prev, Depth::Full, &m);
        let bytes = [0xAAu8; 4];

        // The gate forbids `heuristic_fallback` from ever routing here —
        // this is the one place a probe legitimately runs anyway (10.1's
        // documented crack), purely to report.
        let diag = engine
            .diagnose_unknown(
                StopReason::UnclaimedRoute(RouteId::UdpPort(4433)),
                &bytes,
                &ctx,
            )
            .expect("UnclaimedRoute is StopClass::UnknownPayload");

        assert_eq!(
            diag.context,
            UnknownContext::UnclaimedRoute {
                predecessor: "udp",
                route: RouteId::UdpPort(4433),
            }
        );
        assert_eq!(
            diag.near_misses.as_slice(),
            [("guess", Confidence::new(30))]
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn sample_never_exceeds_cap_and_handles_a_short_remainder() {
        let engine = Engine::builder().build().expect("valid registry");
        let prev = [prev_layer("udp")];
        let m = meta();
        let ctx = ParseCtx::new(&prev, Depth::Full, &m);

        let long = vec![0xABu8; SAMPLE_CAP + 100];
        let diag = engine
            .diagnose_unknown(StopReason::UnknownHint, &long, &ctx)
            .expect("diagnoses");
        assert_eq!(diag.sample.len(), SAMPLE_CAP);
        assert_eq!(&*diag.sample, &long[..SAMPLE_CAP]);

        // Edge case: fewer bytes remain than the cap — must not panic.
        let short = [0x01u8, 0x02, 0x03];
        let diag = engine
            .diagnose_unknown(StopReason::UnknownHint, &short, &ctx)
            .expect("diagnoses");
        assert_eq!(&*diag.sample, &short[..]);
    }

    #[test]
    fn non_unknown_stops_never_diagnose() {
        let engine = Engine::builder().build().expect("valid registry");
        let prev = [prev_layer("udp")];
        let m = meta();
        let ctx = ParseCtx::new(&prev, Depth::Full, &m);
        for stop in [
            StopReason::Complete,
            StopReason::Terminal,
            StopReason::Truncated { needed: 4, have: 1 },
            StopReason::PluginError,
            StopReason::DepthCap,
        ] {
            assert!(engine.diagnose_unknown(stop, &[0xAA], &ctx).is_none());
        }
    }

    #[test]
    fn near_misses_are_ranked_best_first_capped_at_five_deterministically() {
        let engine = Engine::builder()
            .plugin(prober("a", 10))
            .plugin(prober("b", 90))
            .plugin(prober("c", 40))
            .plugin(prober("d", 90))
            .plugin(prober("e", 5))
            .plugin(prober("f", 70))
            .build()
            .expect("valid registry");
        let m = meta();
        let prev = [prev_layer("eth")];
        let ctx = ParseCtx::new(&prev, Depth::Full, &m);

        let diag = engine
            .diagnose_unknown(StopReason::UnknownHint, &[0xAA, 0xBB], &ctx)
            .expect("diagnoses");

        let names: Vec<_> = diag.near_misses.iter().map(|(n, _)| *n).collect();
        // "b" and "d" tie at 90: stable sort keeps earliest registration.
        assert_eq!(names, ["b", "d", "f", "c", "a"]);
    }
}
