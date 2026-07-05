//! The plugin contract: one trait every protocol satisfies (02.1, FR-9).
//!
//! Two required members; everything else defaults, so the minimal plugin
//! is tiny — that minimality is the "well under an hour" success metric's
//! foundation (PRD §8).

use smallvec::SmallVec;

use crate::context::ParseCtx;
use crate::error::ParseError;
use crate::packet::ProtocolName;
use crate::route::RouteId;
use crate::stream::StreamIdentity;
use crate::value::FieldMap;

/// A plugin's declaration of what follows its header (02.2, FR-11).
///
/// Plugins choose the *most explicit* hint they can: emitting [`Hint::Unknown`]
/// when the header has a next-protocol field is a plugin bug.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Hint {
    /// One definite protocol identifier (EtherType 0x0800, IP proto 6,
    /// dst port 53). Router: one lookup; if claimed → dispatch; if
    /// **unclaimed → stop** (gated, FR-15) — the header *named* a protocol
    /// we lack, so heuristics do not run.
    Route(RouteId),
    /// Ranked candidates, best first — e.g. UDP offering
    /// `[dst_port, src_port]` routes. Router: try in order, first claimed
    /// id whose plugin parses successfully wins; all unclaimed → stop
    /// (no heuristics, same gate as `Route`).
    Candidates(SmallVec<[RouteId; 4]>),
    /// Direct dispatch by plugin name — encapsulation where the inner
    /// protocol is fixed (e.g. VXLAN always wraps `"ethernet"`). Bypasses
    /// route-id lookup entirely; unknown name → stop.
    ByProtocol(ProtocolName),
    /// Header named nothing usable; heuristic fallback may run
    /// (gated, 03.4).
    Unknown,
    /// This layer is definitively last (ICMP payload, ARP). No fallback
    /// runs; dissection ends with `StopReason::Terminal`.
    Terminal,
}

/// Self-scored probe confidence, `0..=100` (02.3). Construction clamps, so
/// a value above 100 is unrepresentable.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Confidence(u8);

impl Confidence {
    /// Clamps to 100. Guidance: 90+ = structural invariants verified;
    /// 50–89 = plausible; below 50, don't bother returning one.
    pub fn new(score: u8) -> Self {
        Self(score.min(100))
    }

    pub fn get(self) -> u8 {
        self.0
    }
}

/// A successful parse of exactly one header.
pub struct ParsedLayer {
    /// Bytes this header consumed (options/extensions count as header);
    /// the parser slices the payload after it.
    pub header_len: usize,
    /// Extracted metadata, respecting `ctx.depth()` and the flow-key
    /// floor (01.3).
    pub fields: FieldMap,
    /// What follows (02.2).
    pub hint: Hint,
}

impl ParsedLayer {
    /// Engine-side rule-3 check: a "successful" parse claiming more bytes
    /// than the input holds is a lying plugin. The parser (04.1) treats a
    /// violation as `StopReason::PluginError` instead of corrupting
    /// offsets.
    pub fn header_len_ok(&self, available: usize) -> bool {
        self.header_len <= available
    }
}

/// One protocol dissector (02.1, FR-9). Object-safe, stateless, shared.
///
/// # Contract rules (enforced by the 09.1 test kit where mechanically possible)
///
/// 1. **Parse one header only.** Never look into the payload beyond your
///    own header, except to compute `header_len`.
/// 2. **Decline, don't guess.** If bytes can't be your protocol, return
///    `Err(ParseError)` — cheap and routine (00.2). Never return a
///    half-parsed success.
/// 3. **`header_len ≤ bytes.len()`** on success; the parser verifies and
///    treats violation as `PluginError`.
/// 4. **Depth-honoring:** field extraction gated on `ctx.depth()`;
///    flow-key fields always present at ≥ `Keys` (01.3).
/// 5. **Stateless:** `&self` methods, no interior mutability. All
///    cross-packet state lives in the aggregator (05). Plugins are
///    constructed once and shared (`Send + Sync`, D5).
pub trait LayerPlugin: Send + Sync {
    /// Unique protocol name, lowercase snake_case: `"ethernet"`, `"ipv4"`,
    /// `"vlan"`. Uniqueness enforced at registry build time (03.2).
    fn name(&self) -> ProtocolName;

    /// Parse exactly one header from the front of `bytes`.
    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError>;

    /// The route ids this plugin natively answers to (02.3). The router
    /// builder auto-installs `claim → plugin` routes; duplicates across
    /// plugins are a build-time error.
    fn claims(&self) -> &'static [RouteId] {
        &[]
    }

    /// Heuristic-mode bias only, never a filter (02.3): candidates whose
    /// expected predecessor matches the just-parsed layer score higher.
    /// Empty = no opinion, no penalty.
    fn expected_predecessors(&self) -> &'static [ProtocolName] {
        &[]
    }

    /// Whether this plugin participates in heuristic fallback (03.2).
    /// Override to `true` alongside [`LayerPlugin::probe`] — the registry
    /// enrolls the fallback pool from this flag at build time (probing
    /// zero bytes to detect a probe is not acceptable).
    fn has_probe(&self) -> bool {
        false
    }

    /// Self-scored confidence for heuristic fallback (02.3). `None`
    /// (default) = "never consider me heuristically". Probes must be cheap
    /// (bounded work, no allocation) and honest.
    fn probe(&self, bytes: &[u8], ctx: &ParseCtx) -> Option<Confidence> {
        let _ = (bytes, ctx);
        None
    }

    /// The declaration that makes this dissector a conversation source
    /// (02.4). `None` = this layer creates no stream.
    fn stream_identity(&self) -> Option<&StreamIdentity> {
        None
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use super::*;
    use crate::bytes::ByteReader;
    use crate::depth::Depth;
    use crate::packet::{LinkType, PacketMeta};
    use crate::value::Value;

    // The trait must stay object-safe: dyn dispatch is how the registry
    // holds plugins.
    const _: fn(&dyn LayerPlugin, Box<dyn LayerPlugin>) = |_, _| {};

    /// The spec's ~30-line no-op plugin: only the two required members.
    struct NoOp;

    impl LayerPlugin for NoOp {
        fn name(&self) -> ProtocolName {
            "no_op"
        }

        fn parse(&self, bytes: &[u8], _ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
            let mut r = ByteReader::new(bytes);
            let first = r.u8()?;
            let mut fields = FieldMap::new();
            fields.insert("first_byte", Value::U64(u64::from(first)));
            Ok(ParsedLayer {
                header_len: 1,
                fields,
                hint: Hint::Terminal,
            })
        }
    }

    /// Rule-3 violator: claims more bytes than the input holds.
    struct Liar;

    impl LayerPlugin for Liar {
        fn name(&self) -> ProtocolName {
            "liar"
        }

        fn parse(&self, _bytes: &[u8], _ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
            Ok(ParsedLayer {
                header_len: 100,
                fields: FieldMap::new(),
                hint: Hint::Terminal,
            })
        }
    }

    fn meta() -> PacketMeta {
        PacketMeta {
            timestamp: SystemTime::UNIX_EPOCH,
            caplen: 10,
            origlen: 10,
            link_type: LinkType::ETHERNET,
        }
    }

    #[test]
    fn minimal_plugin_parses_through_dyn_dispatch() {
        let plugin: Box<dyn LayerPlugin> = Box::new(NoOp);
        let m = meta();
        let ctx = ParseCtx::new(&[], Depth::Full, &m);

        // Generic checks the 09.1 kit will run for every plugin.
        assert_eq!(plugin.name(), "no_op");
        assert!(plugin.claims().is_empty());
        assert!(plugin.expected_predecessors().is_empty());
        assert!(plugin.probe(&[0xAB], &ctx).is_none());
        assert!(plugin.stream_identity().is_none());

        let bytes = [0xAB, 0xCD];
        let parsed = plugin.parse(&bytes, &ctx).expect("one byte available");
        assert!(parsed.header_len_ok(bytes.len()));
        assert_eq!(parsed.header_len, 1);
        assert_eq!(parsed.fields.get("first_byte"), Some(&Value::U64(0xAB)));
        assert_eq!(parsed.hint, Hint::Terminal);

        // Rule 2: declining on non-matching input, not half-parsing.
        assert!(plugin.parse(&[], &ctx).is_err());
    }

    #[test]
    fn engine_side_check_catches_a_lying_plugin() {
        let plugin: &dyn LayerPlugin = &Liar;
        let m = meta();
        let ctx = ParseCtx::new(&[], Depth::Full, &m);

        let bytes = [0u8; 10];
        let parsed = plugin.parse(&bytes, &ctx).expect("liar always succeeds");
        // Rule 3: the parser must detect header_len > bytes.len() and stop
        // with PluginError rather than trust the plugin's offsets.
        assert!(!parsed.header_len_ok(bytes.len()));
    }

    #[test]
    fn candidates_stay_inline_up_to_four() {
        // FR-11's ranked-candidates case must not allocate on the hot
        // path: UDP's worst case is [dst_port, src_port] plus a couple of
        // protocol-specific guesses — 4 covers it inline.
        let four = SmallVec::<[RouteId; 4]>::from_slice(&[
            RouteId::UdpPort(53),
            RouteId::UdpPort(5353),
            RouteId::TcpPort(53),
            RouteId::IpProtocol(17),
        ]);
        assert!(!four.spilled());
        let hint = Hint::Candidates(four);
        assert!(matches!(hint, Hint::Candidates(ref c) if !c.spilled()));

        let five = SmallVec::<[RouteId; 4]>::from_vec(vec![RouteId::UdpPort(0); 5]);
        assert!(five.spilled());
    }

    #[test]
    fn hint_matching_is_exhaustive() {
        // No wildcard arm: adding a Hint variant must fail to compile here,
        // forcing a conscious router update (the 03.4 decision table).
        fn router_action(hint: &Hint) -> &'static str {
            match hint {
                Hint::Route(_) => "lookup; unclaimed => stop (gated)",
                Hint::Candidates(_) => "try in order; all unclaimed => stop",
                Hint::ByProtocol(_) => "dispatch by name; unknown => stop",
                Hint::Unknown => "heuristic fallback may score",
                Hint::Terminal => "dissection ends",
            }
        }

        assert_eq!(
            router_action(&Hint::Route(RouteId::EtherType(0x0800))),
            "lookup; unclaimed => stop (gated)"
        );
        assert_eq!(
            router_action(&Hint::Candidates(SmallVec::new())),
            "try in order; all unclaimed => stop"
        );
        assert_eq!(
            router_action(&Hint::ByProtocol("ethernet")),
            "dispatch by name; unknown => stop"
        );
        assert_eq!(
            router_action(&Hint::Unknown),
            "heuristic fallback may score"
        );
        assert_eq!(router_action(&Hint::Terminal), "dissection ends");
    }

    #[test]
    fn confidence_is_clamped_to_100() {
        assert_eq!(Confidence::new(100).get(), 100);
        assert_eq!(Confidence::new(255).get(), 100);
        assert_eq!(Confidence::new(42).get(), 42);
    }
}
