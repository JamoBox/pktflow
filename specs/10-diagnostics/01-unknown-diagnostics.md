# 10.1 — Unknown-occurrence diagnostics

> Task: [10 Developer diagnostics](README.md) · Depends on: 03.2, 03.3, 03.4, 04.3 · PRD: FR-29 · D9, D11

## Goal
Capture *what the bytes looked like* and *which registered plugins came closest* at the
moment dissection safely stopped on the unknown — but only when a caller asks for it, and
without that capture ever feeding back into the routing decision that already happened. The
gated-termination invariant (03.4: "no phantom streams") must remain absolute; this spec adds
a reporting-only side channel, not a second opinion the router can act on.

## Specification

```rust
pub struct ParseOpts {
    pub depth: Depth,
    pub aggregation: bool,
    pub max_layers: usize,
    pub diagnose_unknown: bool,   // NEW. Default false — opt-in, off the hot path (04.1).
}

pub struct UnknownDiagnostics {
    pub context: UnknownContext,
    /// Ranked, best first, up to 5. A reporting-only score list — never used to pick a
    /// plugin or continue dissection.
    pub near_misses: SmallVec<[(ProtocolName, Confidence); 5]>,
    /// Bounded prefix of the exact byte slice dissection stopped at (the same slice that
    /// becomes `opaque_len`, D9). Cap `SAMPLE_CAP = 256` — larger than packets-mode's 64-byte
    /// `-vv` peek (08.4) since this is the primary artifact a developer works from.
    pub sample: Box<[u8]>,
}

pub enum UnknownContext {
    /// `Hint::Route`/`Hint::Candidates` named something no plugin claims (03.4's gate fired).
    UnclaimedRoute { predecessor: ProtocolName, route: RouteId },
    /// `Hint::Unknown` and the fallback pool produced no winner ≥ `MIN_CONFIDENCE` (03.3).
    NoHeuristicWinner { predecessor: ProtocolName },
}

pub struct DissectedPacket {
    // ...existing fields (04.3)...
    /// `Some` iff `opts.diagnose_unknown` and `stop_reason.class() == StopClass::Unknown`.
    pub unknown: Option<UnknownDiagnostics>,
}
```

Mechanics:

- **Trigger is `StopClass::Unknown` exactly** — the same D9 grouping the summary counters
  already use (`UnclaimedRoute | UnknownHint`). No new taxonomy; this spec reuses D9's.
- **Probing pass.** When triggered, score every plugin in the router's `fallback_pool` (03.2,
  registration order) against the stopped-at bytes via `probe()` — the identical mechanism
  03.3 uses for real routing, run here purely to report:
  1. Runs **unconditionally**, even for `UnclaimedRoute` — bypassing the `Hint::Route`/
     `Hint::Candidates` gate. This is the one deliberate, documented crack in an otherwise
     absolute rule (03.4 cross-references this section). The crack is narrow by construction:
     the pass can only produce a `Confidence` number, it never calls anything that would
     yield a `LayerRecord` or advance the parser.
  2. Keeps the **raw ranked list including sub-`MIN_CONFIDENCE` scores** — a developer wants
     to see "a plugin that vaguely resembles this scored 12"; the production gate's 50-point
     floor is a *routing* safety margin, not a *reporting* one, and does not apply here.
  3. Takes the top 5; stable sort by score, no tie-break semantics needed (this is reporting,
     not selection — unlike 03.3, order among equal scores is not a determinism-critical
     path, though it must still be deterministic given identical byte input).
  - For `NoHeuristicWinner`, this is the same computation 03.3 already performed to reach its
    conclusion; an implementation may thread those scores through directly instead of
    re-running `probe()` a second time (pure optimization — correctness is pinned by the
    equality property test below, not by which code path computed it).
  - For `UnclaimedRoute`, no scoring happens in the router today (the gate forbids it
    entirely) — this is genuinely new work, but it reuses the existing `fallback_pool` and
    `probe()` contract unchanged; no new plugin-facing API.
- **Sample bytes.** `bytes[..bytes.len().min(SAMPLE_CAP)]` of the exact remaining-payload
  slice at the stop (never re-read from elsewhere — must match what `opaque_len` accounts
  for).
- **Cost discipline.** Nothing above runs unless `opts.diagnose_unknown` is true. Every other
  caller (08's `streams`/`packets` subcommands) leaves it `false`, so the existing performance
  story (PRD §7, 09.4) is untouched by this feature merely existing in the codebase.

## Acceptance criteria
- [x] `diagnose_unknown: false` (default): `DissectedPacket.unknown` is always `None`, and an
      instrumented test plugin proves zero extra `probe()` calls beyond what a clean
      `UnknownHint` resolution already makes (03.3) — the false path is provably free.
- [x] `diagnose_unknown: true` on an `UnclaimedRoute` stop: near-misses populate from the full
      fallback pool even though no route/candidate ever named those plugins. Fixture: an
      unclaimed UDP port with one probing plugin scoring 30 — the sub-`MIN_CONFIDENCE` score
      surfaces in `near_misses`.
- [x] Property test: for `NoHeuristicWinner` stops, this spec's near-miss list and 03.3's
      actual scoring round produce an identical ranked top-5 regardless of implementation
      path (recompute vs. thread-through).
- [x] `sample` never exceeds `SAMPLE_CAP` and never panics when fewer bytes remain than the
      cap (edge case: 3-byte remainder at stop).
- [x] The gate exception is documented on `UnknownContext`'s doc comment and cross-referenced
      from 03.4 so a future reader of the gate spec finds this immediately (not a surprise
      discovered by reading two files independently).
