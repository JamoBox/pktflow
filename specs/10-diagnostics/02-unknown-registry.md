# 10.2 — Unknown registry & query API

> Task: [10 Developer diagnostics](README.md) · Depends on: 10.1, 05.2, 05.7 · PRD: FR-29 · D4, D11

## Goal
Roll per-packet `UnknownDiagnostics` (10.1) up into a bounded, queryable, capture-wide
picture — one row per distinct *shape* of unknown, not one per packet — living beside the
aggregator so a live capture dominated by one unclassified UDP flood doesn't grow this
registry without limit, mirroring 05.6's memory discipline for streams themselves.

## Specification

Lives in `pktflow-flows`, alongside `Aggregator`. Never depends on `pktflow-plugins` (00.1's
dependency direction: `flows ─x─ plugins`) — the registry knows `ProtocolName`, `RouteId`,
and `Confidence` as opaque values, never a concrete protocol.

```rust
pub struct UnknownKey {
    pub predecessor: ProtocolName,
    pub route: Option<RouteId>,     // Some for UnclaimedRoute, None for NoHeuristicWinner
}

pub struct UnknownGroup {
    pub key: UnknownKey,
    pub count: u64,
    pub bytes_total: u64,
    pub bytes_min: u32,
    pub bytes_max: u32,
    pub first_seen: SystemTime,
    pub last_seen: SystemTime,
    /// The innermost successfully-parsed layer's canonicalized endpoint key, where that
    /// layer declared a `StreamIdentity` (02.4) — bounded like D4's `Accumulate`, cap 64.
    pub endpoints: IndexSet<EndpointKey>,
    pub endpoints_overflow: bool,
    /// Best-ever-seen ranked list for this group (highest top-score observation wins ties
    /// by most-recent).
    pub near_misses: SmallVec<[(ProtocolName, Confidence); 5]>,
    /// Bounded ring of full sample byte arrays (not just 10.1's report-time prefix),
    /// overwrite-oldest — same pattern as 05.4's `Series`.
    pub samples: VecDeque<Box<[u8]>>,
}

pub struct UnknownRegistryConfig {
    pub max_groups: usize,          // default 500 (D11)
    pub samples_per_group: usize,   // default 5 (D11)
}

impl Aggregator {
    /// Sorted by `count` descending, `UnknownKey` as deterministic tiebreak — same discipline
    /// as `at_layer` (05.7): never hash-map order.
    pub fn unknowns(&self) -> Vec<&UnknownGroup>;
    pub fn unknown_group(&self, key: &UnknownKey) -> Option<&UnknownGroup>;
}
```

Mechanics:

- **Ingest.** The same call that feeds a `DissectedPacket` into the aggregator (05.2) checks
  `packet.unknown`; if `Some`, updates (or inserts) the group keyed by `UnknownKey`. Additive
  to 05.2's existing ingest — not a separate pipeline stage, not a separate channel.
- **Endpoints.** Best-effort context, not identity: reuses whatever canonical key the parent
  stream already computed (D10) rather than re-deriving one, so the registry stays protocol-
  free. Lets a developer distinguish "this unknown shows up under many IP pairs" (probably a
  real protocol worth a plugin) from "always the same one pair" (probably a misconfigured
  peer) at a glance.
- **Bounding (D11).** `max_groups` is an LRU over last-updated group: inserting a new distinct
  key beyond the cap evicts the coldest group entirely, samples included. `samples_per_group`
  overwrites oldest, ring-buffer style (05.4's `Series` pattern reused, not reinvented).
  `unknowns().len() == max_groups` is itself the "you are capped" signal; no separate overflow
  flag is needed at the registry level beyond `endpoints_overflow` (which is per-group, D4
  convention).
- **Independent lifetime.** The registry is not attributed to any `Stream` and does not share
  eviction with it (05.6) — a stream can be fully evicted while its unknown-occurrence history
  survives in the registry. This is deliberate: the diagnostic value of "we saw this shape of
  traffic" outlives the stream bookkeeping that happened to be nearby when it occurred.
- **Determinism.** `unknowns()` ordering is explicit and reproducible — identical input
  produces an identical ordering and identical group contents across runs (PRD §7, same bar as
  05.7).

## Acceptance criteria
- [x] Ingest correctly updates an existing group / creates a new one; count, byte min/max/
      total, first/last seen all correct across a multi-packet synthetic fixture with two
      distinct unknown shapes interleaved.
- [x] `max_groups` cap test: inserting `max_groups + k` distinct unknown shapes evicts exactly
      `k` coldest groups (samples gone with them).
- [x] `samples_per_group` ring test: `cap + k` samples into one group keeps the `k` most
      recent, and retained sample bytes are byte-identical to the source packets.
- [x] Determinism test: two identical runs produce identical `unknowns()` ordering and
      identical group contents (05.7-style test, reused pattern).
- [x] Stream-eviction interaction test: an unknown attributed to a stream's context survives
      in the registry after 05.6 evicts that stream.
