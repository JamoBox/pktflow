# 03.3 — Heuristic fallback

> Task: [03 Router](README.md) · Depends on: 03.2 · PRD: §4.B.3 tier 2, FR-14

## Goal
When no explicit route applies *and the gate permits* (03.4): let probing plugins score the
bytes, weight by predecessor prior, pick deterministically, and require the winner to
actually parse.

## Specification

Fallback runs in exactly two situations (both gate-checked first):

1. The previous layer hinted `Unknown`.
2. First-layer identification when the entry link type is unknown (04.2).

*(A routed plugin failing to parse does NOT trigger fallback in v1 — see 03.4. This is
stricter than PRD §4.B.3's "or the routed plugin failed" and is a deliberate safety choice:
an explicit route that fails means malformed data, not a mystery protocol.)*

Scoring:

```text
for each plugin p in fallback_pool (registration order):
    score(p) = probe(p, bytes, ctx)?                    # None → not a candidate
    if prev_layer.protocol ∈ p.expected_predecessors:   # predecessor prior (FR-14)
        score(p) = min(100, score(p) + PRIOR_BOOST)     # PRIOR_BOOST = 15
winner = max by (score, then earliest registration)     # deterministic tie-break
if winner.score < MIN_CONFIDENCE (= 50): stop           # weak guesses are worse than stopping
result = winner.parse(bytes, ctx)
if Err: remove winner from this attempt's candidate set, take next-best (never re-select the
        failed plugin on these bytes — FR-15), repeat until success or candidates exhausted
if exhausted: StopReason::UnknownHint
```

- `PRIOR_BOOST` and `MIN_CONFIDENCE` are engine constants (not per-plugin) so tuning is
  central; values above are v1 defaults, revisited with 09.4 data.
- Tie-break by registration order, **never** by map iteration or pointer order — this is
  the determinism requirement (PRD §7) that hash-map-ordered designs silently violate.
- Layers parsed via fallback are marked `via_heuristic` in diagnostics (D9) so downstream
  consumers can weigh confidence; the flag lives in `LayerRecord`-adjacent parse diagnostics,
  not the record itself (streams don't care once bytes parsed).

## Acceptance criteria
- [x] Scoring + prior + tie-break implemented as above; constants named and documented.
- [x] Test: two plugins probing 60 vs 60 → earlier-registered wins, both orders exercised.
- [x] Test: winner's `parse` fails → next-best runs, failed plugin not retried (FR-15).
- [x] Test: all candidates below `MIN_CONFIDENCE` → stop, no layer emitted.
