# Task 10 — Developer diagnostics (unknown-protocol discovery)

**Goal:** a debug/dev surface for the thing every other task is built to safely walk away
from — the unknown. When dissection stops because a route was unclaimed or heuristics found
no confident winner (03.4), that is currently just a `StopReason` and an `opaque_bytes` count
(D9). This task rolls those stops up, capture-wide, into a queryable, sampled, scored picture
of *what isn't understood yet* — so a developer can see exactly what a new plugin needs to
claim, with real bytes to develop and test against, instead of grepping packet-mode output by
hand.

This is diagnostics, not a decoder generator: it surfaces evidence (grouped occurrences,
sample bytes, near-miss probe scores) and a starting-point file; a human still writes the
actual parsing logic. It never weakens the no-phantom-streams gate (03.4) — the extra
probing it introduces is a reporting-only side channel that cannot select a plugin or emit a
`LayerRecord`.

**Depends on:** 03 (probe/`Confidence`, the gate it must not weaken), 04 (`StopReason`,
`DissectedPacket`), 05 (aggregator ingest path, query-API and bounding conventions), 08 (CLI
command surface, hex-dump/table rendering conventions). **Blocks:** nothing — a leaf task,
like 09.
**PRD:** FR-29, FR-30 · extends D9 · introduces D11.

## Sub-tasks

- [ ] [10.1 Unknown-occurrence diagnostics](01-unknown-diagnostics.md) — opt-in probing pass,
      `UnknownDiagnostics` on a stop (FR-29)
- [ ] [10.2 Unknown registry & query API](02-unknown-registry.md) — bounded grouping,
      `Aggregator::unknowns()` (FR-29)
- [ ] [10.3 `pktflow unknown` command](03-unknown-command.md) — the CLI lens: table,
      drill-down, export, scaffold (FR-30)

## Definition of done

On a fixture combining an unclaimed-route stop and a no-heuristic-winner stop (03.4's
`encrypted_udp_no_phantom` family plus a second case where a registered plugin's probe fires
below `MIN_CONFIDENCE`), `pktflow unknown` lists both groups with correct counts, byte totals,
and ranked near-misses; a clean fixture with nothing unknown prints an explicit "none
observed" rather than an empty table. `--export` round-trips byte-identical samples;
`--scaffold` emits a compiling plugin stub touching only its own new file (PRD §8's
time-to-new-protocol metric, now literally exercised by tooling). A benchmark asserts the
default `streams`/`packets` paths pay zero cost for this feature's existence when
`diagnose_unknown` is left off (09.4-style measurement) — this is a debug tool, not a tax on
the hot path.
