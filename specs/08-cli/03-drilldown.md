# 08.3 — Stream drill-down

> Task: [08 CLI](README.md) · Depends on: 08.2 · PRD: FR-25, use case 2

## Goal
Everything the aggregator knows about one stream, human-arranged: identity, lineage, stats,
lifecycle, rollups.

## Specification

Selector: `pktflow stream -r FILE '#42'` (run-stable id from 08.2) or a key expression
`'tcp 10.0.0.5:52341 93.184.216.34:443'` (protocol + endpoint pair, order-insensitive —
canonicalization applies; resolves via `at_layer` + endpoint match; ambiguity across parents
lists candidates with their `#ids` and exits 1).

Output sections (omit empty ones):

```text
tcp #42   10.0.0.5:52341 ↔ 93.184.216.34:443        [established]
lineage   eth #3 (aa:bb… ↔ 11:22…) ▸ ipv4 #17 (10.0.0.5 ↔ 93.184.216.34) ▸ this
timing    first 12:04:01.221  last 12:08:13.876  duration 00:04:12
totals    940 pkts / 987 kB       A→B 612 pkts / 641 kB      B→A 328 pkts / 346 kB
initiator A (10.0.0.5:52341)
state     established            (closed: —)
opaque    987,102 payload bytes beyond last parsed layer
rollups
  flags   {SYN, SYN+ACK, ACK, PSH+ACK}                      (accumulate, 4 distinct / 940 obs)
  flags   series: 12:04:01.221 ▲ SYN · 12:04:01.240 ▼ SYN+ACK · 12:04:01.241 ▲ ACK · …
children  udp #55 (…), dns #56 (…)
```

- Rollup rendering per kind: `Accumulate` = value set + distinct/observation counts +
  `≥cap` marker on overflow; `Sample` = `first → last`; `Series` = timeline with direction
  arrows, head/tail elision beyond 20 points (`--full-series` lifts it), `truncated` marker.
- Lifecycle history (use case 2's "handshake story") comes from the flags series when the
  plugin declared one (05.5 note) — the CLI does not reconstruct state history itself.
- `lineage` = walk `parent` links to root; `children` one line each — drill navigation
  without a TUI.

## Acceptance criteria
- [x] Both selector forms resolve; ambiguity path exits 1 listing candidates.
- [x] Golden tests: a TCP session (all sections), a UDP+dns stream (rollups, no lifecycle),
      a GRE stream (children section shows the inner stack).
- [x] Overflow/truncation markers verified against a cap-exceeding fixture (nothing lies
      by omission — 05.4).
