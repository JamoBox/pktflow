# 08.2 — Streams view

> Task: [08 CLI](README.md) · Depends on: 08.1, 05.7 · PRD: FR-24, use cases 1/3/4

## Goal
The default lens: the capture as a set of conversations — hierarchy tree by default,
live-updating unless `--batch`, flat per-layer table with `--layer` (which implies
`--batch`: the live view is tree-only).

## Specification

**Default (tree):** the flow hierarchy (FR-4, use case 4), roots down, one line per stream:

```text
eth  aa:bb:cc:dd:ee:ff ↔ 11:22:33:44:55:66      1,204 pkts   1.2 MB   00:04:31
├─ ipv4  10.0.0.5 ↔ 93.184.216.34                 980 pkts 1,004 kB   00:04:12
│  ├─ tcp  :52341 ↔ :443   [established]           940 pkts   987 kB   00:04:12   ▲612/▼328
│  └─ udp  :34567 ↔ :53                             40 pkts    17 kB   00:00:02   ▲20/▼20
│     └─ dns   12 names                              40 pkts    17 kB
└─ ipv4  10.0.0.5 ↔ 10.0.0.1                       224 pkts   196 kB   00:04:31
```

Line grammar: protocol, rendered endpoint pair (A ↔ B, canonical order; ports prefixed `:`
under an IP parent), `[state]` if lifecycle'd, packets, bytes, duration, direction split
`▲AtoB/▼BtoA` (packets). Children indented; depth unlimited (tunnels prove it). Default sort:
bytes desc within siblings; `--sort {bytes|packets|first-seen|duration}`.

**`--layer PROTO` (flat table):** one row per stream node of that protocol (05.7
`at_layer`); `--merged` switches to `at_layer_merged` (D10 fold). Columns as above plus
first-seen. This is FR-24's literal "list streams at a chosen layer".

**Live view (default, live or replay; `--batch` opts out):** full-screen redraw every 1 s
(plain ANSI clear+home — no TUI framework in v1), top-N by recent bytes, closed streams
drop out, footer = running summary. Snapshot-based (05.7/D5): render thread requests
snapshots; never touches the aggregator.

Stream selectors printed in every view (`#42`) are stable within a run (`created_seq`) and
are what `pktflow stream` (08.3) accepts.

## Acceptance criteria
- [x] Tree and flat views golden-file-tested against 09.2 fixtures (text output is a
      contract; goldens updated deliberately).
- [x] Tunnel fixture renders the full nested chain (use case 6 visible to a human).
- [x] `--merged` fold demonstrated on the dual-parent fixture (05.7).
- [x] Live-view smoke: replay a fixture with simulated pacing, assert no panic, final frame
      matches the `--batch` output (manual on real iface for use case 3).
