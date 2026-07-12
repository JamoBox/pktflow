# The TUI and the web UI

Two interactive front-ends sit on top of the same aggregation pipeline as every
CLI lens. Both read only published `AggregatorSnapshot`s through a snapshot hub
(`pktflow-view`), so the aggregation thread stays the store's single writer;
both keep unknown diagnostics on, making unknown-traffic triage a first-class
pane rather than a separate command. They take the same input flags as
`streams` (`-r FILE` or `-i IFACE`, `-f` BPF filter, `--depth`, `-c`,
`--idle-timeout`, `--max-streams`, `--entry`).

## `pktflow tui` — the terminal UI

```sh
pktflow tui -r capture.pcap        # browse an offline capture
sudo pktflow tui -i eth0           # watch a live interface
```

A full-screen ratatui session with four tabs:

- **Streams** — the hierarchy as a foldable tree (same glyphs and sort orders
  as the `streams` view) beside a live drill-down pane: endpoints, lineage,
  timing, per-direction ratio bars, lifecycle state, opaque bytes, every
  rollup (numeric series render as sparklines), and the child chains.
- **Timeline** — one lane per stream (hierarchy order, honoring the
  query filter), a protocol-colored bar spanning each stream's lifetime,
  and a playhead: `←→` scrub (`[`/`]` coarse), `Space` plays it across
  the capture, `↑↓` picks a lane, `Enter` opens it in the Streams tab.
  Lanes ahead of the playhead are ghosted (unborn), crossed lanes are
  bright (active — counted in the header), passed lanes dim (finished).
- **Unknown** — the 10.2 registry ranked by count; `Enter` opens a drill-down
  with near-miss confidence bars, retained-sample hex dumps, and the
  `--scaffold` command to copy.
- **Summary** — capture totals, stop classes, and per-protocol stream/byte
  bars.

Keys (also on `?` in-app): `↑↓/jk` move · `←→/hl` fold/unfold (`h` on a leaf
jumps to its parent) · `Enter`/`Space` toggle · `e`/`c` expand/collapse all ·
`s` cycle sort · `/` query filter (free text, `/regex/`, and field
comparisons with AND/OR/NOT — see
[`query-language.md`](query-language.md); matches stay reachable through
auto-expanded ancestors, and a parse error is shown instead of silently
filtering) · `J/K` scroll the detail pane ·
`p` freeze live updates · `1/2/3/4`/`Tab` switch tabs · `q` quit. Quitting also
stops a live capture (the run ends like Ctrl-C on `streams`).

## `pktflow serve` — the web UI + JSON API

```sh
pktflow serve -r capture.pcap                    # http://127.0.0.1:8320/
pktflow serve -i eth0 --listen 0.0.0.0:9000      # live, LAN-visible
```

The whole front-end is embedded in the binary — no build step, no CDN, works
air-gapped. The page is a dark single-screen app: stat tiles, a searchable/
sortable stream tree with per-protocol color chips (the search bar speaks
the full [query language](query-language.md), evaluated server-side, with
a live match count, dimmed ancestor-context rows, and a `syntax ?`
cheat-sheet), a **Timeline tab** (per-stream lifetime lanes on a shared
time axis with a draggable/playable scrubber, unborn/active/finished
dimming, and click-through to the drill-down — it honors the current
search, so you can scrub through only `under == vxlan` traffic), a
drill-down panel
(breadcrumb lineage, direction-split bar, rollups with hoverable series
charts, child links, raw JSON), a protocol byte-distribution chart with
stop-class chips, and the unknown-triage table with in-browser hex dumps.
During live capture the page updates itself over SSE; the LIVE badge pulses
until the run finishes.

`--listen` defaults to `127.0.0.1:8320`. Binding beyond loopback exposes the
capture contents to whoever can reach the port — there is no auth layer.

### API

Everything the page shows is plain JSON underneath, reusing the D8 stream
record shape from `pktflow streams --format json`:

| Route | Body |
|---|---|
| `GET /api/meta` | source, mode (`offline`/`live`), finished flag, snapshot generation, pipeline error |
| `GET /api/snapshot` | one document: meta + summary (incl. per-protocol live bytes) + `roots` + `streams[]` (D8 records) + `unknowns[]` (with hex-encoded retained samples) |
| `GET /api/stream/{id}` | a single D8 record by display id; 404 if evicted/absent |
| `GET /api/search?q=EXPR` | evaluate a [query](query-language.md): `matches` (selected ids), `visible` (matches + ancestors), or `error` for a bad expression |
| `GET /api/events` | SSE `tick` events (~2/s): generation, finished, packets, bytes, live streams — refetch `/api/snapshot` when the generation moves |

```sh
curl -s localhost:8320/api/snapshot | jq '.streams[] | select(.protocol=="tcp")'
```

## How they plug in

`pktflow-cli` spawns the ordinary capture→dissect→aggregate pipeline on a
background thread; after each ingest it publishes a throttled (≥250 ms) deep
snapshot into a `SnapshotHub` (`pktflow-view`), plus a final publish after
`finish()`. The TUI event loop and every web request render from the hub's
latest `Arc<AggregatorSnapshot>` — no locks around the aggregator, no protocol
knowledge in either UI (enforced by `scripts/check-boundaries.sh`).
