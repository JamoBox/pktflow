# 13.1 — SPA shell & JSON API

> Task: [13 Interactive front-ends](README.md) · Depends on: 05, 07, 08 · PRD: §4, §5 · D8

## Goal
One embedded, zero-dependency single-page app (`crates/pktflow-web/src/assets/index.html`,
served at `/`) and a JSON API (`crates/pktflow-web/src/api.rs`) that together drive four tabs
— Streams, Timeline, Protocols, Unknown — over a live-updating capture, without a build step
or a JS framework.

## Specification

**Tabs.** `data-tab` buttons (`#tabs`) toggle `#view-{streams,timeline,protocols,unknown}`
via `activateTab(name)`; exactly one `section` carries class `on` at a time. Tab state is a
client-side concern only — no navigation/URL round-trip, no server involvement.

**JSON API** (all under `/api`, all reachable without the SPA — `curl`-able):

| Route | Purpose |
|---|---|
| `GET /api/meta` | `meta_json`: `pktflow` (schema version), `source`, `mode` (`live`\|`offline`), `finished`, `generation`, `error` |
| `GET /api/snapshot` | The browsable state in one document: `meta`, `summary`, `windowed`, `unknowns`, and — only when `!windowed` — the full stream forest (`streams`, `roots`). Refetched by the client only on a `generation` change, never polled. |
| `GET /api/streams` | One window of D8 stream records: `scope=roots\|flat\|children&of=SEQ`, `sort`, `order`, `offset`, `limit` (server-clamped), `q`. Response carries `total`, `match_total`, `rows` — never the whole forest. |
| `GET /api/timeline` | Bounded time×lane density: `bins`, `lanes`, `q` params; `O(bins × lanes)` cost regardless of stream count (13.3 is the client half of this contract). |
| `GET /api/stream/{id}` | One D8 record by display id (`created_seq`), the detail pane's only source. |
| `GET /api/search?q=` | Server-side query evaluation (shared engine, `docs/query-language.md`) — `matches` + `visible` (matches plus ancestors) below the snapshot gate, `match_total`-only above it. |
| `GET /api/events` | SSE stream of tick payloads (below). |
| `POST /api/upload` | Streamed capture upload (12.6) — body streamed to disk, not buffered; out of scope here. |

**Schema reuse (D8).** Every stream record embedded in any of the above is the same
`pktflow_view::json::stream_record` shape the CLI's `--format json` emits — one schema, three
front-ends (CLI, TUI, web), per D8. This task does not define a second stream schema.

**Live refresh discipline.** `GET /api/events` pushes a tick roughly every 250–500 ms
(hub publish cadence, D17.2): `generation`, `finished`, `error`, `packets`, `bytes`,
`streams_live`, `progress` (`{read, total}` over a file source, `null` for live capture). On
each tick the client:
1. Always repaints header counters from the tick payload itself — no fetch needed.
2. Refetches `/api/snapshot` only when `generation` advances past the last one rendered.
3. Drops (does not render) any async response whose `generation` is older than the newest
   already seen — the response is stale by construction, not merely late.

**Search bar** (`#filter`, top of the Streams tab) evaluates the shared query language
server-side (`/api/search`) and is the same expression grammar the TUI's `/` filter and the
CLI's `--where` accept — see `docs/query-language.md`. It is not re-specified per front-end.

## Acceptance criteria
- [x] All eight routes respond from a real `pktflow serve` process without the SPA loaded
      (`curl`-verified), matching the shapes above.
- [x] A capture below the D17.4 gate: `/api/snapshot` carries `streams`/`roots`; above it,
      those keys are absent and `windowed: true` (browser- and `curl`-verified both ways).
- [x] Header counters update every tick without a snapshot refetch; a snapshot refetch fires
      exactly once per generation change, verified by counting `/api/snapshot` requests
      across several ticks in a running capture.
- [x] A response for a superseded generation is discarded, not rendered — verified by racing
      a fast filter change against a slow snapshot fetch (network-throttled) and asserting
      the older response never reaches the DOM.
