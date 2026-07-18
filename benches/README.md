# 09.4 — Benchmark results

Bench sources live in `crates/pktflow-cli/benches/` (cargo's required location for
`[[bench]]` targets); this file records what they measured. Run them all with `just bench`.

## Machine

These numbers come from this session's sandboxed development container, **not** a
dedicated developer machine — treat absolute figures as illustrative, not authoritative.
Re-run locally on real hardware before citing a number externally.

- CPU: Intel Xeon @ 2.80 GHz, 4 vCPUs (virtualized; no guaranteed cache/NUMA topology)
- RAM: 15 GiB
- rustc 1.94.1, release profile, `cargo bench` defaults (criterion 0.8.2)
- Corpus: `pktflow_testkit::mixed_capture` — 70% TCP, 20% UDP+DNS, 5% GRE tunnels, 5%
  unclaimed-port noise, deterministic (no `rand`, reproducible byte-for-byte)

## 1. `dissect_only` — dissection alone, no aggregation, 100k-packet corpus

| Depth | Throughput | Time (100k pkts) |
|---|---|---|
| `None` | 1.16 Melem/s | 86.5 ms |
| `Keys` | 1.15 Melem/s | 87.3 ms |
| `Structural` | 0.75 Melem/s | 133.4 ms |
| `Full` | 0.65 Melem/s | 153.3 ms |

`None`/`Keys` cost almost the same (expected: `Keys` only adds flow-key-relevant field
extraction, which is most of what plugins parse anyway). The real cliff is `Structural`
and `Full`, where the extra field extraction (flags, TTLs, options, rollup-eligible
fields) roughly doubles the per-packet cost over the bare minimum.

## 2. `dissect_aggregate` — full pipeline, `Keys` vs `Full`

| Depth | Throughput | Time (100k pkts) |
|---|---|---|
| `Keys` | 555 Kelem/s | 180.1 ms |
| `Full` | 341 Kelem/s | 292.8 ms |

**§8 metric: does depth pay off?** Yes — `Keys` is **1.63x** faster than `Full`
(555/341), clearing the ≥ 1.5x target. An analyst who only needs flow-level identity
(the streams view's default) gets a real, material speedup over asking for everything,
which is the whole premise behind having a depth knob at all.

## 3. `throughput_floor` — end-to-end, `Keys` + aggregation, 200k-packet corpus

| Metric | Result |
|---|---|
| Packets/sec | 566 Kelem/s |
| MB/sec | 60.2 MiB/s |

**Acceptance floor: >= 500k packets/sec.** Met, with headroom (566k vs. 500k), on a
4-vCPU virtualized sandbox — expect more on dedicated hardware. This is the number the
scheduled CI job's 15% regression gate tracks release-to-release, not the absolute
figure (which is explicitly per-machine per the spec).

## 4. `aggregator_memory` — RSS delta at `max_streams: 100,000`

Each packet in this bench's corpus forms 3 stream layers (eth/ipv4/udp, all distinct —
worst case for the store), so the cap is actually reached around packet 33,334, not
100,000. Checkpoints span the ramp, the cap, and a modest overshoot:

| Packets ingested | Live streams | RSS delta | KB/stream |
|---|---|---|---|
| 10,000 | 30,000 | 25.5 MB | 0.849 |
| 25,000 | 75,000 | 60.3 MB | 0.804 |
| 34,000 | 100,000 (cap) | 76.3 MB | 0.763 |
| 37,000 | 100,000 (cap) | 76.6 MB | 0.766 |
| 40,000 | 100,000 (cap) | 80.0 MB | 0.800 |

**Memory plateaus once the cap is reached** (D2): RSS grows from 25.5 MB to 76.3 MB
while live count grows from 30,000 to the 100,000 cap, then only creeps from 76.3 MB to
80.0 MB over the next 6,000 packets — all past-cap growth, not the linear-with-input
growth seen before the cap. **Per-stream cost is ~0.76-0.85 KB**, under the ~1 KB
baseline target (no series rollups on this corpus's identity-only streams).

**Side finding, not what this bench set out to measure:** LRU eviction
(`Aggregator::enforce_max_streams`) does a fresh `O(live_count)` scan per evicted
stream. At steady state (live count pinned at the cap) that's a per-packet cost
proportional to `max_streams`, not the corpus size — sustained ingestion far past the
cap (this bench originally attempted a 200k-packet run, ~100k packets past the cap)
took minutes rather than seconds. Worth a look if `max_streams` is ever pushed
significantly higher than 100k in practice; out of scope for this round to fix.

## 5. `snapshot_cost` — `snapshot()` latency

| Live streams | Latency |
|---|---|
| 10,000 | 15.9 ms |
| 100,000 | 229.8 ms |

Roughly linear in live-stream count (10x streams, ~14.5x time) — consistent with
`snapshot()`'s documented deep-copy-every-live-stream cost (05.7's accepted cost). At
100k live streams, a 230 ms snapshot is likely fine for the live view's refresh cadence
but would be the first thing to revisit if v2 sharding (D5) becomes necessary at higher
live-stream counts.

## Task 12 — large-capture scale (12.7)

New corpus: `pktflow_testkit::fan_out_packets` — the high-cardinality fan-out shape
(a few `addr:443` anchors × many ephemeral peer ports, ~75/25 TCP/UDP, deterministic).
The **reference fixture** for the numbers below: `FanOutSpec { anchors: 8,
flows_per_anchor: 125_000, packets_per_flow: 3, payload_len: 32, seed: 0xC0FF_EE }` —
1,000,000 flows / 3,000,000 packets / 1,000,048 streams, `Depth::Full`.

### Memory ceiling (`tests/scale.rs`, release, one process per test)

| Run | Peak RSS (VmHWM) | Wall time |
|---|---|---|
| Pre-task baseline (commit `2bbfbb5`), hub-style publishing | 2,606,092 kB (2.49 GiB) | 27.9 s |
| **Current, hub-style publishing** (snapshot every 262k pkts, latest held) | **1,299,492 kB (1.24 GiB)** | 21.8 s |
| Current, batch (no publishing) | 1,069,924 kB (1.02 GiB) | 17.0 s |

- 12.2's RSS criterion: hub-style peak improved **2.0×** over the pre-task baseline.
- Task DoD "hub < 2× batch": **1.21×** — the COW snapshot's held copy adds ~230 MB at
  1M streams instead of the old full deep copy per publish.
- The `#[ignore]`d budget test (`hub_scale_rss_stays_under_budget`) always measures and
  reports; the assertion (budget 100,000 kB — machine-tolerant, guarding the return
  toward per-flow behavior) arms only under `PKTFLOW_ASSERT_RSS=1`, which
  `.github/workflows/bench.yml` sets while running each RSS test in its own process.
  The Docker job's blanket `--include-ignored` run shares one process across both RSS
  tests (VmHWM is process-wide), so there it reports without gating.

### `scale` bench (criterion)

| Benchmark | Result |
|---|---|
| `snapshot_cow/100000_flows_shared_republish` | 14.1 ms |
| `snapshot_cow/100000_flows_1pct_touched` (touch 1k flows + publish) | 25.5 ms |
| `snapshot_cow/400000_flows_shared_republish` | 64.7 ms |
| `snapshot_cow/400000_flows_1pct_touched` (touch 4k flows + publish) | 129.5 ms |
| `ingest_with_publish/batch` (262k pkts, 65k flows) | 637 ms (412 Kelem/s) |
| `ingest_with_publish/publish_every_8k` | 972 ms (270 Kelem/s) |
| `lru_cap_churn/cap_10000` (eviction per packet) | 69.3 ms / 20k pkts (289 Kelem/s) |
| `lru_cap_churn/cap_100000` | 1.94 s / 200k pkts (103 Kelem/s) |

- **12.1 snapshot cost:** an all-shared republish at 100k live streams is **14.1 ms vs
  the 229.8 ms** the pre-task deep copy measured (§ "5. `snapshot_cost`") — **16×** —
  and stays O(live pointer copies) at 400k. That 09.4 "first thing to revisit" callback
  is answered.
- **12.2 LRU gate:** per-eviction cost grew 2.8× across a 10× live-set (3.4 µs → 9.7 µs
  per packet with one eviction per packet) — sub-linear (heap + cache effects), vs. the
  ≥10× a per-eviction scan would force. Confirmed no longer proportional to live count.
- **Publish overhead, raw COW path:** the fixed 8k-packet cadence costs +53% here, and
  the pre-12.3 adaptive pipeline measured +59% end-to-end. The fan-out shape is COW's
  worst case — round-major interleaving touches *every* flow between any two publishes,
  so structural sharing degrades to ~one stream clone per packet no matter the spacing.
  D16 condensation (12.3) removes exactly that shape; the re-measurement below closed
  the 12.1 "< 10% of `--batch`" criterion at **+2.6%**. (These COW/publish/LRU benches
  pin `condense_threshold: 0` so they keep guarding the raw per-stream machinery at
  their stated live counts; `scale_condensation` covers the default-on path.)

### End-to-end, real binary over the on-disk fixture (297 MB pcap)

`write_reference_fixture` (test-gated writer) → `/tmp/.../scale-1m.pcap`, release build.
First measured after 12.1/12.2 (pre-condensation), then re-measured with 12.3's D16
condensation on by default:

| Run | Pre-12.3 | With condensation (default) |
|---|---|---|
| `pktflow streams --batch` (no diagnostics, no publish) | 34.4 s | **21.7 s** |
| `pktflow unknown` (diagnostics, no publish) | 72.5 s | 65.7 s |
| `pktflow serve` read-to-finished (diagnostics + adaptive publish) | 115.2 s | **67.4 s** |
| `pktflow serve` peak RSS | 1,984,216 kB | **48,292 kB** |
| `/api/snapshot` stream records | 1,000,048 | **12,384** |

- **12.1's read-time gate, closed:** publish overhead is now 67.4 vs 65.7 s = **+2.6 %**
  (< 10 %). Condensation removed the COW worst case: with ~12k live nodes instead of 1M,
  inter-publish copies are bounded by nodes, not packets.
- The in-process RSS ceilings collapse accordingly: hub-style **35,876 kB** / batch
  32,720 kB on the 1M-flow fixture (budget re-pinned at 48,000 kB; waypoints 2,606,092
  pre-task → 1,299,492 after 12.1/12.2 → 35,876 after 12.3 — **73×** end to end).
- `scale_condensation` (65k flows × 3 pkts, replayed dissected packets): default-on
  794 Kelem/s vs. off 746 Kelem/s — the group bookkeeping costs *less* than the stream
  creations it avoids, so condensation is a throughput win too, not a trade.
- `scale_window_query` (12.4's gate, 400k **uncondensed** streams — worse than the
  condensed fixture): flat mid-capture page 1.2 ms; queried page (cached evaluation,
  membership scan) 33 ms; `/api/timeline` at 800 bins × 64 lanes 32 ms. All interactions
  land far under the 100 ms DoD budget with window-bounded bodies.
- TUI keypress budget (12.5, `pktflow-tui tests/scale.rs`, `#[ignore]`d release tier):
  keypress + full frame at 100k uncondensed streams = **43 ms** (< 50 ms DoD), with
  `flatten` capped at 10,000 materialized rows. Uncapped it measured 350 ms — the cap is
  what makes the budget hold, not the index alone.
- Browser (12.5, `scripts/webui-scale-check.mjs`, manual/scheduled tier — needs
  `playwright-core` + the preinstalled Chromium): windowed tree pages/expands/queries,
  timeline draws as canvas density, and the DOM stays viewport-bounded after
  scroll-to-bottom over a 100k-stream capture; full mode re-verified against a small
  fixture.
- Unknown-payload diagnostics — every fan-out payload is opaque — now dominates this
  shape (65.7 of 67.4 s vs 21.7 s without). Its per-occurrence probing is the next
  candidate for a bounding knob; out of task-12 scope, noted for a future task.

## Deferred-tuning callbacks

Two callbacks from earlier specs asked this bench round for data; neither is answered
by these five benches, honestly:

- **`PRIOR_BOOST`/`MIN_CONFIDENCE` review (03.3):** these tune the Tier-3 heuristic
  first-layer probe path. The bench corpus never exercises that path (every packet
  arrives over a well-routed `Ethernet` link type, so heuristic fallback never fires) —
  there's no data here bearing on whether the v1 defaults (15 / 50) need adjusting.
- **04.1's clone-vs-borrow revisit:** this asks whether `FieldMap`'s per-layer clone
  shows up on a CPU profile. These benches measure aggregate throughput, not attributed
  per-operation cost, and this sandbox has no `perf`/profiling tooling available. A
  flamegraph-style profile of `dissect_aggregate` is the right follow-up, not yet done.

## CI

Compiled (not run) per PR via `cargo bench --no-run --workspace` — see `.github/workflows/ci.yml`.
Run on a schedule with relative-delta tracking via `.github/workflows/bench.yml` (15%
regression gate against the last scheduled run's baseline).
