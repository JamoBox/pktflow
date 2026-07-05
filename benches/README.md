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
