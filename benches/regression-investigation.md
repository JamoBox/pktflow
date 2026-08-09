# Bench regression investigation — 2026-08-09

The scheduled `Bench` workflow has been failing its 15% regression gate intermittently
since late July. This records what the failures actually are, and what to do about them.

**Conclusion up front: there is no code regression.** Every failing run since 2026-07-29
ran the *same commit* as the passing runs around it — `206f6847`, the current tip of
`main`. The failures are the gate mis-reading cross-machine variance as a code change,
because each run's baseline is the previous run, measured on a different GitHub-hosted
runner.

## 1. The evidence

### 1.1 The code never changed

`main` has been at `206f6847` since 2026-07-29. Every scheduled bench run from
2026-07-30 (run 24) through 2026-08-09 (run 35) — twelve runs — built that same commit:

| Run | Date | Result | Head SHA |
|---|---|---|---|
| 35 | 2026-08-09 | **fail** | `206f6847` |
| 34 | 2026-08-08 | pass | `206f6847` |
| 33 | 2026-08-07 | pass | `206f6847` |
| 32 | 2026-08-06 | **fail** | `206f6847` |
| 31 | 2026-08-05 | pass | `206f6847` |
| 30 | 2026-08-04 | **fail** | `206f6847` |
| 29 | 2026-08-03 | pass | `206f6847` |
| 28 | 2026-08-02 | **fail** | `206f6847` |
| 27 | 2026-08-01 | pass | `206f6847` |
| 26 | 2026-07-31 | pass | `206f6847` |
| 25 | 2026-07-30 | **fail** | `206f6847` |
| 24 | 2026-07-29 | pass | `206f6847` |

The binaries are identical too, not just the source: cargo's metadata hashes in the
`Running benches/...` lines match across passing and failing runs
(`scale-8af4838285391c6d`, `snapshot_cost-542cf0e80e6642fd`), and `rust-cache` served
every dependency from cache, so the toolchain and codegen were the same. Whatever moved,
it was not the program.

### 1.2 What run 35 reported

Run 35's change percentages are measured against run 34 — the previous night, same code:

| Benchmark | Reported change | Working set |
|---|---|---|
| `dissect_only/full` | +5.05% | streaming, cache-resident |
| `dissect_aggregate/keys` | +7.00% | streaming |
| `dissect_aggregate/full` | +5.44% | streaming |
| `throughput_floor/packets_per_sec` | +6.65% | streaming |
| `throughput_floor/mb_per_sec` | +7.40% | streaming |
| `snapshot_cost/10000_streams` | +6.30% | ~10k records |
| `snapshot_cost/100000_streams` | **+58.18%** | ~100k records |
| `scale_snapshot_cow/100000_flows_shared_republish` | **+44.32%** | 100k records |
| `scale_snapshot_cow/400000_flows_shared_republish` | **+61.55%** | 400k records |
| `scale_snapshot_cow/100000_flows_1pct_touched` | +18.42% | 100k records |
| `scale_snapshot_cow/400000_flows_1pct_touched` | +30.36% | 400k records |
| `scale_ingest_with_publish/batch` | +15.43% ⛔ | 65k flows |
| `scale_ingest_with_publish/publish_every_8k` | +19.41% ⛔ | 65k flows |
| `scale_lru_cap_churn/cap_10000` | +17.65% ⛔ | 10k live |
| `scale_lru_cap_churn/cap_100000` | +11.45% | 100k live |
| `scale_condensation/default_on` | +10.56% | 65k flows |
| `scale_condensation/off` | +19.84% ⛔ | 65k flows |
| `scale_window_query/flat_bytes_mid_page` | **−13.02%** (improved) | 400k pointers only |
| `scale_window_query/flat_query_page` | +32.35% | 400k records |
| `scale_window_query/timeline_800x64` | +27.26% | 400k records |

⛔ = tripped the 15% gate. Note the last three rows: in the same process, on the same
data, one benchmark got 13% *faster* while its two neighbours got 27–32% slower.

### 1.3 The magnitude tracks working-set size, not code

`snapshot_cost` is the cleanest control in the suite. Same function, same code path, the
only difference between the two cases is how many records it walks:

- `10000_streams` → **+6.3%**
- `100000_streams` → **+58.2%**

A code change cannot be 9× more damaging at 10× the stream count while leaving the
dissection benches at +5%. A slower memory subsystem can, and that is exactly the
gradient the whole table shows: everything CPU-bound moved 5–7%, everything that chases
one `Arc<Stream>` pointer per record beyond cache moved 30–60%.

`scale_window_query` isolates this within a single benchmark group. `flat_bytes_mid_page`
and `flat_query_page` both scan all 400k entries of the same sort order. The only
difference is that the query variant calls `keep.contains(&s.created_seq)`, which
dereferences each `Arc<Stream>`; the other never touches the record. On identical data:
1.4 ms vs 39 ms locally — a ~28× gap that is pure memory latency. In run 35, the
pointer-free one improved and the pointer-chasing one regressed 32%.

### 1.4 Same-machine repeatability is ±1%

Three consecutive runs of the *identical* `snapshot_cost` binary in one container:

| Run | `10000_streams` | `100000_streams` |
|---|---|---|
| 1 | 615.5 µs | 6.425 ms |
| 2 | 609.7 µs (−2.3%) | 6.457 ms (+0.5%) |
| 3 | 656.5 µs (+6.9%) | 6.392 ms (−1.0%) |

`snapshot_cost/100000_streams` holds ±1% run-to-run on one machine. CI moved it 5.55 ms →
8.79 ms (+58%) on the same code. The CI swing is roughly fifty times the benchmark's own
noise floor — it is not the benchmark being flaky, it is the machine being different.

(Run 3's `10000_streams` is worth noting separately: criterion printed "Performance has
regressed" for a +6.9% blip on an unchanged binary. Criterion's verdict line is a
significance test, not a judgement about the code.)

### 1.5 One benchmark is genuinely unstable on its own

`scale_window_query/timeline_800x64`, run twice back-to-back locally on one machine:

| Run | Time | Criterion's verdict |
|---|---|---|
| 1 | 36.6 ms | — |
| 2 | 52.7 ms | "No change in performance detected" (p = 0.72, CI −10.9% … +20.7%) |

+44% on the same machine and the same binary, with a confidence interval so wide that
criterion could not call it either way. Across CI runs this benchmark has reported
anywhere from ~17 ms to ~52 ms on unchanged code. It cannot support a gate in its current
form, and its +166% "regression" in run 32 was meaningless.

## 2. Why the harness turns this into a red build

Three design choices combine badly.

**The baseline is whatever ran last night, wherever it ran.** `bench.yml` restores
`target/criterion` with `restore-keys: bench-baseline-`, a prefix match that returns the
most recently saved cache — i.e. the previous scheduled run. Criterion compares the new
measurements against that directory and then overwrites it. So every run is a comparison
between two different physical machines from GitHub's heterogeneous hosted pool, with one
sample each. The alternation in §1.1 is the direct consequence: a slow night fails
against the fast night before it, then the next night "improves" against the slow one.

**Save-on-failure poisons the next comparison.** The baseline is saved with `if: always()`,
so an anomalously slow run becomes the reference the following run is judged against.
That is what produces pass/fail/pass/fail rather than a single isolated failure.

**One global 15% threshold for benchmarks with very different noise.** `dissect_only`
repeats to about ±2%; `timeline_800x64` does not repeat to better than ±44% even on fixed
hardware. A single threshold cannot be simultaneously tight enough for the first and loose
enough for the second.

There is also a **false-negative** side to this that matters more than the red builds. The
baseline moves with every run, so a real regression is only ever compared against the run
immediately before it. A change that costs 10% lands, doesn't trip the 15% gate, and
becomes the new normal permanently. Even a genuine 20% regression fails exactly once and
is then absorbed into the baseline forever. The gate as built cannot see gradual drift at
all, and there is no absolute anchor anywhere in the pipeline that would catch it.

## 3. What to do

### 3.1 Gate on same-run ratios, not cross-run absolutes

The highest-value change, and it needs no new infrastructure. Every acceptance criterion
this project actually cares about is already a comparison between two things measured in
the same process on the same machine — publish vs batch (12.1), condensation on vs off
(12.3), per-eviction cost across a 10× live set (12.2), `Keys` vs `Full` (§8), hub RSS vs
batch RSS. Machine speed largely cancels out of such a ratio, and the run 34 → run 35 data
shows how much:

| Ratio | Run 34 | Run 35 | Drift |
|---|---|---|---|
| `publish_every_8k` / `batch` (12.1) | 1.320 | 1.365 | **+3.4%** |
| `cap_100000` / `cap_10000` per packet (12.2) | 3.064 | 2.912 | **−5.0%** |
| `condensation off` / `on` (12.3) | 0.983 | 1.066 | +8.4% |
| *(for contrast)* `snapshot_cost` 100k / 10k | 17.72 | 26.36 | +48.7% |
| *(for contrast)* worst absolute, `400k_shared_republish` | — | — | +61.6% |

The two real gates drift 3–5% across a machine change that moved the absolutes by 15–62%.
That is a usable signal-to-noise ratio, and it needs no baseline cache at all.

The caveat is in the last two rows: this only works when both sides of the ratio have a
similar memory profile. `snapshot_cost`'s 100k/10k ratio drifts 49%, because one side fits
in cache and the other does not, so the machine change hits them unequally. Ratios are the
right tool for the five DoD criteria above — all of which compare like with like — and the
wrong tool for anything that compares a cache-resident workload against a memory-bound one.

Worth checking separately: run 35's `dissect_aggregate` ratio was 280.86/198.00 = **1.42×**,
below the documented ≥ 1.5× target (the bench README records 1.63×). Both sides are
CPU-bound and streaming, so this ratio should be fairly machine-stable — which makes it
worth measuring deliberately. It may be a real drift the current gate was never looking
for. I did not have run 34's `dissect_aggregate` absolutes to compare against, so treat it
as a lead rather than a finding.

### 3.2 Anchor the absolute numbers to a fixed baseline

Replace the rolling chain with an explicit, deliberately-refreshed reference:
`cargo bench -- --save-baseline main` on a known-good commit, `--baseline main` thereafter,
refreshed only when someone decides to. That fixes the false-negative hole in §2 — drift
accumulates against a fixed point instead of disappearing into a moving one — and it makes
"is this run slow?" answerable.

Keep the existing absolute floors as the hard gates, since they are machine-tolerant by
construction: throughput ≥ 500k pkt/s, TUI keypress < 50 ms, the RSS budgets. Those all
passed in run 35 (`peak_rss_kb=35880` vs budget 100000; keypress 42.7 ms vs budget 50 ms).

### 3.3 Require corroboration before going red

Fail only when a benchmark regresses in *N consecutive* runs, or when the regression
exceeds that benchmark's own measured noise band rather than one global 15%. A single
night's point estimate against a single night's baseline is not enough evidence to fail a
build, and the last twelve runs are the proof.

### 3.4 Make the failures diagnosable

Small fixes to `scripts/check-bench-regression.py` and `bench.yml`:

- **Report which benchmark regressed.** Today the error is
  `bench-logs/scale.log: regression of 15.43% exceeds the 15% gate` — no benchmark id. The
  parser already tracks position in the file; capturing the preceding id line is a few
  lines of code, and it is the difference between a five-minute triage and this document.
- **Gate on the conservative bound**, not the point estimate. Use the low end of
  criterion's time-change interval; a regression whose interval straddles the threshold
  should not fail.
- **Record the host.** Log `lscpu`, `nproc` and available memory into `bench-logs/`. The
  hardware hypothesis in §1.3 had to be inferred from the shape of the numbers because the
  logs do not say what machine ran them.
- **Don't save a baseline from a failed run**, or keep the stable anchor separate from the
  rolling one, so one bad night doesn't set up the next.

### 3.5 Reduce the variance at the source

- Move the job to hardware with a fixed CPU SKU — GitHub larger runners or self-hosted.
  This is the only thing that makes cross-run absolute comparison genuinely trustworthy.
- Raise measurement time for the scale group. Several benchmarks print *"Unable to complete
  N samples in 5.0s"* and fall back to 10–20 samples; they are under-sampled at criterion's
  defaults.
- Fix `timeline_800x64` specifically (§1.5) before it gates anything: it allocates a fresh
  `vec![0u32; bins]` per lane per iteration, and the allocator churn is a large part of why
  it will not repeat. Reusing the lane buffers across iterations should tighten it
  considerably.
- Add `unknown_diagnostics` to the run set. It is a declared `[[bench]]` target that
  neither `just bench` nor `bench.yml` executes — and the bench README already flags
  unknown-payload probing as the dominant cost on the fan-out shape (65.7 s of a 67.4 s
  run) and the next candidate for a bounding knob. It is the one thing most worth watching
  and it is not being watched.

## 4. Real headroom, if the goal is to make the numbers better

Separate from the false alarm, the investigation surfaced two concrete optimisations. Both
target precisely the benchmarks that swing hardest, because "memory-latency-bound" is both
why they are noisy and why they are slow.

**Give the reader-side scans a compact parallel array.** `SnapshotIndex::window` and
`::timeline` walk the full sort order and dereference every `Arc<Stream>` to read one or
two scalar fields — `created_seq` for the query filter, `first_seen`/`last_seen` for the
timeline. `Stream` is a fat record (`FlowKey`, `FieldMap`, `Vec<StreamId>`, `RollupSet`,
…), individually heap-allocated, so that is one cache miss per stream at 400k. The
measured cost of exactly this, isolated: `flat_bytes_mid_page` 1.4 ms (never touches a
record) vs `flat_query_page` 39 ms (touches every one). Building a contiguous
`Vec<(u64 seq, u32 first_bin, u32 last_bin)>` once per snapshot, cached alongside `orders`,
makes both scans linear over ~6 MB of prefetchable memory instead of 400k random probes.
Pairing it with a bitset keyed by arena position in place of `query_sets`' `HashSet<u64>`
removes the hashing as well. This is the single largest available win in the view layer.

**Skip the sort and the re-collect on unchanged publishes.** `Aggregator::snapshot()`
collects an `Arc::clone` per live stream, sorts by `created_seq`, and recomputes the
summary — about 20 ns per stream at 400k, all of it atomic RMW plus a random probe per
record. It is already 16× better than the pre-12.1 deep copy, so this is refinement, not
rescue. Under `EvictionPolicy::None` the slots are append-only and already in
`created_seq` order, so the sort is redundant; and a publish where no stream was
created or evicted could hand readers the previous vector instead of rebuilding it.

Neither is urgent. Both would show up directly in `scale_snapshot_cow` and
`scale_window_query`, and both would also shrink the machine-sensitivity that started this
investigation, since less pointer chasing means less exposure to whatever memory subsystem
the runner happens to have.

## 5. Method

- Workflow runs, job metadata and logs read via the GitHub Actions API for runs 24–35.
- Head SHAs and cargo metadata hashes compared across passing and failing runs.
- `snapshot_cost` and `scale_window_query` rebuilt at `206f6847` and run repeatedly in one
  container to establish the same-machine noise floor (§1.4, §1.5). That container is a
  4-vCPU virtualised sandbox, so its absolute numbers are not comparable with CI's — only
  the run-to-run spread on one machine is being used here, which is the point.
- Bench artifacts could not be downloaded directly (the blob host is unreachable from this
  environment); all CI figures come from the job logs.
