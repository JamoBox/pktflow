# 10.3 — `pktflow unknown` command

> Task: [10 Developer diagnostics](README.md) · Depends on: 10.2, 08.1, 08.5 · PRD: FR-30 · D8

## Goal
The dev/debug lens dedicated to the registry (10.2): a capture-wide triage table, a
per-group drill-down with hex samples and near-miss ranking, and two concrete next steps —
export raw bytes for a fixture, and scaffold a starter plugin file — so this command actively
shortens time-to-new-protocol (PRD §8) rather than just reporting a number.

## Specification

```text
pktflow unknown (-r FILE | -i IFACE) [--top N=20] [--min-count N=1] [shared]          # table
pktflow unknown (-r FILE | -i IFACE) '#<n>' [--samples N=3] [--full-samples]          # drill-down
pktflow unknown (-r FILE | -i IFACE) '#<n>' --export DIR                              # dump bytes
pktflow unknown (-r FILE | -i IFACE) '#<n>' --scaffold NAME                            # plugin stub
```

- This subcommand is the **only** place `ParseOpts.diagnose_unknown` is set to `true` in v1
  (08.1's shared flags — `--depth`, `--format`, etc. — apply as usual). Keeping it scoped to
  one command keeps the "off the hot path by default" story (10.1) simple: nowhere else in
  the CLI pays the probing cost.
- **Table (default).** Rows sorted by `count` desc (registry order, 10.2's `unknowns()`):

  ```text
  UNKNOWN PROTOCOLS / STREAMS   (3 groups, 1,142 packets, 412 KB unclassified)

   #  CONTEXT                    KIND                  COUNT   BYTES    FIRST → LAST           NEAR MISSES
   1  udp → udp_port:51820       unclaimed route         812   298 KB   12:04:01 → 12:09:55    wireguard(31) · gre(9)
   2  ipv4 → ip_proto:132         unclaimed route         140    41 KB   12:04:02 → 12:08:10    sctp(44)
   3  udp                        no heuristic winner      190    73 KB   12:04:03 → 12:09:40    vxlan(42) · gre(38)
  ```

  Columns: run-stable selector `#n`; context (`predecessor → route` via `RouteId::Display`,
  03.1, for `UnclaimedRoute`; bare `predecessor` for `NoHeuristicWinner`); kind; count; total
  bytes; first/last seen; up to 3 near-misses as `name(score)`. `--min-count` filters
  single-straggler noise; `--top` caps rows. A capture with nothing unknown prints an explicit
  `no unknown protocols observed` line — never a bare empty table (ambiguous with "did this
  even run").
- **Drill-down** (`'#<n>'`): full `UnknownKey`, stats, the bounded endpoint set (`≥64 distinct`
  marker on overflow, D4 convention — nothing lies by omission), the **full** near-miss
  ranking (drill-down is not capped at 3), and `--samples N` (default 3, capped by what the
  registry actually retained) hex-dumped in 08.5's established style — offset-prefixed lines,
  `…` elision past the shown count. `--full-samples` lifts the *display* truncation only; it
  cannot recover samples the registry never retained (10.2's cap is a capture-time decision).
- **`--export DIR`.** Writes every retained sample as `DIR/<slug>-<n>.bin` (`slug` = a
  sanitized `UnknownKey` string) plus a `manifest.json` (key, count, byte-length stats,
  capture source path — **not** original byte offsets, which aren't recoverable post-hoc and
  are therefore not claimed). This is the direct on-ramp to curating a 09.2 fixture from
  something actually observed in the wild, rather than hand-crafting bytes.
- **`--scaffold NAME`.** Copies `crates/pktflow-plugins/src/template.rs` (06.1) to
  `crates/pktflow-plugins/src/<NAME>.rs`, substituting the protocol name and — when the
  group's `UnknownKey.route` is `Some` — pre-filling `claims()` with that `RouteId` and a doc
  comment showing the first retained sample as a worked hex example. Prints the one
  remaining step (add `NAME` to `default_engine()`'s registration list, per 06's contract)
  rather than editing `lib.rs` itself: the scaffold writes exactly one new file, so even
  generated code holds to PRD §8's "touching only its own file plus one registration line"
  metric literally. Refuses to overwrite an existing file — exits 2 (08.1's usage-error code);
  this is a starting point, not a merge tool.
- **`--format json`** applies to the table and drill-down views (D8 convention): counts,
  context, byte stats, and near-misses, but **not** raw sample bytes (use `--export` for
  those) — a deliberate JSON/binary split, documented as such, not an oversight.

## Acceptance criteria
- [ ] Table golden-tested against a fixture with two unknown groups (one `UnclaimedRoute`, one
      `NoHeuristicWinner` with near-misses) and separately against a clean fixture (zero
      groups ⇒ the explicit "none observed" line).
- [ ] Drill-down selector resolves; hex dump matches 08.5's established shape on a sample
      fixture; endpoint-overflow marker verified on a cap-exceeding fixture.
- [ ] `--export` round-trip: exported `.bin` files are byte-identical to the retained samples;
      `manifest.json` validated against a checked-in JSON Schema file in CI (mirrors 08.5's
      schema-in-CI discipline).
- [ ] `--scaffold`: the generated file compiles standalone (`cargo check -p pktflow-plugins`)
      and passes the 09.1 conformance kit's structural checks (name/claims present) even
      though `parse()` is still the template's placeholder body — the metric is "a human fills
      in real parsing next," not full auto-generation.
- [ ] `--scaffold` refuses to clobber an existing file at the target path (exit 2), verified by
      a test that pre-creates it.
- [ ] `--format json` on the table view validated against a schema file; sample bytes
      deliberately absent from that schema (covered by the export test above instead).
