# 08.1 — Command surface

> Task: [08 CLI](README.md) · Depends on: 07.* · PRD: FR-22, FR-23, FR-27

## Goal
The argument grammar: subcommands mapping one-to-one onto the product's lenses, with input
selection and shared flags factored once.

## Specification

```text
pktflow streams  (-r FILE | -i IFACE) [--layer PROTO] [--merged] [--watch] [shared]   # default lens (08.2)
pktflow stream   (-r FILE | -i IFACE) <STREAM-SELECTOR>                    [shared]   # drill-down (08.3)
pktflow packets  (-r FILE | -i IFACE) [-v...]                              [shared]   # debug lens (08.4)
pktflow ifaces                                                                         # FR-23 (07.3)

shared flags:
  -r, --read FILE            offline replay (07.2)     [conflicts -i]
  -i, --iface IFACE          live capture (07.3)       [conflicts -r]
  -f, --filter BPF           kernel filter string
  -c, --count N              packet cap (FR-27)
      --depth {keys|structural|full}    extraction depth, default structural (01.3;
                                        keys floor auto-applies — aggregation always on in CLI)
      --format {text|json}   D8, default text
      --idle-timeout SECS / --max-streams N     live eviction overrides (D2)
```

- `pktflow FILE` (bare path, no subcommand) = `pktflow streams -r FILE` — the zero-friction
  path for the curious analyst.
- **Mode defaults follow D2 automatically:** `-r` ⇒ `EvictionPolicy::None`; `-i` ⇒
  `Live` defaults; overrides via the two flags.
- End-of-run **summary on stderr** (text mode) regardless of subcommand (FR-27): packets
  processed, per-`StopClass` counts (D9), streams per protocol (ever/live), capture drops
  (07.3 — printed loudly when nonzero), elapsed + rate.
- Exit codes: `0` ok · `1` runtime error (`CaptureError` etc.) · `2` usage error (clap).
  Parse failures of individual packets are **not** process errors (they're data — D9).
- Ctrl-C in live mode: first press = graceful (stop pump → `finish()` → final report);
  second press = immediate exit.

## Acceptance criteria
- [ ] clap tree implemented with the conflicts/defaults above; `--help` snapshot-tested
      (help text is UI; regressions are real).
- [ ] Bare-path shorthand works; usage errors exit 2 with clap's message.
- [ ] Summary appears on stderr for all subcommands and never contaminates `--format json`
      stdout (pipe-safety test: `pktflow streams -r f --format json | jq .` succeeds).
- [ ] Graceful Ctrl-C verified manually on both OSes (checklist item, not CI).
