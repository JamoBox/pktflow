# 03.4 — Gated termination

> Task: [03 Router](README.md) · Depends on: 03.3 · PRD: §4.B.4, FR-15, §8 "no phantom streams"

## Goal
The safety property the whole design leans on: when a header *names* what follows and we
don't have it, **stop** — don't let heuristics invent layers, because a misidentified layer
fabricates a bogus conversation.

## Specification

Decision table after each parsed layer (normative; supersedes prose elsewhere if in conflict):

| Situation | Action | StopReason |
|---|---|---|
| `Hint::Terminal` | stop | `Terminal` |
| `Hint::Route(id)`, id claimed, parse ok | continue | — |
| `Hint::Route(id)`, id claimed, parse **fails** | stop (no fallback — explicit route + failed parse = malformed/truncated, not unknown) | `PluginError` or `Truncated` per the error |
| `Hint::Route(id)`, id **unclaimed** | **stop — the gate.** Payload is unsupported/encrypted; heuristics forbidden | `UnclaimedRoute(id)` |
| `Hint::Candidates`, some claimed | try in rank order; first parse-success wins; all fail → stop | `PluginError` |
| `Hint::Candidates`, none claimed | stop — same gate | `UnclaimedRoute(first)` |
| `Hint::ByProtocol(name)`, known | dispatch; parse fail → stop | `PluginError` |
| `Hint::ByProtocol(name)`, unknown | stop | `UnclaimedRoute(custom)` |
| `Hint::Unknown` | heuristics permitted (03.3) | `UnknownHint` if no winner |
| Remaining payload empty | stop | `Complete` |

Invariants:

1. **The gate:** heuristics run only on `Hint::Unknown` (or entry, 04.2). A named-but-
   unclaimed route can never reach the fallback pool.
2. **No re-selection:** a plugin that failed on byte range X is not re-offered X in the same
   packet's dissection (applies within `Candidates` iteration and fallback rounds, FR-15).
3. **No phantom streams:** stopping produces no `LayerRecord`, hence no stream (05 only sees
   emitted layers). Remaining bytes become `opaque_len` (01.2) attributed to the innermost
   real stream (D9).
4. The motivating failure — encrypted UDP payload "recognized" as TCP→IPv6→TCP forever
   (PRD §4.B.4) — must be encoded as fixture test `encrypted_udp_no_phantom`: UDP layer with
   an unclaimed port route ⇒ dissection ends at UDP, exactly one UDP stream, zero TCP streams.

> **Diagnostics exception (10.1, D11):** an opt-in, off-by-default diagnostic mode may score
> fallback-pool plugins against bytes at any `StopClass::Unknown` stop — including
> `UnclaimedRoute`, where this table forbids fallback from *routing* — purely to report
> near-miss confidence to a developer. This never calls `parse()` and never produces a
> `LayerRecord`; the no-phantom-streams invariant above is unaffected. See 10.1 for the exact
> boundary.

## Acceptance criteria
- [x] Decision table implemented in one place (single `resolve_next` function — not spread
      across the parser) and unit-tested row by row.
- [x] `encrypted_udp_no_phantom` fixture test passes.
- [x] Property test (proptest): random bytes through a full reference-plugin engine never
      panic and never yield a layer whose plugin's own `parse` would decline those bytes.
