# 06.1 — Template plugin

> Task: [06 Plugins](README.md) · Depends on: 02.* · PRD: FR-20

## Goal
`template.rs`: a minimal fictional protocol that is simultaneously a working plugin, the
documentation of the contract, and the file a new author copies. It must exercise *both*
halves — dissection and stream identity — in the simplest possible form.

## Specification

Fictional protocol "PKTT" (so it never collides with reality), 8-byte header:

```text
0      2      4      6      8
| src  | dst  | type | len  |   u16 each, big-endian
```

The file demonstrates, in order, with a tutorial comment per section:

1. Field-name constants (`const SRC: FieldName = "src";` …).
2. `name()` and `parse()` via `ByteReader` — depth gating (`Keys` → src/dst; `Structural`
   → type/len), hint from `type` (`0x0001` → `Hint::ByProtocol("template")` self-nesting to
   demo encapsulation; else `Terminal`).
3. `claims()` → `&[RouteId::Custom { space: "pktt", id: 0 }]` (shows claims without
   squatting a real space).
4. `probe()` → honest check of the `len` field vs. buffer.
5. `stream_identity()` → key `[{src, dst}]`, `EndpointSort`, one `Accumulate` rollup on
   `type`.
6. Unit tests: parse, truncation, flow-key involution via the 09.1 kit — the tests a real
   plugin should copy too.

Target size: **≤ 150 lines including comments and tests.** If the contract can't be
demonstrated in 150 lines, the contract is too heavy — this file is the canary; treat
overshoot as a task-02 design smell, not a reason to trim the tutorial.

Also: `docs/adding-a-protocol.md` — a short walkthrough that says "copy template.rs, rename,
fill in your header, add one line to `default_engine()`", written against this file.

## Acceptance criteria
- [ ] `template.rs` compiles, registers, passes the 09.1 kit, ≤ 150 lines.
- [ ] A synthetic PKTT-in-PKTT capture shows a nested stream in the CLI (proves the full
      pipeline with zero real-protocol involvement).
- [ ] `docs/adding-a-protocol.md` exists and its steps were literally followed once by the
      "16th toy plugin" rehearsal (06 README definition of done).
