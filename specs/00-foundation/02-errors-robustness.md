# 00.2 — Errors & robustness conventions

> Task: [00 Foundation](README.md) · Depends on: 00.1 · PRD: §7 robustness · D9

## Goal
Malformed, truncated, or hostile input must never panic the engine (PRD §7). Establish the
error taxonomy and the byte-access discipline every later task follows.

## Specification

**No-panic policy.** In `core`, `flows`, and `plugins`: no `unwrap`/`expect`/indexing/slicing
on input-derived values in non-test code. All byte access goes through a checked cursor:

```rust
pub struct ByteReader<'a> { /* input slice + position */ }
impl<'a> ByteReader<'a> {
    pub fn u8(&mut self) -> Result<u8, Truncated>;
    pub fn u16_be(&mut self) -> Result<u16, Truncated>;   // u32_be, u64_be, i32_be…
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], Truncated>;
    pub fn remaining(&self) -> usize;
}
pub struct Truncated { pub needed: usize, pub have: usize }
```

`ByteReader` lives in `pktflow-core` and is the **only** sanctioned way plugins read headers.

**Error taxonomy** (`thiserror`-derived, non-exhaustive enums):

| Type | Crate | Meaning |
|---|---|---|
| `ParseError` | core | plugin declined bytes: `Truncated`, `Malformed(&'static str)` |
| `StopReason` | core | why a packet's dissection ended (full list in D9 / spec 04.3) |
| `CaptureError` | capture | device/file/permission failures |
| `CliError` | cli | user-facing wrapper with exit codes |

A `ParseError` is **not** a program error — it is routine data ("these bytes are not my
protocol") and must be cheap: no allocation, no backtrace capture.

## Acceptance criteria
- [x] `ByteReader` implemented with unit tests covering every method at boundary conditions
      (empty input, exact-length, off-by-one).
- [x] Error enums defined and exported; `ParseError` is `Copy` or otherwise allocation-free.
- [x] A crate-level test feeds 0-, 1-, and truncated-length buffers through `ByteReader`
      patterns and asserts `Err(Truncated)` — never a panic (this becomes the fuzz seed).
