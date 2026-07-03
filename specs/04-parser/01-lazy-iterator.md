# 04.1 — Lazy iterator

> Task: [04 Parser](README.md) · Depends on: 03.* · PRD: §4.B.2, FR-13

## Goal
One parsed layer per step, borrowing the capture buffer, consuming only as deep as the
caller pulls — laziness is a real performance lever when depth or an early consumer stops
the walk (PRD §7).

## Specification

```rust
impl Engine {
    pub fn layers<'a>(&'a self, bytes: &'a [u8], meta: &PacketMeta, opts: ParseOpts)
        -> LayerIter<'a>;
}

pub struct ParseOpts {
    pub depth: Depth,             // requested; engine clamps to Keys if aggregation on (01.3)
    pub aggregation: bool,        // enables the flow-key floor
    pub max_layers: usize,        // runaway guard, default 32
}

pub struct LayerIter<'a> { /* engine, cursor, accumulated Vec<LayerRecord>, pending hint */ }

pub struct LayerStep<'a> {
    pub record: LayerRecord,      // owned (fields extracted)
    pub payload: &'a [u8],        // remaining bytes after this header — borrowed, zero-copy
    pub via_heuristic: bool,      // 03.3 diagnostic
}

impl<'a> Iterator for LayerIter<'a> { type Item = LayerStep<'a>; /* ... */ }
impl<'a> LayerIter<'a> {
    pub fn stop_reason(&self) -> Option<StopReason>;  // Some(...) once iteration has ended
    pub fn into_packet(self, meta: PacketMeta) -> DissectedPacket;  // finish eagerly (04.3)
}
```

Step algorithm: resolve next plugin (entry rule 04.2 for the first step, then the 03.4
decision table on the pending hint) → `parse(remaining, ctx)` → verify `header_len` (02.1
rule 3) → push record into the internal stack (this is what `ParseCtx` borrows) → yield
step with advanced payload slice.

- `max_layers` exists because a hostile packet + a buggy plugin could self-encapsulate
  forever; hitting it is `StopReason::DepthCap`.
- The iterator owns the growing `Vec<LayerRecord>` so `ParseCtx` (01.4) can present prior
  layers by reference; `next()` returns clones of nothing — records move out, context reads
  the internal copy. (Concretely: the iterator keeps the records and yields `&LayerRecord`…
  **resolved:** yield index-stable references is lifetime-hostile in an `Iterator`; instead
  the record is *cloned cheap* — FieldMap is small — into the step, canonical copy stays
  internal. Revisit only if 09.4 shows this clone on the profile.)

## Acceptance criteria
- [x] `LayerIter` implemented; a fixture eth/ipv4/tcp packet yields exactly 3 steps with
      correct offsets, payload slices, and final `stop_reason() == Some(Complete)`.
- [x] Pulling only 1 step provably skips inner parsing (instrumented test plugin counts
      `parse` calls — laziness verified, not assumed).
- [x] `max_layers` cap test with a self-recursing test plugin → `DepthCap`, no hang.
- [x] Depth clamp: `aggregation: true` + `Depth::None` ⇒ plugins observe `Keys` (01.3).
