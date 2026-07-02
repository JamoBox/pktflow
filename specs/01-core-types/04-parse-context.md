# 01.4 — Parse context & cross-layer lookup

> Task: [01 Core types](README.md) · Depends on: 01.2, 01.3 · PRD: FR-17, §4.B.6

## Goal
What a plugin sees when parsing: the layers already parsed (outer context) and the effective
extraction depth — with the innermost-wins lookup rule for repeated protocols.

## Specification

```rust
pub struct ParseCtx<'a> {
    layers: &'a [LayerRecord],   // outermost → innermost, all layers parsed so far
    depth: Depth,                // effective depth (already clamped per 01.3)
    meta: &'a PacketMeta,
}
impl<'a> ParseCtx<'a> {
    pub fn depth(&self) -> Depth;
    pub fn meta(&self) -> &PacketMeta;
    /// Innermost layer with this protocol name, if any (FR-17: nearest occurrence).
    pub fn layer(&self, protocol: &str) -> Option<&LayerRecord>;
    /// Convenience: `self.layer(protocol)?.fields.get(field)`.
    pub fn field(&self, protocol: &str, field: &str) -> Option<&Value>;
    /// The immediately preceding layer (the plugin's direct predecessor), if any.
    pub fn prev(&self) -> Option<&LayerRecord>;
}
```

- **Innermost-wins:** `layer()` scans from the end of the slice backwards; with stacked
  repeats (nested tunnels, QinQ VLANs) the nearest enclosing occurrence is returned
  (PRD §4.B.6). No API exposes "all occurrences" in v1 — plugins needing the outer one is a
  non-case so far; add later if a real plugin demands it.
- The context is **read-only**: plugins cannot mutate outer layers. All plugin influence on
  what happens next flows through their returned hint (02.2).
- Borrowed (`'a`) from the in-progress parse session; never stored by plugins (enforced by
  lifetimes — `parse` takes `&ParseCtx`, returns owned data).

## Acceptance criteria
- [x] `ParseCtx` implemented; unit test with layers `[eth, ipv4, gre, ipv4, tcp]` asserts
      `layer("ipv4")` returns the record at index 3 (innermost) and `prev()` from a
      hypothetical next parse sees `tcp`.
- [x] `field()` returns `None` (not panic/error) for absent protocol or field.
- [x] Lifetime design proven: a plugin cannot retain `&LayerRecord` beyond `parse` (compile-
      fail doctest or documented by construction).
