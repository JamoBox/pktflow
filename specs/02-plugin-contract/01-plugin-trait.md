# 02.1 — The `LayerPlugin` trait

> Task: [02 Plugin contract](README.md) · Depends on: 01.* · PRD: FR-9, FR-10, §4.B.1

## Goal
One trait, two required members. Everything else has a default so the minimal plugin is
tiny — that minimality is the "well under an hour" success metric's foundation (PRD §8).

## Specification

```rust
pub trait LayerPlugin: Send + Sync {
    /// Unique protocol name, lowercase snake_case: "ethernet", "ipv4", "vlan".
    fn name(&self) -> ProtocolName;

    /// Parse exactly one header from the front of `bytes`.
    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError>;

    // ---- optional, defaulted (specs 02.3, 02.4) ----
    fn claims(&self) -> &'static [RouteId] { &[] }
    fn expected_predecessors(&self) -> &'static [ProtocolName] { &[] }
    fn probe(&self, bytes: &[u8], ctx: &ParseCtx) -> Option<Confidence> { None }
    fn stream_identity(&self) -> Option<&StreamIdentity> { None }
}

pub struct ParsedLayer {
    pub header_len: usize,   // bytes this header consumed; parser slices payload after it
    pub fields: FieldMap,    // respecting ctx.depth() and the flow-key floor (01.3)
    pub hint: Hint,          // what follows (02.2)
}
```

Contract rules (enforced by the 09.1 test kit where mechanically possible):

1. **Parse one header only.** Never look into the payload beyond your own header, except to
   compute `header_len` (options/extensions count as header).
2. **Decline, don't guess.** If bytes can't be your protocol, return `Err(ParseError)` —
   cheap and routine (00.2). Never return a half-parsed success.
3. **`header_len ≤ bytes.len()`** on success; parser verifies and treats violation as
   `PluginError` (defense against a buggy plugin corrupting offsets).
4. **Depth-honoring:** field extraction gated on `ctx.depth()`; flow-key fields always
   present at ≥ `Keys` (01.3).
5. **Stateless:** `&self` methods, no interior mutability. All cross-packet state lives in
   the aggregator (05). Plugins are constructed once and shared (`Send + Sync`, D5).

## Acceptance criteria
- [ ] Trait object-safe: `Box<dyn LayerPlugin>` and `&dyn LayerPlugin` usable.
- [ ] A ~30-line no-op test plugin (fixed header_len, one field, `Hint::Terminal`)
      implements only the two required members and passes the 09.1 kit's generic checks.
- [ ] Rule 3 verified by an engine-side unit test with a lying plugin.
