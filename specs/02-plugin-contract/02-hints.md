# 02.2 — Next-layer hints

> Task: [02 Plugin contract](README.md) · Depends on: 02.1 · PRD: FR-11, §4.B.3

## Goal
The plugin's declaration of what follows its header — the router's preferred input, covering
all five kinds required by FR-11.

## Specification

```rust
pub enum Hint {
    /// One definite protocol identifier (EtherType 0x0800, IP proto 6, dst port 53).
    Route(RouteId),
    /// Ranked candidates, best first — e.g. UDP offering [dst_port, src_port] routes.
    Candidates(SmallVec<[RouteId; 4]>),
    /// Direct dispatch by plugin name — encapsulation where the inner protocol is fixed
    /// (e.g. VXLAN always wraps "ethernet"). Bypasses route-id lookup entirely.
    ByProtocol(ProtocolName),
    /// Header named nothing usable; heuristic fallback may run (gated, 03.4).
    Unknown,
    /// This layer is definitively last (ICMP payload, ARP). No fallback runs.
    Terminal,
}
```

Semantics (router behavior in 03.x, restated here as the plugin-facing contract):

| Hint | Router action |
|---|---|
| `Route(id)` | one lookup; if claimed → dispatch; if **unclaimed → stop** (gated, FR-15) |
| `Candidates(ids)` | try in order, first claimed id whose plugin parses successfully wins; all unclaimed → stop |
| `ByProtocol(name)` | dispatch to that plugin by name; unknown name → stop |
| `Unknown` | heuristic fallback pool may score (03.3) |
| `Terminal` | dissection ends, `StopReason::Terminal` |

- `Route` vs `Candidates` is the "explicit (preferred)" tier of PRD §4.B.3; `ByProtocol` is
  its direct-by-name flavor; `Unknown`/`Terminal` are the two safe endings.
- **Distinction that matters:** `Unknown` permits heuristics; `Route`/`Candidates` that
  resolve to nothing do **not** — the header *named* a protocol we lack, so guessing would
  fabricate streams (PRD §4.B.4, the encrypted-UDP failure).
- Plugins choose the *most explicit* hint they can. Emitting `Unknown` when the header has a
  next-protocol field is a plugin bug the review checklist (06) catches.

## Acceptance criteria
- [ ] `Hint` implemented; `SmallVec` keeps `Candidates` allocation-free for ≤4 entries.
- [ ] Table above encoded as doc comments on each variant (the plugin author's reference).
- [ ] Exhaustive-match test ensures adding a variant forces conscious router updates.
