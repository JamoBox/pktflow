# 05.1 — Flow keys & canonicalization

> Task: [05 Aggregator](README.md) · Depends on: 02.4 · PRD: FR-2, FR-3, §4.A · D3

## Goal
Turn a layer's extracted fields + its plugin's `StreamIdentity` into a canonical `FlowKey`
plus the packet's direction — the identity operation everything downstream keys on.

## Specification

```rust
pub struct FlowKey(SmallVec<[u8; 40]>);   // canonical byte encoding; Eq + Hash; 40 covers
                                          // an IPv6 pair + qualifiers without heap
pub enum PacketDirection { AtoB, BtoA }
```

Key construction for one layer (engine-side, uniform for every protocol — PRD §4.A):

1. For each `KeyField { a, b }` in the identity, fetch `fields[a]` (and `fields[b]` if
   paired). Missing field ⇒ `KeyError::MissingField` — the packet still counts into parent
   streams, but this layer forms no stream, and the error is a diagnostics counter (a plugin
   contract violation 09.1 should have caught).
2. Encode each `Value` to bytes with a **length-prefixed, type-tagged** encoding (so
   `["ab","c"]` ≠ `["a","bc"]` and `U64(1)` ≠ `Bool(true)`).
3. `Canonicalize::EndpointSort` (D3): concatenate A-side component encodings → `ea`, B-side
   → `eb`; unpaired (shared) components → `es`. If `ea <= eb` lexicographically: key =
   `es ++ ea ++ eb`, packet direction = `AtoB`; else key = `es ++ eb ++ ea`, direction =
   `BtoA`. Equal endpoints (self-talk): direction fixed `AtoB`.
4. `Canonicalize::Custom(f)`: call it; trust its determinism (contract, spot-checked by 09.1
   running it twice per packet).

Properties (the proptest suite for this spec):

- **Involution:** swapping all a/b field values yields the same `FlowKey` with flipped
  direction (FR-3's core promise).
- **Injectivity within a protocol:** distinct canonical endpoint sets ⇒ distinct keys.
- Keys are only compared within `(parent, protocol)` scope (D10), so cross-protocol
  collisions are impossible by construction — no protocol tag needed inside the key.

The **initiator** (D3) is not part of the key: the store (05.2) records the direction of
the stream's first packet as `initiator: PacketDirection` at stream creation.

## Acceptance criteria
- [x] Encoding + `EndpointSort` implemented; the two properties above proptest-verified over
      random field values including empty bytes/strings and lists.
- [x] MAC-pair, IPv6-pair, and port-pair keys stay within the SmallVec inline capacity
      (no heap) — asserted in tests.
- [x] `MissingField` path: layer skipped, parents still updated, diagnostic counter bumped.
