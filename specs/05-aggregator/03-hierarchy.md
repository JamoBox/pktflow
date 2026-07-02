# 05.3 — Flow hierarchy

> Task: [05 Aggregator](README.md) · Depends on: 05.2 · PRD: FR-4, FR-8, §4.A "streams nest" · D10

## Goal
The parent→child linking that makes traffic browsable top-down — MAC conversation ▸ IP
conversation ▸ TCP session ▸ tunneled inner streams — falling naturally out of per-packet
layer order.

## Specification

- **Rule (already in 05.2's ingest):** a layer's stream is parented to the *nearest outer
  stream-bearing layer's stream in the same packet*. No tunnel-special-casing exists —
  GRE/VXLAN nesting (FR-8) is this rule applied to `[eth, ipv4, gre, ipv4, tcp]`: the inner
  ipv4 conversation's parent is the GRE stream, giving
  `eth ▸ ipv4 ▸ gre ▸ ipv4 ▸ tcp` with zero engine knowledge of "tunnel".
- **D10 scoping:** node identity = `(parent, protocol, key)`. Consequences to encode in
  tests, because they define observable behavior:
  1. Same TCP port-pair under two different IP conversations → two distinct sessions
     (this is what makes ports-only TCP keys correct, 02.4).
  2. Same IP pair under two MAC conversations (e.g. traffic before/after ARP re-resolution
     to a new gateway MAC) → two IP conversation nodes. The merged layer view (05.7) can
     fold them for display.
  3. A stream's parent never changes. If a later packet presents the same inner key under a
     different outer path, that is by definition a different node (rule 1/2) — no re-parenting
     logic exists.
- **Roots:** streams with `parent: None` (normally MAC conversations; raw-IP captures root
  at IP). `Aggregator` keeps a `roots: Vec<StreamId>` in creation order.
- `children` order = creation order (deterministic).
- Depth is naturally bounded by `max_layers` (04.1); no separate hierarchy depth limit.

## Acceptance criteria
- [ ] GRE and VXLAN fixtures produce the exact nested chains above (FR-8), asserted
      node-by-node via the query API.
- [ ] Consequence tests 1 and 2 pass as described.
- [ ] Hierarchy integrity property (proptest over random synthetic captures): every
      non-root's parent exists, parent/child links are mutually consistent, no cycles.
