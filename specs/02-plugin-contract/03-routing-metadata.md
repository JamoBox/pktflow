# 02.3 — Routing metadata: claims, predecessors, probe

> Task: [02 Plugin contract](README.md) · Depends on: 02.1, 02.2 · PRD: §4.B.1, FR-9, FR-14

## Goal
The optional self-descriptions that wire a plugin into routing automatically ("I am EtherType
0x0800") and into heuristic fallback safely (probe + predecessor prior).

## Specification

**Claims** — the identifiers a plugin natively answers to:

```rust
fn claims(&self) -> &'static [RouteId] { &[] }
// e.g. ipv4: &[RouteId::EtherType(0x0800), RouteId::IpProtocol(4 /* IP-in-IP */)]
// e.g. dns:  &[RouteId::UdpPort(53), RouteId::TcpPort(53)]
```

The router builder (03.2) auto-installs `claim → plugin` routes. Two plugins claiming the
same id is a **build-time error** (not last-wins): silent shadowing is how decode trees rot.
Overlaps must be resolved by an explicit manual override (FR-12).

**Expected predecessors** — bias for heuristic mode only, never a filter:

```rust
fn expected_predecessors(&self) -> &'static [ProtocolName] { &[] }
// e.g. tcp: &["ipv4", "ipv6"]
```

Used by 03.3 as the predecessor prior: candidates whose expected predecessor matches the
just-parsed layer get a fixed score boost. Empty slice = no opinion, no penalty.

**Probe** — self-scored confidence, fallback tier only:

```rust
pub struct Confidence(u8);           // 0..=100; construction clamps
fn probe(&self, bytes: &[u8], ctx: &ParseCtx) -> Option<Confidence> { None }
```

- `None` (default) = "never consider me heuristically" — the plugin is reachable only via
  explicit routes. Correct default: most protocols are unguessable from bytes.
- Probes must be **cheap** (bounded work, no allocation) and **honest** — checking version
  nibbles, sane lengths, checksums-of-first-header. Guidance scale: 90+ = structural
  invariants verified; 50–89 = plausible; <50 = don't bother returning it.
- A probe is *advisory*: winning the score contest still requires `parse` to succeed (03.3).

## Acceptance criteria
- [ ] Defaults compile away: a claims-less plugin adds no routes; probe-less plugin never
      appears in fallback scoring.
- [ ] Duplicate-claim collision surfaces as a build-time `RegistryError` naming both plugins.
- [ ] `Confidence` unrepresentable above 100.
