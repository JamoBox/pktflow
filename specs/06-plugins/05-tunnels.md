# 06.5 — Tunnels: GRE, VXLAN

> Task: [06 Plugins](README.md) · Depends on: 02–05 · PRD: FR-19 tunneling, FR-8, FR-21 "tunneled nested stream", §4.B.3 direct-by-name

## Goal
Encapsulation as a first-class case: two tunnel shapes — GRE (next protocol named by a
field) and VXLAN (inner protocol fixed ⇒ `ByProtocol`) — whose inner stacks nest as child
streams with zero aggregator special-casing (05.3).

## Specification

**gre** (RFC 2784/2890) — 4–16 bytes depending on C/K/S flag bits.

| Item | Spec |
|---|---|
| Claims | `IpProtocol(47)` |
| Fields | `Keys`: `key` (U64; present only if K bit — see below) · `Structural`: `flags`, `protocol` (EtherType-space value), `version` · `Full`: `checksum`, `sequence` |
| Hint | `Route(EtherType(protocol))` — GRE reuses the EtherType space; no new route space needed (03.1 note) |
| Identity | key `[{key, None}]` when K bit set — the GRE key is a shared (non-endpoint) qualifier (02.4). **Keyless GRE:** `key` field emitted as `U64(0)`… *no*: absent field would kill key-building (05.1). Resolution: plugin emits `key` **always**, `Value::U64(key_or_0)`; keyless tunnels between one IP pair thus share one GRE stream — correct, since nothing distinguishes them |
| Probe | none (tunnels are explicit-only) |

**vxlan** (RFC 7348) — 8-byte header.

| Item | Spec |
|---|---|
| Claims | `UdpPort(4789)` |
| Fields | `Keys`: `vni` (U64) · `Structural`: `flags` |
| Hint | `ByProtocol("ethernet")` — the direct-by-name dispatch demonstration (Hint kind 3, FR-11): VXLAN always wraps an Ethernet frame |
| Identity | key `[{vni, None}]` → one stream per VNI within the outer UDP stream |

Resulting hierarchies (normative fixtures):

```text
GRE:   eth ▸ ipv4 ▸ gre ▸ ipv4 ▸ tcp            (inner IP conv parented to GRE stream)
VXLAN: eth ▸ ipv4 ▸ udp ▸ vxlan ▸ eth ▸ ipv4 ▸ udp   (full inner stack incl. inner MAC conv)
```

Both fall out of the 05.3 nearest-outer rule — these specs add **no** aggregator code.
The inner ethernet layer entering via `ByProtocol` (not link type) exercises 02.2's by-name
path end-to-end.

## Acceptance criteria
- [ ] Both fixture hierarchies asserted node-by-node (FR-8, FR-21 item 5).
- [ ] GRE flag-dependent header length: all 8 C/K/S combinations length-tested; truncation
      inside optional words handled.
- [ ] Two VNIs over one outer UDP stream → two sibling vxlan streams (shared-qualifier key
      semantics verified).
- [ ] Inner streams' `PacketDirection` remains canonical per their own keys even when outer
      and inner directions disagree (return traffic on an asymmetric tunnel fixture).
