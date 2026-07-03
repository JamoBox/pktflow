# 06.2 — Link layer: Ethernet II, 802.1Q VLAN

> Task: [06 Plugins](README.md) · Depends on: 02–05 · PRD: FR-19 link, FR-21 "MAC conversation"

## Goal
The capture entry point (Ethernet → MAC conversations) and the canonical identity-less
pass-through layer (VLAN).

## Specification

**ethernet** — 14-byte header.

| Item | Spec |
|---|---|
| Claims | `LinkType(1 /* DLT_EN10MB */)` |
| Fields | `Keys`: `src_mac`, `dst_mac` (Bytes, 6) · `Structural`: `ethertype` (U64) |
| Hint | `Route(EtherType(ethertype))`; ethertype < 0x0600 (802.3 length) → `Unknown` |
| Probe | none (link entry is explicit by link type) |
| Identity | key `[{src_mac, dst_mac}]`, `EndpointSort` → **MAC conversation** (FR-21) |
| Rollups | `Accumulate` on `ethertype` (protocols seen inside this MAC pair) |

**vlan** (802.1Q) — 4-byte tag.

| Item | Spec |
|---|---|
| Claims | `EtherType(0x8100)`, `EtherType(0x88A8 /* QinQ S-tag */)` |
| Fields | `Keys`: `vlan_id` (U64) · `Structural`: `pcp`, `dei`, `ethertype` |
| Hint | `Route(EtherType(inner_ethertype))` — including 0x8100 again (QinQ stacks naturally) |
| Identity | **None** (02.4's identity-less demonstration): a VLAN tag qualifies the MAC conversation rather than forming its own; per-VLAN conversation splitting is a v2 decision |
| Note | `vlan_id` still extracted at `Keys` for cross-layer readers, harmless without identity |

QinQ: two stacked vlan layers parse as two `LayerRecord`s; cross-layer `layer("vlan")`
returns the inner one (01.4 innermost-wins — this is the spec's stacked-repeat test case).

## Acceptance criteria
- [x] Real-frame fixtures parse with exact expected fields; truncation tests at 13 and
      17 bytes (mid-tag).
- [x] MAC conversation forms with folded directions on an A↔B fixture (FR-21 item 1).
- [x] eth ▸ vlan ▸ ipv4 packet: IP stream's parent is the **eth** stream (identity-less
      bridge, 05.2 criterion).
- [x] QinQ fixture: both tags parsed, innermost-wins lookup verified.
