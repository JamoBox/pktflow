# 06.3 — Network layer: IPv4, IPv6, ARP, ICMPv4, IGMP

> Task: [06 Plugins](README.md) · Depends on: 02–05 · PRD: FR-19 network, FR-21 "IP conversation"

## Goal
IP conversations (both families), plus the three terminal-ish network protocols that
demonstrate `Terminal` hints and rollup-only metadata.

## Specification

**ipv4** — variable header (IHL).

| Item | Spec |
|---|---|
| Claims | `EtherType(0x0800)`, `IpProtocol(4 /* IP-in-IP */)` |
| Fields | `Keys`: `src_addr`, `dst_addr` (Bytes, 4) · `Structural`: `protocol`, `ttl`, `total_len`, `flags`, `frag_offset`, `ihl` · `Full`: `dscp`, `ecn`, `id`, `checksum`, `options` (Bytes) |
| Hint | fragment with offset > 0 → `Terminal` (no transport header present; reassembly is out of scope, D7) — else `Route(IpProtocol(protocol))` |
| Probe | version nibble == 4, IHL ≥ 5, total_len ≤ remaining, header checksum valid → 90; used by raw-IP entry (04.2) |
| Identity | key `[{src_addr, dst_addr}]`, `EndpointSort` → **IP conversation** (FR-21) |
| Rollups | `Accumulate` on `protocol` |

**ipv6** — 40-byte fixed header.

| Item | Spec |
|---|---|
| Claims | `EtherType(0x86DD)`, `IpProtocol(41 /* 6-in-4 */)` |
| Fields | `Keys`: `src_addr`, `dst_addr` (Bytes, 16) · `Structural`: `next_header`, `hop_limit`, `payload_len` · `Full`: `traffic_class`, `flow_label` |
| Ext headers | Hop-by-Hop/Routing/Dest-Options/Fragment consumed as part of this layer's `header_len` (chain walked with a bound of 8); final next-header value routes. Fragment ext with offset > 0 → `Terminal` (as ipv4) |
| Probe | version nibble == 6, payload_len sane → 75 |
| Identity | as ipv4 → IP conversation |

**arp** — `Claims: EtherType(0x0806)`. Fields (`Structural` floor — ARP has no stream
identity so no `Keys` tier): `opcode`, `sender_mac`, `sender_ip`, `target_mac`, `target_ip`.
Hint: `Terminal`. Identity: **None** — ARP is request/reply chatter, not a conversation.
Its packets contribute stats to the parent MAC conversation; its fields remain per-packet
data (rollups attach only via a plugin's own identity, so identity-less ARP cannot declare
them — documented v1 stance, revisit if per-MAC ARP summaries prove wanted).

**icmpv4** — `Claims: IpProtocol(1)`. Fields: `type`, `code` (`Keys`-tier: none needed),
`Full`: `rest_of_header` (Bytes). Hint: `Terminal` (payload quotes the offending packet;
parsing quoted packets is v2). Identity: **None**; the parent IP conversation carries it.

**igmp** — `Claims: IpProtocol(2)`. Fields: `type`, `max_resp`, `group_addr`. Hint:
`Terminal`. Identity: None.

## Acceptance criteria
- [x] Fixture packets for all five parse exactly; ipv4 options and ipv6 ext-header chains
      covered including the chain bound (9th ext header → `PluginError`, no loop).
- [x] IP conversation folding verified for v4 and v6 (FR-21 item 2).
- [x] Fragment handling: offset>0 fragments are `Terminal`, still counted into the IP
      conversation (no phantom transport stream from fragment payloads).
- [x] ipv4 probe honesty: random bytes score `None`/low; checksum-broken header scores low.
