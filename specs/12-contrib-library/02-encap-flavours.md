# 12.2 — Capture-entry, tunnels & encapsulation flavours: SLL, ERSPAN, PPTP, IPsec NAT-T

> Task: [12 Contrib library](README.md) · Depends on: 02–06 · Cross-refs: 06.5 (`gre`),
> 11.5 (`esp`), 11.7 Tier 2 (IKEv2) · PRD: FR-32 · D9, D12, D14, D16

## Goal
Encapsulations the wild actually hands you that the stdlib doesn't open: captures taken
with `tcpdump -i any` (Linux cooked framing — extremely common in shared pcaps and the
single most frequent "why won't this file dissect?" report class), switch-port mirroring
shipped across the network (ERSPAN), and two VPN framings old and current (PPTP control,
UDP-encapsulated ESP). All four are pure dispatch layers — their value is routing into the
existing stack with zero stdlib edits.

## Specification

**sll** (Linux cooked capture v1/v2 — *no RFC*; the libpcap `LINKTYPE_LINUX_SLL`/`SLL2`
registry entries at tcpdump.org are the authoritative format docs).

| Item | Spec |
|---|---|
| Claims | `LinkType(113)` (SLL v1), `LinkType(276)` (SLL2) — entry routing, 04.2 |
| Fields | `Structural`: `packet_type` (0 host/1 broadcast/2 multicast/3 other-host/4 outgoing), `arphrd_type`, `iface_index` (SLL2 only), `addr_len` · `Full`: `link_addr` (Bytes, up to 8) |
| Hint | `Route(EtherType(protocol))` — the protocol field is EtherType-space, so the entire existing stack (ipv4/ipv6/arp/vlan/...) lights up with zero changes, GRE's exact reuse pattern (06.5) |
| Identity | none — framing metadata, not a conversation; contributes to nothing (there is no parent yet at entry) |
| Rollups | none |

**erspan** (Type II/III — *no RFC*; Cisco-proprietary, documented in
draft-foschiano-erspan, the closest authoritative doc).

| Item | Spec |
|---|---|
| Claims | `EtherType(0x88BE)` (Type II), `EtherType(0x22EB)` (Type III) — reachable through the **unmodified** 06.5 `gre`, which hints `Route(EtherType(protocol))`: GRE's protocol field reuses EtherType space, so these claims light up with no stdlib diff (the same zero-touch story as 11.5's Geneve) |
| Fields | `Structural`: `version` (1 = Type II, 2 = Type III), `vlan`, `cos`, `session_id` · `Full` (Type III): `timestamp`, `hw_id` |
| Hint | `ByProtocol("ethernet")` — the payload is a complete mirrored Ethernet frame (vxlan's exact inner-dispatch pattern, 06.5) |
| Identity | key `[{session_id, None}]` (shared qualifier, GRE-key/VXLAN-VNI shape) — one stream per mirror session, the mirrored traffic nesting under it automatically (D10) |
| Rollups | `Sample` on `vlan` |
| Limitation | ERSPAN Type I has **no header at all** (bare GRE 0x88BE with no sequence bit); distinguishing it stateless is guesswork, so v1 parses Type II/III only and a Type I capture declines — documented, not silent |

**pptp** (control channel, RFC 2637).

| Item | Spec |
|---|---|
| Claims | `TcpPort(1723)` |
| Fields | `Structural`: `length`, `message_type` (1 control/2 management), `control_type` (Start-Control-Connection-Request/-Reply, Echo-Request/-Reply, Outgoing-Call-Request/-Reply, Call-Clear-Request, Call-Disconnect-Notify, Set-Link-Info, ...) · `Full`: `call_id`, `peer_call_id` |
| Validation | `magic_cookie` must equal `0x1A2B3C4D` (RFC 2637 §2.2) or the plugin declines — the cheap sanity check this protocol hands us for free |
| Hint | `Terminal` |
| Identity | key `[{app, None}]` (shared, constant `Str("pptp")`), one child per TCP session |
| Rollups | `Accumulate` on `control_type` |
| Limitation | The data path is *enhanced* GREv1 carrying PPP (RFC 2637 §4); 06.5's `gre` parses standard GRE and correctly declines version 1. GREv1+PPP is a Tier-2 refinement of `gre` (coordination note below), not this entry's scope |

**ipsec_natt** (UDP-encapsulated ESP, RFC 3948; non-ESP marker per RFC 7296 §2.23).

| Item | Spec |
|---|---|
| Claims | `UdpPort(4500)` |
| Fields | `Structural`: `encap_kind` (Str: `"esp"` / `"ike"` / `"keepalive"`) — from the demux: a 1-byte `0xFF` datagram is a NAT-keepalive; first 4 bytes `0x00000000` is the non-ESP marker (IKE follows); anything else is ESP, whose first 4 bytes are the SPI |
| Hint | keepalive → `Terminal`; ESP → `ByProtocol("esp")` (the **unmodified** 11.5 plugin — SPI-keyed streams, D12 encryption boundary, all inherited); IKE → `ByProtocol("ikev2")`, which stops `UnclaimedRoute` (D9) until 11.7's Tier-2 IKEv2 is promoted — honest today, self-healing the day that plugin lands, with no edit here |
| Identity | none of its own — a pure demux shim; the streams that matter are `esp`'s underneath |
| Rollups | none |
| Coordination | When 11.7 promotes IKEv2, its spec claims `UdpPort(500)` only — port 4500's IKE arrives via this plugin's `ByProtocol` dispatch, so the two never contest a claim (recorded here so the future 11.7 PR doesn't have to rediscover it) |

### Planned (Tier 2 — not yet specified)
| Protocol | Standard | Note |
|---|---|---|
| GREv1 + PPP (PPTP data path) | RFC 2637 §4 | A refinement of 06.5's `gre` (version-1 handling) plus 11.5's `ppp` — needs a task-06 spec touch first per this task's zero-touch rule |
| VXLAN-GPE | draft-ietf-nvo3-vxlan-gpe | `UdpPort(4790)`; protocol-typed inner (not always Ethernet) |
| CAPWAP | RFC 5415 | `UdpPort(5246)`/`UdpPort(5247)`; DTLS-wrapped (cross-ref 12.4) |
| STT | draft-davie-stt | Stateless Transport Tunneling — TCP-*shaped* header that isn't TCP; a claim-space honesty problem worth its own write-up |
| ZeroTier | *No standard* — project protocol docs | `UdpPort(9993)`, near-fully encrypted (D12 ceiling ≈ header only) |
| L2F | RFC 2341 | Historic; predecessor of L2TP |
| BSD loopback/null | libpcap `LINKTYPE_NULL` | `LinkType(0)`; 4-byte host-order AF — sibling of `sll` for BSD-taken captures |

## Acceptance criteria
- [ ] An `-i any` capture fixture (SLL v1) and an SLL2 fixture both route their inner IPv4
      packets through the **unmodified** stdlib to correct TCP/UDP streams end-to-end; a
      truncated cooked header declines cleanly.
- [ ] `erspan` fixture: a mirrored-session capture routes `gre ▸ erspan ▸ ethernet ▸ ...`
      with no stdlib diff, forms one `session_id` stream, and nests the mirrored traffic
      under it (06.5's tunnel-hierarchy rigor); Type II and Type III both covered.
- [ ] `pptp` fixture: SCCRQ/SCCRP + Outgoing-Call-Request/Reply sequence parses exactly;
      a wrong `magic_cookie` declines rather than parsing garbage.
- [ ] `ipsec_natt` fixtures: an ESP-in-UDP packet reaches the 11.5 `esp` plugin (SPI stream
      forms); a keepalive stops `Terminal`; a non-ESP-marker packet stops
      `UnclaimedRoute("ikev2")` — all three demux arms tested, the third proving the
      documented forward reference behaves as specified.
