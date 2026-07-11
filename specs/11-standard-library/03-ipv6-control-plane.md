# 11.3 — IPv6 control plane: ICMPv6, NDP, MLDv1/v2, DHCPv6

> Task: [11 Standard library](README.md) · Depends on: 02–06 · PRD: FR-31 (D6's "ICMPv6, ND... later" arrives here) · D12, D13, D14

## Goal
IPv6's equivalents of task 06's ICMPv4/ARP/IGMP/DHCP: error/echo messages, neighbor
discovery (IPv6's ARP-equivalent), multicast group management (IPv6's IGMP-equivalent), and
stateful address configuration.

## Specification

**icmpv6** (RFC 4443) — the dispatch layer: basic error/echo types terminate here; Neighbor
Discovery and MLD message types (which the RFCs define as ICMPv6 message types, not separate
IP protocols) route onward to their own plugins by type.

| Item | Spec |
|---|---|
| Claims | `IpProtocol(58)` |
| Fields | `Structural`: `type`, `code` · `Full`: `rest_of_header` (Bytes, 4 — layout is type-specific, kept raw here) |
| Hint | type ∈ {128 Echo Request, 129 Echo Reply, 1–4 Destination Unreachable/Packet Too Big/Time Exceeded/Parameter Problem} → `Terminal`; type ∈ {133..137} (RS/RA/NS/NA/Redirect) → `Route(Custom{space:"icmpv6_type", id: type})` to `ndp`; type ∈ {130,131,132,143} (MLD Query/v1-Report/Done/v2-Report) → `Route(Custom{space:"icmpv6_type", id: type})` to `mld`; else → `Terminal` |
| Identity | None — mirrors icmpv4's stance (06.3): the parent IPv6 conversation carries stats, `type`/`code` remain per-packet data |
| Note | Same v2-revisit note as icmpv4 (06.3): identity-less means no rollup on `type` today |

**ndp** (Neighbor Discovery Protocol, RFC 4861; SLAAC prefix option per RFC 4862) — IPv6's
ARP-equivalent, and given the identical "request/reply chatter, not a conversation" shape,
the identical identity stance (06.3's ARP precedent).

| Item | Spec |
|---|---|
| Claims | `Custom{space:"icmpv6_type", id: 133}` .. `id: 137` (five claims, one plugin) |
| Fields | `Structural`: `msg_type` (re-derived via cross-layer read of `icmpv6.type`, FR-17 — the plugin doesn't re-decide its own dispatch, it trusts the router's), `flags` (M/O bits on RA; solicited/override on NA), `target_address` (Bytes,16 — NS/NA/Redirect only, absent on RS/RA) · `Full`: options walk — `source_link_addr` (Bytes,6), `target_link_addr` (Bytes,6), `prefix_info` (Bytes, raw Prefix Information Option for RA/SLAAC), `router_lifetime`, `reachable_time`, `retrans_timer` (RA only) |
| Hint | `Terminal` |
| Identity | None — same stance as ARP (06.3): NS/NA is request/reply chatter over the parent IPv6 conversation, not its own stream |
| Note | Options walk strictly bounded (type+length read before advancing, same TLV discipline as 06.6's DHCP options) |

**mld** (MLDv1 RFC 2710, MLDv2 RFC 3810) — IPv6's IGMP-equivalent.

| Item | Spec |
|---|---|
| Claims | `Custom{space:"icmpv6_type", id: 130}`, `id: 131`, `id: 132`, `id: 143` |
| Fields | `Structural`: `msg_type` (cross-layer read, as `ndp`), `max_resp_delay`, `multicast_addr` (Bytes,16) · `Full`: MLDv2-report only — `num_sources`, `source_addrs` (List of Bytes,16) |
| Hint | `Terminal` |
| Identity | None — mirrors IGMP exactly (06.3: `igmp`... `Identity: None`) |

**dhcpv6** (RFC 8415) — the app-stream pattern (06.6): no endpoint identity of its own, one
child stream per UDP stream carrying it, rollups doing the stream-level work.

| Item | Spec |
|---|---|
| Claims | `UdpPort(547)`, `UdpPort(546)` |
| Fields | `Keys`: `app` (shared `KeyField`, `b: None`, constant `Str("dhcpv6")` — 06.6's pattern) · `Structural`: `msg_type` (SOLICIT/ADVERTISE/REQUEST/REPLY/RENEW/REBIND/RELEASE/...), `transaction_id` · `Full`: options walk — `client_duid` (Bytes), `server_duid` (Bytes), `requested_ip` (Bytes,16, from IA_NA/IA_TA option), `preferred_lifetime`, `valid_lifetime` |
| Hint | `Terminal` |
| Identity | key `[{app, None}]`, one `dhcpv6` child stream per UDP stream carrying it (06.6 pattern) |
| Rollups | `Series{cap:64}` on `msg_type` — the SOLICIT→ADVERTISE→REQUEST→REPLY sequence is order-sensitive, the exact DHCP DORA precedent (06.6) |

### Planned (Tier 2 — not yet specified)
| Protocol | Standard | Note |
|---|---|---|
| IPv6 extension headers as distinct layers (Hop-by-Hop, Routing, Fragment) | RFC 8200 | Currently consumed inline as part of `ipv6`'s `header_len` (06.3); splitting each into its own `LayerRecord` is a v2 ergonomics question, not a capability gap |

## Acceptance criteria
- [x] `icmpv6` fixtures for echo and each error type parse exactly and stop `Terminal`;
      type-based dispatch to `ndp`/`mld` verified for every named type via the
      `Custom{space:"icmpv6_type",...}` route.
- [ ] `ndp` fixtures: RS, RA (with SLAAC prefix option present), NS, NA (solicited and
      unsolicited/gratuitous), Redirect — each parses exact expected fields; cross-layer read
      of `icmpv6.type` verified against a synthetic plugin-order test.
- [ ] `mld` fixtures for MLDv1 Query/Report/Done and MLDv2 Report (multi-source-record case)
      parse exactly.
- [ ] `dhcpv6` fixture covers the full SOLICIT/ADVERTISE/REQUEST/REPLY sequence; `msg_type`
      series preserves order (mirrors 06.6's DORA-order criterion); one `dhcpv6` child stream
      per UDP stream verified (app-stream pattern, not a new endpoint scheme).
- [ ] Options-walk bound tests for `ndp` and `dhcpv6` (malformed length ⇒ `PluginError`, no
      loop), fuzz targets registered alongside DNS's (06.6) and DHCP's.
