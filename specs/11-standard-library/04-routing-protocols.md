# 11.4 — Routing protocols: BGP-4, OSPFv2/v3, VRRP, HSRP

> Task: [11 Standard library](README.md) · Depends on: 02–06 · PRD: FR-31 · D12, D13, D14

## Goal
The Internet's and the enterprise/DC edge's control plane. Two identity shapes show up:
BGP's long-lived TCP peering (app-stream pattern, 06.6) and VRRP/HSRP's multicast
group-redundancy beacon (a shared-qualifier key, the same pattern GRE/VXLAN use for a tunnel
key/VNI, 06.5 — worth naming here as the **group-beacon pattern**: one stream per group id,
not per pair of endpoints).

## Specification

**bgp** (RFC 4271) — app-stream pattern (06.6): BGP's real identity *is* its TCP session; a
child stream just carries protocol-specific rollups.

| Item | Spec |
|---|---|
| Claims | `TcpPort(179)` |
| Fields | `Keys`: `app` (shared `KeyField`, `b: None`, constant `Str("bgp")`) · `Structural`: `msg_type` (OPEN/UPDATE/NOTIFICATION/KEEPALIVE/ROUTE-REFRESH), `length` · `Full`: OPEN → `my_as` (U64), `hold_time`, `bgp_identifier` (Bytes,4); UPDATE → `withdrawn_routes` (List of Bytes, prefixes), `nlri` (List of Bytes, prefixes), `next_hop` (Bytes, from the MP/NLRI or classic path attribute) |
| Hint | `Terminal` — only the first BGP message in a segment is parsed (D7, same stance as DNS-over-TCP, 06.6); a segment carrying a coalesced second message stops cleanly rather than walking further |
| Identity | key `[{app, None}]`, one `bgp` child stream per TCP session carrying it |
| Rollups | `Accumulate` on `msg_type`; `Sample` on `my_as` (peer AS, first/last — a session renegotiating AS numbers mid-stream is itself interesting and `Sample` surfaces it) |

**ospf** (OSPFv2 RFC 2328, OSPFv3 RFC 5340 — one plugin, `version` field disambiguates).

| Item | Spec |
|---|---|
| Claims | `IpProtocol(89)` |
| Fields | `Structural`: `version` (2 or 3), `type` (Hello/DBD/LSR/LSU/LSAck), `packet_length`, `router_id` (Bytes,4), `area_id` (Bytes,4) · `Full`: type-specific — Hello: `hello_interval`, `router_dead_interval`, `designated_router` (Bytes,4), `neighbors` (List of Bytes); DBD: `interface_mtu`, `dd_sequence`; LSU: `lsa_headers` (List of Bytes, summarized: type+LS-id+advertising-router per entry) |
| Hint | `Terminal` |
| Identity | None. Hello is periodic multicast to `224.0.0.5`/`ff02::5` — the same "beacon, not a conversation" shape as STP (11.1), not the group-beacon shape below, because there is no single group id shared by all speakers on a segment the way a VRID or HSRP group number is. *Unicast* DBD/LSR/LSU exchanges between two adjacency-forming routers are a real point-to-point conversation in principle (keyable on the two `router_id`s); deferred as a v2 refinement rather than specified now, so the plugin doesn't declare a key it only sometimes means |

**vrrp** (RFC 5798 VRRPv3, RFC 3768 VRRPv2) — group-beacon pattern.

| Item | Spec |
|---|---|
| Claims | `IpProtocol(112)` |
| Fields | `Keys`: `vrid` (U64) · `Structural`: `version`, `type`, `priority`, `count_ip_addrs`, `adver_int` · `Full`: `ip_addresses` (List of Bytes — the virtual IP(s) being advertised) |
| Hint | `Terminal` |
| Identity | key `[{vrid, None}]` (shared qualifier, `b: None` — same shape as GRE's `key`/VXLAN's `vni`, 06.5) → one **VRRP group** stream per virtual router id, aggregating every speaker's advertisements for that group regardless of which physical router currently holds master |
| Rollups | `Accumulate` on `priority` (surfaces master/backup priority changes over the group's lifetime — the analytic point of watching VRRP at all) |

**hsrp** (RFC 2281, informational — Cisco's pre-standard equivalent of VRRP).

| Item | Spec |
|---|---|
| Claims | `UdpPort(1985)` |
| Fields | `Keys`: `group` (U64) · `Structural`: `version`, `opcode` (Hello/Coup/Resign), `state` (Speak/Standby/Active/...), `priority`, `hellotime`, `holdtime` · `Full`: `virtual_ip` (Bytes,4), `auth_data` (Bytes,8 — sent in the clear by the protocol itself, not a pktflow limitation) |
| Hint | `Terminal` |
| Identity | key `[{group, None}]`, the same group-beacon pattern as `vrrp` |
| Rollups | `Accumulate` on `state`; `Accumulate` on `priority` |

### Planned (Tier 2 — not yet specified)
| Protocol | Standard | Note |
|---|---|---|
| IS-IS | ISO/IEC 10589; RFC 1195 (IP integration) | Runs directly on the link layer (OSI CLNS), not on IP — a genuinely different entry point than every other protocol in this domain |
| EIGRP | RFC 7868 (informational, Cisco) | `IpProtocol(88)` |
| RIP / RIPng | RFC 2453 (v2), RFC 2080 (ng) | `UdpPort(520)` / `UdpPort(521)` |
| PIM-SM | RFC 7761 | `IpProtocol(103)` |

## Acceptance criteria
- [ ] `bgp` fixtures for OPEN, UPDATE (with withdrawn + NLRI prefixes), KEEPALIVE parse
      exactly; app-stream child forms under the TCP session (mirrors 06.6's DNS-under-UDP
      criterion, ported to TCP).
- [ ] `ospf` fixtures for OSPFv2 and OSPFv3 Hello and DBD parse exactly, including the
      version-dependent field layout; multicast Hello contributes to its parent IP
      conversation with no OSPF stream of its own (identity-less, verified).
- [x] `vrrp` and `hsrp` fixtures: a real master-election sequence (priority/state changes
      across several advertisements) folds into one group stream per `vrid`/`group`; two
      different groups on the same LAN segment produce two independent streams (shared-key
      uniqueness verified, same test shape as 06.5's two-VNIs-one-outer-stream case).
- [ ] Type-specific body walks (`ospf` LSU list, `bgp` UPDATE path attributes) have
      truncation tests at their internal length boundaries.
