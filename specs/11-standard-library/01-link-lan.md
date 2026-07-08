# 11.1 — Link & LAN control/discovery: STP/RSTP, LLDP, CDP, LACP, EAPOL/802.1X

> Task: [11 Standard library](README.md) · Depends on: 02–06 · PRD: FR-31 · D12, D13, D14

## Goal
The control/discovery chatter every switched LAN carries alongside data traffic: spanning
tree, neighbor discovery, link aggregation negotiation, and port-based access control. Most
of these are identity-less beacon/announcement protocols (like ARP, 06.3) rather than
conversations; LACP is the one demonstrated exception.

## Specification

### Prerequisite: `llc` (802.2 LLC + SNAP)
**Standard:** IEEE 802.2-1998 (LLC); SNAP extension per IEEE 802 / RFC 1042.

STP and CDP predate EtherType-based demultiplexing and are carried in classic 802.3 LLC
frames (Ethernet II's `ethertype` field repurposed as a length, so 06.2's ethernet plugin
correctly emits `Hint::Unknown` for these — the 802.3-length case it explicitly declines to
guess about). Routing them requires an `llc` plugin in the heuristic fallback pool:

| Item | Spec |
|---|---|
| Claims | none (see Probe) |
| Fields | `Structural`: `dsap`, `ssap`, `control` · `Full`: `oui` (present only if SNAP: dsap=ssap=0xAA), `pid` |
| Hint | SNAP with OUI `0x000000` (RFC 1042 encapsulation — the PID *is* an EtherType) → `Route(EtherType(pid))`, reusing the real EtherType space exactly like GRE reuses it (06.5); SNAP with any other OUI → `Route(Custom{space:"snap_pid", id: (oui<<16)\|pid})`; non-SNAP → `Route(Custom{space:"llc_dsap", id: dsap})` |
| Probe | `dsap`/`ssap` one of the well-known values (0x42 STP, 0xAA SNAP, 0xE0 IPX, 0xF0 NetBIOS) and `control` is 0x03 (unnumbered) or a valid I/S-frame encoding → 55; `expected_predecessors: ["ethernet", "dot11"]` |
| Identity | None — a demux layer, not a conversation |
| Payoff | The RFC 1042 branch means **no existing EtherType-claiming plugin needs to change** to work over LLC/SNAP-encapsulated media — notably 11.2's 802.11 data frames, which carry EAPOL (11.1's `eapol`, `EtherType(0x888E)`) and IP traffic this same way |

This is the one plugin in this domain that isn't itself a named protocol from the taxonomy;
it's infrastructure the other four need. Declared here rather than in 06 because nothing in
the fixed v1 set requires it (D6).

**stp** (STP/RSTP BPDUs) — IEEE 802.1D-2004 (RSTP folded in; MSTP is Tier 2, see below).

| Item | Spec |
|---|---|
| Claims | `Custom{space:"llc_dsap", id:0x42}` |
| Fields | `Structural`: `protocol_id`, `version` (0=STP,2=RSTP), `bpdu_type`, `flags`, `root_id` (Bytes, 8: priority+MAC), `bridge_id` (Bytes, 8) · `Full`: `root_path_cost`, `port_id`, `message_age`, `max_age`, `hello_time`, `forward_delay` |
| Hint | `Terminal` |
| Identity | None — a periodic multicast beacon to the fixed bridge-group address (01:80:C2:00:00:00), not a two-party conversation (same stance as ARP, 06.3) |
| Rollups | none (identity-less; the parent MAC conversation carries packet/byte stats) |

**cdp** — *no open standard*; Cisco's published CDP protocol reference is the closest
authoritative document.

| Item | Spec |
|---|---|
| Claims | `Custom{space:"snap_pid", id: (0x00000C << 16) \| 0x2000}` (OUI 00-00-0C, PID 0x2000) |
| Fields | `Structural`: `version`, `ttl`, `checksum` · `Full`: TLV walk — `device_id` (Str), `port_id` (Str), `platform` (Str), `capabilities` (U64 bitmask), `native_vlan` (U64), `ip_address` (Bytes, first address TLV entry) |
| Hint | `Terminal` |
| Identity | None (neighbor announcement) |
| Note | TLV walk strictly bounded (type+length read before advancing; malformed length ⇒ `PluginError`, never an infinite/overrun loop) — same discipline as DHCP's option walk (06.6) |

**lldp** — IEEE 802.1AB-2016.

| Item | Spec |
|---|---|
| Claims | `EtherType(0x88CC)` |
| Fields | `Structural`: `chassis_id_subtype`, `chassis_id` (Bytes), `port_id_subtype`, `port_id` (Bytes), `ttl` · `Full`: `system_name` (Str), `system_description` (Str), `management_address` (Bytes), `capabilities` (U64) |
| Hint | `Terminal` |
| Identity | None (neighbor announcement, same stance as CDP) |
| Note | TLV walk bounded on the mandatory-TLV-order + End-of-LLDPDU sentinel; unknown optional TLVs skipped by their own length field |

**lacp** — IEEE 802.3-2018 Clause 43 (formerly 802.3ad). Slow Protocols EtherType, subtype 1.

| Item | Spec |
|---|---|
| Claims | `EtherType(0x8809)` **and** first byte (subtype) `== 0x01`; a non-LACP Slow Protocol subtype (e.g. 0x02 Marker) is a decline, not a route miss — see Tier 2 |
| Fields | `Keys`: `actor_system` (Bytes,6), `partner_system` (Bytes,6) · `Structural`: `actor_key`, `actor_port`, `actor_state` (U64 bitmask), `partner_key`, `partner_port`, `partner_state` · `Full`: padding-region ignored |
| Hint | `Terminal` |
| Identity | key `[{actor_system, partner_system}]`, `EndpointSort` → **LACP negotiation** stream — the one identity-bearing protocol in this domain, showing the flow-key pattern applies to control-plane negotiation, not just transport sessions |
| Rollups | `Accumulate` on `actor_state` (aggregation/synchronization/collecting/distributing flag combinations observed over the negotiation) |

**eapol** — IEEE 802.1X-2020 (framing); RFC 3748 (EAP, inner method chain out of scope — see
note).

| Item | Spec |
|---|---|
| Claims | `EtherType(0x888E)` |
| Fields | `Structural`: `version`, `packet_type` (EAP-Packet/Start/Logoff/Key/...), `body_length` · `Full` (only when `packet_type == Key`): `key_descriptor_type`, `key_info` (U64 bitmask: install/ack/mic/secure/error), `key_length`, `replay_counter`, `nonce` (Bytes,32), `key_iv`, `key_rsc`, `key_mic` (Bytes), `key_data_length` |
| Hint | `Terminal` — an EAP-Packet's inner EAP method (MD5/TLS/PEAP/...) is a further TLV chain this plugin does not walk (multi-round-trip state machine, out of v1 scope, D7-adjacent) |
| Identity | None — per-port link-local signaling |
| Cross-domain | The `packet_type == Key` fields are exactly what 11.2's WPA2/WPA3 handshake entry reads when EAPOL-Key rides over an 802.11 frame instead of Ethernet |

### Planned (Tier 2 — not yet specified)
| Protocol | Standard | Note |
|---|---|---|
| MSTP | IEEE 802.1Q-2018 | Multiple Spanning Tree — `stp` plugin's `version == 3` case, region/instance TLVs unparsed in v1 |
| UDLD | *No open standard* (Cisco) | Unidirectional link detection |
| VTP | *No open standard* (Cisco) | VLAN trunking protocol |
| LACP Marker protocol | IEEE 802.3-2018 Clause 43 | Slow Protocols subtype 0x02 |

## Acceptance criteria
- [ ] `llc` real-frame fixtures (STP-carrying and CDP-carrying) route to `stp`/`cdp`
      correctly via both `llc_dsap` and `snap_pid` `Custom` spaces; a non-LLC 802.3-length
      frame (bad dsap/ssap) declines from the fallback pool rather than mis-routing.
- [ ] `stp`, `cdp`, `lldp` fixtures parse to exact expected fields; each contributes stats
      to its parent MAC conversation with no stream of its own (identity-less pattern
      verified, matching 06.3's ARP precedent).
- [ ] `lacp` fixture: negotiation stream forms keyed on `(actor_system, partner_system)`,
      folds both directions, `actor_state` accumulate populated across a multi-PDU exchange.
- [ ] `eapol` fixture covers all named `packet_type`s; the `Key` body fields parse exactly on
      a real 4-way-handshake message 1 capture; a non-Key EAPOL frame emits none of the Key
      fields (depth/conditional-field discipline, same as DNS query-vs-response, 06.6).
- [ ] TLV-walk bound tests for `cdp` and `lldp` (malformed/oversized length ⇒ clean
      `PluginError`, no loop) registered alongside a fuzz target.
