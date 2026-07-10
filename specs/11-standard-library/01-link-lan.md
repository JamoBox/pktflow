# 11.1 — Link & LAN control/discovery: STP/RSTP, PVST+, LLDP, CDP, LACP, EAPOL/802.1X

> Task: [11 Standard library](README.md) · Depends on: 02–06 · PRD: FR-31 · D12, D13, D14

## Goal
The control/discovery chatter every switched LAN carries alongside data traffic: spanning
tree, neighbor discovery, link aggregation negotiation, and port-based access control. Most
of these are identity-less beacon/announcement protocols (like ARP, 06.3) rather than
conversations; LACP is the one demonstrated exception. This domain is also where destination
MAC address doubles as a routing/confidence signal — most of its protocols target a reserved
multicast address (IEEE's Bridge Group block or Cisco's control-plane block) rather than a
real device, and the spec below is deliberate about where that signal is load-bearing versus
merely corroborating (see "Destination-MAC recognition").

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
| Probe | Base signal: `dsap`/`ssap` one of the well-known values (0x42 STP, 0xAA SNAP, 0xE0 IPX, 0xF0 NetBIOS) and `control` is 0x03 (unnumbered) or a valid I/S-frame encoding → 55. **Cross-layer boost** (FR-17, reading `ctx.field("ethernet", "dst_mac")` — the parent layer's already-parsed field, exactly what cross-layer context exists for): `dst_mac` in the IEEE Bridge Group block (`01:80:C2:00:00:00`–`0F`) or the Cisco block (`01:00:0C:CC:CC:CC`/`CD`) → 90, regardless of the base DSAP signal — a reserved-multicast destination is a far stronger, standards-grounded signal than DSAP pattern-matching alone, and this is the one place in the domain where `dst_mac` is load-bearing rather than confirmatory (see the note above) |
| Expected predecessors | `expected_predecessors: ["ethernet", "dot11"]` |
| Identity | None — a demux layer, not a conversation |
| Payoff | The RFC 1042 branch means **no existing EtherType-claiming plugin needs to change** to work over LLC/SNAP-encapsulated media — notably 11.2's 802.11 data frames, which carry EAPOL (11.1's `eapol`, `EtherType(0x888E)`) and IP traffic this same way |

This is the one plugin in this domain that isn't itself a named protocol from the taxonomy;
it's infrastructure the other four need. Declared here rather than in 06 because nothing in
the fixed v1 set requires it (D6).

### Destination-MAC recognition
Most protocols in this domain are addressed to a **reserved multicast destination MAC**
rather than a real device — IEEE reserves 01:80:C2:00:00:00–0F as the "Bridge Group
Address" block (802.1D Annex, "addresses a conformant bridge must never forward"), and Cisco
separately reserves 01:00:0C:CC:CC:CC/CD for its own control-plane protocols. This is a real,
usable routing signal, and the domain should use it deliberately rather than leaving it as an
unused `dst_mac` field:

| Destination MAC | Family | Carries (this domain) |
|---|---|---|
| `01:80:C2:00:00:00` | IEEE Bridge Group | `stp` (generic 802.1D/w STP/RSTP); **also** LLDP's "nearest customer bridge" scope (see note below) |
| `01:80:C2:00:00:02` | IEEE Bridge Group ("Slow Protocols") | `lacp` (EtherType-routed already, see below) |
| `01:80:C2:00:00:03` | IEEE Bridge Group (PAE) | `eapol` (EtherType-routed already); **also** LLDP's "nearest non-TPMR bridge" scope (see note below) |
| `01:80:C2:00:00:0E` | IEEE Bridge Group (nearest bridge) | `lldp`'s default/most common scope (EtherType-routed already) |
| `01:00:0C:CC:CC:CC` | Cisco multicast | `cdp`, and (Tier 2) `vtp`, `udld`, `dtp` — same address, disambiguated by SNAP PID, **not** by destination MAC (see below) |
| `01:00:0C:CC:CC:CD` | Cisco multicast | `pvst+` (below) |

**Correction from an earlier draft, worth being explicit about:** IEEE 802.1AB actually
defines *three* possible LLDP destination addresses depending on propagation scope, not one
— `01:80:C2:00:00:0E` (nearest-bridge, the default and by far the most common), but also
`01:80:C2:00:00:03` (nearest-non-TPMR-bridge) and `01:80:C2:00:00:00` (nearest-customer-
bridge) for provider-bridge/PBB environments. The latter two are the *exact same addresses*
as `eapol`'s PAE address and `stp`'s Bridge Group Address — so the table above is not a clean
1:1 mapping the way the first draft of this spec implied. **This does not create actual
routing ambiguity in this design**, and it's worth being precise about why: `lldp` is always
`EtherType(0x88CC)`-framed (Ethernet II, never LLC), while `stp` is always 802.3-length +
LLC-DSAP-`0x42`-framed (no EtherType at all) and `eapol` is always `EtherType(0x888E)`-framed
— three structurally distinct wire shapes that are already fully disambiguated by the
EtherType-presence/DSAP signal *before* `dst_mac` is ever consulted. `dst_mac` in this
design is only ever an additive confidence booster on `llc`'s `probe()` (item 1 below), never
the sole or first disambiguator for any plugin — so the address reuse is a real fact worth
documenting (a diagnostic reading dst_mac in isolation, outside this codebase, could
misattribute a frame) but not a design defect here.

Two different roles fall out of this, and it's worth being precise about which is which
rather than treating "check the dst_mac" as one undifferentiated improvement:

1. **Load-bearing, for `llc`'s own entry.** `llc` currently reaches the router only via
   `probe()` in the fallback pool (its outer layer, `ethernet`, emits `Hint::Unknown` for
   the 802.3-length case it declines to name a route for, 06.2). A `dst_mac` match against
   the IEEE or Cisco block is a far stronger, standards-grounded signal than the DSAP/
   control-byte pattern-matching `llc`'s `probe()` used alone — this is the one place in the
   domain where using `dst_mac` materially changes confidence, not just corroborates it. See
   the updated `llc` Probe row below. **Deferred, documented rather than done:** since
   `ethertype < 0x0600` is itself a deterministic IEEE 802.3 signal (never a real EtherType,
   always LLC-framed), `ethernet` (06.2) could in principle emit an explicit `Route` there
   instead of `Unknown`, promoting `llc` to the explicit tier entirely. Left as `Unknown` for
   now — that would mean editing an already-specified/built task-06 file, out of scope for
   this purely-additive task unless a later PR decides it's worth it.
2. **Confirmatory only, for everything already explicitly routed — and correctly absent from
   `Claims`, not just deprioritized.** `lldp`/`eapol`/`lacp` already route deterministically
   via `EtherType` (the explicit tier, PRD §4.B.3); `stp`/`cdp` already route deterministically
   via `llc`'s DSAP/SNAP-PID `Custom` routes. `dst_mac` genuinely cannot appear in any of
   their `Claims` rows, for a structural reason, not a style choice: `RouteId` is
   single-dimension per space (03.1 — `EtherType(u16)`, `Custom{space,id}`, ... one payload
   each), and the *outer* layer (`ethernet`, 06.2) is what decides which `RouteId` gets looked
   up — its `Hint::Route(EtherType(ethertype))` never inspects `dst_mac` at all. A `Custom`
   dst-mac-keyed claim on `eapol` would be unreachable dead code (the same reasoning that kept
   `rtp` from getting a pointless `probe()`, 11.10/D15), not a weaker version of routing —
   `llc` is different only because *it* has no `Claims` at all and reaches the router purely
   through `probe()`, where `dst_mac` genuinely can move the needle.

   `dst_mac` still has a real, but strictly diagnostic, role here: a mismatch is *sometimes*
   worth surfacing, but the exact expectation differs per protocol, and it's worth being
   precise rather than treating all three alike. `lacp` (802.3 Clause 43) and `lldp`'s three
   scopes (802.1AB) are always sent to a fixed group address with no standard unicast
   alternative — a non-matching `dst_mac` there is a clean anomaly signal. `eapol` is
   different: IEEE 802.1X explicitly permits **either** the PAE group address **or** a
   unicast destination (the peer's individual MAC) — supplicant-initiated frames typically use
   the group address, but authenticator *responses* commonly use the supplicant's unicast MAC.
   So "non-PAE `dst_mac`" is **not**, by itself, anomalous for `eapol` the way it would be for
   `lacp`/`lldp` — any future consistency-check feature would need to know that distinction,
   not treat all three uniformly. **Not** modeled as a new per-plugin field in v1 either way
   (would mean adding the same boilerplate to three plugins, with different correct behavior
   for one of them, for a diagnostic nicety); flagged as a natural `pktflow unknown`-adjacent
   (task 10) enhancement — cross-layer consistency checking — if it's ever wanted, not a gap
   in this task.
3. **Honest counterexample, so the table above isn't read as "dst_mac always disambiguates":**
   within the Cisco block, `cdp`/`vtp`/`udld`/`dtp` (and PAgP, not currently in this domain's
   taxonomy at all — see below) all share the *same* destination address
   (`01:00:0C:CC:CC:CC`) — SNAP PID is what actually tells them apart (already how `cdp`'s
   `Custom{space:"snap_pid",...}` claim works). `dst_mac` there narrows "this is Cisco
   control-plane traffic" but does no finer-grained work.

**A genuinely new protocol this makes worth adding**, not just a robustness note — see
`pvst+` below, which *is* cleanly separated from `cdp`/`vtp`/`udld` by destination MAC (a
different Cisco reserved address, `...CD` not `...CC`), on top of its own SNAP PID.

**stp** (STP/RSTP BPDUs) — IEEE 802.1D-2004 (RSTP folded in; MSTP is Tier 2, see below).

| Item | Spec |
|---|---|
| Claims | `Custom{space:"llc_dsap", id:0x42}` |
| Fields | `Structural`: `protocol_id`, `version` (0=STP,2=RSTP), `bpdu_type`, `flags`, `root_id` (Bytes, 8: priority+MAC), `bridge_id` (Bytes, 8) · `Full`: `root_path_cost`, `port_id`, `message_age`, `max_age`, `hello_time`, `forward_delay` |
| Hint | `Terminal` |
| Identity | None — a periodic multicast beacon to the fixed bridge-group address (01:80:C2:00:00:00), not a two-party conversation (same stance as ARP, 06.3) |
| Rollups | none (identity-less; the parent MAC conversation carries packet/byte stats) |

**pvst+** (Cisco Per-VLAN Spanning Tree Plus) — *no open standard*; Cisco's published PVST+
reference is the closest authoritative document. Arguably more common in real Cisco-switched
enterprise networks than generic 802.1D STP, since PVST+ is Cisco's long-standing default —
a genuinely missing gap this destination-MAC review surfaced, not originally in the taxonomy
proposal.

| Item | Spec |
|---|---|
| Claims | `Custom{space:"snap_pid", id: (0x00000C << 16) \| 0x010B}` (OUI 00-00-0C, PID 0x010B) — fully disambiguated from `cdp`/`vtp`/`udld` by SNAP PID alone (all under the same OUI); destination MAC `01:00:0C:CC:CC:CD` (distinct from their `...CC`) is a corroborating, not load-bearing, signal here |
| Fields | Same shape as `stp` (one instance runs per VLAN, so the fields are a per-VLAN 802.1D BPDU) — `Structural`: `protocol_id`, `version`, `bpdu_type`, `flags`, `root_id`, `bridge_id` · `Full`: `root_path_cost`, `port_id`, `message_age`, `max_age`, `hello_time`, `forward_delay`, plus Cisco's appended `originating_vlan` (U64, from the trailing TLV PVST+ adds after the standard BPDU fields) |
| Hint | `Terminal` |
| Identity | None — same stance as `stp` |

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
| UDLD | RFC 5171 (informational, Cisco) | Unidirectional link detection — SNAP PID 0x0111, same `01:00:0C:CC:CC:CC` destination as `cdp`/`vtp`/`dtp` |
| VTP | *No open standard* (Cisco) | VLAN trunking protocol — SNAP PID 0x2003, same `01:00:0C:CC:CC:CC` destination as `cdp`/`udld`/`dtp` |
| DTP | *No open standard* (Cisco) | Dynamic Trunking Protocol — automatic trunk negotiation; same `01:00:0C:CC:CC:CC` destination as `cdp`/`vtp`/`udld`, own SNAP PID |
| PAgP | *No open standard* (Cisco) | Port Aggregation Protocol — Cisco's pre-standard LACP equivalent; same `01:00:0C:CC:CC:CC` destination, own SNAP PID |
| LACP Marker protocol | IEEE 802.3-2018 Clause 43 | Slow Protocols subtype 0x02 |

## Acceptance criteria
- [x] `llc` real-frame fixtures (STP-carrying and CDP-carrying) route to `stp`/`cdp`
      correctly via both `llc_dsap` and `snap_pid` `Custom` spaces; a non-LLC 802.3-length
      frame (bad dsap/ssap) declines from the fallback pool rather than mis-routing.
- [x] `llc` probe cross-layer boost: a fixture with a reserved `dst_mac` (either block) but a
      slightly atypical DSAP/control byte still wins the fallback pool (90 beats other
      candidates' base-signal scores); a fixture with a well-formed DSAP/control pattern but
      an *unreserved* `dst_mac` still gets in via the base 55 score — the boost is additive
      confidence, not a hard requirement, tested as both cases independently.
- [x] `stp`, `pvst+`, `cdp`, `lldp` fixtures parse to exact expected fields; each contributes
      stats to its parent MAC conversation with no stream of its own (identity-less pattern
      verified, matching 06.3's ARP precedent). `pvst+` fixture specifically verifies
      `originating_vlan` and correct disambiguation from generic `stp` via SNAP PID.
- [x] `lacp` fixture: negotiation stream forms keyed on `(actor_system, partner_system)`,
      folds both directions, `actor_state` accumulate populated across a multi-PDU exchange.
- [x] `eapol` fixture covers all named `packet_type`s; the `Key` body fields parse exactly on
      a real 4-way-handshake message 1 capture; a non-Key EAPOL frame emits none of the Key
      fields (depth/conditional-field discipline, same as DNS query-vs-response, 06.6).
- [x] TLV-walk bound tests for `cdp` and `lldp` (malformed/oversized length ⇒ clean
      `PluginError`, no loop) registered alongside a fuzz target.
