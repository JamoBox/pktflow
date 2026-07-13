# Task 12 — Contrib plugin library (`pktflow-contrib`)

**Goal:** the optional, batteries-not-required extension crate (FR-32): the long tail of
protocol coverage that is real and common in the wild — Wireshark dissects all of it — but
too vertical, vendor-specific, legacy, or niche to earn a place in the standard library's
default engine. Everything here is built on the exact same `LayerPlugin` contract as tasks
06 and 11: one file per protocol, registered in exactly one list, same fixture/truncation/
identity test bar. The only thing that changes is *where it lives and when it's compiled in*
— a separate `pktflow-contrib` crate, opt-in per consumer, feature-gated per domain (D16).

**Depends on:** 02–06 (contract, router, parser, aggregator, reference plugins).
Cross-references task 11 where zero-touch reuse of a stdlib plugin is claimed
(e.g. `ipsec_natt ▸ esp`, `netbios_ssn ▸ smb2`) — those entries light up when the 11.x
plugin lands; until then they stop honestly as `UnclaimedRoute` (D9). **Blocks:** nothing.
**PRD:** FR-32 · D12, D13, D14, D15, D16.

## Sub-tasks

12.1 is the crate itself — it must land first; every other sub-task is an independent
protocol domain (buildable in any order once 12.1 exists, same as 11's domains). Every
domain file specifies its **Tier 1** protocols in full (Goal/Specification/Acceptance
criteria) and lists its **Tier 2** protocols in a "Planned" stub table (D13 applies to this
task unchanged).

- [ ] [12.1 Crate, features & registration](01-crate-and-registration.md) — `pktflow-contrib`, per-domain cargo features, `register()`, collision guarantee, CLI opt-in
- [ ] [12.2 Capture-entry, tunnels & encapsulation flavours](02-encap-flavours.md) — Linux SLL/SLL2, ERSPAN, PPTP, IPsec NAT-T (ESP-in-UDP)
- [ ] [12.3 Network ops, SDN & timing](03-netops-sdn-timing.md) — OpenFlow, PTP (IEEE 1588), BFD, Wake-on-LAN
- [ ] [12.4 Security & auth flavours](04-security-flavours.md) — DTLS, MACsec
- [ ] [12.5 Legacy LAN suites](05-legacy-lan.md) — IPX, NetBIOS Session Service, NetBIOS Datagram Service
- [ ] [12.6 Remote access & desktop](06-remote-access.md) — Telnet, RFB/VNC, RDP, X11
- [ ] [12.7 Databases & datastores](07-databases.md) — MySQL, PostgreSQL, TDS (MS SQL Server), MongoDB
- [ ] [12.8 Messaging & IoT](08-messaging-iot.md) — CoAP, XMPP, IRC, NATS, STOMP
- [ ] [12.9 Media, streaming & P2P](09-media-p2p.md) — RTMP, BitTorrent peer wire, BitTorrent DHT
- [ ] [12.10 Storage & SAN](10-storage-san.md) — iSCSI, NBD
- [ ] [12.11 Enterprise services & printing](11-enterprise-printing.md) — IPP, LPD, Git pack protocol
- [ ] [12.12 VoIP & telephony flavours](12-voip-flavours.md) — MGCP, IAX2
- [ ] [12.13 Industrial & building automation flavours](13-industrial-flavours.md) — PROFINET (DCP/RT), EtherCAT, IEC 61850 GOOSE, KNXnet/IP

## Conventions (all plugins in this task)

Everything task 11's README states applies unchanged — one file per protocol
(`crates/pktflow-contrib/src/<name>.rs`), field-name constants at the top, depth gating
(`Keys`/`Structural`/`Full`), real-world byte fixtures plus truncation tests, flow-key tests
through the 09.1 kit where identity is declared, standard citations (D14), the encryption
ceiling (D12), tiering (D13), claim-space honesty, the D15 negotiated-port stance, and the
no-cross-packet-reassembly boundary (D7). Additions specific to this task:

- **Placement rule (D16).** A protocol named anywhere in task 11 — Tier 1 *or* Tier 2 —
  belongs to task 11 and is promoted there, never re-specified here. This task's inventory
  is disjoint by construction; a new protocol proposal decides its home by D16's rule
  (near-universal/high analytic value → 11; everything else worth shipping → here).
- **Claim precedence (D16).** A contrib plugin never claims a `RouteId` the standard library
  claims (statically, in any 06/11 spec — built or not). Contested wants go through
  probe-based fallback admission or are documented as a limitation. The combined-engine
  collision test in 12.1 enforces the built subset mechanically; the spec review enforces
  the not-yet-built subset.
- **Zero-touch on other crates.** A contrib protocol PR touches `crates/pktflow-contrib`
  plus its own spec entry, nothing else. Where an entry composes with a stdlib plugin it
  does so by name (`Hint::ByProtocol`) or by claiming a route the stdlib already emits
  (e.g. `llc`'s `Custom{space:"llc_dsap", id:0xE0}` for IPX) — never by editing the stdlib
  plugin. If a stdlib change is genuinely required, that's a task-06/11 spec change first.
- **One domain feature per plugin.** Every plugin belongs to exactly one cargo feature
  (12.1's table); its `mod` declaration and registration line are gated together, so any
  feature subset compiles and registers a consistent engine.

## Definition of done

12.1's acceptance criteria pass (crate builds, feature matrix holds, combined engine is
collision-free, CLI opt-in proven end-to-end), every domain sub-task's Tier-1 acceptance
criteria pass, and `register()` registers every built Tier-1 plugin with no route/name
collisions against `default_engine()`. Tier-2 tables remain accurate inventory (protocol +
standard + rationale), same as task 11's bar: a domain file is done when its Tier-1
checklist is fully checked and its Tier-2 table still matches the agreed taxonomy.
