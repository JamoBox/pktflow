# Task 11 — Standard plugin library

**Goal:** the "batteries included" standard library (FR-31): broad protocol coverage across
home, enterprise, data-center, private, and internet-facing networks, built on the exact same
`LayerPlugin` contract as task 06 — one file per protocol in `pktflow-plugins`, registered in
`default_engine()`, nothing added to the engine itself. Task 06 remains the fixed, minimal
set that proves the contract (D6); this task is the breadth layer on top of it.

**Depends on:** 02–06. **Blocks:** nothing directly (08/10 already consume whatever's in
`default_engine()`, so plugins land incrementally as each sub-task ships).
**PRD:** FR-31 · D12, D13, D14 (and D6's superseding note).

## Sub-tasks

Each is one functional domain. Every domain file specifies its **Tier 1** protocols in full
(Goal/Specification/Acceptance-criteria) and lists its **Tier 2** protocols in a "Planned"
stub table (name + standard + one-line rationale, not yet implementable per Article I — see
D13).

- [x] [11.1 Link & LAN control/discovery](01-link-lan.md) — STP/RSTP, PVST+, LLDP, CDP, LACP, EAPOL/802.1X
- [x] [11.2 Wireless link (802.11)](02-wireless-link.md) — 802.11 frame + radiotap, WPA2/3 handshake
- [x] [11.3 IPv6 control plane](03-ipv6-control-plane.md) — ICMPv6, NDP, MLDv1/v2, DHCPv6
- [x] [11.4 Routing protocols](04-routing-protocols.md) — BGP-4, OSPFv2/v3, VRRP, HSRP
- [x] [11.5 Tunnels, overlays & VPN](05-tunnels-overlays-vpn.md) — IPsec ESP/AH, WireGuard, L2TPv3, PPPoE, Geneve
- [x] [11.6 Transport extensions](06-transport-extensions.md) — SCTP, QUIC (invariants)
- [ ] [11.7 Security, auth & directory](07-security-auth-directory.md) — TLS, SSH, RADIUS, Kerberos, LDAP
- [ ] [11.8 Web & RPC](08-web-rpc.md) — HTTP/1.1, HTTP/2, WebSocket, STUN, TURN
- [ ] [11.9 File & mail transfer](09-file-mail-transfer.md) — FTP, TFTP, SMTP, IMAP, POP3, SMB2/3, NFS
- [ ] [11.10 Voice, video & real-time](10-voice-video-realtime.md) — SIP, RTP, RTCP
- [x] [11.11 Network management & telemetry](11-network-management-telemetry.md) — SNMP, Syslog, NetFlow v9, IPFIX
- [ ] [11.12 Service & name discovery](12-service-name-discovery.md) — mDNS, SSDP, LLMNR, NetBIOS-NS
- [x] [11.13 Industrial/OT (ICS-SCADA)](13-industrial-ot.md) — Modbus/TCP, DNP3, EtherNet/IP (CIP), BACnet/IP
- [ ] [11.14 Data-center & app messaging](14-datacenter-app-messaging.md) — MQTT, AMQP 0-9-1, Redis (RESP)
- [ ] [11.15 Telco/cellular core](15-telco-cellular-core.md) — GTPv1-U, GTPv1-C, GTPv2-C

## Conventions (all plugins in this task)

Everything task 06's README already states still applies unchanged: one file per protocol
(`crates/pktflow-plugins/src/<name>.rs`), field-name constants at the top, registration only
in `default_engine()`, depth gating (`Keys`/`Structural`/`Full` — 01.3), real-world byte
fixtures plus truncation tests, flow-key tests through the 09.1 kit where identity is
declared. Additions specific to this task:

- **Standard citation (D14).** Every protocol's spec entry names its governing document
  (RFC/IEEE/3GPP/IANA/etc., or explicitly "no open standard" plus the closest authoritative
  doc) next to the protocol name. This is a spec-file requirement; it doesn't change the
  plugin's Rust surface, but a doc comment pointing at the same citation is expected practice.
- **Encrypted/opaque protocols (D12).** Where a protocol encrypts its payload, the plugin
  parses only the plaintext handshake/header fields the protocol itself exposes, then
  declines normally (ordinary `ParseError`/`PluginError`, no new stop-reason kind) on the
  opaque remainder. This is a field-extraction ceiling, not a different contract.
- **Tiering (D13).** A domain file's Tier 1 entries are real specs, reviewable and
  implementable today. Its Tier 2 table is inventory, not a promise — Article I blocks
  building from a stub row until it's promoted to a full entry in a later PR.
- **Claim-space honesty.** Several Tier-1 protocols in this task have no fixed well-known
  port/ethertype (e.g. RTP/RTCP, negotiated via out-of-band signaling) or share a contested
  one (h2c HTTP/2 vs. HTTP/1.1 on port 80). Where a static `claims()` can't be written
  honestly, the domain spec says so and documents the fallback (probe-based heuristic
  admission to the fallback pool, or an explicit v2 limitation) rather than squatting a route
  the plugin can't actually promise.
- **Multi-packet protocols.** Per D7, no cross-packet reassembly. Several protocols here
  (HTTP bodies, WebSocket after the upgrade handshake, TFTP transfers, FTP data channels) are
  visible only at their control/header boundary in v1 — each spec says exactly where
  dissection stops and why, the same honesty as 06.6's DNS-over-TCP note.

## Definition of done

Every Tier-1 sub-task's acceptance criteria pass (fixture tests, truncation tests, 09.1 kit
where identity is declared) and `default_engine()` registers every Tier-1 plugin with no
route/name collisions. Tier-2 tables remain accurate inventory (protocol + standard +
rationale) even though unbuilt — a domain file is not "done" by having an empty or stale
Tier-2 table, it's done by its Tier-1 checklist being fully checked and its Tier-2 table
still matching the agreed taxonomy.
