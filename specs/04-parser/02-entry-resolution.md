# 04.2 — Entry resolution

> Task: [04 Parser](README.md) · Depends on: 04.1 · PRD: FR-13 "known entry protocol or heuristic first-layer identification"

## Goal
Choose the first plugin for a packet: normally dictated by the capture's link type, with
heuristic identification as the explicit opt-in for headerless/raw inputs.

## Specification

Entry precedence for the first layer:

1. **Forced entry** — `ParseOpts.entry: Option<ProtocolName>`; caller says "these bytes
   start at ipv4" (tooling, tests, tunnel re-entry). Dispatch by name; unknown name is a
   build-style error at call time, not a stop.
2. **Link-type route** — `RouteId::LinkType(meta.link_type)` looked up like any explicit
   route. Ethernet plugin claims `LinkType(1 /* DLT_EN10MB */)`; a raw-IP capture
   (`DLT_RAW`) can be claimed by an ipv4/ipv6 demux shim or by claims on both.
3. **Heuristic first layer** — only if `ParseOpts.allow_entry_heuristics: bool` (default
   **false**) and no link-type route exists: run the 03.3 scoring on the whole packet with
   no predecessor prior. Default-off keeps the gate philosophy: an unclaimed link type is a
   configuration gap the user should see (`StopReason::UnclaimedRoute(LinkType(n))`), not
   silently guess around.

Notes:

- The entry is the one place heuristics may run without a preceding `Hint::Unknown`
  (consistent with 03.3's two permitted situations).
- `DLT` numbering is pcap's; `pktflow-core` treats it as an opaque u16 space — the mapping
  from pcap's datalink enum to `LinkType` lives in `pktflow-capture` (07.1) to keep core
  pcap-free.

## Acceptance criteria
- [ ] All three precedence tiers implemented and unit-tested, including precedence order
      (forced entry beats an existing link-type route).
- [ ] Unclaimed link type with heuristics off ⇒ zero layers, `UnclaimedRoute(LinkType(n))`.
- [ ] Raw-IP fixture (`DLT_RAW` with an IPv4 packet) parses via entry heuristics when
      enabled: ipv4's probe (version nibble + header checksum) wins.
