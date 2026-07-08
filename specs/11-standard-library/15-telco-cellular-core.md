# 11.15 — Telco/cellular core: GTP-U, GTP-C (v1/v2)

> Task: [11 Standard library](README.md) · Depends on: 02–06 · PRD: FR-31 · D13, D14

## Goal
Mobile-core tunneling — pulled into its own domain (rather than folded into 11.5's general
tunnels) because it's a genuinely distinct deployment context (mobile network operator core/
roaming interconnect), governed by 3GPP rather than IETF/IEEE, and because GTP-C's two wire
versions collapse into one plugin the same way `ospf` and `stun` already do in this task —
worth landing as a single coherent domain rather than scattered across others.

**Refinement from the original taxonomy proposal**: GTPv1-C (3GPP TS 29.060) and GTPv2-C
(3GPP TS 29.274) share `UdpPort(2123)` and can't both claim it (route collision, 03.2), so
they're one plugin (`gtp_c`) disambiguated by the version bits in the header's flags byte —
not two, as the original three-row taxonomy sketch implied. GTP-U has no "v2" (the 3GPP user
plane stayed on GTPv1-U, TS 29.281, even after the control plane moved to v2), so it remains
its own plugin (`gtp_u`) on its own port.

## Specification

**gtp_u** (3GPP TS 29.281).

| Item | Spec |
|---|---|
| Claims | `UdpPort(2152)` |
| Fields | `Keys`: `teid` (U64) · `Structural`: `message_type` (255=G-PDU/1=Echo-Request/2=Echo-Response/26=Error-Indication/31=End-Marker), `flags`, `length` · `Full`: `sequence_number` (present per the flags' E/S/PN bits) |
| Hint | `message_type == 255` (G-PDU — the actual encapsulated subscriber traffic) → `Unknown`. GTP-U's header names no explicit next-protocol field for its payload (it's always IP, but never says *which* version) — `Hint::Unknown` is the contract-correct choice here (02.2: "header named nothing usable"), not a plugin declining to be more specific. This works with **zero new code** in `ipv4`/`ipv6` (06.3): both already carry a `probe()` (version-nibble check) exactly for this heuristic-fallback case, so G-PDU payloads route correctly through the existing fallback pool unmodified. Other message types → `Terminal` (control messages, no encapsulated payload) |
| Identity | key `[{teid, None}]` (shared qualifier, GRE/VXLAN shape) → one **GTP-U tunnel** stream per Tunnel Endpoint ID |
| Rollups | `Accumulate` on `message_type` |

**gtp_c** (3GPP TS 29.060 GTPv1-C; 3GPP TS 29.274 GTPv2-C — one plugin, `version` field
disambiguates, the `ospf`/`stun` precedent from 11.4/11.8).

| Item | Spec |
|---|---|
| Claims | `UdpPort(2123)` |
| Fields | `Keys`: `teid` (U64, `0` before one is assigned — early Create-Session/Create-PDP-Context messages) · `Structural`: `version` (1 or 2, from the flags byte's top 3 bits), `message_type` (version-specific numbering: v1 Create/Update/Delete-PDP-Context, Echo; v2 Create/Modify/Delete-Session, Echo), `length` · `Full`: `imsi` (Bytes, best-effort — extracted where a bounded TLV(v1)/TLIV(v2) information-element walk locates it), `apn` (Str, best-effort, same walk) |
| IE-walk honesty | v1 uses TLV-encoded information elements, v2 uses TLIV (type+length+**instance**+value) — genuinely different encodings, not just different message numbers. v1 scope extracts `message_type`/`teid` reliably from the fixed header for both versions, and attempts `imsi`/`apn` best-effort via each version's own walk, declining that *specific field* (not the whole packet) if the walk doesn't match the expected shape — the same bounded, honest partial-extraction stance as `enip`'s `cip_service` (11.13) |
| Hint | `Terminal` |
| Identity | key `[{teid, None}]`, works uniformly across both versions since the TEID concept itself is unchanged between them |
| Rollups | `Accumulate` on `message_type` |

### Planned (Tier 2 — not yet specified)
| Protocol | Standard | Note |
|---|---|---|
| M3UA (SS7-over-IP) | RFC 4666 | Carries SS7 MTP3 user traffic over SCTP (11.6) |
| SCCP / TCAP (SS7) | ITU-T Q.71x / Q.77x series | Carried inside M3UA; a nested-decode dependency on it |
| Diameter (S6a/Gx) | RFC 6733 | Cross-referenced from 11.7 — mobile-core AAA/policy signaling, same protocol either domain |

## Acceptance criteria
- [ ] `gtp_u` fixture: a G-PDU carrying a real inner IPv4 packet routes through `Unknown` →
      fallback pool → `ipv4`'s existing probe, ending with the correct nested stream — proves
      the zero-new-code claim end-to-end, not just in prose (mirrors 06.5's tunnel-hierarchy
      acceptance-criteria rigor).
- [ ] `gtp_u` Echo-Request/Response and Error-Indication fixtures stop `Terminal`, no
      spurious inner-stream attempt.
- [ ] `gtp_c` fixture: a GTPv1-C Create-PDP-Context Request/Response pair and a GTPv2-C
      Create-Session Request/Response pair both parse `version`/`message_type`/`teid`
      exactly through the same plugin.
- [ ] `gtp_c` IE-walk honesty: a fixture with an unrecognized/vendor-specific IE type present
      alongside a recognized `imsi`/`apn` still extracts the recognized ones correctly and
      skips the unrecognized one via its own length field (bounded walk, no misalignment).
- [ ] Two different TEIDs over one UDP 5-tuple (a GTP-U gateway serving multiple subscriber
      tunnels) produce two sibling streams (06.5's two-VNIs-one-outer-stream test shape).
