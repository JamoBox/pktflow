# 11.11 — Network management & telemetry: SNMP, Syslog, NetFlow v9, IPFIX

> Task: [11 Standard library](README.md) · Depends on: 02–06 · PRD: FR-31 · D7, D13, D14

## Goal
Universal device-management traffic. SNMP joins Kerberos/LDAP (11.7) as ASN.1/BER-framed
(same "tag-level fields only" scope). NetFlow v9/IPFIX surface a **different** stateless-
plugin ceiling than any protocol so far: their data records are only decodable against a
**template** describing field layout that was sent in an *earlier* packet — the same class
of cross-packet-state problem as HTTP/2's HPACK dynamic table (11.8), named explicitly here
rather than re-derived.

## Specification

**snmp** (RFC 1157 v1, RFC 3416 v2c, RFC 3411–3418 v3) — BER-framed; same tag-level-only
scope as `kerberos`/`ldap` (11.7): version, community, and the PDU's outer tag (which
directly encodes the operation) are cheap to read; the varbind list (OIDs and their values)
needs a full ASN.1 walk and is out of v1 scope.

| Item | Spec |
|---|---|
| Claims | `UdpPort(161)`, `UdpPort(162)` (traps) |
| Fields | `Keys`: `app` (shared, constant `Str("snmp")`) · `Structural`: `version` (0=v1/1=v2c/3=v3), `community` (Str, v1/v2c only — sent in cleartext by the protocol itself, a real security-relevant fact this field surfaces rather than hides), `pdu_type` (from the PDU's context-specific tag: GetRequest/GetNextRequest/GetResponse/SetRequest/Trap/GetBulkRequest/InformRequest/SNMPv2-Trap/Report) · `Full`: `request_id` (U64, the PDU's first INTEGER field) |
| Hint | `Terminal` |
| Identity | key `[{app, None}]`, one `snmp` child stream per UDP stream (manager↔agent) |
| Rollups | `Accumulate` on `pdu_type`; `Sample` on `community` (surfaces which community string is in use — often a default-credential visibility signal worth a security reviewer's attention) |

**syslog** (RFC 5424; legacy RFC 3164 "BSD syslog" also recognized, disambiguated by the
version token immediately after `<PRI>`).

| Item | Spec |
|---|---|
| Claims | `UdpPort(514)` |
| Fields | `Keys`: `app` (shared, constant `Str("syslog")`) · `Structural`: `facility` (U64, decomposed from `<PRI>`), `severity` (U64, decomposed from `<PRI>`), `version` (U64, 0 if legacy format) · `Full`: `hostname` (Str), `app_name` (Str), `msg` (Str, remainder) |
| Hint | `Terminal` |
| Identity | key `[{app, None}]`, one `syslog` child stream per UDP stream (sender↔collector) |
| Rollups | `Accumulate` on `severity` |

**netflow9** (RFC 3954, informational) — **stateful-template ceiling, stated plainly**:
FlowSet id `0` is a *Template* FlowSet defining a data record's field layout; FlowSet ids
`≥256` are *Data* FlowSets whose bytes are meaningless without the matching template seen on
a **prior** packet. Decoding Data FlowSets needs cross-packet state — the same class of gap
as HTTP/2's HPACK dynamic table (11.8) — which this stateless-plugin contract (02.1 rule 5)
doesn't carry. v1 parses the packet header and each FlowSet's `id`/`length` framing, plus
decodes Template FlowSets fully (self-contained, no external state needed); Data FlowSets are
retained as raw bytes, explicitly opaque.

| Item | Spec |
|---|---|
| Claims | `UdpPort(2055)` (common default; not IANA-fixed, several deployments use others — a claim-honesty note like `wireguard`'s, no `probe()` given the 4-byte version+count header is too generic to guess safely) |
| Fields | `Structural`: `version` (must be 9), `count`, `sequence`, `source_id` · `Full`: `flowsets` (List of Bytes — one entry per FlowSet: `flowset_id` + `length`, with Template FlowSets' field-definition list decoded inline as a nested `List`; Data FlowSets left as opaque raw bytes) |
| Hint | `Terminal` |
| Identity | key `[{app, None}]` (shared, constant `Str("netflow9")`), one child stream per UDP stream (exporter→collector) |
| Rollups | `Accumulate` on `source_id` |

**ipfix** (RFC 7011) — the IETF-standardized successor to NetFlow v9; same Template/Data Set
structure and the identical stateful-decode ceiling described above.

| Item | Spec |
|---|---|
| Claims | `UdpPort(4739)` |
| Fields | `Structural`: `version` (must be 10), `length`, `sequence`, `domain_id` · `Full`: `sets` (List of Bytes, same Template-decoded/Data-opaque treatment as `netflow9`) |
| Hint | `Terminal` |
| Identity | key `[{app, None}]` (shared, constant `Str("ipfix")`) |
| Rollups | `Accumulate` on `domain_id` |

### Planned (Tier 2 — not yet specified)
| Protocol | Standard | Note |
|---|---|---|
| sFlow | *Not IETF* — sflow.org spec | Sampling-based, structurally different from NetFlow/IPFIX's per-flow export |
| TR-069/CWMP | Broadband Forum TR-069 | Consumer-CPE remote management (ISP/home-router context) |

## Acceptance criteria
- [x] `snmp` fixtures for GetRequest/GetResponse (v1/v2c) and an SNMPv2-Trap parse
      `pdu_type`/`community`/`request_id` exactly; DER length-decoding truncation test
      shared with the 11.7 boundary cases.
- [x] `syslog` fixtures cover both RFC 5424 and legacy RFC 3164 framing, `facility`/
      `severity` decomposition verified against the combined `<PRI>` value.
- [ ] `netflow9`/`ipfix` fixtures: a Template FlowSet/Set decodes its field-definition list
      exactly; a Data FlowSet/Set immediately following in the **same packet** is still left
      opaque even though its template was just seen — proves the stateless-only boundary is
      real and consistent (no partial, order-dependent decode that would work sometimes).
- [ ] Header version-field validation (`netflow9` rejects a non-9 version, `ipfix` rejects a
      non-10 version) tested — the one cheap sanity check available without templates.
