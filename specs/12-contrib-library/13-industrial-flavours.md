# 12.13 — Industrial & building automation flavours: PROFINET, EtherCAT, GOOSE, KNXnet/IP

> Task: [12 Contrib library](README.md) · Depends on: 02–06 · Cross-refs: 11.13 (the OT
> domain this extends), 11.1 (`vlan` composition) · PRD: FR-32 · D10, D14, D16

## Goal
The fieldbus and substation protocols beyond 11.13's Tier-1 quartet — three of them raw
Ethernet protocols (this task's deepest link-layer flavours: hard-real-time traffic that
never touches IP), plus the building-automation standard of European installations. Between
them they cover discrete manufacturing (PROFINET, EtherCAT), electrical substations
(GOOSE), and smart buildings (KNX) — the verticals D13's Tier-2 bar explicitly deferred,
now given their contrib home per D16.

## Specification

**profinet** (IEC 61158 / IEC 61784-2 — PROFINET; PROFIBUS & PROFINET International (PI)
maintains the profile specs).

| Item | Spec |
|---|---|
| Claims | `EtherType(0x8892)` — commonly VLAN-tagged with priority (rides under the unmodified 06.2 `vlan`, composition for free) |
| Fields | `Structural`: `frame_id` (U64) and its decoded `frame_class` (Str — cyclic RT class data `0x8000–0xBFFF`; alarm high `0xFC01` / low `0xFE01`; DCP Hello `0xFEFC` / Get-Set `0xFEFD` / Identify-Request `0xFEFE` / Identify-Response `0xFEFF`) · `Full` (DCP frames only): `service_id` (Get/Set/Identify/Hello), `service_type` (request/response-success), `xid`, and from the block walk → `station_name` (Str, NameOfStation option 2/suboption 2), `device_vendor` (Str, when the DeviceProperties block is present) |
| Hint | `Terminal` — cyclic RT payload is process-image data (envelope only: `frame_id` + class; the deliberate depth cap 11.13 set for `enip`'s CIP, applied to cyclic IO) |
| Identity | none for cyclic RT (beacon-like, folds into the parent MAC conversation); DCP is identity-less discovery chatter like 11.1's `lldp` |
| Rollups | n/a (identity-less) |

**ethercat** (IEC 61158 Type 12; EtherCAT Technology Group (ETG) publishes the
specification).

| Item | Spec |
|---|---|
| Claims | `EtherType(0x88A4)` |
| Fields | `Structural`: `length` (11-bit), `ec_type` (4-bit, 1 = EtherCAT command frame) · `Full` (first datagram only — the multi-chunk stance of 11.6's `sctp`, applied to EtherCAT's datagram chain): `cmd` (NOP/APRD/APWR/APRW/FPRD/FPWR/FPRW/BRD/BWR/BRW/LRD/LWR/LRW/ARMW/FRMW), `index`, `address` (U64 — the raw 32-bit ADP/ADO or logical address, undissected), `data_len`, `more` (Bool — the M bit says further datagrams follow; counted, not walked) |
| Hint | `Terminal` |
| Identity | none — cyclic master/slave chatter on a segment, identity-less |
| Rollups | n/a |

**goose** (IEC 61850-8-1 — GOOSE; substation event messaging).

| Item | Spec |
|---|---|
| Claims | `EtherType(0x88B8)` |
| Fields | `Structural`: `appid`, `length`, and from the BER-encoded goosePdu (bounded ASN.1 walk — the shared DER/BER length-decoding discipline of 11.7 `kerberos`/11.11 `snmp`): `st_num`, `sq_num`, `time_allowed_to_live`, `test` (Bool), `conf_rev`, `num_entries` · `Full`: `gocb_ref` (Str), `dat_set` (Str), `go_id` (Str) — the allData values themselves are process data, left unparsed |
| Hint | `Terminal` |
| Identity | key `[{appid, None}]` — one stream per GOOSE publication under its MAC conversation (the `vrrp` group-stream shape, 11.4) |
| Rollups | `Sample` on `gocb_ref`; `Series` on `st_num` — a state-number jump is *the* GOOSE event signal (and a replayed/stale `st_num` is the classic substation-attack indicator), so the timeline is the analytic product |

**knxnet_ip** (ISO 22510 / EN 13321-2 — KNXnet/IP; the KNX Association's specification).

| Item | Spec |
|---|---|
| Claims | `UdpPort(3671)` |
| Fields | `Keys`: `app` (shared, constant `Str("knxnet_ip")`) · `Structural`: `header_length` (6), `version` (0x10), `service_type` (Str-decoded U64 — SEARCH_REQUEST 0x0201/SEARCH_RESPONSE 0x0202/DESCRIPTION_REQUEST 0x0203/CONNECT_REQUEST 0x0205/CONNECT_RESPONSE 0x0206/DISCONNECT_REQUEST 0x0209/TUNNELLING_REQUEST 0x0420/TUNNELLING_ACK 0x0421/ROUTING_INDICATION 0x0530), `total_length`; tunnelling/routing → `channel_id`, `seq_counter` · `Full` (cEMI, bounded): `message_code` (L_Data.req 0x11/L_Data.ind 0x29), `group_address` (Str, rendered `main/middle/sub`) |
| Hint | `Terminal` (the APDU beyond the group address is the payload value — content by this domain's cap) |
| Identity | key `[{app, None}]`, one child per UDP stream |
| Rollups | `Accumulate` on `service_type`; `Accumulate` on `group_address` (which lights/valves/sensors this connection touched — the topic-rollup pattern, 11.14 `mqtt`, in a building) |

### Planned (Tier 2 — not yet specified)
| Protocol | Standard | Note |
|---|---|---|
| IEC 61850-9-2 Sampled Values | IEC 61850-9-2 | `EtherType(0x88BA)` — GOOSE's high-rate sibling (merging units); same BER discipline |
| MMS (+ TPKT/COTP framing) | ISO 9506 over RFC 1006 / ITU-T X.224 | `TcpPort(102)` — shares the framing 11.13's Tier-2 S7comm needs and the extraction call 12.6's `rdp` deferred; promoting either forces the shared-`tpkt` decision |
| HART-IP | FieldComm Group HART-IP | `UdpPort(5094)`/`TcpPort(5094)` |
| Ethernet POWERLINK | EPSG DS 301 | `EtherType(0x88AB)` |
| SERCOS III | IEC 61158 Type 16 | `EtherType(0x88CD)` |
| CC-Link IE | CLPA specification | Field/Control variants, raw Ethernet |
| PROFINET acyclic (RPC) | IEC 61158 | PROFINET's DCE/RPC-over-UDP channel — meets 11.9's Tier-2 DCE/RPC row; whichever promotes first owns the envelope |

## Acceptance criteria
- [ ] `profinet` fixtures: a DCP Identify-Request/Response pair (station name extracted
      exactly) and a cyclic RT frame (envelope-only, correct `frame_class`) — including one
      VLAN-tagged RT fixture proving the unmodified 06.2 composition.
- [ ] `ethercat` fixture: a multi-datagram frame parses the first datagram's
      cmd/index/address exactly with `more == true` and no second-datagram walk (explicit
      non-goal, tested — the 11.6 `sctp` criterion shape).
- [ ] `goose` fixture: a real state-change burst (same `appid`, incrementing `sq_num`, then
      an `st_num` bump with `sq_num` reset) folds into one `appid` stream whose `st_num`
      series shows the event; BER long-form lengths and a truncated goosePdu decline
      cleanly (fuzz target registered).
- [ ] `knxnet_ip` fixture: SEARCH → CONNECT → TUNNELLING_REQUEST/ACK sequence parses
      exactly; `group_address` rendering verified against known bus addresses; a
      ROUTING_INDICATION multicast fixture reaches the same plugin.
