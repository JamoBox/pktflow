# 11.13 — Industrial/OT (ICS-SCADA): Modbus/TCP, DNP3, EtherNet/IP (CIP), BACnet/IP

> Task: [11 Standard library](README.md) · Depends on: 02–06 · PRD: FR-31 · D13, D14

## Goal
The control-systems protocols relevant to enterprise facilities (BACnet/IP building
automation) and manufacturing/utility OT networks (Modbus, DNP3, EtherNet/IP). Notably,
unlike most of this task's other domains, these are mostly **plaintext by design** — OT
protocols historically prioritized determinism over confidentiality — so D12's encryption
boundary rarely applies here; the limiting factor is field depth (vendor-specific object
models), not opacity.

## Specification

**modbus** (Modbus Organization — *Modbus Application Protocol Specification V1.1b3*, not an
IETF/IEEE document).

| Item | Spec |
|---|---|
| Claims | `TcpPort(502)` |
| Fields | `Keys`: `unit_id` (U64) · `Structural`: `function_code`, `is_exception` (Bool, top bit of `function_code`), `exception_code` (if exception) · `Full`: `start_address`, `quantity` (read/write-multiple requests), `register_value`/`coil_value` (single-write requests) |
| Hint | `Terminal` |
| Identity | key `[{unit_id, None}]` (shared qualifier) — a single Modbus/TCP gateway connection commonly multiplexes several downstream serial `unit_id`s, so this is the right identity granularity, not the bare TCP session |
| Rollups | `Accumulate` on `function_code` |

**dnp3** (IEEE 1815-2012) — link-layer header only in v1; the transport-segment reassembly
and full application-layer object-header walk are out of scope (D7-consistent: no
cross-segment reassembly).

| Item | Spec |
|---|---|
| Claims | `TcpPort(20000)`, `UdpPort(20000)` |
| Probe | `start_bytes == 0x0564` (DNP3's fixed link-layer sync pattern) exactly → 90 — strong and deterministic, worth having since DNP3-over-serial-gateway deployments don't always land on the standard port |
| Fields | `Keys`: `source` (U64), `destination` (U64) · `Structural`: `start_bytes` (verified, not exposed as meaningfully variable), `length`, `control` · `Full`: `function_code` (application layer, best-effort — read directly when it falls within this segment; DNP3's transport-segment framing means a function code split across segments is not reconstructed) |
| Hint | `Terminal` |
| Identity | key `[{a: "source", b: "destination"}]`, `EndpointSort` → **DNP3 station-pair conversation** |
| Rollups | `Accumulate` on `function_code` |

**enip** (EtherNet/IP + CIP — ODVA's *CIP and EtherNet/IP Specification*).

| Item | Spec |
|---|---|
| Claims | `TcpPort(44818)` |
| Fields | `Keys`: `session_handle` (U64) · `Structural`: `command` (RegisterSession=0x65/UnRegisterSession=0x66/SendRRData=0x6F/SendUnitData=0x70/ListServices=0x04/ListIdentity=0x63), `length`, `status` (U64) · `Full`: `cip_service` (U64, best-effort — read from the first Common-Packet-Format data item's leading service byte on `SendRRData`/`SendUnitData`; CIP's own routing-path/attribute walk is out of v1 scope, the same "cheap framing field, not a full decode" stance as LDAP's `bind_dn`, 11.7) |
| Hint | `Terminal` |
| Identity | key `[{session_handle, None}]` (shared qualifier) → one CIP session stream per `session_handle`, assigned by `RegisterSession`, within the parent TCP session |
| Rollups | `Accumulate` on `command` |

**bacnet_ip** (ANSI/ASHRAE 135, Annex J — the IP/BVLL variant).

| Item | Spec |
|---|---|
| Claims | `UdpPort(47808 /* 0xBAC0 */)` |
| Probe | BVLC `type == 0x81` (fixed magic) and `function` is a defined value (0x00 Result/0x0A Original-Unicast-NPDU/0x0B Original-Broadcast-NPDU/0x04 Forwarded-NPDU/...) → 60 |
| Fields | `Keys`: `app` (shared, constant `Str("bacnet")`) · `Structural`: `bvlc_function`, `npdu_control` · `Full`: `apdu_type` (Confirmed-Request/Unconfirmed-Request/SimpleACK/ComplexACK, from the APDU's top nibble, network-layer-message-only NPDUs have none), `service_choice` (U64, best-effort — WhoIs=8/IAm=0/ReadProperty=12/WriteProperty=15/...; property-value decoding itself is Tier 2) |
| Hint | `Terminal` |
| Identity | key `[{app, None}]`, one `bacnet_ip` child stream per UDP stream — reasonable uniformly even though a large share of real BACnet traffic is broadcast Who-Is/I-Am discovery (STP/CDP-shaped) rather than unicast ReadProperty/WriteProperty (session-shaped); app-stream keeps both cases in one model rather than branching |
| Rollups | `Accumulate` on `service_choice` |

### Planned (Tier 2 — not yet specified)
| Protocol | Standard | Note |
|---|---|---|
| IEC 60870-5-104 | IEC 60870-5-104 | European utility SCADA, structurally similar to DNP3 |
| S7comm | *No public standard* — reverse-engineered (Siemens proprietary) | Siemens S7 PLC protocol |
| OPC-UA (binary header) | IEC 62541 | Increasingly common OT/IT convergence protocol; has its own TLS-secured mode (D12-relevant when it lands) |

## Acceptance criteria
- [x] `modbus` fixtures cover Read Holding Registers, Write Single Register, and an
      exception response; two different `unit_id`s over one TCP connection produce two
      sibling streams (mirrors 06.5's two-VNIs test shape).
- [x] `dnp3` fixture parses link-layer header exactly; `start_bytes` probe honesty verified
      (non-`0x0564` bytes score `None`/low even with a plausible-looking rest of header).
- [ ] `enip` fixture: RegisterSession → SendRRData sequence forms one `session_handle`
      stream; `cip_service` best-effort extraction verified against a real capture.
- [x] `bacnet_ip` fixtures cover a Who-Is/I-Am broadcast discovery exchange and a unicast
      ReadProperty/ComplexACK pair, both folding correctly into the app-stream pattern.
- [ ] Each plugin's field-depth honesty is tested, not just documented: a fixture with a
      protocol feature explicitly out of v1 scope (DNP3 multi-segment function code, CIP
      routing path, BACnet property value) still parses its in-scope fields correctly and
      omits the rest cleanly, no crash or wrong guess. (`bacnet_ip` done — its own
      `segmented_confirmed_request_skips_sequence_and_window_first` and
      `i_am_extracts_service_choice_and_leaves_params_opaque` tests; `enip`'s CIP
      routing-path case is still outstanding.)
