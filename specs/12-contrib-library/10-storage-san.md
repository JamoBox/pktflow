# 12.10 — Storage & SAN: iSCSI, NBD

> Task: [12 Contrib library](README.md) · Depends on: 02–06 · PRD: FR-32 · D7, D14, D16

## Goal
Block-storage-over-IP session protocols: the SAN traffic of virtualization hosts, homelab
NAS boxes, and datacenter storage networks. Both follow the app-stream pattern with the
same depth cap as everything in this task — operation types and session/login metadata,
never block data.

## Specification

**iscsi** (RFC 7143 — consolidated iSCSI).

| Item | Spec |
|---|---|
| Claims | `TcpPort(3260)` |
| Fields | `Keys`: `app` (shared, constant `Str("iscsi")`) · `Structural`: `opcode` (masked low 6 bits — initiator: 0x00 NOP-Out/0x01 SCSI Command/0x02 Task Mgmt/0x03 Login Request/0x04 Text Request/0x05 SCSI Data-Out/0x06 Logout Request; target: 0x20 NOP-In/0x21 SCSI Response/0x23 Login Response/0x25 SCSI Data-In/0x26 Logout Response), `immediate` (the 0x40 I bit), `flags`, `data_segment_length` (24-bit), `initiator_task_tag` · `Full` (Login/Text PDUs only): `csg`/`nsg` stages; bounded key=value scan of the data segment → `initiator_name` (Str, `InitiatorName=iqn....`), `target_name` (Str) — connection attribution, the `bind_dn` pattern (11.7) |
| Hint | `Terminal` — Data-In/Data-Out segments are block content (D7), counted via `data_segment_length` only |
| Identity | key `[{app, None}]`, one child per TCP session (multiple connections per iSCSI session — MC/S — appear as sibling children; correlating them by ISID is a v2 refinement, noted not silently wrong) |
| Rollups | `Accumulate` on `opcode`; `Sample` on `initiator_name`, `target_name` |

**nbd** (Network Block Device protocol — the `doc/proto.md` in the canonical nbd
repository; *no standards body*, the project document is the governing spec).

| Item | Spec |
|---|---|
| Claims | `TcpPort(10809)` (IANA-assigned) |
| Fields | `Keys`: `app` (shared, constant `Str("nbd")`) · `Structural`: phase recognized by magic — negotiation: `NBDMAGIC` + `IHAVEOPT` (server greeting) or `IHAVEOPT` (client option) → `option` (1 EXPORT_NAME/3 LIST/5 STARTTLS/6 INFO/7 GO), `handshake_flags`; transmission: request magic `0x25609513` → `cmd_type` (0 READ/1 WRITE/2 DISC/3 FLUSH/4 TRIM), `cmd_flags`, `handle`, `offset`, `req_length`; reply magic `0x67446698` → `error`, `handle` · `Full`: `export_name` (Str, from EXPORT_NAME/GO option data) |
| Hint | `Terminal` — WRITE payload and READ reply data are block content (D7). A STARTTLS option marks the D12 boundary |
| Identity | key `[{app, None}]`, one child per TCP session |
| Rollups | `Accumulate` on `cmd_type`; `Sample` on `export_name` |
| Honesty | The magics make per-packet phase detection unusually reliable for a TCP protocol, but a WRITE whose header crossed a segment boundary declines (`Truncated`) like every other protocol here — magic-based recognition is not reassembly (D7) |

### Planned (Tier 2 — not yet specified)
| Protocol | Standard | Note |
|---|---|---|
| NVMe/TCP | NVM Express, *NVMe over Fabrics — TCP transport binding* | `TcpPort(4420)`; the modern successor traffic — likely first promotion out of this table |
| FCoE + FIP | INCITS T11 FC-BB-5 | `EtherType(0x8906)` / `EtherType(0x8914)` — a link-layer flavour; the encapsulated FC frame's `d_id`/`s_id` give a real conversation identity |
| ATA over Ethernet | *No standards body* — Coraid/Brantley Coile published spec | `EtherType(0x88A2)`; minimalist L2 block protocol |
| Ceph messenger | *Project doc* — Ceph msgr v1/v2 | `TcpPort(3300)` (v2)/`TcpPort(6789)` (v1) |
| DRBD | *Project doc* (LINBIT) | `TcpPort(7788)` region, configurable |
| NDMP | *No current standards body* — NDMP v4 spec (originally SNIA/NDMP.org) | `TcpPort(10000)`; backup control sessions |

## Acceptance criteria
- [ ] `iscsi` fixture: Login Request/Response (with `InitiatorName`/`TargetName` extracted
      from the key=value segment), SCSI Command, Data-In, Logout sequence parses exactly;
      the block-data bytes appear in no field (D7 cap tested).
- [ ] `iscsi` truncation tests at the 48-byte BHS boundary and inside the key=value scan
      (a value split across segments declines, no partial pair emitted).
- [ ] `nbd` fixture: full newstyle negotiation (greeting → GO with export name → reply)
      then READ/WRITE/FLUSH transmission requests parse exactly; each magic mismatch case
      declines rather than misclassifying phase.
- [ ] Both app-stream children form correctly under their TCP sessions (06.6 pattern);
      `cmd_type`/`opcode` accumulations reflect each fixture's full operation mix.
