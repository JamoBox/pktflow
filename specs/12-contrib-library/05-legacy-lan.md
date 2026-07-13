# 12.5 — Legacy LAN suites: IPX, NetBIOS Session Service, NetBIOS Datagram Service

> Task: [12 Contrib library](README.md) · Depends on: 02–06 · Cross-refs: 11.1 (`llc`),
> 11.9 (`smb2`), 11.12 (`netbios_ns` name decoding) · PRD: FR-32 · D3, D10, D14, D16

## Goal
The pre-TCP/IP LAN protocols still alive in industrial sites, retro networks, and a large
share of the pcaps people actually ask tools to explain (CTFs, forensics of old captures,
long-lived Windows estates). IPX is this task's network-layer flavour — a full non-IP
conversation identity. The two NetBIOS services complete the RFC 1001/1002 triple whose
name service the stdlib already ships (11.12), reusing its name decoding rather than
re-implementing it.

## Specification

**ipx** (*no open standard* — Novell's IPX router specification is the closest
authoritative doc; the format derives from Xerox XNS IDP).

| Item | Spec |
|---|---|
| Claims | `EtherType(0x8137)` (Ethernet II framing), `Custom{space:"llc_dsap", id:0xE0}` — a route the stdlib's `llc` (11.1) **already mints** for DSAP 0xE0 and nothing claims until now: the emit-side existed first, contrib supplies the claim side, zero llc edits |
| Probe | For Novell's third framing ("802.3 raw": IPX directly after the 802.3 length field, no LLC): first two payload bytes `0xFFFF` (the IPX checksum field, always 0xFFFF on the wire) + `packet_type` in the known set + declared `length` ≤ frame length → moderate score, fallback-pool admission. `llc` correctly declines these frames (DSAP/SSAP 0xFF is invalid LLC), so the pool is reachable |
| Fields | `Keys`: `dst_network`, `dst_node`, `dst_socket`, `src_network`, `src_node`, `src_socket` · `Structural`: `checksum`, `length`, `transport_control` (hop count), `packet_type` (0 unknown/1 RIP/4 PEP-SAP/5 SPX/17 NCP) |
| Hint | `Terminal` (RIP/SAP/SPX/NCP dissection is Tier 2 — dispatched by socket/packet_type when promoted) |
| Identity | full endpoint-pair conversation: each side is `{network, node, socket}`, canonicalized per D3 — the same shape as 06.3's IP conversation, proving the identity contract isn't IP-specific |
| Rollups | `Accumulate` on `packet_type` |

**netbios_ssn** (NetBIOS Session Service, RFC 1001/1002 §4.3).

| Item | Spec |
|---|---|
| Claims | `TcpPort(139)` |
| Fields | `Keys`: `app` (shared, constant `Str("netbios_ssn")`) · `Structural`: `msg_type` (0x00 session message/0x81 session request/0x82 positive response/0x83 negative response/0x85 keep-alive), `length` (17-bit, flags E bit) · `Full`: session request → `called_name`, `calling_name` (Str, decoded via the **same first-level encoding routine as 11.12's `netbios_ns`** — shared, not duplicated); negative response → `error_code` |
| Hint | Session message whose payload begins `0xFE 'S' 'M' 'B'` → `ByProtocol("smb2")` — the unmodified 11.9 plugin, which claims `TcpPort(445)` for direct transport and gains NetBIOS-carried reachability from here with zero edits (D16's cross-crate composition). Payload beginning `0xFF 'S' 'M' 'B'` is SMB1 (Tier 2) → `Terminal`. Everything else → `Terminal` |
| Identity | key `[{app, None}]`, one child per TCP session |
| Rollups | `Accumulate` on `msg_type`; `Sample` on `called_name` |

**netbios_dgm** (NetBIOS Datagram Service, RFC 1001/1002 §4.4).

| Item | Spec |
|---|---|
| Claims | `UdpPort(138)` |
| Fields | `Keys`: `app` (shared, constant `Str("netbios_dgm")`) · `Structural`: `msg_type` (0x10 direct unique/0x11 direct group/0x12 broadcast/0x13 error/0x14–0x16 query-request/-positive/-negative), `flags`, `dgm_id` · `Full`: `source_name`, `dest_name` (same shared first-level decoding), `dgm_length` |
| Hint | `Terminal` — the payload is typically an SMB MailSlot write (browser elections, `\MAILSLOT\BROWSE`); its SMB1 framing is Tier 2, stated not silently skipped |
| Identity | key `[{app, None}]`, one child per UDP stream |
| Rollups | `Accumulate` on `msg_type`; `Accumulate` on `source_name` (who's announcing on this segment — the browser-election visibility that makes this protocol worth parsing at all) |

### Planned (Tier 2 — not yet specified)
| Protocol | Standard | Note |
|---|---|---|
| SPX | *No open standard* (Novell) | Rides `ipx` `packet_type == 5`; connection-oriented, has real lifecycle semantics worth a stream when promoted |
| IPX RIP / SAP | *No open standard* (Novell) | Sockets 0x453/0x452 — dispatch refinement of `ipx`; SAP's service-name table is the analytic prize |
| NCP | *No open standard* (Novell) | Socket 0x451; NetWare Core Protocol — the suite's application layer |
| SMB1 | *No open standard* — Microsoft [MS-SMB]/[MS-CIFS] | The `0xFF SMB` arm of `netbios_ssn` and the MailSlot payload of `netbios_dgm`; legacy but forensically everywhere |
| AppleTalk (DDP + AARP + NBP) | *No open standard* — Apple, *Inside AppleTalk* | `EtherType(0x809B)` / `EtherType(0x80F3)`; the other great legacy suite, a network-conversation identity like `ipx` when promoted |
| DECnet Phase IV | *No open standard* — Digital's DNA specs | `EtherType(0x6003)` (+ LAT 0x6004) |
| Banyan VINES | *No open standard* (Banyan) | `EtherType(0x0BAD)` — yes, really |
| SNA over LLC | IBM SNA formats (GA27-3136) | `Custom{space:"llc_dsap", id:0x04}` — another route `llc` already mints unclaimed |

## Acceptance criteria
- [ ] `ipx` fixtures cover all three framings — Ethernet II (0x8137), 802.2/LLC (DSAP 0xE0,
      through the unmodified 11.1 `llc`), and 802.3-raw (probe admission) — all reaching
      the same plugin and the same conversation identity.
- [ ] `ipx` conversation folds both directions of a `{network,node,socket}` pair into one
      stream (D3 canonicalization on non-IP endpoint bytes, 09.1 kit).
- [ ] `netbios_ssn` fixture: session request (both names decoded exactly, via the shared
      11.12 routine — one implementation, asserted by test structure) → positive response →
      session message carrying SMB2 dispatches to the unmodified `smb2` plugin end-to-end.
- [ ] `netbios_dgm` browser-election fixture parses `msg_type`/`source_name` exactly and
      stops `Terminal` at the MailSlot payload (the documented Tier-2 boundary, tested).
