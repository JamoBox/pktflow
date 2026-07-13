# 12.12 — VoIP & telephony flavours: MGCP, IAX2

> Task: [12 Contrib library](README.md) · Depends on: 02–06 · Cross-refs: 11.10 (`sip`
> D15 stance, `rtp` reachability) · PRD: FR-32 · D10, D14, D15, D16

## Goal
Telephony signaling beyond 11.10's SIP/RTP core: the gateway-control protocol of carrier
and PBX deployments (MGCP) and Asterisk's trunk protocol (IAX2) — the latter chosen
partly because it *solves* the D15 problem architecturally: signaling and media share one
UDP port pair, so unlike RTP, every packet of a call is reachable through an honest static
claim, and its in-band call multiplexing exercises D10's parent-scoped identity harder
than anything else in the tree.

## Specification

**mgcp** (RFC 3435).

| Item | Spec |
|---|---|
| Claims | `UdpPort(2427)` (gateway side), `UdpPort(2727)` (call-agent side) |
| Fields | `Keys`: `app` (shared, constant `Str("mgcp")`) · `Structural`: `verb` (Str — EPCF/CRCX/MDCX/DLCX/RQNT/NTFY/AUEP/AUCX/RSIP, or the 3-digit response code as `response_code`), `transaction_id` · `Full`: `endpoint` (Str, e.g. `aaln/1@gw.example.net`), `call_id` (C: parameter line, when present) |
| Hint | `Terminal` — the SDP body names the RTP media ports; per D15 (stated once there, applied here exactly as in 11.10's `sip`) that continuation traffic is architecturally invisible, and this spec does not pretend otherwise |
| Identity | key `[{app, None}]`, one child per UDP stream |
| Rollups | `Accumulate` on `verb`; `Accumulate` on `endpoint` (which lines/channels this gateway conversation touched) |

**iax2** (RFC 5456 — Inter-Asterisk eXchange v2).

| Item | Spec |
|---|---|
| Claims | `UdpPort(4569)` |
| Fields | `Keys`: `source_call`, `dest_call` (the 15-bit call numbers) · `Structural`: `full_frame` (Bool — F bit), full frames → `timestamp` (U64, 32-bit), `oseqno`, `iseqno`, `frame_type` (1 DTMF/2 Voice/3 Video/4 Control/6 IAX control/...), `subclass` (IAX control: NEW/PING/PONG/ACK/HANGUP/REJECT/ACCEPT/AUTHREQ/LAGRQ/...); mini frames → `timestamp` (16-bit) only |
| Hint | `Terminal` — mini-frame payload is codec media (D7); full-frame information elements beyond the header are Tier-2 depth (the TLV-envelope stance of 11.7/11.13) |
| Identity | one child stream per **call**: key `[{source_call}, {dest_call}]` with a custom key function folding the two directions' swapped call-number pairs (each direction numbers the call independently — the same unordered-endpoint canonicalization D3 does for addresses, applied to in-band call numbers). Many calls multiplex over one UDP trunk → many sibling children under one UDP stream, D10's parent-scoped identity doing real work (the two-VNIs-one-outer-stream shape, 06.5, at call granularity) |
| Rollups | `Accumulate` on `frame_type`; `Series` on `subclass` for IAX-control frames — call progress (NEW → ACCEPT → ... → HANGUP) as a timeline per call stream |

### Planned (Tier 2 — not yet specified)
| Protocol | Standard | Note |
|---|---|---|
| Megaco / H.248 | ITU-T H.248.1 | `TcpPort(2944)`/`UdpPort(2944)` text, 2945 binary — MGCP's standards-track successor |
| H.225.0 (Q.931 + RAS) | ITU-T H.225.0 | `TcpPort(1720)` signaling, `UdpPort(1719)` RAS; ASN.1 PER — the hardest encoding in this task's inventory, scoped honestly when promoted |
| H.245 | ITU-T H.245 | Negotiated port (D15) — control channel companion to H.225.0 |
| RTCP-XR | RFC 3611 | A refinement of 11.10's `rtcp` (new block types), not a new plugin |
| IAX2 information elements | RFC 5456 §8.6 | The Tier-2 depth extension of `iax2` above: calling/called number IEs — attribution-grade metadata when promoted |

## Acceptance criteria
- [ ] `mgcp` fixture: CRCX/200 + NTFY/RQNT exchange parses verb/transaction/endpoint
      exactly; the SDP body's negotiated port is visible nowhere as a stream (the D15
      criterion, tested the same way 11.9 tests FTP's PASV).
- [ ] `iax2` fixture: a real two-call trunk capture — NEW/ACCEPT/ANSWER control frames plus
      voice mini-frames — folds each call into its own child stream under one UDP stream;
      the swapped call-number pairs of the two directions land in the same stream (custom
      key function through the 09.1 kit).
- [ ] `iax2` `subclass` series preserves call-progress order per call (mirrors 11.10 `sip`'s
      `status_code` series criterion).
- [ ] Mini-frame media payload appears in no extracted field (D7 cap tested).
