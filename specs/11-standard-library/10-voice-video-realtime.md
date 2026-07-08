# 11.10 — Voice, video & real-time: SIP, RTP, RTCP

> Task: [11 Standard library](README.md) · Depends on: 02–06 · PRD: FR-31 · D7, D13, D14, D15

## Goal
VoIP's signaling plane (SIP, reliably routable — a well-known port) and media plane (RTP/
RTCP, **not** reliably routable — D15's clearest instance, since the whole point of SIP is to
negotiate an ephemeral port pair for RTP inside its SDP body).

## Specification

**sip** (RFC 3261) — text-based, HTTP-shaped (11.8's `http` is a structural cousin). Per D7,
the SDP body (if present) is unparsed payload — which is exactly where the RTP port that D15
names as "would need cross-stream correlation" is announced. Extracting that port from SDP
and pre-registering a route for the resulting RTP stream is precisely the future capability
D15 describes; not attempted here.

| Item | Spec |
|---|---|
| Claims | `UdpPort(5060)`, `TcpPort(5060)` |
| Fields | `Keys`: `call_id` (Str, shared `KeyField`, `b: None` — from the mandatory `Call-ID` header) · `Structural`: `is_request` (Bool), `method` (Str: INVITE/ACK/BYE/CANCEL/REGISTER/OPTIONS/...), `status_code` (U64, response only) · `Full`: `from` (Str), `to` (Str), `via` (Str), `cseq` (Str) |
| Hint | `Terminal` |
| Identity | key `[{call_id, None}]` (shared qualifier, GRE/VXLAN shape) → one **SIP dialog** stream per `Call-ID`, the SIP-native session identifier spanning INVITE...200 OK...ACK...BYE — a more precise identity than the generic app-stream constant, since SIP itself already defines what "one call" means |
| Rollups | `Accumulate` on `method`; `Series{cap:64}` on `status_code` — the call-progress sequence (100 Trying → 180 Ringing → 200 OK) is order-sensitive, the same shape as DHCP's DORA series (06.6) |

**rtp** (RFC 3550) — **D15 applies in full**: RTP has no well-known port; the port pair is
negotiated inside SIP's (unparsed) SDP body. UDP's hint is unconditionally `Candidates`
(06.4), never `Unknown`, so an ephemeral, unclaimed port pair **gates shut** rather than
reaching heuristic fallback — meaning a `probe()` here would never actually be consulted.
Giving `rtp` one anyway would be dishonest scaffolding (the same reasoning UDP itself uses to
justify having no `probe()`, 06.4). This plugin is real, specified, and fixture-tested by
feeding bytes directly to `parse()` (09.1) — it is just not reachable via routing in v1.

| Item | Spec |
|---|---|
| Claims | none |
| Probe | none — see above; would be dead code under the current gate |
| Fields | `Keys`: `ssrc` (U64) · `Structural`: `version`, `payload_type`, `sequence_number`, `timestamp`, `marker_bit` · `Full`: `csrc_list` (List of U64) |
| Hint | `Terminal` |
| Identity | key `[{ssrc, None}]` (shared qualifier) → one stream per RTP synchronization source, ready to be reached the moment cross-stream port correlation (D15) exists |
| Rollups | `Accumulate` on `payload_type` |

**rtcp** (RFC 3550, same document as RTP — sender/receiver reports, source description,
bye). Same reachability stance as `rtp`.

| Item | Spec |
|---|---|
| Claims | none |
| Fields | `Keys`: `ssrc` (U64) · `Structural`: `packet_type` (SR=200/RR=201/SDES=202/BYE=203/APP=204) · `Full` (SR only): `ntp_timestamp` (U64), `rtp_timestamp` (U64), `packet_count`, `octet_count`; (SDES only): `cname` (Str) |
| Hint | `Terminal` |
| Identity | key `[{ssrc, None}]` |
| Rollups | `Accumulate` on `packet_type` |

### Planned (Tier 2 — not yet specified)
| Protocol | Standard | Note |
|---|---|---|
| RTSP | RFC 7826 (2.0) | Media *control* (play/pause/seek), text-based like SIP — reliably routable, unlike the media itself |
| Skinny/SCCP | *No open standard* (Cisco) | Cisco's proprietary IP-phone signaling protocol |

## Acceptance criteria
- [ ] `sip` fixture: a full INVITE/180/200/ACK/BYE dialog folds into one `call_id`-keyed
      stream; `status_code` series preserves call-progress order.
- [ ] `rtp`/`rtcp` fixtures fed directly to `parse()` (bypassing routing, per the documented
      reachability limitation) parse real-capture bytes exactly, including CSRC-list and
      SR/SDES variants.
- [ ] A same-session test proves the D15 claim mechanically, not just in prose: a synthetic
      capture with a SIP INVITE (whose SDP names an RTP port) followed by RTP packets on that
      port shows the RTP packets **stopping** at the UDP layer with
      `StopReason::UnclaimedRoute` — the gate behaving exactly as designed, end-to-end.
