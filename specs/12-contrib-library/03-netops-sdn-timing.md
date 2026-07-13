# 12.3 — Network ops, SDN & timing: OpenFlow, PTP, BFD, Wake-on-LAN

> Task: [12 Contrib library](README.md) · Depends on: 02–06 · PRD: FR-32 · D4, D14, D16

## Goal
Operational control-plane chatter beyond 11.4/11.11's scope: SDN controller sessions,
sub-microsecond clock sync, liveness micro-sessions, and the humble magic packet. Two of
these (PTP, WoL) are also this task's deliberate "flavour from the link layer" — both claim
EtherTypes alongside (or instead of) ports.

## Specification

**openflow** (Open Networking Foundation, OpenFlow Switch Specification 1.0–1.5.1 —
*not IETF*; ONF's published spec is the governing document).

| Item | Spec |
|---|---|
| Claims | `TcpPort(6653)` (IANA-assigned), `TcpPort(6633)` (pre-IANA legacy, still common — the same legacy-port stance as 11.7's Tier-2 RADIUS note, but load-bearing enough here to claim now) |
| Fields | `Keys`: `app` (shared, constant `Str("openflow")`) · `Structural`: `version` (0x01=1.0 … 0x06=1.5), `msg_type` (HELLO/ERROR/ECHO_REQUEST/FEATURES_REQUEST/FEATURES_REPLY/PACKET_IN/PACKET_OUT/FLOW_MOD/MULTIPART_*/...), `length`, `xid` |
| Hint | `Terminal` — PACKET_IN/PACKET_OUT carry an embedded frame, but re-dissecting controller-relayed packets as if on-wire would fabricate traffic that never crossed this link; explicit non-goal |
| Identity | key `[{app, None}]`, one `openflow` child per TCP session (controller↔switch) |
| Rollups | `Accumulate` on `msg_type`; `Sample` on `version` |

**ptp** (IEEE 1588-2019, PTPv2).

| Item | Spec |
|---|---|
| Claims | `UdpPort(319)` (event), `UdpPort(320)` (general), `EtherType(0x88F7)` (L2 transport) — the same multi-space claim shape as 11.5's `l2tpv3` |
| Fields | `Structural`: `message_type` (Sync/Delay_Req/Pdelay_Req/Pdelay_Resp/Follow_Up/Delay_Resp/Announce/Signaling/Management), `version`, `domain`, `sequence_id`, `flags` · `Full`: `correction`, `clock_identity` (Bytes 8, from sourcePortIdentity), `source_port`; Announce → `grandmaster_identity`, `priority1`, `priority2` |
| Hint | `Terminal` |
| Identity | none — multicast announce/sync pattern, identity-less like `ospf` Hello (11.4); contributes stats to its parent conversation |
| Rollups | n/a (identity-less) |

**bfd** (RFC 5880; single-hop encapsulation RFC 5881, multihop RFC 5883).

| Item | Spec |
|---|---|
| Claims | `UdpPort(3784)`, `UdpPort(4784)` (multihop). Echo (3785) is Tier 2 — its payload is deliberately opaque (RFC 5880 §5, sender-defined), so there'd be nothing to parse anyway |
| Fields | `Structural`: `version`, `diag`, `state` (AdminDown/Down/Init/Up), `flags` (P/F/C/A/D/M), `detect_mult`, `my_discriminator`, `your_discriminator` · `Full`: `desired_min_tx`, `required_min_rx`, `required_min_echo_rx` |
| Hint | `Terminal` |
| Identity | key `[{app, None}]` (shared, constant `Str("bfd")`), one child per UDP stream — RFC 5881 §4 requires a unique source port per session, so the UDP 5-tuple already *is* the session boundary; no discriminator-keyed scheme needed |
| Rollups | `Series` on `state` (D4) — the state machine's transitions over time are the entire analytic value of watching BFD; a flap is visible as Up→Down→Init→Up in one stream's series |

**wol** (Wake-on-LAN magic packet — *no open standard*; AMD's "Magic Packet Technology"
whitepaper is the closest authoritative doc).

| Item | Spec |
|---|---|
| Claims | `EtherType(0x0842)`, `UdpPort(9)` — **claim-honesty note**: UDP 9 is the discard port and the *convention*, not an assignment (7 and 0 also occur in the wild; Tier-2 territory). Anything on either route that isn't 6×`0xFF` + 16 repetitions of one MAC declines — the format is its own validator |
| Fields | `Structural`: `target_mac` · `Full`: `has_password` (Bool, trailing 4/6-byte SecureOn) |
| Hint | `Terminal` |
| Identity | none — a one-shot datagram, identity-less |
| Rollups | n/a |

### Planned (Tier 2 — not yet specified)
| Protocol | Standard | Note |
|---|---|---|
| Babel | RFC 8966 | `UdpPort(6696)`; mesh/homenet routing |
| LISP | RFC 9300/9301 | `UdpPort(4341)` data / `UdpPort(4342)` control |
| TWAMP / OWAMP | RFC 5357 / RFC 4656 | Active measurement; control `TcpPort(862)`/`TcpPort(861)`, test sessions negotiated (D15) |
| TZSP | *No standard* — de facto (TaZmen, documented by Wireshark) | `UdpPort(37008)`; encapsulated-capture transport, another entry-flavour like `sll` |
| CARP | *No RFC* — OpenBSD project doc | **Shares `IpProtocol(112)` with 11.4's `vrrp`** — promotion requires a vrrp-side version-field disambiguation spec'd in 11.4 first (claim-precedence rule, D16) |
| gPTP | IEEE 802.1AS | A profile/refinement of `ptp`, not a new wire format |
| NETCONF | RFC 6241 | Runs inside SSH (11.7) — nothing routable to claim; listed so the taxonomy shows it was considered, not missed |

## Acceptance criteria
- [ ] `openflow` fixture: HELLO/FEATURES_REQUEST/FEATURES_REPLY/PACKET_IN sequence parses
      exactly on both 6653 and 6633; one app-stream child per controller session.
- [ ] `ptp` fixtures cover the UDP transport (Sync/Follow_Up/Delay_Req/Delay_Resp) and the
      L2 transport (Announce over `EtherType(0x88F7)`) through the same plugin — the
      multi-space claim proven, mirroring 11.5's `l2tpv3` criterion.
- [ ] `bfd` fixture: a real session bring-up (Down→Init→Up) folds into one child stream
      whose `state` series preserves transition order; a multihop (4784) packet reaches the
      same plugin.
- [ ] `wol` fixtures: one L2 (0x0842) and one UDP/9 magic packet parse `target_mac`
      exactly; a non-magic payload on UDP 9 declines (the discard port's other traffic must
      not be claimed as WoL).
