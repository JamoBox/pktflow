# 12.16 — Gaming & consumer realtime: Source A2S, Minecraft

> Task: [12 Contrib library](README.md) · Depends on: 02–06 · Cross-refs: 11.8 (`stun`),
> 11.10 (`rtp`), 12.4 (`dtls`) — the WebRTC composition row below · PRD: FR-32 · D7, D12,
> D14, D15, D16

## Goal
The client-side traffic class every home capture is full of and almost no non-Wireshark
tool names: game servers and their query/handshake protocols. Two Tier-1 picks chosen for
being genuinely parseable (documented framing, strong magics) *and* enormously widespread —
Valve's server-query protocol answers for thousands of games built on Source/GoldSrc, and
Minecraft is the best-selling game in history with a community-documented wire protocol.
The Tier-2 table is where the honesty lives: most consumer realtime (Zoom, Discord voice,
console networks) is proprietary-and-encrypted, and this file says so per row rather than
pretending coverage.

## Specification

**a2s** (Valve Source engine server queries — the Valve Developer Community wiki's
"Server queries" page; *no standards body*, Valve's wiki is the de facto spec).

| Item | Spec |
|---|---|
| Claims | `UdpPort(27015)` — **claim-honesty note**: the conventional default game port, not an assignment; servers run anywhere in the 27000s and beyond. The probe covers the rest, `wireguard`'s dual-admission split (11.5) |
| Probe | First 4 bytes `0xFFFFFFFF` (single-packet header) and byte 5 a known query/reply type (`T`/`U`/`V`/`A`/`I`/`E`/`m`) → high; first 4 bytes `0xFFFFFFFE` (split-packet header) → moderate (envelope-only parse) |
| Fields | `Keys`: `app` (shared, constant `Str("a2s")`) · `Structural`: `packet_kind` (single/split), `query_type` (Str — A2S_INFO `T`/A2S_PLAYER `U`/A2S_RULES `V`/challenge `A`/info-reply `I`/GoldSrc info `m`) · `Full` (info reply): `server_name` (Str), `map` (Str), `game` (Str), `players`, `max_players`, `vac_enabled` (Bool) |
| Hint | `Terminal`; split packets parse the split header (id, total, number) then stop — no cross-packet reassembly (D7) |
| Identity | key `[{app, None}]`, one child per UDP stream |
| Rollups | `Sample` on `server_name`, `game`; `Accumulate` on `map` (map rotation observed across a capture); `Series` on `players` (population over time — the one place a game-server capture has a genuinely interesting time series) |

**minecraft** (Minecraft: Java Edition protocol — community-documented at wiki.vg /
minecraft.wiki's protocol pages; *no open standard*, Mojang does not publish one, and the
community documentation is the citation per D14's no-open-standard clause).

| Item | Spec |
|---|---|
| Claims | `TcpPort(25565)` |
| Fields | `Keys`: `app` (shared, constant `Str("minecraft")`) · `Structural`: `packet_len` (VarInt), `packet_id` (VarInt — the two VarInt reads are bounded to 5 bytes each, malformed continuation declines) · `Full` (pre-encryption handshake/status/login phases only): Handshake (0x00, first client packet) → `protocol_version` (VarInt — maps to a game version), `server_address` (Str — the hostname the client typed, SNI's gaming cousin), `next_state` (1 status ping/2 login); Status response → `json_len` (the SLP JSON is identified and counted, not parsed); Login Start → `player_name` (Str) |
| Hint | `Terminal` — online-mode servers negotiate encryption after Login Start (D12: everything past the encryption-response boundary is opaque); offline-mode play traffic is unencrypted but its packet vocabulary is version-dependent and out of v1 scope (`packet_id` envelope only, stated) |
| Identity | key `[{app, None}]`, one child per TCP session |
| Rollups | `Sample` on `player_name`, `server_address`, `protocol_version` — who connected, to which vhost, on which game version: the complete attribution ask |

### Planned (Tier 2 — not yet specified)
| Protocol | Standard | Note |
|---|---|---|
| RakNet (Minecraft Bedrock) | *Project doc* — RakNet source/community docs | `UdpPort(19132)`; the 16-byte offline-message magic (`00 ff ff 00 fe fe fe fe fd fd fd fd 12 34 56 78`) is probe gold — strongest promotion candidate here |
| ENet | *Project doc* (enet.bespin.org) | UDP reliability layer under many indie/game engines; no fixed port |
| KCP | *Project doc* | UDP ARQ layer, common in Asian-market games and some VPNs; weak externals, honesty write-up needed |
| Steam Remote Play / in-home streaming | *Proprietary* (Valve) | Discovery on `UdpPort(27036)` is recognizable; the streams themselves are encrypted (D12 ceiling ≈ nothing) |
| Zoom media transport | *Proprietary* — no public spec | UDP 8801–8810; encrypted; named so "why is this row absent" has an answer |
| Discord voice | *Semi-documented* (developer docs) | WebRTC-derived: negotiated UDP + encrypted RTP — lands as composition below |
| Nintendo/PSN/Xbox Live transports | *Proprietary* | Placed for taxonomy honesty: identifiable at best by endpoints, not by wire format |
| WebRTC session (composition) | RFC 8825 family (8831 data channels) | **Not a plugin** — a capture-level composition of already-specified pieces: `stun` (11.8) + `dtls` (12.4) + SRTP/`rtp` (11.10, D15-invisible media) + SCTP-over-DTLS (11.6 + D12). Row exists to state that "WebRTC support" is the sum of those specs, not a new claim |

## Acceptance criteria
- [ ] `a2s` fixture: A2S_INFO challenge/response round trip parses query types and every
      info-reply field exactly, on 27015 via the claim and on 27045 via the probe (both
      admission paths); a split-packet reply parses its envelope then stops (D7).
- [ ] `a2s` probe honesty: DNS, QUIC, and random UDP payloads score `None`/low against the
      `0xFFFFFFFF` probe (the all-ones prefix must not be treated as sufficient without a
      valid type byte).
- [ ] `minecraft` fixture: handshake → status ping (SLP) parses
      `protocol_version`/`server_address`/`next_state` exactly; a login fixture extracts
      `player_name` and then stops at the encryption boundary (D12 criterion, tested on a
      real online-mode capture).
- [ ] `minecraft` VarInt bounds: 5-byte-max enforcement tested at the boundary (valid
      5-byte VarInt parses; 6-byte continuation declines, no loop) — fuzz target
      registered alongside DNS's (06.6 precedent).
