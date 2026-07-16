# 11.8 — Web & RPC: HTTP/1.1, HTTP/2, WebSocket, STUN/TURN

> Task: [11 Standard library](README.md) · Depends on: 02–06 · PRD: FR-31 · D7, D12, D13, D14

## Goal
The web stack, plus NAT-traversal (STUN/TURN — central to modern internet-facing/WebRTC
traffic, the reason they're Tier 1 despite being less familiar than HTTP). This domain has
the task's clearest examples of a real architectural ceiling: **protocol upgrades mid-TCP-
session** (h2c, WebSocket, STARTTLS at 11.7) are cases our stateless, per-packet routing
model cannot follow across packets — documented explicitly below rather than glossed over.

## Specification

**http** (RFC 9110/9112) — app-stream pattern (06.6). Per D7, no body reassembly: only the
request/status line and headers are parsed; the body is unparsed remainder.

| Item | Spec |
|---|---|
| Claims | `TcpPort(80)` |
| Fields | `Keys`: `app` (shared, constant `Str("http")`) · `Structural`: `is_request` (Bool), `method` (Str, request only), `status_code` (U64, response only), `version` (Str) · `Full`: `host` (Str), `content_type` (Str), `content_length` (U64), `user_agent` (Str, request only), `upgrade` (Str, from an `Upgrade:` header if present) |
| Header-block framing | `header_len` = offset of the blank-line (`CRLFCRLF`) terminator; not found within this segment ⇒ `Truncated{needed, have}` (D9) — headers split across TCP segments are a known, honestly-declined v1 gap (no reassembly, D7) |
| h2c handshake | If the packet's bytes begin with HTTP/2's fixed 24-byte connection preface (`"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"`, RFC 9113 §3.4), `header_len` is just those 24 bytes and the hint is `ByProtocol("http2")` — a direct-by-name dispatch (VXLAN's pattern, 06.5) that avoids `http2` needing its own claimed route at all (see below) |
| Hint | h2c preface → `ByProtocol("http2")`, as above; otherwise `Terminal` |
| Identity | key `[{app, None}]`, one `http` child stream per TCP session |
| Rollups | `Accumulate` on `method`; `Sample` on `host`. (`status_code` stays a per-packet `Structural` field, **not** a rollup: no single HTTP message carries both `method` and `status_code`, and the 09.1 kit's rule 3 requires every declared rollup field on every canonical good sample — so a rollup naming both cannot be validated. `method`+`host` co-occur on a request, the app-stream's canonical shape.) |

**http2** (RFC 9113) — reached only via `http`'s `ByProtocol` dispatch above, so it has no
`claims()` of its own (avoiding a route collision with `http` on the same port). **Known,
material v1 reachability limitation**: the overwhelming majority of real HTTP/2 traffic
negotiates via TLS ALPN (`"h2"`), never touching cleartext h2c — and `tls` stops at the
encryption boundary (D12), so this plugin's frame-level parsing is reachable only on the
niche cleartext-h2c deployment path. `tls`'s `alpn` field (11.7) still surfaces "this session
negotiated h2" as metadata even when frames stay opaque — that is the honest ceiling for
encrypted HTTP/2 in v1, not a gap in this plugin.

| Item | Spec |
|---|---|
| Claims | none (see above) |
| Fields | `Keys`: `stream_id` (U64) · `Structural`: `frame_type` (DATA/HEADERS/PRIORITY/RST_STREAM/SETTINGS/PUSH_PROMISE/PING/GOAWAY/WINDOW_UPDATE/CONTINUATION), `flags`, `length` · `Full` (SETTINGS only): `settings_entries` (List of Bytes, raw 6-byte id+value pairs, not individually decoded) |
| HPACK note | `HEADERS`/`CONTINUATION` frame bodies are HPACK-compressed (RFC 7541) with a **connection-scoped dynamic table** — decoding them needs state this contract's stateless plugins (rule 5, 02.1) don't carry. v1 extracts the frame envelope only (`stream_id`, `END_HEADERS`/`END_STREAM` flags), enough to track stream lifecycle without decoding header contents. Full HPACK decoding is a real Tier 2+ candidate, not a quick TLV walk |
| Hint | `Terminal` — only the first frame in a segment is parsed (the same "first message only" stance as `bgp`/`sctp`/DNS-over-TCP) |
| Identity | key `[{stream_id, None}]` (shared qualifier, GRE/VXLAN shape) → one stream per HTTP/2 stream id within the parent TCP session — visibility into multiplexed stream *counts* without decoding header content |
| Rollups | `Accumulate` on `frame_type` |

**websocket** (RFC 6455) — **known, material v1 reachability limitation, stated plainly**:
an `Upgrade: websocket` handshake is visible to `http` (captured in its `upgrade` field
above), but subsequent binary WS-framed packets on that same TCP session still route through
TCP's ordinary `Candidates(TcpPort)` path (06.4) back to whichever plugin claims that port
(`http`) — there is no session-scoped mechanism in this contract for "this TCP session
changed protocol at byte offset N." `http.parse()` would then decline (`ParseError`) on
binary WS frames it can't read as request/status lines. This is the same class of gap as
STARTTLS (11.7): **a protocol upgrade mid-session is invisible to per-packet, stateless
routing** — fixing it needs a session-scoped routing override, an aggregator-level feature
out of this task's scope, tracked as a v2 architectural question. The plugin below is
specified and fixture-tested at the frame-parsing level regardless (fed WS-frame bytes
directly, the same way any plugin's unit tests work, 09.1), and remains reachable in
practice wherever WebSocket runs on a port `http`/`https` doesn't already claim.

| Item | Spec |
|---|---|
| Claims | none — fallback-pool only |
| Fields | `Keys`: `app` (shared, constant `Str("websocket")`) · `Structural`: `fin`, `opcode` (continuation/text/binary/close/ping/pong), `mask_bit`, `payload_len` (U64, 7-bit/16-bit-extended/64-bit-extended forms) · `Full`: `masking_key` (Bytes,4, if masked) |
| Hint | `Terminal` |
| Probe | `opcode` ∈ {0,1,2,8,9,10} (defined values), RSV bits zero (the common no-extensions case), and the extended-length encoding is self-consistent with the remaining buffer → 50 |
| Identity | key `[{app, None}]`, one `websocket` child stream where reached |
| Rollups | `Accumulate` on `opcode` |

**stun** (RFC 8489) — **turn** (RFC 8656) is the *same message format*, extended with more
methods/attributes and no new header shape (RFC 8656 §5), so one plugin covers both,
disambiguated by `message_method`; the precedent is `ospf` unifying v2/v3 in 11.4.

| Item | Spec |
|---|---|
| Claims | `UdpPort(3478)`, `TcpPort(3478)` |
| Probe | `magic_cookie == 0x2112A442` (RFC 8489's fixed constant) → 95 — an unusually strong, near-unambiguous signal, so this plugin is also a good fallback-pool citizen on non-standard ports |
| Fields | `Keys`: `app` (shared, constant `Str("stun")`) · `Structural`: `message_class` (Request/Success-Response/Error-Response/Indication), `message_method` (Binding=0x001; TURN: Allocate=0x003/Refresh=0x004/Send=0x006/Data=0x007/CreatePermission=0x008/ChannelBind=0x009), `message_length` · `Full`: attribute walk — `xor_mapped_address` (Bytes, the NAT-discovered public address — STUN's whole point), `username` (Str, attr 0x0006), `error_code` (U64, attr 0x0009), and **TURN-specific**: `relayed_address` (Bytes, XOR-RELAYED-ADDRESS), `lifetime` (U64), `channel_number` (U64, ChannelBind) |
| Hint | `Terminal` |
| Identity | key `[{app, None}]`, one `stun` child stream per UDP/TCP stream (client↔STUN/TURN server) |
| Rollups | `Accumulate` on `message_class`; `Sample` on `xor_mapped_address` (the discovered public address — the actual analytic payoff for internet-facing/WebRTC traffic) |

### Planned (Tier 2 — not yet specified)
| Protocol | Standard | Note |
|---|---|---|
| gRPC (status extraction over h2) | *Not IETF* — grpc.io protocol spec | Same reachability ceiling as `http2` itself (mostly TLS-wrapped) |
| SOCKS5 | RFC 1928 | Proxy negotiation protocol |

## Acceptance criteria
- [x] `http` fixtures: GET/POST requests and 200/404/101 responses parse exactly;
      header-block-split-across-segments fixture yields `Truncated`, not a wrong parse.
- [ ] h2c fixture: a real HTTP/2 cleartext-upgrade capture dispatches `http ▸ http2` via
      `ByProtocol` with the connection preface consumed exactly as `http`'s `header_len`.
- [ ] `http2` fixture: SETTINGS, HEADERS (envelope only, no HPACK attempt), DATA frames parse
      exact expected envelope fields; one stream id per HTTP/2 stream verified across a
      multi-stream fixture (mirrors 06.5's two-VNIs test shape).
- [ ] `websocket` fixture fed frame bytes directly (bypassing routing, per the documented
      reachability limitation) parses text/binary/close/ping/pong frames exactly, masked and
      unmasked.
- [ ] `stun`/`turn` fixtures: a Binding Request/Response pair recovers the correct
      `xor_mapped_address`; a TURN Allocate/CreatePermission/ChannelBind sequence parses
      `relayed_address`/`channel_number` from the same plugin, no `turn`-specific claim
      needed (proves the "same format" design decision, not just states it).
- [ ] `stun` probe honesty: `magic_cookie` mismatch scores `None`/near-zero even with an
      otherwise plausible-looking header.
