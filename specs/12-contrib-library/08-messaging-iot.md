# 12.8 — Messaging & IoT: CoAP, XMPP, IRC, NATS, STOMP

> Task: [12 Contrib library](README.md) · Depends on: 02–06 · Cross-refs: 11.14 (`mqtt`
> topic-rollup pattern, `amqp` port coexistence) · PRD: FR-32 · D7, D12, D14, D16

## Goal
The messaging protocols beyond 11.14's broker trio: constrained-device request/response
(CoAP — this domain's UDP flavour), federated chat old and standardized (IRC, XMPP), and
two lightweight text-framed brokers (NATS, STOMP). The shared analytic move is 11.14's
`mqtt` topic pattern: accumulate the *subjects/destinations/paths* observed, never message
bodies.

## Specification

**coap** (RFC 7252).

| Item | Spec |
|---|---|
| Claims | `UdpPort(5683)` — coaps (5684) is DTLS's claim (12.4); a CoAP-over-DTLS payload is behind the D12 boundary and never reaches this plugin |
| Fields | `Keys`: `app` (shared, constant `Str("coap")`) · `Structural`: `version` (1), `type` (CON/NON/ACK/RST), `code` (Str, `class.detail` rendered — `0.01` GET/`0.02` POST/`2.05` Content/`4.04` Not Found/...), `message_id`, `token_len` · `Full`: options walk (delta-encoded, bounded) → `uri_path` (Str, `Uri-Path` segments joined `/`), `uri_host`, `content_format` |
| Hint | `Terminal` (payload after the `0xFF` marker is content, D7) |
| Identity | key `[{app, None}]`, one child per UDP stream |
| Rollups | `Accumulate` on `code`; `Accumulate` on `uri_path` (the resource-observed pattern — DNS's query-name rollup transposed to REST-ish IoT) |

**xmpp** (RFC 6120).

| Item | Spec |
|---|---|
| Claims | `TcpPort(5222)` (client-to-server), `TcpPort(5269)` (server-to-server) |
| Fields | `Keys`: `app` (shared, constant `Str("xmpp")`) · `Structural`: `stanza` (Str — leading-tag match: `stream:stream`/`message`/`presence`/`iq`/`auth`/`starttls`/`proceed`) · `Full`: `to`, `from` attributes (Str, when the attribute list is within this segment) |
| Hint | `Terminal` — after `<proceed/>` the session is TLS (D12); stanza bodies are content (D7). A segment starting mid-XML (no `<` at a stanza boundary) declines — no cross-segment reassembly, the 06.6 DNS-over-TCP honesty note applied to XML framing |
| Identity | key `[{app, None}]`, one child per TCP session |
| Rollups | `Accumulate` on `stanza` |

**irc** (RFC 1459 / RFC 2812).

| Item | Spec |
|---|---|
| Claims | `TcpPort(6667)` — 6697 is IRC-over-TLS (11.7 `tls`'s territory, not claimable here); other conventional ports (6660–6669) are Tier-2 territory |
| Fields | `Keys`: `app` (shared, constant `Str("irc")`) · `Structural`: `command` (Str — first line's command word or 3-digit numeric reply), `line_count` (U64, complete CRLF lines in this segment) · `Full`: `target` (Str, first parameter of PRIVMSG/NOTICE/JOIN/PART — channel/nick names are addressing metadata; message trailers are content and never extracted, D7) |
| Hint | `Terminal` |
| Identity | key `[{app, None}]`, one child per TCP session |
| Rollups | `Accumulate` on `command`; `Accumulate` on `target` (channels touched by the session) |

**nats** (NATS client protocol — nats.io documentation; *no standards body*).

| Item | Spec |
|---|---|
| Claims | `TcpPort(4222)` |
| Fields | `Keys`: `app` (shared, constant `Str("nats")`) · `Structural`: `op` (Str — INFO/CONNECT/PUB/HPUB/SUB/UNSUB/MSG/HMSG/PING/PONG/+OK/-ERR, case-insensitive per the protocol) · `Full`: `subject` (Str, PUB/SUB/MSG argument), `sid` (SUB/MSG), `payload_size` (declared byte count — counted, not captured) |
| Hint | `Terminal` |
| Identity | key `[{app, None}]`, one child per TCP session |
| Rollups | `Accumulate` on `op`; `Accumulate` on `subject` (the `mqtt` topic pattern, 11.14) |

**stomp** (STOMP 1.2 — stomp.github.io specification; *no standards body*).

| Item | Spec |
|---|---|
| Claims | `TcpPort(61613)` |
| Fields | `Keys`: `app` (shared, constant `Str("stomp")`) · `Structural`: `command` (Str — CONNECT/CONNECTED/SEND/SUBSCRIBE/UNSUBSCRIBE/ACK/NACK/BEGIN/COMMIT/ABORT/DISCONNECT/MESSAGE/RECEIPT/ERROR) · `Full`: `destination` header (Str) |
| Hint | `Terminal` (frame body after the blank line is content, D7; a frame not ending its NUL in this segment still yields command+headers if they fit — headers-first, the 11.8 `http` stance) |
| Identity | key `[{app, None}]`, one child per TCP session |
| Rollups | `Accumulate` on `command`; `Accumulate` on `destination` |

### Planned (Tier 2 — not yet specified)
| Protocol | Standard | Note |
|---|---|---|
| AMQP 1.0 | OASIS AMQP 1.0 / ISO/IEC 19464 | **Contested claim**: shares `TcpPort(5672)` with 11.14's `amqp` (0-9-1) — a completely different wire format on the same port. Promotion path is probe-based admission on the 8-byte protocol header `AMQP\x00\x01\x00\x00` (0-9-1's is `AMQP\x00\x00\x09\x01`), with the stdlib keeping the static claim (D16 claim precedence) |
| ZMTP (ZeroMQ) | *Project spec* — rfc.zeromq.org ZMTP 3.1 | No fixed port (D15-adjacent); signature `\xFF …\x7F` greeting is a strong probe |
| MQTT-SN | OASIS MQTT-SN 1.2 | UDP; no IANA port (conventionally 1884) — claim-honesty write-up needed |
| OMA LwM2M | OMA-TS-LightweightM2M | Rides CoAP — a `uri_path`-aware refinement of `coap`, not a new claim |
| Matter | CSA Matter specification | `UdpPort(5540)`; almost fully encrypted — D12 ceiling ≈ message-header flags only |
| SMPP | SMPP v3.4/v5.0 (SMS Forum) | `TcpPort(2775)`; SMS gateway traffic — telco-adjacent but broker-shaped |
| Apache Pulsar | *Project doc* — Pulsar binary protocol | `TcpPort(6650)`; length-prefixed protobuf commands |
| NSQ | *Project doc* (nsq.io) | `TcpPort(4150)`; `  V2` magic + size-prefixed frames |
| RabbitMQ Stream | *Project doc* | `TcpPort(5552)`; the third distinct wire protocol from one broker (after AMQP 0-9-1/1.0) — the taxonomy note writes itself |

## Acceptance criteria
- [ ] `coap` fixture: CON GET → ACK 2.05 exchange parses exactly including `uri_path`
      reassembled from multiple Uri-Path options; option-delta edge cases (13/14 extended
      deltas) and a malformed options walk (decline, no loop) tested.
- [ ] `xmpp` fixture: stream open + auth + message stanza sequence parses `stanza` exactly;
      post-STARTTLS bytes decline (D12 boundary); a mid-stanza continuation segment
      declines (no reassembly, tested).
- [ ] `irc` fixture: NICK/USER/JOIN/PRIVMSG/numeric-replies capture parses commands and
      targets exactly; trailer text verifiably absent from extracted fields.
- [ ] `nats` and `stomp` fixtures: connect + subscribe + publish/message round trips parse
      op/command and subject/destination exactly; both app-children form under their TCP
      sessions (06.6 pattern for all five plugins in this file).
