# 12.9 — Media, streaming & P2P: RTMP, BitTorrent peer wire, BitTorrent DHT

> Task: [12 Contrib library](README.md) · Depends on: 02–06 · PRD: FR-32 · D7, D14, D15, D16

## Goal
Consumer-scale media and peer-to-peer traffic — high-volume, instantly recognizable in any
home/ISP capture, and (for BitTorrent) the task's showcase of probe-only admission: a
protocol with **no honest static claim at all**, identified purely by its handshake
signature.

## Specification

**rtmp** (Adobe's RTMP specification, December 2012 — Adobe-published; *no standards
body*).

| Item | Spec |
|---|---|
| Claims | `TcpPort(1935)` |
| Fields | `Keys`: `app` (shared, constant `Str("rtmp")`) · `Structural`: handshake → `handshake_stage` (C0+C1/S0+S1+S2 recognized by the version byte 3 and 1536-byte block shape); chunks → `fmt`, `chunk_stream_id`, `type_id` (1 Set Chunk Size/4 User Control/5 Window Ack Size/8 Audio/9 Video/18 AMF0 Data/20 AMF0 Command/...), `msg_stream_id` · `Full` (type 20 only): `command` (Str — the leading AMF0 string: `connect`/`createStream`/`play`/`publish`/`FCPublish`/...; one AMF string read, never an object-graph walk — 11.14's bounded-depth stance) |
| Hint | `Terminal` (audio/video chunk payloads are content, D7) |
| Identity | key `[{app, None}]`, one child per TCP session |
| Rollups | `Accumulate` on `command`; `Accumulate` on `type_id` (the session's audio/video/control mix) |

**bittorrent** (peer wire protocol, BEP-3 — bittorrent.org; the BEP series is the de facto
standard, *no standards body*).

| Item | Spec |
|---|---|
| Claims | **none** — the conventional 6881–6889 range is neither assigned nor honored by modern clients; a static port claim would be dishonest (the claim-space honesty rule, task 11 README). Probe-only admission |
| Probe | Payload begins `\x13BitTorrent protocol` (pstrlen 19 + exact literal) → maximal confidence — a 20-byte magic is as strong as probe signals get |
| Fields | `Keys`: `info_hash` (Bytes 20) · `Structural`: `reserved` (Bytes 8 — the extension bits: BEP-10 flag et al.) · `Full`: `peer_id` (Bytes 20 — client fingerprint) |
| Hint | `Terminal` |
| Identity | key `[{info_hash, None}]` — one child per torrent per TCP session; the same `info_hash` across many peer sessions is the cross-parent fold that the merged view (05.7/D10) exists for |
| Rollups | `Sample` on `peer_id` |
| Honesty | Only handshake packets are reachable: post-handshake message traffic (length-prefixed choke/interested/piece/...) has no signature a probe can honestly score high, so those packets stop at the transport layer — the D15-shaped "architecturally invisible continuation" documented up front, not discovered later |

**bt_dht** (Mainline DHT, BEP-5 — KRPC over bencoded UDP; bittorrent.org, *no standards
body*).

| Item | Spec |
|---|---|
| Claims | **none** — the DHT runs on each client's arbitrarily chosen UDP port. Probe-only |
| Probe | Payload begins `d` (bencode dict) and a bounded top-level scan finds key `y` with value `q`/`r`/`e` and key `t` → high; the scan never recurses into nested values (bounded by the same discipline as 11.14 `redis`'s top-level-only walk) |
| Fields | `Keys`: `app` (shared, constant `Str("bt_dht")`) · `Structural`: `msg_kind` (Str: query/response/error), `transaction_id` (Bytes) · `Full` (queries): `query` (Str — `ping`/`find_node`/`get_peers`/`announce_peer`), `node_id` (Bytes 20, from the arguments dict's `id` key when present at top level of `a`) |
| Hint | `Terminal` |
| Identity | key `[{app, None}]`, one child per UDP stream |
| Rollups | `Accumulate` on `query` |

### Planned (Tier 2 — not yet specified)
| Protocol | Standard | Note |
|---|---|---|
| µTP | BEP-29 | BitTorrent's UDP transport — the DHT's sibling; version/type nibbles + connection id give a workable probe |
| BitTorrent extension protocol | BEP-10 | Rides the peer wire post-handshake — blocked on the same reachability ceiling documented above |
| SRT | *Not yet an RFC* — Haivision's published spec (draft-sharabayko-srt) | Live-video contribution transport, UDP |
| Icecast/SHOUTcast source | *Project docs* | HTTP-shaped on arbitrary ports; mostly an 11.8 `http` refinement |
| RTMPS / RTMPT | Adobe | TLS-/HTTP-tunneled RTMP — D12/11.8 territory respectively; named so the taxonomy shows the variants were placed, not forgotten |

## Acceptance criteria
- [ ] `rtmp` fixture: C0C1/S0S1S2 handshake then `connect` + `createStream` + `play`
      command sequence parses exactly; an audio/video chunk yields envelope fields only.
- [ ] `bittorrent` fixture: a real handshake on an arbitrary high port is admitted via the
      fallback pool and forms an `info_hash`-keyed stream; two peer sessions sharing an
      `info_hash` produce two children whose keys are equal (the merged-view precondition,
      09.1 kit).
- [ ] `bittorrent` probe honesty: post-handshake piece traffic on the same port scores
      `None`/low and stops at transport (the documented ceiling, tested end-to-end); random
      payloads never score.
- [ ] `bt_dht` fixture: `ping` and `get_peers` query/response pairs parse exactly; a
      deeply-nested malicious bencode value terminates the bounded scan cleanly (fuzz
      target registered alongside DNS's, 06.6 precedent).
