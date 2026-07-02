# 06.6 — Application: DNS, DHCP, NTP

> Task: [06 Plugins](README.md) · Depends on: 02–05 · PRD: FR-19 application "metadata rollups", §4.A DNS example · D7

## Goal
Application-layer metadata riding on transport streams: single-datagram parsing only (D7),
rollups doing the stream-level work — DNS query names observed in a UDP stream is the PRD's
own example.

## Specification

Common stance — the **app-stream pattern**: these protocols have no endpoint identity of
their own (their conversation *is* the transport stream), but rollups attach only via a
`StreamIdentity` (05.4). So each declares an identity whose key is a single *shared*
`KeyField` (02.4's `b: None` form) on a constant field the plugin always emits
(`"app" = Str("dns")` etc.). Result: exactly one child stream per transport stream carrying
that protocol — a clean home for rollups without inventing endpoint semantics. The pattern
is documented in `docs/adding-a-protocol.md` (06.1) as the standard recipe for
endpoint-less protocols that want rollups.

**dns** — `Claims: UdpPort(53), TcpPort(53)`. Over TCP, the 2-byte length prefix is
consumed; only the first message in a segment is parsed (D7 — no cross-segment reassembly;
`Truncated` if the message exceeds the segment, caught as a clean stop).

| Item | Spec |
|---|---|
| Fields | `Keys`: `app` · `Structural`: `id`, `is_response`, `opcode`, `rcode`, `qname` (Str, first question), `qtype` · `Full`: `answers` (List of Str, RDATA rendered for A/AAAA/CNAME/PTR; else type name), counts |
| Name decoding | compression-pointer loops bounded (max 64 jumps, pointers must go backward) — classic parser bomb, gets its own fuzz target (09.1) |
| Hint | `Terminal` |
| Rollups | `Accumulate` on `qname` (**the PRD §4.A example**), `Accumulate` on `rcode` |

**dhcp** — `Claims: UdpPort(67), UdpPort(68)`. Fields: `Keys`: `app` · `Structural`: `op`,
`msg_type` (from option 53), `xid`, `client_mac` · `Full`: `requested_ip`, `server_id`,
`hostname` (options 50/54/12). Options TLV walk with strict bounds; unknown options skipped.
Hint: `Terminal`. Rollups: `Series{cap:64}` on `msg_type` — the DORA sequence, order-sensitive
(05.4's motivating case); `Accumulate` on `client_mac`.

**ntp** — `Claims: UdpPort(123)`. Fields: `Keys`: `app` · `Structural`: `version`, `mode`,
`stratum` · `Full`: `ref_id`, timestamps as U64 raw. Hint: `Terminal`. Rollups: `Accumulate`
on `mode`, `Sample` on `stratum`.

Port-claim honesty note: claiming a port routes *all* traffic on it here, and non-DNS bytes
on port 53 will fail `parse` → `PluginError` stop (03.4 row 3). That is correct behavior:
counted, visible, no guessing.

## Acceptance criteria
- [ ] Real-capture fixtures for each (DNS query+response, full DORA, NTP client/server
      exchange) parse to exact expected fields and rollups.
- [ ] DNS compression-bomb and forward-pointer fixtures decline safely (no hang/panic);
      fuzz target registered.
- [ ] The app-stream pattern verified: one `dns` child stream under the UDP stream,
      `qname` accumulate populated across multiple queries (PRD use case: "DNS query names
      observed in a UDP stream").
- [ ] DHCP `msg_type` series preserves DORA order.
