# 11.9 — File & mail transfer: FTP, TFTP, SMTP, IMAP, POP3, SMB2/3, NFS

> Task: [11 Standard library](README.md) · Depends on: 02–06 · PRD: FR-31 · D7, D13, D14, D15

## Goal
Enterprise file sharing (SMB2/3, NFS) and the classic text command/response protocols
(FTP, SMTP, IMAP, POP3) that share one shape closely enough to name once: a **tagged
command/response pattern** — client sends a line-oriented command, server replies with a
status code/word plus text, both riding the app-stream pattern (06.6). Two of the seven
(FTP, and NFSv3 specifically) also hit D15's dynamic-port ceiling head-on; TFTP hits it for
its entire data phase.

## Specification

Shared shape for `ftp`/`smtp`/`imap`/`pop3`: `Keys`: `app` (shared, protocol-name constant)
· `Structural`: `is_request`/`command` (or `tag`+`command` for IMAP) on the request side,
`reply_code`/`status` on the response side · `Full`: the command argument / reply text as a
single `Str`. Per D7, none of these parse the data that follows a transfer-initiating command
(FTP's data channel, SMTP's `DATA` body, IMAP/POP3's message bodies) — that's payload, not
header.

**ftp** (RFC 959).

| Item | Spec |
|---|---|
| Claims | `TcpPort(21)` |
| Fields | as above; `command` ∈ {USER,PASS,RETR,STOR,PASV,PORT,...}, `reply_code` is the 3-digit numeric code |
| Data channel | **D15 applies directly**: the port `PASV`/`PORT` negotiates for the actual transfer is readable as a field (`arg`, the raw reply/command text) but the resulting data-channel session is not correlated back to this control stream or auto-routed to a data-plane plugin — it appears as an ordinary untagged TCP session in v1 |
| Hint | `Terminal` |
| Identity | key `[{app, None}]`, one `ftp` child stream per TCP session |
| Rollups | `Accumulate` on `command`. **`reply_code` stays a per-packet `Structural` field, not a rollup** — the same `http`/`sip` rule-3 constraint (11.8/11.10): no single line carries both `command` and `reply_code` |

**tftp** (RFC 1350).

| Item | Spec |
|---|---|
| Claims | `UdpPort(69)` |
| Fields | `Structural`: `opcode` (RRQ=1/WRQ=2/DATA=3/ACK=4/ERROR=5), `filename` (Str, RRQ/WRQ only), `mode` (Str, "octet"/"netascii") · `Full`: `block_num` (U64, DATA/ACK), `error_code`+`error_msg` (ERROR) |
| D15 applies directly | Only the initial `RRQ`/`WRQ` (client→port 69) is reachable via the static claim — the server's reply and every subsequent `DATA`/`ACK` packet uses a server-chosen ephemeral port on *both* sides, so neither the `Candidates([UdpPort(dst), UdpPort(src)])` check (06.4) nor any claimed route matches, and the gate stops rather than guessing. `DATA`/`ACK`/`ERROR` fields above are specified and fixture-tested by feeding bytes directly to `parse()`, but are **not reachable via routing** in v1 |
| Hint | `Terminal` |
| Identity | None — given the above, there is no multi-packet exchange this plugin ever actually observes in v1, so an identity declaration would be vacuous |

**smtp** (RFC 5321).

| Item | Spec |
|---|---|
| Claims | `TcpPort(25)` |
| Fields | as the shared shape; `command` ∈ {HELO,EHLO,MAIL,RCPT,DATA,QUIT,...} |
| Hint | `Terminal` — the `DATA` command's message body (terminated by a bare `.` line) is payload, not parsed (D7) |
| Identity | key `[{app, None}]`, one `smtp` child stream per TCP session |
| Rollups | `Accumulate` on `command`. **`reply_code` stays a per-packet `Structural` field, not a rollup** — the same `http`/`sip` rule-3 constraint (11.8/11.10): no single line carries both `command` and `reply_code` |

**imap** (RFC 9051 rev2 / RFC 3501 rev1) — the one member of this group with client-chosen
tags rather than a fixed status word.

| Item | Spec |
|---|---|
| Claims | `TcpPort(143)` |
| Fields | `Keys`: `app` (shared, constant `Str("imap")`) · `Structural`: `tag` (Str), `command` (Str: LOGIN/SELECT/FETCH/LOGOUT/...), `is_response` (Bool), `response_status` (Str: OK/NO/BAD, response only) · `Full`: `args` (Str, raw remainder of the line) |
| Hint | `Terminal` |
| Identity | key `[{app, None}]`, one `imap` child stream per TCP session |
| Rollups | `Accumulate` on `command` |

**pop3** (RFC 1939).

| Item | Spec |
|---|---|
| Claims | `TcpPort(110)` |
| Fields | as the shared shape; `command` ∈ {USER,PASS,STAT,RETR,DELE,QUIT,...}, `status` is `"+OK"`/`"-ERR"` |
| Hint | `Terminal` |
| Identity | key `[{app, None}]`, one `pop3` child stream per TCP session |
| Rollups | `Accumulate` on `command` |

**smb2** ([MS-SMB2] — *no open standard*; Microsoft's published Open Specification is the
closest authoritative document) — 64-byte fixed header, binary framing.

| Item | Spec |
|---|---|
| Claims | `TcpPort(445)` — the legacy SMB1 negotiation prefix (`0xFF 'SMB'`) is out of v1 scope; SMB1 is deprecated and declines cleanly as unrecognized bytes |
| Fields | `Keys`: `session_id` (U64) · `Structural`: `command` (Negotiate=0/SessionSetup=1/TreeConnect=3/Create=5/Close=6/Read=8/Write=9/...), `status` (U64), `flags` (U64 — response bit distinguishes request/response), `message_id` (U64) · `Full`: `tree_id` (U64), `file_id` (Bytes,16, present on Create response / Read/Write/Close requests) |
| Hint | `Terminal` — command-specific bodies (a `Create`'s filename, a `Read`/`Write`'s file data) are not parsed further in v1; file contents are explicitly out of scope (D7) |
| Identity | key `[{session_id, None}]` (shared qualifier) → one SMB2 session-stream per `session_id` **within the parent TCP session**. Real SMB sessions can span multiple TCP connections (multichannel); v1 scopes to per-TCP-session correlation only, the same honest ceiling as FTP's data channel — cross-TCP-session correlation isn't something this architecture does yet |
| Rollups | `Accumulate` on `command` |

**nfs** (RFC 1813 NFSv3, RFC 7530 NFSv4) — rides on ONC RPC (RFC 5531). App-stream pattern;
v1 reads only the RPC call/reply envelope, not credentials/verifiers or NFS arguments.

| Item | Spec |
|---|---|
| Claims | `UdpPort(2049)`, `TcpPort(2049)` — NFSv4's fixed, well-known port. **NFSv3 traditionally negotiates its actual port via portmapper/rpcbind (port 111)** — D15 applies: only NFS traffic on the fixed 2049 port (the common NFSv4 case) is reachable via static claim in v1 |
| Fields | `Keys`: `app` (shared, constant `Str("nfs")`) · `Structural`: `xid` (U64), `msg_type` (Call/Reply), `program` (U64, expect 100003), `program_version` (U64, 3 or 4), `procedure` (U64) |
| Full | none — RPC credentials/verifier (opaque, variable-length auth) and NFS's own per-procedure arguments are unparsed; NFSv4's `COMPOUND` (procedure 1, itself a nested list of sub-operations) is recognized as "this is a v4 compound call" via `procedure == 1` but its operation list is not walked — a real Tier 2 candidate needing its own nested-TLV spec, not a quick addition here |
| Hint | `Terminal` |
| Identity | key `[{app, None}]`, one `nfs` child stream per UDP/TCP stream |
| Rollups | `Accumulate` on `procedure` |

### Planned (Tier 2 — not yet specified)
| Protocol | Standard | Note |
|---|---|---|
| DCE/RPC | The Open Group C706 | SMB2's `Create`+named-pipe path often carries this; a natural companion to `smb2` |
| rsync | *No RFC* — protocol documented in rsync source/manual | |
| WebDAV | RFC 4918 | An HTTP method/header extension — likely a refinement of 11.8's `http` rather than a new plugin |

## Acceptance criteria
- [x] `ftp`/`smtp`/`imap`/`pop3` each have real-capture fixtures covering a full login +
      one representative command sequence; app-stream child forms correctly in every case.
      (`src/ftp.rs`, `src/smtp.rs`, `src/imap.rs`, `src/pop3.rs`) **Note:** `ftp`/`smtp` name
      both `command` and `reply_code` as rollups, but no single line carries both (a request
      has the former, a response the latter) — the same rule-3 constraint `http`/`sip`
      document for their own request/response field split (11.8/11.10); only `command` is a
      declared rollup in the shipped plugins.
- [x] `ftp` `PASV` response fixture: the negotiated port is visible in the parsed `arg`
      field, but no data-channel stream is fabricated or auto-linked (D15 criterion, tested
      not just asserted in prose). (`src/ftp.rs`, `tests/filemail.rs`)
- [x] `tftp` fixture: `RRQ` parses exactly via the static claim; a synthetic continuation
      `DATA`/`ACK` packet on an unclaimed ephemeral port is confirmed to **stop** at the
      transport layer with `StopReason::UnclaimedRoute`, not silently vanish or panic — the
      D15 gate behaving as designed, verified end-to-end. (`src/tftp.rs`, `tests/filemail.rs`)
- [ ] `smb2` fixture: Negotiate/SessionSetup/TreeConnect/Create/Read/Close sequence forms one
      session-id stream; `command` accumulate reflects the full operation mix.
- [ ] `nfs` fixture: an NFSv3 GETATTR/LOOKUP call+reply pair and an NFSv4 COMPOUND call parse
      their envelope fields exactly, with the COMPOUND op-list correctly left unparsed (no
      attempt, no crash).
