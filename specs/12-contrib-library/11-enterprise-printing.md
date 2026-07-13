# 12.11 — Enterprise services & printing: IPP, LPD, Git pack protocol

> Task: [12 Contrib library](README.md) · Depends on: 02–06 · Cross-refs: 11.8 (`http` —
> IPP's carrier) · PRD: FR-32 · D7, D14, D16

## Goal
Office and infrastructure services every enterprise (and most homes — every CUPS install
speaks two of these) runs without thinking about: print protocols spanning three decades,
and the git daemon that still moves a surprising amount of source. Small, well-framed,
high-recognition-value protocols.

## Specification

**ipp** (encoding RFC 8010, semantics RFC 8011 — IPP/1.1 and 2.x).

| Item | Spec |
|---|---|
| Claims | `TcpPort(631)` |
| Fields | `Keys`: `app` (shared, constant `Str("ipp")`) · `Structural`: `http_method` (Str — IPP rides HTTP POST; the request line and headers are consumed as this plugin's framing on port 631, the same inline-framing call as `rdp`'s TPKT, 12.6 — 11.8's `http` keeps port 80, no contest), `version` (Str, e.g. `"2.0"`), `operation_id` (requests — 0x0002 Print-Job/0x0004 Validate-Job/0x0005 Create-Job/0x0006 Send-Document/0x0008 Cancel-Job/0x0009 Get-Job-Attributes/0x000A Get-Jobs/0x000B Get-Printer-Attributes) or `status_code` (responses), `request_id` · `Full` (operation-attributes group, bounded walk): `printer_uri` (Str), `job_name` (Str, when present) — document data after the attribute groups is content (D7) |
| Hint | `Terminal` |
| Identity | key `[{app, None}]`, one child per TCP session |
| Rollups | `Accumulate` on `operation_id`; `Sample` on `printer_uri` |
| Honesty | The IPP body must begin in the same segment as the HTTP headers, else `Truncated` — the 11.8 header-block criterion applied to a wrapped protocol |

**lpd** (RFC 1179 — Line Printer Daemon).

| Item | Spec |
|---|---|
| Claims | `TcpPort(515)` |
| Fields | `Keys`: `app` (shared, constant `Str("lpd")`) · `Structural`: `command` (first byte — 1 print-waiting-jobs/2 receive-job/3 queue-state-short/4 queue-state-long/5 remove-jobs; within receive-job, subcommands 1 abort/2 control-file/3 data-file) · `Full`: `queue` (Str, the command's operand up to LF), `agent`/`job_list` for remove-jobs |
| Hint | `Terminal` (control/data file contents are content, D7) |
| Identity | key `[{app, None}]`, one child per TCP session |
| Rollups | `Accumulate` on `command`; `Sample` on `queue` |

**git** (Git pack protocol / pkt-line framing — the Git project's
`gitprotocol-pack(5)`/`gitprotocol-common(5)` documentation; *no standards body*).

| Item | Spec |
|---|---|
| Claims | `TcpPort(9418)` (git daemon). Smart-HTTP and SSH transports are 11.8/11.7
territory respectively (D12 for the latter) — this claim is the cleartext daemon only |
| Fields | `Keys`: `app` (shared, constant `Str("git")`) · `Structural`: `pkt_len` (the 4-hex-digit length prefix; `0000` flush-pkt recognized), `pkt_count` (complete pkt-lines in this segment) · `Full` (request pkt only): `service` (Str — `git-upload-pack`/`git-receive-pack`/`git-upload-archive`), `repo_path` (Str), `host` (Str, from the `\0host=` extra parameter), `protocol_version` (from a `version=2` extra parameter when present) |
| Hint | `Terminal` — ref advertisements parse as pkt-lines structurally; packfile data is content (D7) |
| Identity | key `[{app, None}]`, one child per TCP session |
| Rollups | `Sample` on `service`, `repo_path` — "who fetched/pushed which repo" is the entire ask |

### Planned (Tier 2 — not yet specified)
| Protocol | Standard | Note |
|---|---|---|
| SVN (svnserve) | *Project doc* — Subversion's `protocol` document | `TcpPort(3690)`; s-expression-framed |
| HP JetDirect / raw-9100 | *No standard* — de facto | `TcpPort(9100)`; deliberately structureless (raw PDL bytes) — the entry would mostly *name* the traffic, which is still worth something on a print VLAN |
| CUPS browsing | *Project doc* (OpenPrinting CUPS) | `UdpPort(631)` — the UDP sibling of `ipp`'s TCP claim |
| WHOIS | RFC 3912 | `TcpPort(43)`; trivially simple, high fixture value |
| Finger | RFC 1288 | `TcpPort(79)`; legacy but beloved of CTF captures |
| AJP13 | *Project doc* — Apache Tomcat AJPv13 | `TcpPort(8009)` — the reason that port is contested space (12.9/12.10 notes); `0x1234`/`AB` magics per direction |
| FastCGI | *Project doc* — Open Market FastCGI spec 1.0 | Conventional `TcpPort(9000)` collides with ClickHouse's convention (12.7) — a claim-space honesty write-up comes with promotion |
| rsync daemon | *(placed in 11.9's Tier 2 — listed here only as a cross-reference, per the D16 disjointness rule)* | |

## Acceptance criteria
- [ ] `ipp` fixture: Get-Printer-Attributes and Print-Job requests plus their responses
      parse `operation_id`/`status_code`/`printer_uri` exactly; a POST whose IPP body
      starts in a later segment yields `Truncated`, not a wrong parse.
- [ ] `lpd` fixture: a receive-job session (command 2, control-file + data-file
      subcommands) parses exactly; queue name extracted; file contents in no field.
- [ ] `git` fixture: a real `git-upload-pack` request pkt-line parses service/path/host
      exactly; flush-pkt (`0000`) handled; a malformed hex length declines cleanly
      (fuzz-adjacent boundary, tested).
- [ ] All three app-stream children form correctly under their TCP sessions (06.6 pattern).
