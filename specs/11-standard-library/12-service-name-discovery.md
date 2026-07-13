# 11.12 — Service & name discovery: mDNS, SSDP, LLMNR, NetBIOS-NS

> Task: [11 Standard library](README.md) · Depends on: 02–06, 06.6 (`dns`) · PRD: FR-31 · D13, D14

## Goal
Home/enterprise device and service discovery. Two members (mDNS, LLMNR) reuse DNS's exact
message wire format (RFC 1035) and so reuse `dns`'s (06.6) message-parsing routine directly;
NetBIOS-NS looks DNS-shaped at the header level but uses its own name encoding, so it doesn't
share code the same way; SSDP is HTTP-request/response syntax carried over UDP instead of
TCP, structurally closer to 11.8's `http` than to DNS.

## Specification

**mdns** (RFC 6762) — same message format as `dns` (RFC 1035); this plugin's `parse()`
**reuses `dns`'s message-parsing routine** (an internal code-sharing detail — `dns.rs`'s
name-decompression/question/RR-walk logic is called, not duplicated), adding only the two
mDNS-specific bit interpretations. This is an implementation detail, not a change to
`dns`'s own contract or fields — 06.6's spec is unaffected.

| Item | Spec |
|---|---|
| Claims | `UdpPort(5353)` |
| Fields | Same shape as `dns` (06.6): `Keys`: `app` · `Structural`: `id`, `is_response`, `opcode`, `rcode`, `qname`, `qtype` · `Full`: `answers` · plus mDNS-specific `Structural`: `is_multicast_query` (from the QU bit, top bit of the question's class field), `cache_flush` (from the top bit of an answer RR's class field) |
| Hint | `Terminal` |
| Identity | key `[{app, None}]` (shared, constant `Str("mdns")` — deliberately **not** reusing `dns`'s `"dns"` constant, since mDNS's local-network service namespace is semantically distinct from resolver-hierarchy DNS traffic) |
| Rollups | `Accumulate` on `qname` — mDNS's `_services._dns-sd._udp.local` service-type queries are the home-network-discovery payoff, the same PRD §4.A pattern `dns` demonstrates (06.6), applied to `.local` |

**ssdp** (*no ratified RFC* — draft-cai-ssdp-v1-03 expired; the UPnP Forum's *UPnP Device
Architecture* specification is the closest authoritative document) — HTTP request/response
syntax over UDP; structurally a cousin of 11.8's `http` (same "header block ends at
`CRLFCRLF`" framing idea) but its own plugin given the transport and verb-set differences.

| Item | Spec |
|---|---|
| Claims | `UdpPort(1900)` |
| Fields | `Keys`: `app` (shared, constant `Str("ssdp")`) · `Structural`: `method` (Str: `M-SEARCH`/`NOTIFY`, or `status_code` for the `HTTP/1.1 200 OK` search-response form), `nts` (Str, NOTIFY only: `ssdp:alive`/`ssdp:byebye`) · `Full`: `st` (Str, Search Target), `usn` (Str, Unique Service Name), `location` (Str, URL to the device's UPnP description XML) |
| Hint | `Terminal` |
| Identity | key `[{app, None}]`, one `ssdp` child stream per UDP stream |
| Rollups | `Accumulate` on `nts`; `Sample` on `location` (a real home-network device-inventory signal — the URL names the specific device) |

**llmnr** (RFC 4795) — same DNS message format again; reuses `dns`'s parsing routine
identically to `mdns` above. RFC 4795 §2.1.1 keeps the 16-bit flags word at the exact bit
offsets RFC 1035 defines but repurposes two of them: the position DNS gives `AA` (bit 10,
mask `0x0400`) becomes the **`C` (conflict)** bit, and the position DNS gives `RD` (bit 8,
mask `0x0100`) becomes the **`T` (tentative)** bit — the same "reuse the wire position, change
the semantics" move `mdns` makes on the class field's top bit (§5.4/§10.2), applied here to
the flags word instead. Per §2.1.1/§4.1/§7.1: `C` set on a response means the responder has
detected the queried name is not unique on the link (a sender already treating the query as
answered should still keep watching for a late `C`-set response, since conflict detection is
best-effort); `T` set on a response means the responder is authoritative for the name but has
not yet finished verifying its own uniqueness (RFC 4795 says such a response is normally
discarded by the receiver, except when it's itself a uniqueness probe, in which case `T` set
signals a conflict). Both are read-only surfaced bits — this plugin does not implement sender
conflict-resolution behavior (§4.1), only exposes what's on the wire.

| Item | Spec |
|---|---|
| Claims | `UdpPort(5355)` |
| Fields | Same shape as `dns`/`mdns`: `Keys`: `app` · `Structural`: `id`, `is_response`, `opcode`, `rcode`, `qname`, `qtype`, plus LLMNR-specific `Structural`: `conflict` (the `C` bit, RFC 4795 §7.1), `tentative` (the `T` bit, RFC 4795 §7.1) · `Full`: `answers` |
| Hint | `Terminal` |
| Identity | key `[{app, None}]` (shared, constant `Str("llmnr")`) |
| Rollups | `Accumulate` on `qname` |

**netbios_ns** (RFC 1001 §14 encoding, RFC 1002 §4.2 message format) — the header shape
echoes DNS's (id/flags/counts), but NetBIOS names use their own 16-byte "first-level"
encoding (RFC 1001 §14.1), not DNS label compression — **not** shared with `dns`'s parser;
this plugin owns its own name decoder.

| Item | Spec |
|---|---|
| Claims | `UdpPort(137)` |
| Fields | `Structural`: `opcode`, `nm_flags`, `rcode`, `question_count`, `answer_count` · `Full`: `name` (Str, decoded via the NetBIOS first-level encoding), `name_type` (U64, the encoded name's 16th byte — workstation/server/domain-master/... suffix), `rr_type` (NB=0x0020/NBSTAT=0x0021) |
| Hint | `Terminal` |
| Identity | key `[{app, None}]` (shared, constant `Str("netbios_ns")`) |
| Rollups | `Accumulate` on `name` |

### Planned (Tier 2 — not yet specified)
| Protocol | Standard | Note |
|---|---|---|
| WS-Discovery | OASIS WS-Discovery standard | SOAP/XML-over-UDP, enterprise device discovery (printers, ONVIF cameras) |

## Acceptance criteria
- [ ] `mdns`/`llmnr` fixtures parse identically to equivalent `dns` fixtures for the shared
      fields, proving the reused-routine claim (same test vectors through both call paths
      where the wire bytes are format-identical) plus their own extra bits/fields correctly.
- [ ] `ssdp` fixtures cover M-SEARCH, NOTIFY (`ssdp:alive` and `ssdp:byebye`), and a search
      response; `location` extracted exactly.
- [ ] `netbios_ns` fixture decodes a real first-level-encoded name (the classic
      `"FACFCEECFCEFFCFGEFGEFCCACACACACA"`-style 32-char encoded form) to its correct
      plaintext NetBIOS name and type suffix.
- [ ] Each plugin's app-stream child stream forms correctly under its UDP stream (06.6
      pattern), with `qname`/`name`/`st` accumulation verified across a multi-message
      fixture per protocol.
