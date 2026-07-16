# 11.7 — Security, auth & directory: TLS, SSH, RADIUS, Kerberos, LDAP

> Task: [11 Standard library](README.md) · Depends on: 02–06 · PRD: FR-31 (D6's "TLS... later" arrives here) · D7, D12, D13, D14

## Goal
The enterprise auth backbone (RADIUS, Kerberos, LDAP) plus the two protocols D12 exists for
(TLS, SSH). Two of these (Kerberos, LDAP) are ASN.1/BER-encoded — the first protocols in
either task where full field decoding would mean shipping a BER/DER decoder. v1 scope for
both is deliberately narrow: cheap, tag-level framing fields only, named as an explicit
boundary rather than attempted-and-wrong deep decoding.

## Specification

**tls** (RFC 8446 TLS 1.3, RFC 5246 TLS 1.2) — app-stream pattern (06.6): TLS's identity is
its TCP session.

| Item | Spec |
|---|---|
| Claims | `TcpPort(443)` |
| Probe | record `content_type` ∈ {20,21,22,23} and `record_version` is a plausible TLS version (`0x03,0x00..=0x03,0x04`) and the record `length` is consistent with the buffer → 55. (The score must clear `MIN_CONFIDENCE` = 50 — the floor below which the router discards a probe (03.3) — or the probe can never win a fallback-pool route and is dead weight; a valid content type plus a plausible version plus a length check is a specific-enough signal that random bytes almost never pass, which the 09.1 kit's rule 5 verifies.) TLS runs on many ports beyond 443 (993, 995, 465/587, 636, 3389, ...) and some of those only switch to TLS mid-session via STARTTLS — a plaintext-then-upgrade transition this single-packet plugin **cannot** detect (no session state, contract rule 5). The static claim plus probe covers "TLS from the first byte"; STARTTLS upgrade is an explicit, documented v1 gap, not silently unhandled |
| Fields | `Keys`: `app` (shared, constant `Str("tls")`) · `Structural`: `content_type`, `record_version`, `handshake_type` (ClientHello=1/ServerHello=2/..., only when `content_type==22`), `sni` (Str, ClientHello server_name extension) · `Full` (ClientHello only): `alpn` (List of Str), `cipher_suites` (List of U64); (ServerHello only): `selected_cipher_suite` (U64), `tls_version_selected`. **`sni` is a `Structural` field, not `Full`**, so the `sni` rollup populates in the default (`Structural`) view rather than only under `--depth full` — the same placement `dns` gives its rollup field `qname` (06.6/11.11). |
| Hint | `Terminal` — `ApplicationData` records (`content_type==23`) are opaque (D12); intermediate handshake records past ServerHello (Certificate, KeyExchange, Finished) are recognized by `content_type`/`handshake_type` but not decoded further in v1 |
| Identity | key `[{app, None}]`, one `tls` child stream per TCP session |
| Rollups | `Sample` on `sni` (first/last SNI seen — flags a session that renegotiates, the analytic payoff for otherwise-opaque HTTPS); `Accumulate` on `handshake_type` (the handshake shapes the session went through). (`selected_cipher_suite`/`tls_version_selected` stay per-packet `Full` fields, **not** rollups: they appear only in the ServerHello while `sni` appears only in the ClientHello — no single record carries both, and the 09.1 kit's rule 3 requires every declared rollup field on every canonical good sample. `sni`+`handshake_type` co-occur on a ClientHello.) |

**ssh** (RFC 4251 architecture, RFC 4253 transport) — app-stream pattern. Scope is narrowed
to exactly what RFC 4253 guarantees is cleartext: the identification banner exchange, and
each side's first binary packet (`SSH_MSG_KEXINIT`, always message code 20 by protocol
definition, RFC 4253 §7.1). Everything after key exchange is ciphertext, including the
packet-length framing itself under common cipher modes — so this plugin does not attempt to
track "are we still in cleartext" across packets (no session state); it recognizes exactly
these two shapes and declines everything else.

| Item | Spec |
|---|---|
| Claims | `TcpPort(22)` |
| Fields | `Keys`: `app` (shared, constant `Str("ssh")`) · `Structural`: `banner` (Str, present only when the packet starts with ASCII `"SSH-"`) *or* `msg_type` (present only when, after the binary packet-length prefix, the first payload byte is exactly `20`) · `Full` (KEXINIT only): `kex_algorithms`, `server_host_key_algorithms`, `encryption_algorithms_client_to_server`, `encryption_algorithms_server_to_client`, `mac_algorithms_client_to_server` (all List of Str) |
| Hint | `Terminal` |
| Decline case | Any packet matching neither shape (i.e., genuinely encrypted post-KEX traffic) → `ParseError`, the same honest "port claimed, bytes weren't ours" outcome 06.6 documents for non-DNS traffic on port 53 |
| Identity | key `[{app, None}]`, one `ssh` child stream per TCP session |
| Rollups | `Sample` on `banner` (client and server version strings — a real fingerprinting signal for security review) |

**radius** (RFC 2865 auth, RFC 2866 accounting).

| Item | Spec |
|---|---|
| Claims | `UdpPort(1812)`, `UdpPort(1813)` (current IANA ports; legacy 1645/1646 are Tier 2 — see below) |
| Fields | `Keys`: `app` (shared, constant `Str("radius")`) · `Structural`: `code` (Access-Request/Accept/Reject/Challenge, Accounting-Request/Response), `identifier` · `Full`: attribute walk — `user_name` (Str, attr 1), `nas_ip_address` (Bytes,4, attr 4), `calling_station_id` (Str, attr 31), `acct_status_type` (U64, attr 40, accounting only) |
| Hint | `Terminal` |
| Identity | key `[{app, None}]`, one `radius` child stream per UDP stream (NAS↔server) |
| Rollups | `Accumulate` on `code`; `Sample` on `user_name` |

**kerberos** (RFC 4120) — ASN.1/DER-encoded; v1 reads only the outer APPLICATION tag (which
directly encodes msg-type per Kerberos's own convention) and the DER length, not the ticket
contents. Full field decoding (principal names, realm, encrypted parts) needs a real ASN.1
decoder — named as a Tier 2 dependency, not attempted here as a partial TLV walk the way
this task's other TLV-based protocols are.

| Item | Spec |
|---|---|
| Claims | `UdpPort(88)`, `TcpPort(88)` |
| Fields | `Keys`: `app` (shared, constant `Str("kerberos")`) · `Structural`: `msg_type` (from the outer ASN.1 APPLICATION tag number: AS-REQ=10/AS-REP=11/TGS-REQ=12/TGS-REP=13/AP-REQ=14/AP-REP=15/ERROR=30), `der_length` (U64, BER/DER short- or long-form length) |
| Hint | `Terminal` |
| Identity | key `[{app, None}]`, one `kerberos` child stream per UDP/TCP stream |
| Rollups | `Accumulate` on `msg_type` |

**ldap** (RFC 4511) — same BER-framing-only scope as `kerberos`.

| Item | Spec |
|---|---|
| Claims | `TcpPort(389)` — LDAPS (port 636) is LDAP fully wrapped in TLS; since `tls` stops at the encryption boundary (D12), LDAPS traffic correctly shows as an opaque `tls` child stream with no `ldap` grandchild — that is accurate, not a gap |
| Fields | `Keys`: `app` (shared, constant `Str("ldap")`) · `Structural`: `message_id` (U64, BER INTEGER), `protocol_op` (from the `protocolOp` CHOICE's APPLICATION tag: bindRequest=0/bindResponse=1/unbindRequest=2/searchRequest=3/searchResEntry=4/searchResDone=5/...) · `Full` (bindRequest only, best-effort): `bind_dn` (Str) — LDAP's BER encoding places the DN octet-string at a fixed position right after the version INTEGER for simple-auth binds, so it's locatable without a general ASN.1 walk; anything requiring CHOICE/SET traversal (search filters, attribute lists, SASL credentials) is out of v1 scope |
| Hint | `Terminal` |
| Identity | key `[{app, None}]`, one `ldap` child stream per TCP session |
| Rollups | `Accumulate` on `protocol_op`; `Sample` on `bind_dn` |

### Planned (Tier 2 — not yet specified)
| Protocol | Standard | Note |
|---|---|---|
| TACACS+ | RFC 8907 (informational) | Cisco AAA, encrypts the body by default (a shared-secret XOR scheme, not TLS) |
| Diameter | RFC 6733 | Cross-referenced at 11.15 for telco AAA (S6a/Gx) |
| NTLM | *No open standard* — Microsoft [MS-NLMP] Open Specification | Windows challenge/response auth |
| IKEv2 | RFC 7296 | IPsec's key-management companion to 11.5's `esp`/`ah` |
| RADIUS legacy ports | RFC 2865 (historical) | `UdpPort(1645)`, `UdpPort(1646)` — pre-IANA-assignment ports still seen in older deployments |

## Acceptance criteria
- [x] `tls` fixtures: ClientHello (with SNI+ALPN+cipher list) and ServerHello parse exactly;
      an ApplicationData record stops `Terminal` with no handshake fields beyond the
      per-record `content_type`/`record_version` envelope.
- [ ] `ssh` fixtures: both banner lines and both KEXINIT packets parse exactly; a synthetic
      "encrypted-looking" packet on port 22 declines with `ParseError` rather than
      misreading ciphertext as a message type (the port-claim-honesty criterion, ported from
      06.6's DNS case).
- [x] `radius` fixture covers a full Access-Request/Access-Accept exchange plus one
      Accounting-Request; app-stream child forms under the UDP stream.
- [ ] `kerberos` fixture: AS-REQ/AS-REP/TGS-REQ/TGS-REP each parse `msg_type` exactly from
      real captures; DER long-form length (>127 bytes) tested alongside short-form.
- [ ] `ldap` fixture: bindRequest (DN extracted), searchRequest, and unbindRequest each parse
      `protocol_op` exactly; a fixture with a compound/nested BER structure the plugin isn't
      meant to walk (a complex search filter) still parses `message_id`/`protocol_op`
      correctly and simply omits fields it doesn't attempt (no crash, no wrong guess).
- [ ] `kerberos`/`ldap` DER length-decoding has a truncation test at the short/long-form
      boundary (length byte `0x7f` vs `0x81` vs `0x82`).
