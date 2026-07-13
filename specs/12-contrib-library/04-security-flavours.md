# 12.4 — Security & auth flavours: DTLS, MACsec

> Task: [12 Contrib library](README.md) · Depends on: 02–06 · Cross-refs: 11.7 (`tls`
> field vocabulary), 12.8 (`coap` — coaps is DTLS on 5684) · PRD: FR-32 · D12, D14, D15, D16

## Goal
Two encryption envelopes the stdlib doesn't cover, one from each end of the stack: DTLS
(the datagram sibling of 11.7's TLS — WebRTC, CoAPs, CAPWAP) and MACsec (802.1AE hop-by-hop
link encryption). Both are D12 protocols through and through: the plugin's whole job is to
parse the plaintext envelope honestly and stop exactly where the ciphertext starts —
turning "unknown UDP noise" / "unknown EtherType" into named, stream-forming traffic.

## Specification

**dtls** (DTLS 1.2 RFC 6347; DTLS 1.3 RFC 9147).

| Item | Spec |
|---|---|
| Claims | `UdpPort(5684)` (coaps — IANA-assigned, DTLS is legitimately the outer layer there). **Claim-honesty note:** there is no universal DTLS port — WebRTC negotiates its media ports out-of-band (D15, the same architectural invisibility as RTP), CAPWAP wraps DTLS on its own ports (12.2 Tier 2). The static claim covers coaps; `probe()` covers the rest |
| Probe | `content_type` ∈ {20 change_cipher_spec, 21 alert, 22 handshake, 23 application_data, 25 ack} **and** version bytes `0xFEFF` (1.0) / `0xFEFD` (1.2) at offset 1, with the record's declared length consistent with the datagram → high; DTLS 1.3's unified header (first byte `001xxxxx`) → moderate (structurally weaker signal, scored honestly lower) |
| Fields | `Keys`: `app` (shared, constant `Str("dtls")`) · `Structural`: `content_type`, `version`, `epoch`, `sequence_number`, `length` · `Full` (handshake records only, D12 ceiling — mirrors 11.7 `tls` field-for-field where the wire allows): `handshake_type` (ClientHello/ServerHello/HelloVerifyRequest/...), ClientHello → `sni` (Str), `alpn` (List of Str), `cipher_suite_count`; HelloVerifyRequest → `cookie_len` (the DTLS-specific stateless-retry step) |
| Hint | `Terminal` — epoch > 0 records are ciphertext; identified (`content_type` + `length`) but never parsed, exactly TLS's ApplicationData stance (D12) |
| Identity | key `[{app, None}]`, one `dtls` child per UDP stream |
| Rollups | `Sample` on `sni`; `Accumulate` on `content_type` |

**macsec** (IEEE 802.1AE-2018).

| Item | Spec |
|---|---|
| Claims | `EtherType(0x88E5)` |
| Fields | `Structural`: `tci_an` decomposed — `version` (V), `es`, `sc`, `scb`, `encrypted` (E bit, Bool), `changed` (C bit), `an` (association number, 2 bits) — plus `short_length`, `packet_number` · `Full`: `sci` (Bytes 8, present only when SC set — system identifier + port) |
| Hint | `encrypted == false` (integrity-only mode) → the secure-data field begins with the original inner EtherType: `Route(EtherType(inner))`, vlan's exact pattern (06.2) — the whole stack lights up under authenticated-but-cleartext MACsec with zero stdlib edits. `encrypted == true` → `Terminal` (D12: the boundary, stated per-mode rather than per-protocol — this plugin is the one place in the tree where D12's ceiling is a runtime bit, not a constant) |
| Identity | key `[{sci, None}]` when SCI is present (one stream per secure channel, VNI shape); identity-less otherwise (stats fold into the parent MAC conversation) |
| Rollups | `Accumulate` on `an` (key-rotation visibility: AN changes when the SAK rotates); `Sample` on `encrypted` |

### Planned (Tier 2 — not yet specified)
| Protocol | Standard | Note |
|---|---|---|
| RadSec | RFC 6614 | RADIUS/TLS, `TcpPort(2083)` — D12 ceiling is 11.7 `tls`'s fields; the RADIUS inside is never visible |
| DNS-over-TLS | RFC 7858 | `TcpPort(853)` — a `tls` claim refinement (app label + SNI), not a new wire format; needs 11.7's `tls` built first |
| kpasswd | RFC 3244 | `UdpPort(464)`/`TcpPort(464)`; Kerberos password-change, companion to 11.7's `kerberos` |
| Tor | *No standard* — Tor project spec (`tor-spec.txt`) | TLS-wrapped with deliberately unremarkable externals; heuristic identification only, and an honesty write-up is most of the work |
| OCSP | RFC 6960 | Rides HTTP — a refinement of 11.8's `http` (content-type dispatch), nothing routable of its own |

## Acceptance criteria
- [ ] `dtls` fixtures: a ClientHello (with SNI + ALPN) / HelloVerifyRequest / ServerHello
      exchange on 5684 parses exactly; an epoch-1 application-data record yields only
      `content_type`/`length` then stops `Terminal` (D12 boundary tested, not stated).
- [ ] `dtls` probe honesty: a genuine ClientHello on a random high port is admitted via the
      fallback pool; random UDP noise and a QUIC Initial packet both score low/`None`
      (the sibling-protocol confusion case named and tested).
- [ ] `macsec` integrity-only fixture routes to the inner `ipv4` through the unmodified
      stdlib; an encrypted fixture stops `Terminal` with `packet_number`/`sci` extracted —
      both E-bit arms proven.
- [ ] `macsec` SCI-keyed stream forms per secure channel; two ANs on one SCI fold into one
      stream whose `an` accumulation shows the rotation (09.1 kit).
