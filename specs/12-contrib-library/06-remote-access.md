# 12.6 — Remote access & desktop: Telnet, RFB/VNC, RDP, X11

> Task: [12 Contrib library](README.md) · Depends on: 02–06 · PRD: FR-32 · D7, D12, D14, D16

## Goal
Interactive remote-access sessions — the traffic a network analyst most wants *named and
attributed* (who connected where, with what client, negotiating what security), and where
D7's metadata-only line does the most work: session content (keystrokes, screen data) is
never extracted, only the negotiation envelope around it.

## Specification

**telnet** (RFC 854; option negotiation RFC 855).

| Item | Spec |
|---|---|
| Claims | `TcpPort(23)` |
| Fields | `Keys`: `app` (shared, constant `Str("telnet")`) · `Structural`: `iac_count` (U64, IAC sequences in this segment), `data_len` (U64, non-IAC NVT bytes — counted, never captured: D7) · `Full`: `commands` (List — WILL/WONT/DO/DONT/SB per IAC), `options` (List of U64 — 1 Echo, 3 Suppress-Go-Ahead, 24 Terminal-Type, 31 NAWS, ...) |
| Hint | `Terminal` |
| Identity | key `[{app, None}]`, one child per TCP session |
| Rollups | `Accumulate` on `options` (the negotiated-capability fingerprint of the session) |

**rfb** (VNC — RFB protocol, RFC 6143).

| Item | Spec |
|---|---|
| Claims | `TcpPort(5900)` — **claim-honesty note**: display `:n` listens on 5900+n; only `:0` is claimed statically. The banner probe below admits the others via the fallback pool, the same split as 11.5's `wireguard` |
| Probe | Payload begins `"RFB "` + 11 more bytes matching the `xxx.yyy\n` version grammar → high |
| Fields | `Keys`: `app` (shared, constant `Str("rfb")`) · `Structural`: `protocol_version` (Str, e.g. `"3.8"`) · `Full`: `security_types` (List — 1 None, 2 VNC Auth, ...), ServerInit → `width`, `height`, `desktop_name` (Str) |
| Hint | `Terminal` |
| Identity | key `[{app, None}]`, one child per TCP session |
| Rollups | `Sample` on `desktop_name`; `Sample` on `protocol_version` |
| Honesty | Post-handshake message packets (FramebufferUpdate, KeyEvent, ...) are not reliably distinguishable per-packet without session state (D7 — the first byte is a small integer with no magic); v1 parses the handshake packets and declines the rest. Stated here exactly like `bittorrent`'s post-handshake note (12.9) |

**rdp** (*no open standard* — Microsoft [MS-RDPBCGR] Open Specification; framing per
TPKT RFC 1006 and X.224/COTP ITU-T X.224).

| Item | Spec |
|---|---|
| Claims | `TcpPort(3389)` |
| Fields | `Keys`: `app` (shared, constant `Str("rdp")`) · `Structural`: `tpkt_length`, `x224_type` (0xE0 Connection Request/0xD0 Connection Confirm/0xF0 Data) · `Full` (connection sequence only): `cookie_user` (Str, from `Cookie: mstshash=<user>`), `nego_type` (RDP Negotiation Request/Response), `requested_protocols` / `selected_protocol` (bitmask: standard RDP / TLS / CredSSP / CredSSP-EX) |
| Hint | `Terminal` — after the negotiation the session upgrades to TLS/CredSSP (D12); Data TPDUs carrying legacy non-TLS RDP are identified by envelope only |
| Identity | key `[{app, None}]`, one child per TCP session |
| Rollups | `Sample` on `selected_protocol`; `Sample` on `cookie_user` — "which user, which security level" is the entire forensic ask for RDP |
| Note | TPKT + X.224 are consumed inline as this plugin's framing (4 + 7 bytes), not split into their own plugins — 12.13's Tier-2 MMS names the same framing; if that promotes, extracting a shared `tpkt` plugin becomes its spec's call, not a retrofit forced here |

**x11** (X Window System protocol, version 11 — X.Org's published protocol specification;
*no IETF standard*).

| Item | Spec |
|---|---|
| Claims | `TcpPort(6000)` — display `:0`; higher displays (6001+) via probe, same stance as `rfb` |
| Probe | First byte `0x42` (`'B'`, MSB) or `0x6C` (`'l'`, LSB) + protocol-major-version 11 at the byte-order-appropriate offset → high |
| Fields | `Keys`: `app` (shared, constant `Str("x11")`) · `Structural`: `byte_order`, `protocol_major`, `protocol_minor` · `Full`: `auth_protocol` (Str, e.g. `"MIT-MAGIC-COOKIE-1"` — the name only, never the cookie data: D7 applied to credentials) |
| Hint | `Terminal` — post-setup request/reply traffic is the same per-packet ambiguity as `rfb`'s (opcodes are small integers); connection-setup packets only |
| Identity | key `[{app, None}]`, one child per TCP session |
| Rollups | `Sample` on `auth_protocol` |

### Planned (Tier 2 — not yet specified)
| Protocol | Standard | Note |
|---|---|---|
| SPICE | *No standard* — spice-space.org project protocol doc | `TcpPort(5930)` region; KVM/QEMU remote display |
| rlogin | RFC 1282 | `TcpPort(513)`; BSD r-command, terse first-packet format |
| rsh / rexec | *No RFC* — BSD manual pages are the closest doc | `TcpPort(514)`/`TcpPort(512)` — **note**: rsh's 514/tcp is disjoint from syslog's 514/udp (11.11); no collision, but worth stating |
| mosh | *No standard* — project paper/docs | UDP 60000–61000, fully encrypted (D12 ceiling ≈ nothing) and port-roaming (D15) — an honesty write-up more than a parser |
| TeamViewer | *Proprietary, undocumented* | Named for taxonomy completeness; heuristic-only if ever attempted |

## Acceptance criteria
- [ ] `telnet` fixture: a real login-negotiation capture parses IAC command/option
      sequences exactly; a segment of pure NVT data yields `data_len` only (no content
      retained — asserted, not assumed).
- [ ] `rfb` fixtures: version banner + security handshake + ServerInit parse exactly on
      5900; the same handshake on 5901 is admitted via the probe (both paths to the same
      plugin, wireguard's dual-admission criterion shape).
- [ ] `rdp` fixture: Connection Request (with mstshash cookie) / Connection Confirm
      (TLS selected) parse exactly; the subsequent TLS ClientHello on the same session is
      left to 11.7's `tls` claim-free (this plugin must not squat post-upgrade bytes).
- [ ] `x11` fixture: both byte orders' setup requests parse exactly (B and l fixtures);
      `auth_protocol` name extracted with cookie bytes verifiably absent from all fields.
