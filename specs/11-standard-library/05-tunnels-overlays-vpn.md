# 11.5 — Tunnels, overlays & VPN: IPsec ESP/AH, WireGuard, L2TPv3, PPPoE (+PPP), Geneve

> Task: [11 Standard library](README.md) · Depends on: 02–06 · PRD: FR-31 · D7, D12, D13, D14

## Goal
Encryption-boundary tunnels (ESP, WireGuard — governed by D12) alongside cleartext-framed
ones (AH, L2TPv3, PPPoE, Geneve) that nest a full inner stack with zero aggregator
special-casing, extending 06.5's GRE/VXLAN precedent.

## Specification

**esp** (IPsec ESP, RFC 4303).

| Item | Spec |
|---|---|
| Claims | `IpProtocol(50)` |
| Fields | `Keys`: `spi` (U64) · `Structural`: `sequence` (U64) · `Full`: none — everything past the 8-byte header (ciphertext, padding, pad-length, next-header) is encrypted; there is no next-header field to read in cleartext |
| Hint | `Terminal` (D12: identify, don't guess past encryption — ESP has no plaintext next-protocol signal at all, unlike AH below) |
| Identity | key `[{spi, None}]` (shared qualifier, GRE-key/VXLAN-VNI shape). Because ESP's SPI is **unidirectional** (each direction of a security association picks its own SPI), the two directions of one IPsec tunnel naturally form two sibling `esp` streams under the same parent IP conversation (D10's parent-scoped node identity) rather than one folded stream — this is correct ESP semantics, not a modeling gap |
| Rollups | `Accumulate` on `sequence`? No — `Sample` on `sequence` (first/last observed, a coarse liveness/replay-window signal without trying to be a security tool) |

**ah** (IPsec AH, RFC 4302) — unlike ESP, AH authenticates but does not encrypt, so its
`next_header` field is genuinely readable and routes onward.

| Item | Spec |
|---|---|
| Claims | `IpProtocol(51)` |
| Fields | `Keys`: `spi` (U64) · `Structural`: `next_header`, `payload_len`, `sequence` (U64) · `Full`: `icv` (Bytes, integrity check value, length derived from `payload_len`) |
| Hint | `Route(IpProtocol(next_header))` — AH is transparent to what it protects |
| Identity | key `[{spi, None}]`, same unidirectional-SPI shape as `esp` |

**wireguard** (no RFC — canonical spec is the WireGuard whitepaper, wireguard.com/papers).
App-stream pattern (06.6): message-type rollups on top of the UDP stream, no separate
endpoint scheme (the handshake's ephemeral `sender_index`/`receiver_index` values are
per-session identifiers, not stable endpoint identity worth keying on).

| Item | Spec |
|---|---|
| Claims | `UdpPort(51820)` — **claim-honesty note**: 51820 is WireGuard's *conventional* default, not an IANA-assigned port; real deployments commonly run on arbitrary ports. The static claim covers the common case; `probe()` below covers the rest |
| Fields | `Keys`: `app` (shared `KeyField`, `b: None`, constant `Str("wireguard")`) · `Structural`: `msg_type` (Handshake-Initiation/Handshake-Response/Cookie-Reply/Transport-Data) · `Full`: `sender_index`/`receiver_index` (U64, present per type) |
| Hint | `Terminal` — every message type's payload past the fixed header is either a cryptographic handshake field or encrypted transport data, never a further protocol |
| Probe | `msg_type` byte ∈ {1,2,3,4}, reserved bytes are zero, total length matches the fixed size for that type exactly → 50; lets non-default-port deployments still land in the fallback pool honestly, rather than only working on port 51820 |
| Identity | key `[{app, None}]`, one `wireguard` child stream per UDP stream |
| Rollups | `Accumulate` on `msg_type` (handshake lifecycle mix observed) |

**l2tpv3** (RFC 3931) — v1 scope is the **data-message path** (the actual pseudowire being
tunneled); control messages (tunnel/session setup AVPs) are identified but not decoded, an
explicit, honestly-flagged limitation rather than a silent gap.

| Item | Spec |
|---|---|
| Claims | `UdpPort(1701)`, `IpProtocol(115)` (RFC 3931 §4.1 allows direct IP encapsulation too, no UDP header) |
| Fields | `Structural`: `t_bit` (control vs. data) · **data path** (`t_bit == 0`) `Keys`: `session_id` (U64) · **control path** (`t_bit == 1`) `Structural`: `control_connection_id` (U64) |
| Fields (data path, Full) | `cookie` (Bytes) **only if present** — cookie length (0/32/64 bits) is negotiated out-of-band during control-channel setup and isn't visible in the data header itself; v1 assumes the common zero-length-cookie default and documents this as a known limitation rather than guessing a length |
| Hint | data path → `ByProtocol("ethernet")` (the pseudowire payload — L2TPv3's dominant real-world use is carrying Ethernet); control path → `Terminal` (AVP walk is Tier 2) |
| Identity | data path: key `[{session_id, None}]`; control path: None |

**ppp** (RFC 1661) — PPPoE session payload is PPP with HDLC framing/FCS already stripped
(RFC 2516 §4.4: the payload starts directly at PPP's Protocol field), so this plugin only
ever needs to handle that trimmed shape.

| Item | Spec |
|---|---|
| Claims | `Custom{space:"ppp_protocol", id: 0x0021}` .. handled via `ByProtocol` dispatch from `pppoe`, not a route claim of its own (see `pppoe`'s Hint row) |
| Fields | `Structural`: `protocol` (U64, the 1–2 byte PPP Protocol field, re-emitted for readers) |
| Hint | `protocol == 0x0021` → `Route(EtherType(0x0800))`; `protocol == 0x0057` → `Route(EtherType(0x86DD))` — a **translation**, not a reuse: `Hint::Route` only requires the *target* `RouteId` to be real, not that the plugin's own header literally contained that numeric value (unlike GRE/Geneve's coincidental reuse below). This lets `ppp` route into the existing `ipv4`/`ipv6` plugins with **zero changes to their `claims()`** (06.3 untouched); anything else (LCP/PAP/CHAP control protocols, `0xC021`/`0xC023`/`0xC223`) → `Terminal`, Tier 2 |
| Identity | None — a translation layer, like `llc` (11.1) |

**pppoe** (RFC 2516) — two phases sharing one 6-byte header shape.

| Item | Spec |
|---|---|
| Claims | `EtherType(0x8863 /* Discovery */)`, `EtherType(0x8864 /* Session */)` |
| Fields | `Structural`: `version`, `type`, `code`, `session_id` · `Full` (Discovery only, `code` ∈ {PADI 0x09, PADO 0x07, PADR 0x19, PADS 0x65, PADT 0xa7}): tag walk — `service_name` (Str), `ac_name` (Str), `host_uniq` (Bytes) |
| Hint | `code == 0x00` (Session data) → `ByProtocol("ppp")`; else (Discovery) → `Terminal` |
| Identity | key `[{session_id, None}]` — one PPPoE session stream per `session_id`, parenting the `ppp ▸ ipv4/ipv6 ▸ ...` inner stack |

**geneve** (RFC 8926) — like GRE, its `protocol_type` field *is* an EtherType value by
protocol design (no translation table needed, unlike `ppp` above).

| Item | Spec |
|---|---|
| Claims | `UdpPort(6081)` |
| Fields | `Keys`: `vni` (U64, 3 bytes) · `Structural`: `version`, `opt_len`, `o_bit`, `c_bit`, `protocol_type` · `Full`: `options` (Bytes, raw — `opt_len × 4` bytes, length-bounded, TLV contents not decoded in v1) |
| Hint | `Route(EtherType(protocol_type))` — the GRE precedent (06.5), Geneve's own flavor |
| Identity | key `[{vni, None}]`, the VXLAN precedent (06.5) |
| Rollups | `Accumulate` on `protocol_type` |

Resulting hierarchies (normative fixtures, extending 06.5's table):

```text
ESP:      eth ▸ ipv4 ▸ esp                              (opaque past the ESP header, D12)
AH:       eth ▸ ipv4 ▸ ah ▸ tcp                          (AH is transparent, unlike ESP)
L2TPv3:   eth ▸ ipv4 ▸ udp ▸ l2tpv3 ▸ ethernet ▸ ...      (pseudowire, full inner stack)
PPPoE:    eth ▸ pppoe ▸ ppp ▸ ipv4 ▸ ...                  (translation hint, no claims change)
Geneve:   eth ▸ ipv4 ▸ udp ▸ geneve ▸ ipv4 ▸ ...          (EtherType reuse, GRE's pattern)
```

### Planned (Tier 2 — not yet specified)
| Protocol | Standard | Note |
|---|---|---|
| MPLS-in-IP | RFC 4023 | `IpProtocol(137)`; MPLS label stack itself is also relevant to 11.4-adjacent traffic-engineering analysis |
| Teredo | RFC 4380 | IPv6-in-UDP-in-IPv4 |
| 6in4 / 6to4 | RFC 3056 | `IpProtocol(41)` — currently claimed by `ipv6` itself (06.3) as a bare route; a dedicated 6in4 identity is a v2 refinement |
| OpenVPN | *No RFC* — OpenVPN project protocol doc | Heuristic identification only; format is intentionally not fully published |
| NSH | RFC 8300 | Service function chaining header |

## Acceptance criteria
- [ ] `esp`/`ah` fixtures: AH correctly routes to its inner transport layer; ESP stops
      `Terminal` at the encryption boundary with no fabricated inner stream (D12/PRD §4.B.4
      "no phantom streams" applied to a real encrypted-tunnel case, not just encrypted UDP).
- [ ] `wireguard` fixtures cover all four message types on both the default port (static
      claim) and a non-default port (probe-based fallback-pool admission) — both must reach
      the same plugin and produce the same parsed fields.
- [ ] `l2tpv3` data-path fixture nests a full inner Ethernet stack under the `session_id`
      stream; control-path fixture stops `Terminal` without misinterpreting AVPs as data.
- [ ] `pppoe ▸ ppp ▸ ipv4` fixture proves the translation-hint mechanism end-to-end with
      the **unmodified** 06.3 `ipv4` plugin (no `claims()` diff in that file) — the specific
      claim this domain makes about zero-touch reuse.
- [ ] `geneve` fixture mirrors 06.5's VXLAN two-VNIs-one-outer-stream test.
- [ ] All five hierarchies above asserted node-by-node, same rigor as 06.5's acceptance
      criteria.
