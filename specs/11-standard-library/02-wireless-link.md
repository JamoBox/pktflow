# 11.2 — Wireless link: 802.11 frame + radiotap, WPA2/WPA3 handshake

> Task: [11 Standard library](README.md) · Depends on: 02–06, 11.1 (`llc`, `eapol`) · PRD: FR-31 · D12, D13, D14

## Goal
A second link-layer entry point alongside Ethernet (06.2) — the home-network-relevant case
of a Wi-Fi capture. Proves `RouteId::LinkType` generalizes past DLT_EN10MB with zero engine
changes (03.1's `Custom`-free well-known variant already covers arbitrary DLTs).

**Capture-layer note:** offline replay of an `.pcap`/`.pcapng` file with
`DLT_IEEE802_11`/`DLT_IEEE802_11_RADIOTAP` works today against 07.1/07.2 unchanged — the
source abstraction maps whatever DLT the file declares. *Live* monitor-mode capture is not:
07's current interface model assumes a normal (non-monitor) capture device. That is a
capture-layer gap tracked as a follow-up to task 07, not a blocker for these plugins or their
fixture-based tests.

## Specification

**radiotap** — *no formal standards body*; canonical reference is the community spec at
radiotap.org.

| Item | Spec |
|---|---|
| Claims | `LinkType(127 /* DLT_IEEE802_11_RADIOTAP */)` |
| Fields | `Structural`: `it_version`, `it_len`, `it_present` (U64, first present bitmask word) · `Full`: `antenna_signal` (I64, dBm, if the corresponding present bit is set), `rate` (U64), `channel_freq` (U64) |
| Field walk | Present-word chain bounded (bit 31 of each word signals another follows; max 8 words), then fields read in the fixed order radiotap.org defines, each aligned to its own size — a misaligned/overrun read is `PluginError`, not a guess |
| Hint | `ByProtocol("dot11")` — radiotap always wraps an 802.11 frame (direct-by-name, same shape as VXLAN→ethernet, 06.5) |
| Probe | none (explicit entry via `LinkType`) |
| Identity | None — per-packet radio metadata, not conversation-bearing. A signal-strength trend *per link* would be a natural `Series` rollup, but 02.4 only allows a plugin to declare rollups on its own identity, and radiotap has none. Documented v1 stance (same shape as ARP's rollup gap, 06.3) — revisit only if attaching cross-plugin rollups to a neighboring layer's stream becomes a real ask. |

**dot11** (802.11 frame: management/control/data) — IEEE 802.11-2020.

| Item | Spec |
|---|---|
| Claims | `LinkType(105 /* DLT_IEEE802_11 */)` (raw, no radiotap) |
| Fields | `Keys`: `addr1` (Bytes,6 — RA), `addr2` (Bytes,6 — TA) · `Structural`: `frame_type`, `frame_subtype`, `flags` (U64 bitmask: to_ds/from_ds/more_frag/retry/pwr_mgt/more_data/protected/order), `duration`, `seq_num`, `addr3` (Bytes,6 — BSSID or DA depending on to-DS/from-DS) · `Full`: `addr4` (Bytes,6, WDS frames only), `qos_control`, and — **management frames only** (Beacon/Probe-Request/Probe-Response subtypes) — `ssid` (Str) read from the bounded information-element walk (Element ID 0) |
| Hint | `protected` flag set → `Terminal` (payload is encrypted at the 802.11 layer itself — D12's stance applied one layer down: identify, don't guess past opacity); management/control frames → `Terminal`; QoS-Null data (no body) → `Terminal`; else (ordinary data frame body) → `ByProtocol("llc")` — reuses 11.1's LLC/SNAP demux, so IP traffic and unprotected EAPOL (the WPA handshake, below) fall through the same path wired Ethernet uses |
| Probe | none (explicit entry via `LinkType`; radiotap-wrapped frames arrive by `ByProtocol`, also explicit) |
| Identity | key `[{addr1, addr2}]`, `EndpointSort` → the **over-the-air link** between two radios (AP↔STA), parent of whatever LLC/IP/EAPOL stack rides inside — the 802.11 sibling of Ethernet's MAC conversation (06.2) |
| Rollups | `Accumulate` on `frame_subtype` (mirrors ethernet's `ethertype` rollup, 06.2) |

**WPA2/WPA3 4-way handshake — not a separate plugin.** The EAPOL-Key messages that
negotiate session keys are ordinary *unprotected* 802.11 data frames (the `protected` flag
isn't set until keys are installed), carrying LLC/SNAP-encapsulated EtherType `0x888E` —
exactly 11.1's `eapol` plugin, unmodified. The resulting hierarchy:

```text
dot11 ▸ llc ▸ eapol            (Key messages 1-4, unprotected)
dot11                          (post-handshake data frames: protected=1 → Terminal)
```

This is the domain's demonstration that a well-designed demux layer (`llc`, 11.1) composes
across two different physical media without either side knowing about the other.

### Planned (Tier 2 — not yet specified)
| Protocol | Standard | Note |
|---|---|---|
| WPS | Wi-Fi Alliance WPS spec | Registrar/enrollee negotiation, EAP-WSC inner method |

## Acceptance criteria
- [x] `radiotap` fixtures across several present-word configurations parse to exact expected
      fields; a present-word chain forced past the 8-word bound declines cleanly.
- [x] `dot11` fixtures cover management (beacon with SSID extracted), control (ACK/RTS/CTS —
      `Terminal`, no body), and data (both protected and unprotected) subtypes.
- [x] 802.11 link stream forms on `{addr1, addr2}`, folds both directions on an
      AP↔STA exchange fixture (mirrors 06.2's MAC-conversation criterion).
- [x] Real 4-way-handshake fixture (radiotap ▸ dot11 ▸ llc ▸ eapol, unprotected) parses all
      four `Key` messages with exact `key_info`/`nonce` fields via the unmodified 11.1
      `eapol` plugin — proves the cross-medium composition claim above, not just asserts it.
- [x] A protected (post-handshake) data frame fixture stops at `dot11` with
      `StopReason::Terminal`, never attempting `llc` on encrypted bytes.

## Implementation notes
- `crates/pktflow-plugins/src/radiotap.rs` — walks the present-word chain (bounded to 8
  words) and the fixed-order field layout for bits 0-5 only (the fields this plugin names),
  each aligned to its own size from the start of the header, per radiotap.org. `header_len`
  is always the declared `it_len`, not however far the local field walk went — the walk is
  cross-checked to never claim to have read past it.
- `crates/pktflow-plugins/src/dot11.rs` — one MAC-header parse branching on frame
  type/subtype (management/control/data), all multi-octet fields read little-endian (802.11
  is LSB-first on the wire, unlike Ethernet/IP). `header_len` is the fixed address/sequence/QoS
  shape for control and data frames (the boundary `llc` starts from); for management frames —
  always `Hint::Terminal`, so nothing ever reads past this layer — the whole frame including
  the bounded SSID information-element walk is the header, same stance as CDP/LLDP/STP (11.1).
- Conformance-kit coverage (`tests/conformance.rs`) is deliberately a representative subset,
  not the full acceptance-criteria breadth: management frames read their entire remaining
  buffer as `Hint::Terminal` "header" with no required terminator, so a truncated prefix can
  legitimately still parse (a smaller, self-consistent `header_len`) — which the kit's
  truncation-sweep rule cannot distinguish from a lying plugin. ACK/CTS control frames carry
  no `addr2`, which the kit's flow-key-presence rule requires for every sample once a plugin
  declares a `{addr1, addr2}` identity. Both cases are exhaustively covered by `dot11.rs`'s own
  `#[cfg(test)]` module instead (matches `llc_conforms`'s existing precedent of a narrower
  kit subset plus full in-file breadth).
- `tests/wireless.rs` — the domain's cross-medium composition claim, exercised end to end via
  `Engine::dissect`/`Aggregator`: the 802.11 link stream fold, the real
  radiotap ▸ dot11 ▸ llc ▸ eapol chain for all four handshake messages, and the protected-frame
  stop.
