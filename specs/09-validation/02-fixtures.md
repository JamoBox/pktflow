# 09.2 — Fixture corpus

> Task: [09 Validation](README.md) · Depends on: 07.2 (replay) · PRD: §7 "synthetic multi-packet capture → expected streams"

## Goal
The shared test data: a programmatic packet builder for surgical synthetic cases, plus a
small curated set of real captures — each fixture paired with its expected outcome.

## Specification

**Synthetic builder** (`tests/support/builder.rs`, shared across crates per 00.1):

```rust
PacketBuilder::new(ts)                      // fluent, layer by layer
    .eth("aa:…", "11:…")
    .ipv4("10.0.0.5", "93.184.216.34")
    .tcp(52341, 443, flags::SYN, seq)
    .payload(n_bytes)
    .build() -> (PacketMeta, Vec<u8>)       // real wire bytes, checksums computed
CaptureBuilder::new().packet(…)… .write_pcap(path) / .into_mock_source()
```

Builds *actual wire-format bytes* (not mock structs) so fixtures exercise the real parse
path; writes pcap files for CLI-level tests and yields `MockSource` (07.1) for in-process
ones.

**Named synthetic fixtures** (each a function returning `CaptureBuilder` + an
`ExpectedStreams` assertion tree — the pairing is the point):

| Fixture | Proves |
|---|---|
| `bidi_tcp_session` | handshake→data→teardown; folding, lifecycle, initiator (05.x, 06.4) |
| `encrypted_udp_no_phantom` | the gate (03.4): unclaimed port 51820, zero phantom streams |
| `gre_nested` / `vxlan_nested` | tunnel hierarchies incl. asymmetric return path (06.5) |
| `dual_parent_ip` | same IP pair under two MAC pairs (D10, 05.3, `--merged`) |
| `dns_over_udp_session` | app-stream pattern + qname rollup (06.6) |
| `dhcp_dora` | order-sensitive series rollup (05.4) |
| `idle_eviction` / `lru_pressure` | D2 policies with packet-time clocks (05.6) |
| `qinq_stack` | innermost-wins context (01.4, 06.2) |
| `malformed_zoo` | truncations at every layer, bad IHL, fragment offsets, DNS pointer bomb |
| `mixed_stop_reasons` | one packet per `StopReason` variant (04.3, 08.4 goldens) |

**Real captures** (`fixtures/real/`, each < 1 MB, provenance + license noted in a README;
sources: self-captured lab traffic or public sample repositories with redistribution
allowed): one browsing session (eth/ip/tcp/dns mix), one DHCP exchange, one VXLAN overlay
sample, one capture with traffic the v1 set does not claim (QUIC) — the honest-unknowns
sample for D9 reporting.

Sourced from public repositories with redistribution explicitly permitted, rather than
self-captured traffic: `dhcp_dora.pcap` (DORA exchange), `vxlan_overlay.pcap` (VXLAN
tunnel), and — standing in for the single browsing-session fixture, since neither
project's corpus has one organic multi-protocol session under a permissive license —
`dns_lookup.pcap` + `http_transaction.pcap` as two genuine real captures, all four from
tcpdump's BSD-licensed test suite. `quic_unknown.pcap` (the honest-unknowns sample) is a
tshark-filtered, byte-unmodified slice of Wireshark's own GPLv2-licensed
`quic-with-secrets.pcapng` test capture — tcpdump's QUIC fixtures all use `DLT_NULL`
loopback framing, which pktflow's v1 entry points (Ethernet/Raw-IP only) don't route, so
they'd stop at layer zero rather than exercise the intended case. Full provenance,
license texts, and checksums in `fixtures/real/README.md`.

## Acceptance criteria
- [x] Builder produces byte-identical output across runs (checksums deterministic) and its
      pcap files open in Wireshark/tshark without warnings (sanity anchor for 09.3).
- [x] All named fixtures implemented with `ExpectedStreams` trees; used by ≥1 test each.
- [x] Real captures checked in with provenance README; total corpus < 5 MB.
