# 11.6 — Transport extensions: SCTP, QUIC (invariants)

> Task: [11 Standard library](README.md) · Depends on: 02–06 · PRD: FR-31 (D6's "QUIC... later" arrives here) · D7, D12, D13, D14

## Goal
Two more transport-layer session shapes: SCTP's multi-homed, multi-stream association
(TCP-shaped enough to reuse the lifecycle pattern), and QUIC's connection-ID-addressed,
mostly-encrypted transport (governed entirely by D12's handshake/metadata boundary).

## Specification

**sctp** (RFC 9260, obsoletes RFC 4960).

| Item | Spec |
|---|---|
| Claims | `IpProtocol(132)` |
| Fields | `Keys`: `src_port`, `dst_port` · `Structural`: `verification_tag`, `first_chunk_type` · `Full` (only when `first_chunk_type` ∈ {INIT, INIT-ACK}): `initiate_tag`, `a_rwnd`, `num_outbound_streams`, `num_inbound_streams`, `initial_tsn` |
| Hint | `Terminal` — an SCTP packet may bundle multiple chunks; only the **first** chunk is parsed (D7-consistent stance, same honesty as BGP/DNS's "first message only" in this task and 06.6) |
| Probe | none — like UDP (06.4), an 8-byte-ish common header with a plausible-looking verification tag is not distinguishable enough to guess safely; explicit `IpProtocol(132)` routing only |
| Identity | key `[{src_port, dst_port}]`, `EndpointSort` → **SCTP association** |
| Rollups | `Accumulate` on `first_chunk_type` (the TCP-flags-accumulate precedent, 06.4) |

Lifecycle (`LifecycleSpec`, same coarseness stance as TCP's, 06.4 — association bookkeeping,
not a retransmission-correct state machine):

```text
initial: "new"
new          --INIT(initiator)-->              init_sent
init_sent    --INIT-ACK(responder)-->           cookie_wait
cookie_wait  --COOKIE-ECHO(initiator)-->        cookie_echoed
cookie_echoed--COOKIE-ACK(responder)-->         established
new          --DATA/any non-INIT-->             established_midstream
established* --SHUTDOWN-->                      shutdown_pending
shutdown_pending--SHUTDOWN-ACK+SHUTDOWN-COMPLETE--> closed
any          --ABORT-->                         aborted
closed_states: ["closed", "aborted"]
```

**quic** (RFC 8999 invariants; RFC 9000/9001 for context only — this plugin never implements
transport or crypto, purely the invariant-level framing D12 permits).

| Item | Spec |
|---|---|
| Claims | `UdpPort(443)` — shared, contested space with HTTP/3-over-QUIC negotiation and arbitrary-port deployments; **claim-honesty note** matching `wireguard` (11.5): the static claim covers the common case, `probe()` covers the rest |
| Fields | **Long header only**, `Keys`: `dcid` (Bytes, variable length, 0–20 — the declared flow key, so 01.3's flow-key floor puts it at `Keys`, not `Full` as an earlier draft of this row said) · `Structural`: `header_form` (Long/Short), `fixed_bit` · **Long header only**, `Full`: `version` (U64), `scid` (Bytes, variable length), `packet_type` (Initial/0-RTT/Handshake/Retry, derived from the type bits + `version`) |
| Hint | `Terminal` unconditionally — even a Long-header Initial packet's frame contents sit behind QUIC's mandatory header protection (a lightweight but real cryptographic step RFC 9001 requires even before TLS keys exist); this plugin does not remove header protection, so there is nothing further to route to, ever. Short-header (1-RTT) packets carry no invariant-guaranteed fields beyond `header_form`/`fixed_bit` at all |
| Probe | `fixed_bit == 1` and (Long header: `header_form==1` and `version` is a value that has ever been assigned, or is the reserved-for-negotiation pattern `0x?a?a?a?a`) → 50, the `MIN_CONFIDENCE` floor itself (03.3) — QUIC's invariants are thin, an honest reflection of how little is guessable, and this is as low as a probe can score while still being able to win a fallback-pool route at all; below the floor it would be discarded outright (the same "dead weight" note 11.8's `tls` entry states explicitly) and this domain's own acceptance criterion (a genuine Initial packet on a non-standard port must be admitted) would be unmeetable |
| Identity | key `[{dcid, None}]` (Long-header packets only) — one QUIC stream per destination connection id observed. **Known v1 limitation, documented not hidden**: QUIC connections may migrate to a new connection ID mid-session (RFC 9000 §5.1.1); a post-migration DCID forms a new sibling stream rather than folding into the pre-migration one, the same shape as ESP's per-direction-SPI note (11.5) — a protocol-level identifier rotation the plugin can observe but not reconcile without decrypting NEW_CONNECTION_ID frames it has no access to |
| Short-header packets and `key_errors` | A 1-RTT packet has no `dcid` to extract, so 05.1's key build fails and the aggregator skips the layer, incrementing its `key_errors` total (05.2). That is the correct *stream* outcome — bytes still land on the parent UDP stream, and inventing an empty-DCID key would fold every 1-RTT packet of every connection into one bogus node — but it means an ordinary HTTPS-over-QUIC capture drives `key_errors` up on the majority of its packets, since 1-RTT is where a QUIC session spends nearly all of its life. `key_errors` is otherwise a "plugin contract violation" signal, so a reader must not treat a non-zero count as a bug when `quic` is in the capture. Separating "this packet legitimately carries no key" from "the plugin declared a key it failed to produce" would need a third `flow_key` outcome in 05.1; not attempted here, but this row is why it's worth having |
| Rollups | `Accumulate` on `packet_type` (Initial/0-RTT/Handshake/Retry mix seen for this DCID — the handshake's shape, without its content) |

### Planned (Tier 2 — not yet specified)
| Protocol | Standard | Note |
|---|---|---|
| DCCP | RFC 4340 | `IpProtocol(33)` |
| MPTCP options | RFC 8684 | Rides inside TCP's own `options` field (06.4) — a refinement of the existing `tcp` plugin's `Full`-tier extraction, not a new claimed route |

## Acceptance criteria
- [x] `sctp` fixture walks a full association lifecycle (INIT/INIT-ACK/COOKIE-ECHO/
      COOKIE-ACK/DATA/SHUTDOWN sequence) hitting every named state, mirroring 06.4's TCP
      lifecycle criterion exactly.
- [x] `sctp` multi-chunk-bundle fixture: only the first chunk's type/fields are asserted;
      no attempt to walk a second bundled chunk (explicit non-goal, tested not just stated).
- [x] `quic` fixtures: Initial, 0-RTT, Handshake, Retry Long-header packets parse
      `dcid`/`scid`/`packet_type` exactly; a Short-header packet stops `Terminal` with no
      fields beyond `header_form`/`fixed_bit`. (`src/quic.rs`)
- [x] `quic` connection-migration fixture (same connection, DCID changes mid-capture)
      produces two sibling streams under the same parent UDP stream — proves the documented
      limitation is real and bounded, not a crash or a silently wrong fold.
      (`tests/transport.rs::quic_connection_migration_produces_sibling_streams`)
- [x] `quic` probe honesty: random UDP payload on port 443 scores low/`None`; a genuine
      QUIC Initial packet is probe-admissible, and `parse()` on those bytes is identical
      whichever path admits them (the claimed-port route or the fallback pool) — proven the
      same way `wireguard`/`dnp3` do (11.5/11.13), since `Hint::Candidates` (`udp.rs`) only
      ever opens the fallback pool via `Hint::Unknown`, never for a genuinely unclaimed port
      pair (03.4's gate). (`src/quic.rs` probe tests;
      `tests/transport.rs::quic_claim_path_and_probe_admitted_path_parse_identically`)
