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
| Fields | `Keys`: `dcid` (Bytes, variable length, 0–20; **Long header only** — promoted ahead of `Structural` from this domain's original draft specifically because it is the identity key, matching every other flow-key field in this codebase — `esp`'s SPI, `gre`'s key, `vxlan`'s VNI — all of which are surfaced starting at `Depth::Keys`, never `Full`, per the 09.1 kit's mechanical rule that key fields must exist at ≥ `Keys`) · `Structural`: `header_form` (Long/Short), `fixed_bit` (both header forms) · **Long header only**, `Full`: `version` (U64), `scid` (Bytes, variable length), `packet_type` (Initial/0-RTT/Handshake/Retry, derived from the type bits + `version`; recognizes QUICv1 RFC 9000 §17.2 and QUICv2 RFC 9369 §3.2's permuted mapping — any other version, including the version-negotiation marker `version==0`, yields `version`/`dcid`/`scid` honestly with no `packet_type` guess) |
| Hint | `Terminal` unconditionally — even a Long-header Initial packet's frame contents sit behind QUIC's mandatory header protection (a lightweight but real cryptographic step RFC 9001 requires even before TLS keys exist); this plugin does not remove header protection, so there is nothing further to route to, ever. Short-header (1-RTT) packets carry no invariant-guaranteed fields beyond `header_form`/`fixed_bit` at all |
| Probe | `fixed_bit == 1` and (Long header: `header_form==1` and `version` is a value that has ever been assigned, or is the reserved-for-negotiation pattern `0x?a?a?a?a`) → `MIN_CONFIDENCE` (50). Set at exactly the router's own admission floor rather than below it (an earlier draft of this row said 40): a probe that can never clear `MIN_CONFIDENCE` never actually admits a non-standard-port deployment to the fallback pool, which would defeat the reason this plugin implements one at all — still deliberately unauthoritative (the same tier `wireguard`'s analogous thin per-packet signal uses, 11.5), just not inert |
| Identity | key `[{dcid, None}]` (Long-header packets only) — one QUIC stream per destination connection id observed. **Known v1 limitation, documented not hidden**: QUIC connections may migrate to a new connection ID mid-session (RFC 9000 §5.1.1); a post-migration DCID forms a new sibling stream rather than folding into the pre-migration one, the same shape as ESP's per-direction-SPI note (11.5) — a protocol-level identifier rotation the plugin can observe but not reconcile without decrypting NEW_CONNECTION_ID frames it has no access to |
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
      fields beyond `header_form`/`fixed_bit`.
- [x] `quic` connection-migration fixture (same connection, DCID changes mid-capture)
      produces two sibling streams under the same parent UDP stream — proves the documented
      limitation is real and bounded, not a crash or a silently wrong fold.
- [x] `quic` probe honesty: random UDP payload on port 443 scores low/`None`; a genuine
      QUIC Initial packet on a non-standard port is still admitted via the fallback pool.
