# Design Decisions

Resolutions for PRD §9's open questions, plus one structural decision (D10) that emerged
during spec design. Each is binding for v1 unless a spec explicitly supersedes it.

---

## D1 — Language & capture backend
**Rust** (2021 edition, stable toolchain) with the **`pcap` crate** binding libpcap (Linux)
and Npcap (Windows). One backend covers live capture, offline `.pcap`/`.pcapng` replay, and
interface enumeration on both target platforms. The capture dependency is isolated in the
`pktflow-capture` crate so the core engine and aggregator stay pure-Rust and fuzzable.

## D2 — Stream lifetime & eviction
Hybrid policy, configured per run (`AggregatorConfig`), with different defaults per mode:

- **Offline replay:** no eviction; everything flushes as *Closed* at capture end.
- **Live capture:** (a) protocol-declared close (e.g. TCP teardown) plus a 15 s linger for
  stragglers; (b) idle timeout, default 300 s since `last_seen`; (c) hard LRU cap, default
  1,000,000 streams — evicting the least-recently-updated leaf first, never a parent before
  its children.

Evicted/closed streams are emitted to an optional **sink** (callback) before removal so
callers can persist or count them; totals survive in aggregate counters either way.

## D3 — Direction canonicalization
Default rule (plugins may override in their `StreamIdentity`): compare the two endpoints as
byte strings — `(address bytes, then port/qualifier bytes)` lexicographically. The smaller
endpoint is canonical **A**, the larger **B**; a packet's direction is `AtoB` iff its source
is A. Separately, the **initiator** is recorded as the direction of the first packet observed
for the stream — canonical identity and session semantics stay independent.

## D4 — Metadata stream retention
Three rollup kinds, declared per field by the plugin (`RollupSpec`, see 02.4):

- **Accumulate** — running aggregate: counter, min/max, or bounded value-set (default set cap
  64 distinct values, then overflow flag).
- **Sample** — keep first and last observed value only.
- **Series** — time-ordered `(timestamp, direction, value)` ring buffer, default cap 1,024
  entries per stream, overwrite-oldest, `truncated` flag.

Baseline stats (packets/bytes per direction, first/last seen) are always kept and are not a
rollup. Default when a plugin declares nothing for a field: not retained at stream level.

## D5 — Aggregator concurrency model
**Single-writer.** The `Aggregator` is `Send` but not internally synchronized; exactly one
thread mutates it. Live pipeline: capture thread → bounded MPSC channel → aggregation thread,
which also answers query/snapshot requests over a command channel. Parser, router, and plugin
registry are immutable after build and `Send + Sync`, shared freely. Per-flow sharding is a
possible v2; the store (05.2) must not preclude it (no global sequential stream-id semantics
beyond insertion order).

## D6 — v1 protocol set
Exactly the PRD FR-19 list: Ethernet II, 802.1Q VLAN, IPv4, IPv6, ARP, ICMPv4, IGMP, TCP,
UDP, GRE, VXLAN, DNS, DHCP, NTP, plus the template plugin. Stream semantics that are
must-have: MAC conversation, IP conversation, TCP session w/ lifecycle, UDP stream, GRE and
VXLAN nested tunnels, DNS query-name rollup. ICMPv6, ND, MPLS, QUIC, TLS: explicitly later.

> **Superseded in part** by task 11 (FR-31): "later" arrived. ICMPv6 and ND are specified in
> 11.3, MPLS (as MPLS-in-IP, RFC 4023) in 11.5, QUIC invariants in 11.6, TLS handshake
> metadata in 11.7. Task 06's list itself is unchanged — this note just closes the forward
> reference so it doesn't read as a stale promise.

## D7 — Content vs. metadata boundary
Confirmed: **metadata only** in v1. No TCP payload reassembly, no body parsing, no
decryption. Application plugins (DNS/DHCP/NTP) parse only what fits in a single datagram/
segment; multi-segment application messages are out of scope and terminate dissection safely.

## D8 — Output formats
Both, behind `--format text|json` (default `text`). Offline: one final JSON document
(summary + stream tree). Live: NDJSON events (`stream_new`, `stream_update` on a throttle,
`stream_closed`, `summary`). Schema specified in 08.5 and covered by e2e tests, since JSON
output doubles as the test-assertion surface.

## D9 — Error surfacing
Every packet's dissection ends with a `StopReason`:
`Complete | Terminal | UnclaimedRoute(RouteId) | UnknownHint | Truncated{needed, have} |
PluginError{layer} | DepthCap`. The CLI packet mode prints it per packet; the summary counts
packets by reason; stream views show per-stream `opaque_bytes` (payload beyond the last
parsed layer, attributed to the innermost stream). Unknown payloads never create a stream
(PRD §8), but their bytes are still accounted for.

## D10 — Stream node identity is parent-scoped
A stream node in the hierarchy is unique per **(parent stream, protocol, canonical key)** —
the same IP pair under two different MAC conversations yields two nodes, keeping the tree
well-formed and tunnel nesting automatic. The layer-listing query (FR-24) lists nodes; an
optional *merged* view that folds same-key nodes across parents is a query-time concern
(05.7), not a storage concern.

## D11 — Unknown-diagnostics scope and bounding
Diagnostic probing (10.1) is **opt-in per parse session** (`ParseOpts.diagnose_unknown`,
default `false`) and is the one documented exception to the gated-termination rule (03.4):
it may score every fallback-pool plugin's `probe()` against bytes stopped at by an unclaimed
route or exhausted heuristics, purely for reporting — it can never select a plugin or emit a
`LayerRecord`. In the shipped CLI, only `pktflow unknown` (10.3) turns it on; every other
subcommand pays no cost for the feature's existence. The resulting registry (10.2) is bounded
independently of stream storage — default caps 500 distinct unknown "shapes" (LRU over
last-updated) and 5 retained raw samples per shape (overwrite-oldest) — and survives stream
eviction (05.6), since a stream's bookkeeping lifecycle and the diagnostic value of "we saw
this" are independent concerns.

## D12 — Encrypted/opaque protocol boundary (task 11)
Protocols that encrypt their payload are still worth dissecting up to the point encryption
starts — that boundary, not the protocol's presence, is where D7's "metadata only" line
falls. Each such plugin parses **only the plaintext handshake/header fields the protocol
itself exposes before payload opacity begins**, then declines (`ParseError`) on the encrypted
remainder exactly like any other plugin hitting bytes it can't interpret (D9's ordinary
`PluginError`/`Truncated` path — no new `StopReason` variant):

- **TLS** — ClientHello/ServerHello only: SNI, ALPN, negotiated cipher suite, TLS version,
  certificate basics if present in cleartext (pre-1.3) or via unencrypted extensions.
  `ApplicationData` records are identified (record type + length) but not parsed.
- **QUIC** — the version-independent invariants (RFC 8999): version, connection IDs, packet
  type. Long-header `Initial` packet cleartext fields where the QUIC version defines them;
  everything past that is opaque.
- **SSH** — the identification banner (RFC 4253 §4.2) and unencrypted KEX negotiation
  messages only; post-KEX traffic is opaque by design.
- **WireGuard / IPsec ESP** — header fields and handshake message *type* (WireGuard's
  four message types; ESP's SPI/sequence number), never plaintext payload since none exists
  on the wire.

A plugin under this decision still declares `claims`/`hint`/`stream_identity` normally — the
stream still forms, rollups on the cleartext fields still work (e.g. TLS SNI as an
`Accumulate` rollup). Only the *field extraction ceiling* is protocol-specific here, not the
contract shape.

## D13 — Standard-library tiering (task 11)
Task 11's taxonomy is delivered in tiers, a spec-tree concept (not a code construct):

- **Tier 1** — near-universal or high analytic value across the target network types (home,
  enterprise, data-center, private, internet-facing, telco). Gets a full
  Goal/Specification/Acceptance-criteria entry in its domain sub-task file now, and is
  buildable immediately under the same rules as task 06.
- **Tier 2** — common but deployment-specific (a particular vertical or vendor ecosystem).
  Named in the domain file's "Planned" table with its governing standard, but **not yet
  specified** — Article I still applies: nothing in Tier 2 is implemented until a later PR
  fleshes out its own Goal/Specification/Acceptance-criteria entry, at which point it is
  promoted out of the stub table.
- Tier 2 protocols named in a stub table are not a commitment to build; they're a documented
  inventory so the taxonomy doesn't need re-deriving from scratch when someone picks one up.

## D14 — Standards citation requirement (task 11)
Every protocol entry in task 11 (Tier 1 now; Tier 2 when it graduates out of its stub table)
states the document that governs the wire format it implements: an RFC number, an
IEEE/ISO/IEC/ANSI/ITU-T standard, a 3GPP TS number, or an IANA registry, cited inline next to
the protocol name (e.g. "**gtpv2-c** (3GPP TS 29.274)"). Where no open standard exists — true
for a real minority of shipped protocols (vendor-proprietary wire formats, project-maintained
de facto specs) — the entry says so explicitly and names the closest authoritative document
instead (a vendor's published protocol description, a project's protocol.txt, a whitepaper),
so the absence of a standards body is a documented fact about that protocol, not a silently
missing field. This does not retroactively apply to task 06 (D6's list predates this
decision) but does apply to any future addition to either task.

## D15 — Dynamic/negotiated-port protocols (task 11)
Several protocols negotiate the port for their actual data/media traffic **inside** an
already-flowing control-channel stream: FTP's `PASV`/`PORT` response (11.9), TFTP's
server-chosen TID after the initial request (11.9), NFSv3's portmapper-negotiated port
(11.9), RTP/RTCP's port pair negotiated out-of-band via SDP/SIP (11.10). Once that
negotiation happens, the continuation traffic's transport-layer hint (`Candidates`, 06.4)
resolves to ports nothing claims — and per the gated-termination rule (03.4/FR-15), an
explicitly-named-but-unclaimed route **stops** rather than falling into heuristic fallback.

This is not a bug or an oversight: it is exactly the protection the PRD's motivating
encrypted-UDP case (§4.B.4) describes, applied here to traffic that happens to be benign.
Stated once so it isn't rediscovered as if new in each affected domain file: **v1 sees only
the control-channel packets that arrive on the protocol's own claimed, well-known port; the
negotiated-port continuation traffic is architecturally invisible to per-packet dissection.**
Reading a negotiated port out of one stream's payload and registering a route for it
(cross-stream port correlation) is a real, valuable capability — it needs the router or
aggregator to accept a runtime route registration keyed off a *live stream's* parsed field,
which doesn't exist yet. Explicitly out of scope for this task; a candidate for its own
future decision and spec, not a silent gap in the protocols that hit it.

## D16 — High-cardinality condensation (task 12)
A capture where one service endpoint talks to many ephemeral peer ports (scans, load tests,
busy client↔server pairs, NAT'd aggregation points) creates one full stream node per
ephemeral flow under the same parent — hundreds of thousands of siblings that no human will
ever browse row-by-row, each paying the full per-stream cost in the aggregator, in every
snapshot, in every JSON document, and in every UI render. The fix lives **in the
aggregator**, not the view layer: fixing it downstream would leave memory and snapshot cost
unbounded.

**Decision:** when the number of live same-protocol children under one parent that share the
same *anchor endpoint* (the repeating side of the declared key pair — e.g. `10.0.0.5:443` —
compared by field values, not by canonical A/B label) exceeds a threshold **K** (default
256), subsequent flows in that group fold into a single **condensed stream node** instead of
creating new nodes. The condensed node retains: member-flow count, summed per-direction
stats, opaque bytes, first/last seen, a bounded distinct-value tally of the varying
(ephemeral) key component with an explicit overflow flag (same honesty contract as D4 /
D11 — never lie by omission), and a lifecycle-state histogram where the protocol declares
one. The first K flows of a group remain ordinary, fully browsable streams.

Which key components may vary is **plugin-declared** (`LayerPlugin::condense`, a defaulted
trait method like `claims`/`probe`), keeping the engine protocol-free: TCP/UDP nominate
their port pair; a protocol that declares nothing never condenses. Condensation is on by
default in every aggregating mode and can be disabled per run (`--no-condense`); the
threshold is configurable (`AggregatorConfig`). The trigger counts in deterministic
creation order, so the same input yields the same expanded set and the same condensed
tallies (PRD §7). What is knowingly given up: per-flow rollups, lifecycle detail, and
drill-down for flows beyond the first K of a group — the condensed row states the loss
explicitly (`× 49,744 flows`), and re-running with `--no-condense` or a raised threshold
recovers full detail.

## D17 — Snapshot & rendering scale contract (task 12)
The D5 snapshot model (deep copy, publish, render from the copy) is correct but was costed
for live captures bounded by D2's `max_streams`. Offline replay has no eviction, so on a
multi-gigabyte capture every 250 ms publish deep-clones an ever-growing stream set
(read-time cost quadratic in stream count, peak memory a multiple of aggregator state), and
the web UI's single-document `/api/snapshot` ships the entire forest to the browser on every
generation change. Four rules make cost proportional to *change and viewport* instead of
*capture size*, binding on the aggregator, `pktflow-view`, and both front-ends:

1. **Publication is incremental.** Snapshots share unchanged stream records with the
   previous publish (`Arc`-per-stream structural sharing; the store mutates copy-on-write):
   deep-copy work between two publishes is O(streams touched in between), never O(all
   streams) clones at publish. Summary counters are maintained incrementally, not
   recomputed by full scan at publish.
2. **Publish cadence is adaptive.** The interval floor stays 250 ms, but a publish that took
   `t` defers the next by ≥ max(250 ms, c·t) — a snapshot can be briefly stale, but
   publication may never dominate the ingest thread.
3. **Readers never do O(total streams) work per interaction.** Sort orders, id maps, and
   child lists are computed once per published snapshot in a shared, lazily-built
   `SnapshotIndex` (pktflow-view); UI requests and keypresses resolve against windows of it.
   Timelines render at bounded resolution (server-side time×lane binning), never one drawn
   element per stream.
4. **Full-document transfer is size-gated.** `/api/snapshot` carries the whole forest only
   below a stream-count threshold; above it the client must use the windowed API. The
   browser's working set is viewport-bounded by design, not by hoping captures stay small.
