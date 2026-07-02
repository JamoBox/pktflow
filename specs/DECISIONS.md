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
