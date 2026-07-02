# 06.4 — Transport: TCP, UDP

> Task: [06 Plugins](README.md) · Depends on: 02–05 · PRD: FR-19 transport, FR-21 sessions/streams, FR-6

## Goal
The two flagship stream protocols: TCP sessions with the reference lifecycle implementation,
UDP streams with candidate-port routing.

## Specification

**tcp** — variable header (data offset).

| Item | Spec |
|---|---|
| Claims | `IpProtocol(6)` |
| Fields | `Keys`: `src_port`, `dst_port` · `Structural`: `flags` (U64 bitfield), `seq`, `ack`, `window`, `data_offset` · `Full`: `checksum`, `urgent`, `options` (Bytes) |
| Hint | payload empty → `Terminal`; else `Candidates([TcpPort(dst), TcpPort(src)])` |
| Probe | data_offset in 5..=15, flags not nonsensical (e.g. SYN+FIN scores 0), header fits → 60; `expected_predecessors: ["ipv4", "ipv6"]` |
| Identity | key `[{src_port, dst_port}]` (5-tuple completed by the parent IP conversation path, D10/02.4), `EndpointSort` → **TCP session** |
| Rollups | `Accumulate` on `flags` (set of flag combinations seen — FR-5's example); `Series{cap:1024}` on `flags` (handshake/teardown timeline, 05.5 note) |

Lifecycle (`LifecycleSpec`, the FR-6 reference; direction-aware, initiator = first packet):

```text
initial: "new"
new          --SYN(initiator)-->        syn_sent
syn_sent     --SYN+ACK(responder)-->    syn_received
syn_received --ACK(initiator)-->        established
new          --any non-SYN-->           established_midstream   (capture began mid-session)
established* --FIN-->                   closing
closing      --FIN(other dir seen)+ACK--> closed
any          --RST-->                   reset
closed_states: ["closed", "reset"]
```

Kept deliberately coarse — this is session bookkeeping, not a sequence-number-correct TCP
state machine (no reassembly, D7). Unrecognized transitions keep current state (05.5).

**udp** — 8-byte header.

| Item | Spec |
|---|---|
| Claims | `IpProtocol(17)` |
| Fields | `Keys`: `src_port`, `dst_port` · `Structural`: `length` · `Full`: `checksum` |
| Hint | `Candidates([UdpPort(dst), UdpPort(src)])`; **this is the gate's front line** — unclaimed ports stop dissection (03.4 fixture `encrypted_udp_no_phantom` lives here) |
| Probe | none — UDP is 8 unguessable bytes; heuristically claiming it would undermine the gate |
| Identity | key `[{src_port, dst_port}]`, `EndpointSort` → **UDP stream**; no lifecycle |

## Acceptance criteria
- [ ] Full lifecycle walk on a real handshake+teardown fixture hits every named state;
      midstream fixture lands `established_midstream`; RST fixture lands `reset`.
- [ ] Closed TCP session becomes close-eligible in the aggregator (05.5 integration).
- [ ] `Candidates` ordering test: DNS reply (src 53 → dst 34567) routes via `TcpPort(src)`
      second candidate. Same for UDP.
- [ ] FR-21 items: TCP session with lifecycle ✔, UDP stream ✔, both direction-folded with
      correct per-direction stats.
