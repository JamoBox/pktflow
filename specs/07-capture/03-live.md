# 07.3 — Live capture & interface listing

> Task: [07 Capture](README.md) · Depends on: 07.1 · PRD: FR-22 "live-capture", FR-23 · D1, D2

## Goal
Open a named interface, stream packets with kernel-drop visibility, list what's available —
on Linux (libpcap) and Windows (Npcap).

## Specification

```rust
pub struct LiveSource { /* pcap::Capture<Active> */ }
pub struct LiveConfig {
    pub promiscuous: bool,        // default true
    pub snaplen: i32,             // default 65535
    pub buffer_size: usize,       // default 4 MiB kernel buffer
    pub read_timeout: Duration,   // default 250 ms — bounds shutdown latency, see below
    pub bpf: Option<String>,      // pre-kernel filter string, compiled via libpcap
}
impl LiveSource {
    pub fn open(device: &str, cfg: LiveConfig) -> Result<LiveSource, CaptureError>;
}

pub struct InterfaceInfo { pub name: String, pub description: Option<String>,
                           pub addrs: Vec<IpAddr>, pub up: bool, pub loopback: bool }
pub fn list_interfaces() -> Result<Vec<InterfaceInfo>, CaptureError>;  // FR-23
```

- **Shutdown:** `next_packet` uses pcap's read timeout so the pump loop re-checks a stop
  flag (`Arc<AtomicBool>`, set by Ctrl-C handler in the CLI) at least every
  `read_timeout` — no hanging on quiet interfaces. Timeout expiry with no packet is *not*
  `Ok(None)`; it's an internal retry (`Ok(None)` strictly means "source ended").
- **BPF filters:** accepted as a string, compiled by libpcap; compile errors surface as
  `CaptureError::Backend` with libpcap's message. Filtering *before* the engine is the
  cheap path for targeted live analysis; no pktflow-level filter language in v1.
- **Drops:** `CaptureStats { received, dropped_kernel, dropped_iface }` polled per pump
  report; the CLI summary must print drops when nonzero (an analyst must know the stream
  picture may be incomplete — silent drops corrupt trust in stream stats).
- Device naming is passed through verbatim (Linux `eth0`, Windows `\Device\NPF_{GUID}`);
  `list_interfaces` output is the user's source for the latter (FR-23's real purpose on
  Windows).

## Acceptance criteria
- [ ] `list_interfaces` returns a non-empty, well-formed list on both CI OSes.
- [x] Loopback round-trip test (`#[ignore]` by default; run where CI grants capture rights):
      send UDP packets to localhost, capture them, assert content arrival.
- [x] Stop-flag shutdown from a quiet interface completes within 2× `read_timeout`.
- [x] Invalid BPF string → clean `Backend` error naming the filter.
