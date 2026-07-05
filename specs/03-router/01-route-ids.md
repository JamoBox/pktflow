# 03.1 — Route identifiers

> Task: [03 Router](README.md) · Depends on: 02.2 · PRD: §4.B.3, §10 "Route"

## Goal
Protocol identifiers that are unambiguous across layers: the number 6 means TCP in the IP
protocol space and something unrelated elsewhere, so ids must carry their namespace.

## Specification

```rust
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum RouteId {
    LinkType(u16),       // pcap DLT space — entry routing (04.2)
    EtherType(u16),      // Ethernet/VLAN "what's next" space
    IpProtocol(u8),      // IPv4 protocol / IPv6 next-header space
    UdpPort(u16),
    TcpPort(u16),
    /// Escape hatch for plugin-defined spaces (e.g. GRE protocol field reuses
    /// EtherType values — GRE emits EtherType; but e.g. a custom mux protocol
    /// can mint its own space without touching core).
    Custom { space: &'static str, id: u64 },
}
```

- **Well-known spaces are enum variants** (fast, `Copy`, exhaustive matching); unforeseen
  spaces go through `Custom` so adding a protocol never requires editing this enum — the
  engine stays protocol-free in spirit: variants name *id spaces*, not protocols.
- Port spaces are split TCP/UDP deliberately: port 53/UDP (DNS) and 53/TCP route to the same
  plugin only because the DNS plugin claims both (02.3) — the router never conflates them.
- Ports are a *hint* space, not a truth space: port-based routing is explicit-tier because
  the header named the port, but the routed plugin's parse can still decline, after which
  the gate (03.4) — not further guessing — decides what happens.
- `Display` renders as `"ethertype:0x0800"`, `"udp_port:53"`, `"custom:gre_flags:1"` for
  diagnostics and D9 stop-reason messages.

## Acceptance criteria
- [x] `RouteId` implemented, `Copy + Eq + Hash`, with `Display` as specified.
- [x] Unit test: `EtherType(6) != IpProtocol(6)` as map keys (no cross-space collision).
- [x] A `Custom`-space id round-trips through claim → route table → dispatch in a test with
      a synthetic plugin pair.
