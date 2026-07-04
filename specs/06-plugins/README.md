# Task 06 — Reference plugins

**Goal:** the shipped protocol set (D6/FR-19): every plugin a self-contained file in
`pktflow-plugins`, registered in exactly one list, demonstrating between them every contract
feature — claims, candidates, direct-by-name encapsulation, probes, terminal hints, MAC/IP
conversations, TCP lifecycle, UDP streams, nested tunnels, and rollups (FR-21).

**Depends on:** 02–05. **Blocks:** 08.
**PRD:** FR-19, FR-20, FR-21 · D6, D7.

## Sub-tasks

- [x] [06.1 Template plugin](01-template.md) — the copyable starting point (FR-20)
- [x] [06.2 Link layer](02-link.md) — Ethernet II, 802.1Q VLAN
- [x] [06.3 Network layer](03-network.md) — IPv4, IPv6, ARP, ICMPv4, IGMP
- [x] [06.4 Transport](04-transport.md) — TCP (lifecycle), UDP
- [x] [06.5 Tunnels](05-tunnels.md) — GRE, VXLAN
- [x] [06.6 Application](06-application.md) — DNS, DHCP, NTP

## Conventions (all plugins)

- One file per protocol: `crates/pktflow-plugins/src/<name>.rs`; field-name constants at the
  top; registration only in `lib.rs::default_engine()` — the single "registration list" of
  the PRD §8 metric.
- Every plugin ships: unit tests from real-world byte captures (hex literals with a source
  comment), a truncation test at every internal length boundary, and — if it declares
  identity — a flow-key test through the 09.1 kit.
- Depth gating: `Keys` = flow-key fields; `Structural` = lengths/flags/types/TTL/etc.;
  `Full` = everything (checksums, options). Per-plugin tables in each spec are normative.
- Review checklist: most-explicit-hint rule (02.2), decline-don't-guess (02.1), probe
  honesty (02.3).

## Definition of done

`default_engine()` builds with all 15 plugins; every FR-21 demonstration has a passing
fixture test; the 09.1 kit passes for all plugins; adding a 16th toy plugin end-to-end
(new file + one registration line → streams visible in CLI) is rehearsed and takes < 1 hour
(PRD §8 metric, measured honestly).
