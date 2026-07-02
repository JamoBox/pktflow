# pktflow — Specification Index

Specs for building **pktflow**, the network traffic stream-understanding engine described in
[PRD.md](../PRD.md). Packets are the input; **streams/conversations with rolled-up metadata**
are the product. Dissection (plugins, router, lazy parser) is the substrate that feeds the
flow aggregator.

## How this tree works

- Each numbered folder is a **task**. Its `README.md` states the goal, dependencies, the
  sub-task checklist, and the task-level definition of done.
- Each numbered file inside is a **sub-task spec**: goal, specification, acceptance criteria.
  A task is done only when every sub-task's acceptance criteria pass.
- Cross-cutting design choices live in [DECISIONS.md](DECISIONS.md) (D1–D10). Specs cite them
  as `D#` and the PRD as `FR-#` / `§#`.
- Rust snippets in specs are **shape sketches**, not literal code — names and signatures are
  normative, bodies are not.

## Tasks

| # | Task | Delivers | Depends on |
|---|------|----------|------------|
| 00 | [Foundation](00-foundation/README.md) | Cargo workspace, error/robustness conventions, CI | — |
| 01 | [Core types](01-core-types/README.md) | Values, field maps, layers, depth, parse context | 00 |
| 02 | [Plugin contract](02-plugin-contract/README.md) | `LayerPlugin` trait, hints, stream-identity declaration | 01 |
| 03 | [Router](03-router/README.md) | Route ids, builder, heuristic fallback, gated termination | 02 |
| 04 | [Lazy parser](04-parser/README.md) | Layer-at-a-time iterator, entry resolution, stop reasons | 03 |
| 05 | [Stream aggregator](05-aggregator/README.md) | **The product**: flow keys, store, hierarchy, rollups, lifecycle, eviction, queries | 02, 04 |
| 06 | [Reference plugins](06-plugins/README.md) | Ethernet/VLAN, IPv4/6/ARP/ICMP/IGMP, TCP/UDP, GRE/VXLAN, DNS/DHCP/NTP, template | 02–05 |
| 07 | [Capture I/O](07-capture/README.md) | pcap file replay, live capture, interface listing | 00 |
| 08 | [CLI](08-cli/README.md) | `pktflow` binary: streams view, drill-down, packet mode, JSON | 05, 06, 07 |
| 09 | [Validation](09-validation/README.md) | Plugin test kit, fixtures, e2e stream tests, benchmarks | all |

## Dependency graph

```
00 ──► 01 ──► 02 ──► 03 ──► 04 ──┐
              │                  ├──► 05 ──► 06 ──► 08 ──► 09
              └──────────────────┘          ▲
00 ─────────────────────────► 07 ───────────┘
```

Recommended build order: 00 → 01 → 02 → 03 → 04 → 05 → 06 → 07 → 08 → 09, with 07 parallel
to 03–05 and 09's test kit (09.1) started alongside 06.

## Definition of done (project)

1. All task checklists complete; `cargo test --workspace` green on Linux and Windows.
2. Success metrics of PRD §8 demonstrated by 09.3/09.4: reference-tool flow parity, correct
   tunnel nesting, zero phantom streams on the encrypted fixture, and a measured cost gap
   between `Keys` and `Full` extraction depth.
3. A new protocol plugin can be added end-to-end (dissection + streams in CLI) touching only
   its own file plus one registration list (PRD §8 "time-to-new-protocol").
