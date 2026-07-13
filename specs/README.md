# pktflow — Specification Index

Specs for building **pktflow**, the network traffic stream-understanding engine described in
[PRD.md](../PRD.md). Packets are the input; **streams/conversations with rolled-up metadata**
are the product. Dissection (plugins, router, lazy parser) is the substrate that feeds the
flow aggregator.

## How this tree works

Governed by [CONSTITUTION.md](CONSTITUTION.md): specs precede implementation, and every
merged behavior change is reflected back into its spec in the same PR. The summary:

- Each numbered folder is a **task**. Its `README.md` states the goal, dependencies, the
  sub-task checklist, and the task-level definition of done.
- Each numbered file inside is a **sub-task spec**: goal, specification, acceptance criteria.
  A task is done only when every sub-task's acceptance criteria pass.
- Cross-cutting design choices live in [DECISIONS.md](DECISIONS.md) (D1–D16). Specs cite them
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
| 10 | [Developer diagnostics](10-diagnostics/README.md) | `pktflow unknown`: grouped unclassified traffic, near-miss scores, export/scaffold | 03, 04, 05, 08 |
| 11 | [Standard plugin library](11-standard-library/README.md) | Batteries-included protocol coverage: link/wireless/routing/tunnels/transport/security/web/file/voice/telemetry/discovery/OT/DC-messaging/telco, tiered (D13) | 02–06 |
| 12 | [Contrib plugin library](12-contrib-library/README.md) | Optional `pktflow-contrib` crate (opt-in, feature-gated): long-tail coverage — encapsulations/remote-access/databases/messaging/media/storage/enterprise/VoIP/industrial/security/legacy-LAN, tiered (D13), stdlib-disjoint (D16) | 02–06 |

## Dependency graph

```
00 ──► 01 ──► 02 ──► 03 ──► 04 ──┐
              │                  ├──► 05 ──► 06 ──► 08 ──► 09
              └──────────────────┘          ▲   │
00 ─────────────────────────► 07 ───────────┘   └──► 11, 12
              03,04,05,08 ──────────────────► 10
```

Recommended build order: 00 → 01 → 02 → 03 → 04 → 05 → 06 → 07 → 08 → 09, with 07 parallel
to 03–05 and 09's test kit (09.1) started alongside 06. Task 10 is a leaf (like 09) started
once 08 exists. Task 11 is a leaf on 06: its domain sub-tasks are independent of each other
and independent of 07–10, so they can be built in any order (or in parallel) once 06 lands.
Task 12 is the same shape one step out — a leaf on 06 whose domain sub-tasks are mutually
independent once its crate sub-task (12.1) exists; where a 12.x entry composes with an 11.x
plugin it says so and degrades honestly (D9) until that plugin lands.

## Definition of done (project)

1. All task checklists complete; `cargo test --workspace` green on Linux and Windows.
2. Success metrics of PRD §8 demonstrated by 09.3/09.4: reference-tool flow parity, correct
   tunnel nesting, zero phantom streams on the encrypted fixture, and a measured cost gap
   between `Keys` and `Full` extraction depth.
3. A new protocol plugin can be added end-to-end (dissection + streams in CLI) touching only
   its own file plus one registration list (PRD §8 "time-to-new-protocol") — and `pktflow
   unknown` (task 10) can point a developer at the evidence that motivated adding it.
