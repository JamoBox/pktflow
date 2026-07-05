# 00.1 — Workspace layout

> Task: [00 Foundation](README.md) · Depends on: — · PRD: §7 extensibility/testability · D1, D5

## Goal
A Cargo workspace whose crate boundaries mirror the architecture: substrate, product,
plugins, I/O, UI — so the engine stays protocol-free and the core stays OS-free.

## Specification

```
pktflow/
├── Cargo.toml            # [workspace], shared lints, resolver = "2"
├── crates/
│   ├── pktflow-core/     # values, layers, plugin trait, router, lazy parser (tasks 01–04)
│   ├── pktflow-flows/    # stream aggregator: store, hierarchy, rollups, queries (task 05)
│   ├── pktflow-plugins/  # reference plugin set + registration list (task 06)
│   ├── pktflow-capture/  # pcap-backed sources, interface listing (task 07)
│   └── pktflow-cli/      # binary `pktflow` (task 08)
└── specs/                # this tree
```

Dependency direction (enforced — a reverse edge is a design bug):

```
cli ──► flows ──► core          cli ──► capture
cli ──► plugins ──► core        flows ─x─ plugins (never)
```

- `pktflow-core` and `pktflow-flows`: **no** dependency on `pcap`, no protocol names, no OS
  conditionals. These are the fuzzable, platform-free heart.
- `pktflow-core` holds no protocol knowledge (PRD §1); anything mentioning "TCP" belongs in
  `pktflow-plugins`.
- Workspace-level `[workspace.lints]`: `unsafe_code = "forbid"` in core/flows/plugins,
  `clippy::unwrap_used = "deny"` in non-test code.
- Shared dev-deps for fixtures live in a `tests/` support module inside each crate, not a
  sixth crate, until 09.2 justifies one.

## Acceptance criteria
- [x] Workspace builds with all five crates stubbed (`lib.rs`/`main.rs` compiling, no logic).
- [x] `cargo tree -i pcap` shows only `pktflow-capture` and `pktflow-cli` as dependents.
- [x] `pktflow-flows` does not depend on `pktflow-plugins` (checked in CI via `cargo tree`).
- [x] Lints configured at workspace level and inherited by all crates.
