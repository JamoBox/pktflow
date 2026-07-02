# Task 00 — Foundation

**Goal:** a Cargo workspace with the crate boundaries, error-handling conventions, and CI
needed so every later task lands in the right place and holds to the same quality bar.

**Depends on:** nothing. **Blocks:** everything.
**PRD:** §7 (robustness, cross-platform, testability), D1, D5.

## Sub-tasks

- [ ] [00.1 Workspace layout](01-workspace.md) — five crates, dependency direction enforced
- [ ] [00.2 Errors & robustness](02-errors-robustness.md) — no-panic policy, error taxonomy
- [ ] [00.3 CI & tooling](03-ci-tooling.md) — fmt/clippy/test matrix on Linux + Windows

## Definition of done

`cargo build --workspace` and `cargo test --workspace` succeed on Linux and Windows CI from
a clean checkout; `pktflow-core` and `pktflow-flows` compile with no capture/OS dependencies;
lint gates are enforced.
