# 00.3 — CI & tooling

> Task: [00 Foundation](README.md) · Depends on: 00.1 · PRD: §7 cross-platform, determinism

## Goal
Every commit proves the workspace builds, lints, and tests on both target platforms, so
cross-platform breakage (the capture layer especially) is caught at the PR, not at release.

## Specification

CI (GitHub Actions, `.github/workflows/ci.yml`):

1. **Lint job** (Linux): `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`.
2. **Test matrix**: `{ubuntu-latest, windows-latest}` × stable Rust:
   `cargo test --workspace`. Linux installs `libpcap-dev`; Windows installs the Npcap SDK
   (cached). Capture *unit* tests must not require a live device or elevation — anything
   touching real NICs is `#[ignore]`d and run manually.
3. **Boundary check**: script asserting the D1/00.1 dependency rules via `cargo tree`
   (core/flows free of `pcap`; flows free of plugins).
4. **Determinism smoke** (added once 09.2 fixtures exist): run the CLI twice over a fixture,
   diff JSON outputs, assert byte-identical (PRD §7 determinism).

Local tooling: `rust-toolchain.toml` pinning stable; `justfile` (or `cargo xtask`) with
`just ci` reproducing the full gate locally.

## Acceptance criteria
- [ ] CI green on a clean checkout for both OSes.
- [ ] A deliberately introduced `clippy::unwrap_used` violation fails CI.
- [ ] Boundary-check script fails if `pktflow-flows` gains a `pktflow-plugins` dependency.
- [ ] `just ci` (or equivalent) runs the same gates locally.
