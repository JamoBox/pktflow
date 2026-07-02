# Local reproduction of the CI gate (00.3): `just ci` == what the PR runs.

default: ci

ci: fmt clippy boundaries test

fmt:
    cargo fmt --all --check

clippy:
    cargo clippy --workspace --all-targets -- -D warnings

boundaries:
    ./scripts/check-boundaries.sh

test:
    cargo test --workspace
