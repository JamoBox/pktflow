# Local reproduction of the CI gate (00.3): `just ci` == what the PR runs.

default: ci

ci: fmt clippy boundaries test

fmt:
    cargo fmt --all --check

clippy:
    cargo clippy --workspace --all-targets --all-features -- -D warnings

boundaries:
    ./scripts/check-boundaries.sh

test:
    cargo test --workspace --all-features

# 09.1: local fuzz smoke, same targets/duration as the scheduled CI job
# (nightly toolchain + cargo-fuzz required; not part of `just ci` — this
# is a background safety net, not a merge gate).
fuzz seconds="300":
    cd crates/pktflow-plugins && cargo +nightly fuzz run dissect -- -max_total_time={{seconds}}
    cd crates/pktflow-plugins && cargo +nightly fuzz run dns_name -- -max_total_time={{seconds}}

# 09.4 + 12.7: run the offline benches (no NIC in the loop). Not
# part of `just ci` — measurements are a scheduled/manual check, not a
# per-PR gate (see the fuzz recipe above for the same reasoning).
bench:
    cargo bench --no-run --workspace
    cargo bench -p pktflow-cli --bench dissect_only
    cargo bench -p pktflow-cli --bench dissect_aggregate
    cargo bench -p pktflow-cli --bench throughput_floor
    cargo bench -p pktflow-cli --bench aggregator_memory
    cargo bench -p pktflow-cli --bench snapshot_cost
    cargo bench -p pktflow-cli --bench scale
