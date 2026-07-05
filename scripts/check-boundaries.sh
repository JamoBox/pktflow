#!/usr/bin/env bash
# Enforce the D1/00.1 crate-boundary rules via `cargo tree`.
# A reverse edge here is a design bug, not a style problem.
set -euo pipefail

fail() {
    echo "boundary violation: $1" >&2
    exit 1
}

# pktflow-core and pktflow-flows are the platform-free heart: no pcap
# anywhere in their normal-dependency trees.
if cargo tree -p pktflow-core --edges normal | grep -Eq '\bpcap v'; then
    fail "pktflow-core depends on pcap"
fi
if cargo tree -p pktflow-flows --edges normal | grep -Eq '\bpcap v'; then
    fail "pktflow-flows depends on pcap"
fi

# The aggregator must never know about protocols: flows -x- plugins.
if cargo tree -p pktflow-flows --edges normal | grep -q 'pktflow-plugins'; then
    fail "pktflow-flows depends on pktflow-plugins"
fi

# Only the capture crate and the CLI that links it may sit above pcap.
bad=$(cargo tree -i pcap --edges normal \
    | grep -o 'pktflow-[a-z]*' | sort -u \
    | grep -vE '^pktflow-(capture|cli)$' || true)
if [ -n "$bad" ]; then
    fail "unexpected pcap dependents: $bad"
fi

echo "crate boundaries OK"
