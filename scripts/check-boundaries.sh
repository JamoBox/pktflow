#!/usr/bin/env bash
# Enforce the D1/00.1 crate-boundary rules via `cargo tree`.
# A reverse edge here is a design bug, not a style problem.
set -euo pipefail

fail() {
    echo "boundary violation: $1" >&2
    exit 1
}

# pktflow-core, pktflow-flows, pktflow-view, and UIs must never depend
# on pkttap or pktbaffle.
for crate in pktflow-core pktflow-flows pktflow-view pktflow-tui pktflow-web; do
    for dep in pkttap pktbaffle; do
        if cargo tree -p "$crate" --edges normal | grep -Eq "\\b$dep v"; then
            fail "$crate depends on $dep"
        fi
    done
done

# The aggregator must never know about protocols: flows -x- plugins.
# The presentation layer and both UIs are protocol-free for the same
# reason — they render whatever the snapshot says, no protocol names
# baked in.
for crate in pktflow-flows pktflow-view pktflow-tui pktflow-web; do
    if cargo tree -p "$crate" --edges normal | grep -q 'pktflow-plugins'; then
        fail "$crate depends on pktflow-plugins"
    fi
done

# Only the capture crate and the CLI that links it may sit above pkttap or pktbaffle.
for dep in pkttap pktbaffle; do
    bad=$(cargo tree -i "$dep" --edges normal \
        | grep -o 'pktflow-[a-z]*' | sort -u \
        | grep -vE '^pktflow-(capture|cli)$' || true)
    if [ -n "$bad" ]; then
        fail "unexpected $dep dependents: $bad"
    fi
done

echo "crate boundaries OK"
