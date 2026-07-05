# pktflow

A plugin-extensible Rust engine that dissects captured network traffic and aggregates it
into a browsable hierarchy of conversations and streams — MAC conversations, IP
conversations, TCP/UDP sessions, and application-level streams (DNS, DHCP, ...), each
carrying rolled-up metadata over its lifetime.

A packet in isolation is noise. The signal is that two endpoints have an ongoing session,
riding inside their IP conversation, riding on a MAC conversation, and over its lifetime it
has exchanged N packets, this much data, this metadata. pktflow's job is producing that
picture, not just decoding bytes. See [`PRD.md`](PRD.md) for the full product rationale and
[`specs/`](specs/) for the design-by-task breakdown this codebase was built against.

## Highlights

- **Protocol plugins are self-contained.** The engine holds no protocol knowledge; each
  plugin declares how it's routed to, parses its own header, and (optionally) declares the
  stream identity and rollups it contributes. Adding a protocol is one new file plus one
  registration line — see [`docs/adding-a-protocol.md`](docs/adding-a-protocol.md).
- **Streams nest by construction.** A tunnel's inner conversation becomes a child of the
  outer one purely from per-packet layer order — no protocol-specific tunnel handling
  anywhere in the aggregator.
- **Depth is a caller-set knob.** Ask for just flow-key fields (`--depth keys`) and skip the
  cost of full field extraction, or ask for everything (`--depth full`).
- **No phantom streams.** Unclaimed/encrypted payloads land as opaque bytes on their
  innermost recognized parent, never a fabricated child stream.
- 13 reference protocol plugins today: Ethernet, 802.1Q VLAN, ARP, IPv4, IPv6, ICMPv4, IGMP,
  TCP, UDP, GRE, VXLAN, DNS, DHCP, NTP.

## Quick start

```sh
cargo build --release
./target/release/pktflow capture.pcap                  # shorthand for `pktflow streams -r capture.pcap`
./target/release/pktflow streams -r capture.pcap --format json
./target/release/pktflow stream -r capture.pcap '#3'      # drill into one stream (by id from a streams view)
./target/release/pktflow packets -r capture.pcap -v       # per-packet debug lens
./target/release/pktflow ifaces                           # list capturable interfaces
sudo ./target/release/pktflow streams -i eth0 --watch     # live, full-screen view
```

Run `pktflow <subcommand> --help` for the full flag set (BPF filters, live-mode eviction
tuning, `--entry` for forced first-layer dissection, NDJSON live events via
`--watch --format json`, and more).

## Workspace layout

| Crate | Role |
|---|---|
| `pktflow-core` | Values, layers, the plugin trait, router, lazy parser — protocol-free |
| `pktflow-plugins` | The reference protocol set and its registration list |
| `pktflow-flows` | The stream aggregator: store, hierarchy, rollups, lifecycle, queries |
| `pktflow-capture` | The only crate touching libpcap/Npcap — offline files, live devices |
| `pktflow-cli` | The `pktflow` binary: streams view, drill-down, packet mode, JSON output |
| `pktflow-testkit` | Synthetic wire-format packet/capture builders shared by tests |

Crate boundaries are enforced mechanically (`scripts/check-boundaries.sh`, part of `just
ci`): `pktflow-core`/`pktflow-flows` never touch pcap, and `pktflow-flows` never depends on
`pktflow-plugins` — the aggregator has no protocol knowledge.

## Development

This repo uses [`just`](https://github.com/casey/just) as its task runner.

```sh
just ci      # fmt --check, clippy -D warnings, boundary check, cargo test --workspace
just bench   # the five criterion benches (throughput, depth payoff, memory) — see benches/README.md
just fuzz    # local fuzz smoke (nightly + cargo-fuzz required) — same targets as the scheduled CI job
```

`just ci` is what the GitHub Actions `lint`/`boundaries`/`test` jobs run per PR/push. Fuzzing
and benchmarks are scheduled jobs, not per-PR gates — see `.github/workflows/fuzz.yml` and
`.github/workflows/bench.yml`.

A `Dockerfile` is also provided: it builds the workspace and runs the full test suite
(`cargo test --workspace --all-features -- --include-ignored`) inside a container, which
gets `CAP_NET_RAW` by default — that's enough to run the three `#[ignore]`d live-capture
tests in `crates/pktflow-capture/tests/live.rs` that a bare CI runner can't. Wired into the
`privileged-integration-tests` job in `.github/workflows/ci.yml`.

```sh
docker build -t pktflow-test .
docker run --rm pktflow-test
```

## Project status

Built task-by-task against the specs in [`specs/`](specs/); each sub-task's acceptance
criteria are tracked as checkboxes in its own file. See `specs/README.md`/`specs/*/README.md`
for the current breakdown.

## License

MIT — see [`LICENSE`](LICENSE).
