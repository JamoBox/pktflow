# Finding and triaging unknown traffic

`pktflow unknown` is the dev/debug lens dedicated to the thing every other view is built to
safely walk away from: traffic no plugin claimed, or traffic no heuristic was confident
enough to guess at (03.4's "no phantom streams" gate — see [`specs/10-diagnostics/`](../specs/10-diagnostics/)
for the full design). Instead of grepping `packets -vv` output by hand, it rolls every such
stop up, capture-wide, into a queryable, sampled, scored picture of *what isn't understood
yet* — with two concrete next steps: export real bytes for a fixture, or scaffold a starter
plugin.

It is the **only** place `pktflow` turns on the extra probing this needs (D11): every other
subcommand — `streams`, `stream`, `packets` — pays no cost for the feature's existence.

## The table

```sh
pktflow unknown -r capture.pcap
```

```text
UNKNOWN PROTOCOLS / STREAMS   (2 groups, 3 packets, 80 B unclassified)

#  CONTEXT               KIND                 COUNT  BYTES  FIRST → LAST                 NEAR MISSES
1  udp → udp_port:51820  unclaimed route          2   40 B  00:01:40.000 → 00:01:41.000  tcp(60)
2  ethernet              no heuristic winner      1   40 B  00:01:42.000 → 00:01:42.000  ipv6(75)
```

Each row is one distinct *shape* of unknown — same predecessor protocol plus either the same
named-but-unclaimed route (`unclaimed route`), or the same "heuristics found nothing
confident" story (`no heuristic winner`). `NEAR MISSES` are registered plugins whose `probe()`
scored the bytes without ever being allowed to claim them — `tcp(60)` means TCP's probe
thought these 20 bytes looked 60%-plausible, which is exactly the kind of clue that tells you
what to write next.

A capture with nothing unknown prints an explicit `no unknown protocols observed` line, never
a bare empty table — you can always tell "ran clean" apart from "didn't run."

Useful flags: `--top N` caps rows (default 20), `--min-count N` hides single-straggler noise
(default 1, i.e. show everything).

## Drilling into one group

Select a row with its `#n` from the table:

```sh
pktflow unknown -r capture.pcap '#1'
```

```text
#1  udp → udp_port:51820   unclaimed route
count     2
bytes     total 40 B  min 20 B  max 20 B
seen      first 1970-01-01T00:01:40Z  last 1970-01-01T00:01:41Z
endpoints
  udp [1, 0, 0, 0, 0, 0, 0, 9c, 41, 1, 0, 0, 0, 0, 0, 0, ca, 6c]
  udp [1, 0, 0, 0, 0, 0, 0, 9c, 42, 1, 0, 0, 0, 0, 0, 0, ca, 6c]
near misses
  tcp(60)
samples   (2 of 2 retained)
  sample 1: 20 bytes
    0000  00 50 01 bb 00 00 00 00 00 00 00 00 50 02 20 00
    0010  00 00 00 00
  sample 2: 20 bytes
    0000  00 50 01 bb 00 00 00 00 00 00 00 00 50 02 20 00
    0010  00 00 00 00
```

This is the un-capped view: the **full** near-miss ranking (the table shows only the top 3),
the bounded endpoint set (an `endpoint` entry per distinct stream key this shape showed up
under — many distinct endpoints under one shape usually means "a real protocol worth a
plugin"; always the same one or two usually means "a misconfigured peer"), and up to
`--samples N` (default 3) retained raw samples, hex-dumped. `--full-samples` shows every
sample the registry actually kept (bounded independently, see D11) instead of just the first
`N`.

If a shape's endpoint set hit its cap, the header reads `endpoints (≥64 distinct)` — never
silently truncated without saying so.

## Exporting real bytes for a fixture

```sh
pktflow unknown -r capture.pcap '#1' --export ./fixtures/udp-51820
```

Writes every retained sample as `<slug>-<n>.bin` (byte-identical to what the registry holds)
plus a `manifest.json` (key, counts, byte-length stats, and the source capture path — never
fabricated byte offsets, which aren't recoverable after the fact). This is the direct on-ramp
from "I saw this in the wild" to a curated fixture for `pktflow-testkit`/the 09.2 corpus,
instead of hand-crafting bytes from a spec.

## Scaffolding a plugin

```sh
pktflow unknown -r capture.pcap '#1' --scaffold wireguard
```

Copies [`crates/pktflow-plugins/src/template.rs`](../crates/pktflow-plugins/src/template.rs)
to `crates/pktflow-plugins/src/wireguard.rs`, and — since group `#1` here has a route
(`udp_port:51820`) — pre-fills `claims()` with that route and adds a doc comment showing the
first retained sample as a worked hex example to parse against. It writes exactly **one** new
file; `parse()` is still the template's placeholder body, so the command prints the one
remaining step:

```text
scaffolded crates/pktflow-plugins/src/wireguard.rs
next: add `.plugin(wireguard::Wireguard)` to default_engine() in crates/pktflow-plugins/src/lib.rs
```

From here, follow [`docs/adding-a-protocol.md`](adding-a-protocol.md) starting at step 2 —
filling in the header — since steps 1 (copy the template) and 3 (declare the route) are
already done for you. `--scaffold` refuses to overwrite an existing file (exit 2): it's a
starting point, not a merge tool.

## Scripting: `--format json`

`--format json` applies to both the table and drill-down views (`schema/unknown-v1.json`):
counts, context, byte stats, and near-misses — but deliberately **not** raw sample bytes
(`--export` is the JSON/binary split's other half).

```sh
pktflow unknown -r capture.pcap --format json | jq '.groups[] | {predecessor, route, count}'
```
