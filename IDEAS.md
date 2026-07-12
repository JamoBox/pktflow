# Feature ideas

A running shortlist of candidate features, ranked by how strongly they
exploit what is *unique* about pktflow's data model: a stream hierarchy by
construction, deterministic snapshots, time-stamped rollups, lifecycle
states, and the ranked unknown registry. Generic features other tools
already do well rank lower regardless of how useful they'd be.

## 1. Capture diff & baseline drift

Snapshots are deterministic by design (PRD §7): same input → same tree,
same ids. That makes comparison a first-class operation almost no network
tool has:

- `pktflow diff before.pcap after.pcap` (+ a diff mode in the web UI):
  what appeared, what vanished, what changed shape — new talkers, a port
  gone quiet, a conversation that tripled in volume, a tunnel that wasn't
  there yesterday.
- Live extension: save a snapshot as a *baseline profile*; the LIVE
  header shows drift ("2 new protocols, 14 new conversations vs.
  baseline").
- Composes with the query language for free:
  `pktflow diff a b --where 'proto == dns'`.

Answers "what changed after the deploy / during the incident?" — today
people answer that by eyeballing two Wireshark windows.

## 2. Time-lane view with a scrubber  *(→ shipped: Timeline tab in TUI and web)*

Every stream carries `first_seen`/`last_seen`, per-direction counters,
lifecycle transitions, and time-stamped series rollups — everything
needed for a waterfall of stream lifetimes:

- One lane per stream, still grouped by hierarchy (child lanes indented
  under their tunnel), bars spanning each conversation's life, colored by
  protocol; close reasons and state transitions as markers.
- A time scrubber: drag it and the view renders as of that instant —
  watch the DNS lookup fire just before the TCP session opens; see which
  flows died when the tunnel closed.
- Honors the query language ("scrub through only `under == vxlan`
  traffic").

Feasible without engine changes; turns temporal causality — invisible in
every tree/table view — into the primary picture. TUI and web.

## 3. `STATS` / GROUP BY stage in the query language

A pipe stage on the existing engine:
`proto == tcp | stats sum(bytes), count() by endpoint sort sum(bytes) desc`
— Splunk-style analytics over streams, one implementation serving
`--stats` tables in the CLI, the TUI, and a web results grid. "Top
talkers inside VXLAN tunnels" becomes a one-liner. Cheapest of the top
three since the parser/evaluator already exists.

## Ranked lower

- **Query watches in live mode** — pin named queries as live tiles with
  sparklines; emit an NDJSON event the moment a stream first matches.
  Great ops value, modest effort, less of a headline.
- **Endpoint graph view** — force-directed comms map, edge width =
  bytes, click-through to streams. Fun, but several products have one.
- **"Streams like this" similarity** — cluster by series-rollup
  shape/timing to find behavioral twins of a suspicious flow. The most
  novel scientifically; highest risk to get right.
- **Follow-stream payload reassembly** — deferred: the aggregator
  deliberately retains no payload bytes, so this is an engine-level
  architecture change, and it chases Wireshark parity rather than doing
  something it can't.
