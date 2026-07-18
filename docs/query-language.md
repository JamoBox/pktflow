# The stream query language

One query engine (`pktflow-view`) powers three surfaces, so the same
expression means the same thing everywhere:

- the **TUI** filter box (`/` in `pktflow tui`),
- the **web UI** search bar (`pktflow serve`, evaluated server-side via
  `GET /api/search?q=…`),
- the **CLI**: `pktflow streams … --where 'EXPR'`.

In the tree views (TUI, web, CLI tree) results keep their hierarchy
context: the visible set is every match **plus its ancestors**, ancestors
auto-expanded (the web UI dims ancestor-only rows). `--layer` tables and
the `--batch --format json` envelope contain matches only.

## Quick reference

```text
dns                                  free text over protocol/#id/endpoints/state
"192.168.203.5"                      quoted free text (spaces, keywords)
/te?ls|ssl/                          bare regex over the same text (case-insensitive)
proto == dns                         field comparison ( = and 'is' are aliases)
bytes > 10k                          k/M/G/T suffixes on byte & count fields
duration >= 5m                       ms/s/m/h on duration (m = minutes here)
port == 443                          this layer or any ancestor — "riding on 443"
qname =~ /google/                    any key field or rollup value, by name
endpoint contains 192.168            'contains' / 'has' substring operator
under == vxlan                       any ancestor protocol (tunnel contents)
parent == udp                        direct parent protocol
NOT closed AND (proto == tcp OR proto == udp)
WHERE proto == dns                   leading WHERE is accepted and ignored
tcp 10.0.0                           adjacent terms are AND
```

## Grammar

```text
query   := [WHERE] or
or      := and (OR and)*
and     := unary ([AND] unary)*         -- juxtaposition is AND
unary   := NOT unary | primary
primary := '(' or ')' | comparison | flag | free-text | /regex/
comparison := field op value
op      := == | = | is | != | =~ | !~ | > | >= | < | <= | contains | has
```

Keywords (`AND OR NOT WHERE contains has is`) are case-insensitive;
`&&`/`||`/`!` also work. Operators may hug their operands (`bytes>=10k`).

## Terms

**Free text** — a bare word or quoted string substring-matches the
stream's *searchable text*: `protocol #id endpoints state` (exactly what a
streams-view row shows), case-insensitively. A bare `/regex/` does the
same as a case-insensitive regex; escape a literal slash as `\/`.

**Flags** — bare `closed`, `live` (alias `open`), `root` (no parent),
`leaf` (no children), `condensed` (a folded fan-out group, D16).

**Comparisons** — `field op value`. String equality is case-insensitive;
`contains` is substring; `=~` / `!~` compile the value as a
case-insensitive regex (`/…/` or a plain word). `>` `>=` `<` `<=` compare
numbers only. A comparison matches if *any* candidate value of the field
matches (a field can be multi-valued: both endpoints, every rollup
observation, every ancestor port).

## Fields

| Field | Meaning |
|---|---|
| `proto` / `protocol` | this stream's protocol name |
| `id` | display id (`#n` in every view) |
| `packets` / `pkts`, `bytes`, `opaque` | totals across both directions |
| `duration` / `dur` | last-seen − first-seen, in seconds (`ms/s/m/h` suffixes) |
| `depth` | nesting depth (roots are 0) |
| `children` | direct child count |
| `state` | lifecycle state (empty when the protocol has none) |
| `reason` / `close_reason` | close reason (`capture-end`, `idle-timeout`, …) |
| `endpoint` / `ep` / `host` / `addr` | rendered endpoint sides + qualifier fields |
| `port` | numeric `*_port` key fields of this stream **or any ancestor** |
| `parent` | direct parent's protocol name (empty for roots) |
| `under` / `ancestor` / `in` | every ancestor's protocol name |
| anything else | key field or rollup of that name (`vni == 100`, `qname =~ /google/`, `flags contains SYN`) |

Numeric values accept magnitude suffixes `k`/`M`/`G`/`T` (SI, matching the
byte columns; `kb`/`mb`/… also accepted). On `duration` the suffixes are
time units instead: `500ms`, `90s`, `5m`, `1h`.

## Errors

A malformed expression never silently filters: the TUI and web UI show
the parse error (with a column pointer) and keep the tree unfiltered;
`--where` exits 2 before the capture is opened. `--where` combined with
the live NDJSON stream (`--format json` without `--batch`) is refused —
NDJSON events are per-stream and unfiltered.

## Worked examples

```sh
# Everything carried inside VXLAN tunnels, as a contextual tree
pktflow streams -r overlay.pcap --batch --where 'under == vxlan'

# Fat, long-lived TCP sessions
pktflow streams -r big.pcap --batch --where 'proto == tcp AND bytes > 1M AND duration > 30s'

# DNS lookups for a domain, as JSON for scripting
pktflow streams -r cap.pcap --batch --format json --where 'qname =~ /corp\.example/' | jq '.streams[].id'

# Anything touching one host, on either side, at any layer
pktflow streams -r cap.pcap --batch --where 'endpoint contains 10.1.4.7'

# Streams still open when the capture ended, excluding chatter
pktflow streams -r cap.pcap --batch --where 'NOT reason == capture-end OR (live AND packets > 10)'
```
