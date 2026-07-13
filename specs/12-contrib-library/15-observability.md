# 12.15 — Observability & telemetry pipelines: StatsD, Graphite, Zabbix

> Task: [12 Contrib library](README.md) · Depends on: 02–06 · Cross-refs: 11.11 (the
> network-telemetry domain this is the *application*-telemetry sibling of) · PRD: FR-32 ·
> D4, D7, D14, D16

## Goal
The metrics-pipeline protocols every modern deployment emits constantly — the application
sibling of 11.11's SNMP/NetFlow world. High packet rates, tiny well-framed payloads, and an
analytic question ("what is instrumented, and how hard is it hammering the pipeline?") that
maps perfectly onto rollups: metric names are this domain's DNS-query-names.

## Specification

**statsd** (StatsD line protocol — Etsy's statsd project documentation, extended by
DogStatsD; *no standards body*).

| Item | Spec |
|---|---|
| Claims | `UdpPort(8125)` |
| Fields | `Keys`: `app` (shared, constant `Str("statsd")`) · `Structural`: `metric_count` (U64 — newline-separated metrics per datagram), `metric_type` (Str, first metric's — `c` counter/`g` gauge/`ms` timer/`h` histogram/`s` set/`d` distribution) · `Full`: `name` (Str, first metric's dotted path), `sample_rate` (present when `|@` given), `has_tags` (Bool — DogStatsD `#` extension observed) |
| Hint | `Terminal` (metric *values* are content by this domain's cap — the pipeline's shape matters, individual samples don't: D7) |
| Identity | key `[{app, None}]`, one child per UDP stream |
| Rollups | `Accumulate` on `name` (the instrumented-metric inventory — D4's 64-value set cap plus overflow flag is load-bearing here and that is fine: "more than 64 distinct metrics" is itself the finding); `Accumulate` on `metric_type` |

**graphite** (Graphite plaintext protocol — the Graphite project's feeding-carbon
documentation; *no standards body*).

| Item | Spec |
|---|---|
| Claims | `TcpPort(2003)` |
| Fields | `Keys`: `app` (shared, constant `Str("graphite")`) · `Structural`: `line_count` (complete `path value timestamp\n` lines in this segment) · `Full`: `path` (Str, first line's), `timestamp` (U64, first line's — sanity-checked to a plausible epoch range, the cheap validation this format offers) |
| Hint | `Terminal`; a segment starting mid-line declines (no reassembly, D7 — the 06.6 DNS-over-TCP honesty note, text-pipeline edition) |
| Identity | key `[{app, None}]`, one child per TCP session |
| Rollups | `Accumulate` on `path` (same D4 stance as `statsd.name`) |

**zabbix** (Zabbix protocol — zabbix.com protocol documentation; *no standards body*).

| Item | Spec |
|---|---|
| Claims | `TcpPort(10050)` (agent, passive checks), `TcpPort(10051)` (server/trapper, active checks) |
| Fields | `Keys`: `app` (shared, constant `Str("zabbix")`) · `Structural`: `magic` validated (`ZBXD` + protocol flags byte — flag 0x01 Zabbix communications, 0x02 compressed), `compressed` (Bool), `data_len` (LE) · `Full` (uncompressed JSON body only): `request` (Str — a bounded scan for the first `"request":"..."` member within the segment: `active checks`/`agent data`/`sender data`/`queue.get`/...; the `mongodb` first-key stance applied to JSON), plus legacy plaintext passive checks on 10050 (`key[params]\n`) → `item_key` (Str, key name up to `[`) |
| Hint | `Terminal` — compressed bodies are identified by flag + length, never inflated (explicit non-goal: decompression is content processing, D7) |
| Identity | key `[{app, None}]`, one child per TCP session |
| Rollups | `Accumulate` on `request`; `Accumulate` on `item_key` |

### Planned (Tier 2 — not yet specified)
| Protocol | Standard | Note |
|---|---|---|
| collectd | *Project doc* — collectd binary protocol | `UdpPort(25826)`; parts-based TLV, signed/encrypted modes are a D12 case |
| Fluentd forward | *Project spec* — fluent/fluentd forward protocol v1 | `TcpPort(24224)`; msgpack-framed, tag extraction is the prize |
| Graphite pickle | *Project doc* | `TcpPort(2004)`; Python-pickle framing — parse the envelope only, never unpickle (a security stance as much as a scope one) |
| Riemann | *Project doc* | `TcpPort(5555)`; length-prefixed protobuf |
| NSCA | *Project doc* (Nagios) | `TcpPort(5667)`; XOR/static-key obfuscation — a D12-adjacent honesty write-up |
| Zabbix agent 2 / TLS modes | Zabbix docs | PSK/cert-wrapped variants of the above — D12 ceiling = `tls` fields |
| OTLP, Prometheus scrape & remote-write | — | All ride HTTP/1.1, HTTP/2, or gRPC — 11.8's territory (and gRPC is its Tier 2); cross-referenced so the modern observability stack shows as placed, not missed |

## Acceptance criteria
- [ ] `statsd` fixture: a multi-metric datagram (counter + timer + tagged gauge) parses
      count/type/name/rate exactly; a 100-distinct-name replay drives the `name`
      accumulate into its overflow state and the flag is asserted (D4's cap tested as a
      feature, not an accident).
- [ ] `graphite` fixture: a multi-line feed parses first path/timestamp and line count
      exactly; a mid-line continuation segment declines; an implausible timestamp declines
      (validation criterion).
- [ ] `zabbix` fixtures: an active-checks request/response on 10051 (magic validated,
      `request` extracted), a legacy plaintext passive check on 10050 (`item_key`
      extracted), and a compressed-flag packet that yields envelope fields only — all
      three framing modes proven.
- [ ] All three app-stream children form correctly under their transport streams
      (06.6 pattern).
