# 08.5 — Rendering & JSON output

> Task: [08 CLI](README.md) · Depends on: 08.2–08.4 · PRD: FR-28 · D8

## Goal
Human-friendly rendering of well-known field shapes (FR-28) and the machine-readable D8
schema that doubles as the e2e test surface.

## Specification

**Text rendering (FR-28).** A CLI-side renderer keyed on `(protocol, field_name)` with a
shape fallback — core stays presentation-free (01.1):

| Shape | Rendering |
|---|---|
| 6-byte `Bytes` named `*_mac` | `aa:bb:cc:dd:ee:ff` |
| 4-byte `Bytes` named `*_addr`/`*_ip` | dotted quad |
| 16-byte `Bytes` named `*_addr`/`*_ip` | RFC 5952 compressed IPv6 |
| tcp `flags` | symbolic `SYN+ACK` |
| other `Bytes` | lowercase hex, `…` past 32 bytes |
| `U64`/`I64` | decimal, thousands-separated in tables |
| durations / byte counts | `00:04:12` / `1.2 MB` (SI) in tables; exact in drill-down |

**JSON (`--format json`, D8).** Envelope: `{"pktflow": 1, ...}` — the schema version;
additive changes only within major.

- *Offline* — one document on stdout:

```json
{ "pktflow": 1, "mode": "offline", "source": "path.pcap",
  "summary": { "packets": 1204, "bytes": 1234567, "stop_classes": {"clean": 1200, "unknown_payload": 4},
               "streams": {"eth": 2, "ipv4": 3, "tcp": 5}, "capture_drops": 0 },
  "streams": [ { "id": 42, "protocol": "tcp", "parent": 17, "children": [55],
      "endpoint_a": {"src_port": 52341}, "endpoint_b": {"dst_port": 443},
      "initiator": "a_to_b", "state": "established", "closed": null,
      "first_seen": "2026-07-02T12:04:01.221Z", "last_seen": "…", 
      "packets": {"a_to_b": 612, "b_to_a": 328}, "bytes": {"a_to_b": 641210, "b_to_a": 346021},
      "opaque_bytes": 987102,
      "rollups": {"flags": {"kind": "accumulate", "values": ["SYN","SYN+ACK","ACK"],
                             "distinct": 3, "observations": 940, "overflow": false}} } ] }
```

  `streams` is the flat node list (tree reconstructable via `parent`/`children`); ordering =
  `created_seq` (deterministic, 05.7). Values rendered per the text table *for well-known
  shapes* (MACs/IPs as strings — JSON consumers deserve readable endpoints too); unknown
  bytes as hex strings; timestamps RFC 3339 UTC. This shape is what `--batch` gives (offline
  or live, the source doesn't matter — `--batch` is what selects it).
- *Default (unless `--batch`)* — NDJSON events:
  `{"event":"stream_new"|"stream_update"|"stream_closed"|"summary", …}` with `stream_update`
  throttled to ≥1 s per stream; `stream_closed` carries the final record + `close_reason`;
  `summary` is the last line (D8).
- `packets` subcommand + json = NDJSON, one `DissectedPacket` projection per line (layers,
  fields, stop reason) — the 09 suites' dissection-assertion format.

## Acceptance criteria
- [x] Renderer table implemented with unit tests per shape, incl. IPv6 compression edge
      cases (`::`, embedded v4) and the hex elision.
- [x] Offline JSON validated against a checked-in JSON Schema file (`schema/streams-v1.json`)
      in CI; goldens for the fixtures.
- [x] NDJSON live events smoke-tested via replay pacing; final `summary` line always present
      (even on Ctrl-C — graceful path, 08.1).
- [x] Determinism: repeated runs produce byte-identical offline JSON (00.3 hook).
