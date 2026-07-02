# 08.4 — Packets mode

> Task: [08 CLI](README.md) · Depends on: 08.1 · PRD: FR-26 · D9

## Goal
The retained per-packet debug lens: one summary line per packet, per-layer field dumps under
verbosity, stop reasons visible — the tool for "why didn't this parse / why is this stream
weird".

## Specification

```text
pktflow packets -r FILE [-v | -vv] [--depth …]
```

- **Base (no `-v`):** one line per packet:
  `N  12:04:01.221  eth ▸ ipv4 ▸ udp ▸ dns  10.0.0.5:34567 → 93.184.216.34:53  qname=example.com  90 B  [complete]`
  — index, timestamp, layer chain, innermost endpoints (source-order, *not* canonicalized —
  this is the per-packet view; direction arrows belong to streams), one headline field
  contributed by the innermost layer that offers one, caplen, stop class.
- **`-v`:** adds a per-layer block per packet — every extracted field at the active depth,
  offsets and header lengths included. `-vv`: adds a bounded hex dump of unparsed payload
  (first 64 bytes) and `via_heuristic` markers (03.3).
- **Stop-reason surfacing (D9's home):** non-clean stops render with detail —
  `[unclaimed: udp_port:51820]`, `[truncated: needed 20, have 14]` — the exact answer to
  "why did dissection stop". The end summary already counts classes (08.1); this is where
  individual culprits are found.
- Packets mode still runs the aggregator (streams summary at end is often the context a
  debugger wants) unless `--no-streams` is passed for maximum-throughput triage.
- Headline-field selection: a plugin-facing nicety, not a contract — v1 hardcodes a
  preference list in the CLI (dns qname, arp opcode, tcp flags, icmp type…) with fallback to
  nothing. Explicitly *not* part of the plugin trait (presentation stays out of core).

## Acceptance criteria
- [ ] Golden tests for base/`-v`/`-vv` on a mixed fixture including an unclaimed-port packet
      and a truncated packet (stop details rendered as specified).
- [ ] `--depth keys` visibly reduces `-v` field blocks (FR-16 demonstrable from the CLI).
- [ ] Throughput sanity: packets mode with `--no-streams` on the 09.4 benchmark capture is
      not slower than streams mode (it must be the cheap lens).
