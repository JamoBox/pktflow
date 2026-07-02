# Task 07 — Capture I/O

**Goal:** `pktflow-capture`: the only crate touching libpcap/Npcap (D1). One source
abstraction, two implementations (offline file, live device), plus interface enumeration —
feeding borrowed packet buffers + `PacketMeta` into the engine/aggregator pipeline.

**Depends on:** 00 (01.2 for `PacketMeta`). Parallel to 03–05. **Blocks:** 08.
**PRD:** FR-22, FR-23, §7 cross-platform.

## Sub-tasks

- [ ] [07.1 Source abstraction](01-source-abstraction.md) — `PacketSource`, DLT mapping
- [ ] [07.2 Offline replay](02-offline.md) — pcap/pcapng files (FR-22a)
- [ ] [07.3 Live capture & interfaces](03-live.md) — devices, listing, BPF (FR-22b, FR-23)

## Definition of done

CLI-shaped smoke test: open a fixture file → stream packets through `Engine::dissect` →
counts match the file, on Linux and Windows CI (file path only; live path covered by
`#[ignore]`d manual tests + a loopback test where CI permits).
