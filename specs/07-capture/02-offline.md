# 07.2 — Offline replay

> Task: [07 Capture](README.md) · Depends on: 07.1 · PRD: FR-22 "capture file" · D1, D2

## Goal
Read `.pcap` and `.pcapng` files through the same `PacketSource`, as fast as the disk allows,
with deterministic results.

## Specification

```rust
pub struct FileSource { /* pkttap pure-Rust reader + optional pktbaffle BPF VM */ }
impl FileSource {
    pub fn open(path: &Path) -> Result<FileSource, CaptureError>;
    pub fn open_with_filter(path: &Path, filter: Option<&str>) -> Result<FileSource, CaptureError>;
}
impl PacketSource for FileSource { /* ... */ }
```

- `pkttap` handles both container formats (`.pcap` and `.pcapng`) transparently via pure-Rust
  parsing (D1) — no external C library build or runtime dependency. `FileFormat` errors
  pass through `pkttap`'s message plus the path.
- **Offline BPF filtering:** supported via `pktbaffle`'s userspace software VM (`pktbaffle::Vm`).
  BPF filter strings passed via `--filter` are compiled by `pktbaffle` and evaluated against
  raw packet buffers during file replay, discarding non-matching packets before ingestion.
- **Timestamps:** file-provided, converted to `SystemTime` in `PacketMeta`; the aggregator's
  packet-time clock (05.6) makes replay of old captures behave exactly as live processing
  would have — no "everything instantly idle-times-out" bug. Out-of-order timestamps (real
  files have them): the clock is monotonic-max (05.6), packets still ingest; a
  `timestamps_regressed` counter surfaces in the summary.
- **Multi-linktype pcapng:** v1 uses the file's first interface's link type for the whole
  run; packets from interfaces with a different DLT are counted-and-skipped
  (`mixed_linktype_skipped` counter) rather than misparsed. Full per-interface routing is a
  v2 nicety; the counter keeps it honest.
- Eviction default for file sources is `EvictionPolicy::None` (D2) — set by the CLI, not by
  this crate (capture doesn't know about aggregation).

## Acceptance criteria
- [x] Fixture `.pcap` and `.pcapng` files (09.2) replay with exact packet counts, lens, and
      timestamps.
- [x] Offline BPF filtering via `pktbaffle` VM matches expected packet subset during replay.
- [x] Nonexistent / non-capture / zero-packet files produce clean `CaptureError`s and a
      clean empty run respectively.
- [x] Out-of-order-timestamp fixture: all packets ingested, counter set, no panic.
- [x] Determinism: two replays of the same file produce byte-identical JSON output
      (hooks into 00.3's determinism smoke).
