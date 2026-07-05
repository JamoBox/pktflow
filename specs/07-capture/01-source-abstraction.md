# 07.1 — Source abstraction

> Task: [07 Capture](README.md) · Depends on: 01.2 · PRD: FR-22 · D1, D5

## Goal
One interface the CLI pumps regardless of file vs. device, delivering zero-copy buffers and
capture metadata, and owning the pcap↔core type mapping so core stays pcap-free (04.2 note).

## Specification

```rust
pub trait PacketSource {
    /// Blocking next packet. Ok(None) = clean end (file EOF / capture stopped).
    fn next_packet(&mut self) -> Result<Option<RawPacket<'_>>, CaptureError>;
    fn link_type(&self) -> LinkType;         // core's u16 space, mapped from pcap DLT here
    fn stats(&self) -> CaptureStats;         // received / dropped (kernel + buffer), FR-27
}

pub struct RawPacket<'a> {
    pub bytes: &'a [u8],                     // borrowed from pcap's buffer — valid until next call
    pub meta: PacketMeta,                    // timestamp, caplen, origlen, link_type (01.2)
}
```

- **Lending iterator shape:** `RawPacket` borrows the source's internal buffer (libpcap
  semantics), so `next_packet` takes `&mut self` and the previous packet dies at the next
  call. The pipeline (08) dissects immediately — `DissectedPacket` is owned (01.2) — so the
  borrow never needs to outlive one loop turn. This is *the* zero-copy decision: bytes are
  copied only into `Value::Bytes` fields, never wholesale.
- **Pump helper** (the D5 pipeline's producer side, shared by offline and live):

```rust
pub fn pump(src: &mut dyn PacketSource, engine: &Engine, opts: ParseOpts,
            tx: &SyncSender<DissectedPacket>, limit: Option<u64>) -> Result<PumpReport, CaptureError>;
```

  Bounded channel (default 1024) provides backpressure; `limit` implements FR-27's packet
  cap; `PumpReport` carries totals + `CaptureStats` for the final summary.
- `CaptureError`: `DeviceNotFound(String)`, `PermissionDenied` (with per-OS remediation
  text: setcap/sudo vs. Npcap install/admin), `FileFormat(String)`, `Io(io::Error)`,
  `Backend(String)`.

## Acceptance criteria
- [x] Trait + pump implemented; a `Vec<(SystemTime, Vec<u8>)>`-backed `MockSource` ships in
      the crate for tests (07/08/09 all reuse it).
- [x] Pump respects `limit` exactly and reports totals matching a fixture.
- [x] Backpressure verified: a stalled consumer blocks the pump rather than growing memory.
- [x] `PermissionDenied` remediation text present for both OSes (string-tested).
