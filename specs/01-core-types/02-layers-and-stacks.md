# 01.2 — Layers & stacks

> Task: [01 Core types](README.md) · Depends on: 01.1 · PRD: FR-10, §4.B "Layer", §10 "Stack"

## Goal
The record type for one parsed protocol header, and the per-packet accumulation of those
records — the unit the parser yields (04) and the aggregator consumes (05).

## Specification

```rust
pub struct LayerRecord {
    pub protocol: ProtocolName,   // = &'static str, the plugin's declared name, e.g. "ipv4"
    pub offset: usize,            // byte offset of this header within the packet
    pub header_len: usize,        // bytes consumed by this header
    pub fields: FieldMap,         // typed metadata (FR-10)
}
```

- Payload is **not** stored in the record; the remaining payload is a borrowed slice carried
  by the parser step (04.1). `LayerRecord` owns no packet bytes — captured byte values live
  in `fields` as `Value::Bytes`.
- `protocol` is the plugin's `name()`; uniqueness across registered plugins is enforced at
  registry build time (03.2).

```rust
pub struct PacketMeta {                      // capture-provided, protocol-free
    pub timestamp: SystemTime,
    pub caplen: usize,                       // bytes captured
    pub origlen: usize,                      // bytes on the wire
    pub link_type: LinkType,                 // pcap DLT, e.g. LinkType::ETHERNET
}

pub struct DissectedPacket {
    pub meta: PacketMeta,
    pub layers: Vec<LayerRecord>,            // outermost → innermost (the "stack")
    pub stop: StopReason,                    // why dissection ended (04.3)
    pub opaque_len: usize,                   // payload bytes beyond the last parsed layer
}
```

- `layers` order **is** the stack order (PRD §10); the aggregator derives parent→child
  stream nesting from it (05.3), including repeats (tunnels: two `ipv4` entries is normal).
- `opaque_len` feeds D9's per-stream opaque-byte accounting.

## Acceptance criteria
- [x] Types implemented; `DissectedPacket` is `Send` and self-contained (no borrows of the
      capture buffer), so it can cross the channel to the aggregation thread (D5).
- [x] Unit test: constructing a 3-layer stack preserves order and offsets are monotonic.
- [x] Size check documented: `LayerRecord` stays lean (target ≤ 64 bytes + fields) — noted in
      code comment only if a constraint forces a layout choice.
