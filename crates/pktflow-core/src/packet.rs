//! Layer records and per-packet stacks (01.2, FR-10).
//!
//! One [`LayerRecord`] per parsed protocol header; a [`DissectedPacket`]
//! accumulates them outermost → innermost. This is the unit the parser (04)
//! yields and the aggregator (05) consumes.

use std::time::SystemTime;

use crate::error::StopReason;
use crate::value::FieldMap;

/// A plugin's declared protocol name, e.g. `"ipv4"`. Uniqueness across
/// registered plugins is enforced at registry build time (03.2).
pub type ProtocolName = &'static str;

/// A pcap DLT (data-link type) value, kept as a plain number so core stays
/// free of the capture dependency. Constants cover the DLTs the reference
/// set routes on; anything else still round-trips untouched.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct LinkType(pub u16);

impl LinkType {
    /// DLT_NULL — BSD loopback.
    pub const NULL: LinkType = LinkType(0);
    /// DLT_EN10MB — Ethernet II.
    pub const ETHERNET: LinkType = LinkType(1);
    /// DLT_RAW — raw IP, no link header.
    pub const RAW: LinkType = LinkType(101);
}

/// Capture-provided, protocol-free facts about one packet.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PacketMeta {
    pub timestamp: SystemTime,
    /// Bytes captured.
    pub caplen: usize,
    /// Bytes on the wire.
    pub origlen: usize,
    pub link_type: LinkType,
}

/// One parsed protocol header.
///
/// Owns no packet bytes: the remaining payload is a borrowed slice carried
/// by the parser step (04.1), and captured byte values live in `fields` as
/// `Value::Bytes`. Kept lean — see the size assertion in the tests.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LayerRecord {
    /// The plugin's declared `name()`.
    pub protocol: ProtocolName,
    /// Byte offset of this header within the packet.
    pub offset: usize,
    /// Bytes consumed by this header.
    pub header_len: usize,
    /// Typed metadata (FR-10).
    pub fields: FieldMap,
}

/// A fully dissected packet: the stack of parsed layers plus why parsing
/// stopped. Self-contained (no borrows of the capture buffer) so it can
/// cross the channel to the aggregation thread (D5).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DissectedPacket {
    pub meta: PacketMeta,
    /// Outermost → innermost — the order **is** the stack order (PRD §10).
    /// Repeats are normal (tunnels: two `ipv4` entries).
    pub layers: Vec<LayerRecord>,
    /// Why dissection ended (04.3).
    pub stop: StopReason,
    /// Payload bytes beyond the last parsed layer (D9 opaque accounting).
    pub opaque_len: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::value::Value;

    // D5: the packet must cross an MPSC channel to the aggregation thread,
    // so it has to be Send and own everything ('static = no borrows of the
    // capture buffer).
    const _: fn() = || {
        fn assert_send_and_owned<T: Send + 'static>() {}
        assert_send_and_owned::<DissectedPacket>();
    };

    fn layer(protocol: ProtocolName, offset: usize, header_len: usize) -> LayerRecord {
        let mut fields = FieldMap::new();
        fields.insert("len", Value::U64(header_len as u64));
        LayerRecord {
            protocol,
            offset,
            header_len,
            fields,
        }
    }

    #[test]
    fn three_layer_stack_preserves_order_and_monotonic_offsets() {
        let layers = vec![
            layer("eth", 0, 14),
            layer("ipv4", 14, 20),
            layer("udp", 34, 8),
        ];
        let packet = DissectedPacket {
            meta: PacketMeta {
                timestamp: SystemTime::UNIX_EPOCH,
                caplen: 60,
                origlen: 60,
                link_type: LinkType::ETHERNET,
            },
            layers,
            stop: StopReason::Complete,
            opaque_len: 0,
        };

        let names: Vec<_> = packet.layers.iter().map(|l| l.protocol).collect();
        assert_eq!(names, ["eth", "ipv4", "udp"]);

        // Each layer starts exactly where the previous header ended.
        let mut expected_offset = 0;
        for l in &packet.layers {
            assert_eq!(l.offset, expected_offset);
            expected_offset += l.header_len;
        }
        assert_eq!(expected_offset, 42);
    }

    #[test]
    fn layer_record_stays_lean() {
        // Target from the spec: ≤ 64 bytes + the FieldMap's heap. Today:
        // &'static str (16) + 2×usize (16) + Vec header (24) = 56.
        assert!(
            std::mem::size_of::<LayerRecord>() <= 64,
            "LayerRecord grew past 64 bytes ({}); check the layout",
            std::mem::size_of::<LayerRecord>()
        );
    }
}
