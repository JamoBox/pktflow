//! Parse context: what a plugin sees while parsing (01.4, FR-17).
//!
//! The layers already parsed (outer context) and the effective extraction
//! depth. Read-only — plugins cannot mutate outer layers; all influence on
//! what happens next flows through their returned hint (02.2).

use crate::depth::Depth;
use crate::packet::{LayerRecord, PacketMeta};
use crate::value::Value;

/// Read-only view of an in-progress parse session, borrowed for the
/// duration of one `parse` call.
///
/// Borrowed data cannot be retained by plugins — `parse` takes `&ParseCtx`
/// and returns owned data, so any reference obtained here dies with the
/// call:
///
/// ```compile_fail
/// use std::time::SystemTime;
/// use pktflow_core::{Depth, LayerRecord, LinkType, PacketMeta, ParseCtx};
///
/// let stolen;
/// {
///     let layers: Vec<LayerRecord> = Vec::new();
///     let meta = PacketMeta {
///         timestamp: SystemTime::UNIX_EPOCH,
///         caplen: 0,
///         origlen: 0,
///         link_type: LinkType::ETHERNET,
///     };
///     let ctx = ParseCtx::new(&layers, Depth::Full, &meta);
///     stolen = ctx.prev(); // borrow of `layers`…
/// }
/// let _ = stolen; // …cannot outlive the session: does not compile
/// ```
pub struct ParseCtx<'a> {
    /// Outermost → innermost, all layers parsed so far.
    layers: &'a [LayerRecord],
    /// Effective depth (already clamped per 01.3).
    depth: Depth,
    meta: &'a PacketMeta,
}

impl<'a> ParseCtx<'a> {
    /// Built by the parser (04.1) for each `parse` call.
    pub fn new(layers: &'a [LayerRecord], depth: Depth, meta: &'a PacketMeta) -> Self {
        Self {
            layers,
            depth,
            meta,
        }
    }

    pub fn depth(&self) -> Depth {
        self.depth
    }

    pub fn meta(&self) -> &PacketMeta {
        self.meta
    }

    /// Innermost layer with this protocol name, if any (FR-17: nearest
    /// occurrence). With stacked repeats (nested tunnels, QinQ VLANs) the
    /// nearest enclosing occurrence wins; no API exposes "all occurrences"
    /// in v1.
    pub fn layer(&self, protocol: &str) -> Option<&LayerRecord> {
        self.layers.iter().rev().find(|l| l.protocol == protocol)
    }

    /// Convenience: `self.layer(protocol)?.fields.get(field)`.
    pub fn field(&self, protocol: &str, field: &str) -> Option<&Value> {
        self.layer(protocol)?.fields.get(field)
    }

    /// The immediately preceding layer (the plugin's direct predecessor),
    /// if any.
    pub fn prev(&self) -> Option<&LayerRecord> {
        self.layers.last()
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use super::*;
    use crate::packet::LinkType;
    use crate::value::FieldMap;

    fn meta() -> PacketMeta {
        PacketMeta {
            timestamp: SystemTime::UNIX_EPOCH,
            caplen: 128,
            origlen: 128,
            link_type: LinkType::ETHERNET,
        }
    }

    fn layer(protocol: &'static str, offset: usize, key: &'static str, v: u64) -> LayerRecord {
        let mut fields = FieldMap::new();
        fields.insert(key, Value::U64(v));
        LayerRecord {
            protocol,
            offset,
            header_len: 0,
            fields,
        }
    }

    /// The spec's stacked-repeats fixture: an IPv4-in-GRE-in-IPv4 tunnel.
    fn tunnel_stack() -> Vec<LayerRecord> {
        vec![
            layer("eth", 0, "ethertype", 0x0800),
            layer("ipv4", 14, "ttl", 64), // outer (index 1)
            layer("gre", 34, "proto", 0x0800),
            layer("ipv4", 38, "ttl", 8), // inner (index 3)
            layer("tcp", 58, "src_port", 443),
        ]
    }

    #[test]
    fn layer_lookup_is_innermost_wins() {
        let layers = tunnel_stack();
        let m = meta();
        let ctx = ParseCtx::new(&layers, Depth::Full, &m);

        let inner = ctx.layer("ipv4").expect("ipv4 present");
        // The record at index 3 (inner tunnel hop), not index 1 (outer).
        assert!(std::ptr::eq(inner, &layers[3]));
        assert_eq!(inner.offset, 38);
        assert_eq!(inner.fields.get("ttl"), Some(&Value::U64(8)));

        // Non-repeated layers resolve normally.
        assert!(std::ptr::eq(ctx.layer("eth").expect("eth"), &layers[0]));
    }

    #[test]
    fn prev_is_the_direct_predecessor() {
        let layers = tunnel_stack();
        let m = meta();
        // A hypothetical next parse (the layer after tcp) sees tcp.
        let ctx = ParseCtx::new(&layers, Depth::Full, &m);
        assert_eq!(ctx.prev().map(|l| l.protocol), Some("tcp"));

        // First layer of a packet has no predecessor.
        let empty = ParseCtx::new(&[], Depth::Full, &m);
        assert!(empty.prev().is_none());
    }

    #[test]
    fn field_miss_is_none_not_panic() {
        let layers = tunnel_stack();
        let m = meta();
        let ctx = ParseCtx::new(&layers, Depth::Full, &m);

        assert_eq!(ctx.field("ipv6", "hop_limit"), None); // absent protocol
        assert_eq!(ctx.field("ipv4", "no_such_field"), None); // absent field
        assert_eq!(ctx.field("ipv4", "ttl"), Some(&Value::U64(8))); // innermost hit
    }

    #[test]
    fn depth_and_meta_are_exposed() {
        let layers = tunnel_stack();
        let m = meta();
        let ctx = ParseCtx::new(&layers, Depth::Keys, &m);
        assert_eq!(ctx.depth(), Depth::Keys);
        assert_eq!(ctx.meta(), &m);
    }
}
