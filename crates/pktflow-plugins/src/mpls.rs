//! MPLS (RFC 3032): the label-switched underlay — one plugin walks the
//! whole label stack (each entry `label(20) | tc(3) | s(1) | ttl(8)`, 4
//! bytes) until the bottom-of-stack bit, so a stacked LSP is one layer,
//! not one layer per label (the VLAN precedent of one plugin per tagging
//! scheme, not per tag).
//!
//! MPLS famously has **no next-protocol field** — with one exception the
//! header itself provides: the reserved Explicit NULL labels (RFC 3032
//! §2.1, RFC 4182). A bottom-of-stack label 0 (IPv4 Explicit NULL) or 2
//! (IPv6 Explicit NULL) *names* the payload protocol, so those dispatch
//! directly by name (the most explicit hint the header allows, 02.1).
//! Any other bottom label names nothing: what follows is whatever the
//! LSP's endpoints agreed on out of band, so the honest hint is
//! [`Hint::Unknown`] — the gated heuristic fallback (03.4) then lets
//! `ipv4`/`ipv6` claim the payload via their probes, which covers the
//! dominant IP-over-MPLS case without this plugin peeking past its own
//! header (contract rule 1). Pseudowire payloads (EoMPLS with a control
//! word) stay unknown rather than guessed.
//!
//! Stream identity follows the GRE-`key`/VXLAN-`vni` shared-qualifier
//! shape (06.5): one stream per top label — the label *is* the LSP as far
//! as this hop can see.

use pktflow_core::{
    ByteReader, Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx,
    ParseError, ParsedLayer, ProtocolName, RouteId, StreamIdentity, Value,
};

const LABEL: FieldName = "label";
const TC: FieldName = "tc";
const TTL: FieldName = "ttl";
const STACK_DEPTH: FieldName = "stack_depth";
const LABELS: FieldName = "labels";

/// Real stacks run a handful of labels (transport + service + entropy);
/// anything past this is hostile or corrupt, not an LSP.
const MAX_LABELS: usize = 16;

/// RFC 3032 §2.1 reserved labels that name the payload protocol when
/// they sit at the bottom of the stack.
const IPV4_EXPLICIT_NULL: u64 = 0;
const IPV6_EXPLICIT_NULL: u64 = 2;

static KEY: &[KeyField] = &[KeyField {
    a: LABEL,
    b: None, // shared qualifier: one stream per top label (= LSP)
}];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: &[],
};

pub struct Mpls;

impl LayerPlugin for Mpls {
    fn name(&self) -> ProtocolName {
        "mpls"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let mut entries: Vec<Value> = Vec::new();
        let (mut top_label, mut top_tc, mut top_ttl) = (0u64, 0u64, 0u64);
        let bottom_label = loop {
            if entries.len() == MAX_LABELS {
                return Err(ParseError::Malformed("MPLS: label stack too deep"));
            }
            let entry = r.u32_be()?;
            let label = u64::from(entry >> 12);
            if entries.is_empty() {
                top_label = label;
                top_tc = u64::from((entry >> 9) & 0x7);
                top_ttl = u64::from(entry & 0xFF);
            }
            entries.push(Value::U64(label));
            if entry & 0x100 != 0 {
                break label; // bottom of stack
            }
        };

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(LABEL, Value::U64(top_label));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(STACK_DEPTH, Value::U64(entries.len() as u64));
            fields.insert(TC, Value::U64(top_tc));
            fields.insert(TTL, Value::U64(top_ttl));
        }
        let header_len = 4 * entries.len();
        if ctx.depth() >= Depth::Full {
            fields.insert(LABELS, Value::List(entries));
        }

        // An Explicit NULL at the bottom is the one case where the stack
        // itself names its payload (module doc); everything else defers
        // to the gated heuristics instead of guessing.
        let hint = match bottom_label {
            IPV4_EXPLICIT_NULL => Hint::ByProtocol("ipv4"),
            IPV6_EXPLICIT_NULL => Hint::ByProtocol("ipv6"),
            _ => Hint::Unknown,
        };
        Ok(ParsedLayer {
            header_len,
            fields,
            hint,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[
            RouteId::EtherType(0x8847), // unicast
            RouteId::EtherType(0x8848), // multicast
        ]
    }

    // No probe: 4 opaque bytes have no recognizable structure to score
    // honestly, and MPLS is always reached by explicit EtherType anyway.

    fn stream_identity(&self) -> Option<&StreamIdentity> {
        Some(&IDENTITY)
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use pktflow_core::{LinkType, PacketMeta};

    use super::*;

    fn parse(bytes: &[u8]) -> Result<ParsedLayer, ParseError> {
        let meta = PacketMeta {
            timestamp: SystemTime::UNIX_EPOCH,
            caplen: bytes.len(),
            origlen: bytes.len(),
            link_type: LinkType::ETHERNET,
        };
        Mpls.parse(bytes, &ParseCtx::new(&[], Depth::Full, &meta))
    }

    /// One label-stack entry: `label | tc | s | ttl`.
    fn entry(label: u32, tc: u8, s: bool, ttl: u8) -> [u8; 4] {
        let word = (label << 12) | (u32::from(tc) << 9) | (u32::from(s) << 8) | u32::from(ttl);
        word.to_be_bytes()
    }

    #[test]
    fn single_label_parses() {
        // Label 16 (first unreserved value), TC 5, bottom of stack, TTL 64.
        let bytes = entry(16, 5, true, 64);
        let parsed = parse(&bytes).expect("valid single-label stack");
        assert_eq!(parsed.header_len, 4);
        assert_eq!(parsed.hint, Hint::Unknown);
        assert_eq!(parsed.fields.get(LABEL), Some(&Value::U64(16)));
        assert_eq!(parsed.fields.get(TC), Some(&Value::U64(5)));
        assert_eq!(parsed.fields.get(TTL), Some(&Value::U64(64)));
        assert_eq!(parsed.fields.get(STACK_DEPTH), Some(&Value::U64(1)));
        assert_eq!(
            parsed.fields.get(LABELS),
            Some(&Value::List(vec![Value::U64(16)]))
        );
    }

    #[test]
    fn stacked_labels_walk_to_bottom_and_key_on_top() {
        // Transport label 100 over service label 200: fields come from the
        // top entry, the stack is fully consumed.
        let mut bytes = entry(100, 0, false, 255).to_vec();
        bytes.extend_from_slice(&entry(200, 0, true, 255));
        bytes.extend_from_slice(&[0x45, 0x00]); // payload beyond the stack
        let parsed = parse(&bytes).expect("valid two-label stack");
        assert_eq!(parsed.header_len, 8);
        assert_eq!(parsed.fields.get(LABEL), Some(&Value::U64(100)));
        assert_eq!(parsed.fields.get(STACK_DEPTH), Some(&Value::U64(2)));
        assert_eq!(
            parsed.fields.get(LABELS),
            Some(&Value::List(vec![Value::U64(100), Value::U64(200)]))
        );
    }

    #[test]
    fn ipv4_explicit_null_at_bottom_names_the_payload() {
        // Transport label over IPv4 Explicit NULL (RFC 4182's stack shape):
        // the bottom label is a definitive protocol indicator.
        let mut bytes = entry(100, 0, false, 255).to_vec();
        bytes.extend_from_slice(&entry(0, 0, true, 255));
        let parsed = parse(&bytes).expect("valid explicit-null stack");
        assert_eq!(parsed.hint, Hint::ByProtocol("ipv4"));
        assert_eq!(parsed.fields.get(LABEL), Some(&Value::U64(100)));
    }

    #[test]
    fn ipv6_explicit_null_at_bottom_names_the_payload() {
        let bytes = entry(2, 0, true, 64);
        let parsed = parse(&bytes).expect("valid explicit-null stack");
        assert_eq!(parsed.hint, Hint::ByProtocol("ipv6"));
    }

    #[test]
    fn explicit_null_above_the_bottom_is_not_a_protocol_indicator() {
        // Label 0 in a non-bottom position doesn't name the payload —
        // only the bottom entry sits next to it.
        let mut bytes = entry(0, 0, false, 255).to_vec();
        bytes.extend_from_slice(&entry(200, 0, true, 255));
        let parsed = parse(&bytes).expect("valid stack");
        assert_eq!(parsed.hint, Hint::Unknown);
    }

    #[test]
    fn unterminated_stack_declines() {
        // S bit never set: the stack runs off the end of the input.
        let mut bytes = entry(100, 0, false, 255).to_vec();
        bytes.extend_from_slice(&entry(200, 0, false, 255));
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn hostile_depth_declines_instead_of_walking_forever() {
        let mut bytes = Vec::new();
        for _ in 0..(MAX_LABELS + 1) {
            bytes.extend_from_slice(&entry(100, 0, false, 255));
        }
        bytes.extend_from_slice(&entry(200, 0, true, 255));
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn truncated_entries_decline() {
        let bytes = entry(16, 5, true, 64);
        for n in 0..bytes.len() {
            assert!(parse(&bytes[..n]).is_err(), "prefix of {n} bytes");
        }
    }
}
