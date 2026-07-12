//! mDNS (11.12, RFC 6762 — Multicast DNS): the exact RFC 1035 message
//! format `dns` (06.6) already parses, sent to the `224.0.0.251` /
//! `[ff02::fb]` multicast group on port 5353 instead of to a unicast
//! resolver. This plugin's `parse()` calls `dns::parse_message` — the
//! shared name-decompression/question/RR-walk routine — and adds only the
//! two bit interpretations mDNS itself repurposes from the class field
//! (RFC 6762 §5.4, §10.2). `dns`'s own contract and fields are unaffected;
//! this is code reuse, not a change to `dns`'s public shape.
//!
//! App-stream pattern (same as `dns`): no endpoint identity of its own, so
//! the key is one shared constant field (`app = "mdns"`) — one child
//! stream per UDP stream, home for the `qname` rollup (home-network
//! service-discovery names, the same PRD §4.A pattern `dns` demonstrates).
//!
//! `"mdns"` is deliberately its own key constant, not `dns`'s `"dns"`:
//! mDNS's local-network (`.local`) service namespace is semantically
//! distinct from resolver-hierarchy DNS traffic, and merging their streams
//! would blend two different questions an operator asks ("what's this host
//! resolving on the internet" vs. "what's on my LAN").

use pktflow_core::{
    Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx, ParseError, ParsedLayer,
    ProtocolName, RollupKind, RollupSpec, RouteId, StreamIdentity, Value,
};

use crate::dns::parse_message;

const APP: FieldName = "app";
const ID: FieldName = "id";
const IS_RESPONSE: FieldName = "is_response";
const OPCODE: FieldName = "opcode";
const RCODE: FieldName = "rcode";
const QNAME: FieldName = "qname";
const QTYPE: FieldName = "qtype";
const ANSWERS: FieldName = "answers";
const IS_MULTICAST_QUERY: FieldName = "is_multicast_query";
const CACHE_FLUSH: FieldName = "cache_flush";

/// RFC 6762 §5.4 / §10.2: both reuse the class field's top bit, whichever
/// section it's read from (question `QU`, answer cache-flush).
const TOP_BIT: u16 = 0x8000;

static KEY: &[KeyField] = &[KeyField { a: APP, b: None }];
static ROLLUPS: &[RollupSpec] = &[RollupSpec {
    field: QNAME,
    kind: RollupKind::Accumulate,
}];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: pktflow_core::Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: ROLLUPS,
};

pub struct Mdns;

impl LayerPlugin for Mdns {
    fn name(&self) -> ProtocolName {
        "mdns"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        // mDNS has no TCP framing (RFC 6762 is UDP multicast only, unlike
        // plain DNS's optional 2-byte TCP length prefix) — the message
        // starts at byte 0, always.
        let raw = parse_message(bytes)?;

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(APP, Value::from("mdns"));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(ID, Value::U64(u64::from(raw.id)));
            fields.insert(IS_RESPONSE, Value::Bool(raw.flags & 0x8000 != 0));
            fields.insert(OPCODE, Value::U64(u64::from((raw.flags >> 11) & 0xF)));
            fields.insert(RCODE, Value::U64(u64::from(raw.flags & 0xF)));
            if let (Some(name), Some(t)) = (raw.qname, raw.qtype) {
                fields.insert(QNAME, Value::from(name.as_str()));
                fields.insert(QTYPE, Value::U64(u64::from(t)));
            }
            if let Some(qclass) = raw.qclass {
                fields.insert(IS_MULTICAST_QUERY, Value::Bool(qclass & TOP_BIT != 0));
            }
            if let Some(acls) = raw.first_answer_class {
                fields.insert(CACHE_FLUSH, Value::Bool(acls & TOP_BIT != 0));
            }
        }
        if ctx.depth() >= Depth::Full {
            fields.insert(ANSWERS, Value::List(raw.answers));
        }

        Ok(ParsedLayer {
            header_len: raw.header_len,
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::UdpPort(5353)]
    }

    fn stream_identity(&self) -> Option<&StreamIdentity> {
        Some(&IDENTITY)
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use pktflow_core::{LinkType, PacketMeta};

    use super::*;

    fn meta(len: usize) -> PacketMeta {
        PacketMeta {
            timestamp: SystemTime::UNIX_EPOCH,
            caplen: len,
            origlen: len,
            link_type: LinkType::ETHERNET,
        }
    }

    fn ctx(depth: Depth, meta: &PacketMeta) -> ParseCtx<'_> {
        ParseCtx::new(&[], depth, meta)
    }

    /// A standard query for `<name>` (A record), with the QU bit optionally
    /// set on the question's class field (RFC 6762 §5.4).
    fn mdns_query(id: u16, name_labels: &[&str], qu: bool) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&id.to_be_bytes());
        m.extend_from_slice(&[0x00, 0x00]); // no flags: a plain query
        m.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
        for label in name_labels {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.push(0);
        m.extend_from_slice(&[0, 1]); // qtype A
        let class = if qu { 0x8001u16 } else { 0x0001 };
        m.extend_from_slice(&class.to_be_bytes());
        m
    }

    /// A response with one A-record answer, cache-flush bit optionally set
    /// on the answer's class field (RFC 6762 §10.2).
    fn mdns_response(id: u16, name_labels: &[&str], cache_flush: bool) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&id.to_be_bytes());
        m.extend_from_slice(&[0x84, 0x00]); // QR|AA
        m.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0]);
        for label in name_labels {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.push(0);
        m.extend_from_slice(&[0, 1]); // type A
        let class = if cache_flush { 0x8001u16 } else { 0x0001 };
        m.extend_from_slice(&class.to_be_bytes());
        m.extend_from_slice(&[0, 0, 0, 120]); // ttl
        m.extend_from_slice(&[0, 4, 192, 0, 2, 5]); // rdlength + A record
        m
    }

    #[test]
    fn parses_query_with_qu_bit_and_reports_qname() {
        let bytes = mdns_query(0x0000, &["example", "local"], true);
        let m = meta(bytes.len());
        let parsed = Mdns
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid mDNS query");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(APP), Some(&Value::from("mdns")));
        assert_eq!(
            parsed.fields.get(QNAME),
            Some(&Value::from("example.local"))
        );
        assert_eq!(parsed.fields.get(QTYPE), Some(&Value::U64(1)));
        assert_eq!(parsed.fields.get(IS_RESPONSE), Some(&Value::Bool(false)));
        assert_eq!(
            parsed.fields.get(IS_MULTICAST_QUERY),
            Some(&Value::Bool(true))
        );
        assert_eq!(parsed.fields.get(CACHE_FLUSH), None);
    }

    #[test]
    fn qu_bit_unset_reports_false_not_absent() {
        let bytes = mdns_query(0x0000, &["example", "local"], false);
        let m = meta(bytes.len());
        let parsed = Mdns
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid mDNS query");
        assert_eq!(
            parsed.fields.get(IS_MULTICAST_QUERY),
            Some(&Value::Bool(false))
        );
    }

    #[test]
    fn parses_response_with_cache_flush_bit_and_answer() {
        let bytes = mdns_response(0x0000, &["example", "local"], true);
        let m = meta(bytes.len());
        let parsed = Mdns
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid mDNS response");
        assert_eq!(parsed.fields.get(IS_RESPONSE), Some(&Value::Bool(true)));
        assert_eq!(parsed.fields.get(CACHE_FLUSH), Some(&Value::Bool(true)));
        assert_eq!(
            parsed.fields.get(ANSWERS),
            Some(&Value::List(vec![Value::from("192.0.2.5")]))
        );
    }

    #[test]
    fn structural_depth_omits_answers_but_keeps_bits() {
        let bytes = mdns_response(0x0000, &["example", "local"], true);
        let m = meta(bytes.len());
        let parsed = Mdns
            .parse(&bytes, &ctx(Depth::Structural, &m))
            .expect("valid mDNS response");
        assert_eq!(parsed.fields.get(CACHE_FLUSH), Some(&Value::Bool(true)));
        assert_eq!(parsed.fields.get(ANSWERS), None);
    }

    #[test]
    fn keys_depth_only_has_app() {
        let bytes = mdns_query(0x0000, &["example", "local"], true);
        let m = meta(bytes.len());
        let parsed = Mdns
            .parse(&bytes, &ctx(Depth::Keys, &m))
            .expect("valid mDNS query");
        assert_eq!(parsed.fields.get(APP), Some(&Value::from("mdns")));
        assert_eq!(parsed.fields.get(QNAME), None);
    }

    #[test]
    fn truncated_frames_decline() {
        let bytes = mdns_query(0x1234, &["example", "local"], true);
        let m = meta(bytes.len());
        for n in 0..bytes.len() {
            let full_ctx = ctx(Depth::Full, &m);
            assert!(
                Mdns.parse(&bytes[..n], &full_ctx).is_err(),
                "prefix of {n}/{} bytes must decline",
                bytes.len()
            );
        }
    }
}
