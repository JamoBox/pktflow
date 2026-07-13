//! LLMNR (11.12, RFC 4795 — Link-Local Multicast Name Resolution): the
//! same RFC 1035 message format `dns` (06.6) and `mdns` (11.12) already
//! parse, sent to the `224.0.0.252` / `[ff02::1:3]` link-local multicast
//! group on port 5355 (RFC 4795 §2.5, §15.1) instead of to a unicast
//! resolver or the mDNS group. This plugin's `parse()` calls
//! `dns::parse_message` — the shared name-decompression/question/RR-walk
//! routine — and adds only the two flags-word bit reinterpretations LLMNR
//! itself makes (RFC 4795 §2.1.1). `dns`'s own contract and fields are
//! unaffected; this is code reuse, not a change to `dns`'s public shape.
//!
//! RFC 4795 §2.1.1 keeps RFC 1035's 16-bit flags word at the exact same
//! bit offsets but repurposes two of them for link-local conflict
//! detection: the wire position DNS gives `AA` (bit 10, mask `0x0400`)
//! becomes the **`C` (conflict)** bit, and the position DNS gives `RD`
//! (bit 8, mask `0x0100`) becomes the **`T` (tentative)** bit. Per RFC 4795
//! §7.1 (with behavioral context from §4.1): `C` set on a response means
//! the responder has determined the queried name is not unique on this
//! link; `T` set on a response means the responder is authoritative for
//! the name but has not yet finished verifying its own uniqueness. This
//! plugin only surfaces both bits as read fields — it implements no sender
//! conflict-resolution behavior (that's host stack logic, out of scope for
//! a passive dissector).
//!
//! App-stream pattern (same as `dns`/`mdns`): no endpoint identity of its
//! own, so the key is one shared constant field (`app = "llmnr"`) — one
//! child stream per UDP stream, home for the `qname` rollup.
//!
//! `"llmnr"` is deliberately its own key constant, not `dns`'s or `mdns`'s:
//! LLMNR's link-local, non-hierarchical name resolution is a distinct
//! traffic class from both resolver-hierarchy DNS and mDNS's `.local`
//! service discovery.

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
const CONFLICT: FieldName = "conflict";
const TENTATIVE: FieldName = "tentative";

/// RFC 4795 §2.1.1: same wire position as DNS's `AA` bit (RFC 1035
/// §4.1.1), repurposed as the conflict-detected bit.
const CONFLICT_BIT: u16 = 0x0400;
/// RFC 4795 §2.1.1: same wire position as DNS's `RD` bit, repurposed as
/// the tentative-response bit.
const TENTATIVE_BIT: u16 = 0x0100;

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

pub struct Llmnr;

impl LayerPlugin for Llmnr {
    fn name(&self) -> ProtocolName {
        "llmnr"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        // LLMNR has no TCP framing (RFC 4795 is UDP-only, §2.5) — the
        // message starts at byte 0, always.
        let raw = parse_message(bytes)?;

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(APP, Value::from("llmnr"));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(ID, Value::U64(u64::from(raw.id)));
            fields.insert(IS_RESPONSE, Value::Bool(raw.flags & 0x8000 != 0));
            fields.insert(OPCODE, Value::U64(u64::from((raw.flags >> 11) & 0xF)));
            fields.insert(RCODE, Value::U64(u64::from(raw.flags & 0xF)));
            fields.insert(CONFLICT, Value::Bool(raw.flags & CONFLICT_BIT != 0));
            fields.insert(TENTATIVE, Value::Bool(raw.flags & TENTATIVE_BIT != 0));
            if let (Some(name), Some(t)) = (raw.qname, raw.qtype) {
                fields.insert(QNAME, Value::from(name.as_str()));
                fields.insert(QTYPE, Value::U64(u64::from(t)));
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
        &[RouteId::UdpPort(5355)]
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

    /// A standard query for `<name>` (A record). `flags` lets callers set
    /// the QR/C/TC/T bits directly (RFC 4795 §2.1.1 keeps DNS's flags-word
    /// layout, so this is the same shape as `dns_query`/`mdns_query` with
    /// an explicit flags word instead of a fixed one).
    fn llmnr_query(id: u16, name_labels: &[&str], flags: u16) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&id.to_be_bytes());
        m.extend_from_slice(&flags.to_be_bytes());
        m.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
        for label in name_labels {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.push(0);
        m.extend_from_slice(&[0, 1, 0, 1]); // qtype A, class IN
        m
    }

    /// A response with one A-record answer.
    fn llmnr_response(id: u16, name_labels: &[&str], flags: u16) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&id.to_be_bytes());
        m.extend_from_slice(&flags.to_be_bytes());
        m.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0]);
        for label in name_labels {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.push(0);
        m.extend_from_slice(&[0, 1, 0, 1]); // type A, class IN
        m.extend_from_slice(&[0, 0, 0, 120]); // ttl
        m.extend_from_slice(&[0, 4, 192, 0, 2, 5]); // rdlength + A record
        m
    }

    #[test]
    fn parses_plain_query_and_reports_qname() {
        let bytes = llmnr_query(0x1234, &["host-a"], 0x0000);
        let m = meta(bytes.len());
        let parsed = Llmnr
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid LLMNR query");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(APP), Some(&Value::from("llmnr")));
        assert_eq!(parsed.fields.get(QNAME), Some(&Value::from("host-a")));
        assert_eq!(parsed.fields.get(QTYPE), Some(&Value::U64(1)));
        assert_eq!(parsed.fields.get(IS_RESPONSE), Some(&Value::Bool(false)));
        assert_eq!(parsed.fields.get(CONFLICT), Some(&Value::Bool(false)));
        assert_eq!(parsed.fields.get(TENTATIVE), Some(&Value::Bool(false)));
    }

    #[test]
    fn conflict_bit_set_on_response_is_reported() {
        // QR|C (RFC 4795 §7.1: a responder that has detected the queried
        // name is not unique sets C on its response).
        let bytes = llmnr_response(0x0000, &["host-a"], 0x8400);
        let m = meta(bytes.len());
        let parsed = Llmnr
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid LLMNR response");
        assert_eq!(parsed.fields.get(IS_RESPONSE), Some(&Value::Bool(true)));
        assert_eq!(parsed.fields.get(CONFLICT), Some(&Value::Bool(true)));
        assert_eq!(parsed.fields.get(TENTATIVE), Some(&Value::Bool(false)));
        assert_eq!(
            parsed.fields.get(ANSWERS),
            Some(&Value::List(vec![Value::from("192.0.2.5")]))
        );
    }

    #[test]
    fn tentative_bit_set_on_response_is_reported() {
        // QR|T (RFC 4795 §7.1: the responder is authoritative but hasn't
        // finished verifying its own uniqueness yet).
        let bytes = llmnr_response(0x0000, &["host-a"], 0x8100);
        let m = meta(bytes.len());
        let parsed = Llmnr
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid LLMNR response");
        assert_eq!(parsed.fields.get(CONFLICT), Some(&Value::Bool(false)));
        assert_eq!(parsed.fields.get(TENTATIVE), Some(&Value::Bool(true)));
    }

    #[test]
    fn structural_depth_omits_answers_but_keeps_bits() {
        let bytes = llmnr_response(0x0000, &["host-a"], 0x8400);
        let m = meta(bytes.len());
        let parsed = Llmnr
            .parse(&bytes, &ctx(Depth::Structural, &m))
            .expect("valid LLMNR response");
        assert_eq!(parsed.fields.get(CONFLICT), Some(&Value::Bool(true)));
        assert_eq!(parsed.fields.get(ANSWERS), None);
    }

    #[test]
    fn keys_depth_only_has_app() {
        let bytes = llmnr_query(0x0000, &["host-a"], 0x0000);
        let m = meta(bytes.len());
        let parsed = Llmnr
            .parse(&bytes, &ctx(Depth::Keys, &m))
            .expect("valid LLMNR query");
        assert_eq!(parsed.fields.get(APP), Some(&Value::from("llmnr")));
        assert_eq!(parsed.fields.get(QNAME), None);
    }

    #[test]
    fn truncated_frames_decline() {
        let bytes = llmnr_query(0x1234, &["host-a"], 0x0000);
        let m = meta(bytes.len());
        for n in 0..bytes.len() {
            let full_ctx = ctx(Depth::Full, &m);
            assert!(
                Llmnr.parse(&bytes[..n], &full_ctx).is_err(),
                "prefix of {n}/{} bytes must decline",
                bytes.len()
            );
        }
    }
}
