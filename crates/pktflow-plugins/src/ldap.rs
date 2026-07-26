//! LDAP (11.7, RFC 4511) — app-stream pattern (06.6), the same BER-framing-
//! only scope as `kerberos` (D12's field-extraction ceiling for ASN.1/BER
//! protocols in this task): no general ASN.1 decoder, just enough
//! tag-length-value walking to read `LDAPMessage`'s two leading fields and,
//! for `bindRequest` specifically, one more fixed-position field.
//!
//! ## `LDAPMessage` (RFC 4511 §4.1.1)
//! `SEQUENCE { messageID MessageID, protocolOp CHOICE {...}, controls [0]
//! Controls OPTIONAL }`. The outer tag is Universal SEQUENCE (`0x30`);
//! `header_len` is exactly `1 (tag) + length-field width + length` (X.690
//! §8.1.3, the same short/long-form DER length reader `kerberos` uses) —
//! self-describing, so `controls` never needs to be located or walked.
//!
//! `messageID` is a plain `INTEGER` (Universal tag `0x02`); `protocolOp` is
//! a CHOICE of `[APPLICATION n] ...` alternatives (RFC 4511 §4.2 onward:
//! `bindRequest=0`, `bindResponse=1`, `unbindRequest=2`, `searchRequest=3`,
//! `searchResEntry=4`, `searchResDone=5`, `searchResRef=19`,
//! `modifyRequest=6`, `addRequest=8`, `delRequest=10`, ... — some of these
//! alias a primitive type (e.g. `delRequest`'s `LDAPDN`) rather than a
//! `SEQUENCE`, so the *constructed* bit is not checked, only the tag
//! *class* bits (top two) being `APPLICATION`); `n` is `protocol_op`
//! directly. This plugin reads only these two TLVs' tags/lengths — never
//! walks into `protocolOp`'s content — except for one bounded exception
//! below.
//!
//! ## `bind_dn` (`BindRequest`, RFC 4511 §4.2, best-effort)
//! `BindRequest ::= [APPLICATION 0] SEQUENCE { version INTEGER (1..127),
//! name LDAPDN, authentication AuthenticationChoice }`. `name` (an
//! `OCTET STRING`, tag `0x04`) sits at a fixed position right after
//! `version` for every bind, so it's locatable without a general ASN.1
//! walk: read `version`'s TLV to skip it, then `name`'s TLV as `bind_dn`.
//! Anything requiring CHOICE/SET traversal (search filters, attribute
//! lists, SASL credentials) is out of v1 scope — and, since `header_len`
//! never depends on this walk, a shape that doesn't match (wrong tag,
//! truncated) just omits `bind_dn` rather than declining the message.

use pktflow_core::{
    ByteReader, Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx,
    ParseError, ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId, StreamIdentity, Value,
};

const APP: FieldName = "app";
const MESSAGE_ID: FieldName = "message_id";
const PROTOCOL_OP: FieldName = "protocol_op";
const BIND_DN: FieldName = "bind_dn";

const TAG_SEQUENCE: u8 = 0x30;
const TAG_INTEGER: u8 = 0x02;
const TAG_OCTET_STRING: u8 = 0x04;
/// X.690 §8.1.2: top two bits of the identifier octet select the tag
/// class; `01` is APPLICATION (the constructed bit, bit 6, is deliberately
/// not checked here — see the module doc).
const APPLICATION_CLASS_MASK: u8 = 0xC0;
const APPLICATION_CLASS: u8 = 0x40;
const TAG_NUMBER_MASK: u8 = 0x1F;

const BIND_REQUEST: u8 = 0;

/// One BER tag-length-value: the tag octet and the exact `length` content
/// bytes (X.690 §8.1). Shares the short/long-form DER length reader with
/// `kerberos.rs` (11.7's other BER-framing-only plugin); duplicated rather
/// than shared across files per this crate's one-file-per-protocol
/// convention.
struct Tlv<'a> {
    tag: u8,
    content: &'a [u8],
}

fn read_der_length(r: &mut ByteReader) -> Result<u64, ParseError> {
    let first = r.u8()?;
    if first & 0x80 == 0 {
        return Ok(u64::from(first));
    }
    let width = first & 0x7F;
    if width == 0 {
        return Err(ParseError::Malformed(
            "indefinite-length BER encoding is not valid DER",
        ));
    }
    if width > 8 {
        return Err(ParseError::Malformed("DER length wider than 8 octets"));
    }
    let octets = r.take(usize::from(width))?;
    let mut len = 0u64;
    for &b in octets {
        len = (len << 8) | u64::from(b);
    }
    Ok(len)
}

fn read_tlv<'a>(r: &mut ByteReader<'a>) -> Result<Tlv<'a>, ParseError> {
    let tag = r.u8()?;
    let length = read_der_length(r)?;
    let content = r.take(usize::try_from(length).unwrap_or(usize::MAX))?;
    Ok(Tlv { tag, content })
}

/// A non-negative BER `INTEGER`'s value, big-endian. LDAP message ids are
/// always small and non-negative in practice; this omits full two's-
/// complement handling as out of scope, the same bounded-honesty stance
/// `radius`'s attribute walk takes on out-of-scope AVPs (11.7).
fn decode_uint(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() || bytes.len() > 8 {
        return None;
    }
    Some(bytes.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b)))
}

/// Best-effort `bind_dn` extraction for `bindRequest` only (module doc):
/// any shape mismatch yields `None`, never a decline.
fn read_bind_dn(op_content: &[u8]) -> Option<String> {
    let mut r = ByteReader::new(op_content);
    let version = read_tlv(&mut r).ok()?;
    if version.tag != TAG_INTEGER {
        return None;
    }
    let name = read_tlv(&mut r).ok()?;
    if name.tag != TAG_OCTET_STRING {
        return None;
    }
    std::str::from_utf8(name.content).ok().map(String::from)
}

static KEY: &[KeyField] = &[KeyField { a: APP, b: None }];
static ROLLUPS: &[RollupSpec] = &[
    RollupSpec {
        field: PROTOCOL_OP,
        kind: RollupKind::Accumulate,
    },
    RollupSpec {
        field: BIND_DN,
        kind: RollupKind::Sample,
    },
];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: ROLLUPS,
};

pub struct Ldap;

impl LayerPlugin for Ldap {
    fn name(&self) -> ProtocolName {
        "ldap"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let outer = read_tlv(&mut r)?;
        if outer.tag != TAG_SEQUENCE {
            return Err(ParseError::Malformed("not an LDAPMessage SEQUENCE"));
        }
        let header_len = bytes.len() - r.remaining();

        let mut cr = ByteReader::new(outer.content);
        let msg_id_tlv = read_tlv(&mut cr)?;
        if msg_id_tlv.tag != TAG_INTEGER {
            return Err(ParseError::Malformed("LDAPMessage missing messageID"));
        }
        let message_id =
            decode_uint(msg_id_tlv.content).ok_or(ParseError::Malformed("messageID too wide"))?;

        let op_tlv = read_tlv(&mut cr)?;
        if op_tlv.tag & APPLICATION_CLASS_MASK != APPLICATION_CLASS {
            return Err(ParseError::Malformed(
                "protocolOp is not an APPLICATION-tagged CHOICE",
            ));
        }
        let protocol_op = op_tlv.tag & TAG_NUMBER_MASK;

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(APP, Value::from("ldap"));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(MESSAGE_ID, Value::U64(message_id));
            fields.insert(PROTOCOL_OP, Value::U64(u64::from(protocol_op)));
        }
        if ctx.depth() >= Depth::Full && protocol_op == BIND_REQUEST {
            if let Some(dn) = read_bind_dn(op_tlv.content) {
                fields.insert(BIND_DN, Value::from(dn.as_str()));
            }
        }

        Ok(ParsedLayer {
            header_len,
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::TcpPort(389)]
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

    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut b = vec![tag, content.len() as u8];
        b.extend_from_slice(content);
        b
    }

    fn ldap_message(message_id: u8, op_tag: u8, op_content: &[u8]) -> Vec<u8> {
        let mut content = tlv(TAG_INTEGER, &[message_id]);
        content.extend_from_slice(&tlv(op_tag, op_content));
        let mut msg = vec![TAG_SEQUENCE, content.len() as u8];
        msg.extend_from_slice(&content);
        msg
    }

    /// A simple-auth `bindRequest`: version 3, DN, then a 2-byte
    /// authentication choice this plugin never touches.
    fn bind_request(message_id: u8, dn: &str) -> Vec<u8> {
        let mut op = tlv(TAG_INTEGER, &[3]);
        op.extend_from_slice(&tlv(TAG_OCTET_STRING, dn.as_bytes()));
        op.extend_from_slice(&[0x80, 0x00]); // simple authentication, empty password
        ldap_message(message_id, 0x60, &op) // [APPLICATION 0], constructed
    }

    #[test]
    fn bind_request_recovers_message_id_op_and_dn() {
        let bytes = bind_request(1, "cn=admin,dc=example,dc=com");
        let m = meta(bytes.len());
        let parsed = Ldap
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid bindRequest");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(APP), Some(&Value::from("ldap")));
        assert_eq!(parsed.fields.get(MESSAGE_ID), Some(&Value::U64(1)));
        assert_eq!(parsed.fields.get(PROTOCOL_OP), Some(&Value::U64(0)));
        assert_eq!(
            parsed.fields.get(BIND_DN),
            Some(&Value::from("cn=admin,dc=example,dc=com"))
        );
    }

    #[test]
    fn search_request_recovers_message_id_and_op_but_no_bind_dn() {
        // searchRequest ::= [APPLICATION 3] SEQUENCE {...}. The filter
        // (a CHOICE/SET the plugin never walks) is opaque content here.
        let filter = [0xA0u8, 0x03, 0x87, 0x01, b'*']; // present filter, opaque shape
        let bytes = ldap_message(2, 0x63, &filter); // [APPLICATION 3], constructed
        let m = meta(bytes.len());
        let parsed = Ldap
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid searchRequest");
        assert_eq!(parsed.fields.get(MESSAGE_ID), Some(&Value::U64(2)));
        assert_eq!(parsed.fields.get(PROTOCOL_OP), Some(&Value::U64(3)));
        assert_eq!(parsed.fields.get(BIND_DN), None);
    }

    #[test]
    fn unbind_request_has_no_content_and_no_bind_dn() {
        // unbindRequest ::= [APPLICATION 2] SEQUENCE {} — an empty body.
        let bytes = ldap_message(3, 0x62, &[]);
        let m = meta(bytes.len());
        let parsed = Ldap
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid unbindRequest");
        assert_eq!(parsed.fields.get(PROTOCOL_OP), Some(&Value::U64(2)));
        assert_eq!(parsed.fields.get(BIND_DN), None);
    }

    #[test]
    fn depth_gates_message_id_and_bind_dn() {
        let bytes = bind_request(1, "cn=admin,dc=example,dc=com");
        let m = meta(bytes.len());
        let keys = Ldap.parse(&bytes, &ctx(Depth::Keys, &m)).expect("valid");
        assert_eq!(keys.fields.get(APP), Some(&Value::from("ldap")));
        assert_eq!(keys.fields.get(MESSAGE_ID), None);
        assert_eq!(keys.fields.get(BIND_DN), None);

        let structural = Ldap
            .parse(&bytes, &ctx(Depth::Structural, &m))
            .expect("valid");
        assert_eq!(structural.fields.get(MESSAGE_ID), Some(&Value::U64(1)));
        assert_eq!(structural.fields.get(PROTOCOL_OP), Some(&Value::U64(0)));
        assert_eq!(structural.fields.get(BIND_DN), None);
    }

    #[test]
    fn non_sequence_outer_tag_declines() {
        let bytes = vec![0x04, 0x02, 0xAA, 0xBB]; // OCTET STRING, not SEQUENCE
        let m = meta(bytes.len());
        assert!(Ldap.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn missing_message_id_declines() {
        // protocolOp where messageID should be.
        let content = tlv(0x62, &[]);
        let mut bytes = vec![TAG_SEQUENCE, content.len() as u8];
        bytes.extend_from_slice(&content);
        let m = meta(bytes.len());
        assert!(Ldap.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn non_application_protocol_op_declines() {
        // messageID, then a Universal-class TLV instead of an
        // APPLICATION-tagged protocolOp.
        let mut content = tlv(TAG_INTEGER, &[1]);
        content.extend_from_slice(&tlv(0x30, &[]));
        let mut bytes = vec![TAG_SEQUENCE, content.len() as u8];
        bytes.extend_from_slice(&content);
        let m = meta(bytes.len());
        assert!(Ldap.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn malformed_bind_body_omits_dn_without_declining() {
        // version present, but the second element isn't an OCTET STRING —
        // bind_dn is simply absent, the whole message still parses.
        let mut op = tlv(TAG_INTEGER, &[3]);
        op.extend_from_slice(&tlv(0x30, &[])); // not OCTET STRING
        let bytes = ldap_message(1, 0x60, &op);
        let m = meta(bytes.len());
        let parsed = Ldap
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("still a valid LDAPMessage");
        assert_eq!(parsed.fields.get(PROTOCOL_OP), Some(&Value::U64(0)));
        assert_eq!(parsed.fields.get(BIND_DN), None);
    }

    #[test]
    fn truncated_frames_decline_at_every_prefix() {
        let bytes = bind_request(1, "cn=admin,dc=example,dc=com");
        let m = meta(bytes.len());
        let full = ctx(Depth::Full, &m);
        for n in 0..bytes.len() {
            assert!(
                Ldap.parse(&bytes[..n], &full).is_err(),
                "prefix of {n}/{} bytes must decline",
                bytes.len()
            );
        }
    }
}
