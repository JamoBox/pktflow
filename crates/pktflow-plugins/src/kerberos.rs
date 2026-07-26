//! Kerberos (11.7, RFC 4120) — app-stream pattern (06.6). ASN.1/DER-encoded;
//! v1 reads only the outer `APPLICATION` tag (which directly encodes
//! Kerberos's own `msg-type` per its own convention, RFC 4120 §5.10) and the
//! DER length, not the ticket contents. Full field decoding (principal
//! names, realm, encrypted parts) needs a real ASN.1/BER decoder — a Tier 2
//! dependency, not attempted here as a partial TLV walk the way this task's
//! other TLV-based protocols are (D12's field-extraction ceiling).
//!
//! ## Outer tag (X.690 §8.1.2, ITU-T Rec. X.680 tag class encoding)
//! Every Kerberos message is `[APPLICATION n] SEQUENCE`, i.e. a single BER
//! tag-length-value whose identifier octet's top three bits are `011`
//! (class `APPLICATION`, constructed) and whose low five bits are `n` —
//! Kerberos never needs the high-tag-number form (every `n` here is ≤ 30),
//! so this plugin doesn't implement it. `n` is `msg_type` directly (RFC
//! 4120 §5.10: `AS-REQ=10`, `AS-REP=11`, `TGS-REQ=12`, `TGS-REP=13`,
//! `AP-REQ=14`, `AP-REP=15`, `KRB-ERROR=30`); any other identifier octet —
//! including a well-formed BER tag for a message type Kerberos doesn't
//! define — is not one of this plugin's recognized shapes and declines,
//! the same claim-honesty stance 06.6 documents for non-DNS traffic on
//! port 53.
//!
//! ## DER length (X.690 §8.1.3)
//! Short form (top bit clear): the byte itself is the length. Long form
//! (top bit set): the low 7 bits count how many following big-endian
//! octets encode the length; `0x80` alone (indefinite length) is a BER-only
//! construct DER forbids and this plugin declines. `header_len` is exactly
//! `1 (tag) + length-field width + length` — self-describing framing,
//! independent of whether the content is walked any further (it never is).

use pktflow_core::{
    ByteReader, Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx,
    ParseError, ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId, StreamIdentity, Value,
};

const APP: FieldName = "app";
const MSG_TYPE: FieldName = "msg_type";
const DER_LENGTH: FieldName = "der_length";

/// X.690 §8.1.2: class bits `01` (APPLICATION) + constructed bit `1`,
/// occupying the identifier octet's top three bits.
const APPLICATION_CONSTRUCTED_MASK: u8 = 0xE0;
const APPLICATION_CONSTRUCTED_TAG: u8 = 0x60;
const TAG_NUMBER_MASK: u8 = 0x1F;

/// RFC 4120 §5.10's `msg-type` values, Tier 1's recognized set.
const AS_REQ: u8 = 10;
const AS_REP: u8 = 11;
const TGS_REQ: u8 = 12;
const TGS_REP: u8 = 13;
const AP_REQ: u8 = 14;
const AP_REP: u8 = 15;
const KRB_ERROR: u8 = 30;

fn is_recognized_msg_type(msg_type: u8) -> bool {
    matches!(
        msg_type,
        AS_REQ | AS_REP | TGS_REQ | TGS_REP | AP_REQ | AP_REP | KRB_ERROR
    )
}

/// X.690 §8.1.3: short or long form. Returns the decoded length.
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

static KEY: &[KeyField] = &[KeyField { a: APP, b: None }];
static ROLLUPS: &[RollupSpec] = &[RollupSpec {
    field: MSG_TYPE,
    kind: RollupKind::Accumulate,
}];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: ROLLUPS,
};

pub struct Kerberos;

impl LayerPlugin for Kerberos {
    fn name(&self) -> ProtocolName {
        "kerberos"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let tag = r.u8()?;
        if tag & APPLICATION_CONSTRUCTED_MASK != APPLICATION_CONSTRUCTED_TAG {
            return Err(ParseError::Malformed(
                "not a Kerberos [APPLICATION n] SEQUENCE tag",
            ));
        }
        let msg_type = tag & TAG_NUMBER_MASK;
        if !is_recognized_msg_type(msg_type) {
            return Err(ParseError::Malformed("unrecognized Kerberos msg-type"));
        }
        let length = read_der_length(&mut r)?;
        let _content = r.take(usize::try_from(length).unwrap_or(usize::MAX))?;
        let header_len = bytes.len() - r.remaining();

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(APP, Value::from("kerberos"));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(MSG_TYPE, Value::U64(u64::from(msg_type)));
            fields.insert(DER_LENGTH, Value::U64(length));
        }

        Ok(ParsedLayer {
            header_len,
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::UdpPort(88), RouteId::TcpPort(88)]
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

    /// A `[APPLICATION msg_type] SEQUENCE` with `content_len` opaque
    /// content bytes, DER short-form length.
    fn message_short(msg_type: u8, content_len: usize) -> Vec<u8> {
        let mut b = vec![APPLICATION_CONSTRUCTED_TAG | msg_type, content_len as u8];
        b.extend(std::iter::repeat_n(0xABu8, content_len));
        b
    }

    /// Same, but with a DER long-form length (>127 bytes of content).
    fn message_long(msg_type: u8, content_len: usize) -> Vec<u8> {
        let mut b = vec![APPLICATION_CONSTRUCTED_TAG | msg_type];
        let len_bytes = (content_len as u32).to_be_bytes();
        // Trim to the minimal number of octets DER requires.
        let trimmed: Vec<u8> = {
            let mut i = 0;
            while i < 3 && len_bytes[i] == 0 {
                i += 1;
            }
            len_bytes[i..].to_vec()
        };
        b.push(0x80 | trimmed.len() as u8);
        b.extend_from_slice(&trimmed);
        b.extend(std::iter::repeat_n(0xCDu8, content_len));
        b
    }

    #[test]
    fn as_req_and_as_rep_parse_msg_type_and_length() {
        for (msg_type, expected) in [(AS_REQ, 10u64), (AS_REP, 11)] {
            let bytes = message_short(msg_type, 20);
            let m = meta(bytes.len());
            let parsed = Kerberos
                .parse(&bytes, &ctx(Depth::Full, &m))
                .unwrap_or_else(|e| panic!("msg_type {msg_type}: {e}"));
            assert_eq!(parsed.header_len, bytes.len());
            assert_eq!(parsed.hint, Hint::Terminal);
            assert_eq!(parsed.fields.get(APP), Some(&Value::from("kerberos")));
            assert_eq!(parsed.fields.get(MSG_TYPE), Some(&Value::U64(expected)));
            assert_eq!(parsed.fields.get(DER_LENGTH), Some(&Value::U64(20)));
        }
    }

    #[test]
    fn tgs_req_tgs_rep_ap_req_ap_rep_and_error_all_recognized() {
        for msg_type in [TGS_REQ, TGS_REP, AP_REQ, AP_REP, KRB_ERROR] {
            let bytes = message_short(msg_type, 4);
            let m = meta(bytes.len());
            let parsed = Kerberos
                .parse(&bytes, &ctx(Depth::Full, &m))
                .unwrap_or_else(|e| panic!("msg_type {msg_type}: {e}"));
            assert_eq!(
                parsed.fields.get(MSG_TYPE),
                Some(&Value::U64(u64::from(msg_type)))
            );
        }
    }

    #[test]
    fn der_long_form_length_parses_correctly() {
        let bytes = message_long(AS_REQ, 300);
        let m = meta(bytes.len());
        let parsed = Kerberos
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid long-form length");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.fields.get(DER_LENGTH), Some(&Value::U64(300)));
    }

    /// The short/long-form boundary itself: length byte `0x7f` (short
    /// form, value 127) vs `0x81` (long form, 1 width octet) vs `0x82`
    /// (long form, 2 width octets).
    #[test]
    fn short_and_long_form_boundary_bytes() {
        let short_127 = message_short(AS_REQ, 127);
        let m = meta(short_127.len());
        let parsed = Kerberos
            .parse(&short_127, &ctx(Depth::Full, &m))
            .expect("0x7f is short form");
        assert_eq!(parsed.fields.get(DER_LENGTH), Some(&Value::U64(127)));

        let mut long_1_octet = vec![APPLICATION_CONSTRUCTED_TAG | AS_REQ, 0x81, 128];
        long_1_octet.extend(std::iter::repeat_n(0u8, 128));
        let m = meta(long_1_octet.len());
        let parsed = Kerberos
            .parse(&long_1_octet, &ctx(Depth::Full, &m))
            .expect("0x81 is one-octet long form");
        assert_eq!(parsed.fields.get(DER_LENGTH), Some(&Value::U64(128)));

        let mut long_2_octet = vec![APPLICATION_CONSTRUCTED_TAG | AS_REQ, 0x82, 0x01, 0x00];
        long_2_octet.extend(std::iter::repeat_n(0u8, 256));
        let m = meta(long_2_octet.len());
        let parsed = Kerberos
            .parse(&long_2_octet, &ctx(Depth::Full, &m))
            .expect("0x82 is two-octet long form");
        assert_eq!(parsed.fields.get(DER_LENGTH), Some(&Value::U64(256)));
    }

    #[test]
    fn indefinite_length_declines() {
        let bytes = vec![APPLICATION_CONSTRUCTED_TAG | AS_REQ, 0x80, 0x00, 0x00];
        let m = meta(bytes.len());
        assert!(Kerberos.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn non_application_tag_declines() {
        // A SEQUENCE (Universal, constructed, tag 16 = 0x30), not an
        // APPLICATION tag.
        let bytes = vec![0x30, 0x02, 0xAA, 0xBB];
        let m = meta(bytes.len());
        assert!(Kerberos.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn unrecognized_msg_type_declines() {
        // msg-type 5 is unassigned in RFC 4120 §5.10's registry.
        let bytes = message_short(5, 4);
        let m = meta(bytes.len());
        assert!(Kerberos.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn depth_none_omits_every_field() {
        let bytes = message_short(AS_REQ, 4);
        let m = meta(bytes.len());
        let parsed = Kerberos
            .parse(&bytes, &ctx(Depth::None, &m))
            .expect("valid");
        assert!(parsed.fields.is_empty());
    }

    #[test]
    fn keys_depth_only_has_app() {
        let bytes = message_short(AS_REQ, 4);
        let m = meta(bytes.len());
        let parsed = Kerberos
            .parse(&bytes, &ctx(Depth::Keys, &m))
            .expect("valid");
        assert_eq!(parsed.fields.get(APP), Some(&Value::from("kerberos")));
        assert_eq!(parsed.fields.get(MSG_TYPE), None);
    }

    #[test]
    fn truncated_frames_decline_at_every_prefix() {
        let bytes = message_short(AS_REQ, 20);
        let m = meta(bytes.len());
        let full = ctx(Depth::Full, &m);
        for n in 0..bytes.len() {
            assert!(
                Kerberos.parse(&bytes[..n], &full).is_err(),
                "prefix of {n}/{} bytes must decline",
                bytes.len()
            );
        }
    }
}
