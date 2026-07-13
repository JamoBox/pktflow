//! RADIUS — 11.7, D14 citation: RFC 2865 (RADIUS authentication/
//! authorization, obsoletes RFC 2138) and RFC 2866 (RADIUS accounting,
//! obsoletes RFC 2139). Attribute numbers below are from IANA's "RADIUS
//! Attribute Types" registry, seeded by RFC 2865 §5 and RFC 2866 §5.
//!
//! **App-stream pattern (06.6).** RADIUS has no endpoint identity beyond
//! the UDP 4-tuple (NAS <-> RADIUS server) — `app = "radius"` is a shared
//! constant key, one child stream per UDP stream, the same shape as
//! `dns`/`syslog`/`snmp`.
//!
//! **Whole-message framing, not attribute-count framing (RFC 2865 §3).**
//! The 2-octet `Length` field is authoritative: "If the packet is shorter
//! than the Length field indicates, it MUST be silently discarded... If the
//! packet is longer than the Length field indicates, the remainder MUST be
//! treated as padding and ignored." This dissector's `header_len` is
//! exactly that `Length` value; a packet whose declared length exceeds the
//! bytes actually present declines as `Truncated` — the same "trust the
//! length field, not the buffer size" shape `snmp`'s outer BER TLV uses.
//!
//! **Attribute (AVP) walk, bounded strictly by `Length` (RFC 2865 §5).**
//! Every attribute is `Type(1) + Length(1, inclusive of these two octets) +
//! Value(Length-2)`. Once the outer `Length` field has proven enough bytes
//! exist, any AVP whose own framing doesn't fit (a `Length < 2`, or a value
//! that would run past the message boundary) is a malformed attribute
//! stream, not a short buffer — declined as `Malformed`, not `Truncated`.
//! Unrecognized attribute types, or a recognized type carrying an
//! unexpected value length, are skipped individually (the same bounded,
//! best-effort stance `dhcp`'s option walk and `enip`'s `cip_service`
//! (11.13) take) rather than failing the whole message.
//!
//! **`User-Password` (attribute 2) is not decoded.** RFC 2865 §5.2 XORs it
//! against an MD5 stream keyed on the shared secret plus the Request
//! Authenticator — recovering it needs the secret, which this dissector
//! never has (D12's "parse only what the protocol itself exposes"
//! boundary); the attribute is simply skipped, like any other
//! out-of-v1-scope AVP.

use pktflow_core::{
    ByteReader, Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx,
    ParseError, ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId, StreamIdentity, Value,
};

const APP: FieldName = "app";
const CODE: FieldName = "code";
const IDENTIFIER: FieldName = "identifier";
const USER_NAME: FieldName = "user_name";
const NAS_IP_ADDRESS: FieldName = "nas_ip_address";
const CALLING_STATION_ID: FieldName = "calling_station_id";
const ACCT_STATUS_TYPE: FieldName = "acct_status_type";

/// RFC 2865 §3's fixed header: Code(1) + Identifier(1) + Length(2) +
/// Authenticator(16).
const FIXED_HEADER_LEN: usize = 20;
/// RFC 2865 §3: "Length ... MUST be between 20 and 4096."
const MIN_LENGTH: u16 = 20;
const MAX_LENGTH: u16 = 4096;

/// RFC 2866 §3 accounting codes — gates `acct_status_type` extraction to
/// accounting packets only, per the spec's "accounting only" note.
const ACCOUNTING_REQUEST: u8 = 4;
const ACCOUNTING_RESPONSE: u8 = 5;

/// IANA RADIUS Attribute Types (seeded by RFC 2865 §5 / RFC 2866 §5).
const ATTR_USER_NAME: u8 = 1;
const ATTR_NAS_IP_ADDRESS: u8 = 4;
const ATTR_CALLING_STATION_ID: u8 = 31;
const ATTR_ACCT_STATUS_TYPE: u8 = 40;

static KEY: &[KeyField] = &[KeyField { a: APP, b: None }];
static ROLLUPS: &[RollupSpec] = &[
    RollupSpec {
        field: CODE,
        kind: RollupKind::Accumulate,
    },
    RollupSpec {
        field: USER_NAME,
        kind: RollupKind::Sample,
    },
];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: ROLLUPS,
};

pub struct Radius;

impl LayerPlugin for Radius {
    fn name(&self) -> ProtocolName {
        "radius"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let code = r.u8()?;
        let identifier = r.u8()?;
        let length = r.u16_be()?;
        let _authenticator = r.take(16)?;

        if !(MIN_LENGTH..=MAX_LENGTH).contains(&length) {
            return Err(ParseError::Malformed(
                "RADIUS Length field outside the RFC 2865 §3 20..=4096 range",
            ));
        }
        let total_length = usize::from(length);
        // Prove the declared Length is actually present before walking
        // attributes — RFC 2865 §3's "shorter than Length MUST be
        // discarded" rule, reported the same way as any other short read.
        r.take(total_length - FIXED_HEADER_LEN)?;

        let mut attrs = ByteReader::new(&bytes[FIXED_HEADER_LEN..total_length]);
        let mut user_name: Option<&[u8]> = None;
        let mut nas_ip_address: Option<&[u8]> = None;
        let mut calling_station_id: Option<&[u8]> = None;
        let mut acct_status_type: Option<u32> = None;

        while attrs.remaining() > 0 {
            let attr_type = attrs
                .u8()
                .map_err(|_| ParseError::Malformed("RADIUS attribute stream ends mid-attribute"))?;
            let attr_len = attrs
                .u8()
                .map_err(|_| ParseError::Malformed("RADIUS attribute stream ends mid-attribute"))?;
            let attr_len = usize::from(attr_len);
            if attr_len < 2 {
                return Err(ParseError::Malformed(
                    "RADIUS attribute Length must be at least 2",
                ));
            }
            let value = attrs.take(attr_len - 2).map_err(|_| {
                ParseError::Malformed("RADIUS attribute overruns the message Length")
            })?;
            match attr_type {
                ATTR_USER_NAME => user_name = Some(value),
                ATTR_NAS_IP_ADDRESS if value.len() == 4 => nas_ip_address = Some(value),
                ATTR_CALLING_STATION_ID => calling_station_id = Some(value),
                ATTR_ACCT_STATUS_TYPE if value.len() == 4 => {
                    let octets: [u8; 4] = value
                        .try_into()
                        .map_err(|_| ParseError::Malformed("unreachable: length checked above"))?;
                    acct_status_type = Some(u32::from_be_bytes(octets));
                }
                _ => {}
            }
        }

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(APP, Value::from("radius"));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(CODE, Value::U64(u64::from(code)));
            fields.insert(IDENTIFIER, Value::U64(u64::from(identifier)));
        }
        if ctx.depth() >= Depth::Full {
            if let Some(v) = user_name {
                fields.insert(USER_NAME, Value::from(String::from_utf8_lossy(v).as_ref()));
            }
            if let Some(v) = nas_ip_address {
                fields.insert(NAS_IP_ADDRESS, Value::from(v));
            }
            if let Some(v) = calling_station_id {
                fields.insert(
                    CALLING_STATION_ID,
                    Value::from(String::from_utf8_lossy(v).as_ref()),
                );
            }
            if matches!(code, ACCOUNTING_REQUEST | ACCOUNTING_RESPONSE) {
                if let Some(v) = acct_status_type {
                    fields.insert(ACCT_STATUS_TYPE, Value::U64(u64::from(v)));
                }
            }
        }

        Ok(ParsedLayer {
            header_len: total_length,
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::UdpPort(1812), RouteId::UdpPort(1813)]
    }

    fn stream_identity(&self) -> Option<&StreamIdentity> {
        Some(&IDENTITY)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    use pktflow_core::{LinkType, PacketMeta};

    fn ctx_bytes(meta: &PacketMeta, depth: Depth) -> ParseCtx<'_> {
        ParseCtx::new(&[], depth, meta)
    }

    fn meta(len: usize) -> PacketMeta {
        PacketMeta {
            timestamp: SystemTime::UNIX_EPOCH,
            caplen: len,
            origlen: len,
            link_type: LinkType::ETHERNET,
        }
    }

    fn attr(attr_type: u8, value: &[u8]) -> Vec<u8> {
        let mut out = vec![attr_type, (value.len() + 2) as u8];
        out.extend_from_slice(value);
        out
    }

    /// Access-Request (RFC 2865 §4.1): identifier 1, a 16-byte Request
    /// Authenticator (arbitrary in this fixture — this dissector never
    /// validates it), `User-Name` "bob", and `Calling-Station-Id`
    /// "00-11-22-33-44-55".
    fn access_request() -> Vec<u8> {
        let mut attrs = Vec::new();
        attrs.extend_from_slice(&attr(1, b"bob"));
        attrs.extend_from_slice(&attr(31, b"00-11-22-33-44-55"));

        let mut out = vec![1, 1]; // code = Access-Request, identifier = 1
        out.extend_from_slice(&((20 + attrs.len()) as u16).to_be_bytes());
        out.extend_from_slice(&[0xAA; 16]); // Request Authenticator
        out.extend_from_slice(&attrs);
        out
    }

    /// Access-Accept (RFC 2865 §4.2) answering the request above, carrying
    /// `NAS-IP-Address` 10.0.0.1.
    fn access_accept() -> Vec<u8> {
        let attrs = attr(4, &[10, 0, 0, 1]);

        let mut out = vec![2, 1]; // code = Access-Accept, identifier = 1
        out.extend_from_slice(&((20 + attrs.len()) as u16).to_be_bytes());
        out.extend_from_slice(&[0xBB; 16]); // Response Authenticator
        out.extend_from_slice(&attrs);
        out
    }

    /// Accounting-Request (RFC 2866 §4.1) with `Acct-Status-Type` = Start
    /// (1) and `User-Name` "bob".
    fn accounting_request_start() -> Vec<u8> {
        let mut attrs = Vec::new();
        attrs.extend_from_slice(&attr(1, b"bob"));
        attrs.extend_from_slice(&attr(40, &1u32.to_be_bytes()));

        let mut out = vec![4, 7]; // code = Accounting-Request, identifier = 7
        out.extend_from_slice(&((20 + attrs.len()) as u16).to_be_bytes());
        out.extend_from_slice(&[0xCC; 16]);
        out.extend_from_slice(&attrs);
        out
    }

    #[test]
    fn access_request_fields_and_header_len() {
        let bytes = access_request();
        let m = meta(bytes.len());
        let ctx = ctx_bytes(&m, Depth::Full);
        let parsed = Radius
            .parse(&bytes, &ctx)
            .expect("well-formed Access-Request");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(APP), Some(&Value::from("radius")));
        assert_eq!(parsed.fields.get(CODE), Some(&Value::U64(1)));
        assert_eq!(parsed.fields.get(IDENTIFIER), Some(&Value::U64(1)));
        assert_eq!(parsed.fields.get(USER_NAME), Some(&Value::from("bob")));
        assert_eq!(
            parsed.fields.get(CALLING_STATION_ID),
            Some(&Value::from("00-11-22-33-44-55"))
        );
        assert_eq!(parsed.fields.get(NAS_IP_ADDRESS), None);
        assert_eq!(parsed.fields.get(ACCT_STATUS_TYPE), None);
    }

    #[test]
    fn access_accept_carries_nas_ip_address() {
        let bytes = access_accept();
        let m = meta(bytes.len());
        let ctx = ctx_bytes(&m, Depth::Full);
        let parsed = Radius
            .parse(&bytes, &ctx)
            .expect("well-formed Access-Accept");
        assert_eq!(parsed.fields.get(CODE), Some(&Value::U64(2)));
        assert_eq!(
            parsed.fields.get(NAS_IP_ADDRESS),
            Some(&Value::from(&[10u8, 0, 0, 1][..]))
        );
    }

    #[test]
    fn accounting_request_reports_acct_status_type() {
        let bytes = accounting_request_start();
        let m = meta(bytes.len());
        let ctx = ctx_bytes(&m, Depth::Full);
        let parsed = Radius
            .parse(&bytes, &ctx)
            .expect("well-formed Accounting-Request");
        assert_eq!(parsed.fields.get(CODE), Some(&Value::U64(4)));
        assert_eq!(parsed.fields.get(ACCT_STATUS_TYPE), Some(&Value::U64(1)));
    }

    /// `Acct-Status-Type` is scoped to accounting codes (RFC 2866): an
    /// Access-Request never reports it even if a well-formed attribute 40
    /// were present, since the spec table marks the field "accounting
    /// only".
    #[test]
    fn acct_status_type_absent_outside_accounting_codes() {
        let mut attrs = Vec::new();
        attrs.extend_from_slice(&attr(40, &1u32.to_be_bytes()));
        let mut bytes = vec![1, 9]; // code = Access-Request
        bytes.extend_from_slice(&((20 + attrs.len()) as u16).to_be_bytes());
        bytes.extend_from_slice(&[0xDD; 16]);
        bytes.extend_from_slice(&attrs);

        let m = meta(bytes.len());
        let ctx = ctx_bytes(&m, Depth::Full);
        let parsed = Radius.parse(&bytes, &ctx).expect("well-formed packet");
        assert_eq!(parsed.fields.get(ACCT_STATUS_TYPE), None);
    }

    #[test]
    fn length_below_minimum_declines() {
        let mut bytes = access_request();
        bytes[2..4].copy_from_slice(&19u16.to_be_bytes());
        let m = meta(bytes.len());
        let ctx = ctx_bytes(&m, Depth::Full);
        assert!(Radius.parse(&bytes, &ctx).is_err());
    }

    #[test]
    fn length_above_maximum_declines() {
        let mut bytes = access_request();
        bytes[2..4].copy_from_slice(&4097u16.to_be_bytes());
        let m = meta(bytes.len());
        let ctx = ctx_bytes(&m, Depth::Full);
        assert!(Radius.parse(&bytes, &ctx).is_err());
    }

    /// Length claims more bytes than the buffer actually holds — RFC 2865
    /// §3's "shorter than Length MUST be discarded" case.
    #[test]
    fn length_exceeding_available_bytes_declines() {
        let mut bytes = access_request();
        let claimed = (bytes.len() + 50) as u16;
        bytes[2..4].copy_from_slice(&claimed.to_be_bytes());
        let m = meta(bytes.len());
        let ctx = ctx_bytes(&m, Depth::Full);
        assert!(Radius.parse(&bytes, &ctx).is_err());
    }

    #[test]
    fn attribute_length_below_minimum_declines() {
        let mut bytes = vec![1, 1, 0, 21];
        bytes.extend_from_slice(&[0xAA; 16]);
        bytes.extend_from_slice(&[1, 1]); // attr type 1, length 1 (< 2, invalid)
        let m = meta(bytes.len());
        let ctx = ctx_bytes(&m, Depth::Full);
        assert!(Radius.parse(&bytes, &ctx).is_err());
    }

    #[test]
    fn attribute_overrunning_message_length_declines() {
        // Attribute claims a 20-byte value but only 3 bytes remain in the
        // declared message Length.
        let mut bytes = vec![1, 1, 0, 25];
        bytes.extend_from_slice(&[0xAA; 16]);
        bytes.extend_from_slice(&[1, 22, b'a', b'b', b'c']);
        let m = meta(bytes.len());
        let ctx = ctx_bytes(&m, Depth::Full);
        assert!(Radius.parse(&bytes, &ctx).is_err());
    }

    #[test]
    fn depth_none_yields_no_fields() {
        let bytes = access_request();
        let m = meta(bytes.len());
        let ctx = ctx_bytes(&m, Depth::None);
        let parsed = Radius
            .parse(&bytes, &ctx)
            .expect("well-formed Access-Request");
        assert!(parsed.fields.get(APP).is_none());
        assert!(parsed.fields.get(CODE).is_none());
    }

    #[test]
    fn depth_structural_omits_full_only_fields() {
        let bytes = access_request();
        let m = meta(bytes.len());
        let ctx = ctx_bytes(&m, Depth::Structural);
        let parsed = Radius
            .parse(&bytes, &ctx)
            .expect("well-formed Access-Request");
        assert_eq!(parsed.fields.get(CODE), Some(&Value::U64(1)));
        assert!(parsed.fields.get(USER_NAME).is_none());
    }
}
