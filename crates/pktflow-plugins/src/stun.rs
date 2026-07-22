//! STUN (11.8, RFC 8489) — **TURN** (RFC 8656) is the *same message
//! format*, extended with more methods/attributes and no new header
//! shape (RFC 8656 §5), so one plugin covers both, disambiguated by
//! `message_method` — the `ospf`/`stun` precedent (11.4/11.8's own
//! sibling, `gtp_c`, 11.15) of "one plugin, a field in the shared header
//! picks the variant".
//!
//! ## Header (RFC 8489 §5)
//!
//! ```text
//! Octets 0-1  : 00 | STUN Message Type (14 bits)
//! Octets 2-3  : Message Length (attribute bytes following this header;
//!               always a multiple of 4)
//! Octets 4-7  : Magic Cookie, fixed 0x2112A442
//! Octets 8-19 : Transaction ID (96 bits)
//! ```
//!
//! **Message Type's class/method bit-interleaving** (§5, Figure 3): the
//! 14-bit type field interleaves a 2-bit class (Request/Indication/
//! Success-Response/Error-Response) with a 12-bit method (Binding=0x001;
//! TURN adds Allocate=0x003/Refresh=0x004/Send=0x006/Data=0x007/
//! CreatePermission=0x008/ChannelBind=0x009) at fixed bit positions —
//! decoded here with the same bit-compaction every STUN stack uses, not
//! a simple mask.
//!
//! ## Attribute walk (§14)
//!
//! `Type(2) + Length(2, unpadded byte count) + Value(Length, then padded
//! to a 4-octet boundary)`. Recognized attributes: `XOR-MAPPED-ADDRESS`
//! (0x0020) and TURN's `XOR-RELAYED-ADDRESS` (0x0022) — both XOR the
//! address against the Magic Cookie (IPv6 additionally against the
//! Transaction ID, §14.2) to recover the real NAT-discovered address,
//! stored as the plain (un-XORed) address bytes; `USERNAME` (0x0006);
//! `ERROR-CODE` (0x0009, class*100+number per §14.8); TURN's `LIFETIME`
//! (0x000D) and `CHANNEL-NUMBER` (0x000C). Unrecognized attributes are
//! skipped via their own `Length` field — the same bounded, best-effort
//! stance `radius`'s AVP walk takes (11.7) — but a framing violation
//! (a `Length`/padding that doesn't fit the declared `Message Length`)
//! declines the whole message, the same honesty `radius` gives its own
//! `Length` field.

use pktflow_core::{
    ByteReader, Canonicalize, Confidence, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin,
    ParseCtx, ParseError, ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId,
    StreamIdentity, Truncated, Value,
};

const APP: FieldName = "app";
const MESSAGE_CLASS: FieldName = "message_class";
const MESSAGE_METHOD: FieldName = "message_method";
const MESSAGE_LENGTH: FieldName = "message_length";
const XOR_MAPPED_ADDRESS: FieldName = "xor_mapped_address";
const USERNAME: FieldName = "username";
const ERROR_CODE: FieldName = "error_code";
const RELAYED_ADDRESS: FieldName = "relayed_address";
const LIFETIME: FieldName = "lifetime";
const CHANNEL_NUMBER: FieldName = "channel_number";

/// §5: the fixed header prefix before attributes begin.
const FIXED_HEADER_LEN: usize = 20;
/// §5: fixed constant identifying this as a STUN (post-RFC 3489) message.
const MAGIC_COOKIE: u32 = 0x2112_A442;

const ATTR_USERNAME: u16 = 0x0006;
const ATTR_ERROR_CODE: u16 = 0x0009;
const ATTR_CHANNEL_NUMBER: u16 = 0x000C;
const ATTR_LIFETIME: u16 = 0x000D;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const ATTR_XOR_RELAYED_ADDRESS: u16 = 0x0022;

const FAMILY_IPV4: u8 = 0x01;
const FAMILY_IPV6: u8 = 0x02;

static KEY: &[KeyField] = &[KeyField { a: APP, b: None }];
static ROLLUPS: &[RollupSpec] = &[
    RollupSpec {
        field: MESSAGE_CLASS,
        kind: RollupKind::Accumulate,
    },
    RollupSpec {
        field: XOR_MAPPED_ADDRESS,
        kind: RollupKind::Sample,
    },
];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: ROLLUPS,
};

/// §5 Figure 3's class/method bit-interleaving: `C1` at bit 8, `C0` at
/// bit 4, method bits everywhere else in the low 14 bits.
fn message_class(message_type: u16) -> u16 {
    ((message_type >> 4) & 0x1) | ((message_type >> 7) & 0x2)
}

fn message_method(message_type: u16) -> u16 {
    (message_type & 0x000F) | ((message_type & 0x00E0) >> 1) | ((message_type & 0x3E00) >> 2)
}

/// Un-XORs an `XOR-MAPPED-ADDRESS`/`XOR-RELAYED-ADDRESS` value (§14.2),
/// returning the real address octets (4 for IPv4, 16 for IPv6). `None`
/// on a family/length this plugin doesn't recognize — declines just this
/// attribute (D12), not the whole message.
fn decode_xor_address(value: &[u8], transaction_id: &[u8]) -> Option<Vec<u8>> {
    let family = *value.get(1)?;
    match family {
        FAMILY_IPV4 if value.len() >= 8 => {
            let cookie = MAGIC_COOKIE.to_be_bytes();
            Some((0..4).map(|i| value[4 + i] ^ cookie[i]).collect())
        }
        FAMILY_IPV6 if value.len() >= 20 => {
            let mut pad = Vec::with_capacity(16);
            pad.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
            pad.extend_from_slice(transaction_id);
            Some((0..16).map(|i| value[4 + i] ^ pad[i]).collect())
        }
        _ => None,
    }
}

pub struct Stun;

impl LayerPlugin for Stun {
    fn name(&self) -> ProtocolName {
        "stun"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let raw_type = r.u16_be()?;
        if raw_type & 0xC000 != 0 {
            return Err(ParseError::Malformed(
                "STUN: message type's top two bits must be 0",
            ));
        }
        let message_length = r.u16_be()?;
        if message_length % 4 != 0 {
            return Err(ParseError::Malformed(
                "STUN: Message Length must be a multiple of 4",
            ));
        }
        let magic_cookie = r.u32_be()?;
        if magic_cookie != MAGIC_COOKIE {
            return Err(ParseError::Malformed("STUN: wrong magic cookie"));
        }
        let transaction_id = r.take(12)?;

        let total_len = FIXED_HEADER_LEN + usize::from(message_length);
        if bytes.len() < total_len {
            return Err(ParseError::Truncated(Truncated {
                needed: total_len,
                have: bytes.len(),
            }));
        }

        let mut xor_mapped_address = None;
        let mut username = None;
        let mut error_code = None;
        let mut relayed_address = None;
        let mut lifetime = None;
        let mut channel_number = None;

        let mut attrs = ByteReader::new(&bytes[FIXED_HEADER_LEN..total_len]);
        while attrs.remaining() > 0 {
            let attr_type = attrs
                .u16_be()
                .map_err(|_| ParseError::Malformed("STUN: attribute stream ends mid-attribute"))?;
            let attr_len = attrs
                .u16_be()
                .map_err(|_| ParseError::Malformed("STUN: attribute stream ends mid-attribute"))?;
            let value = attrs
                .take(usize::from(attr_len))
                .map_err(|_| ParseError::Malformed("STUN: attribute overruns Message Length"))?;
            let padding = (4 - usize::from(attr_len) % 4) % 4;
            attrs.take(padding).map_err(|_| {
                ParseError::Malformed("STUN: attribute padding overruns Message Length")
            })?;

            match attr_type {
                ATTR_USERNAME => {
                    username = Some(String::from_utf8_lossy(value).into_owned());
                }
                ATTR_ERROR_CODE if value.len() >= 4 => {
                    let class = u64::from(value[2] & 0x07);
                    let number = u64::from(value[3]);
                    error_code = Some(class * 100 + number);
                }
                ATTR_XOR_MAPPED_ADDRESS => {
                    xor_mapped_address = decode_xor_address(value, transaction_id);
                }
                ATTR_XOR_RELAYED_ADDRESS => {
                    relayed_address = decode_xor_address(value, transaction_id);
                }
                ATTR_LIFETIME if value.len() == 4 => {
                    lifetime = Some(u64::from(u32::from_be_bytes([
                        value[0], value[1], value[2], value[3],
                    ])));
                }
                ATTR_CHANNEL_NUMBER if value.len() >= 2 => {
                    channel_number = Some(u64::from(u16::from_be_bytes([value[0], value[1]])));
                }
                _ => {}
            }
        }

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(APP, Value::from("stun"));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(
                MESSAGE_CLASS,
                Value::U64(u64::from(message_class(raw_type))),
            );
            fields.insert(
                MESSAGE_METHOD,
                Value::U64(u64::from(message_method(raw_type))),
            );
            fields.insert(MESSAGE_LENGTH, Value::U64(u64::from(message_length)));
        }
        if ctx.depth() >= Depth::Full {
            if let Some(v) = xor_mapped_address {
                fields.insert(XOR_MAPPED_ADDRESS, Value::from(v.as_slice()));
            }
            if let Some(v) = username {
                fields.insert(USERNAME, Value::from(v.as_str()));
            }
            if let Some(v) = error_code {
                fields.insert(ERROR_CODE, Value::U64(v));
            }
            if let Some(v) = relayed_address {
                fields.insert(RELAYED_ADDRESS, Value::from(v.as_slice()));
            }
            if let Some(v) = lifetime {
                fields.insert(LIFETIME, Value::U64(v));
            }
            if let Some(v) = channel_number {
                fields.insert(CHANNEL_NUMBER, Value::U64(v));
            }
        }

        Ok(ParsedLayer {
            header_len: total_len,
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::UdpPort(3478), RouteId::TcpPort(3478)]
    }

    fn has_probe(&self) -> bool {
        true
    }

    fn probe(&self, bytes: &[u8], _ctx: &ParseCtx) -> Option<Confidence> {
        let mut r = ByteReader::new(bytes);
        let _type_and_length = r.take(4).ok()?;
        let magic_cookie = r.u32_be().ok()?;
        (magic_cookie == MAGIC_COOKIE).then(|| Confidence::new(95))
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

    const BINDING: u16 = 0x0001;
    const ALLOCATE: u16 = 0x0003;

    /// Class bits per §5: Request=0b00, Indication=0b01,
    /// Success-Response=0b10, Error-Response=0b11 — combined with a
    /// method to build the wire `message_type`.
    fn message_type(method: u16, class: u16) -> u16 {
        let c0 = (class & 0x1) << 4;
        let c1 = (class & 0x2) << 7;
        let m_low = method & 0x000F;
        let m_mid = (method & 0x0070) << 1;
        let m_high = (method & 0x0F80) << 2;
        m_low | m_mid | m_high | c0 | c1
    }

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

    fn attr(ty: u16, value: &[u8]) -> Vec<u8> {
        let mut out = ty.to_be_bytes().to_vec();
        out.extend_from_slice(&(value.len() as u16).to_be_bytes());
        out.extend_from_slice(value);
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
        out
    }

    fn header(method: u16, class: u16, transaction_id: [u8; 12], attrs: &[u8]) -> Vec<u8> {
        let mut b = message_type(method, class).to_be_bytes().to_vec();
        b.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
        b.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        b.extend_from_slice(&transaction_id);
        b.extend_from_slice(attrs);
        b
    }

    fn xor_mapped_address_attr(port: u16, addr: [u8; 4]) -> Vec<u8> {
        let cookie = MAGIC_COOKIE.to_be_bytes();
        let xport = port ^ ((MAGIC_COOKIE >> 16) as u16);
        let mut value = vec![0x00, FAMILY_IPV4];
        value.extend_from_slice(&xport.to_be_bytes());
        for i in 0..4 {
            value.push(addr[i] ^ cookie[i]);
        }
        attr(ATTR_XOR_MAPPED_ADDRESS, &value)
    }

    #[test]
    fn binding_request_reports_class_method_and_length() {
        let bytes = header(BINDING, 0b00, [0xAA; 12], &[]);
        let m = meta(bytes.len());
        let parsed = Stun
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid Binding Request");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(APP), Some(&Value::from("stun")));
        assert_eq!(parsed.fields.get(MESSAGE_CLASS), Some(&Value::U64(0)));
        assert_eq!(
            parsed.fields.get(MESSAGE_METHOD),
            Some(&Value::U64(u64::from(BINDING)))
        );
        assert_eq!(parsed.fields.get(MESSAGE_LENGTH), Some(&Value::U64(0)));
    }

    #[test]
    fn binding_success_response_recovers_xor_mapped_address() {
        let attrs = xor_mapped_address_attr(54321, [203, 0, 113, 42]);
        let bytes = header(BINDING, 0b10, [0xBB; 12], &attrs);
        let m = meta(bytes.len());
        let parsed = Stun
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid Binding Success Response");
        assert_eq!(parsed.fields.get(MESSAGE_CLASS), Some(&Value::U64(2)));
        assert_eq!(
            parsed.fields.get(XOR_MAPPED_ADDRESS),
            Some(&Value::from(&[203u8, 0, 113, 42][..]))
        );
    }

    #[test]
    fn turn_allocate_with_lifetime_and_relayed_address() {
        let mut attrs = attr(ATTR_LIFETIME, &600u32.to_be_bytes());
        let relayed = {
            let cookie = MAGIC_COOKIE.to_be_bytes();
            let mut value = vec![0x00, FAMILY_IPV4];
            value.extend_from_slice(&(1234u16 ^ ((MAGIC_COOKIE >> 16) as u16)).to_be_bytes());
            for i in 0..4 {
                value.push([198, 51, 100, 7][i] ^ cookie[i]);
            }
            attr(ATTR_XOR_RELAYED_ADDRESS, &value)
        };
        attrs.extend_from_slice(&relayed);
        let bytes = header(ALLOCATE, 0b10, [0xCC; 12], &attrs);
        let m = meta(bytes.len());
        let parsed = Stun
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid TURN Allocate Success Response");
        assert_eq!(
            parsed.fields.get(MESSAGE_METHOD),
            Some(&Value::U64(u64::from(ALLOCATE)))
        );
        assert_eq!(parsed.fields.get(LIFETIME), Some(&Value::U64(600)));
        assert_eq!(
            parsed.fields.get(RELAYED_ADDRESS),
            Some(&Value::from(&[198u8, 51, 100, 7][..]))
        );
    }

    #[test]
    fn channel_bind_reports_channel_number() {
        let attrs = attr(ATTR_CHANNEL_NUMBER, &[0x40, 0x00, 0x00, 0x00]);
        let bytes = header(0x0009, 0b00, [0xDD; 12], &attrs);
        let m = meta(bytes.len());
        let parsed = Stun
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid ChannelBind");
        assert_eq!(parsed.fields.get(CHANNEL_NUMBER), Some(&Value::U64(0x4000)));
    }

    #[test]
    fn error_response_reports_error_code() {
        let mut value = vec![0x00, 0x00, 0x04, 0x01]; // class 4, number 1 -> 401
        value.extend_from_slice(b"Unauthorized");
        let attrs = attr(ATTR_ERROR_CODE, &value);
        let bytes = header(BINDING, 0b11, [0xEE; 12], &attrs);
        let m = meta(bytes.len());
        let parsed = Stun
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid error response");
        assert_eq!(parsed.fields.get(MESSAGE_CLASS), Some(&Value::U64(3)));
        assert_eq!(parsed.fields.get(ERROR_CODE), Some(&Value::U64(401)));
    }

    #[test]
    fn probe_scores_confident_on_the_magic_cookie() {
        let bytes = header(BINDING, 0b00, [0; 12], &[]);
        let m = meta(bytes.len());
        let score = Stun
            .probe(&bytes, &ctx(Depth::Full, &m))
            .expect("magic cookie present");
        assert_eq!(score.get(), 95);
    }

    #[test]
    fn probe_declines_on_wrong_magic_cookie() {
        let mut bytes = header(BINDING, 0b00, [0; 12], &[]);
        bytes[4] = 0x00; // corrupt the magic cookie
        let m = meta(bytes.len());
        assert!(Stun.probe(&bytes, &ctx(Depth::Full, &m)).is_none());
    }

    #[test]
    fn wrong_magic_cookie_declines_parse() {
        let mut bytes = header(BINDING, 0b00, [0; 12], &[]);
        bytes[4] = 0x00;
        assert!(Stun
            .parse(&bytes, &ctx(Depth::Full, &meta(bytes.len())))
            .is_err());
    }

    #[test]
    fn odd_message_length_declines() {
        let mut bytes = header(BINDING, 0b00, [0; 12], &[0, 0, 0, 0]);
        bytes[2..4].copy_from_slice(&3u16.to_be_bytes());
        assert!(Stun
            .parse(&bytes, &ctx(Depth::Full, &meta(bytes.len())))
            .is_err());
    }

    #[test]
    fn truncated_frames_decline() {
        let bytes = header(
            BINDING,
            0b00,
            [0xAA; 12],
            &xor_mapped_address_attr(1, [1, 2, 3, 4]),
        );
        let m = meta(bytes.len());
        for n in 0..bytes.len() {
            let full = ctx(Depth::Full, &m);
            assert!(
                Stun.parse(&bytes[..n], &full).is_err(),
                "prefix of {n}/{} bytes must decline",
                bytes.len()
            );
        }
    }

    #[test]
    fn keys_depth_only_has_app() {
        let bytes = header(BINDING, 0b00, [0; 12], &[]);
        let parsed = Stun
            .parse(&bytes, &ctx(Depth::Keys, &meta(bytes.len())))
            .expect("valid header");
        assert_eq!(parsed.fields.len(), 1);
        assert_eq!(parsed.fields.get(APP), Some(&Value::from("stun")));
    }

    #[test]
    fn structural_depth_omits_attribute_fields() {
        let attrs = xor_mapped_address_attr(1, [1, 2, 3, 4]);
        let bytes = header(BINDING, 0b10, [0; 12], &attrs);
        let parsed = Stun
            .parse(&bytes, &ctx(Depth::Structural, &meta(bytes.len())))
            .expect("valid header");
        assert_eq!(parsed.fields.get(XOR_MAPPED_ADDRESS), None);
        assert_eq!(parsed.fields.get(MESSAGE_CLASS), Some(&Value::U64(2)));
    }
}
