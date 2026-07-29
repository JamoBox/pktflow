//! STUN (11.8, RFC 8489) / TURN (RFC 8656) — one plugin covers both: TURN
//! is the *same message format*, extended with more methods/attributes and
//! no new header shape (RFC 8656 §5), the `ospf`/`stun`-unifying-versions
//! precedent this task already sets (11.4). Disambiguated purely by
//! `message_method` — no `turn`-specific claim exists or is needed.
//!
//! ## Header (RFC 8489 §5)
//! 20 bytes, fixed: `00 | Message Type(14) | Message Length(16) | Magic
//! Cookie(32, fixed `0x2112A442`) | Transaction ID(96)`. The two leading
//! bits are always `0` (STUN's own self-multiplexing discipline, letting
//! it share a port with other protocols like DTLS); this plugin declines
//! otherwise. `Message Length` counts only the attributes that follow, so
//! `header_len` is `20 + message_length` — self-describing, independent of
//! how far the attribute walk below gets.
//!
//! `Message Type`'s 14 bits interleave a 2-bit class and a 12-bit method
//! (RFC 8489 §5's bit diagram): class bit `C0` sits at bit 4, `C1` at bit
//! 8 (`class = C1*2 + C0`); the method's 12 bits split into three runs
//! around them — bits 0-3, bits 5-7 (shifted into method bits 4-6), bits
//! 9-13 (shifted into method bits 7-11). `class` is `0`=Request,
//! `1`=Indication, `2`=Success Response, `3`=Error Response.
//!
//! ## Attributes (RFC 8489 §14)
//! `Type(16) + Length(16) + Value(Length, padded to a 4-byte boundary)`,
//! repeated until `message_length` bytes are consumed. The walk is
//! best-effort and stops silently at the first malformed entry (never
//! declines the whole message over it — the same bounded-attribute stance
//! `radius`'s AVP walk takes, 11.7) since `header_len` never depends on it.
//! `XOR-MAPPED-ADDRESS` (0x0020) / `XOR-RELAYED-ADDRESS` (0x0016, TURN)
//! both XOR the address bytes against the magic cookie (IPv4) or the magic
//! cookie plus the transaction id (IPv6, RFC 8489 §14.2) — the port is
//! discarded here, keeping the field a plain address `Bytes` value per
//! 11.8's field table. `ERROR-CODE` (0x0009) packs `class*100 + number`
//! into a single `U64` (the reason phrase that follows is not extracted).

use pktflow_core::{
    ByteReader, Canonicalize, Confidence, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin,
    ParseCtx, ParseError, ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId,
    StreamIdentity, Value,
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

const MAGIC_COOKIE: u32 = 0x2112_A442;
const HEADER_LEN: usize = 20;

const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const ATTR_USERNAME: u16 = 0x0006;
const ATTR_ERROR_CODE: u16 = 0x0009;
const ATTR_XOR_RELAYED_ADDRESS: u16 = 0x0016;
const ATTR_LIFETIME: u16 = 0x000D;
const ATTR_CHANNEL_NUMBER: u16 = 0x000C;

fn message_class_name(class: u8) -> &'static str {
    match class {
        0 => "request",
        1 => "indication",
        2 => "success_response",
        _ => "error_response",
    }
}

/// RFC 8489 §5's interleaved class/method bit layout: `C0` sits at bit 4,
/// `C1` at bit 8; the method's 12 bits split into three runs (bits 0-3,
/// 5-7, 9-13) around them.
fn decode_message_type(msg_type: u16) -> (u8, u16) {
    let c0 = (msg_type >> 4) & 0x1;
    let c1 = (msg_type >> 8) & 0x1;
    let class = ((c1 << 1) | c0) as u8;
    let method =
        (msg_type & 0xF) | (((msg_type >> 5) & 0x7) << 4) | (((msg_type >> 9) & 0x1F) << 7);
    (class, method)
}

/// RFC 8489 §14.2's XOR transform: IPv4 XORs against the magic cookie
/// alone; IPv6 XORs against the cookie followed by the full transaction id.
fn decode_xor_address(value: &[u8], transaction_id: &[u8]) -> Option<Vec<u8>> {
    let mut r = ByteReader::new(value);
    let _reserved = r.u8().ok()?;
    let family = r.u8().ok()?;
    let _xor_port = r.u16_be().ok()?;
    match family {
        0x01 => {
            let addr = r.take(4).ok()?;
            let cookie = MAGIC_COOKIE.to_be_bytes();
            Some(addr.iter().zip(cookie.iter()).map(|(a, c)| a ^ c).collect())
        }
        0x02 => {
            let addr = r.take(16).ok()?;
            let mut key = MAGIC_COOKIE.to_be_bytes().to_vec();
            key.extend_from_slice(transaction_id);
            Some(addr.iter().zip(key.iter()).map(|(a, c)| a ^ c).collect())
        }
        _ => None,
    }
}

/// RFC 8489 §14.8: `Reserved(21) + Class(3) + Number(8)`; the real code is
/// `class*100 + number`. The reason phrase that follows is not extracted.
fn decode_error_code(value: &[u8]) -> Option<u64> {
    let mut r = ByteReader::new(value);
    let _reserved_and_class_hi = r.u16_be().ok()?;
    let class_and_reserved = r.u8().ok()?;
    let number = r.u8().ok()?;
    let class = class_and_reserved & 0x07;
    Some(u64::from(class) * 100 + u64::from(number))
}

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

pub struct Stun;

impl LayerPlugin for Stun {
    fn name(&self) -> ProtocolName {
        "stun"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let msg_type = r.u16_be()?;
        if msg_type & 0xC000 != 0 {
            return Err(ParseError::Malformed(
                "STUN message type's top two bits must be zero",
            ));
        }
        let message_length = r.u16_be()?;
        // RFC 8489 §5: every attribute is padded to a multiple of 4, so
        // the length's low two bits are always zero. A cheap structural
        // invariant on a plugin that claims a whole port — non-STUN bytes
        // that happen to clear the magic-cookie check still fail here.
        if message_length % 4 != 0 {
            return Err(ParseError::Malformed(
                "STUN message length is not a multiple of 4",
            ));
        }
        let magic_cookie = r.u32_be()?;
        if magic_cookie != MAGIC_COOKIE {
            return Err(ParseError::Malformed("STUN magic cookie mismatch"));
        }
        let transaction_id = r.take(12)?;
        let attrs = r.take(usize::from(message_length))?;
        let header_len = HEADER_LEN + usize::from(message_length);

        let (class, method) = decode_message_type(msg_type);

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(APP, Value::from("stun"));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(MESSAGE_CLASS, Value::from(message_class_name(class)));
            fields.insert(MESSAGE_METHOD, Value::U64(u64::from(method)));
            fields.insert(MESSAGE_LENGTH, Value::U64(u64::from(message_length)));
        }
        if ctx.depth() >= Depth::Full {
            let mut ar = ByteReader::new(attrs);
            while ar.remaining() >= 4 {
                let Ok(attr_type) = ar.u16_be() else { break };
                let Ok(attr_len) = ar.u16_be() else { break };
                let Ok(value) = ar.take(usize::from(attr_len)) else {
                    break;
                };
                let padding = (4 - usize::from(attr_len) % 4) % 4;
                if ar.take(padding).is_err() {
                    break;
                }
                match attr_type {
                    ATTR_XOR_MAPPED_ADDRESS => {
                        if let Some(addr) = decode_xor_address(value, transaction_id) {
                            fields.insert(XOR_MAPPED_ADDRESS, Value::from(&addr[..]));
                        }
                    }
                    ATTR_XOR_RELAYED_ADDRESS => {
                        if let Some(addr) = decode_xor_address(value, transaction_id) {
                            fields.insert(RELAYED_ADDRESS, Value::from(&addr[..]));
                        }
                    }
                    ATTR_USERNAME => {
                        if let Ok(s) = std::str::from_utf8(value) {
                            fields.insert(USERNAME, Value::from(s));
                        }
                    }
                    ATTR_ERROR_CODE => {
                        if let Some(code) = decode_error_code(value) {
                            fields.insert(ERROR_CODE, Value::U64(code));
                        }
                    }
                    ATTR_LIFETIME if value.len() == 4 => {
                        let secs = u32::from_be_bytes(value.try_into().unwrap_or([0; 4]));
                        fields.insert(LIFETIME, Value::U64(u64::from(secs)));
                    }
                    ATTR_CHANNEL_NUMBER if value.len() >= 2 => {
                        let ch = u16::from_be_bytes([value[0], value[1]]);
                        fields.insert(CHANNEL_NUMBER, Value::U64(u64::from(ch)));
                    }
                    _ => {}
                }
            }
        }

        Ok(ParsedLayer {
            header_len,
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
        let msg_type = r.u16_be().ok()?;
        if msg_type & 0xC000 != 0 {
            return None;
        }
        let _message_length = r.u16_be().ok()?;
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

    fn header(msg_type: u16, message_length: u16, txn: &[u8; 12]) -> Vec<u8> {
        let mut b = msg_type.to_be_bytes().to_vec();
        b.extend_from_slice(&message_length.to_be_bytes());
        b.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        b.extend_from_slice(txn);
        b
    }

    fn attr(attr_type: u16, value: &[u8]) -> Vec<u8> {
        let mut b = attr_type.to_be_bytes().to_vec();
        b.extend_from_slice(&(value.len() as u16).to_be_bytes());
        b.extend_from_slice(value);
        while !b.len().is_multiple_of(4) {
            b.push(0);
        }
        b
    }

    fn xor_mapped_v4(port: u16, addr: [u8; 4]) -> Vec<u8> {
        let mut v = vec![0x00, 0x01];
        let xport = port ^ (MAGIC_COOKIE >> 16) as u16;
        v.extend_from_slice(&xport.to_be_bytes());
        let cookie = MAGIC_COOKIE.to_be_bytes();
        for i in 0..4 {
            v.push(addr[i] ^ cookie[i]);
        }
        v
    }

    #[test]
    fn binding_request_parses_class_and_method() {
        let txn = [0x01u8; 12];
        let bytes = header(0x0001, 0, &txn); // Binding Request
        let m = meta(bytes.len());
        let parsed = Stun
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid Binding Request");
        assert_eq!(parsed.header_len, 20);
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(APP), Some(&Value::from("stun")));
        assert_eq!(
            parsed.fields.get(MESSAGE_CLASS),
            Some(&Value::from("request"))
        );
        assert_eq!(parsed.fields.get(MESSAGE_METHOD), Some(&Value::U64(0x001)));
    }

    #[test]
    fn binding_success_response_recovers_xor_mapped_address() {
        let txn = [0x02u8; 12];
        let addr_attr = attr(
            ATTR_XOR_MAPPED_ADDRESS,
            &xor_mapped_v4(3478, [203, 0, 113, 5]),
        );
        let mut bytes = header(0x0101, addr_attr.len() as u16, &txn); // Binding Success Response
        bytes.extend_from_slice(&addr_attr);
        let m = meta(bytes.len());
        let parsed = Stun
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid Binding Success Response");
        assert_eq!(
            parsed.fields.get(MESSAGE_CLASS),
            Some(&Value::from("success_response"))
        );
        assert_eq!(
            parsed.fields.get(XOR_MAPPED_ADDRESS),
            Some(&Value::from(&[203u8, 0, 113, 5][..]))
        );
    }

    #[test]
    fn error_response_class_and_error_code_decode() {
        let txn = [0x03u8; 12];
        // ERROR-CODE: class 4, number 1 -> 401.
        let ec = attr(ATTR_ERROR_CODE, &[0, 0, 0x04, 0x01]);
        let mut bytes = header(0x0111, ec.len() as u16, &txn); // Binding Error Response
        bytes.extend_from_slice(&ec);
        let m = meta(bytes.len());
        let parsed = Stun
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid Binding Error Response");
        assert_eq!(
            parsed.fields.get(MESSAGE_CLASS),
            Some(&Value::from("error_response"))
        );
        assert_eq!(parsed.fields.get(ERROR_CODE), Some(&Value::U64(401)));
    }

    #[test]
    fn turn_allocate_refresh_send_data_and_create_permission_methods() {
        let txn = [0x04u8; 12];
        for (method, expected) in [
            (0x003u16, 0x003u64), // Allocate
            (0x004, 0x004),       // Refresh
            (0x006, 0x006),       // Send
            (0x007, 0x007),       // Data
            (0x008, 0x008),       // CreatePermission
            (0x009, 0x009),       // ChannelBind
        ] {
            let bytes = header(method, 0, &txn); // class Request (0)
            let m = meta(bytes.len());
            let parsed = Stun
                .parse(&bytes, &ctx(Depth::Full, &m))
                .unwrap_or_else(|e| panic!("method {method:#x}: {e}"));
            assert_eq!(
                parsed.fields.get(MESSAGE_METHOD),
                Some(&Value::U64(expected))
            );
        }
    }

    #[test]
    fn turn_allocate_response_recovers_relayed_address_and_lifetime() {
        let txn = [0x05u8; 12];
        let mut attrs = attr(
            ATTR_XOR_RELAYED_ADDRESS,
            &xor_mapped_v4(50000, [198, 51, 100, 9]),
        );
        attrs.extend_from_slice(&attr(ATTR_LIFETIME, &600u32.to_be_bytes()));
        let mut bytes = header(0x0103, attrs.len() as u16, &txn); // Allocate Success Response
        bytes.extend_from_slice(&attrs);
        let m = meta(bytes.len());
        let parsed = Stun
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid Allocate response");
        assert_eq!(
            parsed.fields.get(RELAYED_ADDRESS),
            Some(&Value::from(&[198u8, 51, 100, 9][..]))
        );
        assert_eq!(parsed.fields.get(LIFETIME), Some(&Value::U64(600)));
    }

    #[test]
    fn channel_bind_recovers_channel_number() {
        let txn = [0x06u8; 12];
        let mut value = vec![0x40, 0x00];
        value.extend_from_slice(&[0, 0]); // RFFU
        let attrs = attr(ATTR_CHANNEL_NUMBER, &value);
        let mut bytes = header(0x0009, attrs.len() as u16, &txn); // ChannelBind Request
        bytes.extend_from_slice(&attrs);
        let m = meta(bytes.len());
        let parsed = Stun
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid ChannelBind request");
        assert_eq!(parsed.fields.get(CHANNEL_NUMBER), Some(&Value::U64(0x4000)));
    }

    #[test]
    fn username_attribute_decodes_as_utf8() {
        let txn = [0x07u8; 12];
        let attrs = attr(ATTR_USERNAME, b"alice");
        let mut bytes = header(0x0001, attrs.len() as u16, &txn);
        bytes.extend_from_slice(&attrs);
        let m = meta(bytes.len());
        let parsed = Stun.parse(&bytes, &ctx(Depth::Full, &m)).expect("valid");
        assert_eq!(parsed.fields.get(USERNAME), Some(&Value::from("alice")));
    }

    #[test]
    fn magic_cookie_mismatch_declines() {
        let mut bytes = 0x0001u16.to_be_bytes().to_vec();
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(&0xDEAD_BEEFu32.to_be_bytes()); // wrong cookie
        bytes.extend_from_slice(&[0u8; 12]);
        let m = meta(bytes.len());
        assert!(Stun.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn top_bits_set_declines() {
        let txn = [0u8; 12];
        let mut bytes = header(0x0001, 0, &txn);
        bytes[0] |= 0x80; // sets one of the reserved top two bits
        let m = meta(bytes.len());
        assert!(Stun.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn malformed_attribute_stops_the_walk_without_declining() {
        let txn = [0x08u8; 12];
        // A well-formed attribute followed by one whose declared length
        // overruns the buffer — the walk stops there, the message as a
        // whole still parses.
        let mut attrs = attr(ATTR_USERNAME, b"bob");
        attrs.extend_from_slice(&0x0020u16.to_be_bytes());
        attrs.extend_from_slice(&9000u16.to_be_bytes()); // absurd length
        let mut bytes = header(0x0001, attrs.len() as u16, &txn);
        bytes.extend_from_slice(&attrs);
        let m = meta(bytes.len());
        let parsed = Stun
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("still parses despite the malformed trailing attribute");
        assert_eq!(parsed.fields.get(USERNAME), Some(&Value::from("bob")));
        assert_eq!(parsed.fields.get(XOR_MAPPED_ADDRESS), None);
    }

    #[test]
    fn depth_ladder_gates_class_and_attributes() {
        let txn = [0x09u8; 12];
        let addr_attr = attr(ATTR_XOR_MAPPED_ADDRESS, &xor_mapped_v4(1, [1, 1, 1, 1]));
        let mut bytes = header(0x0101, addr_attr.len() as u16, &txn);
        bytes.extend_from_slice(&addr_attr);
        let m = meta(bytes.len());

        let keys = Stun.parse(&bytes, &ctx(Depth::Keys, &m)).expect("valid");
        assert_eq!(keys.fields.get(APP), Some(&Value::from("stun")));
        assert_eq!(keys.fields.get(MESSAGE_CLASS), None);

        let structural = Stun
            .parse(&bytes, &ctx(Depth::Structural, &m))
            .expect("valid");
        assert_eq!(
            structural.fields.get(MESSAGE_CLASS),
            Some(&Value::from("success_response"))
        );
        assert_eq!(structural.fields.get(XOR_MAPPED_ADDRESS), None);
    }

    #[test]
    fn truncated_frames_decline_at_every_prefix() {
        let txn = [0x0Au8; 12];
        let addr_attr = attr(ATTR_XOR_MAPPED_ADDRESS, &xor_mapped_v4(1, [1, 1, 1, 1]));
        let mut bytes = header(0x0101, addr_attr.len() as u16, &txn);
        bytes.extend_from_slice(&addr_attr);
        let m = meta(bytes.len());
        let full = ctx(Depth::Full, &m);
        for n in 0..bytes.len() {
            assert!(
                Stun.parse(&bytes[..n], &full).is_err(),
                "prefix of {n}/{} bytes must decline",
                bytes.len()
            );
        }
    }

    #[test]
    fn probe_scores_correct_magic_cookie_and_declines_mismatch() {
        let txn = [0x0Bu8; 12];
        let good = header(0x0001, 0, &txn);
        let m = meta(good.len());
        let c = ctx(Depth::Full, &m);
        assert_eq!(Stun.probe(&good, &c).map(|c| c.get()), Some(95));

        let mut bad = good.clone();
        bad[4..8].copy_from_slice(&0x1234_5678u32.to_be_bytes());
        assert_eq!(Stun.probe(&bad, &c), None);
    }
}
