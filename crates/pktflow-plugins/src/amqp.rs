//! AMQP 0-9-1 (11.14 — the RabbitMQ-maintained specification; **distinct**
//! from AMQP **1.0**, the separate OASIS/ISO 19464 standard and a
//! different wire format entirely). App-stream pattern (06.6): one
//! `amqp` child stream per TCP session, the same shape `mqtt`/`redis`
//! use.
//!
//! ## Frame format (§2.3.5)
//!
//! ```text
//! octet 0    : type      (1=METHOD, 2=HEADER, 3=BODY, 8=HEARTBEAT)
//! octets 1-2 : channel   (u16 BE)
//! octets 3-6 : size      (u32 BE, payload length in octets)
//! octets 7..7+size : payload
//! octet 7+size     : frame-end marker, always 0xCE
//! ```
//!
//! `header_len` is the whole frame (`size + 8`) — the frame-end marker
//! makes every AMQP frame self-delimiting the same way a length-prefixed
//! record elsewhere in this codebase is. A **Method** frame's payload
//! opens with `class-id(2) + method-id(2)` identifying *what kind* of
//! AMQP operation this is (e.g. class 60/method 40 is `Basic.Publish`)
//! without decoding that method's argument list, which varies per method
//! and is out of v1 scope — the same bounded stance `ldap`'s `bind_dn`
//! and `enip`'s `cip_service` take (D12, 11.7/11.13). Header/Body/
//! Heartbeat frame payloads are not decoded at all beyond the common
//! envelope.

use pktflow_core::{
    ByteReader, Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx,
    ParseError, ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId, StreamIdentity, Value,
};

const APP: FieldName = "app";
const FRAME_TYPE: FieldName = "frame_type";
const CHANNEL: FieldName = "channel";
const SIZE: FieldName = "size";
const CLASS_ID: FieldName = "class_id";
const METHOD_ID: FieldName = "method_id";

const FRAME_METHOD: u8 = 1;
const FRAME_HEADER: u8 = 2;
const FRAME_BODY: u8 = 3;
const FRAME_HEARTBEAT: u8 = 8;

/// §2.3.5: every frame ends with this fixed marker octet.
const FRAME_END: u8 = 0xCE;

static KEY: &[KeyField] = &[KeyField { a: APP, b: None }];
static ROLLUPS: &[RollupSpec] = &[
    RollupSpec {
        field: FRAME_TYPE,
        kind: RollupKind::Accumulate,
    },
    RollupSpec {
        field: CLASS_ID,
        kind: RollupKind::Accumulate,
    },
];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: ROLLUPS,
};

pub struct Amqp;

impl LayerPlugin for Amqp {
    fn name(&self) -> ProtocolName {
        "amqp"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let frame_type = r.u8()?;
        if !matches!(
            frame_type,
            FRAME_METHOD | FRAME_HEADER | FRAME_BODY | FRAME_HEARTBEAT
        ) {
            return Err(ParseError::Malformed("AMQP: unrecognized frame type"));
        }
        let channel = r.u16_be()?;
        let size = r.u32_be()?;
        let payload = r.take(usize::try_from(size).map_err(|_| {
            ParseError::Malformed("AMQP: frame size does not fit this platform's usize")
        })?)?;
        let frame_end = r.u8()?;
        if frame_end != FRAME_END {
            return Err(ParseError::Malformed(
                "AMQP: missing frame-end marker (0xCE)",
            ));
        }

        let mut class_id = None;
        let mut method_id = None;
        if frame_type == FRAME_METHOD {
            let mut pr = ByteReader::new(payload);
            class_id = Some(pr.u16_be()?);
            method_id = Some(pr.u16_be()?);
        }

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(APP, Value::from("amqp"));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(FRAME_TYPE, Value::U64(u64::from(frame_type)));
            fields.insert(CHANNEL, Value::U64(u64::from(channel)));
            fields.insert(SIZE, Value::U64(u64::from(size)));
        }
        if ctx.depth() >= Depth::Full {
            if let Some(v) = class_id {
                fields.insert(CLASS_ID, Value::U64(u64::from(v)));
            }
            if let Some(v) = method_id {
                fields.insert(METHOD_ID, Value::U64(u64::from(v)));
            }
        }

        Ok(ParsedLayer {
            header_len: bytes.len() - r.remaining(),
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::TcpPort(5672)]
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

    fn frame(frame_type: u8, channel: u16, payload: &[u8]) -> Vec<u8> {
        let mut b = vec![frame_type];
        b.extend_from_slice(&channel.to_be_bytes());
        b.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        b.extend_from_slice(payload);
        b.push(FRAME_END);
        b
    }

    /// class 60 (`basic`), method 40 (`Basic.Publish`): a Method frame,
    /// arguments unparsed.
    fn basic_publish_method() -> Vec<u8> {
        let mut payload = vec![0x00, 60, 0x00, 40];
        payload.extend_from_slice(&[0xAA, 0xBB]); // opaque method arguments
        frame(FRAME_METHOD, 1, &payload)
    }

    #[test]
    fn method_frame_reports_class_and_method_id() {
        let bytes = basic_publish_method();
        let m = meta(bytes.len());
        let parsed = Amqp
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid Method frame");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(APP), Some(&Value::from("amqp")));
        assert_eq!(
            parsed.fields.get(FRAME_TYPE),
            Some(&Value::U64(u64::from(FRAME_METHOD)))
        );
        assert_eq!(parsed.fields.get(CHANNEL), Some(&Value::U64(1)));
        assert_eq!(parsed.fields.get(CLASS_ID), Some(&Value::U64(60)));
        assert_eq!(parsed.fields.get(METHOD_ID), Some(&Value::U64(40)));
    }

    #[test]
    fn header_frame_has_no_class_or_method_id() {
        let bytes = frame(FRAME_HEADER, 1, &[0u8; 14]);
        let m = meta(bytes.len());
        let parsed = Amqp
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid Header frame");
        assert_eq!(
            parsed.fields.get(FRAME_TYPE),
            Some(&Value::U64(u64::from(FRAME_HEADER)))
        );
        assert_eq!(parsed.fields.get(CLASS_ID), None);
    }

    #[test]
    fn body_frame_payload_is_not_decoded() {
        let bytes = frame(FRAME_BODY, 1, b"hello, amqp");
        let m = meta(bytes.len());
        let parsed = Amqp
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid Body frame");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(
            parsed.fields.get(SIZE),
            Some(&Value::U64(b"hello, amqp".len() as u64))
        );
        assert_eq!(parsed.fields.get(CLASS_ID), None);
    }

    #[test]
    fn heartbeat_frame_has_zero_size() {
        let bytes = frame(FRAME_HEARTBEAT, 0, &[]);
        let m = meta(bytes.len());
        let parsed = Amqp
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid Heartbeat frame");
        assert_eq!(parsed.fields.get(SIZE), Some(&Value::U64(0)));
    }

    #[test]
    fn missing_frame_end_marker_declines() {
        let mut bytes = basic_publish_method();
        let last = bytes.len() - 1;
        bytes[last] = 0x00;
        assert!(Amqp
            .parse(&bytes, &ctx(Depth::Full, &meta(bytes.len())))
            .is_err());
    }

    #[test]
    fn unrecognized_frame_type_declines() {
        let bytes = frame(99, 0, &[]);
        assert!(Amqp
            .parse(&bytes, &ctx(Depth::Full, &meta(bytes.len())))
            .is_err());
    }

    #[test]
    fn truncated_frames_decline() {
        let bytes = basic_publish_method();
        let m = meta(bytes.len());
        for n in 0..bytes.len() {
            let full = ctx(Depth::Full, &m);
            assert!(
                Amqp.parse(&bytes[..n], &full).is_err(),
                "prefix of {n}/{} bytes must decline",
                bytes.len()
            );
        }
    }

    #[test]
    fn keys_depth_only_has_app() {
        let bytes = basic_publish_method();
        let parsed = Amqp
            .parse(&bytes, &ctx(Depth::Keys, &meta(bytes.len())))
            .expect("valid frame");
        assert_eq!(parsed.fields.len(), 1);
        assert_eq!(parsed.fields.get(APP), Some(&Value::from("amqp")));
    }

    #[test]
    fn structural_depth_omits_class_and_method_id() {
        let bytes = basic_publish_method();
        let parsed = Amqp
            .parse(&bytes, &ctx(Depth::Structural, &meta(bytes.len())))
            .expect("valid frame");
        assert_eq!(
            parsed.fields.get(FRAME_TYPE),
            Some(&Value::U64(u64::from(FRAME_METHOD)))
        );
        assert_eq!(parsed.fields.get(CLASS_ID), None);
    }
}
