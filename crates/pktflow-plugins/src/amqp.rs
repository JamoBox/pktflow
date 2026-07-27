//! AMQP 0-9-1 (11.14, the RabbitMQ-maintained specification — **distinct**
//! from AMQP **1.0**, the separate OASIS/ISO 19464 standard and a
//! different wire format entirely) — app-stream pattern (06.6).
//!
//! ## Frame format (AMQP 0-9-1 §2.3.5)
//! `type(8) | channel(16) | size(32) | payload(size) | frame-end(8, must
//! be `0xCE`)`. `header_len` is `1 + 2 + 4 + size + 1` — self-describing
//! via `size`, the same "consume the declared unit" stance `tls`/`sctp`
//! take, independent of whether the payload is walked any further.
//!
//! ## `Method` frames only (`type == 1`)
//! The payload opens `class-id(16) | method-id(16) | arguments...`;
//! `class_id`/`method_id` identify *what kind* of AMQP operation this is
//! (e.g. class 60/method 40 is `Basic.Publish`) without decoding that
//! method's argument list, which varies per method and is out of v1 scope
//! — the same bounded-envelope stance `http2`'s `SETTINGS` entries and
//! `enip`'s `cip_service` take (11.8/11.13).

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

const TYPE_METHOD: u8 = 1;
const TYPE_HEADER: u8 = 2;
const TYPE_BODY: u8 = 3;
const TYPE_HEARTBEAT: u8 = 8;
/// AMQP 0-9-1 §2.3.5: every frame ends with this fixed octet.
const FRAME_END: u8 = 0xCE;

fn frame_type_name(ty: u8) -> Option<&'static str> {
    Some(match ty {
        TYPE_METHOD => "method",
        TYPE_HEADER => "header",
        TYPE_BODY => "body",
        TYPE_HEARTBEAT => "heartbeat",
        _ => return None,
    })
}

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
        let ty = r.u8()?;
        let frame_type =
            frame_type_name(ty).ok_or(ParseError::Malformed("unrecognized AMQP frame type"))?;
        let channel = r.u16_be()?;
        let size = r.u32_be()?;
        let payload = r.take(usize::try_from(size).unwrap_or(usize::MAX))?;
        let frame_end = r.u8()?;
        if frame_end != FRAME_END {
            return Err(ParseError::Malformed(
                "AMQP frame missing 0xCE frame-end octet",
            ));
        }
        let header_len = 1 + 2 + 4 + usize::try_from(size).unwrap_or(usize::MAX) + 1;

        let (class_id, method_id) = if ty == TYPE_METHOD {
            let mut pr = ByteReader::new(payload);
            match (pr.u16_be(), pr.u16_be()) {
                (Ok(c), Ok(m)) => (Some(c), Some(m)),
                _ => (None, None),
            }
        } else {
            (None, None)
        };

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(APP, Value::from("amqp"));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(FRAME_TYPE, Value::from(frame_type));
            fields.insert(CHANNEL, Value::U64(u64::from(channel)));
            fields.insert(SIZE, Value::U64(u64::from(size)));
        }
        if ctx.depth() >= Depth::Full {
            if let Some(c) = class_id {
                fields.insert(CLASS_ID, Value::U64(u64::from(c)));
            }
            if let Some(m) = method_id {
                fields.insert(METHOD_ID, Value::U64(u64::from(m)));
            }
        }

        Ok(ParsedLayer {
            header_len,
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

    fn frame(ty: u8, channel: u16, payload: &[u8]) -> Vec<u8> {
        let mut b = vec![ty];
        b.extend_from_slice(&channel.to_be_bytes());
        b.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        b.extend_from_slice(payload);
        b.push(FRAME_END);
        b
    }

    #[test]
    fn basic_publish_method_frame_parses_class_and_method_id() {
        // Basic.Publish is class 60, method 40.
        let mut payload = 60u16.to_be_bytes().to_vec();
        payload.extend_from_slice(&40u16.to_be_bytes());
        payload.extend_from_slice(&[0u8; 4]); // arguments, unparsed
        let bytes = frame(TYPE_METHOD, 1, &payload);
        let m = meta(bytes.len());
        let parsed = Amqp
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid Basic.Publish method frame");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(APP), Some(&Value::from("amqp")));
        assert_eq!(parsed.fields.get(FRAME_TYPE), Some(&Value::from("method")));
        assert_eq!(parsed.fields.get(CHANNEL), Some(&Value::U64(1)));
        assert_eq!(parsed.fields.get(CLASS_ID), Some(&Value::U64(60)));
        assert_eq!(parsed.fields.get(METHOD_ID), Some(&Value::U64(40)));
    }

    #[test]
    fn header_and_body_frames_on_same_channel_have_no_class_id() {
        let header = frame(TYPE_HEADER, 1, &[0u8; 14]);
        let m = meta(header.len());
        let parsed = Amqp
            .parse(&header, &ctx(Depth::Full, &m))
            .expect("valid header frame");
        assert_eq!(parsed.fields.get(FRAME_TYPE), Some(&Value::from("header")));
        assert_eq!(parsed.fields.get(CLASS_ID), None);

        let body = frame(TYPE_BODY, 1, b"payload bytes, unparsed");
        let m = meta(body.len());
        let parsed = Amqp
            .parse(&body, &ctx(Depth::Full, &m))
            .expect("valid body frame");
        assert_eq!(parsed.fields.get(FRAME_TYPE), Some(&Value::from("body")));
    }

    #[test]
    fn heartbeat_frame_has_empty_payload() {
        let bytes = frame(TYPE_HEARTBEAT, 0, &[]);
        let m = meta(bytes.len());
        let parsed = Amqp
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid heartbeat");
        assert_eq!(
            parsed.fields.get(FRAME_TYPE),
            Some(&Value::from("heartbeat"))
        );
        assert_eq!(parsed.fields.get(SIZE), Some(&Value::U64(0)));
    }

    #[test]
    fn depth_gates_frame_type_and_class_id() {
        let mut payload = 60u16.to_be_bytes().to_vec();
        payload.extend_from_slice(&40u16.to_be_bytes());
        let bytes = frame(TYPE_METHOD, 1, &payload);
        let m = meta(bytes.len());
        let keys = Amqp.parse(&bytes, &ctx(Depth::Keys, &m)).expect("valid");
        assert_eq!(keys.fields.get(APP), Some(&Value::from("amqp")));
        assert_eq!(keys.fields.get(FRAME_TYPE), None);

        let structural = Amqp
            .parse(&bytes, &ctx(Depth::Structural, &m))
            .expect("valid");
        assert_eq!(
            structural.fields.get(FRAME_TYPE),
            Some(&Value::from("method"))
        );
        assert_eq!(structural.fields.get(CLASS_ID), None);
    }

    #[test]
    fn missing_frame_end_octet_declines() {
        let mut bytes = frame(TYPE_HEARTBEAT, 0, &[]);
        let last = bytes.len() - 1;
        bytes[last] = 0x00;
        let m = meta(bytes.len());
        assert!(Amqp.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn unrecognized_frame_type_declines() {
        let bytes = frame(9, 0, &[]);
        let m = meta(bytes.len());
        assert!(Amqp.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn truncated_frames_decline_at_every_prefix() {
        let mut payload = 60u16.to_be_bytes().to_vec();
        payload.extend_from_slice(&40u16.to_be_bytes());
        let bytes = frame(TYPE_METHOD, 1, &payload);
        let m = meta(bytes.len());
        let full = ctx(Depth::Full, &m);
        for n in 0..bytes.len() {
            assert!(
                Amqp.parse(&bytes[..n], &full).is_err(),
                "prefix of {n}/{} bytes must decline",
                bytes.len()
            );
        }
    }
}
