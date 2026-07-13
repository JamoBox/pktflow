//! MQTT (11.14, OASIS *MQTT Version 5.0* <https://docs.oasis-open.org/mqtt/mqtt/v5.0/mqtt-v5.0.html>,
//! also ISO/IEC 20922:2016; wire-compatible with *MQTT Version 3.1.1*
//! <https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html> for everything this
//! plugin reads): a fixed header (control packet type + flags, then a Variable Byte
//! Integer "Remaining Length", 5.0 §1.5.5 / 3.1.1 §2.2.3 — identical scheme in both)
//! followed by a per-type variable header and payload. `remaining_length` is
//! authoritative and self-bounding, the same "no cross-packet state needed to find the
//! frame's end" property MBAP framing gives Modbus/TCP (modbus.rs) — the whole control
//! packet, recognized shape or not, is consumed as `header_len`, and anything this
//! plugin doesn't decode is left opaque (D12). A packet whose declared
//! `remaining_length` is not fully present in this segment (e.g. a PUBLISH payload
//! spanning multiple TCP segments) simply declines, the same "only the first message in
//! a segment is parsed" honesty DNS-over-TCP documents (dns.rs, D7).
//!
//! **Version ambiguity, stated (D12/D13 honesty stance).** CONNECT carries its own
//! Protocol Version byte, so it decodes correctly for both 3.1.1 and 5.0 — 5.0 adds a
//! Properties field between Keep Alive and the Client Identifier, accounted for below.
//! PUBLISH and SUBSCRIBE carry no such tag, and this is a stateless, one-packet-at-a-time
//! plugin (rule 5, 02.1) that never saw the session's CONNECT — the same "can't
//! disambiguate a shape without seeing the matching request first" ceiling modbus.rs
//! documents for its own read-function responses. PUBLISH's `topic` sits at a fixed
//! offset in *both* versions (the first variable-header field), so it always decodes;
//! SUBSCRIBE's topic-filter list assumes the 3.1.1 shape (Packet Identifier, then
//! filters directly — no 5.0 Properties in between). A 5.0 SUBSCRIBE carrying
//! properties shifts that walk out of alignment and yields an empty or partial
//! `topics` rather than the true list — `header_len` is computed from
//! `remaining_length` alone and is unaffected either way, so a mis-shaped walk cannot
//! desync framing, only omit a field (bounded blast radius, same contract modbus's
//! opaque fallback keeps).

use pktflow_core::{
    ByteReader, Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx,
    ParseError, ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId, StreamIdentity, Value,
};

const APP: FieldName = "app";
const MESSAGE_TYPE: FieldName = "message_type";
const REMAINING_LENGTH: FieldName = "remaining_length";
const CLIENT_ID: FieldName = "client_id";
const KEEP_ALIVE: FieldName = "keep_alive";
const TOPIC: FieldName = "topic";
const QOS: FieldName = "qos";
const RETAIN: FieldName = "retain";
const TOPICS: FieldName = "topics";

/// Control Packet type nibble (5.0 §2.1.2 Table 2-1 / 3.1.1 §2.2.1 Table 2.1 — identical
/// numbering in both; 0 and values above 15 are impossible in a 4-bit nibble, but 0 is
/// itself "Reserved", never a legal packet).
const CONNECT: u8 = 1;
const PUBLISH: u8 = 3;
const SUBSCRIBE: u8 = 8;

/// CONNECT's Protocol Version byte value for MQTT 5.0 (5.0 §3.1.2.2); 3 (the legacy
/// MQIsdp 3.1) and 4 (3.1.1) carry no Properties field.
const PROTOCOL_VERSION_5: u8 = 5;

/// PUBLISH fixed-header flags (5.0 §3.3.1 / 3.1.1 §3.3.1 — identical bit layout).
const PUBLISH_RETAIN: u8 = 0x01;
const PUBLISH_QOS_MASK: u8 = 0x06;
const PUBLISH_QOS_SHIFT: u8 = 1;
/// QoS 3 is reserved and MUST NOT appear on the wire (5.0 §3.3.1.3 / 3.1.1 §3.3.1.3).
const RESERVED_QOS: u64 = 3;

/// Hostile SUBSCRIBE payloads must not turn into an unbounded topic-filter walk.
const MAX_TOPICS: usize = 128;

static KEY: &[KeyField] = &[KeyField { a: APP, b: None }];
static ROLLUPS: &[RollupSpec] = &[
    RollupSpec {
        field: MESSAGE_TYPE,
        kind: RollupKind::Accumulate,
    },
    RollupSpec {
        field: TOPIC,
        kind: RollupKind::Accumulate,
    },
];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: ROLLUPS,
};

/// Decodes a Variable Byte Integer (5.0 §1.5.5 / 3.1.1 §2.2.3): up to four
/// continuation-bit-tagged base-128 digits, least significant first. Both
/// `remaining_length` and (MQTT 5 only) property lengths use this encoding.
fn variable_byte_int(r: &mut ByteReader<'_>) -> Result<usize, ParseError> {
    let mut value: u32 = 0;
    let mut multiplier: u32 = 1;
    for _ in 0..4 {
        let byte = r.u8()?;
        value += u32::from(byte & 0x7F) * multiplier;
        if byte & 0x80 == 0 {
            return usize::try_from(value).map_err(|_| {
                ParseError::Malformed("variable byte integer exceeds addressable size")
            });
        }
        multiplier *= 128;
    }
    Err(ParseError::Malformed(
        "variable byte integer exceeds 4 bytes",
    ))
}

/// Reads one UTF-8 Encoded String (5.0 §1.5.4 / 3.1.1 §1.5.3): a 2-byte big-endian
/// length prefix followed by that many bytes, required to be well-formed UTF-8. Strict
/// (not lossy) on purpose — MQTT itself makes malformed encoding a protocol error here,
/// and rejecting it doubles as a sanity check against the SUBSCRIBE shape ambiguity
/// noted above (a misaligned walk is likely to hit invalid UTF-8 and decline cleanly
/// rather than emit a plausible-looking wrong string).
fn utf8_string(r: &mut ByteReader<'_>) -> Result<String, ParseError> {
    let len = usize::from(r.u16_be()?);
    let bytes = r.take(len)?;
    str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| ParseError::Malformed("invalid UTF-8 encoded string"))
}

/// CONNECT's variable header + the payload's leading Client Identifier (5.0 §3.1.2-3.1.3
/// / 3.1.1 §3.1.2-3.1.3): Protocol Name, Protocol Version, Connect Flags, Keep Alive,
/// then (5.0 only) Properties, then Client Identifier. Will/User Name/Password payload
/// fields follow the Client Identifier and are out of scope (opaque, per `header_len`
/// already covering the whole packet via `remaining_length`).
fn connect_fields(body: &[u8]) -> Result<(String, u16), ParseError> {
    let mut r = ByteReader::new(body);
    let _protocol_name = utf8_string(&mut r)?;
    let protocol_version = r.u8()?;
    let _connect_flags = r.u8()?;
    let keep_alive = r.u16_be()?;
    if protocol_version == PROTOCOL_VERSION_5 {
        let property_len = variable_byte_int(&mut r)?;
        let _properties = r.take(property_len)?;
    }
    let client_id = utf8_string(&mut r)?;
    Ok((client_id, keep_alive))
}

/// PUBLISH's Topic Name (5.0 §3.3.2.1 / 3.1.1 §3.3.2): the first variable-header field
/// in both protocol versions, so — unlike SUBSCRIBE's payload — reading it needs no
/// version assumption.
fn publish_topic(body: &[u8]) -> Result<String, ParseError> {
    let mut r = ByteReader::new(body);
    utf8_string(&mut r)
}

/// SUBSCRIBE's topic-filter list (5.0 §3.8.3 / 3.1.1 §3.8.3): Packet Identifier, then
/// (Topic Filter, Subscription Options) pairs to the end of the payload. Assumes the
/// 3.1.1 shape (see module doc) — a 5.0 Properties field between Packet Identifier and
/// the filter list is not accounted for.
fn subscribe_topics(body: &[u8]) -> Result<Vec<String>, ParseError> {
    let mut r = ByteReader::new(body);
    let _packet_identifier = r.u16_be()?;
    let mut topics = Vec::new();
    while r.remaining() > 0 && topics.len() < MAX_TOPICS {
        let topic_filter = utf8_string(&mut r)?;
        let _subscription_options = r.u8()?;
        topics.push(topic_filter);
    }
    Ok(topics)
}

pub struct Mqtt;

impl LayerPlugin for Mqtt {
    fn name(&self) -> ProtocolName {
        "mqtt"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let first = r.u8()?;
        let message_type = first >> 4;
        if message_type == 0 {
            return Err(ParseError::Malformed("reserved MQTT control packet type"));
        }
        let flags = first & 0x0F;
        let remaining_length = variable_byte_int(&mut r)?;
        let body = r.take(remaining_length)?;

        let qos = u64::from((flags & PUBLISH_QOS_MASK) >> PUBLISH_QOS_SHIFT);
        if message_type == PUBLISH && qos == RESERVED_QOS {
            return Err(ParseError::Malformed("PUBLISH QoS value 3 is reserved"));
        }

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(APP, Value::from("mqtt"));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(MESSAGE_TYPE, Value::U64(u64::from(message_type)));
            fields.insert(REMAINING_LENGTH, Value::U64(remaining_length as u64));
        }
        if ctx.depth() >= Depth::Full {
            match message_type {
                CONNECT => {
                    if let Ok((client_id, keep_alive)) = connect_fields(body) {
                        fields.insert(CLIENT_ID, Value::from(client_id.as_str()));
                        fields.insert(KEEP_ALIVE, Value::U64(u64::from(keep_alive)));
                    }
                }
                PUBLISH => {
                    if let Ok(topic) = publish_topic(body) {
                        fields.insert(TOPIC, Value::from(topic.as_str()));
                    }
                    fields.insert(QOS, Value::U64(qos));
                    fields.insert(RETAIN, Value::Bool(flags & PUBLISH_RETAIN != 0));
                }
                SUBSCRIBE => {
                    if let Ok(topics) = subscribe_topics(body) {
                        fields.insert(
                            TOPICS,
                            Value::List(topics.iter().map(|t| Value::from(t.as_str())).collect()),
                        );
                    }
                }
                _ => {}
            }
        }

        Ok(ParsedLayer {
            header_len: bytes.len() - r.remaining(),
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::TcpPort(1883)]
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

    fn encode_variable_byte_int(mut value: usize) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut byte = (value % 128) as u8;
            value /= 128;
            if value > 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if value == 0 {
                break;
            }
        }
        out
    }

    fn frame(message_type: u8, flags: u8, body: &[u8]) -> Vec<u8> {
        let mut f = vec![(message_type << 4) | flags];
        f.extend_from_slice(&encode_variable_byte_int(body.len()));
        f.extend_from_slice(body);
        f
    }

    fn utf8_field(s: &str) -> Vec<u8> {
        let mut out = (s.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(s.as_bytes());
        out
    }

    fn parse(bytes: &[u8]) -> Result<ParsedLayer, ParseError> {
        let meta = PacketMeta {
            timestamp: SystemTime::UNIX_EPOCH,
            caplen: bytes.len(),
            origlen: bytes.len(),
            link_type: LinkType::ETHERNET,
        };
        Mqtt.parse(bytes, &ParseCtx::new(&[], Depth::Full, &meta))
    }

    // CONNECT, MQTT 3.1.1: "MQTT"/level 4, clean-session flag, keep_alive=60,
    // client id "pktflow-test" (3.1.1 §3.1).
    fn connect_311(client_id: &str, keep_alive: u16) -> Vec<u8> {
        let mut body = utf8_field("MQTT");
        body.push(4); // protocol level 4 = 3.1.1
        body.push(0x02); // Clean Session
        body.extend_from_slice(&keep_alive.to_be_bytes());
        body.extend_from_slice(&utf8_field(client_id));
        frame(CONNECT, 0x00, &body)
    }

    // CONNECT, MQTT 5.0: same shape plus a zero-length Properties field ahead of the
    // client id (5.0 §3.1.2.11).
    fn connect_v5(client_id: &str, keep_alive: u16) -> Vec<u8> {
        let mut body = utf8_field("MQTT");
        body.push(5); // protocol level 5 = MQTT 5.0
        body.push(0x02);
        body.extend_from_slice(&keep_alive.to_be_bytes());
        body.push(0x00); // Property Length = 0 (Variable Byte Integer)
        body.extend_from_slice(&utf8_field(client_id));
        frame(CONNECT, 0x00, &body)
    }

    // PUBLISH, QoS 1, retain set: topic "sensors/temp", packet id 7, payload "21.5".
    fn publish_qos1_retain(topic: &str, payload: &[u8]) -> Vec<u8> {
        let mut body = utf8_field(topic);
        body.extend_from_slice(&7u16.to_be_bytes()); // packet identifier (QoS > 0)
        body.extend_from_slice(payload);
        // flags: QoS=1 (bits 2-1), RETAIN=1 (bit 0)
        frame(PUBLISH, 0x03, &body)
    }

    // SUBSCRIBE, MQTT 3.1.1 shape: packet id 9, two (filter, requested QoS) pairs.
    fn subscribe_311(topics: &[(&str, u8)]) -> Vec<u8> {
        let mut body = 9u16.to_be_bytes().to_vec();
        for (topic, qos) in topics {
            body.extend_from_slice(&utf8_field(topic));
            body.push(*qos);
        }
        frame(SUBSCRIBE, 0x02, &body)
    }

    #[test]
    fn connect_311_extracts_client_id_and_keep_alive() {
        let bytes = connect_311("pktflow-test", 60);
        let parsed = parse(&bytes).expect("valid CONNECT");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(
            parsed.fields.get(MESSAGE_TYPE),
            Some(&Value::U64(u64::from(CONNECT)))
        );
        assert_eq!(
            parsed.fields.get(CLIENT_ID),
            Some(&Value::from("pktflow-test"))
        );
        assert_eq!(parsed.fields.get(KEEP_ALIVE), Some(&Value::U64(60)));
        assert_eq!(parsed.hint, Hint::Terminal);
    }

    #[test]
    fn connect_v5_skips_properties_to_reach_client_id() {
        let bytes = connect_v5("pktflow-v5", 30);
        let parsed = parse(&bytes).expect("valid CONNECT v5");
        assert_eq!(
            parsed.fields.get(CLIENT_ID),
            Some(&Value::from("pktflow-v5"))
        );
        assert_eq!(parsed.fields.get(KEEP_ALIVE), Some(&Value::U64(30)));
    }

    #[test]
    fn connack_carries_only_structural_fields() {
        // Session Present = 0, Reason Code = 0 (Success) — 3.1.1 §3.2.
        let bytes = frame(2, 0x00, &[0x00, 0x00]);
        let parsed = parse(&bytes).expect("valid CONNACK");
        assert_eq!(parsed.fields.get(MESSAGE_TYPE), Some(&Value::U64(2)));
        assert_eq!(parsed.fields.get(CLIENT_ID), None);
    }

    #[test]
    fn publish_extracts_topic_qos_and_retain() {
        let bytes = publish_qos1_retain("sensors/temp", b"21.5");
        let parsed = parse(&bytes).expect("valid PUBLISH");
        assert_eq!(parsed.fields.get(TOPIC), Some(&Value::from("sensors/temp")));
        assert_eq!(parsed.fields.get(QOS), Some(&Value::U64(1)));
        assert_eq!(parsed.fields.get(RETAIN), Some(&Value::Bool(true)));
    }

    #[test]
    fn publish_qos3_declines() {
        let mut body = utf8_field("t");
        body.extend_from_slice(b"x");
        let bytes = frame(PUBLISH, 0x06, &body); // bits 2-1 = 11 = QoS 3
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn subscribe_311_extracts_topic_list() {
        let bytes = subscribe_311(&[("a/b", 0), ("c/#", 1)]);
        let parsed = parse(&bytes).expect("valid SUBSCRIBE");
        assert_eq!(
            parsed.fields.get(TOPICS),
            Some(&Value::List(vec![Value::from("a/b"), Value::from("c/#")]))
        );
    }

    #[test]
    fn subscribe_v5_shaped_properties_do_not_desync_header_len() {
        // 3.1.1-shaped walk misreads the leading Property Length byte as part of the
        // first filter's length prefix; header_len must still be exact and correct
        // regardless (see module doc — the ambiguity can only cost the `topics` field).
        let mut body = 9u16.to_be_bytes().to_vec();
        body.push(0x00); // MQTT 5 Property Length = 0
        body.extend_from_slice(&utf8_field("a/b"));
        body.push(0x00);
        let bytes = frame(SUBSCRIBE, 0x02, &body);
        let parsed = parse(&bytes).expect("valid SUBSCRIBE frame");
        assert_eq!(parsed.header_len, bytes.len());
    }

    #[test]
    fn pingreq_has_no_payload() {
        let bytes = frame(12, 0x00, &[]);
        let parsed = parse(&bytes).expect("valid PINGREQ");
        assert_eq!(parsed.header_len, 2);
        assert_eq!(parsed.fields.get(REMAINING_LENGTH), Some(&Value::U64(0)));
    }

    #[test]
    fn remaining_length_one_byte_to_two_byte_boundary() {
        // 127 fits in one Variable Byte Integer byte; 128 needs two (5.0 §1.5.5
        // worked example).
        let at_127 = frame(12, 0x00, &[0xAB; 127]);
        assert_eq!(at_127[1], 0x7F);
        let parsed = parse(&at_127).expect("127-byte remaining length");
        assert_eq!(parsed.header_len, 2 + 127);

        let at_128 = frame(12, 0x00, &[0xAB; 128]);
        assert_eq!(&at_128[1..3], &[0x80, 0x01]);
        let parsed = parse(&at_128).expect("128-byte remaining length");
        assert_eq!(parsed.header_len, 3 + 128);
    }

    #[test]
    fn remaining_length_two_byte_to_three_byte_boundary() {
        let at_16383 = frame(12, 0x00, &vec![0xAB; 16383]);
        assert_eq!(&at_16383[1..3], &[0xFF, 0x7F]);
        let parsed = parse(&at_16383).expect("16383-byte remaining length");
        assert_eq!(parsed.header_len, 3 + 16383);

        let at_16384 = frame(12, 0x00, &vec![0xAB; 16384]);
        assert_eq!(&at_16384[1..4], &[0x80, 0x80, 0x01]);
        let parsed = parse(&at_16384).expect("16384-byte remaining length");
        assert_eq!(parsed.header_len, 4 + 16384);
    }

    #[test]
    fn truncated_header_declines() {
        let bytes = connect_311("pktflow-test", 60);
        assert!(parse(&bytes[..bytes.len() - 1]).is_err());
        assert!(parse(&bytes[..1]).is_err());
    }

    #[test]
    fn incomplete_segment_declines_rather_than_guesses() {
        // remaining_length says 200 bytes follow; only 10 are here (large PUBLISH
        // payload split across TCP segments, D7: no reassembly).
        let mut bytes = vec![(PUBLISH << 4)];
        bytes.extend_from_slice(&encode_variable_byte_int(200));
        bytes.extend_from_slice(&[0u8; 10]);
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn reserved_message_type_zero_declines() {
        assert!(parse(&[0x00, 0x00]).is_err());
    }
}
