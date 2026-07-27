//! HTTP/2 (11.8, RFC 9113) — reached only via `http`'s `ByProtocol`
//! dispatch on the h2c cleartext connection preface (VXLAN's direct-
//! encapsulation pattern, 06.5), so this plugin has no `claims()` of its
//! own (avoiding a route collision with `http` on the same port).
//!
//! **Known, material v1 reachability limitation (11.8).** The overwhelming
//! majority of real HTTP/2 traffic negotiates via TLS ALPN (`"h2"`), never
//! touching cleartext h2c — and `tls` stops at the encryption boundary
//! (D12), so this plugin's frame-level parsing is reachable only on the
//! niche cleartext-h2c deployment path. `tls`'s `alpn` field (11.7) still
//! surfaces "this session negotiated h2" as metadata even when frames stay
//! opaque — the honest ceiling for encrypted HTTP/2 in v1, not a gap here.
//!
//! ## Frame header (RFC 9113 §4.1)
//! `Length(24) | Type(8) | Flags(8) | R(1) + Stream Identifier(31)` — a
//! fixed 9-byte header, then `Length` bytes of frame payload. Per D7 (no
//! reassembly) and this task's "first message only" convention (`bgp`,
//! `sctp`, DNS-over-TCP), only the **first** frame in a segment is parsed;
//! `header_len` covers that whole frame (9 + `Length`), so any further
//! frames bundled into the same TCP segment are left untouched, not walked
//! or even skipped over.
//!
//! ## HPACK boundary (RFC 7541)
//! `HEADERS`/`CONTINUATION` frame bodies are HPACK-compressed with a
//! connection-scoped dynamic table — decoding needs state this contract's
//! stateless plugins don't carry (rule 5). v1 extracts the frame envelope
//! only (`stream_id`, `frame_type`, `flags`, `length`), enough to track
//! stream lifecycle (frame-count mix per `stream_id`) without decoding
//! header contents.
//!
//! ## `SETTINGS` (RFC 9113 §6.5)
//! A sequence of 6-byte `Identifier(16) + Value(32)` pairs filling the
//! frame body; `settings_entries` keeps each pair as raw `Bytes`, not
//! individually decoded — the same bounded-envelope stance `amqp`'s
//! method-frame arguments and `enip`'s `cip_service` take (11.13/11.14).

use pktflow_core::{
    ByteReader, Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx,
    ParseError, ParsedLayer, ProtocolName, RollupKind, RollupSpec, StreamIdentity, Value,
};

const STREAM_ID: FieldName = "stream_id";
const FRAME_TYPE: FieldName = "frame_type";
const FLAGS: FieldName = "flags";
const LENGTH: FieldName = "length";
const SETTINGS_ENTRIES: FieldName = "settings_entries";

/// RFC 9113 §4.1: 9-byte fixed frame header.
const FRAME_HEADER_LEN: usize = 9;
/// RFC 9113 §6.5.1: one SETTINGS parameter is `Identifier(2) + Value(4)`.
const SETTINGS_ENTRY_LEN: usize = 6;

const TYPE_DATA: u8 = 0x0;
const TYPE_HEADERS: u8 = 0x1;
const TYPE_PRIORITY: u8 = 0x2;
const TYPE_RST_STREAM: u8 = 0x3;
const TYPE_SETTINGS: u8 = 0x4;
const TYPE_PUSH_PROMISE: u8 = 0x5;
const TYPE_PING: u8 = 0x6;
const TYPE_GOAWAY: u8 = 0x7;
const TYPE_WINDOW_UPDATE: u8 = 0x8;
const TYPE_CONTINUATION: u8 = 0x9;

/// RFC 9113 §6's registered frame types, Tier 1's recognized set.
fn frame_type_name(ty: u8) -> Option<&'static str> {
    Some(match ty {
        TYPE_DATA => "DATA",
        TYPE_HEADERS => "HEADERS",
        TYPE_PRIORITY => "PRIORITY",
        TYPE_RST_STREAM => "RST_STREAM",
        TYPE_SETTINGS => "SETTINGS",
        TYPE_PUSH_PROMISE => "PUSH_PROMISE",
        TYPE_PING => "PING",
        TYPE_GOAWAY => "GOAWAY",
        TYPE_WINDOW_UPDATE => "WINDOW_UPDATE",
        TYPE_CONTINUATION => "CONTINUATION",
        _ => return None,
    })
}

static KEY: &[KeyField] = &[KeyField {
    a: STREAM_ID,
    b: None, // shared (non-endpoint) qualifier: one stream per HTTP/2 stream id
}];
static ROLLUPS: &[RollupSpec] = &[RollupSpec {
    field: FRAME_TYPE,
    kind: RollupKind::Accumulate,
}];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: ROLLUPS,
};

pub struct Http2;

impl LayerPlugin for Http2 {
    fn name(&self) -> ProtocolName {
        "http2"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let len_hi = r.take(3)?;
        let length =
            (usize::from(len_hi[0]) << 16) | (usize::from(len_hi[1]) << 8) | usize::from(len_hi[2]);
        let ty = r.u8()?;
        let frame_type =
            frame_type_name(ty).ok_or(ParseError::Malformed("unrecognized HTTP/2 frame type"))?;
        let flags = r.u8()?;
        let stream_id_word = r.u32_be()?;
        let stream_id = u64::from(stream_id_word & 0x7FFF_FFFF); // R bit (top bit) is reserved

        let payload = r.take(length)?;
        let header_len = FRAME_HEADER_LEN + length;

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(STREAM_ID, Value::U64(stream_id));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(FRAME_TYPE, Value::from(frame_type));
            fields.insert(FLAGS, Value::U64(u64::from(flags)));
            fields.insert(LENGTH, Value::U64(length as u64));
        }
        if ctx.depth() >= Depth::Full && ty == TYPE_SETTINGS {
            let entries: Vec<Value> = payload
                .chunks_exact(SETTINGS_ENTRY_LEN)
                .map(Value::from)
                .collect();
            fields.insert(SETTINGS_ENTRIES, Value::List(entries));
        }

        Ok(ParsedLayer {
            header_len,
            fields,
            hint: Hint::Terminal,
        })
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

    fn frame(ty: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        let len = payload.len() as u32;
        b.extend_from_slice(&len.to_be_bytes()[1..]); // 24-bit length
        b.push(ty);
        b.push(flags);
        b.extend_from_slice(&stream_id.to_be_bytes());
        b.extend_from_slice(payload);
        b
    }

    #[test]
    fn data_frame_parses_envelope() {
        let bytes = frame(TYPE_DATA, 0x01, 1, b"hello");
        let m = meta(bytes.len());
        let parsed = Http2
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid DATA frame");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(STREAM_ID), Some(&Value::U64(1)));
        assert_eq!(parsed.fields.get(FRAME_TYPE), Some(&Value::from("DATA")));
        assert_eq!(parsed.fields.get(FLAGS), Some(&Value::U64(1)));
        assert_eq!(parsed.fields.get(LENGTH), Some(&Value::U64(5)));
    }

    #[test]
    fn settings_frame_lists_raw_entry_pairs() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&1u16.to_be_bytes()); // SETTINGS_HEADER_TABLE_SIZE
        payload.extend_from_slice(&4096u32.to_be_bytes());
        payload.extend_from_slice(&3u16.to_be_bytes()); // SETTINGS_MAX_CONCURRENT_STREAMS
        payload.extend_from_slice(&100u32.to_be_bytes());
        let bytes = frame(TYPE_SETTINGS, 0, 0, &payload);
        let m = meta(bytes.len());
        let parsed = Http2
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid SETTINGS frame");
        assert_eq!(
            parsed.fields.get(FRAME_TYPE),
            Some(&Value::from("SETTINGS"))
        );
        assert_eq!(
            parsed.fields.get(SETTINGS_ENTRIES),
            Some(&Value::List(vec![
                Value::from(&payload[0..6]),
                Value::from(&payload[6..12]),
            ]))
        );
    }

    #[test]
    fn non_settings_frame_omits_settings_entries() {
        let bytes = frame(TYPE_PING, 0, 0, &[0u8; 8]);
        let m = meta(bytes.len());
        let parsed = Http2
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid PING frame");
        assert_eq!(parsed.fields.get(SETTINGS_ENTRIES), None);
    }

    #[test]
    fn multiple_stream_ids_are_distinguishable() {
        for (ty, name) in [
            (TYPE_HEADERS, "HEADERS"),
            (TYPE_PRIORITY, "PRIORITY"),
            (TYPE_RST_STREAM, "RST_STREAM"),
            (TYPE_PUSH_PROMISE, "PUSH_PROMISE"),
            (TYPE_GOAWAY, "GOAWAY"),
            (TYPE_WINDOW_UPDATE, "WINDOW_UPDATE"),
            (TYPE_CONTINUATION, "CONTINUATION"),
        ] {
            let bytes = frame(ty, 0, 5, &[0u8; 4]);
            let m = meta(bytes.len());
            let parsed = Http2
                .parse(&bytes, &ctx(Depth::Full, &m))
                .unwrap_or_else(|e| panic!("type {ty}: {e}"));
            assert_eq!(parsed.fields.get(FRAME_TYPE), Some(&Value::from(name)));
            assert_eq!(parsed.fields.get(STREAM_ID), Some(&Value::U64(5)));
        }
    }

    #[test]
    fn reserved_bit_is_masked_out_of_stream_id() {
        let mut bytes = frame(TYPE_DATA, 0, 0, &[]);
        // Set the reserved top bit alongside stream id 7.
        bytes[5..9].copy_from_slice(&(0x8000_0007u32).to_be_bytes());
        let m = meta(bytes.len());
        let parsed = Http2
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid frame");
        assert_eq!(parsed.fields.get(STREAM_ID), Some(&Value::U64(7)));
    }

    #[test]
    fn unrecognized_frame_type_declines() {
        let bytes = frame(0xFF, 0, 0, &[]);
        let m = meta(bytes.len());
        assert!(Http2.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn a_bundled_second_frame_is_left_untouched() {
        let first = frame(TYPE_PING, 0, 0, &[0u8; 8]);
        let first_len = first.len();
        let mut bytes = first;
        bytes.extend_from_slice(&frame(TYPE_DATA, 0, 1, b"more"));
        let m = meta(bytes.len());
        let parsed = Http2
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("first frame parses");
        assert_eq!(parsed.header_len, first_len);
        assert_eq!(parsed.fields.get(FRAME_TYPE), Some(&Value::from("PING")));
    }

    #[test]
    fn depth_ladder_gates_stream_id_and_settings() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&1u16.to_be_bytes());
        payload.extend_from_slice(&4096u32.to_be_bytes());
        let bytes = frame(TYPE_SETTINGS, 0, 0, &payload);
        let m = meta(bytes.len());

        let keys = Http2.parse(&bytes, &ctx(Depth::Keys, &m)).expect("valid");
        assert_eq!(keys.fields.get(STREAM_ID), Some(&Value::U64(0)));
        assert_eq!(keys.fields.get(FRAME_TYPE), None);

        let structural = Http2
            .parse(&bytes, &ctx(Depth::Structural, &m))
            .expect("valid");
        assert_eq!(
            structural.fields.get(FRAME_TYPE),
            Some(&Value::from("SETTINGS"))
        );
        assert_eq!(structural.fields.get(SETTINGS_ENTRIES), None);
    }

    #[test]
    fn truncated_frames_decline_at_every_prefix() {
        let bytes = frame(TYPE_HEADERS, 0, 1, b"header-block-fragment");
        let m = meta(bytes.len());
        let full = ctx(Depth::Full, &m);
        for n in 0..bytes.len() {
            assert!(
                Http2.parse(&bytes[..n], &full).is_err(),
                "prefix of {n}/{} bytes must decline",
                bytes.len()
            );
        }
    }
}
