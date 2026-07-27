//! WebSocket (11.8, RFC 6455) — **known, material v1 reachability
//! limitation, stated plainly**: an `Upgrade: websocket` handshake is
//! visible to `http` (captured in its `upgrade` field), but subsequent
//! binary WS-framed packets on that same TCP session still route through
//! TCP's ordinary `Candidates(TcpPort)` path (06.4) back to whichever
//! plugin claims that port (`http`) — there is no session-scoped mechanism
//! in this contract for "this TCP session changed protocol at byte offset
//! N." `http.parse()` then declines (`ParseError`) on binary WS frames it
//! can't read as request/status lines. This is the same class of gap as
//! STARTTLS (11.7): a protocol upgrade mid-session is invisible to
//! per-packet, stateless routing — fixing it needs a session-scoped
//! routing override, a v2 architectural question out of this task's scope.
//! This plugin is specified and fixture-tested at the frame-parsing level
//! regardless (fed WS-frame bytes directly to `parse()`, the same way any
//! plugin's unit tests work, 09.1), and remains reachable in practice
//! wherever WebSocket runs on a port `http`/`https` doesn't already claim.
//!
//! ## Frame format (RFC 6455 §5.2)
//! `FIN(1) RSV1-3(3) Opcode(4) | MASK(1) Payload-len(7) [Extended payload
//! length(16 or 64)] [Masking-key(32) if MASK] | Payload Data`.
//! `header_len` covers only the frame's own control bytes — `2 +
//! extended-length-width + (4 if masked)` — never the payload itself,
//! matching how `http`/`ftp`/`smtp` all stop before their own bodies (D7):
//! the payload is unparsed remainder, not "header we can't read". `parse()`
//! therefore does not require the declared payload to actually be present
//! in the buffer (an oversized `payload_len` on a short capture is a
//! plausibility question for `probe()`, not a framing failure — the same
//! stance `wireguard`'s Transport Data prefix takes on its trailing
//! ciphertext, 11.5).

use pktflow_core::{
    ByteReader, Canonicalize, Confidence, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin,
    ParseCtx, ParseError, ParsedLayer, ProtocolName, RollupKind, RollupSpec, StreamIdentity, Value,
};

const APP: FieldName = "app";
const FIN: FieldName = "fin";
const OPCODE: FieldName = "opcode";
const MASK_BIT: FieldName = "mask_bit";
const PAYLOAD_LEN: FieldName = "payload_len";
const MASKING_KEY: FieldName = "masking_key";

const OPCODE_CONTINUATION: u8 = 0x0;
const OPCODE_TEXT: u8 = 0x1;
const OPCODE_BINARY: u8 = 0x2;
const OPCODE_CLOSE: u8 = 0x8;
const OPCODE_PING: u8 = 0x9;
const OPCODE_PONG: u8 = 0xA;

fn is_defined_opcode(opcode: u8) -> bool {
    matches!(
        opcode,
        OPCODE_CONTINUATION
            | OPCODE_TEXT
            | OPCODE_BINARY
            | OPCODE_CLOSE
            | OPCODE_PING
            | OPCODE_PONG
    )
}

/// Control-frame invariants (RFC 6455 §5.5): "All control frames MUST have
/// a payload length of 125 bytes or less and MUST NOT be fragmented" — so
/// a genuine control frame is always `FIN=1` with a small `payload_len`.
fn is_control_opcode(opcode: u8) -> bool {
    matches!(opcode, OPCODE_CLOSE | OPCODE_PING | OPCODE_PONG)
}

struct FrameHeader {
    fin: bool,
    rsv: u8,
    opcode: u8,
    mask_bit: bool,
    payload_len: u64,
    masking_key: Option<[u8; 4]>,
    /// Bytes actually consumed by the control fields (never the payload).
    consumed: usize,
}

fn read_frame_header(bytes: &[u8]) -> Result<FrameHeader, ParseError> {
    let mut r = ByteReader::new(bytes);
    let byte0 = r.u8()?;
    let fin = byte0 & 0x80 != 0;
    let rsv = (byte0 & 0x70) >> 4;
    let opcode = byte0 & 0x0F;

    let byte1 = r.u8()?;
    let mask_bit = byte1 & 0x80 != 0;
    let len7 = byte1 & 0x7F;
    let payload_len = match len7 {
        126 => u64::from(r.u16_be()?),
        127 => r.u64_be()?,
        n => u64::from(n),
    };
    let masking_key = if mask_bit {
        let key = r.take(4)?;
        Some([key[0], key[1], key[2], key[3]])
    } else {
        None
    };
    let consumed = bytes.len() - r.remaining();

    Ok(FrameHeader {
        fin,
        rsv,
        opcode,
        mask_bit,
        payload_len,
        masking_key,
        consumed,
    })
}

static KEY: &[KeyField] = &[KeyField { a: APP, b: None }];
static ROLLUPS: &[RollupSpec] = &[RollupSpec {
    field: OPCODE,
    kind: RollupKind::Accumulate,
}];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: ROLLUPS,
};

pub struct WebSocket;

impl LayerPlugin for WebSocket {
    fn name(&self) -> ProtocolName {
        "websocket"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let h = read_frame_header(bytes)?;

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(APP, Value::from("websocket"));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(FIN, Value::Bool(h.fin));
            fields.insert(OPCODE, Value::U64(u64::from(h.opcode)));
            fields.insert(MASK_BIT, Value::Bool(h.mask_bit));
            fields.insert(PAYLOAD_LEN, Value::U64(h.payload_len));
        }
        if ctx.depth() >= Depth::Full {
            if let Some(key) = h.masking_key {
                fields.insert(MASKING_KEY, Value::from(&key[..]));
            }
        }

        Ok(ParsedLayer {
            header_len: h.consumed,
            fields,
            hint: Hint::Terminal,
        })
    }

    fn has_probe(&self) -> bool {
        true
    }

    fn probe(&self, bytes: &[u8], _ctx: &ParseCtx) -> Option<Confidence> {
        let h = read_frame_header(bytes).ok()?;
        if h.rsv != 0 {
            return None;
        }
        // A bare Continuation frame (opcode 0) is protocol-invalid as a
        // session's first frame (RFC 6455 §5.4: "it is not legal to send a
        // Continuation frame as the very first frame") and carries no
        // structure beyond RSV/opcode being zero — the weakest possible
        // signal, indistinguishable from arbitrary leading zero bytes in
        // unrelated protocols. `parse()` still accepts it where genuinely
        // reached (mid-fragmentation, fed directly per this plugin's
        // documented reachability limitation); `probe()` just never guesses
        // it from raw bytes.
        if h.opcode == OPCODE_CONTINUATION {
            return None;
        }
        if !is_defined_opcode(h.opcode) {
            return None;
        }
        // Control frames carry a real structural invariant (RFC 6455 §5.5):
        // never fragmented, never more than 125 bytes.
        if is_control_opcode(h.opcode) && (!h.fin || h.payload_len > 125) {
            return None;
        }
        let remaining_after_header = u64::try_from(bytes.len() - h.consumed).ok()?;
        (h.payload_len <= remaining_after_header).then(|| Confidence::new(50))
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

    fn unmasked(fin: bool, opcode: u8, payload_len: usize) -> Vec<u8> {
        let mut b = vec![(if fin { 0x80 } else { 0 }) | opcode];
        if payload_len < 126 {
            b.push(payload_len as u8);
        } else if payload_len <= 0xFFFF {
            b.push(126);
            b.extend_from_slice(&(payload_len as u16).to_be_bytes());
        } else {
            b.push(127);
            b.extend_from_slice(&(payload_len as u64).to_be_bytes());
        }
        b.extend(std::iter::repeat_n(0xABu8, payload_len));
        b
    }

    fn masked(opcode: u8, key: [u8; 4], payload_len: usize) -> Vec<u8> {
        let mut b = vec![0x80 | opcode, 0x80 | (payload_len as u8)];
        b.extend_from_slice(&key);
        b.extend(std::iter::repeat_n(0xCDu8, payload_len));
        b
    }

    #[test]
    fn small_unmasked_text_frame() {
        let bytes = unmasked(true, OPCODE_TEXT, 10);
        let m = meta(bytes.len());
        let parsed = WebSocket
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid frame");
        assert_eq!(parsed.header_len, 2);
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(APP), Some(&Value::from("websocket")));
        assert_eq!(parsed.fields.get(FIN), Some(&Value::Bool(true)));
        assert_eq!(parsed.fields.get(OPCODE), Some(&Value::U64(1)));
        assert_eq!(parsed.fields.get(MASK_BIT), Some(&Value::Bool(false)));
        assert_eq!(parsed.fields.get(PAYLOAD_LEN), Some(&Value::U64(10)));
        assert_eq!(parsed.fields.get(MASKING_KEY), None);
    }

    #[test]
    fn masked_binary_frame_extracts_masking_key() {
        let bytes = masked(OPCODE_BINARY, [0x11, 0x22, 0x33, 0x44], 5);
        let m = meta(bytes.len());
        let parsed = WebSocket
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid frame");
        assert_eq!(parsed.header_len, 6);
        assert_eq!(parsed.fields.get(MASK_BIT), Some(&Value::Bool(true)));
        assert_eq!(
            parsed.fields.get(MASKING_KEY),
            Some(&Value::from(&[0x11, 0x22, 0x33, 0x44][..]))
        );
    }

    #[test]
    fn sixteen_bit_extended_length_boundary() {
        let bytes = unmasked(true, OPCODE_BINARY, 126);
        let m = meta(bytes.len());
        let parsed = WebSocket
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid frame");
        assert_eq!(parsed.header_len, 4);
        assert_eq!(parsed.fields.get(PAYLOAD_LEN), Some(&Value::U64(126)));
    }

    #[test]
    fn sixty_four_bit_extended_length_boundary() {
        let bytes = unmasked(true, OPCODE_BINARY, 70000);
        let m = meta(bytes.len());
        let parsed = WebSocket
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid frame");
        assert_eq!(parsed.header_len, 10);
        assert_eq!(parsed.fields.get(PAYLOAD_LEN), Some(&Value::U64(70000)));
    }

    #[test]
    fn control_opcodes_parse() {
        for (opcode, name) in [
            (OPCODE_CLOSE, "close"),
            (OPCODE_PING, "ping"),
            (OPCODE_PONG, "pong"),
        ] {
            let bytes = unmasked(true, opcode, 0);
            let m = meta(bytes.len());
            let parsed = WebSocket
                .parse(&bytes, &ctx(Depth::Full, &m))
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(
                parsed.fields.get(OPCODE),
                Some(&Value::U64(u64::from(opcode)))
            );
        }
    }

    #[test]
    fn header_len_excludes_payload() {
        let bytes = unmasked(false, OPCODE_CONTINUATION, 1000);
        let m = meta(bytes.len());
        let parsed = WebSocket
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid frame");
        assert_eq!(parsed.header_len, 4); // 2 base + 2 for the 16-bit extended length
        assert!(parsed.header_len < bytes.len());
    }

    #[test]
    fn declared_payload_longer_than_buffer_still_parses_the_header() {
        // header_len never covers the payload (module doc), so a truncated
        // capture with a large declared payload_len still parses cleanly —
        // the plausibility question belongs to probe(), not parse().
        let mut bytes = vec![0x82, 126]; // FIN|binary, 16-bit extended length
        bytes.extend_from_slice(&60000u16.to_be_bytes());
        let m = meta(bytes.len());
        let parsed = WebSocket
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("header alone still parses");
        assert_eq!(parsed.header_len, 4);
        assert_eq!(parsed.fields.get(PAYLOAD_LEN), Some(&Value::U64(60000)));
    }

    #[test]
    fn depth_ladder_gates_opcode_and_masking_key() {
        let bytes = masked(OPCODE_TEXT, [1, 2, 3, 4], 3);
        let m = meta(bytes.len());
        let keys = WebSocket
            .parse(&bytes, &ctx(Depth::Keys, &m))
            .expect("valid");
        assert_eq!(keys.fields.get(APP), Some(&Value::from("websocket")));
        assert_eq!(keys.fields.get(OPCODE), None);

        let structural = WebSocket
            .parse(&bytes, &ctx(Depth::Structural, &m))
            .expect("valid");
        assert_eq!(structural.fields.get(OPCODE), Some(&Value::U64(1)));
        assert_eq!(structural.fields.get(MASKING_KEY), None);
    }

    #[test]
    fn truncated_control_bytes_decline() {
        let bytes = masked(OPCODE_TEXT, [1, 2, 3, 4], 3);
        let m = meta(bytes.len());
        let full = ctx(Depth::Full, &m);
        // Only the first 6 bytes are control fields; a prefix short of
        // that must decline (the payload past it is not required).
        for n in 0..6 {
            assert!(
                WebSocket.parse(&bytes[..n], &full).is_err(),
                "prefix of {n}/6 control bytes must decline"
            );
        }
    }

    #[test]
    fn probe_scores_defined_opcode_with_zero_rsv_and_consistent_length() {
        let m = meta(64);
        let c = ctx(Depth::Full, &m);
        let text = unmasked(true, OPCODE_TEXT, 5);
        assert_eq!(WebSocket.probe(&text, &c).map(|c| c.get()), Some(50));
    }

    #[test]
    fn probe_declines_nonzero_rsv_and_undefined_opcode() {
        let m = meta(64);
        let c = ctx(Depth::Full, &m);
        let mut rsv_set = unmasked(true, OPCODE_TEXT, 5);
        rsv_set[0] |= 0x40; // RSV1 set
        assert_eq!(WebSocket.probe(&rsv_set, &c), None);

        let undefined_opcode = unmasked(true, 0x3, 5); // opcode 0x3 is reserved
        assert_eq!(WebSocket.probe(&undefined_opcode, &c), None);
    }

    /// A bare Continuation frame (opcode 0) is the weakest possible
    /// signal — indistinguishable from arbitrary leading zero bytes in an
    /// unrelated protocol (the mpls pseudowire-control-word false-positive
    /// this test guards against) — so `probe()` never scores it, even
    /// though `parse()` still accepts it where genuinely reached.
    #[test]
    fn probe_declines_bare_continuation_opcode() {
        let m = meta(64);
        let c = ctx(Depth::Full, &m);
        let bytes = unmasked(false, OPCODE_CONTINUATION, 0);
        assert_eq!(WebSocket.probe(&bytes, &c), None);
        assert!(
            WebSocket.parse(&bytes, &c).is_ok(),
            "parse() still accepts it"
        );
    }

    #[test]
    fn probe_declines_fragmented_or_oversized_control_frames() {
        let m = meta(256);
        let c = ctx(Depth::Full, &m);
        // FIN=0 on a control opcode: RFC 6455 §5.5 forbids fragmentation.
        let fragmented_ping = unmasked(false, OPCODE_PING, 4);
        assert_eq!(WebSocket.probe(&fragmented_ping, &c), None);

        // Over the 125-byte control-frame payload ceiling.
        let oversized_pong = unmasked(true, OPCODE_PONG, 200);
        assert_eq!(WebSocket.probe(&oversized_pong, &c), None);

        // A well-formed control frame still scores.
        let ok_ping = unmasked(true, OPCODE_PING, 4);
        assert_eq!(WebSocket.probe(&ok_ping, &c).map(|c| c.get()), Some(50));
    }

    #[test]
    fn probe_declines_inconsistent_extended_length() {
        // Declares far more payload than the buffer actually holds.
        let mut bytes = vec![0x82, 127];
        bytes.extend_from_slice(&(u64::MAX / 2).to_be_bytes());
        let m = meta(bytes.len());
        let c = ctx(Depth::Full, &m);
        assert_eq!(WebSocket.probe(&bytes, &c), None);
    }
}
