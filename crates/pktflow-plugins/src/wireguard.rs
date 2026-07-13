//! WireGuard (11.5 — *no RFC*; canonical references are the WireGuard
//! whitepaper, Jason A. Donenfeld, *"WireGuard: Next Generation Kernel
//! Network Tunnel"*, NDSS 2017 (wireguard.com/papers), §5 for the
//! handshake/transport protocol design, and the exact wire-format struct
//! layouts published at wireguard.com/protocol/ ("Messages" section),
//! which every interoperable implementation (wireguard-go, wireguard-rs,
//! the Linux kernel module) and Wireshark's own dissector are built from.
//! D14 note: this is the "closest authoritative document" case, not an
//! omission — WireGuard deliberately has no IETF RFC.
//!
//! All four message types share one leading shape: a 1-byte `message_type`
//! (1=handshake initiation, 2=handshake response, 3=cookie reply,
//! 4=transport data) followed by 3 reserved bytes that must read zero,
//! encoded together as one little-endian `u32` (wireguard.com/protocol/
//! states all fields are little-endian, matching every implementation).
//! Past that, each type's layout is fixed by protocol design:
//!
//! - Handshake Initiation (148 bytes total): sender_index, then a Noise
//!   `IK` handshake payload (unencrypted ephemeral key, encrypted static
//!   key, encrypted timestamp) and two MACs — none of it a separable
//!   "header" over "payload", so the whole fixed-size message is consumed.
//! - Handshake Response (92 bytes total): sender_index, receiver_index,
//!   the responder's ephemeral key, an empty AEAD-encrypted payload, two
//!   MACs — same all-or-nothing shape.
//! - Cookie Reply (64 bytes total): receiver_index, a nonce, and an
//!   encrypted cookie — a DoS-mitigation message (whitepaper §5.3), not
//!   session traffic; also all-or-nothing.
//! - Transport Data (16-byte fixed prefix + variable ciphertext):
//!   receiver_index and a 64-bit counter precede an arbitrary-length
//!   AEAD-encrypted payload (in real traffic, minimum 16 bytes — a
//!   Poly1305 tag with no plaintext, e.g. a keepalive). This is the one
//!   type with a genuine header/payload split, and D12 draws the same
//!   line ESP does (11.5): `header_len` covers only the fixed prefix, the
//!   ciphertext is never counted as header no matter how long it runs —
//!   nor is its presence validated in `parse()` at all: like ESP, this
//!   plugin certifies only the cleartext prefix it can read, and the
//!   09.1 kit's self-containment rule requires that `header_len` bytes
//!   alone still parse. The tag-floor plausibility check lives in
//!   `probe()` instead, where a heuristic belongs.
//!
//! App-stream pattern (06.6/11.12): the handshake's `sender_index`/
//! `receiver_index` are per-session, ephemeral identifiers — not stable
//! endpoint identity worth keying a stream on (the domain spec is explicit
//! about this) — so, like `dns`/`mdns`, the key is one shared constant
//! field (`app = "wireguard"`), one child stream per UDP stream, home for
//! the `msg_type` handshake-lifecycle-mix rollup.

use pktflow_core::{
    ByteReader, Canonicalize, Confidence, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin,
    ParseCtx, ParseError, ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId,
    StreamIdentity, Value,
};

const APP: FieldName = "app";
const MSG_TYPE: FieldName = "msg_type";
const SENDER_INDEX: FieldName = "sender_index";
const RECEIVER_INDEX: FieldName = "receiver_index";

const TYPE_HANDSHAKE_INITIATION: u8 = 1;
const TYPE_HANDSHAKE_RESPONSE: u8 = 2;
const TYPE_COOKIE_REPLY: u8 = 3;
const TYPE_TRANSPORT_DATA: u8 = 4;

/// Fixed total message sizes (wireguard.com/protocol/), each an
/// all-or-nothing Noise/AEAD message with no separable header.
const HANDSHAKE_INITIATION_LEN: usize = 148;
const HANDSHAKE_RESPONSE_LEN: usize = 92;
const COOKIE_REPLY_LEN: usize = 64;

/// Transport Data's genuinely fixed prefix: message_type+reserved (4) +
/// receiver_index (4) + counter (8). Everything past this is the
/// AEAD-encrypted payload — arbitrary length, the ESP precedent (D12).
const TRANSPORT_DATA_HEADER_LEN: usize = 16;
/// Floor for a *valid* Transport Data message: the fixed prefix plus a
/// Poly1305 tag with zero plaintext (a keepalive is exactly this size).
const TRANSPORT_DATA_MIN_LEN: usize = TRANSPORT_DATA_HEADER_LEN + 16;

static KEY: &[KeyField] = &[KeyField { a: APP, b: None }];
static ROLLUPS: &[RollupSpec] = &[RollupSpec {
    field: MSG_TYPE,
    kind: RollupKind::Accumulate, // handshake-lifecycle mix observed on the stream
}];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: ROLLUPS,
};

pub struct Wireguard;

impl LayerPlugin for Wireguard {
    fn name(&self) -> ProtocolName {
        "wireguard"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let type_and_reserved = r.u32_le()?;
        let msg_type = (type_and_reserved & 0xFF) as u8;
        let reserved = type_and_reserved >> 8;
        if reserved != 0 {
            return Err(ParseError::Malformed(
                "wireguard reserved bytes are not zero",
            ));
        }

        let (msg_type_str, header_len, sender_index, receiver_index) = match msg_type {
            TYPE_HANDSHAKE_INITIATION => {
                let sender = r.u32_le()?;
                // Ephemeral(32) + encrypted static(48) + encrypted
                // timestamp(28) + mac1(16) + mac2(16): consumed to prove
                // the full fixed-size message is present, never decoded.
                r.take(HANDSHAKE_INITIATION_LEN - 8)?;
                (
                    "handshake_initiation",
                    HANDSHAKE_INITIATION_LEN,
                    Some(sender),
                    None,
                )
            }
            TYPE_HANDSHAKE_RESPONSE => {
                let sender = r.u32_le()?;
                let receiver = r.u32_le()?;
                // Ephemeral(32) + encrypted-nothing(16) + mac1(16) + mac2(16).
                r.take(HANDSHAKE_RESPONSE_LEN - 12)?;
                (
                    "handshake_response",
                    HANDSHAKE_RESPONSE_LEN,
                    Some(sender),
                    Some(receiver),
                )
            }
            TYPE_COOKIE_REPLY => {
                let receiver = r.u32_le()?;
                // Nonce(24) + encrypted cookie(32).
                r.take(COOKIE_REPLY_LEN - 8)?;
                ("cookie_reply", COOKIE_REPLY_LEN, None, Some(receiver))
            }
            // No minimum-ciphertext check here, deliberately: like ESP
            // (D12, 11.5), `parse()` only certifies the cleartext prefix
            // it can actually read — whether the AEAD payload trailing it
            // is a real, tag-bearing ciphertext is not something a header
            // parser can verify, and the 09.1 kit's self-containment rule
            // requires that exactly `header_len` bytes alone still parse.
            // The Poly1305-tag floor is a *plausibility* signal, applied
            // in `probe` only, where it belongs.
            TYPE_TRANSPORT_DATA => {
                let receiver = r.u32_le()?;
                r.take(8)?; // 64-bit counter: framing-only, not a field (D7)
                (
                    "transport_data",
                    TRANSPORT_DATA_HEADER_LEN,
                    None,
                    Some(receiver),
                )
            }
            _ => return Err(ParseError::Malformed("unknown wireguard message type")),
        };

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(APP, Value::from("wireguard"));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(MSG_TYPE, Value::from(msg_type_str));
        }
        if ctx.depth() >= Depth::Full {
            if let Some(s) = sender_index {
                fields.insert(SENDER_INDEX, Value::U64(u64::from(s)));
            }
            if let Some(rcv) = receiver_index {
                fields.insert(RECEIVER_INDEX, Value::U64(u64::from(rcv)));
            }
        }

        Ok(ParsedLayer {
            header_len,
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        // 51820 is WireGuard's *conventional* default (wireguard.com/quickstart),
        // not an IANA-assigned port (D14 claim-honesty note, domain spec).
        // Real deployments commonly run on arbitrary ports — `probe` below
        // covers those, admitted to the fallback pool honestly rather than
        // only ever working on the default.
        &[RouteId::UdpPort(51820)]
    }

    fn has_probe(&self) -> bool {
        true
    }

    fn probe(&self, bytes: &[u8], _ctx: &ParseCtx) -> Option<Confidence> {
        let mut r = ByteReader::new(bytes);
        let type_and_reserved = r.u32_le().ok()?;
        let msg_type = (type_and_reserved & 0xFF) as u8;
        let reserved = type_and_reserved >> 8;
        if reserved != 0 {
            return None;
        }
        // Handshake/cookie messages are fixed-size — an exact length match
        // is a strong structural signal; Transport Data is the one
        // variable-length type, so only the Poly1305-tag floor applies.
        let plausible = match msg_type {
            TYPE_HANDSHAKE_INITIATION => bytes.len() == HANDSHAKE_INITIATION_LEN,
            TYPE_HANDSHAKE_RESPONSE => bytes.len() == HANDSHAKE_RESPONSE_LEN,
            TYPE_COOKIE_REPLY => bytes.len() == COOKIE_REPLY_LEN,
            TYPE_TRANSPORT_DATA => bytes.len() >= TRANSPORT_DATA_MIN_LEN,
            _ => false,
        };
        plausible.then(|| Confidence::new(50))
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

    fn handshake_initiation(sender_index: u32) -> Vec<u8> {
        let mut m = Vec::with_capacity(HANDSHAKE_INITIATION_LEN);
        m.extend_from_slice(&1u32.to_le_bytes()); // type=1, reserved=0
        m.extend_from_slice(&sender_index.to_le_bytes());
        m.extend(std::iter::repeat_n(0xABu8, HANDSHAKE_INITIATION_LEN - 8));
        m
    }

    fn handshake_response(sender_index: u32, receiver_index: u32) -> Vec<u8> {
        let mut m = Vec::with_capacity(HANDSHAKE_RESPONSE_LEN);
        m.extend_from_slice(&2u32.to_le_bytes());
        m.extend_from_slice(&sender_index.to_le_bytes());
        m.extend_from_slice(&receiver_index.to_le_bytes());
        m.extend(std::iter::repeat_n(0xCDu8, HANDSHAKE_RESPONSE_LEN - 12));
        m
    }

    fn cookie_reply(receiver_index: u32) -> Vec<u8> {
        let mut m = Vec::with_capacity(COOKIE_REPLY_LEN);
        m.extend_from_slice(&3u32.to_le_bytes());
        m.extend_from_slice(&receiver_index.to_le_bytes());
        m.extend(std::iter::repeat_n(0xEFu8, COOKIE_REPLY_LEN - 8));
        m
    }

    fn transport_data(receiver_index: u32, counter: u64, encrypted_len: usize) -> Vec<u8> {
        let mut m = Vec::with_capacity(TRANSPORT_DATA_HEADER_LEN + encrypted_len);
        m.extend_from_slice(&4u32.to_le_bytes());
        m.extend_from_slice(&receiver_index.to_le_bytes());
        m.extend_from_slice(&counter.to_le_bytes());
        m.extend(std::iter::repeat_n(0x11u8, encrypted_len));
        m
    }

    #[test]
    fn handshake_initiation_extracts_sender_index_only() {
        let bytes = handshake_initiation(0xDEAD_BEEF);
        let m = meta(bytes.len());
        let parsed = Wireguard
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid handshake initiation");
        assert_eq!(parsed.header_len, HANDSHAKE_INITIATION_LEN);
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(APP), Some(&Value::from("wireguard")));
        assert_eq!(
            parsed.fields.get(MSG_TYPE),
            Some(&Value::from("handshake_initiation"))
        );
        assert_eq!(
            parsed.fields.get(SENDER_INDEX),
            Some(&Value::U64(0xDEAD_BEEF))
        );
        assert_eq!(parsed.fields.get(RECEIVER_INDEX), None);
    }

    #[test]
    fn handshake_response_extracts_both_indices() {
        let bytes = handshake_response(0x1111_2222, 0xDEAD_BEEF);
        let m = meta(bytes.len());
        let parsed = Wireguard
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid handshake response");
        assert_eq!(parsed.header_len, HANDSHAKE_RESPONSE_LEN);
        assert_eq!(
            parsed.fields.get(MSG_TYPE),
            Some(&Value::from("handshake_response"))
        );
        assert_eq!(
            parsed.fields.get(SENDER_INDEX),
            Some(&Value::U64(0x1111_2222))
        );
        assert_eq!(
            parsed.fields.get(RECEIVER_INDEX),
            Some(&Value::U64(0xDEAD_BEEF))
        );
    }

    #[test]
    fn cookie_reply_extracts_receiver_index_only() {
        let bytes = cookie_reply(0xCAFE_F00D);
        let m = meta(bytes.len());
        let parsed = Wireguard
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid cookie reply");
        assert_eq!(parsed.header_len, COOKIE_REPLY_LEN);
        assert_eq!(
            parsed.fields.get(MSG_TYPE),
            Some(&Value::from("cookie_reply"))
        );
        assert_eq!(parsed.fields.get(SENDER_INDEX), None);
        assert_eq!(
            parsed.fields.get(RECEIVER_INDEX),
            Some(&Value::U64(0xCAFE_F00D))
        );
    }

    #[test]
    fn transport_data_header_stops_before_ciphertext() {
        // A keepalive: zero plaintext, the bare 16-byte Poly1305 tag.
        let bytes = transport_data(0x4242_4242, 7, 16);
        let m = meta(bytes.len());
        let parsed = Wireguard
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid transport data");
        assert_eq!(parsed.header_len, TRANSPORT_DATA_HEADER_LEN);
        assert_eq!(
            parsed.fields.get(MSG_TYPE),
            Some(&Value::from("transport_data"))
        );
        assert_eq!(
            parsed.fields.get(RECEIVER_INDEX),
            Some(&Value::U64(0x4242_4242))
        );

        // A large real-world packet's ciphertext must never be counted.
        let large = transport_data(0x4242_4242, 8, 1400);
        let parsed_large = Wireguard
            .parse(&large, &ctx(Depth::Full, &m))
            .expect("valid transport data");
        assert_eq!(parsed_large.header_len, TRANSPORT_DATA_HEADER_LEN);
    }

    #[test]
    fn transport_data_below_tag_floor_still_parses_the_header() {
        // The Poly1305-tag floor is a `probe()` plausibility signal only
        // (see the domain spec's probe row); `parse()` never validates it,
        // deliberately, so that feeding exactly `header_len` bytes alone
        // (the 09.1 kit's self-containment rule) always succeeds — the
        // same reasoning as ESP not checking ciphertext length (D12).
        let bytes = transport_data(0x1, 1, 0); // zero trailing ciphertext
        let m = meta(bytes.len());
        let parsed = Wireguard
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("header alone still parses");
        assert_eq!(parsed.header_len, TRANSPORT_DATA_HEADER_LEN);
    }

    #[test]
    fn nonzero_reserved_bytes_decline() {
        let mut bytes = handshake_initiation(1);
        bytes[1] = 0x01; // reserved byte set
        let m = meta(bytes.len());
        assert!(Wireguard.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn unknown_message_type_declines() {
        let mut bytes = handshake_initiation(1);
        bytes[0] = 9;
        let m = meta(bytes.len());
        assert!(Wireguard.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn depth_ladder_is_monotonic() {
        let bytes = handshake_response(1, 2);
        let m = meta(bytes.len());
        let keys_only = Wireguard
            .parse(&bytes, &ctx(Depth::Keys, &m))
            .expect("valid");
        assert_eq!(keys_only.fields.get(APP), Some(&Value::from("wireguard")));
        assert_eq!(keys_only.fields.get(MSG_TYPE), None);
        assert_eq!(keys_only.fields.get(SENDER_INDEX), None);

        let structural = Wireguard
            .parse(&bytes, &ctx(Depth::Structural, &m))
            .expect("valid");
        assert_eq!(
            structural.fields.get(MSG_TYPE),
            Some(&Value::from("handshake_response"))
        );
        assert_eq!(structural.fields.get(SENDER_INDEX), None);
    }

    #[test]
    fn truncated_frames_decline_for_every_type() {
        for bytes in [
            handshake_initiation(1),
            handshake_response(1, 2),
            cookie_reply(1),
            transport_data(1, 1, 32),
        ] {
            let m = meta(bytes.len());
            let full = ctx(Depth::Full, &m);
            let header_len = Wireguard.parse(&bytes, &full).expect("valid").header_len;
            for n in 0..header_len {
                assert!(
                    Wireguard.parse(&bytes[..n], &full).is_err(),
                    "prefix of {n}/{header_len} bytes must decline"
                );
            }
        }
    }

    #[test]
    fn probe_scores_exact_fixed_sizes_and_transport_floor() {
        let m = meta(0);
        let ctx = ctx(Depth::Full, &m);

        assert_eq!(
            Wireguard
                .probe(&handshake_initiation(1), &ctx)
                .map(|c| c.get()),
            Some(50)
        );
        assert_eq!(
            Wireguard
                .probe(&handshake_response(1, 2), &ctx)
                .map(|c| c.get()),
            Some(50)
        );
        assert_eq!(
            Wireguard.probe(&cookie_reply(1), &ctx).map(|c| c.get()),
            Some(50)
        );
        assert_eq!(
            Wireguard
                .probe(&transport_data(1, 1, 16), &ctx)
                .map(|c| c.get()),
            Some(50)
        );

        // A handshake initiation one byte short of its fixed size must
        // not probe-match (rule 5 honesty: exact match, not "close enough").
        let mut short_initiation = handshake_initiation(1);
        short_initiation.pop();
        assert_eq!(Wireguard.probe(&short_initiation, &ctx), None);

        // Below the Transport Data tag floor: no probe match either.
        assert_eq!(Wireguard.probe(&transport_data(1, 1, 15), &ctx), None);

        // Noise: random bytes overwhelmingly fail the reserved-bytes check.
        assert_eq!(Wireguard.probe(&[0x42; 40], &ctx), None);
    }

    #[test]
    fn stream_identity_keys_on_shared_app_constant() {
        let identity = Wireguard.stream_identity().expect("declares identity");
        assert_eq!(identity.key.len(), 1);
        assert_eq!(identity.key[0].a, APP);
        assert_eq!(identity.key[0].b, None);
    }
}
