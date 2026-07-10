//! EAPOL (11.1, IEEE 802.1X-2020 framing; RFC 3748 EAP, inner method
//! chain out of scope): the 4-byte common header (version, packet type,
//! body length) plus, only for `packet_type == Key`, the fixed-shape
//! EAPOL-Key descriptor (802.1X-2020 §11.9, historically the WPA/WPA2
//! 4-way handshake's wire format). An EAP-Packet's inner EAP method
//! (MD5/TLS/PEAP/...) is a further chain this plugin does not walk — a
//! multi-round-trip state machine, out of v1 scope (D7-adjacent). Per-port
//! link-local signaling, not a two-party conversation: no stream of its
//! own.
//!
//! Cross-domain note: the `packet_type == Key` fields are exactly what
//! 11.2's WPA2/WPA3 handshake entry reads when EAPOL-Key rides over an
//! 802.11 frame instead of Ethernet.

use pktflow_core::{
    ByteReader, Depth, FieldMap, FieldName, Hint, LayerPlugin, ParseCtx, ParseError, ParsedLayer,
    ProtocolName, RouteId, StreamIdentity, Value,
};

const VERSION: FieldName = "version";
const PACKET_TYPE: FieldName = "packet_type";
const BODY_LENGTH: FieldName = "body_length";
const KEY_DESCRIPTOR_TYPE: FieldName = "key_descriptor_type";
const KEY_INFO: FieldName = "key_info";
const KEY_LENGTH: FieldName = "key_length";
const REPLAY_COUNTER: FieldName = "replay_counter";
const NONCE: FieldName = "nonce";
const KEY_IV: FieldName = "key_iv";
const KEY_RSC: FieldName = "key_rsc";
const KEY_MIC: FieldName = "key_mic";
const KEY_DATA_LENGTH: FieldName = "key_data_length";

/// 802.1X-2020 Table 11-5 packet types: 0 EAP-Packet, 1 EAPOL-Start,
/// 2 EAPOL-Logoff, 3 EAPOL-Key, 4 EAPOL-Encapsulated-ASF-Alert, ...
const PACKET_TYPE_KEY: u8 = 3;

/// The EAPOL-Key descriptor's fixed-shape sub-fields (§11.9), present
/// only when `packet_type == Key`.
struct KeyDescriptor<'a> {
    key_descriptor_type: u8,
    key_info: u16,
    key_length: u16,
    replay_counter: u64,
    nonce: &'a [u8],
    key_iv: &'a [u8],
    key_rsc: u64,
    key_mic: &'a [u8],
    key_data_length: u16,
}

/// Reads the fixed 95-byte EAPOL-Key descriptor portion (everything
/// before the variable-length Key Data, which this plugin does not
/// walk): 1 + 2 + 2 + 8 + 32 + 16 + 8 + 8(reserved) + 16 + 2 = 95.
fn read_key_descriptor(body: &[u8]) -> Result<KeyDescriptor<'_>, ParseError> {
    let mut r = ByteReader::new(body);
    let key_descriptor_type = r.u8()?;
    let key_info = r.u16_be()?;
    let key_length = r.u16_be()?;
    let replay_counter = r.u64_be()?;
    let nonce = r.take(32)?;
    let key_iv = r.take(16)?;
    let key_rsc = r.u64_be()?;
    r.take(8)?; // Key ID / reserved — not exposed
    let key_mic = r.take(16)?;
    let key_data_length = r.u16_be()?;
    Ok(KeyDescriptor {
        key_descriptor_type,
        key_info,
        key_length,
        replay_counter,
        nonce,
        key_iv,
        key_rsc,
        key_mic,
        key_data_length,
    })
}

pub struct Eapol;

impl LayerPlugin for Eapol {
    fn name(&self) -> ProtocolName {
        "eapol"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let version = r.u8()?;
        let packet_type = r.u8()?;
        let body_length = r.u16_be()?;
        let body = r.take(usize::from(body_length))?;

        let key = if packet_type == PACKET_TYPE_KEY {
            Some(read_key_descriptor(body)?)
        } else {
            None
        };

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Structural {
            fields.insert(VERSION, Value::U64(u64::from(version)));
            fields.insert(PACKET_TYPE, Value::U64(u64::from(packet_type)));
            fields.insert(BODY_LENGTH, Value::U64(u64::from(body_length)));
        }
        if ctx.depth() >= Depth::Full {
            if let Some(k) = &key {
                fields.insert(
                    KEY_DESCRIPTOR_TYPE,
                    Value::U64(u64::from(k.key_descriptor_type)),
                );
                fields.insert(KEY_INFO, Value::U64(u64::from(k.key_info)));
                fields.insert(KEY_LENGTH, Value::U64(u64::from(k.key_length)));
                fields.insert(REPLAY_COUNTER, Value::U64(k.replay_counter));
                fields.insert(NONCE, Value::from(k.nonce));
                fields.insert(KEY_IV, Value::from(k.key_iv));
                fields.insert(KEY_RSC, Value::U64(k.key_rsc));
                fields.insert(KEY_MIC, Value::from(k.key_mic));
                fields.insert(KEY_DATA_LENGTH, Value::U64(u64::from(k.key_data_length)));
            }
        }

        Ok(ParsedLayer {
            header_len: 4 + usize::from(body_length),
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::EtherType(0x888E)]
    }

    fn stream_identity(&self) -> Option<&StreamIdentity> {
        None
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

    /// EAPOL-Start: no body.
    fn start_frame() -> Vec<u8> {
        vec![0x01, 0x01, 0x00, 0x00]
    }

    /// A structurally-real-shaped EAPOL-Key frame (802.1X-2020 §11.9),
    /// key descriptor type 2 (IEEE 802.11/RSN), no trailing Key Data.
    fn key_frame() -> Vec<u8> {
        let mut body = Vec::new();
        body.push(0x02); // key_descriptor_type: RSN
        body.extend_from_slice(&0x008Au16.to_be_bytes()); // key_info bitmask
        body.extend_from_slice(&16u16.to_be_bytes()); // key_length
        body.extend_from_slice(&1u64.to_be_bytes()); // replay_counter
        body.extend_from_slice(&[0xAA; 32]); // nonce
        body.extend_from_slice(&[0; 16]); // key_iv
        body.extend_from_slice(&0u64.to_be_bytes()); // key_rsc
        body.extend_from_slice(&[0; 8]); // key id / reserved
        body.extend_from_slice(&[0; 16]); // key_mic (unset on message 1)
        body.extend_from_slice(&0u16.to_be_bytes()); // key_data_length

        let mut b = vec![0x01, 0x03]; // version 1, packet_type Key
        b.extend_from_slice(
            &u16::try_from(body.len())
                .expect("eapol body fits")
                .to_be_bytes(),
        );
        b.extend_from_slice(&body);
        b
    }

    #[test]
    fn parses_the_start_frame_with_no_body() {
        let bytes = start_frame();
        let m = meta(bytes.len());
        let parsed = Eapol
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid EAPOL-Start");
        assert_eq!(parsed.header_len, 4);
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(PACKET_TYPE), Some(&Value::U64(1)));
        assert_eq!(parsed.fields.get(KEY_INFO), None, "not a Key packet");
    }

    /// Every named 802.1X-2020 Table 11-5 packet type except Key (its
    /// own dedicated fixture below): 0 EAP-Packet, 1 EAPOL-Start,
    /// 2 EAPOL-Logoff, 4 EAPOL-Encapsulated-ASF-Alert. All behave
    /// identically in v1 (no Full-only fields, raw body consumed as
    /// opaque) — only `packet_type == Key` branches, so this proves the
    /// non-Key path is honored uniformly across the whole named set, not
    /// just the one Start sample above.
    #[test]
    fn every_non_key_packet_type_parses_uniformly() {
        for (packet_type, body) in [
            (0u8, &b"\x02\x01\x00\x04"[..]), // EAP-Packet: inner EAP not walked
            (1, &b""[..]),                   // EAPOL-Start
            (2, &b""[..]),                   // EAPOL-Logoff
            (4, &b"\x00\x00\x00\x00"[..]),   // EAPOL-Encapsulated-ASF-Alert
        ] {
            let mut bytes = vec![0x01, packet_type];
            bytes.extend_from_slice(&u16::try_from(body.len()).expect("fits").to_be_bytes());
            bytes.extend_from_slice(body);

            let m = meta(bytes.len());
            let parsed = Eapol
                .parse(&bytes, &ctx(Depth::Full, &m))
                .unwrap_or_else(|e| panic!("packet_type {packet_type} declined: {e}"));
            assert_eq!(parsed.header_len, bytes.len());
            assert_eq!(
                parsed.fields.get(PACKET_TYPE),
                Some(&Value::U64(u64::from(packet_type)))
            );
            assert_eq!(parsed.fields.get(KEY_INFO), None);
        }
    }

    #[test]
    fn parses_the_key_frame_fields() {
        let bytes = key_frame();
        let m = meta(bytes.len());
        let parsed = Eapol
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid EAPOL-Key");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.fields.get(PACKET_TYPE), Some(&Value::U64(3)));
        assert_eq!(parsed.fields.get(KEY_DESCRIPTOR_TYPE), Some(&Value::U64(2)));
        assert_eq!(parsed.fields.get(KEY_INFO), Some(&Value::U64(0x008A)));
        assert_eq!(parsed.fields.get(KEY_LENGTH), Some(&Value::U64(16)));
        assert_eq!(parsed.fields.get(REPLAY_COUNTER), Some(&Value::U64(1)));
        assert_eq!(
            parsed.fields.get(NONCE),
            Some(&Value::from(&[0xAA; 32][..]))
        );
        assert_eq!(parsed.fields.get(KEY_DATA_LENGTH), Some(&Value::U64(0)));
    }

    #[test]
    fn structural_depth_omits_key_fields() {
        let bytes = key_frame();
        let m = meta(bytes.len());
        let parsed = Eapol
            .parse(&bytes, &ctx(Depth::Structural, &m))
            .expect("valid EAPOL-Key");
        assert_eq!(parsed.fields.get(PACKET_TYPE), Some(&Value::U64(3)));
        assert_eq!(parsed.fields.get(KEY_INFO), None);
    }

    #[test]
    fn key_packet_type_with_a_body_too_short_for_the_descriptor_declines() {
        let mut bytes = vec![0x01, 0x03];
        bytes.extend_from_slice(&10u16.to_be_bytes()); // far short of the 95-byte descriptor
        bytes.extend_from_slice(&[0; 10]);
        let m = meta(bytes.len());
        assert!(Eapol.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn oversized_body_length_declines_cleanly() {
        let mut bytes = vec![0x01, 0x00]; // EAP-Packet
        bytes.extend_from_slice(&200u16.to_be_bytes()); // claims far more than present
        bytes.extend_from_slice(&[0; 5]);
        let m = meta(bytes.len());
        assert!(Eapol.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn truncated_frames_decline() {
        for bytes in [start_frame(), key_frame()] {
            let m = meta(bytes.len());
            for n in 0..bytes.len() {
                let full_ctx = ctx(Depth::Full, &m);
                assert!(
                    Eapol.parse(&bytes[..n], &full_ctx).is_err(),
                    "prefix of {n}/{} bytes must decline",
                    bytes.len()
                );
            }
        }
    }
}
