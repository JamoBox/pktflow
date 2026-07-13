//! GTP-U (11.15, 3GPP TS 29.281 — "General Packet Radio System (GPRS)
//! Tunnelling Protocol User Plane (GTPv1-U)"): the mobile-core user-plane
//! tunnel — every subscriber's IP traffic between a mobile-network eNB/gNB
//! and the packet core (and at various points along the core itself, e.g.
//! S1-U, S5/S8, N3) rides inside a GTP-U tunnel identified by a 32-bit
//! Tunnel Endpoint ID (TEID). §5.1's own words: "the TEID shall be used to
//! multiplex different connections on the same IP address" — this is the
//! same GRE/VXLAN "shared-qualifier key, one stream per tunnel id" shape
//! task 06.5 already establishes, not a new pattern.
//!
//! ## Header format (TS 29.281 §5.1, "General format")
//!
//! ```text
//! Octet 1   : Version (bits 8-6) | PT (bit 5) | (*) (bit 4) | E (bit 3) | S (bit 2) | PN (bit 1)
//! Octet 2   : Message Type
//! Octets 3-4: Length (payload length in octets, i.e. everything after
//!             this 8-octet mandatory part; includes the optional
//!             fields/extension headers below when present)
//! Octets 5-8: TEID
//! -- present as one block iff any of E, S or PN is set (§5.1) --
//! Octets 9-10 : Sequence Number
//! Octet 11    : N-PDU Number
//! Octet 12    : Next Extension Header Type
//! ```
//!
//! - **Version/PT** (§5.1): this plugin is GTPv1-U specifically — GTP-U
//!   never grew a "v2" (3GPP kept the user plane on GTPv1-U, TS 29.281,
//!   even after the control plane moved to GTPv2-C, TS 29.274 — see
//!   11.15's domain spec) — so `version` must read `1`. PT distinguishes
//!   GTP (`1`) from GTP' ("GTP-prime", a separate CDR-transfer protocol
//!   that reuses this header shape on its own port, 3GPP TS 32.295); a
//!   `0` here on our UdpPort(2152) claim is a different protocol wearing
//!   the same header, not malformed GTP-U, so it's declined the same
//!   honest way `hsrp` declines an unrecognized version (D12).
//! - **E/S/PN flags** (§5.1): "If and only if one or more of these three
//!   flags are set, the fields Sequence Number, N-PDU Number and
//!   [Next Extension Header Type] shall be present" — one 4-octet block,
//!   present as a unit regardless of *which* of the three bits is set.
//!   Per §5.1's own field descriptions, though, each sub-field is only
//!   *meaningful* when its own bit is set ("Sequence Number... shall be
//!   interpreted only if the S flag is set"); this plugin follows that
//!   distinction — it always consumes the 4-octet block once any bit is
//!   set (wire correctness), but only surfaces `sequence_number` when `S`
//!   itself is set (field-extraction honesty, D12), the same way `gre`
//!   only surfaces `sequence` when GRE's own S bit is set.
//! - **Extension headers** (§5.2.1): chained TLV-ish records — one octet
//!   Length (in 4-octet units, counting the Length octet and the trailing
//!   Next Extension Header Type octet themselves), that many octets of
//!   content, then the Next Extension Header Type octet for the next
//!   record; `0x00` ends the chain. This plugin walks the chain (bounded:
//!   each iteration consumes >= 4 real bytes, so a truncated buffer
//!   surfaces as an ordinary `Truncated` decline, never a spin) purely to
//!   compute `header_len` correctly — it does not decode any extension
//!   header's contents (e.g. the 5G PDU Session Container, TS 38.415);
//!   that is out of this Tier-1 entry's field list, the same bounded-walk
//!   honesty `enip`'s CIP service walk and `gtp_c`'s planned IE walk use
//!   (D12, 11.13).
//!
//! ## Message types (TS 29.281 §6.1, Table 6.1-1)
//!
//! `1` Echo Request, `2` Echo Response, `26` Error Indication, `31`
//! Supported Extension Headers Notification, `254` End Marker, `255`
//! G-PDU (the actual encapsulated subscriber datagram — every other type
//! here is GTP-U tunnel-management signaling, not user data). Note for
//! anyone cross-checking against 11.15's domain spec table: that table's
//! "31 = End Marker" is a transcription slip — Table 6.1-1 assigns `31`
//! to Supported Extension Headers Notification and `254` to End Marker;
//! this plugin (and the domain spec, corrected alongside it) uses the
//! verified 3GPP values.
//!
//! G-PDU's payload is always IP, but the header names no explicit
//! next-protocol field for *which* IP version — `Hint::Unknown` is the
//! contract-correct choice (02.2: "header named nothing usable"), not a
//! plugin declining to be more specific. This costs zero new code in
//! `ipv4`/`ipv6` (06.3): both already carry a `probe()` (version-nibble
//! check) exactly for this heuristic-fallback case, so G-PDU payloads
//! route correctly through the existing fallback pool unmodified — the
//! same zero-new-code claim `vxlan`'s inner-Ethernet dispatch makes for
//! its own encapsulation, proven end-to-end in `tests/telco.rs`. Every
//! other message type is tunnel-management signaling with no encapsulated
//! payload of its own: `Hint::Terminal`.

use pktflow_core::{
    ByteReader, Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx,
    ParseError, ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId, StreamIdentity, Value,
};

const TEID: FieldName = "teid";
const MESSAGE_TYPE: FieldName = "message_type";
const FLAGS: FieldName = "flags";
const LENGTH: FieldName = "length";
const SEQUENCE_NUMBER: FieldName = "sequence_number";

/// §5.1: bits 8-6 of octet 1. GTP-U stayed on version 1 (module doc).
const VERSION_MASK: u8 = 0xE0;
const VERSION_SHIFT: u32 = 5;
const GTP_VERSION_1: u8 = 1;
/// §5.1: bit 5 — Protocol Type; `1` selects GTP over GTP'.
const PT_BIT: u8 = 0x10;
/// §5.1: bit 3 — Extension Header flag.
const E_BIT: u8 = 0x04;
/// §5.1: bit 2 — Sequence Number flag.
const S_BIT: u8 = 0x02;
/// §5.1: bit 1 — N-PDU Number flag.
const PN_BIT: u8 = 0x01;

/// Table 6.1-1: G-PDU — the encapsulated subscriber datagram, the one
/// message type this plugin branches on. Every other type (`1` Echo
/// Request, `2` Echo Response, `26` Error Indication, `31` Supported
/// Extension Headers Notification, `254` End Marker, ...) is
/// tunnel-management signaling captured verbatim in `message_type` with
/// no further branching needed — see the module doc's citation note.
const MSG_GPDU: u8 = 255;

static KEY: &[KeyField] = &[KeyField {
    a: TEID,
    b: None, // shared (non-endpoint) qualifier: one stream per TEID
}];
static ROLLUPS: &[RollupSpec] = &[RollupSpec {
    field: MESSAGE_TYPE,
    kind: RollupKind::Accumulate,
}];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: ROLLUPS,
};

pub struct GtpU;

impl LayerPlugin for GtpU {
    fn name(&self) -> ProtocolName {
        "gtp_u"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let flags_octet = r.u8()?;
        let version = (flags_octet & VERSION_MASK) >> VERSION_SHIFT;
        if version != GTP_VERSION_1 {
            return Err(ParseError::Malformed("GTP-U: unsupported version"));
        }
        if flags_octet & PT_BIT == 0 {
            return Err(ParseError::Malformed("GTP-U: PT bit selects GTP', not GTP"));
        }
        let message_type = r.u8()?;
        let length = r.u16_be()?;
        let teid = r.u32_be()?;

        let mut header_len = 8usize;
        let mut sequence_number = None;
        if flags_octet & (E_BIT | S_BIT | PN_BIT) != 0 {
            let seq = r.u16_be()?;
            let _n_pdu_number = r.u8()?;
            let mut next_ext_type = r.u8()?;
            header_len += 4;
            if flags_octet & S_BIT != 0 {
                sequence_number = Some(seq);
            }

            // §5.2.1: walk the extension header chain purely to keep
            // header_len honest. Each record is at least 4 octets (a
            // zero-length record is malformed, not an infinite loop).
            while next_ext_type != 0 {
                let length_words = r.u8()?;
                if length_words == 0 {
                    return Err(ParseError::Malformed("GTP-U: zero-length extension header"));
                }
                let record_len = usize::from(length_words) * 4;
                let _content = r.take(record_len - 2)?;
                next_ext_type = r.u8()?;
                header_len += record_len;
            }
        }

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(TEID, Value::U64(u64::from(teid)));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(MESSAGE_TYPE, Value::U64(u64::from(message_type)));
            fields.insert(FLAGS, Value::U64(u64::from(flags_octet)));
            fields.insert(LENGTH, Value::U64(u64::from(length)));
        }
        if ctx.depth() >= Depth::Full {
            if let Some(seq) = sequence_number {
                fields.insert(SEQUENCE_NUMBER, Value::U64(u64::from(seq)));
            }
        }

        // G-PDU carries the subscriber's IP packet, version unnamed by
        // this header (module doc) -> Unknown, existing ipv4/ipv6 probes
        // take it from here. Everything else is tunnel signaling with no
        // encapsulated payload.
        let hint = if message_type == MSG_GPDU {
            Hint::Unknown
        } else {
            Hint::Terminal
        };

        Ok(ParsedLayer {
            header_len,
            fields,
            hint,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::UdpPort(2152)]
    }

    // No probe: like gre/vxlan (06.5), this tunnel is explicit-route-only.

    fn stream_identity(&self) -> Option<&StreamIdentity> {
        Some(&IDENTITY)
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use pktflow_core::{LinkType, PacketMeta};

    /// Table 6.1-1: Echo Request — a tunnel-management message type used
    /// throughout these tests wherever the specific type doesn't matter.
    const MSG_ECHO_REQUEST: u8 = 1;

    use super::*;

    fn meta(len: usize) -> PacketMeta {
        PacketMeta {
            timestamp: SystemTime::UNIX_EPOCH,
            caplen: len,
            origlen: len,
            link_type: LinkType::ETHERNET,
        }
    }

    fn ctx<'a>(depth: Depth, m: &'a PacketMeta) -> ParseCtx<'a> {
        ParseCtx::new(&[], depth, m)
    }

    fn parse_at(bytes: &[u8], depth: Depth) -> Result<ParsedLayer, ParseError> {
        let m = meta(bytes.len());
        GtpU.parse(bytes, &ctx(depth, &m))
    }

    fn parse(bytes: &[u8]) -> Result<ParsedLayer, ParseError> {
        parse_at(bytes, Depth::Full)
    }

    /// version=1, PT=1, no E/S/PN, message_type, TEID, and (for G-PDU) a
    /// minimal inner payload so header_len + payload lines up.
    fn mandatory_only(message_type: u8, teid: u32, payload: &[u8]) -> Vec<u8> {
        let mut b = vec![0x30, message_type];
        b.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        b.extend_from_slice(&teid.to_be_bytes());
        b.extend_from_slice(payload);
        b
    }

    /// version=1, PT=1, S flag only set, sequence number `seq`, no
    /// extension headers (next_ext_type = 0).
    fn with_sequence_number(message_type: u8, teid: u32, seq: u16, payload: &[u8]) -> Vec<u8> {
        let mut b = vec![0x32, message_type];
        b.extend_from_slice(&((4 + payload.len()) as u16).to_be_bytes());
        b.extend_from_slice(&teid.to_be_bytes());
        b.extend_from_slice(&seq.to_be_bytes());
        b.push(0); // N-PDU number, not meaningful (PN not set)
        b.push(0); // next extension header type: none
        b.extend_from_slice(payload);
        b
    }

    #[test]
    fn gpdu_mandatory_header_only_hints_unknown_for_fallback_routing() {
        let inner = [0x45u8, 0x00, 0x00, 0x14]; // stand-in inner bytes
        let bytes = mandatory_only(MSG_GPDU, 0xAABBCCDD, &inner);
        let parsed = parse(&bytes).expect("valid GTP-U G-PDU header");
        assert_eq!(parsed.header_len, 8);
        assert_eq!(parsed.hint, Hint::Unknown);
        assert_eq!(parsed.fields.get(TEID), Some(&Value::U64(0xAABBCCDD)));
        assert_eq!(parsed.fields.get(MESSAGE_TYPE), Some(&Value::U64(255)));
        assert_eq!(parsed.fields.get(LENGTH), Some(&Value::U64(4)));
    }

    #[test]
    fn echo_request_response_and_error_indication_are_terminal() {
        // Table 6.1-1: Echo Request (1), Echo Response (2), Error Indication (26).
        for mt in [1u8, 2, 26] {
            let bytes = mandatory_only(mt, 0, &[]);
            let parsed = parse(&bytes).unwrap_or_else(|e| panic!("message type {mt}: {e}"));
            assert_eq!(parsed.hint, Hint::Terminal, "message type {mt}");
            assert_eq!(
                parsed.fields.get(MESSAGE_TYPE),
                Some(&Value::U64(u64::from(mt)))
            );
        }
    }

    #[test]
    fn end_marker_and_supported_ext_hdr_notification_are_terminal() {
        // Table 6.1-1: End Marker (254), Supported Extension Headers
        // Notification (31) — the value this repo's domain spec had
        // transposed with End Marker before this plugin's citation fix
        // (module doc).
        for mt in [254u8, 31] {
            let bytes = mandatory_only(mt, 0, &[]);
            let parsed = parse(&bytes).unwrap_or_else(|e| panic!("message type {mt}: {e}"));
            assert_eq!(parsed.hint, Hint::Terminal, "message type {mt}");
        }
    }

    #[test]
    fn s_flag_surfaces_sequence_number_and_advances_header_len() {
        let bytes = with_sequence_number(MSG_ECHO_REQUEST, 7, 0x1234, &[]);
        let parsed = parse(&bytes).expect("valid GTP-U header with sequence number");
        assert_eq!(parsed.header_len, 12);
        assert_eq!(
            parsed.fields.get(SEQUENCE_NUMBER),
            Some(&Value::U64(0x1234))
        );
    }

    #[test]
    fn no_flags_set_omits_sequence_number() {
        let bytes = mandatory_only(MSG_ECHO_REQUEST, 7, &[]);
        let parsed = parse(&bytes).expect("valid GTP-U header");
        assert_eq!(parsed.fields.get(SEQUENCE_NUMBER), None);
    }

    #[test]
    fn extension_header_chain_is_skipped_and_header_len_accounts_for_it() {
        // flags: version=1, PT=1, E=1 (0x34). One 8-octet extension header
        // (length_words=2 -> 6 content octets), then chain end (0x00),
        // followed by a 4-byte inner payload stand-in.
        let mut b = vec![0x34, MSG_GPDU];
        let inner = [0xDEu8, 0xAD, 0xBE, 0xEF];
        b.extend_from_slice(&((4 + 8 + inner.len()) as u16).to_be_bytes());
        b.extend_from_slice(&99u32.to_be_bytes());
        b.extend_from_slice(&0u16.to_be_bytes()); // sequence number (not meaningful, S unset)
        b.push(0); // N-PDU number
        b.push(0x85); // next extension header type: PDU Session Container (TS 38.415)
        b.push(2); // length: 2 * 4 = 8 octets total for this record
        b.extend_from_slice(&[0u8; 6]); // content: 8 - 1 (length octet) - 1 (next-type octet)
        b.push(0x00); // chain end
        b.extend_from_slice(&inner);

        let parsed = parse(&b).expect("valid GTP-U header with one extension header");
        assert_eq!(parsed.header_len, 8 + 4 + 8);
        assert_eq!(parsed.hint, Hint::Unknown);
        assert_eq!(parsed.fields.get(TEID), Some(&Value::U64(99)));
    }

    #[test]
    fn wrong_version_declines() {
        let mut bytes = mandatory_only(MSG_ECHO_REQUEST, 1, &[]);
        bytes[0] = 0x10; // version 0, PT=1
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn gtp_prime_protocol_type_declines() {
        let mut bytes = mandatory_only(MSG_ECHO_REQUEST, 1, &[]);
        bytes[0] = 0x20; // version 1, PT=0 (GTP')
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn truncated_mandatory_header_declines() {
        let bytes = mandatory_only(MSG_ECHO_REQUEST, 1, &[]);
        assert!(parse(&bytes[..7]).is_err());
    }

    #[test]
    fn truncated_optional_block_declines() {
        let bytes = with_sequence_number(MSG_ECHO_REQUEST, 7, 0x1234, &[]);
        assert!(parse(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn zero_length_extension_header_declines() {
        let mut b = vec![0x34, MSG_ECHO_REQUEST];
        b.extend_from_slice(&5u16.to_be_bytes());
        b.extend_from_slice(&1u32.to_be_bytes());
        b.extend_from_slice(&0u16.to_be_bytes());
        b.push(0);
        b.push(0x85); // next extension header type present
        b.push(0); // malformed: zero-length record
        assert!(parse(&b).is_err());
    }

    #[test]
    fn keys_depth_has_only_teid() {
        let bytes = mandatory_only(MSG_ECHO_REQUEST, 42, &[]);
        let parsed = parse_at(&bytes, Depth::Keys).expect("valid header");
        assert_eq!(parsed.fields.len(), 1);
        assert_eq!(parsed.fields.get(TEID), Some(&Value::U64(42)));
    }

    #[test]
    fn structural_depth_omits_sequence_number() {
        let bytes = with_sequence_number(MSG_ECHO_REQUEST, 7, 0x1234, &[]);
        let parsed = parse_at(&bytes, Depth::Structural).expect("valid header");
        assert_eq!(parsed.fields.get(SEQUENCE_NUMBER), None);
        assert_eq!(parsed.fields.get(MESSAGE_TYPE), Some(&Value::U64(1)));
    }
}
