//! GTP-C (11.15) — one plugin covering both wire versions sharing
//! `UdpPort(2123)`: GTPv1-C (3GPP TS 29.060, the mobile-core control plane
//! signaling companion to `gtp_u`'s user plane) and GTPv2-C (3GPP TS
//! 29.274, its successor). They can't both claim the port (route
//! collision, 03.2), and the `version` field in the shared top-3-bits
//! position of the first octet disambiguates cleanly — the same `ospf`/
//! `stun` precedent (11.4/11.8) for "one plugin, version field picks the
//! wire format".
//!
//! ## GTPv1-C header (TS 29.060 §7.2/§7.3)
//!
//! Same shape as `gtp_u`'s header: `Flags(1) | MessageType(1) | Length(2) |
//! TEID(4)` (8 octets mandatory), then an optional 4-octet
//! `SequenceNumber/N-PDU Number/Next-Extension-Header-Type` block when any
//! of the Flags byte's E/S/PN bits are set, exactly like `gtp_u`. `Length`
//! is the byte count *after* the mandatory 8-octet part (optional block +
//! information elements).
//!
//! ## GTPv2-C header (TS 29.274 §5.1)
//!
//! `Flags(1) | MessageType(1) | Length(2)` (4 octets), then — if the
//! Flags byte's `T` bit is set — `TEID(4) | SequenceNumber(3) | Spare(1)`,
//! or — if `T` is clear (Echo / Version-Not-Supported only) —
//! `SequenceNumber(3) | Spare(1)` with no TEID at all (`teid` reports `0`
//! per the domain spec, "before one is assigned"). `Length` here excludes
//! only the first four octets (Flags/MessageType/Length itself).
//!
//! ## Information-element walk honesty (D12)
//!
//! v1 and v2 use genuinely different IE encodings, not just different
//! message numbers:
//!
//! - **v2 (TLIV)**: every IE is `Type(1) + Length(2) + Instance(1) +
//!   Value(Length)` — fully self-describing, so this plugin walks the
//!   *entire* IE list safely; any unrecognized type is skipped via its own
//!   `Length` field with no risk of misalignment.
//! - **v1 (TV/TLV mix)**: IE types `< 128` are `TV` — a fixed-length value
//!   whose length is *not* carried in the IE itself but looked up from the
//!   IE's type in TS 29.060's IE table. This plugin knows exactly one such
//!   type, `IMSI` (type 2, 8 octets) — the field this domain names. Any
//!   *other* `TV`-shaped IE encountered has a length this plugin cannot
//!   determine without the full IE table, so the walk stops there rather
//!   than guess (D12: decline the remainder of the walk, not the whole
//!   message — `version`/`message_type`/`teid` from the fixed header are
//!   unaffected). IE types `>= 128` are `TLV` (`Type(1) + Length(2) +
//!   Value(Length)`, explicit length) and are walked the same safe way as
//!   v2's TLIV, so a v1 message whose non-IMSI IEs are all TLV-encoded
//!   (the common shape once IMSI itself has been consumed) still reaches
//!   `APN` past any unrecognized TLV IE in between.
//!
//! `apn`'s value is a DNS-style length-prefixed label sequence (TS 23.003
//! §9.1); this plugin joins the labels with `.` and declines (skips) the
//! field, not the message, if the label framing itself doesn't check out.

use pktflow_core::{
    ByteReader, Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx,
    ParseError, ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId, StreamIdentity,
    Truncated, Value,
};

const TEID: FieldName = "teid";
const VERSION: FieldName = "version";
const MESSAGE_TYPE: FieldName = "message_type";
const LENGTH: FieldName = "length";
const IMSI: FieldName = "imsi";
const APN: FieldName = "apn";

const VERSION_MASK: u8 = 0xE0;
const VERSION_SHIFT: u32 = 5;

/// v1 Flags byte (§7.3): E/S/PN presence bits, same positions as `gtp_u`.
const V1_E_BIT: u8 = 0x04;
const V1_S_BIT: u8 = 0x02;
const V1_PN_BIT: u8 = 0x01;

/// v2 Flags byte (§5.1): the TEID-presence bit (bit 4).
const V2_T_BIT: u8 = 0x08;

/// TS 29.060 §7.7.2: IMSI, a `TV` IE — 1 type octet + 8 fixed value octets.
const IE_V1_IMSI: u8 = 2;
/// TS 29.060 §7.7.30: Access Point Name, a `TLV` IE (type >= 128).
const IE_V1_APN: u8 = 131;
/// TS 29.274 Table 8.1-1: IMSI.
const IE_V2_IMSI: u8 = 1;
/// TS 29.274 Table 8.1-1: APN.
const IE_V2_APN: u8 = 71;

static KEY: &[KeyField] = &[KeyField {
    a: TEID,
    b: None, // shared (non-endpoint) qualifier, the gtp_u precedent
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

/// TS 23.003 §9.1's label-length-prefixed APN encoding, joined with `.`.
/// Malformed framing (a length byte running past the value) declines just
/// this field (D12), not the whole message.
fn decode_apn(bytes: &[u8]) -> Option<String> {
    let mut labels = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        let len = usize::from(bytes[i]);
        i += 1;
        if len == 0 || i + len > bytes.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&bytes[i..i + len]).into_owned());
        i += len;
    }
    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}

/// v2's fully self-describing TLIV walk (see module doc).
fn walk_v2_ies(region: &[u8]) -> (Option<Vec<u8>>, Option<String>) {
    let mut r = ByteReader::new(region);
    let mut imsi = None;
    let mut apn = None;
    while let Ok(ty) = r.u8() {
        let Ok(len) = r.u16_be() else { break };
        let Ok(_instance) = r.u8() else { break };
        let Ok(value) = r.take(usize::from(len)) else {
            break;
        };
        match ty {
            IE_V2_IMSI => imsi = Some(value.to_vec()),
            IE_V2_APN => apn = decode_apn(value),
            _ => {}
        }
    }
    (imsi, apn)
}

/// v1's TV/TLV mixed walk (see module doc): stops the walk — not the
/// message — the moment an unrecognized `TV` IE (length not determinable)
/// is encountered.
fn walk_v1_ies(region: &[u8]) -> (Option<Vec<u8>>, Option<String>) {
    let mut r = ByteReader::new(region);
    let mut imsi = None;
    let mut apn = None;
    while let Ok(ty) = r.u8() {
        if ty < 0x80 {
            if ty == IE_V1_IMSI {
                let Ok(value) = r.take(8) else { break };
                imsi = Some(value.to_vec());
            } else {
                // Unrecognized TV IE: this plugin has no IE-length table
                // beyond IMSI, so it cannot safely skip past it (D12).
                break;
            }
        } else {
            let Ok(len) = r.u16_be() else { break };
            let Ok(value) = r.take(usize::from(len)) else {
                break;
            };
            if ty == IE_V1_APN {
                apn = decode_apn(value);
            }
        }
    }
    (imsi, apn)
}

pub struct GtpC;

impl LayerPlugin for GtpC {
    fn name(&self) -> ProtocolName {
        "gtp_c"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let flags = r.u8()?;
        let version = (flags & VERSION_MASK) >> VERSION_SHIFT;
        let message_type = r.u8()?;
        let length = r.u16_be()?;

        let (teid, _fixed_len, total_len, imsi, apn) = match version {
            1 => {
                let teid = r.u32_be()?;
                let mut fixed_len = 8usize;
                if flags & (V1_E_BIT | V1_S_BIT | V1_PN_BIT) != 0 {
                    let _seq = r.u16_be()?;
                    let _n_pdu_number = r.u8()?;
                    let _next_ext_type = r.u8()?;
                    fixed_len += 4;
                }
                let total_len = 8usize
                    .checked_add(usize::from(length))
                    .ok_or(ParseError::Malformed("GTP-C: length overflow"))?;
                if total_len < fixed_len {
                    return Err(ParseError::Malformed(
                        "GTP-C: v1 Length smaller than the mandatory+optional header",
                    ));
                }
                if bytes.len() < total_len {
                    return Err(ParseError::Truncated(Truncated {
                        needed: total_len,
                        have: bytes.len(),
                    }));
                }
                let (imsi, apn) = walk_v1_ies(&bytes[fixed_len..total_len]);
                (teid, fixed_len, total_len, imsi, apn)
            }
            2 => {
                let has_teid = flags & V2_T_BIT != 0;
                let teid = if has_teid { r.u32_be()? } else { 0 };
                let _seq_and_spare = r.take(4)?;
                let fixed_len = if has_teid { 12usize } else { 8usize };
                let total_len = 4usize
                    .checked_add(usize::from(length))
                    .ok_or(ParseError::Malformed("GTP-C: length overflow"))?;
                if total_len < fixed_len {
                    return Err(ParseError::Malformed(
                        "GTP-C: v2 Length smaller than the mandatory header",
                    ));
                }
                if bytes.len() < total_len {
                    return Err(ParseError::Truncated(Truncated {
                        needed: total_len,
                        have: bytes.len(),
                    }));
                }
                let (imsi, apn) = walk_v2_ies(&bytes[fixed_len..total_len]);
                (teid, fixed_len, total_len, imsi, apn)
            }
            _ => return Err(ParseError::Malformed("GTP-C: unsupported version")),
        };

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(TEID, Value::U64(u64::from(teid)));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(VERSION, Value::U64(u64::from(version)));
            fields.insert(MESSAGE_TYPE, Value::U64(u64::from(message_type)));
            fields.insert(LENGTH, Value::U64(u64::from(length)));
        }
        if ctx.depth() >= Depth::Full {
            if let Some(v) = imsi {
                fields.insert(IMSI, Value::from(v.as_slice()));
            }
            if let Some(v) = apn {
                fields.insert(APN, Value::from(v.as_str()));
            }
        }

        Ok(ParsedLayer {
            header_len: total_len,
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::UdpPort(2123)]
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

    const ECHO_REQUEST: u8 = 1;
    const CREATE_PDP_CONTEXT_REQUEST: u8 = 16;
    const CREATE_PDP_CONTEXT_RESPONSE: u8 = 17;
    const CREATE_SESSION_REQUEST: u8 = 32;
    const CREATE_SESSION_RESPONSE: u8 = 33;

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
        GtpC.parse(bytes, &ctx(depth, &m))
    }

    fn parse(bytes: &[u8]) -> Result<ParsedLayer, ParseError> {
        parse_at(bytes, Depth::Full)
    }

    fn tv(ty: u8, value: &[u8]) -> Vec<u8> {
        let mut out = vec![ty];
        out.extend_from_slice(value);
        out
    }

    fn tlv(ty: u8, value: &[u8]) -> Vec<u8> {
        let mut out = vec![ty];
        out.extend_from_slice(&(value.len() as u16).to_be_bytes());
        out.extend_from_slice(value);
        out
    }

    fn tliv(ty: u8, instance: u8, value: &[u8]) -> Vec<u8> {
        let mut out = vec![ty];
        out.extend_from_slice(&(value.len() as u16).to_be_bytes());
        out.push(instance);
        out.extend_from_slice(value);
        out
    }

    fn apn_encoded(labels: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        for label in labels {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out
    }

    /// GTPv1-C Create-PDP-Context Request (TS 29.060 §7.5.1): version 1,
    /// PT=1, no E/S/PN, IMSI then APN ("internet").
    fn v1_create_pdp_context_request(teid: u32) -> Vec<u8> {
        let mut ies = Vec::new();
        ies.extend_from_slice(&tv(
            IE_V1_IMSI,
            &[0x21, 0x43, 0x65, 0x87, 0x09, 0x21, 0x43, 0xF5],
        ));
        ies.extend_from_slice(&tlv(IE_V1_APN, &apn_encoded(&["internet"])));

        let mut b = vec![0x30, CREATE_PDP_CONTEXT_REQUEST];
        b.extend_from_slice(&(ies.len() as u16).to_be_bytes());
        b.extend_from_slice(&teid.to_be_bytes());
        b.extend_from_slice(&ies);
        b
    }

    /// GTPv1-C Create-PDP-Context Response: a Cause `TV` IE this plugin
    /// doesn't recognize beyond IMSI — the walk stops there (D12), so no
    /// `imsi`/`apn` field is reported, but the fixed header still parses.
    fn v1_create_pdp_context_response(teid: u32) -> Vec<u8> {
        let ies = tv(1, &[128]); // Cause = Request Accepted (unrecognized TV type)
        let mut b = vec![0x30, CREATE_PDP_CONTEXT_RESPONSE];
        b.extend_from_slice(&(ies.len() as u16).to_be_bytes());
        b.extend_from_slice(&teid.to_be_bytes());
        b.extend_from_slice(&ies);
        b
    }

    /// GTPv2-C Create-Session Request (TS 29.274 §7.2.1): version 2,
    /// T=1, IMSI then APN.
    fn v2_create_session_request(teid: u32) -> Vec<u8> {
        let mut ies = Vec::new();
        ies.extend_from_slice(&tliv(
            IE_V2_IMSI,
            0,
            &[0x21, 0x43, 0x65, 0x87, 0x09, 0x21, 0x43, 0xF5],
        ));
        ies.extend_from_slice(&tliv(IE_V2_APN, 0, &apn_encoded(&["internet"])));

        let mut b = vec![0x48, CREATE_SESSION_REQUEST]; // version=2, P=0, T=1
        let payload_len = 4 + ies.len(); // TEID(4) + seq/spare(4) + ies, minus... see below
        let _ = payload_len;
        let mut rest = Vec::new();
        rest.extend_from_slice(&teid.to_be_bytes());
        rest.extend_from_slice(&[0x00, 0x00, 0x01, 0x00]); // sequence number(3) + spare(1)
        rest.extend_from_slice(&ies);
        b.extend_from_slice(&(rest.len() as u16).to_be_bytes());
        b.extend_from_slice(&rest);
        b
    }

    /// GTPv2-C Create-Session Response with a vendor-specific IE (type
    /// 200) sitting between IMSI and APN — proves the TLIV walk skips an
    /// unrecognized IE via its own length field without misaligning.
    fn v2_create_session_response_with_unknown_ie(teid: u32) -> Vec<u8> {
        let mut ies = Vec::new();
        ies.extend_from_slice(&tliv(
            IE_V2_IMSI,
            0,
            &[0x21, 0x43, 0x65, 0x87, 0x09, 0x21, 0x43, 0xF5],
        ));
        ies.extend_from_slice(&tliv(200, 0, &[0xDE, 0xAD, 0xBE])); // vendor-specific, unrecognized
        ies.extend_from_slice(&tliv(IE_V2_APN, 0, &apn_encoded(&["ims"])));

        let mut b = vec![0x48, CREATE_SESSION_RESPONSE];
        let mut rest = Vec::new();
        rest.extend_from_slice(&teid.to_be_bytes());
        rest.extend_from_slice(&[0x00, 0x00, 0x02, 0x00]);
        rest.extend_from_slice(&ies);
        b.extend_from_slice(&(rest.len() as u16).to_be_bytes());
        b.extend_from_slice(&rest);
        b
    }

    /// v1 IE-walk honesty companion: an unrecognized *TLV* (type >= 128)
    /// IE sitting between IMSI and APN is safely skippable via its own
    /// length field, unlike the unrecognized-TV case above.
    fn v1_create_pdp_context_request_with_unknown_tlv(teid: u32) -> Vec<u8> {
        let mut ies = Vec::new();
        ies.extend_from_slice(&tv(
            IE_V1_IMSI,
            &[0x21, 0x43, 0x65, 0x87, 0x09, 0x21, 0x43, 0xF5],
        ));
        ies.extend_from_slice(&tlv(200, &[0xAA, 0xBB, 0xCC])); // vendor-specific TLV
        ies.extend_from_slice(&tlv(IE_V1_APN, &apn_encoded(&["ims"])));

        let mut b = vec![0x30, CREATE_PDP_CONTEXT_REQUEST];
        b.extend_from_slice(&(ies.len() as u16).to_be_bytes());
        b.extend_from_slice(&teid.to_be_bytes());
        b.extend_from_slice(&ies);
        b
    }

    fn v2_echo_request() -> Vec<u8> {
        // T=0: no TEID at all, sequence number + spare only.
        vec![0x40, ECHO_REQUEST, 0x00, 0x04, 0x00, 0x00, 0x03, 0x00]
    }

    #[test]
    fn v1_create_pdp_context_request_reports_imsi_and_apn() {
        let bytes = v1_create_pdp_context_request(0xAABBCCDD);
        let parsed = parse(&bytes).expect("valid GTPv1-C Create-PDP-Context Request");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(VERSION), Some(&Value::U64(1)));
        assert_eq!(
            parsed.fields.get(MESSAGE_TYPE),
            Some(&Value::U64(u64::from(CREATE_PDP_CONTEXT_REQUEST)))
        );
        assert_eq!(parsed.fields.get(TEID), Some(&Value::U64(0xAABBCCDD)));
        assert_eq!(
            parsed.fields.get(IMSI),
            Some(&Value::from(
                &[0x21u8, 0x43, 0x65, 0x87, 0x09, 0x21, 0x43, 0xF5][..]
            ))
        );
        assert_eq!(parsed.fields.get(APN), Some(&Value::from("internet")));
    }

    #[test]
    fn v1_response_stops_ie_walk_at_unrecognized_tv() {
        let bytes = v1_create_pdp_context_response(0x11223344);
        let parsed = parse(&bytes).expect("valid GTPv1-C Create-PDP-Context Response");
        assert_eq!(
            parsed.fields.get(MESSAGE_TYPE),
            Some(&Value::U64(u64::from(CREATE_PDP_CONTEXT_RESPONSE)))
        );
        assert_eq!(parsed.fields.get(IMSI), None);
        assert_eq!(parsed.fields.get(APN), None);
    }

    #[test]
    fn v1_unrecognized_tlv_between_imsi_and_apn_is_skipped_cleanly() {
        let bytes = v1_create_pdp_context_request_with_unknown_tlv(7);
        let parsed = parse(&bytes).expect("valid GTPv1-C request with a vendor TLV IE");
        assert_eq!(
            parsed.fields.get(IMSI),
            Some(&Value::from(
                &[0x21u8, 0x43, 0x65, 0x87, 0x09, 0x21, 0x43, 0xF5][..]
            ))
        );
        assert_eq!(parsed.fields.get(APN), Some(&Value::from("ims")));
    }

    #[test]
    fn v2_create_session_request_reports_imsi_and_apn() {
        let bytes = v2_create_session_request(0x0A0B0C0D);
        let parsed = parse(&bytes).expect("valid GTPv2-C Create-Session Request");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.fields.get(VERSION), Some(&Value::U64(2)));
        assert_eq!(
            parsed.fields.get(MESSAGE_TYPE),
            Some(&Value::U64(u64::from(CREATE_SESSION_REQUEST)))
        );
        assert_eq!(parsed.fields.get(TEID), Some(&Value::U64(0x0A0B0C0D)));
        assert_eq!(
            parsed.fields.get(IMSI),
            Some(&Value::from(
                &[0x21u8, 0x43, 0x65, 0x87, 0x09, 0x21, 0x43, 0xF5][..]
            ))
        );
        assert_eq!(parsed.fields.get(APN), Some(&Value::from("internet")));
    }

    #[test]
    fn v2_unrecognized_tliv_between_imsi_and_apn_is_skipped_cleanly() {
        let bytes = v2_create_session_response_with_unknown_ie(0x55);
        let parsed = parse(&bytes).expect("valid GTPv2-C response with a vendor IE");
        assert_eq!(
            parsed.fields.get(IMSI),
            Some(&Value::from(
                &[0x21u8, 0x43, 0x65, 0x87, 0x09, 0x21, 0x43, 0xF5][..]
            ))
        );
        assert_eq!(parsed.fields.get(APN), Some(&Value::from("ims")));
    }

    #[test]
    fn v2_echo_request_without_teid_flag_reports_zero_teid() {
        let bytes = v2_echo_request();
        let parsed = parse(&bytes).expect("valid GTPv2-C Echo Request");
        assert_eq!(parsed.fields.get(TEID), Some(&Value::U64(0)));
        assert_eq!(
            parsed.fields.get(MESSAGE_TYPE),
            Some(&Value::U64(u64::from(ECHO_REQUEST)))
        );
    }

    #[test]
    fn unsupported_version_declines() {
        let mut bytes = v1_create_pdp_context_request(1);
        bytes[0] = 0x70; // version 3
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn truncated_fixed_header_declines() {
        let bytes = v1_create_pdp_context_request(1);
        assert!(parse(&bytes[..7]).is_err());
    }

    #[test]
    fn length_exceeding_available_bytes_declines() {
        let mut bytes = v2_create_session_request(1);
        let claimed_len = u16::from_be_bytes([bytes[2], bytes[3]]) + 50;
        bytes[2..4].copy_from_slice(&claimed_len.to_be_bytes());
        assert!(matches!(parse(&bytes), Err(ParseError::Truncated(_))));
    }

    #[test]
    fn keys_depth_has_only_teid() {
        let bytes = v1_create_pdp_context_request(42);
        let parsed = parse_at(&bytes, Depth::Keys).expect("valid header");
        assert_eq!(parsed.fields.len(), 1);
        assert_eq!(parsed.fields.get(TEID), Some(&Value::U64(42)));
    }

    #[test]
    fn structural_depth_omits_imsi_and_apn() {
        let bytes = v1_create_pdp_context_request(42);
        let parsed = parse_at(&bytes, Depth::Structural).expect("valid header");
        assert_eq!(parsed.fields.get(IMSI), None);
        assert_eq!(parsed.fields.get(APN), None);
        assert_eq!(
            parsed.fields.get(MESSAGE_TYPE),
            Some(&Value::U64(u64::from(CREATE_PDP_CONTEXT_REQUEST)))
        );
    }
}
