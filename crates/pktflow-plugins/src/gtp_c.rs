//! GTP-C (11.15 — 3GPP TS 29.060 GTPv1-C; 3GPP TS 29.274 GTPv2-C). One
//! plugin: GTPv1-C and GTPv2-C share `UdpPort(2123)` and can't both claim
//! it (route collision, 03.2), so `version` (both formats put it in the
//! same top-3-bits position of octet 1) disambiguates — the `ospf`/`stun`
//! precedent from 11.4/11.8.
//!
//! ## GTPv1-C header (TS 29.060 §6 — the same general GTP header `gtp_u`
//! ## uses)
//! `Version(3)+PT(1)+*(1)+E(1)+S(1)+PN(1) | MessageType(8) | Length(16) |
//! TEID(32) | [Sequence Number(16)+N-PDU Number(8)+Next Ext Header
//! Type(8), present iff E|S|PN]`. `Length` counts everything after the
//! 8-octet mandatory part (the optional block included, TS 29.060 §6), so
//! `header_len = 8 + length` — fully self-describing, the same "consume
//! the declared unit" stance `sctp`/`tls`/`stun` take. `PT` must be `1`
//! (GTP, not GTP') — the same honesty check `gtp_u` makes.
//!
//! ## GTPv2-C header (TS 29.274 §5.1)
//! `Version(3)+P(1)+T(1)+Spare(3) | MessageType(8) | MessageLength(16) |
//! [TEID(32), present iff T] | SequenceNumber(24) | Spare(8)`. `T=0`
//! (Echo Request/Response, Version-Not-Supported-Indication) carries no
//! TEID octets at all — this plugin reports `teid = 0` for those, the same
//! "0 before one is assigned" convention the field table already
//! documents for early v1 messages. `MessageLength` excludes only the
//! first 4 octets (§5.1), so `header_len = 4 + message_length`.
//!
//! ## IE-walk honesty (D12-style bounded partial extraction)
//! GTPv1-C mixes two IE encodings (TS 29.060 §7.7): `Type < 0x80` is
//! **TV** (Type+Value, a *fixed* length only a per-type lookup table
//! reveals — this plugin knows a small, named set of common types well
//! enough to skip past them, and gives up on the walk the moment it meets
//! a TV type it doesn't recognize, rather than guessing a length);
//! `Type >= 0x80` is **TLV** (Type+Length+Value, always safely skippable
//! regardless of type, since the length is self-describing) — `APN`
//! (type `0x83`) is one of these. GTPv2-C's IEs are uniformly **TLIV**
//! (Type+Length+CR/Instance+Value, TS 29.274 §8.1), always self-describing
//! regardless of type, so its walk never needs a lookup table at all.
//! Either way, a field the walk can't reach is simply omitted — never a
//! decline of the whole message, and never a misaligned guess.

use pktflow_core::{
    ByteReader, Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx,
    ParseError, ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId, StreamIdentity, Value,
};

const TEID: FieldName = "teid";
const VERSION: FieldName = "version";
const MESSAGE_TYPE: FieldName = "message_type";
const LENGTH: FieldName = "length";
const IMSI: FieldName = "imsi";
const APN: FieldName = "apn";

const VERSION_MASK: u8 = 0xE0;
const VERSION_SHIFT: u32 = 5;
/// TS 29.060 §6: bit 5 — Protocol Type; `1` selects GTP over GTP'.
const V1_PT_BIT: u8 = 0x10;
const V1_E_BIT: u8 = 0x04;
const V1_S_BIT: u8 = 0x02;
const V1_PN_BIT: u8 = 0x01;
/// TS 29.274 §5.1: bit 4 of octet 1 — TEID present.
const V2_T_BIT: u8 = 0x08;

/// TS 29.060 §7.7's IE Type registry, TV-encoded range only (`Type <
/// 0x80`): `(type, value_len)` for the common types a Create PDP Context
/// Request walk needs to step past to reach IMSI. Not exhaustive — an
/// unrecognized TV type ends the walk (module doc).
const V1_TV_LENGTHS: &[(u8, usize)] = &[
    (0x01, 1), // Cause
    (0x02, 8), // IMSI
    (0x03, 6), // Routeing Area Identity
    (0x0E, 1), // Recovery
    (0x0F, 1), // Selection Mode
    (0x10, 4), // Tunnel Endpoint Identifier Data I
    (0x11, 4), // Tunnel Endpoint Identifier Control Plane
    (0x12, 5), // Tunnel Endpoint Identifier Data II
    (0x14, 1), // NSAPI
    (0x1A, 2), // Charging Characteristics
];
const V1_IMSI_TYPE: u8 = 0x02;
const V1_APN_TYPE: u8 = 0x83;

const V2_IMSI_TYPE: u8 = 1;
const V2_APN_TYPE: u8 = 71;

/// TS 23.003 §2.2: IMSI digits packed two per octet, low nibble first;
/// `0xF` is the filler nibble marking the end of an odd-length number.
fn decode_bcd_digits(bytes: &[u8]) -> Option<String> {
    let mut digits = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        for nibble in [b & 0x0F, (b >> 4) & 0x0F] {
            if nibble == 0xF {
                return (!digits.is_empty()).then_some(digits);
            }
            if nibble > 9 {
                return None;
            }
            digits.push((b'0' + nibble) as char);
        }
    }
    (!digits.is_empty()).then_some(digits)
}

/// TS 23.003 §9.1: APN is DNS-label-encoded — each label prefixed by its
/// length octet, no trailing root label. Decodes to dotted form.
fn decode_apn_labels(bytes: &[u8]) -> Option<String> {
    let mut r = ByteReader::new(bytes);
    let mut labels = Vec::new();
    while r.remaining() > 0 {
        let len = r.u8().ok()?;
        let label = r.take(usize::from(len)).ok()?;
        labels.push(std::str::from_utf8(label).ok()?);
    }
    (!labels.is_empty()).then(|| labels.join("."))
}

/// GTPv1-C's bounded TV/TLV walk (module doc): best-effort `imsi`/`apn`,
/// giving up silently the moment an unrecognized TV type is met.
fn walk_v1_ies(ies: &[u8]) -> (Option<String>, Option<String>) {
    let mut imsi = None;
    let mut apn = None;
    let mut r = ByteReader::new(ies);
    while r.remaining() > 0 {
        let Ok(ty) = r.u8() else { break };
        if ty < 0x80 {
            let Some(&(_, value_len)) = V1_TV_LENGTHS.iter().find(|&&(t, _)| t == ty) else {
                break; // unrecognized TV type: can't safely skip it, stop.
            };
            let Ok(value) = r.take(value_len) else {
                break;
            };
            if ty == V1_IMSI_TYPE {
                imsi = decode_bcd_digits(value);
            }
        } else {
            let Ok(len) = r.u16_be() else { break };
            let Ok(value) = r.take(usize::from(len)) else {
                break;
            };
            if ty == V1_APN_TYPE {
                apn = decode_apn_labels(value);
            }
        }
    }
    (imsi, apn)
}

/// GTPv2-C's uniform TLIV walk (module doc): always self-describing, so
/// unrecognized types are always safely skippable.
fn walk_v2_ies(ies: &[u8]) -> (Option<String>, Option<String>) {
    let mut imsi = None;
    let mut apn = None;
    let mut r = ByteReader::new(ies);
    while r.remaining() > 0 {
        let Ok(ty) = r.u8() else { break };
        // TS 29.274 §8.1: `Length` excludes the Type/Length octets *and*
        // the Spare+Instance octet that follows them — it counts only the
        // IE-specific value that comes after.
        let Ok(len) = r.u16_be() else { break };
        let Ok(_cr_instance) = r.u8() else { break };
        let Ok(value) = r.take(usize::from(len)) else {
            break;
        };
        match ty {
            V2_IMSI_TYPE => imsi = decode_bcd_digits(value),
            V2_APN_TYPE => apn = decode_apn_labels(value),
            _ => {}
        }
    }
    (imsi, apn)
}

static KEY: &[KeyField] = &[KeyField {
    a: TEID,
    b: None, // shared (non-endpoint) qualifier, uniform across both versions
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

pub struct GtpC;

impl LayerPlugin for GtpC {
    fn name(&self) -> ProtocolName {
        "gtp_c"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let flags = r.u8()?;
        let version = (flags & VERSION_MASK) >> VERSION_SHIFT;

        let (teid, message_type, length, ie_start) = match version {
            1 => {
                if flags & V1_PT_BIT == 0 {
                    return Err(ParseError::Malformed(
                        "GTPv1-C: PT bit selects GTP', not GTP",
                    ));
                }
                let message_type = r.u8()?;
                let length = r.u16_be()?;
                let teid = r.u32_be()?;
                let mut ie_start = 8usize;
                if flags & (V1_E_BIT | V1_S_BIT | V1_PN_BIT) != 0 {
                    r.take(4)?; // Sequence Number + N-PDU Number + Next Ext Header Type
                    ie_start += 4;
                }
                (teid, message_type, length, ie_start)
            }
            2 => {
                let message_type = r.u8()?;
                let length = r.u16_be()?;
                let (teid, ie_start) = if flags & V2_T_BIT != 0 {
                    let teid = r.u32_be()?;
                    r.take(4)?; // Sequence Number(3) + Spare(1)
                    (teid, 12)
                } else {
                    r.take(4)?; // Sequence Number(3) + Spare(1)
                    (0, 8)
                };
                (teid, message_type, length, ie_start)
            }
            _ => return Err(ParseError::Malformed("unsupported GTP-C version")),
        };

        let fixed_prefix_len = if version == 1 { 8 } else { 4 };
        let header_len = fixed_prefix_len + usize::from(length);
        let ie_len = header_len
            .checked_sub(ie_start)
            .ok_or(ParseError::Malformed(
                "GTP-C length shorter than the header it must contain",
            ))?;
        // `r` is already positioned at `ie_start`; taking `ie_len` bytes
        // both proves the declared length is actually present (the same
        // "trust the length field, not the buffer size" shape `radius`
        // uses) and yields the IE bytes to walk below.
        let ies = r.take(ie_len)?;

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
            let (imsi, apn) = if version == 1 {
                walk_v1_ies(ies)
            } else {
                walk_v2_ies(ies)
            };
            if let Some(v) = imsi {
                fields.insert(IMSI, Value::from(v.as_str()));
            }
            if let Some(v) = apn {
                fields.insert(APN, Value::from(v.as_str()));
            }
        }

        Ok(ParsedLayer {
            header_len,
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

    fn v1_tv(ty: u8, value: &[u8]) -> Vec<u8> {
        let mut b = vec![ty];
        b.extend_from_slice(value);
        b
    }

    fn v1_tlv(ty: u8, value: &[u8]) -> Vec<u8> {
        let mut b = vec![ty];
        b.extend_from_slice(&(value.len() as u16).to_be_bytes());
        b.extend_from_slice(value);
        b
    }

    /// TS 23.003 BCD encoding of an odd-length digit string (padded with
    /// the `0xF` filler nibble).
    fn bcd_encode(digits: &str) -> Vec<u8> {
        let nibbles: Vec<u8> = digits.bytes().map(|b| b - b'0').collect();
        let mut out = Vec::new();
        let mut i = 0;
        while i < nibbles.len() {
            let lo = nibbles[i];
            let hi = if i + 1 < nibbles.len() {
                nibbles[i + 1]
            } else {
                0xF
            };
            out.push(lo | (hi << 4));
            i += 2;
        }
        out
    }

    fn apn_encode(labels: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        for l in labels {
            out.push(l.len() as u8);
            out.extend_from_slice(l.as_bytes());
        }
        out
    }

    /// GTPv1-C header (no optional block), plus `ies` appended.
    fn v1_message(message_type: u8, teid: u32, ies: &[u8]) -> Vec<u8> {
        let mut b = vec![0x30, message_type]; // version 1, PT=1
        b.extend_from_slice(&(ies.len() as u16).to_be_bytes());
        b.extend_from_slice(&teid.to_be_bytes());
        b.extend_from_slice(ies);
        b
    }

    /// GTPv2-C header with T=1 (TEID present), plus `ies` appended.
    fn v2_message(message_type: u8, teid: u32, ies: &[u8]) -> Vec<u8> {
        let mut b = vec![0x48, message_type]; // version 2, T=1
        b.extend_from_slice(&((8 + ies.len()) as u16).to_be_bytes());
        b.extend_from_slice(&teid.to_be_bytes());
        b.extend_from_slice(&[0x00, 0x00, 0x01]); // sequence number
        b.push(0x00); // spare
        b.extend_from_slice(ies);
        b
    }

    /// GTPv2-C Echo Request (T=0, no TEID octets at all).
    fn v2_echo_request() -> Vec<u8> {
        let mut b = vec![0x40, 1]; // version 2, T=0; message_type Echo Request
        b.extend_from_slice(&4u16.to_be_bytes());
        b.extend_from_slice(&[0x00, 0x00, 0x01]); // sequence number
        b.push(0x00); // spare
        b
    }

    #[test]
    fn v1_create_pdp_context_request_parses_teid_and_imsi() {
        let mut ies = v1_tv(V1_IMSI_TYPE, &bcd_encode("123456789012345"));
        ies.extend_from_slice(&v1_tv(0x0F, &[0x01])); // Selection Mode
        let bytes = v1_message(16, 0, &ies); // Create PDP Context Request
        let m = meta(bytes.len());
        let parsed = GtpC
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid v1 Create PDP Context Request");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(VERSION), Some(&Value::U64(1)));
        assert_eq!(parsed.fields.get(MESSAGE_TYPE), Some(&Value::U64(16)));
        assert_eq!(parsed.fields.get(TEID), Some(&Value::U64(0)));
        assert_eq!(
            parsed.fields.get(IMSI),
            Some(&Value::from("123456789012345"))
        );
    }

    #[test]
    fn v1_apn_recovered_via_tlv_after_skipping_recognized_tv_ies() {
        let mut ies = v1_tv(0x01, &[0x00]); // Cause
        ies.extend_from_slice(&v1_tv(V1_IMSI_TYPE, &bcd_encode("111222333444555")));
        ies.extend_from_slice(&v1_tlv(V1_APN_TYPE, &apn_encode(&["internet"])));
        let bytes = v1_message(17, 0xAABB_CCDD, &ies); // Create PDP Context Response
        let m = meta(bytes.len());
        let parsed = GtpC
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid v1 message");
        assert_eq!(parsed.fields.get(TEID), Some(&Value::U64(0xAABB_CCDD)));
        assert_eq!(
            parsed.fields.get(IMSI),
            Some(&Value::from("111222333444555"))
        );
        assert_eq!(parsed.fields.get(APN), Some(&Value::from("internet")));
    }

    /// The acceptance-criterion fixture: an unrecognized/vendor-specific
    /// TLV IE type present alongside recognized ones still lets the walk
    /// reach IMSI/APN correctly, skipping the unrecognized one via its own
    /// length field — no misalignment.
    #[test]
    fn v1_unrecognized_tlv_ie_is_skipped_via_its_own_length_no_misalignment() {
        let mut ies = v1_tlv(0xFE, &[0xDE, 0xAD, 0xBE, 0xEF, 0x00]); // vendor-specific TLV
        ies.extend_from_slice(&v1_tlv(
            V1_APN_TYPE,
            &apn_encode(&["ims", "mnc001", "mcc001"]),
        ));
        let bytes = v1_message(18, 1, &ies); // Update PDP Context Request
        let m = meta(bytes.len());
        let parsed = GtpC
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid v1 message with vendor TLV");
        assert_eq!(
            parsed.fields.get(APN),
            Some(&Value::from("ims.mnc001.mcc001"))
        );
    }

    #[test]
    fn v1_unrecognized_tv_ie_stops_the_walk_without_declining_the_message() {
        let mut ies = v1_tv(0x7F, &[0x00, 0x00]); // unrecognized TV type: can't skip safely
        ies.extend_from_slice(&v1_tv(V1_IMSI_TYPE, &bcd_encode("123450000000000")));
        let bytes = v1_message(1, 0, &ies); // Echo Request
        let m = meta(bytes.len());
        let parsed = GtpC
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("still a valid GTPv1-C message");
        assert_eq!(parsed.fields.get(IMSI), None);
        assert_eq!(parsed.fields.get(MESSAGE_TYPE), Some(&Value::U64(1)));
    }

    #[test]
    fn v2_create_session_request_parses_teid_imsi_and_apn() {
        let mut ies = Vec::new();
        ies.extend_from_slice(&1u8.to_be_bytes()); // IMSI type
        let imsi_val = bcd_encode("460001357924680");
        ies.extend_from_slice(&(imsi_val.len() as u16).to_be_bytes());
        ies.push(0x00); // CR/Instance
        ies.extend_from_slice(&imsi_val);

        let apn_val = apn_encode(&["internet"]);
        ies.push(71); // APN type
        ies.extend_from_slice(&(apn_val.len() as u16).to_be_bytes());
        ies.push(0x00);
        ies.extend_from_slice(&apn_val);

        let bytes = v2_message(32, 0, &ies); // Create Session Request, TEID 0 pre-assignment
        let m = meta(bytes.len());
        let parsed = GtpC
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid GTPv2-C Create Session Request");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.fields.get(VERSION), Some(&Value::U64(2)));
        assert_eq!(parsed.fields.get(MESSAGE_TYPE), Some(&Value::U64(32)));
        assert_eq!(parsed.fields.get(TEID), Some(&Value::U64(0)));
        assert_eq!(
            parsed.fields.get(IMSI),
            Some(&Value::from("460001357924680"))
        );
        assert_eq!(parsed.fields.get(APN), Some(&Value::from("internet")));
    }

    #[test]
    fn v2_echo_request_has_no_teid_octets_and_reports_zero() {
        let bytes = v2_echo_request();
        let m = meta(bytes.len());
        let parsed = GtpC
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid v2 Echo Request");
        assert_eq!(parsed.fields.get(TEID), Some(&Value::U64(0)));
        assert_eq!(parsed.fields.get(MESSAGE_TYPE), Some(&Value::U64(1)));
    }

    #[test]
    fn same_teid_works_uniformly_across_both_versions() {
        let v1 = v1_message(16, 0x1234_5678, &[]);
        let v2 = v2_message(32, 0x1234_5678, &[]);
        let m1 = meta(v1.len());
        let m2 = meta(v2.len());
        let p1 = GtpC.parse(&v1, &ctx(Depth::Full, &m1)).expect("valid v1");
        let p2 = GtpC.parse(&v2, &ctx(Depth::Full, &m2)).expect("valid v2");
        assert_eq!(p1.fields.get(TEID), Some(&Value::U64(0x1234_5678)));
        assert_eq!(p2.fields.get(TEID), Some(&Value::U64(0x1234_5678)));
    }

    #[test]
    fn depth_gates_teid_version_and_imsi() {
        let ies = v1_tv(V1_IMSI_TYPE, &bcd_encode("123456789012345"));
        let bytes = v1_message(16, 42, &ies);
        let m = meta(bytes.len());
        let keys = GtpC.parse(&bytes, &ctx(Depth::Keys, &m)).expect("valid");
        assert_eq!(keys.fields.get(TEID), Some(&Value::U64(42)));
        assert_eq!(keys.fields.get(VERSION), None);

        let structural = GtpC
            .parse(&bytes, &ctx(Depth::Structural, &m))
            .expect("valid");
        assert_eq!(structural.fields.get(VERSION), Some(&Value::U64(1)));
        assert_eq!(structural.fields.get(IMSI), None);
    }

    #[test]
    fn wrong_version_declines() {
        let mut bytes = v1_message(1, 0, &[]);
        bytes[0] = 0x60; // version 3
        let m = meta(bytes.len());
        assert!(GtpC.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn v1_gtp_prime_protocol_type_declines() {
        let mut bytes = v1_message(1, 0, &[]);
        bytes[0] = 0x20; // version 1, PT=0 (GTP')
        assert!(GtpC
            .parse(&bytes, &ctx(Depth::Full, &meta(bytes.len())))
            .is_err());
    }

    #[test]
    fn truncated_v1_and_v2_headers_decline() {
        let v1 = v1_message(16, 1, b"trailing-ies");
        let v2 = v2_message(32, 1, b"trailing-ies");
        for bytes in [v1, v2] {
            let m = meta(bytes.len());
            let full = ctx(Depth::Full, &m);
            let header_len = GtpC.parse(&bytes, &full).expect("valid").header_len;
            for n in 0..header_len {
                assert!(
                    GtpC.parse(&bytes[..n], &full).is_err(),
                    "prefix of {n}/{header_len} bytes must decline"
                );
            }
        }
    }
}
