//! SNMP — 11.11, D14 citation: RFC 1157 (SNMPv1), RFC 3416 (SNMPv2c PDU
//! formats), RFC 3411-3418 (SNMPv3 architecture, specifically RFC 3412 for
//! the v3 message wrapper cited below). The wire format is ASN.1 encoded
//! with the Basic Encoding Rules — ITU-T X.690 §8 — so this file also
//! carries a small generic BER tag/length/value (TLV) reader; SNMP is the
//! first plugin in this task to need one, but the reader is written
//! generically (no SNMP-specific assumptions) so a later ASN.1/BER plugin
//! (`kerberos`/`ldap`, 11.7) can lift it rather than re-deriving it.
//!
//! **Tag-level-only scope (D12/D13), same ceiling as `kerberos`/`ldap`.**
//! `version`, `community`, and the PDU's outer tag directly encode cheap,
//! structurally-guaranteed facts. The varbind list (the OIDs and values a
//! GetRequest/GetResponse/Trap actually carries) needs a full recursive
//! ASN.1 walk of an open-ended `SEQUENCE OF` — real parsing work, not a
//! header read — and is out of v1 scope. This dissector reads exactly far
//! enough into the PDU to find `request-id` and stops.
//!
//! **`request-id` is read structurally, not by PDU-number special-casing.**
//! RFC 3416 §3's `PDUs` CHOICE (GetRequest/GetNextRequest/Response/
//! SetRequest/GetBulkRequest/InformRequest/SNMPv2-Trap/Report, tags
//! `[0]`-`[3]`,`[5]`-`[8]`) all open with `request-id INTEGER` as the PDU
//! value's first element. RFC 1157 §4.1.6's `Trap-PDU` (`[4]`, v1-only) is
//! structurally different — it has no `request-id` at all; its first
//! element is an `enterprise OBJECT IDENTIFIER`. Rather than hard-coding
//! "skip request-id when tag == 4", this dissector reads the PDU value's
//! first TLV and only reports `request_id` when that TLV's tag is
//! `INTEGER` — the Trap-PDU case falls out naturally (its first tag is
//! `OBJECT IDENTIFIER`) instead of needing a special case.
//!
//! **SNMPv3 (`version == 3`) stops at `version`.** RFC 3412 §6's
//! `SNMPv3Message` wraps the PDU behind `msgSecurityParameters` (an opaque
//! `OCTET STRING` whose *contents* are security-model-defined, e.g. USM's
//! own TLV layout, RFC 3414 §2.4 — not walkable generically) and a
//! `ScopedPduData` `CHOICE` that, under privacy, is itself an opaque
//! `encryptedPDU OCTET STRING` (RFC 3412 §6.5). Even the plaintext case
//! needs two more nested `SEQUENCE`/`OCTET STRING` skips than the "cheap
//! tag read" this task budgets for. No `community` (v3 has none) or
//! `pdu_type`/`request_id` is reported for v3 — an explicit v1 scope
//! limit, not a decode failure; the message still parses successfully.
//!
//! **BER, not DER: only the definite-length forms.** X.690 §8.1.3
//! describes both a definite-length form (short: one byte, `0xxxxxxx`;
//! long: `1nnnnnnn` followed by `nnnnnnn` big-endian length octets) and an
//! indefinite-length form (`0x80`, content terminated by two zero
//! octets). Every SNMP encoder in practice uses definite lengths (DER
//! requires it, and BER implementations follow suit for a
//! request/response protocol with no reason to stream); indefinite length
//! is declined as malformed rather than guessed at.
//!
//! **App-stream pattern (06.6).** SNMP has no endpoint identity of its
//! own beyond the UDP 4-tuple — `app = "snmp"` is a shared constant key,
//! one child stream per UDP stream (manager<->agent), the same shape as
//! `dns`/`syslog`.

use pktflow_core::{
    ByteReader, Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx,
    ParseError, ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId, StreamIdentity, Value,
};

const APP: FieldName = "app";
const VERSION: FieldName = "version";
const COMMUNITY: FieldName = "community";
const PDU_TYPE: FieldName = "pdu_type";
const REQUEST_ID: FieldName = "request_id";

/// RFC 3416 §2's `version` INTEGER values (SNMPv2u's historical `2` is not
/// assigned a name here; it is treated the same as any other version this
/// dissector doesn't recognize — `version` alone is reported).
const SNMP_V1: u64 = 0;
const SNMP_V2C: u64 = 1;

/// X.690 §8.1.2: `SEQUENCE`/`SEQUENCE OF`, universal class, constructed.
const TAG_SEQUENCE: u8 = 0x30;
/// X.690 §8.3: `INTEGER`, universal class, primitive.
const TAG_INTEGER: u8 = 0x02;
/// X.690 §8.7: `OCTET STRING`, universal class, primitive.
const TAG_OCTET_STRING: u8 = 0x04;
/// Mask over the identifier octet's class (bits 8-7) and
/// primitive/constructed bit (bit 6) — X.690 §8.1.2.2.
const PDU_CLASS_MASK: u8 = 0xE0;
/// Context-specific class (`10`), constructed (`1`): every RFC 1157/3416
/// PDU tag (`[0]`-`[8]`) shares this class+constructed prefix, only the
/// low 5 tag-number bits vary.
const PDU_CLASS_TAG: u8 = 0xA0;
const PDU_NUMBER_MASK: u8 = 0x1F;

static KEY: &[KeyField] = &[KeyField { a: APP, b: None }];
static ROLLUPS: &[RollupSpec] = &[
    RollupSpec {
        field: PDU_TYPE,
        kind: RollupKind::Accumulate,
    },
    RollupSpec {
        field: COMMUNITY,
        kind: RollupKind::Sample,
    },
];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: ROLLUPS,
};

/// Decodes one BER length octet run (X.690 §8.1.3): short form is a single
/// byte `<= 0x7F`; long form is `0x80 | n` followed by `n` big-endian
/// length octets. `0x80` itself (indefinite length, `n == 0`) is declined
/// — see the module doc. `n > 8` is declined too: no legitimate SNMP field
/// needs a length wider than 64 bits, and capping it keeps the accumulator
/// a plain `u64` fold with no overflow.
fn ber_length(r: &mut ByteReader<'_>) -> Result<usize, ParseError> {
    let first = r.u8()?;
    if first & 0x80 == 0 {
        return Ok(usize::from(first));
    }
    let n = usize::from(first & 0x7F);
    if n == 0 {
        return Err(ParseError::Malformed("indefinite-length BER not supported"));
    }
    if n > 8 {
        return Err(ParseError::Malformed("BER length field too wide"));
    }
    let octets = r.take(n)?;
    let value = octets
        .iter()
        .fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
    usize::try_from(value).map_err(|_| ParseError::Malformed("BER length exceeds addressable size"))
}

/// Reads one BER TLV: identifier octet, then [`ber_length`], then exactly
/// that many value bytes (bounds-checked by [`ByteReader::take`] — a
/// truncated value reports `Truncated`, not a short read). Generic over
/// tag class: callers check `.0` against the tag(s) they accept.
fn read_tlv<'a>(r: &mut ByteReader<'a>) -> Result<(u8, &'a [u8]), ParseError> {
    let tag = r.u8()?;
    let len = ber_length(r)?;
    let value = r.take(len)?;
    Ok((tag, value))
}

/// Decodes a BER `INTEGER`'s content octets as an unsigned value. SNMP's
/// `version`/`request-id`/`error-status`/`error-index` are all
/// non-negative in every message this dissector reports fields for, so a
/// set high bit (X.690 §8.3.2's two's-complement sign) is treated as out
/// of scope rather than silently reinterpreted.
fn ber_uint(bytes: &[u8]) -> Result<u64, ParseError> {
    let &first = bytes
        .first()
        .ok_or(ParseError::Malformed("empty BER INTEGER"))?;
    if first & 0x80 != 0 {
        return Err(ParseError::Malformed("negative SNMP INTEGER not supported"));
    }
    if bytes.len() > 8 {
        return Err(ParseError::Malformed("SNMP INTEGER wider than 64 bits"));
    }
    Ok(bytes.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b)))
}

pub struct Snmp;

impl LayerPlugin for Snmp {
    fn name(&self) -> ProtocolName {
        "snmp"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let (msg_tag, msg_body) = read_tlv(&mut r)?;
        if msg_tag != TAG_SEQUENCE {
            return Err(ParseError::Malformed("SNMP message must be a BER SEQUENCE"));
        }
        // The whole message is one BER TLV: header_len is exactly what
        // read_tlv just consumed from `r`, regardless of how much of
        // msg_body this dissector goes on to look at.
        let header_len = bytes.len() - r.remaining();

        let mut body = ByteReader::new(msg_body);
        let (version_tag, version_bytes) = read_tlv(&mut body)?;
        if version_tag != TAG_INTEGER {
            return Err(ParseError::Malformed("SNMP version must be an INTEGER"));
        }
        let version = ber_uint(version_bytes)?;

        let mut community: Option<&[u8]> = None;
        let mut pdu_type: Option<u8> = None;
        let mut request_id: Option<u64> = None;

        if version == SNMP_V1 || version == SNMP_V2C {
            let (community_tag, community_bytes) = read_tlv(&mut body)?;
            if community_tag != TAG_OCTET_STRING {
                return Err(ParseError::Malformed(
                    "SNMP community must be an OCTET STRING",
                ));
            }
            community = Some(community_bytes);

            let (pdu_tag, pdu_body) = read_tlv(&mut body)?;
            if pdu_tag & PDU_CLASS_MASK != PDU_CLASS_TAG {
                return Err(ParseError::Malformed(
                    "SNMP PDU tag is not context-specific constructed",
                ));
            }
            pdu_type = Some(pdu_tag & PDU_NUMBER_MASK);

            let mut pdu_reader = ByteReader::new(pdu_body);
            if let Ok((first_tag, first_bytes)) = read_tlv(&mut pdu_reader) {
                if first_tag == TAG_INTEGER {
                    request_id = ber_uint(first_bytes).ok();
                }
            }
        }

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(APP, Value::from("snmp"));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(VERSION, Value::U64(version));
            if let Some(c) = community {
                fields.insert(COMMUNITY, Value::from(String::from_utf8_lossy(c).as_ref()));
            }
            if let Some(t) = pdu_type {
                fields.insert(PDU_TYPE, Value::U64(u64::from(t)));
            }
        }
        if ctx.depth() >= Depth::Full {
            if let Some(id) = request_id {
                fields.insert(REQUEST_ID, Value::U64(id));
            }
        }

        Ok(ParsedLayer {
            header_len,
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::UdpPort(161), RouteId::UdpPort(162)]
    }

    fn stream_identity(&self) -> Option<&StreamIdentity> {
        Some(&IDENTITY)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    use pktflow_core::{LinkType, PacketMeta};

    fn ctx_bytes(meta: &PacketMeta, depth: Depth) -> ParseCtx<'_> {
        ParseCtx::new(&[], depth, meta)
    }

    fn meta(len: usize) -> PacketMeta {
        PacketMeta {
            timestamp: SystemTime::UNIX_EPOCH,
            caplen: len,
            origlen: len,
            link_type: LinkType::ETHERNET,
        }
    }

    /// SEQUENCE{OID sysDescr.0, NULL}, a GetRequest-shaped single varbind
    /// (RFC 1213 MIB-II; `1.3.6.1.2.1.1.1.0`, the textbook SNMP OID).
    fn varbind_oid_null(oid: &[u8]) -> Vec<u8> {
        let mut oid_tlv = vec![0x06, oid.len() as u8];
        oid_tlv.extend_from_slice(oid);
        let mut null_tlv = vec![0x05, 0x00];
        let mut content = Vec::new();
        content.append(&mut oid_tlv);
        content.append(&mut null_tlv);
        let mut out = vec![0x30, content.len() as u8];
        out.extend_from_slice(&content);
        out
    }

    /// `sysDescr.0` (`1.3.6.1.2.1.1.1.0`) BER-encoded per X.690 §8.19: the
    /// first two arcs `1.3` fold into one octet (`40*X+Y`), the rest are
    /// each `< 128` so stay one octet apiece.
    const SYS_DESCR_0: [u8; 8] = [0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00];

    /// A v1 GetRequest for `sysDescr.0`, community `"public"`, request-id
    /// of 1. Hand-built and byte-verified against RFC 1157 §4.1.1/§4.1.2
    /// and RFC 1213's MIB-II OID, not captured from a live agent.
    fn get_request_v1() -> Vec<u8> {
        let varbind_list = {
            let vb = varbind_oid_null(&SYS_DESCR_0);
            let mut out = vec![0x30, vb.len() as u8];
            out.extend_from_slice(&vb);
            out
        };
        let mut pdu_body = vec![
            0x02, 0x01, 0x01, // request-id = 1
            0x02, 0x01, 0x00, // error-status = 0
            0x02, 0x01, 0x00, // error-index = 0
        ];
        pdu_body.extend_from_slice(&varbind_list);
        let mut msg_body = vec![
            0x02, 0x01, 0x00, // version = 0 (v1)
            0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', // community "public"
        ];
        msg_body.push(0xA0); // GetRequest-PDU, tag [0]
        msg_body.push(pdu_body.len() as u8);
        msg_body.extend_from_slice(&pdu_body);
        let mut out = vec![0x30, msg_body.len() as u8];
        out.extend_from_slice(&msg_body);
        out
    }

    #[test]
    fn get_request_v1_fields_and_header_len() {
        let bytes = get_request_v1();
        let m = meta(bytes.len());
        let ctx = ctx_bytes(&m, Depth::Full);
        let parsed = Snmp.parse(&bytes, &ctx).expect("well-formed GetRequest");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(APP), Some(&Value::from("snmp")));
        assert_eq!(parsed.fields.get(VERSION), Some(&Value::U64(0)));
        assert_eq!(parsed.fields.get(COMMUNITY), Some(&Value::from("public")));
        assert_eq!(parsed.fields.get(PDU_TYPE), Some(&Value::U64(0)));
        assert_eq!(parsed.fields.get(REQUEST_ID), Some(&Value::U64(1)));
    }

    /// RFC 1157 §4.1.6's Trap-PDU (`[4]`, v1-only) opens with `enterprise
    /// OBJECT IDENTIFIER`, not `request-id INTEGER` — the one PDU shape
    /// where `request_id` must come out absent, not zero or malformed.
    fn trap_v1() -> Vec<u8> {
        // enterprise = 1.3.6.1.4.1.9 (a real, widely-cited Cisco
        // enterprise OID, used here only as a structurally valid example).
        let enterprise: [u8; 6] = [0x2B, 0x06, 0x01, 0x04, 0x01, 0x09];
        let mut pdu_body = Vec::new();
        pdu_body.push(0x06);
        pdu_body.push(enterprise.len() as u8);
        pdu_body.extend_from_slice(&enterprise);
        pdu_body.extend_from_slice(&[0x40, 0x04, 192, 0, 2, 1]); // agent-addr
        pdu_body.extend_from_slice(&[0x02, 0x01, 0x06]); // generic-trap = enterpriseSpecific
        pdu_body.extend_from_slice(&[0x02, 0x01, 0x00]); // specific-trap = 0
        pdu_body.extend_from_slice(&[0x43, 0x01, 0x00]); // time-stamp (TimeTicks) = 0
        pdu_body.extend_from_slice(&[0x30, 0x00]); // empty variable-bindings

        let mut msg_body = vec![
            0x02, 0x01, 0x00, // version = 0 (v1)
            0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', // community "public"
        ];
        msg_body.push(0xA4); // Trap-PDU, tag [4]
        msg_body.push(pdu_body.len() as u8);
        msg_body.extend_from_slice(&pdu_body);
        let mut out = vec![0x30, msg_body.len() as u8];
        out.extend_from_slice(&msg_body);
        out
    }

    #[test]
    fn trap_v1_has_no_request_id() {
        let bytes = trap_v1();
        let m = meta(bytes.len());
        let ctx = ctx_bytes(&m, Depth::Full);
        let parsed = Snmp.parse(&bytes, &ctx).expect("well-formed Trap-PDU");
        assert_eq!(parsed.fields.get(PDU_TYPE), Some(&Value::U64(4)));
        assert_eq!(
            parsed.fields.get(REQUEST_ID),
            None,
            "Trap-PDU's first element is an OID, not request-id"
        );
    }

    /// SNMPv3 message shell: `version = 3` plus enough of `HeaderData` to
    /// be a plausible RFC 3412 §6.1 `SNMPv3Message`, deliberately not
    /// decoded further (module doc's v3 scope note).
    fn snmpv3_shell() -> Vec<u8> {
        let header_data = {
            // HeaderData ::= SEQUENCE { msgID, msgMaxSize INTEGER,
            // msgFlags OCTET STRING(1), msgSecurityModel INTEGER }.
            let mut content = vec![0x02, 0x01, 0x01]; // msgID = 1
            content.extend_from_slice(&[0x02, 0x02, 0x04, 0x00]); // msgMaxSize
            content.extend_from_slice(&[0x04, 0x01, 0x00]); // msgFlags
            content.extend_from_slice(&[0x02, 0x01, 0x03]); // msgSecurityModel = USM(3)
            let mut out = vec![0x30, content.len() as u8];
            out.extend_from_slice(&content);
            out
        };
        let mut msg_body = vec![0x02, 0x01, 0x03]; // msgVersion = 3
        msg_body.extend_from_slice(&header_data);
        msg_body.extend_from_slice(&[0x04, 0x00]); // msgSecurityParameters (empty, opaque)
        msg_body.extend_from_slice(&[0x04, 0x00]); // msgData: encryptedPDU (opaque)
        let mut out = vec![0x30, msg_body.len() as u8];
        out.extend_from_slice(&msg_body);
        out
    }

    #[test]
    fn snmpv3_reports_only_version() {
        let bytes = snmpv3_shell();
        let m = meta(bytes.len());
        let ctx = ctx_bytes(&m, Depth::Full);
        let parsed = Snmp.parse(&bytes, &ctx).expect("well-formed SNMPv3 shell");
        assert_eq!(parsed.fields.get(VERSION), Some(&Value::U64(3)));
        assert_eq!(parsed.fields.get(COMMUNITY), None);
        assert_eq!(parsed.fields.get(PDU_TYPE), None);
        assert_eq!(parsed.fields.get(REQUEST_ID), None);
    }

    #[test]
    fn non_sequence_outer_tag_declines() {
        let mut bytes = get_request_v1();
        bytes[0] = 0x31; // SET, not SEQUENCE
        let m = meta(bytes.len());
        let ctx = ctx_bytes(&m, Depth::Full);
        assert!(Snmp.parse(&bytes, &ctx).is_err());
    }

    #[test]
    fn non_integer_version_declines() {
        let mut bytes = get_request_v1();
        // Overwrite the version TLV's tag (byte 2, right after the outer
        // SEQUENCE's tag+length) with OCTET STRING instead of INTEGER.
        bytes[2] = 0x04;
        let m = meta(bytes.len());
        let ctx = ctx_bytes(&m, Depth::Full);
        assert!(Snmp.parse(&bytes, &ctx).is_err());
    }

    #[test]
    fn ber_length_long_form_decodes() {
        // 0x82 0x01 0x2C = long form, 2 length octets, value 0x012C = 300.
        let mut r = ByteReader::new(&[0x82, 0x01, 0x2C]);
        assert_eq!(ber_length(&mut r), Ok(300));
    }

    #[test]
    fn ber_length_indefinite_form_declines() {
        let mut r = ByteReader::new(&[0x80]);
        assert!(ber_length(&mut r).is_err());
    }

    #[test]
    fn ber_length_truncated_long_form_declines() {
        // Claims 2 length octets but only 1 follows.
        let mut r = ByteReader::new(&[0x82, 0x01]);
        assert!(ber_length(&mut r).is_err());
    }

    #[test]
    fn depth_none_yields_no_fields() {
        let bytes = get_request_v1();
        let m = meta(bytes.len());
        let ctx = ctx_bytes(&m, Depth::None);
        let parsed = Snmp.parse(&bytes, &ctx).expect("well-formed GetRequest");
        assert!(parsed.fields.get(APP).is_none());
        assert!(parsed.fields.get(VERSION).is_none());
    }
}
