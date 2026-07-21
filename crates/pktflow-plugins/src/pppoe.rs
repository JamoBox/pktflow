//! PPPoE (11.5, RFC 2516) — two phases sharing one 6-byte header shape:
//! Discovery (PADI/PADO/PADR/PADS/PADT, `Code != 0x00`) negotiates a
//! `session_id`, then Session data (`Code == 0x00`) carries PPP framed
//! with HDLC stripped (RFC 2516 §4.4) — handed off via
//! `Hint::ByProtocol("ppp")`, the same zero-touch-reuse pattern `vxlan`
//! uses for its fixed inner protocol (06.5).
//!
//! Discovery's `Length` field is this layer's *own* header content (the
//! tag list, RFC 2516 §5), not a further protocol, so it's walked
//! unconditionally — like CDP's TLV walk (11.1) — to pin down
//! `header_len` and catch structurally invalid tags regardless of depth;
//! only the *values* of the three tags this plugin surfaces
//! (Service-Name, AC-Name, Host-Uniq) are gated to `Full`. Session data's
//! `Length` describes the PPP payload instead — a separate layer this
//! plugin does not consume, matching `l2tpv3`'s data-vs-control header
//! split (11.5).

use pktflow_core::{
    ByteReader, Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx,
    ParseError, ParsedLayer, ProtocolName, RouteId, StreamIdentity, Value,
};

const VERSION: FieldName = "version";
const TYPE: FieldName = "type";
const CODE: FieldName = "code";
const SESSION_ID: FieldName = "session_id";
const SERVICE_NAME: FieldName = "service_name";
const AC_NAME: FieldName = "ac_name";
const HOST_UNIQ: FieldName = "host_uniq";

/// RFC 2516 §4/§5: `Code == 0x00` is the one non-Discovery value —
/// Session data, PPP payload follows directly.
const CODE_SESSION_DATA: u8 = 0x00;

/// RFC 2516 §5: Discovery tag types this plugin surfaces.
const TAG_SERVICE_NAME: u16 = 0x0101;
const TAG_AC_NAME: u16 = 0x0102;
const TAG_HOST_UNIQ: u16 = 0x0103;

static KEY: &[KeyField] = &[KeyField {
    a: SESSION_ID,
    b: None, // shared qualifier: one PPPoE session stream per session_id, the L2TPv3/VXLAN shape (06.5/11.5)
}];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: &[],
};

/// Discovery tags accumulated by the walk — best-effort, same "missing
/// TLV just leaves the field unset" stance as `cdp`'s `Tlvs` (11.1).
#[derive(Default)]
struct Tags {
    service_name: Option<Vec<u8>>,
    ac_name: Option<Vec<u8>>,
    host_uniq: Option<Vec<u8>>,
}

impl Tags {
    fn record(&mut self, tag_type: u16, value: &[u8]) {
        match tag_type {
            TAG_SERVICE_NAME => self.service_name = Some(value.to_vec()),
            TAG_AC_NAME => self.ac_name = Some(value.to_vec()),
            TAG_HOST_UNIQ => self.host_uniq = Some(value.to_vec()),
            _ => {}
        }
    }

    fn insert_full_fields(&self, fields: &mut FieldMap) {
        if let Some(v) = &self.service_name {
            fields.insert(SERVICE_NAME, Value::from(decode_text(v).as_str()));
        }
        if let Some(v) = &self.ac_name {
            fields.insert(AC_NAME, Value::from(decode_text(v).as_str()));
        }
        if let Some(v) = &self.host_uniq {
            fields.insert(HOST_UNIQ, Value::from(v.as_slice()));
        }
    }
}

/// Best-effort text decode, same fallback `cdp`/`lldp` use (11.1):
/// non-graphic bytes render as `?` rather than failing the parse over a
/// cosmetic field.
fn decode_text(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                char::from(b)
            } else {
                '?'
            }
        })
        .collect()
}

/// Walks the Discovery tag list (RFC 2516 §5: `Tag_Type`(2) +
/// `Tag_Length`(2) + `Tag_Value`), bounded strictly by the caller's
/// `Length`-sized slice — a malformed tag (length running past the end
/// of that slice) declines the whole parse, the same "structural
/// validity isn't depth-gated" stance CDP's TLV walk takes.
fn walk_tags(region: &[u8]) -> Result<Tags, ParseError> {
    let mut tags = Tags::default();
    let mut r = ByteReader::new(region);
    while r.remaining() > 0 {
        let tag_type = r.u16_be()?;
        let tag_len = r.u16_be()?;
        let value = r.take(usize::from(tag_len))?;
        tags.record(tag_type, value);
    }
    Ok(tags)
}

pub struct Pppoe;

impl LayerPlugin for Pppoe {
    fn name(&self) -> ProtocolName {
        "pppoe"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let first = r.u8()?;
        if first != 0x11 {
            // RFC 2516 §4: VER and TYPE MUST both be 0x1.
            return Err(ParseError::Malformed("PPPoE: VER/TYPE is not 0x1/0x1"));
        }
        let code = r.u8()?;
        let session_id = r.u16_be()?;
        let length = usize::from(r.u16_be()?);

        let hint;
        let header_len;
        let tags = if code == CODE_SESSION_DATA {
            hint = Hint::ByProtocol("ppp");
            header_len = bytes.len() - r.remaining();
            None
        } else {
            hint = Hint::Terminal;
            let region = r.take(length)?;
            header_len = bytes.len() - r.remaining();
            Some(walk_tags(region)?)
        };

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(SESSION_ID, Value::U64(u64::from(session_id)));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(VERSION, Value::U64(u64::from(first >> 4)));
            fields.insert(TYPE, Value::U64(u64::from(first & 0x0F)));
            fields.insert(CODE, Value::U64(u64::from(code)));
        }
        if ctx.depth() >= Depth::Full {
            if let Some(tags) = &tags {
                tags.insert_full_fields(&mut fields);
            }
        }

        Ok(ParsedLayer {
            header_len,
            fields,
            hint,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[
            RouteId::EtherType(0x8863), // Discovery
            RouteId::EtherType(0x8864), // Session
        ]
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

    fn ctx(depth: Depth, m: &PacketMeta) -> ParseCtx<'_> {
        ParseCtx::new(&[], depth, m)
    }

    fn tag(tag_type: u16, value: &[u8]) -> Vec<u8> {
        let mut b = tag_type.to_be_bytes().to_vec();
        b.extend_from_slice(&(value.len() as u16).to_be_bytes());
        b.extend_from_slice(value);
        b
    }

    /// RFC 2516 §5: a PADI carrying a Service-Name tag (empty, "any
    /// service") and a Host-Uniq tag.
    fn padi_fixture() -> Vec<u8> {
        let mut tags = tag(TAG_SERVICE_NAME, b"");
        tags.extend(tag(TAG_HOST_UNIQ, &[0xDE, 0xAD, 0xBE, 0xEF]));
        let mut b = vec![0x11, 0x09, 0x00, 0x00]; // Ver=1,Type=1, Code=PADI, session_id=0
        b.extend_from_slice(&(tags.len() as u16).to_be_bytes());
        b.extend_from_slice(&tags);
        b
    }

    /// RFC 2516 §5: a PADO reply naming the access concentrator and the
    /// service it's offering.
    fn pado_fixture() -> Vec<u8> {
        let mut tags = tag(TAG_SERVICE_NAME, b"internet");
        tags.extend(tag(TAG_AC_NAME, b"BRAS-1"));
        let mut b = vec![0x11, 0x07, 0x00, 0x00]; // Code=PADO
        b.extend_from_slice(&(tags.len() as u16).to_be_bytes());
        b.extend_from_slice(&tags);
        b
    }

    /// RFC 2516 §4.4: Session data — the 6-byte header, then a PPP
    /// frame (Protocol=0x0021 IPv4, uncompressed) as the payload.
    fn session_data_fixture(session_id: u16, ppp_payload: &[u8]) -> Vec<u8> {
        let mut b = vec![0x11, 0x00]; // Code=0x00 (session data)
        b.extend_from_slice(&session_id.to_be_bytes());
        b.extend_from_slice(&(ppp_payload.len() as u16).to_be_bytes());
        b.extend_from_slice(ppp_payload);
        b
    }

    #[test]
    fn padi_parses_tags_and_stops_terminal() {
        let bytes = padi_fixture();
        let m = meta(bytes.len());
        let parsed = Pppoe
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid PADI");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(VERSION), Some(&Value::U64(1)));
        assert_eq!(parsed.fields.get(TYPE), Some(&Value::U64(1)));
        assert_eq!(parsed.fields.get(CODE), Some(&Value::U64(0x09)));
        assert_eq!(parsed.fields.get(SESSION_ID), Some(&Value::U64(0)));
        assert_eq!(parsed.fields.get(SERVICE_NAME), Some(&Value::from("")));
        assert_eq!(
            parsed.fields.get(HOST_UNIQ),
            Some(&Value::from(&[0xDE, 0xAD, 0xBE, 0xEF][..]))
        );
    }

    #[test]
    fn pado_parses_service_name_and_ac_name() {
        let bytes = pado_fixture();
        let m = meta(bytes.len());
        let parsed = Pppoe
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid PADO");
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(CODE), Some(&Value::U64(0x07)));
        assert_eq!(
            parsed.fields.get(SERVICE_NAME),
            Some(&Value::from("internet"))
        );
        assert_eq!(parsed.fields.get(AC_NAME), Some(&Value::from("BRAS-1")));
    }

    #[test]
    fn session_data_stops_by_protocol_ppp_with_6_byte_header() {
        let bytes = session_data_fixture(0x1234, &[0x00, 0x21, 0x45, 0x00]);
        let m = meta(bytes.len());
        let parsed = Pppoe
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid session data");
        assert_eq!(parsed.header_len, 6);
        assert_eq!(parsed.hint, Hint::ByProtocol("ppp"));
        assert_eq!(parsed.fields.get(SESSION_ID), Some(&Value::U64(0x1234)));
        assert_eq!(parsed.fields.get(CODE), Some(&Value::U64(0)));
        assert_eq!(parsed.fields.get(SERVICE_NAME), None);
    }

    #[test]
    fn session_id_present_at_keys_depth() {
        let bytes = session_data_fixture(7, &[]);
        let m = meta(bytes.len());
        let parsed = Pppoe.parse(&bytes, &ctx(Depth::Keys, &m)).expect("valid");
        assert_eq!(parsed.fields.len(), 1);
        assert_eq!(parsed.fields.get(SESSION_ID), Some(&Value::U64(7)));
    }

    #[test]
    fn wrong_ver_type_declines() {
        let mut bytes = padi_fixture();
        bytes[0] = 0x21; // Ver=2, Type=1 — not PPPoE
        let m = meta(bytes.len());
        assert!(Pppoe.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn tag_length_running_past_the_declared_region_declines() {
        // Length says 4 bytes of tags follow, but the one tag inside
        // claims a value longer than what's left in that region.
        let mut b = vec![0x11, 0x09, 0x00, 0x00, 0x00, 0x04];
        b.extend_from_slice(&TAG_SERVICE_NAME.to_be_bytes());
        b.extend_from_slice(&0x00FFu16.to_be_bytes()); // claims 255 bytes, none present
        let m = meta(b.len());
        assert!(Pppoe.parse(&b, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn truncated_discovery_frames_decline() {
        let bytes = padi_fixture();
        let m = meta(bytes.len());
        let full_ctx = ctx(Depth::Full, &m);
        for n in 0..bytes.len() {
            assert!(
                Pppoe.parse(&bytes[..n], &full_ctx).is_err(),
                "prefix of {n}/{} header bytes must decline",
                bytes.len()
            );
        }
    }

    #[test]
    fn truncated_session_data_frames_decline() {
        let bytes = session_data_fixture(1, &[0xAA, 0xBB]);
        let m = meta(bytes.len());
        let full_ctx = ctx(Depth::Full, &m);
        for n in 0..6 {
            assert!(
                Pppoe.parse(&bytes[..n], &full_ctx).is_err(),
                "prefix of {n}/6 header bytes must decline"
            );
        }
    }
}
