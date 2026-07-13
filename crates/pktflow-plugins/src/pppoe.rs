//! PPPoE (11.5, RFC 2516) — the Discovery/Session multiplexer that carries
//! `ppp` (this domain's other half) over Ethernet, the standard access
//! mechanism for DSL/fiber broadband where a PPP session runs directly on
//! a shared Ethernet segment instead of a point-to-point serial line.
//!
//! **Header shape (RFC 2516 §4.1).** Both stages share one 6-byte fixed
//! header: `VER`/`TYPE` nibbles (each always `0x1` per §4.1 — a frame with
//! any other value is not PPPoE and is declined, not force-read), `CODE`,
//! `SESSION_ID`, `LENGTH` (payload byte count that follows).
//!
//! **Two stages, one header.** `CODE == 0x00` is Session data — the
//! `LENGTH`-bounded payload *is* a PPP frame (RFC 2516 §4.4 strips PPP's
//! own framing already, `ppp.rs`'s module doc), so this plugin stops at
//! the fixed 6-byte header and hands off `Hint::ByProtocol("ppp")`,
//! deliberately not slicing by `LENGTH` first — the same choice `udp`
//! makes with its own length field (06.4): a mismatched `LENGTH` shouldn't
//! silently truncate a well-formed inner frame. Every other `CODE` value
//! (PADI `0x09`, PADO `0x07`, PADR `0x19`, PADS `0x65`, PADT `0xa7`) is a
//! Discovery-stage message: the `LENGTH`-bounded region holds TAG-TLVs
//! (§5.1, `TAG_TYPE` u16 + `TAG_LENGTH` u16 + value), walked here for the
//! three tags with real diagnostic value — `Service-Name` (`0x0101`),
//! `AC-Name` (`0x0102`), `Host-Uniq` (`0x0103`) — everything else (vendor,
//! error, relay-session-id tags) is skipped by its own declared length
//! rather than decoded, Tier 1's "field-extraction ceiling" the same shape
//! D12 already applies to encrypted protocols, just for "not analytically
//! interesting yet" instead of "opaque". This stage stops `Terminal` after
//! consuming exactly the `LENGTH`-bounded tag region (no further layer, no
//! trailing-padding swallowed — the `dns`/`mdns` precedent, 06.6/11.12).
//!
//! **Stream identity.** One `pppoe` stream per `session_id` (shared
//! qualifier — the GRE-key/VXLAN-VNI/L2TPv3-session_id shape this whole
//! task keeps reusing, 06.5/11.5), parenting the `ppp -> ipv4/ipv6 -> ...`
//! inner stack. `ppp` itself forms no stream (translation layer, its own
//! module doc), so by the aggregator's nearest-outer-stream rule (05.3)
//! the inner IP conversation parents directly to this `pppoe` stream.
//! Discovery frames never surface `session_id` as a field at all (`parse`
//! below) — it's always the §5.2 `0x0000` placeholder before a session
//! exists, and keying on it would collapse unrelated PADI/PADO exchanges
//! from different peers onto one fake stream, so no `pppoe` stream forms
//! during Discovery (L2TPv3's control path applies the identical
//! reasoning to its own always-absent `session_id`).

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

/// §4.1: both nibbles of the first octet are fixed at 1 for PPPoE.
const PPPOE_VERSION: u8 = 1;
const PPPOE_TYPE: u8 = 1;
/// §4.4: the only Session-stage code; everything else is Discovery (§5).
const CODE_SESSION_DATA: u8 = 0x00;

/// §5.1: the three Discovery tags with real diagnostic value.
const TAG_SERVICE_NAME: u16 = 0x0101;
const TAG_AC_NAME: u16 = 0x0102;
const TAG_HOST_UNIQ: u16 = 0x0103;

static KEY: &[KeyField] = &[KeyField {
    a: SESSION_ID,
    b: None, // shared qualifier: one session stream per session_id
}];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: &[],
};

pub struct Pppoe;

impl LayerPlugin for Pppoe {
    fn name(&self) -> ProtocolName {
        "pppoe"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let ver_type = r.u8()?;
        let version = ver_type >> 4;
        let ty = ver_type & 0x0F;
        if version != PPPOE_VERSION || ty != PPPOE_TYPE {
            return Err(ParseError::Malformed("PPPoE: VER/TYPE must both be 1"));
        }
        let code = r.u8()?;
        let session_id = r.u16_be()?;
        let length = r.u16_be()?;

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Structural {
            fields.insert(VERSION, Value::U64(u64::from(version)));
            fields.insert(TYPE, Value::U64(u64::from(ty)));
            fields.insert(CODE, Value::U64(u64::from(code)));
        }

        if code == CODE_SESSION_DATA {
            // Session stage (§4.4): `session_id` is now the real,
            // established identifier — the only stage a `pppoe` stream
            // forms from. Discovery's `session_id` is always the
            // `0x0000` placeholder §5.2 mandates before a session
            // exists, so it is never surfaced as a field at all (not
            // even Structural) — exposing it would let unrelated PADI/
            // PADO exchanges from different peers collapse onto one
            // fake `session_id == 0` stream, exactly the "no phantom
            // streams" failure mode D12/PRD §4.B.4 already guards
            // against elsewhere in this task, and the same reasoning
            // L2TPv3's control path applies to its own always-absent
            // `session_id` (11.5).
            if ctx.depth() >= Depth::Keys {
                fields.insert(SESSION_ID, Value::U64(u64::from(session_id)));
            }
            return Ok(ParsedLayer {
                header_len: 6,
                fields,
                hint: Hint::ByProtocol("ppp"),
            });
        }

        // Discovery stage: the LENGTH-bounded tag region, walked for the
        // three recognized tags; unrecognized tags are skipped by their
        // own declared length (module doc).
        let tag_region = r.take(usize::from(length))?;
        if ctx.depth() >= Depth::Full {
            let mut t = ByteReader::new(tag_region);
            while t.remaining() >= 4 {
                let tag_type = t.u16_be()?;
                let tag_len = t.u16_be()?;
                let value = t.take(usize::from(tag_len))?;
                match tag_type {
                    TAG_SERVICE_NAME => {
                        fields.insert(
                            SERVICE_NAME,
                            Value::from(String::from_utf8_lossy(value).as_ref()),
                        );
                    }
                    TAG_AC_NAME => {
                        fields.insert(
                            AC_NAME,
                            Value::from(String::from_utf8_lossy(value).as_ref()),
                        );
                    }
                    TAG_HOST_UNIQ => {
                        fields.insert(HOST_UNIQ, Value::from(value));
                    }
                    _ => {}
                }
            }
        }

        Ok(ParsedLayer {
            header_len: 6 + tag_region.len(),
            fields,
            hint: Hint::Terminal,
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

    fn ctx(depth: Depth, meta: &PacketMeta) -> ParseCtx<'_> {
        ParseCtx::new(&[], depth, meta)
    }

    fn tag(tag_type: u16, value: &[u8]) -> Vec<u8> {
        let mut t = tag_type.to_be_bytes().to_vec();
        t.extend_from_slice(&(value.len() as u16).to_be_bytes());
        t.extend_from_slice(value);
        t
    }

    /// §5.2 PADI: a Service-Name tag (often empty, "any service"), an
    /// AC-Name tag, and a Host-Uniq tag a client attaches to match the
    /// eventual PADO reply to this request.
    fn padi_fixture(session_id: u16) -> Vec<u8> {
        let mut tags = tag(TAG_SERVICE_NAME, b"internet");
        tags.extend_from_slice(&tag(TAG_AC_NAME, b"access-concentrator-1"));
        tags.extend_from_slice(&tag(TAG_HOST_UNIQ, &[0xDE, 0xAD, 0xBE, 0xEF]));

        let mut b = vec![0x11, 0x09]; // VER=1 TYPE=1, CODE=PADI
        b.extend_from_slice(&session_id.to_be_bytes());
        b.extend_from_slice(&(tags.len() as u16).to_be_bytes());
        b.extend_from_slice(&tags);
        b
    }

    fn session_data_fixture(session_id: u16, payload: &[u8]) -> Vec<u8> {
        let mut b = vec![0x11, 0x00]; // VER=1 TYPE=1, CODE=Session Data
        b.extend_from_slice(&session_id.to_be_bytes());
        b.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        b.extend_from_slice(payload);
        b
    }

    #[test]
    fn padi_fixture_extracts_the_three_recognized_tags() {
        let bytes = padi_fixture(0);
        let m = meta(bytes.len());
        let parsed = Pppoe
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid PADI");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(CODE), Some(&Value::U64(0x09)));
        assert_eq!(
            parsed.fields.get(SESSION_ID),
            None,
            "Discovery's session_id is always the 0x0000 placeholder, never surfaced"
        );
        assert_eq!(
            parsed.fields.get(SERVICE_NAME),
            Some(&Value::from("internet"))
        );
        assert_eq!(
            parsed.fields.get(AC_NAME),
            Some(&Value::from("access-concentrator-1"))
        );
        assert_eq!(
            parsed.fields.get(HOST_UNIQ),
            Some(&Value::from(&[0xDE, 0xAD, 0xBE, 0xEF][..]))
        );
    }

    #[test]
    fn unrecognized_tags_are_skipped_not_faulted() {
        let mut tags = tag(TAG_SERVICE_NAME, b"voip");
        tags.extend_from_slice(&tag(0x0105, &[0x01, 0x02, 0x03])); // Vendor-Specific: skipped
        tags.extend_from_slice(&tag(0x0110, &[0xAA, 0xBB])); // Relay-Session-Id: skipped

        let mut b = vec![0x11, 0x07]; // PADO
        b.extend_from_slice(&7u16.to_be_bytes());
        b.extend_from_slice(&(tags.len() as u16).to_be_bytes());
        b.extend_from_slice(&tags);

        let m = meta(b.len());
        let parsed = Pppoe.parse(&b, &ctx(Depth::Full, &m)).expect("valid PADO");
        assert_eq!(parsed.header_len, b.len());
        assert_eq!(parsed.fields.get(SERVICE_NAME), Some(&Value::from("voip")));
        assert_eq!(parsed.fields.get(AC_NAME), None);
        assert_eq!(parsed.fields.get(HOST_UNIQ), None);
    }

    #[test]
    fn session_data_stops_after_the_fixed_header_and_routes_to_ppp() {
        let bytes = session_data_fixture(0x1234, &[0x00, 0x21, 0xDE, 0xAD]);
        let m = meta(bytes.len());
        let parsed = Pppoe
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid session data");
        assert_eq!(parsed.header_len, 6, "fixed header only, LENGTH not sliced");
        assert_eq!(parsed.hint, Hint::ByProtocol("ppp"));
        assert_eq!(parsed.fields.get(SESSION_ID), Some(&Value::U64(0x1234)));
        assert_eq!(parsed.fields.get(SERVICE_NAME), None);
    }

    #[test]
    fn wrong_ver_type_declines() {
        let mut bytes = padi_fixture(1);
        bytes[0] = 0x21; // VER=2, TYPE=1
        let m = meta(bytes.len());
        assert!(Pppoe.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn keys_depth_has_only_session_id() {
        let bytes = session_data_fixture(9, &[0x00, 0x21]);
        let m = meta(bytes.len());
        let parsed = Pppoe.parse(&bytes, &ctx(Depth::Keys, &m)).expect("valid");
        assert_eq!(parsed.fields.len(), 1);
        assert_eq!(parsed.fields.get(SESSION_ID), Some(&Value::U64(9)));
    }

    #[test]
    fn structural_depth_omits_tags() {
        let bytes = padi_fixture(2);
        let m = meta(bytes.len());
        let parsed = Pppoe
            .parse(&bytes, &ctx(Depth::Structural, &m))
            .expect("valid");
        assert_eq!(parsed.fields.get(CODE), Some(&Value::U64(0x09)));
        assert_eq!(parsed.fields.get(SERVICE_NAME), None);
    }

    #[test]
    fn truncated_fixed_header_declines() {
        let bytes = session_data_fixture(1, &[0xAA]);
        let m = meta(bytes.len());
        for n in 0..6 {
            let full_ctx = ctx(Depth::Full, &m);
            assert!(
                Pppoe.parse(&bytes[..n], &full_ctx).is_err(),
                "prefix of {n}/6 header bytes must decline"
            );
        }
    }

    #[test]
    fn truncated_discovery_tag_region_declines() {
        let bytes = padi_fixture(3);
        let m = meta(bytes.len());
        for n in 0..bytes.len() {
            let full_ctx = ctx(Depth::Full, &m);
            assert!(
                Pppoe.parse(&bytes[..n], &full_ctx).is_err(),
                "prefix of {n}/{} bytes must decline",
                bytes.len()
            );
        }
    }
}
