//! BGP-4 (11.4, RFC 4271): app-stream pattern (06.6, same shape as `dns`)
//! — BGP's real identity *is* its TCP session (port 179); a `bgp` child
//! stream just carries protocol-specific rollups, exactly like DNS-under-UDP
//! but ported to TCP (this plugin never checks `ctx.prev()` the way DNS
//! does for its length prefix, because BGP carries its own message
//! `Length` field directly in the fixed header instead of relying on
//! TCP-specific framing).
//!
//! Per D7 (no cross-packet reassembly) only the first BGP message present
//! in a segment is parsed — `header_len` is set from the message's own
//! `Length` field, not from `bytes.len()`, so a segment carrying a second,
//! coalesced message stops cleanly at the first message's boundary rather
//! than walking further (the same stance DNS-over-TCP takes, 06.6).
//!
//! Message types covered (RFC 4271 §4, plus RFC 2918's ROUTE-REFRESH):
//! OPEN (1), UPDATE (2), NOTIFICATION (3), KEEPALIVE (4), ROUTE-REFRESH (5).
//! Only OPEN and UPDATE carry Tier-1 fields beyond the common header
//! (11.4's field table); NOTIFICATION/KEEPALIVE/ROUTE-REFRESH bodies are
//! still consumed for `header_len` correctness (bounded by `Length`, so
//! draining them isn't even required) but expose nothing further, the same
//! stance `ospf` takes on Link State Request/Acknowledgment (11.4).
//!
//! The 16-byte Marker (RFC 4271 §4.1) is read and discarded, not validated
//! against the all-ones invariant — a passive dissector has no BGP session
//! state to detect the connection-collision case the Marker exists for, the
//! same "consumed for framing, not verified" stance `vrrp`/`igmp` already
//! take on their own checksums (11.4/06.3).
//!
//! `next_hop` is read from whichever of UPDATE's path attributes exposes it
//! first: the classic NEXT_HOP attribute (type 3, RFC 4271 §5.1.3, always
//! a 4-byte IPv4 address) or, if that's absent, MP_REACH_NLRI (type 14,
//! RFC 4760 §3) — read leniently (a malformed MP_REACH_NLRI value just
//! means no `next_hop`, not a declined message, since it's one optional
//! attribute among possibly several, not framing-critical).

use pktflow_core::{
    ByteReader, Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx,
    ParseError, ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId, StreamIdentity, Value,
};

const APP: FieldName = "app";
const MSG_TYPE: FieldName = "msg_type";
const LENGTH: FieldName = "length";
const MY_AS: FieldName = "my_as";
const HOLD_TIME: FieldName = "hold_time";
const BGP_IDENTIFIER: FieldName = "bgp_identifier";
const WITHDRAWN_ROUTES: FieldName = "withdrawn_routes";
const NLRI: FieldName = "nlri";
const NEXT_HOP: FieldName = "next_hop";

/// RFC 4271 §4.1: Marker(16) + Length(2) + Type(1).
const MARKER_LEN: usize = 16;
const HEADER_LEN: usize = 19;
/// RFC 4271 §4.1: a BGP message is never longer than this.
const MAX_LENGTH: usize = 4096;

/// RFC 4271 §4: BGP-4 message types.
const TYPE_OPEN: u8 = 1;
const TYPE_UPDATE: u8 = 2;

/// RFC 4271 §4.2: the only version this plugin (BGP-**4**) understands.
const BGP_VERSION_4: u8 = 4;

/// RFC 4271 §4.3: Attribute Flags bit 0x10 — Extended Length (2-byte
/// attribute length instead of 1).
const ATTR_EXTENDED_LENGTH: u8 = 0x10;
/// RFC 4271 §5.1.3: NEXT_HOP path attribute type code.
const ATTR_NEXT_HOP: u8 = 3;
/// RFC 4760 §3: MP_REACH_NLRI path attribute type code.
const ATTR_MP_REACH_NLRI: u8 = 14;

static KEY: &[KeyField] = &[KeyField { a: APP, b: None }];
static ROLLUPS: &[RollupSpec] = &[
    RollupSpec {
        field: MSG_TYPE,
        kind: RollupKind::Accumulate,
    },
    RollupSpec {
        field: MY_AS,
        // A session renegotiating its peer AS mid-stream is itself
        // interesting; first/last surfaces that instead of hiding it
        // behind a growing distinct-value set (11.4).
        kind: RollupKind::Sample,
    },
];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: ROLLUPS,
};

/// Walks a withdrawn-routes or NLRI list: each entry is `<length (bits,
/// 1 byte)><prefix (ceil(length/8) bytes)>` (RFC 4271 §4.3). Every entry is
/// kept as its raw wire bytes (length byte + prefix octets) — a lossless,
/// self-describing representation rather than inventing a CIDR string
/// format this plugin has no authority to define.
fn parse_prefix_list(bytes: &[u8]) -> Result<Vec<Value>, ParseError> {
    let mut r = ByteReader::new(bytes);
    let mut out = Vec::new();
    while r.remaining() > 0 {
        let prefix_len_bits = r.u8()?;
        let prefix_byte_len = usize::from(prefix_len_bits).div_ceil(8);
        if prefix_byte_len > 4 {
            return Err(ParseError::Malformed("BGP: prefix length exceeds 32 bits"));
        }
        let addr = r.take(prefix_byte_len)?;
        let mut raw = Vec::with_capacity(1 + prefix_byte_len);
        raw.push(prefix_len_bits);
        raw.extend_from_slice(addr);
        out.push(Value::from(raw.as_slice()));
    }
    Ok(out)
}

/// RFC 4760 §3: AFI(2) + SAFI(1) + Next Hop Length(1) + Next Hop(variable).
/// Lenient by design (module doc): a malformed value here just means no
/// next hop is reported, not a declined UPDATE.
fn mp_reach_next_hop(value: &[u8]) -> Option<Vec<u8>> {
    let mut r = ByteReader::new(value);
    let _afi = r.u16_be().ok()?;
    let _safi = r.u8().ok()?;
    let nh_len = usize::from(r.u8().ok()?);
    r.take(nh_len).ok().map(<[u8]>::to_vec)
}

/// Walks UPDATE's Path Attributes (RFC 4271 §4.3), each
/// `<flags(1)><type(1)><length(1 or 2, Extended Length bit)><value>`, and
/// returns the first `next_hop` found (module doc: classic NEXT_HOP wins
/// over MP_REACH_NLRI). Every attribute is walked regardless — an
/// attribute whose declared length runs past `bytes` is truncated input,
/// declined like any other boundary violation.
fn extract_next_hop(bytes: &[u8]) -> Result<Option<Vec<u8>>, ParseError> {
    let mut r = ByteReader::new(bytes);
    let mut next_hop = None;
    while r.remaining() > 0 {
        let flags = r.u8()?;
        let type_code = r.u8()?;
        let length = if flags & ATTR_EXTENDED_LENGTH != 0 {
            usize::from(r.u16_be()?)
        } else {
            usize::from(r.u8()?)
        };
        let value = r.take(length)?;
        if next_hop.is_none() {
            match type_code {
                ATTR_NEXT_HOP => next_hop = Some(value.to_vec()),
                ATTR_MP_REACH_NLRI => next_hop = mp_reach_next_hop(value),
                _ => {}
            }
        }
    }
    Ok(next_hop)
}

pub struct Bgp;

impl LayerPlugin for Bgp {
    fn name(&self) -> ProtocolName {
        "bgp"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let _marker = r.take(MARKER_LEN)?;
        let length = usize::from(r.u16_be()?);
        let msg_type = r.u8()?;
        if !(HEADER_LEN..=MAX_LENGTH).contains(&length) {
            return Err(ParseError::Malformed("BGP: length out of range"));
        }
        // Bounding the body to the message's own `Length` (not
        // `bytes.len()`) is what makes a coalesced second message in the
        // same segment stay untouched (module doc).
        let body = r.take(length - HEADER_LEN)?;

        let mut my_as = None;
        let mut hold_time = None;
        let mut bgp_identifier: Option<&[u8]> = None;
        let mut withdrawn_routes = Vec::new();
        let mut nlri = Vec::new();
        let mut next_hop = None;

        match msg_type {
            TYPE_OPEN => {
                let mut br = ByteReader::new(body);
                let version = br.u8()?;
                if version != BGP_VERSION_4 {
                    return Err(ParseError::Malformed("BGP: unsupported OPEN version"));
                }
                let as_num = br.u16_be()?;
                let ht = br.u16_be()?;
                let identifier = br.take(4)?;
                let opt_parm_len = br.u8()?;
                // Walked for internal-boundary honesty, not surfaced —
                // Optional Parameters aren't in 11.4's Tier-1 field list.
                br.take(usize::from(opt_parm_len))?;
                my_as = Some(u64::from(as_num));
                hold_time = Some(u64::from(ht));
                bgp_identifier = Some(identifier);
            }
            TYPE_UPDATE => {
                let mut br = ByteReader::new(body);
                let withdrawn_len = usize::from(br.u16_be()?);
                let withdrawn_bytes = br.take(withdrawn_len)?;
                withdrawn_routes = parse_prefix_list(withdrawn_bytes)?;

                let path_attr_len = usize::from(br.u16_be()?);
                let path_attrs = br.take(path_attr_len)?;
                next_hop = extract_next_hop(path_attrs)?;

                let nlri_bytes = br.take(br.remaining())?;
                nlri = parse_prefix_list(nlri_bytes)?;
            }
            _ => {}
        }

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(APP, Value::from("bgp"));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(MSG_TYPE, Value::U64(u64::from(msg_type)));
            fields.insert(LENGTH, Value::U64(length as u64));
        }
        if ctx.depth() >= Depth::Full {
            if let Some(v) = my_as {
                fields.insert(MY_AS, Value::U64(v));
            }
            if let Some(v) = hold_time {
                fields.insert(HOLD_TIME, Value::U64(v));
            }
            if let Some(v) = bgp_identifier {
                fields.insert(BGP_IDENTIFIER, Value::from(v));
            }
            if msg_type == TYPE_UPDATE {
                fields.insert(WITHDRAWN_ROUTES, Value::List(withdrawn_routes));
                fields.insert(NLRI, Value::List(nlri));
                if let Some(nh) = next_hop {
                    fields.insert(NEXT_HOP, Value::from(nh.as_slice()));
                }
            }
        }

        Ok(ParsedLayer {
            header_len: length,
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::TcpPort(179)]
    }

    fn stream_identity(&self) -> Option<&StreamIdentity> {
        Some(&IDENTITY)
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use pktflow_core::{LayerRecord, LinkType, PacketMeta};

    use super::*;

    fn meta(len: usize) -> PacketMeta {
        PacketMeta {
            timestamp: SystemTime::UNIX_EPOCH,
            caplen: len,
            origlen: len,
            link_type: LinkType::ETHERNET,
        }
    }

    fn ctx<'a>(outer: &'a [LayerRecord], depth: Depth, m: &'a PacketMeta) -> ParseCtx<'a> {
        ParseCtx::new(outer, depth, m)
    }

    fn tcp_predecessor() -> Vec<LayerRecord> {
        vec![LayerRecord {
            protocol: "tcp",
            offset: 34,
            header_len: 20,
            fields: FieldMap::new(),
        }]
    }

    /// RFC 4271 §4.1 common header: Marker (all-ones) + Length + Type.
    fn header(msg_type: u8, body: &[u8]) -> Vec<u8> {
        let mut b = vec![0xFFu8; MARKER_LEN];
        let length = (HEADER_LEN + body.len()) as u16;
        b.extend_from_slice(&length.to_be_bytes());
        b.push(msg_type);
        b.extend_from_slice(body);
        b
    }

    /// RFC 4271 §4.2: version 4, AS 65001, hold time 180, a router id, no
    /// optional parameters.
    fn open_fixture() -> Vec<u8> {
        let mut body = vec![4];
        body.extend_from_slice(&65001u16.to_be_bytes());
        body.extend_from_slice(&180u16.to_be_bytes());
        body.extend_from_slice(&[10, 0, 0, 1]);
        body.push(0); // Opt Parm Len = 0
        header(TYPE_OPEN, &body)
    }

    /// RFC 4271 §4.3: one withdrawn route (10.0.0.0/8), a NEXT_HOP path
    /// attribute (10.0.0.2), and one NLRI prefix (192.0.2.0/24).
    fn update_fixture() -> Vec<u8> {
        let mut body = Vec::new();
        let withdrawn = [8u8, 10]; // 10.0.0.0/8
        body.extend_from_slice(&(withdrawn.len() as u16).to_be_bytes());
        body.extend_from_slice(&withdrawn);

        // ORIGIN (type 1, flags: well-known transitive), value IGP (0).
        let mut attrs = vec![0x40, 1, 1, 0];
        // NEXT_HOP (type 3), value 10.0.0.2.
        attrs.extend_from_slice(&[0x40, 3, 4]);
        attrs.extend_from_slice(&[10, 0, 0, 2]);
        body.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
        body.extend_from_slice(&attrs);

        // NLRI: 192.0.2.0/24.
        body.extend_from_slice(&[24, 192, 0, 2]);

        header(TYPE_UPDATE, &body)
    }

    fn keepalive_fixture() -> Vec<u8> {
        header(4, &[])
    }

    #[test]
    fn open_message_parses_exactly() {
        let bytes = open_fixture();
        let m = meta(bytes.len());
        let outer = tcp_predecessor();
        let parsed = Bgp
            .parse(&bytes, &ctx(&outer, Depth::Full, &m))
            .expect("valid OPEN");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(APP), Some(&Value::from("bgp")));
        assert_eq!(parsed.fields.get(MSG_TYPE), Some(&Value::U64(1)));
        assert_eq!(parsed.fields.get(LENGTH), Some(&Value::U64(29)));
        assert_eq!(parsed.fields.get(MY_AS), Some(&Value::U64(65001)));
        assert_eq!(parsed.fields.get(HOLD_TIME), Some(&Value::U64(180)));
        assert_eq!(
            parsed.fields.get(BGP_IDENTIFIER),
            Some(&Value::from(&[10u8, 0, 0, 1][..]))
        );
    }

    #[test]
    fn update_message_parses_withdrawn_nlri_and_next_hop() {
        let bytes = update_fixture();
        let m = meta(bytes.len());
        let outer = tcp_predecessor();
        let parsed = Bgp
            .parse(&bytes, &ctx(&outer, Depth::Full, &m))
            .expect("valid UPDATE");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.fields.get(MSG_TYPE), Some(&Value::U64(2)));
        assert_eq!(
            parsed.fields.get(WITHDRAWN_ROUTES),
            Some(&Value::List(vec![Value::from(&[8u8, 10][..])]))
        );
        assert_eq!(
            parsed.fields.get(NLRI),
            Some(&Value::List(vec![Value::from(&[24u8, 192, 0, 2][..])]))
        );
        assert_eq!(
            parsed.fields.get(NEXT_HOP),
            Some(&Value::from(&[10u8, 0, 0, 2][..]))
        );
    }

    #[test]
    fn keepalive_message_has_no_body_fields() {
        let bytes = keepalive_fixture();
        let m = meta(bytes.len());
        let outer = tcp_predecessor();
        let parsed = Bgp
            .parse(&bytes, &ctx(&outer, Depth::Full, &m))
            .expect("valid KEEPALIVE");
        assert_eq!(parsed.header_len, HEADER_LEN);
        assert_eq!(parsed.fields.get(MSG_TYPE), Some(&Value::U64(4)));
        assert_eq!(parsed.fields.get(MY_AS), None);
    }

    #[test]
    fn keys_depth_has_only_app() {
        let bytes = open_fixture();
        let m = meta(bytes.len());
        let outer = tcp_predecessor();
        let parsed = Bgp
            .parse(&bytes, &ctx(&outer, Depth::Keys, &m))
            .expect("valid OPEN");
        assert_eq!(parsed.fields.len(), 1);
        assert_eq!(parsed.fields.get(APP), Some(&Value::from("bgp")));
    }

    #[test]
    fn structural_depth_omits_open_body_fields() {
        let bytes = open_fixture();
        let m = meta(bytes.len());
        let outer = tcp_predecessor();
        let parsed = Bgp
            .parse(&bytes, &ctx(&outer, Depth::Structural, &m))
            .expect("valid OPEN");
        assert_eq!(parsed.fields.get(MY_AS), None);
        assert_eq!(parsed.fields.get(MSG_TYPE), Some(&Value::U64(1)));
    }

    #[test]
    fn a_coalesced_second_message_is_left_untouched() {
        let mut bytes = keepalive_fixture();
        bytes.extend_from_slice(&keepalive_fixture());
        let m = meta(bytes.len());
        let outer = tcp_predecessor();
        let parsed = Bgp
            .parse(&bytes, &ctx(&outer, Depth::Full, &m))
            .expect("first KEEPALIVE parses");
        assert_eq!(parsed.header_len, HEADER_LEN);
        assert_eq!(parsed.hint, Hint::Terminal);
    }

    #[test]
    fn length_below_header_size_declines() {
        let mut bytes = keepalive_fixture();
        bytes[16] = 0;
        bytes[17] = 10; // Length = 10, below the 19-byte header floor
        let m = meta(bytes.len());
        let outer = tcp_predecessor();
        assert!(Bgp.parse(&bytes, &ctx(&outer, Depth::Full, &m)).is_err());
    }

    #[test]
    fn unsupported_open_version_declines() {
        let mut bytes = open_fixture();
        bytes[19] = 3; // version 3, pre-RFC 4271
        let m = meta(bytes.len());
        let outer = tcp_predecessor();
        assert!(Bgp.parse(&bytes, &ctx(&outer, Depth::Full, &m)).is_err());
    }

    #[test]
    fn withdrawn_route_longer_than_32_bits_declines() {
        let mut body = Vec::new();
        let withdrawn = [33u8]; // prefix length in bits > 32: impossible for IPv4
        body.extend_from_slice(&(withdrawn.len() as u16).to_be_bytes());
        body.extend_from_slice(&withdrawn);
        body.extend_from_slice(&0u16.to_be_bytes()); // no path attributes
        let bytes = header(TYPE_UPDATE, &body);
        let m = meta(bytes.len());
        let outer = tcp_predecessor();
        assert!(Bgp.parse(&bytes, &ctx(&outer, Depth::Full, &m)).is_err());
    }

    #[test]
    fn truncated_open_frames_decline() {
        let bytes = open_fixture();
        let m = meta(bytes.len());
        let outer = tcp_predecessor();
        for n in 0..bytes.len() {
            let full_ctx = ctx(&outer, Depth::Full, &m);
            assert!(
                Bgp.parse(&bytes[..n], &full_ctx).is_err(),
                "prefix of {n}/{} bytes must decline",
                bytes.len()
            );
        }
    }

    #[test]
    fn truncated_update_frames_decline() {
        let bytes = update_fixture();
        let m = meta(bytes.len());
        let outer = tcp_predecessor();
        for n in 0..bytes.len() {
            let full_ctx = ctx(&outer, Depth::Full, &m);
            assert!(
                Bgp.parse(&bytes[..n], &full_ctx).is_err(),
                "prefix of {n}/{} bytes must decline",
                bytes.len()
            );
        }
    }
}
