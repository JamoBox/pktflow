//! VRRP (11.4: RFC 5798 VRRPv3, RFC 3768 VRRPv2 — IANA protocol number 112):
//! the group-beacon pattern GRE's `key`/VXLAN's `vni` already established
//! (06.5) — one **VRRP group** stream per virtual router id (VRID),
//! aggregating every speaker's advertisements for that group regardless of
//! which physical router currently holds master.
//!
//! One plugin covers both wire versions, disambiguated by the `version`
//! nibble in the first byte (the same "version field picks the layout"
//! shape `ospf` uses for OSPFv2/v3, 11.4):
//!
//! - **v2** (RFC 3768 §5.1): `Auth Type` (1 byte) + `Adver Int` (1 byte,
//!   whole seconds) in place of v3's packed reserved/interval word, IPv4
//!   addresses only, and an 8-byte Authentication Data trailer that is
//!   *always structurally present* even though RFC 3768 deprecates its use
//!   (receivers of Auth Type 0 MUST still expect the bytes, just ignore
//!   their content) — walked here to keep `header_len` correct, not
//!   surfaced as a field (not in Tier 1's field list).
//! - **v3** (RFC 5798 §5.2): a 4-bit reserved nibble + 12-bit
//!   `Max Adver Int` in centiseconds, no authentication trailer, and
//!   dual-stack: it runs directly over IPv4 *or* IPv6 with an identical
//!   header, distinguishing the address width (4 vs 16 bytes) only by
//!   which network layer carried it. VRRP has no self-describing
//!   address-family field for this, so v3 reads it back from its direct
//!   predecessor layer's protocol name (`ctx.prev()`, FR-17's cross-layer
//!   read, same mechanism `mld`/`ndp` use for icmpv6's `rest_of_header` —
//!   here the "cross-layer field" is simply which plugin ran immediately
//!   before this one). Absent or unrecognized predecessor falls back to
//!   the IPv4 width, the deployment-majority case and the only width v2
//!   ever had.
//!
//! `adver_int` is exposed in the wire's own unit (whole seconds for v2,
//! centiseconds for v3) rather than normalized to one unit — the two RFCs
//! disagree on resolution and inventing a shared unit here would be a
//! conversion this plugin has no authority to make.
//!
//! Checksum (RFC 5798 §5.2.8, IPv4-style ones' complement over the VRRP
//! message with a pseudo-header for v3) is consumed for `header_len`
//! correctness but not verified or surfaced — the same stance `igmp`
//! already takes on its own checksum field (06.3).

use pktflow_core::{
    ByteReader, Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx,
    ParseError, ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId, StreamIdentity, Value,
};

const VRID: FieldName = "vrid";
const VERSION: FieldName = "version";
const TYPE: FieldName = "type";
const PRIORITY: FieldName = "priority";
const COUNT_IP_ADDRS: FieldName = "count_ip_addrs";
const ADVER_INT: FieldName = "adver_int";
const IP_ADDRESSES: FieldName = "ip_addresses";

/// The only VRRP packet type either RFC defines; a receiver of anything
/// else MUST discard (RFC 3768 §5.1, RFC 5798 §5.2.2).
const TYPE_ADVERTISEMENT: u8 = 1;

/// RFC 3768's fixed 8-byte Authentication Data trailer (2 x 4-byte words),
/// present in every v2 packet regardless of Auth Type's value.
const V2_AUTH_DATA_LEN: usize = 8;

static KEY: &[KeyField] = &[KeyField {
    a: VRID,
    b: None, // shared qualifier: one stream per virtual router id
}];
static ROLLUPS: &[RollupSpec] = &[RollupSpec {
    field: PRIORITY,
    kind: RollupKind::Accumulate,
}];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: ROLLUPS,
};

/// v3's dual-stack address width: VRRP itself never names its address
/// family, so it's read back from whichever network-layer plugin ran
/// immediately before this one (module doc). v2 is IPv4-only regardless.
fn address_len(version: u8, ctx: &ParseCtx) -> usize {
    if version == 3 && ctx.prev().map(|l| l.protocol) == Some("ipv6") {
        16
    } else {
        4
    }
}

pub struct Vrrp;

impl LayerPlugin for Vrrp {
    fn name(&self) -> ProtocolName {
        "vrrp"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let version_type = r.u8()?;
        let version = version_type >> 4;
        let vrrp_type = version_type & 0x0F;
        if version != 2 && version != 3 {
            return Err(ParseError::Malformed("VRRP: unsupported version"));
        }
        if vrrp_type != TYPE_ADVERTISEMENT {
            return Err(ParseError::Malformed("VRRP: unknown packet type"));
        }

        let vrid = r.u8()?;
        let priority = r.u8()?;
        let count_ip_addrs = r.u8()?;

        let adver_int = if version == 2 {
            let _auth_type = r.u8()?;
            u64::from(r.u8()?)
        } else {
            let word = r.u16_be()?;
            u64::from(word & 0x0FFF)
        };
        let _checksum = r.u16_be()?;

        let addr_len = address_len(version, ctx);
        let mut ip_addresses = Vec::with_capacity(usize::from(count_ip_addrs));
        for _ in 0..count_ip_addrs {
            ip_addresses.push(Value::from(r.take(addr_len)?));
        }

        if version == 2 {
            r.take(V2_AUTH_DATA_LEN)?;
        }

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(VRID, Value::U64(u64::from(vrid)));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(VERSION, Value::U64(u64::from(version)));
            fields.insert(TYPE, Value::U64(u64::from(vrrp_type)));
            fields.insert(PRIORITY, Value::U64(u64::from(priority)));
            fields.insert(COUNT_IP_ADDRS, Value::U64(u64::from(count_ip_addrs)));
            fields.insert(ADVER_INT, Value::U64(adver_int));
        }
        if ctx.depth() >= Depth::Full {
            fields.insert(IP_ADDRESSES, Value::List(ip_addresses));
        }

        Ok(ParsedLayer {
            header_len: bytes.len() - r.remaining(),
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::IpProtocol(112)]
    }

    fn stream_identity(&self) -> Option<&StreamIdentity> {
        Some(&IDENTITY)
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use pktflow_core::{FieldMap as CoreFieldMap, LayerRecord, LinkType, PacketMeta};

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

    fn ipv6_predecessor() -> Vec<LayerRecord> {
        vec![LayerRecord {
            protocol: "ipv6",
            offset: 14,
            header_len: 40,
            fields: CoreFieldMap::new(),
        }]
    }

    fn ipv4_predecessor() -> Vec<LayerRecord> {
        vec![LayerRecord {
            protocol: "ipv4",
            offset: 14,
            header_len: 20,
            fields: CoreFieldMap::new(),
        }]
    }

    /// RFC 3768 §5.1: version 2, VRID 51, priority 100, one IPv4 address,
    /// Auth Type 0 (none), Adver Int 1s, 8 zeroed auth-data bytes.
    fn v2_fixture() -> Vec<u8> {
        let mut b = vec![0x21, 51, 100, 1, 0x00, 1, 0x00, 0x00];
        b.extend_from_slice(&[192, 168, 1, 1]);
        b.extend_from_slice(&[0; V2_AUTH_DATA_LEN]);
        b
    }

    /// RFC 5798 §5.2: version 3, VRID 7, priority 255 (address owner), two
    /// IPv4 addresses, Max Adver Int 100 centiseconds.
    fn v3_fixture(count: u8, addr_len: usize) -> Vec<u8> {
        let mut b = vec![0x31, 7, 255, count, 0x00, 100, 0x00, 0x00];
        for i in 0..count {
            b.extend(std::iter::repeat_n(0xA0 + i, addr_len));
        }
        b
    }

    #[test]
    fn v2_advertisement_parses_exactly() {
        let bytes = v2_fixture();
        let m = meta(bytes.len());
        let empty = ipv4_predecessor();
        let parsed = Vrrp
            .parse(&bytes, &ctx(&empty, Depth::Full, &m))
            .expect("valid VRRPv2 advertisement");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(VRID), Some(&Value::U64(51)));
        assert_eq!(parsed.fields.get(VERSION), Some(&Value::U64(2)));
        assert_eq!(parsed.fields.get(TYPE), Some(&Value::U64(1)));
        assert_eq!(parsed.fields.get(PRIORITY), Some(&Value::U64(100)));
        assert_eq!(parsed.fields.get(COUNT_IP_ADDRS), Some(&Value::U64(1)));
        assert_eq!(parsed.fields.get(ADVER_INT), Some(&Value::U64(1)));
        assert_eq!(
            parsed.fields.get(IP_ADDRESSES),
            Some(&Value::List(vec![Value::from(&[192u8, 168, 1, 1][..])]))
        );
    }

    #[test]
    fn v3_ipv4_advertisement_with_two_addresses() {
        let bytes = v3_fixture(2, 4);
        let m = meta(bytes.len());
        let outer = ipv4_predecessor();
        let parsed = Vrrp
            .parse(&bytes, &ctx(&outer, Depth::Full, &m))
            .expect("valid VRRPv3/IPv4 advertisement");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.fields.get(VERSION), Some(&Value::U64(3)));
        assert_eq!(parsed.fields.get(ADVER_INT), Some(&Value::U64(100)));
        assert_eq!(
            parsed.fields.get(IP_ADDRESSES),
            Some(&Value::List(vec![
                Value::from(&[0xA0u8, 0xA0, 0xA0, 0xA0][..]),
                Value::from(&[0xA1u8, 0xA1, 0xA1, 0xA1][..]),
            ]))
        );
    }

    #[test]
    fn v3_over_ipv6_reads_sixteen_byte_addresses() {
        let bytes = v3_fixture(1, 16);
        let m = meta(bytes.len());
        let outer = ipv6_predecessor();
        let parsed = Vrrp
            .parse(&bytes, &ctx(&outer, Depth::Full, &m))
            .expect("valid VRRPv3/IPv6 advertisement");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(
            parsed.fields.get(IP_ADDRESSES),
            Some(&Value::List(vec![Value::from(&[0xA0u8; 16][..])]))
        );
    }

    #[test]
    fn v3_with_no_predecessor_assumes_ipv4_width() {
        let bytes = v3_fixture(1, 4);
        let m = meta(bytes.len());
        let parsed = Vrrp
            .parse(&bytes, &ctx(&[], Depth::Full, &m))
            .expect("valid VRRPv3 advertisement");
        assert_eq!(parsed.header_len, bytes.len());
    }

    #[test]
    fn keys_depth_has_only_vrid() {
        let bytes = v2_fixture();
        let m = meta(bytes.len());
        let outer = ipv4_predecessor();
        let parsed = Vrrp
            .parse(&bytes, &ctx(&outer, Depth::Keys, &m))
            .expect("valid VRRPv2 advertisement");
        assert_eq!(parsed.fields.len(), 1);
        assert_eq!(parsed.fields.get(VRID), Some(&Value::U64(51)));
    }

    #[test]
    fn structural_depth_omits_ip_addresses() {
        let bytes = v2_fixture();
        let m = meta(bytes.len());
        let outer = ipv4_predecessor();
        let parsed = Vrrp
            .parse(&bytes, &ctx(&outer, Depth::Structural, &m))
            .expect("valid VRRPv2 advertisement");
        assert_eq!(parsed.fields.get(IP_ADDRESSES), None);
        assert_eq!(parsed.fields.get(PRIORITY), Some(&Value::U64(100)));
    }

    #[test]
    fn unsupported_version_declines() {
        let mut bytes = v2_fixture();
        bytes[0] = 0x41; // version 4, type 1
        let m = meta(bytes.len());
        let outer = ipv4_predecessor();
        assert!(Vrrp.parse(&bytes, &ctx(&outer, Depth::Full, &m)).is_err());
    }

    #[test]
    fn unknown_packet_type_declines() {
        let mut bytes = v2_fixture();
        bytes[0] = 0x22; // version 2, type 2 (undefined)
        let m = meta(bytes.len());
        let outer = ipv4_predecessor();
        assert!(Vrrp.parse(&bytes, &ctx(&outer, Depth::Full, &m)).is_err());
    }

    #[test]
    fn zero_addresses_is_valid() {
        let bytes = v3_fixture(0, 4);
        let m = meta(bytes.len());
        let outer = ipv4_predecessor();
        let parsed = Vrrp
            .parse(&bytes, &ctx(&outer, Depth::Full, &m))
            .expect("zero-address advertisement still parses");
        assert_eq!(parsed.fields.get(IP_ADDRESSES), Some(&Value::List(vec![])));
    }

    #[test]
    fn truncated_v2_frames_decline() {
        let bytes = v2_fixture();
        let m = meta(bytes.len());
        let outer = ipv4_predecessor();
        for n in 0..bytes.len() {
            let full_ctx = ctx(&outer, Depth::Full, &m);
            assert!(
                Vrrp.parse(&bytes[..n], &full_ctx).is_err(),
                "prefix of {n}/{} bytes must decline",
                bytes.len()
            );
        }
    }

    #[test]
    fn truncated_v3_frames_decline() {
        let bytes = v3_fixture(2, 4);
        let m = meta(bytes.len());
        let outer = ipv4_predecessor();
        for n in 0..bytes.len() {
            let full_ctx = ctx(&outer, Depth::Full, &m);
            assert!(
                Vrrp.parse(&bytes[..n], &full_ctx).is_err(),
                "prefix of {n}/{} bytes must decline",
                bytes.len()
            );
        }
    }
}
