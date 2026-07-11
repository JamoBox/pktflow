//! OSPF (11.4: OSPFv2 RFC 2328, OSPFv3 RFC 5340 — IANA IP protocol number
//! 89): one plugin covers both wire versions, disambiguated by the
//! `version` byte at the very front of the common header (RFC 2328
//! Appendix A.3.1; RFC 5340 Appendix A.3.1) — the same "version field
//! picks the layout" shape `vrrp` uses for VRRPv2/v3 (11.4).
//!
//! ## Framing: `packet_length` is authoritative, not `bytes.len()`
//!
//! Both RFCs give the common header a self-declared `packet_length` field
//! (bytes 2-3, counted from the `version` byte, "the length of the
//! protocol packet in bytes, including the OSPF header" — RFC 2328 A.3.1;
//! RFC 5340 A.3.1). This plugin treats it the same way `dns` treats
//! DNS-over-TCP's 2-byte length prefix (06.6): the authoritative end of
//! *this* message, bounded via `ByteReader::take` rather than trusted-but-
//! unverified. That matters here specifically because two Tier-1-adjacent
//! structures — Hello's `neighbors` list and (unsurfaced) DBD's trailing
//! LSA-header inventory — have no count field of their own; both RFCs
//! describe them as running "to the end of the packet", which only
//! `packet_length` can mean (`bytes` itself may carry link-layer padding
//! or other trailing junk past the real message, the same reason `hsrp`/
//! `vrrp` document for their own fixed-length trailers). `header_len` is
//! set to `packet_length` directly rather than derived from how far
//! parsing walked, so it stays correct even for message types this
//! plugin declines to look inside (Link State Request/Acknowledgment).
//!
//! ## Version differences
//!
//! - **Common header** (RFC 2328 A.3.1 vs RFC 5340 A.3.1): v2 is 24 bytes
//!   and ends with a 2-byte `AuType` + 8-byte `Authentication` trailer
//!   (cleartext-password-only in the base RFC; the same "sent in the
//!   clear by the protocol itself" stance `hsrp`/`vrrp` already take on
//!   their own auth fields, D12). v3 is 16 bytes and replaces that
//!   trailer with a 1-byte `Instance ID` + 1 reserved byte — OSPFv3 has
//!   no protocol-native authentication of its own, relying on IPsec
//!   instead. Neither AuType/Authentication nor Instance ID/Reserved is
//!   in 11.4's field list; both are consumed only to keep the cursor
//!   aligned ahead of the type-specific body.
//! - **Hello** (RFC 2328 A.3.2 vs RFC 5340 A.3.2): v2 carries a 4-byte
//!   Network Mask and identifies the DR/BDR by *IP interface address*; v3
//!   drops the mask entirely (OSPFv3 runs per-link, not per-subnet) and
//!   widens `Options` from 1 byte to 3, but otherwise keeps the same
//!   shape, now identifying the DR/BDR by *Router ID* instead — both
//!   still 4-byte fields either way, so `designated_router`'s width is
//!   version-independent even though its meaning shifts.
//! - **Database Description** (RFC 2328 A.3.3 vs RFC 5340 A.3.3): same
//!   `interface_mtu`/`dd_sequence` pair either version, v3 again widening
//!   `Options` to 3 bytes and adding a leading reserved byte ahead of it.
//!   Both versions trail with an inventory of the sender's LSA headers,
//!   running "to the end of the packet" the same way Hello's neighbor
//!   list does — but that inventory isn't in 11.4's field list for
//!   `ospf` (only `lsu`'s `lsa_headers` is), so this plugin doesn't walk
//!   it; `header_len` is already correct via `packet_length` regardless
//!   (module doc above).
//! - **Link State Update** (RFC 2328 A.3.5 vs RFC 5340 A.3.5): identical
//!   shape both versions — a 4-byte LSA count followed by that many LSAs,
//!   each opening with a 20-byte LSA header (RFC 2328 A.4.1; RFC 5340
//!   A.4.2.1 — same 20-byte shape both versions, v3 merging v2's separate
//!   1-byte Options + 1-byte LS type into one 2-byte LS Type at the same
//!   offset) followed by a type-specific body whose length the header's
//!   own `length` field gives. This plugin captures each 20-byte header
//!   verbatim as one `lsa_headers` list entry — type + LS-id +
//!   advertising-router, plus age/sequence/checksum/length, is exactly
//!   what that fixed header holds, nothing more — and skips the variable
//!   body by that field without decoding it, the same field-extraction
//!   ceiling `modbus` documents for PDU shapes it can't disambiguate
//!   (11.13) and `netflow9` documents for Data FlowSets (11.11).
//! - **Link State Request / Link State Acknowledgment** (RFC 2328
//!   A.3.4/A.3.6; RFC 5340 A.3.4/A.3.6), and any type value neither RFC
//!   defines: no Tier-1 fields beyond the common header, so this plugin
//!   doesn't walk their bodies at all — `header_len` is still exactly
//!   right via `packet_length`.
//!
//! ## Identity
//! Hello is periodic multicast to `224.0.0.5`/`ff02::5` — a beacon, not a
//! conversation, the same shape `stp` already establishes (11.1): no
//! stream of its own. Unicast DBD/LSR/LSU adjacency exchanges are a real
//! point-to-point conversation in principle (keyable on the two
//! `router_id`s) but are deferred as a v2 refinement per 11.4's domain
//! spec, so this plugin declares no identity at all rather than one
//! that's only sometimes true.

use pktflow_core::{
    ByteReader, Depth, FieldMap, FieldName, Hint, LayerPlugin, ParseCtx, ParseError, ParsedLayer,
    ProtocolName, RouteId, StreamIdentity, Value,
};

const VERSION: FieldName = "version";
const TYPE: FieldName = "type";
const PACKET_LENGTH: FieldName = "packet_length";
const ROUTER_ID: FieldName = "router_id";
const AREA_ID: FieldName = "area_id";
const HELLO_INTERVAL: FieldName = "hello_interval";
const ROUTER_DEAD_INTERVAL: FieldName = "router_dead_interval";
const DESIGNATED_ROUTER: FieldName = "designated_router";
const NEIGHBORS: FieldName = "neighbors";
const INTERFACE_MTU: FieldName = "interface_mtu";
const DD_SEQUENCE: FieldName = "dd_sequence";
const LSA_HEADERS: FieldName = "lsa_headers";

// RFC 2328 A.3.1 / RFC 5340 A.3.1: OSPF packet types, shared by both wire
// versions. Only the three types this plugin walks a body for are named;
// Link State Request (3) and Link State Acknowledgment (5) — see the
// module doc — fall through the `_` arm in `parse` below like any other
// value neither RFC defines.
const HELLO: u8 = 1;
const DATABASE_DESCRIPTION: u8 = 2;
const LINK_STATE_UPDATE: u8 = 4;

/// RFC 2328 A.3.1: v2's fixed 8-byte Authentication trailer.
const V2_AUTH_LEN: usize = 8;

/// RFC 2328 A.4.1 / RFC 5340 A.4.2.1: every LSA, of every type, opens
/// with this same 20-byte header.
const LSA_HEADER_LEN: usize = 20;

pub struct Ospf;

impl LayerPlugin for Ospf {
    fn name(&self) -> ProtocolName {
        "ospf"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let version = r.u8()?;
        if version != 2 && version != 3 {
            return Err(ParseError::Malformed("OSPF: unsupported version"));
        }
        let msg_type = r.u8()?;
        let packet_length_word = r.u16_be()?;
        let packet_length = usize::from(packet_length_word);
        if packet_length < 4 {
            return Err(ParseError::Malformed(
                "OSPF: packet_length shorter than the common header prefix",
            ));
        }
        // Bounding the rest of the read to the declared message length
        // (rather than to `bytes.len()`) is what makes Hello's
        // `neighbors` list and DBD's (unwalked) LSA-header trailer honest
        // about where the message actually ends (module doc).
        let body = r.take(packet_length - 4)?;
        let mut r = ByteReader::new(body);

        let router_id = r.take(4)?;
        let area_id = r.take(4)?;
        let _checksum = r.u16_be()?;
        if version == 2 {
            let _autype = r.u16_be()?;
            r.take(V2_AUTH_LEN)?;
        } else {
            let _instance_id = r.u8()?;
            let _reserved = r.u8()?;
        }

        let mut hello_interval = None;
        let mut router_dead_interval = None;
        let mut designated_router = None;
        let mut neighbors = Vec::new();
        let mut interface_mtu = None;
        let mut dd_sequence = None;
        let mut lsa_headers = Vec::new();

        match msg_type {
            HELLO if version == 2 => {
                let _network_mask = r.take(4)?;
                hello_interval = Some(u64::from(r.u16_be()?));
                let _options = r.u8()?;
                let _rtr_pri = r.u8()?;
                router_dead_interval = Some(u64::from(r.u32_be()?));
                designated_router = Some(r.take(4)?);
                let _backup_designated_router = r.take(4)?;
                while r.remaining() > 0 {
                    neighbors.push(Value::from(r.take(4)?));
                }
            }
            HELLO => {
                // v3 (RFC 5340 A.3.2): no Network Mask (per-link, not
                // per-subnet), a 4-byte Interface ID instead, and the
                // DR/BDR are Router IDs rather than interface addresses.
                let _interface_id = r.u32_be()?;
                let _rtr_pri = r.u8()?;
                let _options = r.take(3)?;
                hello_interval = Some(u64::from(r.u16_be()?));
                router_dead_interval = Some(u64::from(r.u16_be()?));
                designated_router = Some(r.take(4)?);
                let _backup_designated_router = r.take(4)?;
                while r.remaining() > 0 {
                    neighbors.push(Value::from(r.take(4)?));
                }
            }
            DATABASE_DESCRIPTION if version == 2 => {
                interface_mtu = Some(u64::from(r.u16_be()?));
                let _options = r.u8()?;
                let _bits = r.u8()?;
                dd_sequence = Some(u64::from(r.u32_be()?));
                // DBD's own trailing LSA-header inventory runs to the end
                // of the packet the same way Hello's neighbor list does,
                // but it's not in 11.4's field list for `ospf` — left
                // unwalked (module doc); `header_len` doesn't depend on
                // draining `r`.
            }
            DATABASE_DESCRIPTION => {
                let _reserved1 = r.u8()?;
                let _options = r.take(3)?;
                interface_mtu = Some(u64::from(r.u16_be()?));
                let _reserved2 = r.u8()?;
                let _bits = r.u8()?;
                dd_sequence = Some(u64::from(r.u32_be()?));
            }
            LINK_STATE_UPDATE => {
                let num_lsas = r.u32_be()?;
                for _ in 0..num_lsas {
                    let header = r.take(LSA_HEADER_LEN)?;
                    let mut hr = ByteReader::new(header);
                    let _age = hr.u16_be()?;
                    let _type_field = hr.u16_be()?;
                    let _link_state_id = hr.take(4)?;
                    let _advertising_router = hr.take(4)?;
                    let _sequence = hr.u32_be()?;
                    let _checksum = hr.u16_be()?;
                    let length = usize::from(hr.u16_be()?);
                    if length < LSA_HEADER_LEN {
                        return Err(ParseError::Malformed(
                            "OSPF: LSA length shorter than its own header",
                        ));
                    }
                    r.take(length - LSA_HEADER_LEN)?;
                    lsa_headers.push(Value::from(header));
                }
            }
            // Link State Request (type 3) / Link State Acknowledgment
            // (type 5) (RFC 2328 A.3.4/A.3.6; RFC 5340 A.3.4/A.3.6) carry
            // no Tier-1 fields beyond the common header (module doc); any
            // type value neither RFC defines falls in here too rather
            // than guessing a body shape it doesn't have.
            _ => {}
        }

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Structural {
            fields.insert(VERSION, Value::U64(u64::from(version)));
            fields.insert(TYPE, Value::U64(u64::from(msg_type)));
            fields.insert(PACKET_LENGTH, Value::U64(u64::from(packet_length_word)));
            fields.insert(ROUTER_ID, Value::from(router_id));
            fields.insert(AREA_ID, Value::from(area_id));
        }
        if ctx.depth() >= Depth::Full {
            if let Some(v) = hello_interval {
                fields.insert(HELLO_INTERVAL, Value::U64(v));
            }
            if let Some(v) = router_dead_interval {
                fields.insert(ROUTER_DEAD_INTERVAL, Value::U64(v));
            }
            if let Some(v) = designated_router {
                fields.insert(DESIGNATED_ROUTER, Value::from(v));
            }
            if msg_type == HELLO {
                fields.insert(NEIGHBORS, Value::List(neighbors));
            }
            if let Some(v) = interface_mtu {
                fields.insert(INTERFACE_MTU, Value::U64(v));
            }
            if let Some(v) = dd_sequence {
                fields.insert(DD_SEQUENCE, Value::U64(v));
            }
            if msg_type == LINK_STATE_UPDATE {
                fields.insert(LSA_HEADERS, Value::List(lsa_headers));
            }
        }

        Ok(ParsedLayer {
            header_len: packet_length,
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::IpProtocol(89)]
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

    fn ctx<'a>(depth: Depth, m: &'a PacketMeta) -> ParseCtx<'a> {
        ParseCtx::new(&[], depth, m)
    }

    /// The common header prefix (RFC 2328 A.3.1 / RFC 5340 A.3.1) with a
    /// zero `packet_length` placeholder patched in by [`finish`].
    fn header_prefix(version: u8, msg_type: u8) -> Vec<u8> {
        let mut b = vec![version, msg_type, 0, 0];
        b.extend_from_slice(&[10, 0, 0, 1]); // router_id
        b.extend_from_slice(&[0, 0, 0, 1]); // area_id
        b.extend_from_slice(&[0, 0]); // checksum
        if version == 2 {
            b.extend_from_slice(&[0, 0]); // AuType: none
            b.extend_from_slice(&[0; V2_AUTH_LEN]);
        } else {
            b.push(0); // Instance ID
            b.push(0); // reserved
        }
        b
    }

    /// Patches `packet_length` (bytes 2-3) to `b`'s final length.
    fn finish(mut b: Vec<u8>) -> Vec<u8> {
        let len = u16::try_from(b.len()).expect("fixture fits in u16");
        b[2..4].copy_from_slice(&len.to_be_bytes());
        b
    }

    /// RFC 2328 A.3.2: network mask, hello_interval 10s, options 0x02
    /// (E-bit), rtr_pri 1, router_dead_interval 40s, DR/BDR by interface
    /// address, two neighbors.
    fn hello_v2_fixture() -> Vec<u8> {
        let mut b = header_prefix(2, HELLO);
        b.extend_from_slice(&[255, 255, 255, 0]); // network_mask
        b.extend_from_slice(&10u16.to_be_bytes()); // hello_interval
        b.push(0x02); // options
        b.push(1); // rtr_pri
        b.extend_from_slice(&40u32.to_be_bytes()); // router_dead_interval
        b.extend_from_slice(&[10, 0, 0, 1]); // designated_router
        b.extend_from_slice(&[10, 0, 0, 2]); // backup_designated_router
        b.extend_from_slice(&[10, 0, 0, 3]); // neighbor
        b.extend_from_slice(&[10, 0, 0, 4]); // neighbor
        finish(b)
    }

    /// RFC 5340 A.3.2: no network mask, 3-byte options, DR/BDR by
    /// Router ID, one neighbor.
    fn hello_v3_fixture() -> Vec<u8> {
        let mut b = header_prefix(3, HELLO);
        b.extend_from_slice(&7u32.to_be_bytes()); // interface_id
        b.push(1); // rtr_pri
        b.extend_from_slice(&[0, 0, 0x02]); // options (24-bit)
        b.extend_from_slice(&10u16.to_be_bytes()); // hello_interval
        b.extend_from_slice(&40u16.to_be_bytes()); // router_dead_interval
        b.extend_from_slice(&[10, 0, 0, 1]); // designated_router (Router ID)
        b.extend_from_slice(&[10, 0, 0, 2]); // backup_designated_router
        b.extend_from_slice(&[10, 0, 0, 5]); // neighbor
        finish(b)
    }

    /// RFC 2328 A.3.3: interface_mtu 1500, options 0x02, bits I|M|MS
    /// (0x07), dd_sequence, plus a trailing (unwalked) LSA-header entry.
    fn dbd_v2_fixture() -> Vec<u8> {
        let mut b = header_prefix(2, DATABASE_DESCRIPTION);
        b.extend_from_slice(&1500u16.to_be_bytes()); // interface_mtu
        b.push(0x02); // options
        b.push(0x07); // bits: I|M|MS
        b.extend_from_slice(&0xAABB_CCDDu32.to_be_bytes()); // dd_sequence
        b.extend_from_slice(&[0xEE; LSA_HEADER_LEN]); // unwalked trailer
        finish(b)
    }

    /// RFC 5340 A.3.3: leading reserved byte, 3-byte options, same
    /// interface_mtu/dd_sequence pair.
    fn dbd_v3_fixture() -> Vec<u8> {
        let mut b = header_prefix(3, DATABASE_DESCRIPTION);
        b.push(0); // reserved1
        b.extend_from_slice(&[0, 0, 0x02]); // options (24-bit)
        b.extend_from_slice(&1500u16.to_be_bytes()); // interface_mtu
        b.push(0); // reserved2
        b.push(0x07); // bits: I|M|MS
        b.extend_from_slice(&0xAABB_CCDDu32.to_be_bytes()); // dd_sequence
        finish(b)
    }

    /// One LSA (RFC 2328 A.4.1 / RFC 5340 A.4.2.1): age, type field,
    /// link-state id, advertising router, sequence, checksum, then
    /// `length` (header + `extra`'s byte count) and `extra` itself.
    fn lsa(link_state_id: [u8; 4], advertising_router: [u8; 4], extra: &[u8]) -> Vec<u8> {
        let mut l = vec![0x00, 0x01]; // age = 1
        l.extend_from_slice(&[0x00, 0x01]); // type field (router-LSA)
        l.extend_from_slice(&link_state_id);
        l.extend_from_slice(&advertising_router);
        l.extend_from_slice(&0x8000_0001u32.to_be_bytes()); // sequence
        l.extend_from_slice(&[0xBE, 0xEF]); // checksum
        let length = u16::try_from(LSA_HEADER_LEN + extra.len()).expect("fixture fits in u16");
        l.extend_from_slice(&length.to_be_bytes());
        l.extend_from_slice(extra);
        l
    }

    /// RFC 2328 A.3.5 / RFC 5340 A.3.5: two LSAs, one header-only and one
    /// with a 4-byte body this plugin skips without decoding.
    fn lsu_fixture(version: u8) -> Vec<u8> {
        let first = lsa([10, 0, 0, 1], [10, 0, 0, 1], &[]);
        let second = lsa([10, 0, 0, 2], [10, 0, 0, 1], &[0xDE, 0xAD, 0xBE, 0xEF]);
        let mut b = header_prefix(version, LINK_STATE_UPDATE);
        b.extend_from_slice(&2u32.to_be_bytes()); // num_lsas
        b.extend_from_slice(&first);
        b.extend_from_slice(&second);
        finish(b)
    }

    #[test]
    fn hello_v2_parses_exactly() {
        let bytes = hello_v2_fixture();
        let m = meta(bytes.len());
        let parsed = Ospf
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid OSPFv2 Hello");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(VERSION), Some(&Value::U64(2)));
        assert_eq!(parsed.fields.get(TYPE), Some(&Value::U64(1)));
        assert_eq!(
            parsed.fields.get(PACKET_LENGTH),
            Some(&Value::U64(bytes.len() as u64))
        );
        assert_eq!(
            parsed.fields.get(ROUTER_ID),
            Some(&Value::from(&[10u8, 0, 0, 1][..]))
        );
        assert_eq!(
            parsed.fields.get(AREA_ID),
            Some(&Value::from(&[0u8, 0, 0, 1][..]))
        );
        assert_eq!(parsed.fields.get(HELLO_INTERVAL), Some(&Value::U64(10)));
        assert_eq!(
            parsed.fields.get(ROUTER_DEAD_INTERVAL),
            Some(&Value::U64(40))
        );
        assert_eq!(
            parsed.fields.get(DESIGNATED_ROUTER),
            Some(&Value::from(&[10u8, 0, 0, 1][..]))
        );
        assert_eq!(
            parsed.fields.get(NEIGHBORS),
            Some(&Value::List(vec![
                Value::from(&[10u8, 0, 0, 3][..]),
                Value::from(&[10u8, 0, 0, 4][..]),
            ]))
        );
        assert_eq!(parsed.fields.get(INTERFACE_MTU), None);
    }

    #[test]
    fn hello_v3_parses_exactly_and_has_no_network_mask() {
        let bytes = hello_v3_fixture();
        let m = meta(bytes.len());
        let parsed = Ospf
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid OSPFv3 Hello");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.fields.get(VERSION), Some(&Value::U64(3)));
        assert_eq!(parsed.fields.get(HELLO_INTERVAL), Some(&Value::U64(10)));
        assert_eq!(
            parsed.fields.get(ROUTER_DEAD_INTERVAL),
            Some(&Value::U64(40))
        );
        assert_eq!(
            parsed.fields.get(DESIGNATED_ROUTER),
            Some(&Value::from(&[10u8, 0, 0, 1][..]))
        );
        assert_eq!(
            parsed.fields.get(NEIGHBORS),
            Some(&Value::List(vec![Value::from(&[10u8, 0, 0, 5][..])]))
        );
    }

    #[test]
    fn zero_neighbors_is_valid() {
        let mut b = header_prefix(2, HELLO);
        b.extend_from_slice(&[255, 255, 255, 0]);
        b.extend_from_slice(&10u16.to_be_bytes());
        b.push(0x02);
        b.push(1);
        b.extend_from_slice(&40u32.to_be_bytes());
        b.extend_from_slice(&[10, 0, 0, 1]);
        b.extend_from_slice(&[10, 0, 0, 2]);
        let bytes = finish(b);
        let m = meta(bytes.len());
        let parsed = Ospf
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("neighbor-less Hello is valid");
        assert_eq!(parsed.fields.get(NEIGHBORS), Some(&Value::List(vec![])));
    }

    #[test]
    fn dbd_v2_parses_exactly_and_ignores_lsa_header_trailer() {
        let bytes = dbd_v2_fixture();
        let m = meta(bytes.len());
        let parsed = Ospf
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid OSPFv2 DBD");
        // header_len covers the whole message, including the trailing
        // LSA-header inventory this plugin doesn't walk (module doc).
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.fields.get(TYPE), Some(&Value::U64(2)));
        assert_eq!(parsed.fields.get(INTERFACE_MTU), Some(&Value::U64(1500)));
        assert_eq!(
            parsed.fields.get(DD_SEQUENCE),
            Some(&Value::U64(0xAABB_CCDD))
        );
        assert_eq!(parsed.fields.get(NEIGHBORS), None);
        assert_eq!(parsed.fields.get(LSA_HEADERS), None);
    }

    #[test]
    fn dbd_v3_parses_exactly() {
        let bytes = dbd_v3_fixture();
        let m = meta(bytes.len());
        let parsed = Ospf
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid OSPFv3 DBD");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.fields.get(VERSION), Some(&Value::U64(3)));
        assert_eq!(parsed.fields.get(INTERFACE_MTU), Some(&Value::U64(1500)));
        assert_eq!(
            parsed.fields.get(DD_SEQUENCE),
            Some(&Value::U64(0xAABB_CCDD))
        );
    }

    #[test]
    fn lsu_v2_summarizes_lsa_headers_and_skips_bodies() {
        let bytes = lsu_fixture(2);
        let m = meta(bytes.len());
        let parsed = Ospf
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid OSPFv2 LSU");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.fields.get(TYPE), Some(&Value::U64(4)));
        let Some(Value::List(headers)) = parsed.fields.get(LSA_HEADERS) else {
            panic!("lsa_headers must be a list");
        };
        assert_eq!(headers.len(), 2);
        // Each entry is exactly the 20-byte LSA header, not the body.
        for h in headers {
            let Value::Bytes(b) = h else {
                panic!("lsa_headers entries must be Bytes");
            };
            assert_eq!(b.len(), LSA_HEADER_LEN);
        }
        assert_eq!(
            headers[0],
            Value::from(&lsa([10, 0, 0, 1], [10, 0, 0, 1], &[])[..LSA_HEADER_LEN])
        );
    }

    #[test]
    fn lsu_v3_shares_the_same_lsa_header_shape() {
        let bytes = lsu_fixture(3);
        let m = meta(bytes.len());
        let parsed = Ospf
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid OSPFv3 LSU");
        assert_eq!(parsed.header_len, bytes.len());
        let Some(Value::List(headers)) = parsed.fields.get(LSA_HEADERS) else {
            panic!("lsa_headers must be a list");
        };
        assert_eq!(headers.len(), 2);
    }

    #[test]
    fn zero_lsas_is_valid() {
        let mut b = header_prefix(2, LINK_STATE_UPDATE);
        b.extend_from_slice(&0u32.to_be_bytes());
        let bytes = finish(b);
        let m = meta(bytes.len());
        let parsed = Ospf
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("zero-LSA update is valid");
        assert_eq!(parsed.fields.get(LSA_HEADERS), Some(&Value::List(vec![])));
    }

    #[test]
    fn lsa_length_shorter_than_its_own_header_declines() {
        let mut l = lsa([10, 0, 0, 1], [10, 0, 0, 1], &[]);
        l[18..20].copy_from_slice(&19u16.to_be_bytes()); // < LSA_HEADER_LEN
        let mut b = header_prefix(2, LINK_STATE_UPDATE);
        b.extend_from_slice(&1u32.to_be_bytes());
        b.extend_from_slice(&l);
        let bytes = finish(b);
        let m = meta(bytes.len());
        assert!(Ospf.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn link_state_request_and_ack_carry_only_the_common_header() {
        // RFC 2328 A.3.1: type 3 (Link State Request), type 5 (Link
        // State Acknowledgment).
        for msg_type in [3u8, 5] {
            let bytes = finish(header_prefix(2, msg_type));
            let m = meta(bytes.len());
            let parsed = Ospf
                .parse(&bytes, &ctx(Depth::Full, &m))
                .unwrap_or_else(|e| panic!("type {msg_type} must parse: {e}"));
            assert_eq!(parsed.header_len, bytes.len());
            assert_eq!(
                parsed.fields.get(TYPE),
                Some(&Value::U64(u64::from(msg_type)))
            );
            assert_eq!(parsed.fields.get(HELLO_INTERVAL), None);
            assert_eq!(parsed.fields.get(INTERFACE_MTU), None);
            assert_eq!(parsed.fields.get(LSA_HEADERS), None);
        }
    }

    #[test]
    fn unrecognized_type_still_parses_the_common_header() {
        let bytes = finish(header_prefix(2, 200));
        let m = meta(bytes.len());
        let parsed = Ospf
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("reserved type still parses the common header");
        assert_eq!(parsed.fields.get(TYPE), Some(&Value::U64(200)));
    }

    #[test]
    fn unsupported_version_declines() {
        let bytes = finish(header_prefix(1, HELLO));
        let m = meta(bytes.len());
        assert!(Ospf.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn packet_length_shorter_than_common_header_prefix_declines() {
        let mut bytes = finish(header_prefix(2, HELLO));
        bytes[2..4].copy_from_slice(&3u16.to_be_bytes());
        let m = meta(bytes.len());
        assert!(Ospf.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn packet_length_beyond_available_bytes_declines() {
        let mut bytes = finish(header_prefix(2, HELLO));
        let claimed = u16::try_from(bytes.len()).expect("fixture fits in u16") + 4;
        bytes[2..4].copy_from_slice(&claimed.to_be_bytes());
        let m = meta(bytes.len());
        assert!(Ospf.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn trailing_bytes_beyond_packet_length_are_ignored() {
        let mut bytes = hello_v2_fixture();
        let declared = bytes.len();
        bytes.extend_from_slice(&[0xAA, 0xBB]); // e.g. link-layer padding
        let m = meta(bytes.len());
        let parsed = Ospf
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("trailing bytes beyond packet_length are fine");
        assert_eq!(parsed.header_len, declared);
    }

    #[test]
    fn keys_depth_has_no_fields() {
        let bytes = hello_v2_fixture();
        let m = meta(bytes.len());
        let parsed = Ospf
            .parse(&bytes, &ctx(Depth::Keys, &m))
            .expect("valid OSPFv2 Hello");
        assert_eq!(parsed.fields.len(), 0);
    }

    #[test]
    fn structural_depth_omits_type_specific_fields() {
        let bytes = hello_v2_fixture();
        let m = meta(bytes.len());
        let parsed = Ospf
            .parse(&bytes, &ctx(Depth::Structural, &m))
            .expect("valid OSPFv2 Hello");
        assert_eq!(parsed.fields.get(VERSION), Some(&Value::U64(2)));
        assert_eq!(parsed.fields.get(HELLO_INTERVAL), None);
        assert_eq!(parsed.fields.get(NEIGHBORS), None);
    }

    #[test]
    fn no_stream_identity_declared() {
        assert!(Ospf.stream_identity().is_none());
    }

    #[test]
    fn truncated_hello_v2_frames_decline() {
        let bytes = hello_v2_fixture();
        let m = meta(bytes.len());
        for n in 0..bytes.len() {
            let full_ctx = ctx(Depth::Full, &m);
            assert!(
                Ospf.parse(&bytes[..n], &full_ctx).is_err(),
                "prefix of {n}/{} bytes must decline",
                bytes.len()
            );
        }
    }

    #[test]
    fn truncated_lsu_frames_decline_inside_the_second_lsa_body() {
        let bytes = lsu_fixture(2);
        let m = meta(bytes.len());
        for n in 0..bytes.len() {
            let full_ctx = ctx(Depth::Full, &m);
            assert!(
                Ospf.parse(&bytes[..n], &full_ctx).is_err(),
                "prefix of {n}/{} bytes must decline",
                bytes.len()
            );
        }
    }
}
