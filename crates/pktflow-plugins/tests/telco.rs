//! Telco/cellular-core stream behavior (11.15): `gtp_u`'s G-PDU payload
//! falls back through `Hint::Unknown` to the existing `ipv4`/`ipv6` probes
//! with zero new code (the same zero-new-code claim `vxlan`'s by-name
//! inner-Ethernet dispatch makes in `tests/tunnels.rs`, proven here
//! end-to-end instead of just in the module doc); tunnel-management
//! messages (Echo, Error Indication) stop `Terminal` with no spurious
//! inner-stream attempt; and two TEIDs sharing one outer UDP 5-tuple (a
//! GTP-U gateway serving multiple subscriber tunnels) produce sibling
//! streams, the same shared-qualifier shape `tests/tunnels.rs` proves for
//! two VNIs over one outer UDP stream. `gtp_c`'s GTPv1-C/GTPv2-C pairs
//! parse through the one plugin the `version` field disambiguates, and its
//! bounded IE walk skips a vendor-specific TLV via its own length field to
//! still recover a recognized IMSI.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use pktflow_core::{LinkType, PacketMeta, ParseOpts, ProtocolName, StopReason};
use pktflow_flows::{Aggregator, AggregatorConfig, StreamId};
use pktflow_plugins::default_engine;
use pktflow_plugins::ipv4::internet_checksum;

fn meta(len: usize, ms: u64) -> PacketMeta {
    PacketMeta {
        timestamp: SystemTime::UNIX_EPOCH + Duration::from_millis(ms),
        caplen: len,
        origlen: len,
        link_type: LinkType::ETHERNET,
    }
}

fn eth(dst: [u8; 6], src: [u8; 6]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&dst);
    f.extend_from_slice(&src);
    f.extend_from_slice(&0x0800u16.to_be_bytes());
    f
}

/// `total_len` is the real IPv4 total length (header + everything after
/// it) — unlike some other fixture files' fixed stand-in value, this must
/// be accurate here: `ipv4`'s `probe()` (06.3) checks it against the
/// available bytes when this header is reached via `gtp_u`'s `Hint::Unknown`
/// fallback rather than an explicit route.
fn ipv4(protocol: u8, total_len: u16, src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
    let mut h = vec![0x45, 0x00];
    h.extend_from_slice(&total_len.to_be_bytes());
    h.extend_from_slice(&[0x1C, 0x46, 0x40, 0x00, 0x40, protocol, 0, 0]);
    h.extend_from_slice(&src);
    h.extend_from_slice(&dst);
    let ck = internet_checksum(&h);
    h[10..12].copy_from_slice(&ck.to_be_bytes());
    h
}

fn tcp(src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut s = Vec::new();
    s.extend_from_slice(&src_port.to_be_bytes());
    s.extend_from_slice(&dst_port.to_be_bytes());
    s.extend_from_slice(&[0, 0, 1, 0, 0, 0, 0, 0]);
    s.extend_from_slice(&0x5002u16.to_be_bytes()); // SYN
    s.extend_from_slice(&[0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00]);
    s
}

fn udp(src_port: u16, dst_port: u16, payload_len: u16) -> Vec<u8> {
    let mut d = Vec::new();
    d.extend_from_slice(&src_port.to_be_bytes());
    d.extend_from_slice(&dst_port.to_be_bytes());
    d.extend_from_slice(&(8 + payload_len).to_be_bytes());
    d.extend_from_slice(&[0x00, 0x00]);
    d
}

/// TS 29.281 §5.1 mandatory-only header (no E/S/PN).
fn gtp_u(message_type: u8, teid: u32, payload_len: u16) -> Vec<u8> {
    let mut g = vec![0x30, message_type];
    g.extend_from_slice(&payload_len.to_be_bytes());
    g.extend_from_slice(&teid.to_be_bytes());
    g
}

const MAC_A: [u8; 6] = [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E];
const MAC_B: [u8; 6] = [0x00, 0x1B, 0x44, 0x11, 0x3A, 0xB7];

/// Walks the single root-to-leaf chain, returning protocols in order.
fn chain(agg: &Aggregator) -> Vec<ProtocolName> {
    let roots: Vec<StreamId> = agg.roots().map(|r| r.id).collect();
    assert_eq!(roots.len(), 1, "one root");
    let mut path = Vec::new();
    let mut cursor = roots.first().copied();
    while let Some(id) = cursor {
        let s = agg.get(id).expect("node");
        path.push(s.protocol);
        assert!(s.children.len() <= 1, "fixture chains are linear");
        cursor = s.children.first().copied();
    }
    path
}

#[test]
fn gpdu_carrying_ipv4_tcp_routes_through_unknown_fallback_to_ipv4_probe() {
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    let inner_tcp = tcp(51000, 443);
    let mut inner = ipv4(
        6,
        (20 + inner_tcp.len()) as u16,
        [10, 45, 0, 1],
        [8, 8, 8, 8],
    );
    inner.extend_from_slice(&inner_tcp);

    let mut frame = eth(MAC_B, MAC_A);
    frame.extend_from_slice(&ipv4(
        17,
        (20 + 8 + 8 + inner.len()) as u16,
        [192, 168, 0, 1],
        [192, 168, 0, 2],
    ));
    frame.extend_from_slice(&udp(2152, 2152, (8 + inner.len()) as u16));
    frame.extend_from_slice(&gtp_u(255, 0xAABBCCDD, inner.len() as u16));
    frame.extend_from_slice(&inner);

    let packet = engine.dissect(&frame, meta(frame.len(), 0), ParseOpts::default());
    assert_eq!(packet.stop, StopReason::Complete);
    agg.ingest(&packet);

    // G-PDU has no next-protocol field of its own: this chain only works
    // because ipv4's existing probe (06.3) claims the fallback pool for
    // it, zero new code in either plugin.
    assert_eq!(
        chain(&agg),
        ["ethernet", "ipv4", "udp", "gtp_u", "ipv4", "tcp"]
    );

    let gtp_stream = agg.at_layer("gtp_u")[0];
    let inner_ip_stream = agg
        .at_layer("ipv4")
        .into_iter()
        .find(|s| s.parent == Some(gtp_stream.id))
        .expect("inner ip parented to the gtp_u tunnel stream, not the outer one");
    let session = agg.at_layer("tcp")[0];
    assert_eq!(session.parent, Some(inner_ip_stream.id));
}

#[test]
fn echo_request_response_and_error_indication_stop_terminal_with_no_inner_stream() {
    let engine = Arc::new(default_engine());

    for (name, message_type) in [
        ("echo request", 1u8),
        ("echo response", 2u8),
        ("error indication", 26u8),
    ] {
        // A trailing information element (e.g. Error Indication's
        // mandatory TEID Data I / GTP-U Peer Address, or an Echo's
        // optional Private Extension) so bytes remain after the header —
        // otherwise the engine would stop `Complete` (payload exhausted)
        // before ever consulting `gtp_u`'s `Hint::Terminal`.
        let trailing_ie = [0x00u8, 0x00, 0x00, 0x00];
        let mut frame = eth(MAC_B, MAC_A);
        frame.extend_from_slice(&ipv4(
            17,
            20 + 8 + 8 + trailing_ie.len() as u16,
            [192, 168, 0, 1],
            [192, 168, 0, 2],
        ));
        frame.extend_from_slice(&udp(2152, 2152, 8 + trailing_ie.len() as u16));
        frame.extend_from_slice(&gtp_u(message_type, 0, trailing_ie.len() as u16));
        frame.extend_from_slice(&trailing_ie);

        let packet = engine.dissect(&frame, meta(frame.len(), 0), ParseOpts::default());
        assert_eq!(
            packet.stop,
            StopReason::Terminal,
            "{name}: tunnel-management message must stop Terminal"
        );

        let mut agg = Aggregator::new(&engine, AggregatorConfig::default());
        agg.ingest(&packet);
        assert_eq!(
            chain(&agg),
            ["ethernet", "ipv4", "udp", "gtp_u"],
            "{name}: no spurious inner-stream attempt"
        );
    }
}

#[test]
fn two_teids_over_one_outer_udp_are_sibling_streams() {
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    for (ms, teid) in [(0u64, 100u32), (1, 200)] {
        let mut frame = eth(MAC_B, MAC_A);
        frame.extend_from_slice(&ipv4(17, 20 + 8 + 8, [192, 168, 0, 1], [192, 168, 0, 2]));
        frame.extend_from_slice(&udp(2152, 2152, 8));
        // Echo Request: tunnel-management-only, no inner-stream nesting to
        // muddy the sibling-stream assertion below.
        frame.extend_from_slice(&gtp_u(1, teid, 0));
        agg.ingest(&engine.dissect(&frame, meta(frame.len(), ms), ParseOpts::default()));
    }

    let outer_udp = agg.at_layer("udp")[0];
    let gtp_streams = agg.at_layer("gtp_u");
    assert_eq!(
        gtp_streams.len(),
        2,
        "one stream per TEID (shared-qualifier key)"
    );
    assert!(gtp_streams.iter().all(|g| g.parent == Some(outer_udp.id)));
    assert_ne!(gtp_streams[0].key, gtp_streams[1].key);
}

// --- GTP-C (11.15, TS 29.060 GTPv1-C / TS 29.274 GTPv2-C) ----------------

/// TS 29.060 §6 GTPv1-C header, no optional block.
fn gtp1c(message_type: u8, teid: u32, ies: &[u8]) -> Vec<u8> {
    let mut g = vec![0x30, message_type]; // version 1, PT=1
    g.extend_from_slice(&(ies.len() as u16).to_be_bytes());
    g.extend_from_slice(&teid.to_be_bytes());
    g.extend_from_slice(ies);
    g
}

/// TS 29.274 §5.1 GTPv2-C header, `T=1` (TEID present).
fn gtp2c(message_type: u8, teid: u32, ies: &[u8]) -> Vec<u8> {
    let mut g = vec![0x48, message_type]; // version 2, T=1
    g.extend_from_slice(&((8 + ies.len()) as u16).to_be_bytes());
    g.extend_from_slice(&teid.to_be_bytes());
    g.extend_from_slice(&[0x00, 0x00, 0x01, 0x00]); // sequence number + spare
    g.extend_from_slice(ies);
    g
}

fn gtp_c_frame(msg: &[u8]) -> Vec<u8> {
    let mut frame = eth(MAC_B, MAC_A);
    frame.extend_from_slice(&ipv4(
        17,
        (20 + 8 + msg.len()) as u16,
        [192, 168, 0, 1],
        [192, 168, 0, 2],
    ));
    frame.extend_from_slice(&udp(2123, 2123, msg.len() as u16));
    frame.extend_from_slice(msg);
    frame
}

#[test]
fn gtpv1c_and_gtpv2c_create_session_pairs_parse_through_the_same_plugin() {
    let engine = Arc::new(default_engine());

    // GTPv1-C Create PDP Context Request (16) / Response (17).
    for (message_type, teid) in [(16u8, 0u32), (17, 0xAABB_CCDD)] {
        let msg = gtp1c(message_type, teid, &[]);
        let frame = gtp_c_frame(&msg);
        let packet = engine.dissect(&frame, meta(frame.len(), 0), ParseOpts::default());
        let layer = packet.layers.last().expect("gtp_c layer");
        assert_eq!(layer.protocol, "gtp_c");
        assert_eq!(
            layer.fields.get("version"),
            Some(&pktflow_core::Value::U64(1))
        );
        assert_eq!(
            layer.fields.get("message_type"),
            Some(&pktflow_core::Value::U64(u64::from(message_type)))
        );
        assert_eq!(
            layer.fields.get("teid"),
            Some(&pktflow_core::Value::U64(u64::from(teid)))
        );
    }

    // GTPv2-C Create Session Request (32) / Response (33) — the same
    // plugin, disambiguated purely by `version`.
    for (message_type, teid) in [(32u8, 0u32), (33, 0x1122_3344)] {
        let msg = gtp2c(message_type, teid, &[]);
        let frame = gtp_c_frame(&msg);
        let packet = engine.dissect(&frame, meta(frame.len(), 0), ParseOpts::default());
        let layer = packet.layers.last().expect("gtp_c layer");
        assert_eq!(layer.protocol, "gtp_c");
        assert_eq!(
            layer.fields.get("version"),
            Some(&pktflow_core::Value::U64(2))
        );
        assert_eq!(
            layer.fields.get("message_type"),
            Some(&pktflow_core::Value::U64(u64::from(message_type)))
        );
        assert_eq!(
            layer.fields.get("teid"),
            Some(&pktflow_core::Value::U64(u64::from(teid)))
        );
    }
}

/// TS 23.003 §2.2 BCD packing: digits two per octet, low nibble first;
/// `0xF` fills the trailing nibble of an odd-length number.
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

#[test]
fn gtp_c_ie_walk_skips_a_vendor_specific_ie_and_still_recovers_imsi() {
    // GTPv1-C Create PDP Context Request: an unrecognized TLV IE
    // (type >= 0x80, self-describing length) ahead of a recognized IMSI TV
    // IE — the walk must skip the former via its own length field and
    // still recover the latter, end-to-end through the real engine.
    let vendor_tlv = {
        let mut b = vec![0xFEu8]; // vendor-specific TLV type
        b.extend_from_slice(&4u16.to_be_bytes());
        b.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        b
    };
    let imsi_tv = {
        let mut b = vec![0x02u8];
        b.extend_from_slice(&bcd_encode("111223334445556"));
        b
    };
    let mut ies = vendor_tlv;
    ies.extend_from_slice(&imsi_tv);

    let msg = gtp1c(16, 0, &ies);
    let frame = gtp_c_frame(&msg);
    let engine = Arc::new(default_engine());
    let packet = engine.dissect(&frame, meta(frame.len(), 0), ParseOpts::default());
    let layer = packet.layers.last().expect("gtp_c layer");
    assert_eq!(layer.protocol, "gtp_c");
    assert_eq!(
        layer.fields.get("imsi"),
        Some(&pktflow_core::Value::from("111223334445556"))
    );
}
