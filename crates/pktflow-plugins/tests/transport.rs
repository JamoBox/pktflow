//! Transport-layer stream behavior (06.4): the TCP lifecycle walk,
//! close-eligibility, candidate-port routing, direction folding, and the
//! 03.4 `encrypted_udp_no_phantom` fixture at full stream level. Also the
//! SCTP association lifecycle walk (11.6), the same full-engine shape as
//! TCP's but through SCTP's INIT/INIT-ACK/COOKIE-ECHO/COOKIE-ACK handshake,
//! and QUIC's (11.6) documented connection-migration behavior: a changed
//! DCID mid-capture forms a new sibling stream under the same parent UDP
//! stream rather than folding into the pre-migration one (RFC 9000 §5.1.1).

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use pktflow_core::{
    Engine, FieldMap, Hint, LayerPlugin, LinkType, PacketMeta, ParseCtx, ParseError, ParseOpts,
    ParsedLayer, ProtocolName, RouteId, StopReason, Value,
};
use pktflow_flows::{Aggregator, AggregatorConfig};
use pktflow_plugins::ipv4::internet_checksum;
use pktflow_plugins::{arp, ethernet, icmpv4, igmp, ipv4, ipv6, tcp, template, udp, vlan};

fn meta(len: usize, ms: u64) -> PacketMeta {
    PacketMeta {
        timestamp: SystemTime::UNIX_EPOCH + Duration::from_millis(ms),
        caplen: len,
        origlen: len,
        link_type: LinkType::ETHERNET,
    }
}

fn eth(ethertype: u16) -> Vec<u8> {
    let mut f = vec![0xAA; 6];
    f.extend_from_slice(&[0xBB; 6]);
    f.extend_from_slice(&ethertype.to_be_bytes());
    f
}

fn ipv4_header(protocol: u8, src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
    let mut h = vec![
        0x45, 0x00, 0x00, 0x3C, 0x1C, 0x46, 0x40, 0x00, 0x40, protocol, 0, 0,
    ];
    h.extend_from_slice(&src);
    h.extend_from_slice(&dst);
    let ck = internet_checksum(&h);
    h[10..12].copy_from_slice(&ck.to_be_bytes());
    h
}

fn tcp_segment(src_port: u16, dst_port: u16, flags: u16, payload: &[u8]) -> Vec<u8> {
    let mut s = Vec::new();
    s.extend_from_slice(&src_port.to_be_bytes());
    s.extend_from_slice(&dst_port.to_be_bytes());
    s.extend_from_slice(&[0, 0, 1, 0, 0, 0, 0, 0]); // seq, ack
    s.extend_from_slice(&(0x5000 | flags).to_be_bytes());
    s.extend_from_slice(&[0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00]); // window, ck, urg
    s.extend_from_slice(payload);
    s
}

fn udp_datagram(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut d = Vec::new();
    d.extend_from_slice(&src_port.to_be_bytes());
    d.extend_from_slice(&dst_port.to_be_bytes());
    d.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    d.extend_from_slice(&[0x00, 0x00]);
    d.extend_from_slice(payload);
    d
}

/// eth + ipv4 + segment; `a_to_b` controls the IP/port direction.
fn tcp_frame(a_to_b: bool, flags: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = eth(0x0800);
    if a_to_b {
        f.extend_from_slice(&ipv4_header(6, [10, 0, 0, 1], [10, 0, 0, 2]));
        f.extend_from_slice(&tcp_segment(34567, 443, flags, payload));
    } else {
        f.extend_from_slice(&ipv4_header(6, [10, 0, 0, 2], [10, 0, 0, 1]));
        f.extend_from_slice(&tcp_segment(443, 34567, flags, payload));
    }
    f
}

/// RFC 9260 §3.3.2/§3.3.3 fixed parameters shared by INIT and INIT ACK.
fn sctp_init_value() -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&0xCAFE_BABEu32.to_be_bytes()); // Initiate Tag
    v.extend_from_slice(&65536u32.to_be_bytes()); // a_rwnd
    v.extend_from_slice(&10u16.to_be_bytes()); // Outbound Streams
    v.extend_from_slice(&10u16.to_be_bytes()); // Inbound Streams
    v.extend_from_slice(&42u32.to_be_bytes()); // Initial TSN
    v
}

/// RFC 9260 §3.1 common header + one chunk's Type/Flags/Length/Value.
fn sctp_packet(
    src_port: u16,
    dst_port: u16,
    verification_tag: u32,
    chunk_type: u8,
    value: &[u8],
) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&src_port.to_be_bytes());
    p.extend_from_slice(&dst_port.to_be_bytes());
    p.extend_from_slice(&verification_tag.to_be_bytes());
    p.extend_from_slice(&0u32.to_be_bytes()); // checksum, unverified
    p.push(chunk_type);
    p.push(0); // chunk flags
    let length = (4 + value.len()) as u16;
    p.extend_from_slice(&length.to_be_bytes());
    p.extend_from_slice(value);
    p
}

/// eth + ipv4(protocol 132) + one SCTP packet; `a_to_b` controls the
/// IP/port direction the same way `tcp_frame` does.
fn sctp_frame(a_to_b: bool, chunk_type: u8, value: &[u8]) -> Vec<u8> {
    let mut f = eth(0x0800);
    if a_to_b {
        f.extend_from_slice(&ipv4_header(132, [10, 0, 0, 1], [10, 0, 0, 2]));
        f.extend_from_slice(&sctp_packet(34567, 3868, 0x1234_5678, chunk_type, value));
    } else {
        f.extend_from_slice(&ipv4_header(132, [10, 0, 0, 2], [10, 0, 0, 1]));
        f.extend_from_slice(&sctp_packet(3868, 34567, 0x8765_4321, chunk_type, value));
    }
    f
}

/// RFC 8999 §5.2 / RFC 9000 §17.2: a Long Header Initial packet, header
/// form + fixed bit + type bits + version + length-prefixed DCID/SCID.
fn quic_long_header(type_bits: u8, version: u32, dcid: &[u8], scid: &[u8]) -> Vec<u8> {
    let mut p = Vec::new();
    p.push(0x80 | 0x40 | (type_bits << 4) | 0x0F);
    p.extend_from_slice(&version.to_be_bytes());
    p.push(dcid.len() as u8);
    p.extend_from_slice(dcid);
    p.push(scid.len() as u8);
    p.extend_from_slice(scid);
    p.extend_from_slice(&[0xEE; 32]); // header-protected region: never parsed (D12)
    p
}

/// eth + ipv4 + udp(443) + one QUIC Long Header Initial packet.
fn quic_frame(a_to_b: bool, dcid: &[u8], scid: &[u8]) -> Vec<u8> {
    let payload = quic_long_header(0x00, 1, dcid, scid);
    let mut f = eth(0x0800);
    if a_to_b {
        f.extend_from_slice(&ipv4_header(17, [10, 0, 0, 1], [10, 0, 0, 2]));
        f.extend_from_slice(&udp_datagram(50000, 443, &payload));
    } else {
        f.extend_from_slice(&ipv4_header(17, [10, 0, 0, 2], [10, 0, 0, 1]));
        f.extend_from_slice(&udp_datagram(443, 50000, &payload));
    }
    f
}

fn aggregate(frames: &[Vec<u8>]) -> (Arc<pktflow_core::Engine>, Aggregator) {
    let engine = Arc::new(pktflow_plugins::default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());
    for (i, frame) in frames.iter().enumerate() {
        agg.ingest(&engine.dissect(frame, meta(frame.len(), i as u64), ParseOpts::default()));
    }
    (engine, agg)
}

const SYN: u16 = 0x002;
const ACK: u16 = 0x010;
const FIN: u16 = 0x001;
const RST: u16 = 0x004;

#[test]
fn lifecycle_walks_every_named_state() {
    let engine = Arc::new(pktflow_plugins::default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());
    let state = |agg: &Aggregator| agg.at_layer("tcp")[0].state;

    let walk = [
        (tcp_frame(true, SYN, &[]), "syn_sent"),
        (tcp_frame(false, SYN | ACK, &[]), "syn_received"),
        (tcp_frame(true, ACK, &[]), "established"),
        (tcp_frame(true, FIN | ACK, &[]), "closing"),
        (tcp_frame(false, ACK, &[]), "closing"),
        (tcp_frame(false, FIN | ACK, &[]), "closed"),
    ];
    for (i, (frame, expected)) in walk.iter().enumerate() {
        agg.ingest(&engine.dissect(frame, meta(frame.len(), i as u64), ParseOpts::default()));
        assert_eq!(state(&agg), Some(*expected), "step {i}");
    }

    // 05.5 integration: the closed session is close-eligible.
    assert!(agg.at_layer("tcp")[0].close_eligible);

    // The flags rollups recorded the timeline (FR-5 + 05.5 note).
    let session = agg.at_layer("tcp")[0];
    match session.rollups.get("flags") {
        Some(pktflow_flows::Rollup::Accumulate { values, .. }) => {
            assert!(values.contains(&Value::U64(u64::from(SYN))));
            assert!(values.contains(&Value::U64(u64::from(SYN | ACK))));
        }
        other => panic!("wrong rollup: {other:?}"),
    }
}

#[test]
fn midstream_and_rst_fixtures() {
    // Capture began mid-session: first packet is a plain ACK.
    let (_, agg) = aggregate(&[tcp_frame(true, ACK, b"data")]);
    assert_eq!(agg.at_layer("tcp")[0].state, Some("established_midstream"));

    // RST from any state lands "reset" and is close-eligible.
    let (_, agg) = aggregate(&[tcp_frame(true, SYN, &[]), tcp_frame(false, RST | ACK, &[])]);
    let session = agg.at_layer("tcp")[0];
    assert_eq!(session.state, Some("reset"));
    assert!(session.close_eligible);
}

/// RFC 9260 §5.1's four-way handshake plus §9's shutdown sequence (11.6),
/// the SCTP counterpart of `lifecycle_walks_every_named_state` above.
#[test]
fn sctp_lifecycle_walks_every_named_state() {
    let engine = Arc::new(pktflow_plugins::default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());
    let state = |agg: &Aggregator| agg.at_layer("sctp")[0].state;

    let init_value = sctp_init_value();
    let walk = [
        (sctp_frame(true, 1, &init_value), "init_sent"), // INIT
        (sctp_frame(false, 2, &init_value), "cookie_wait"), // INIT ACK
        (sctp_frame(true, 10, &[]), "cookie_echoed"),    // COOKIE ECHO
        (sctp_frame(false, 11, &[]), "established"),     // COOKIE ACK
        (sctp_frame(true, 7, &4u32.to_be_bytes()), "shutdown_pending"), // SHUTDOWN
        (sctp_frame(false, 8, &[]), "closed"),           // SHUTDOWN ACK
    ];
    for (i, (frame, expected)) in walk.iter().enumerate() {
        agg.ingest(&engine.dissect(frame, meta(frame.len(), i as u64), ParseOpts::default()));
        assert_eq!(state(&agg), Some(*expected), "step {i}");
    }

    // 05.5 integration: the closed association is close-eligible.
    assert!(agg.at_layer("sctp")[0].close_eligible);

    // The chunk-type rollup recorded the handshake's shape (11.6 rollups).
    let session = agg.at_layer("sctp")[0];
    match session.rollups.get("first_chunk_type") {
        Some(pktflow_flows::Rollup::Accumulate { values, .. }) => {
            assert!(values.contains(&Value::U64(1))); // INIT
            assert!(values.contains(&Value::U64(2))); // INIT ACK
        }
        other => panic!("wrong rollup: {other:?}"),
    }
}

#[test]
fn sctp_midstream_and_abort_fixtures() {
    // Capture began mid-association: first chunk observed is DATA (type 0).
    let (_, agg) = aggregate(&[sctp_frame(true, 0, b"data")]);
    assert_eq!(agg.at_layer("sctp")[0].state, Some("established_midstream"));

    // ABORT from any state lands "aborted" and is close-eligible.
    let init_value = sctp_init_value();
    let (_, agg) = aggregate(&[sctp_frame(true, 1, &init_value), sctp_frame(false, 6, &[])]);
    let session = agg.at_layer("sctp")[0];
    assert_eq!(session.state, Some("aborted"));
    assert!(session.close_eligible);
}

/// RFC 9000 §5.1.1: a QUIC connection may migrate to a new connection id
/// mid-session. This plugin has no access to the encrypted
/// `NEW_CONNECTION_ID` frames announcing that, so — the documented,
/// tested (not just stated) consequence — a post-migration DCID starts a
/// new sibling `quic` stream rather than folding into the pre-migration
/// one, both hanging off the same parent `udp` stream.
#[test]
fn quic_dcid_migration_forms_a_sibling_stream_under_the_same_udp_parent() {
    let dcid_a = [0xAA; 8];
    let dcid_b = [0xBB; 8];
    let scid = [0x11; 8];
    let (_, agg) = aggregate(&[
        quic_frame(true, &dcid_a, &scid),
        quic_frame(true, &dcid_b, &scid),
    ]);

    let udp_streams = agg.at_layer("udp");
    assert_eq!(udp_streams.len(), 1, "one UDP stream for the whole capture");
    let udp_parent = udp_streams[0].id;

    let quic_streams = agg.at_layer("quic");
    assert_eq!(
        quic_streams.len(),
        2,
        "each DCID forms its own quic stream, not one folded stream"
    );
    assert_ne!(quic_streams[0].key, quic_streams[1].key);
    for s in &quic_streams {
        assert_eq!(s.parent, Some(udp_parent));
    }
}

/// A QUIC Short Header packet carries no invariant-guaranteed DCID (RFC
/// 8999 §5.3), so it can't build a flow key at all — it dissects (still
/// reaches `Hint::Terminal` cleanly) but forms no `quic` stream, the same
/// "no key, no stream, packet still counts into parents" shape 05.1
/// documents for `KeyError::MissingField`.
#[test]
fn quic_short_header_forms_no_stream_but_still_counts_into_the_parent() {
    let mut short = vec![0x40 | 0x0F]; // header_form=0 (short), fixed_bit=1
    short.extend_from_slice(&[0xCC; 16]);
    let mut f = eth(0x0800);
    f.extend_from_slice(&ipv4_header(17, [10, 0, 0, 1], [10, 0, 0, 2]));
    f.extend_from_slice(&udp_datagram(50000, 443, &short));

    let (_, agg) = aggregate(&[f]);
    assert!(agg.at_layer("quic").is_empty());
    let udp_streams = agg.at_layer("udp");
    assert_eq!(udp_streams.len(), 1);
    assert_eq!(
        udp_streams[0].stats.iter().map(|s| s.packets).sum::<u64>(),
        1
    );
}

/// Claims port 53 on both transports — the shape the real DNS plugin
/// (06.6) will take; here it proves second-candidate routing mechanics.
struct Port53;

impl LayerPlugin for Port53 {
    fn name(&self) -> ProtocolName {
        "port53"
    }

    fn parse(&self, bytes: &[u8], _ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = pktflow_core::ByteReader::new(bytes);
        let _first = r.u8()?;
        Ok(ParsedLayer {
            header_len: 1,
            fields: FieldMap::new(),
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::TcpPort(53), RouteId::UdpPort(53)]
    }
}

#[test]
fn dns_reply_routes_via_the_second_candidate() {
    let engine = Arc::new(
        Engine::builder()
            .plugin(template::Template)
            .plugin(ethernet::Ethernet)
            .plugin(vlan::Vlan)
            .plugin(ipv4::Ipv4)
            .plugin(ipv6::Ipv6)
            .plugin(arp::Arp)
            .plugin(icmpv4::Icmpv4)
            .plugin(igmp::Igmp)
            .plugin(tcp::Tcp)
            .plugin(udp::Udp)
            .plugin(Port53)
            .build()
            .expect("valid registry"),
    );

    // Reply direction: src 53 -> dst 34567. TcpPort(34567) is unclaimed,
    // so the second candidate TcpPort(src=53) must dispatch.
    let mut over_tcp = eth(0x0800);
    over_tcp.extend_from_slice(&ipv4_header(6, [10, 0, 0, 2], [10, 0, 0, 1]));
    over_tcp.extend_from_slice(&tcp_segment(53, 34567, ACK, b"\x12\x34"));
    let packet = engine.dissect(&over_tcp, meta(over_tcp.len(), 0), ParseOpts::default());
    let protocols: Vec<_> = packet.layers.iter().map(|l| l.protocol).collect();
    assert_eq!(protocols, ["ethernet", "ipv4", "tcp", "port53"]);

    let mut over_udp = eth(0x0800);
    over_udp.extend_from_slice(&ipv4_header(17, [10, 0, 0, 2], [10, 0, 0, 1]));
    over_udp.extend_from_slice(&udp_datagram(53, 34567, b"\x12\x34"));
    let packet = engine.dissect(&over_udp, meta(over_udp.len(), 0), ParseOpts::default());
    let protocols: Vec<_> = packet.layers.iter().map(|l| l.protocol).collect();
    assert_eq!(protocols, ["ethernet", "ipv4", "udp", "port53"]);
}

#[test]
fn fr21_sessions_and_streams_fold_directions() {
    // TCP: SYN one way, SYN+ACK the other — one session, split stats.
    let (_, agg) = aggregate(&[tcp_frame(true, SYN, &[]), tcp_frame(false, SYN | ACK, &[])]);
    let sessions = agg.at_layer("tcp");
    assert_eq!(sessions.len(), 1);
    assert!(sessions[0].stats.iter().all(|s| s.packets == 1));

    // UDP: a datagram each way — one stream, split stats.
    let dgram = |a_to_b: bool| {
        let mut f = eth(0x0800);
        if a_to_b {
            f.extend_from_slice(&ipv4_header(17, [10, 0, 0, 1], [10, 0, 0, 2]));
            f.extend_from_slice(&udp_datagram(50000, 60000, b"x"));
        } else {
            f.extend_from_slice(&ipv4_header(17, [10, 0, 0, 2], [10, 0, 0, 1]));
            f.extend_from_slice(&udp_datagram(60000, 50000, b"x"));
        }
        f
    };
    let (_, agg) = aggregate(&[dgram(true), dgram(false)]);
    let streams = agg.at_layer("udp");
    assert_eq!(streams.len(), 1);
    assert!(streams[0].stats.iter().all(|s| s.packets == 1));
}

#[test]
fn encrypted_udp_no_phantom() {
    // The PRD's motivating failure (03.4, §4.B.4), now over the real
    // plugin set: an encrypted-looking UDP payload on unclaimed ports.
    // Historically this cascaded into TCP -> IPv6 -> TCP phantom layers.
    let mut frame = eth(0x0800);
    frame.extend_from_slice(&ipv4_header(17, [10, 0, 0, 1], [10, 0, 0, 2]));
    frame.extend_from_slice(&udp_datagram(
        4433,
        4433,
        &[0x45, 0x00, 0x60, 0x02, 0xDE, 0xAD, 0xBE, 0xEF],
    ));

    let engine = Arc::new(pktflow_plugins::default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());
    let packet = engine.dissect(&frame, meta(frame.len(), 0), ParseOpts::default());
    let protocols: Vec<_> = packet.layers.iter().map(|l| l.protocol).collect();
    assert_eq!(
        protocols,
        ["ethernet", "ipv4", "udp"],
        "dissection ends at UDP"
    );
    assert_eq!(
        packet.stop,
        StopReason::UnclaimedRoute(RouteId::UdpPort(4433))
    );
    agg.ingest(&packet);

    assert_eq!(agg.at_layer("udp").len(), 1, "exactly one UDP stream");
    assert_eq!(agg.at_layer("tcp").len(), 0, "zero TCP streams");
    assert_eq!(agg.at_layer("udp")[0].opaque_bytes, 8);
}
