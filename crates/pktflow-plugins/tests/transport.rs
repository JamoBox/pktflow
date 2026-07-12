//! Transport-layer stream behavior (06.4, 11.6): the TCP and SCTP
//! lifecycle walks, close-eligibility, candidate-port routing, direction
//! folding, and the 03.4 `encrypted_udp_no_phantom` fixture at full
//! stream level.

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

// --- SCTP (11.6, RFC 9260) --------------------------------------------

const SCTP_INIT: u8 = 1;
const SCTP_INIT_ACK: u8 = 2;
const SCTP_ABORT: u8 = 6;
const SCTP_SHUTDOWN: u8 = 7;
const SCTP_SHUTDOWN_ACK: u8 = 8;
const SCTP_COOKIE_ECHO: u8 = 10;
const SCTP_COOKIE_ACK: u8 = 11;
const SCTP_DATA: u8 = 0;

/// RFC 9260 §3.3.2/§3.3.3: the 16-byte fixed block INIT and INIT-ACK share.
fn sctp_init_family_value(initiate_tag: u32) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&initiate_tag.to_be_bytes());
    v.extend_from_slice(&0x0001_0000u32.to_be_bytes()); // a_rwnd
    v.extend_from_slice(&10u16.to_be_bytes()); // outbound streams
    v.extend_from_slice(&5u16.to_be_bytes()); // inbound streams
    v.extend_from_slice(&0x1234_5678u32.to_be_bytes()); // initial tsn
    v
}

/// RFC 9260 §3.2: one `Type + Flags + Length + Value` chunk.
fn sctp_chunk(chunk_type: u8, value: &[u8]) -> Vec<u8> {
    let mut c = vec![chunk_type, 0x00];
    c.extend_from_slice(&((4 + value.len()) as u16).to_be_bytes());
    c.extend_from_slice(value);
    c
}

/// RFC 9260 §3.1 common header (12 bytes) + one chunk.
fn sctp_segment(src_port: u16, dst_port: u16, chunk_type: u8, value: &[u8]) -> Vec<u8> {
    let mut s = Vec::new();
    s.extend_from_slice(&src_port.to_be_bytes());
    s.extend_from_slice(&dst_port.to_be_bytes());
    s.extend_from_slice(&0x1111_1111u32.to_be_bytes()); // verification tag
    s.extend_from_slice(&0u32.to_be_bytes()); // checksum, not verified
    s.extend_from_slice(&sctp_chunk(chunk_type, value));
    s
}

/// eth + ipv4(proto 132) + segment; `a_to_b` controls the IP/port
/// direction, same shape as `tcp_frame`.
fn sctp_frame(a_to_b: bool, chunk_type: u8, value: &[u8]) -> Vec<u8> {
    let mut f = eth(0x0800);
    if a_to_b {
        f.extend_from_slice(&ipv4_header(132, [10, 0, 0, 1], [10, 0, 0, 2]));
        f.extend_from_slice(&sctp_segment(34567, 3868, chunk_type, value));
    } else {
        f.extend_from_slice(&ipv4_header(132, [10, 0, 0, 2], [10, 0, 0, 1]));
        f.extend_from_slice(&sctp_segment(3868, 34567, chunk_type, value));
    }
    f
}

#[test]
fn sctp_lifecycle_walks_every_named_state() {
    let engine = Arc::new(pktflow_plugins::default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());
    let state = |agg: &Aggregator| agg.at_layer("sctp")[0].state;

    // 11.6's acceptance criterion sequence (INIT/INIT-ACK/COOKIE-ECHO/
    // COOKIE-ACK/DATA/SHUTDOWN), plus the shutdown handshake's closing
    // leg so every named state in the diagram is actually reached.
    let walk = [
        (
            sctp_frame(true, SCTP_INIT, &sctp_init_family_value(0xAAAA_AAAA)),
            "init_sent",
        ),
        (
            sctp_frame(false, SCTP_INIT_ACK, &sctp_init_family_value(0xBBBB_BBBB)),
            "cookie_wait",
        ),
        (sctp_frame(true, SCTP_COOKIE_ECHO, &[]), "cookie_echoed"),
        (sctp_frame(false, SCTP_COOKIE_ACK, &[]), "established"),
        (sctp_frame(true, SCTP_DATA, b"payload"), "established"),
        (
            sctp_frame(true, SCTP_SHUTDOWN, &0u32.to_be_bytes()),
            "shutdown_pending",
        ),
        (sctp_frame(false, SCTP_SHUTDOWN_ACK, &[]), "closed"),
    ];
    for (i, (frame, expected)) in walk.iter().enumerate() {
        agg.ingest(&engine.dissect(frame, meta(frame.len(), i as u64), ParseOpts::default()));
        assert_eq!(state(&agg), Some(*expected), "step {i}");
    }

    // 05.5 integration: the closed association is close-eligible.
    assert!(agg.at_layer("sctp")[0].close_eligible);

    let session = agg.at_layer("sctp")[0];
    match session.rollups.get("first_chunk_type") {
        Some(pktflow_flows::Rollup::Accumulate { values, .. }) => {
            assert!(values.contains(&Value::U64(u64::from(SCTP_INIT))));
            assert!(values.contains(&Value::U64(u64::from(SCTP_SHUTDOWN))));
        }
        other => panic!("wrong rollup: {other:?}"),
    }
}

#[test]
fn sctp_midstream_and_abort_fixtures() {
    // Capture began mid-association: first chunk observed isn't INIT.
    let (_, agg) = aggregate(&[sctp_frame(true, SCTP_DATA, b"data")]);
    assert_eq!(agg.at_layer("sctp")[0].state, Some("established_midstream"));

    // ABORT from any state lands "aborted" and is close-eligible.
    let (_, agg) = aggregate(&[
        sctp_frame(true, SCTP_INIT, &sctp_init_family_value(1)),
        sctp_frame(false, SCTP_ABORT, &[]),
    ]);
    let session = agg.at_layer("sctp")[0];
    assert_eq!(session.state, Some("aborted"));
    assert!(session.close_eligible);
}

#[test]
fn sctp_two_associations_over_the_same_port_pair_fold_directions() {
    // A SACK-shaped exchange each way: one association, split stats,
    // mirroring FR-21's TCP/UDP direction-folding proof above.
    let (_, agg) = aggregate(&[
        sctp_frame(true, SCTP_INIT, &sctp_init_family_value(1)),
        sctp_frame(false, SCTP_INIT_ACK, &sctp_init_family_value(2)),
    ]);
    let sessions = agg.at_layer("sctp");
    assert_eq!(sessions.len(), 1);
    assert!(sessions[0].stats.iter().all(|s| s.packets == 1));
}
