//! File & mail transfer stream behavior (11.9): proves D15 mechanically
//! for `ftp`'s `PASV` reply and `tftp`'s ephemeral-port ceiling, the same
//! end-to-end gate-behaving-as-designed shape `tests/realtime.rs` proves
//! for `sip`/`rtp` and `tests/transport.rs`'s `encrypted_udp_no_phantom`
//! proves for 03.4 in general.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use pktflow_core::{LinkType, PacketMeta, ParseOpts, RouteId, StopReason};
use pktflow_flows::{Aggregator, AggregatorConfig};
use pktflow_plugins::ipv4::internet_checksum;

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

fn ipv4_header(protocol: u8, total_len: u16, src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
    let mut h = vec![0x45, 0x00];
    h.extend_from_slice(&total_len.to_be_bytes());
    h.extend_from_slice(&[0x1C, 0x46, 0x40, 0x00, 0x40, protocol, 0, 0]);
    h.extend_from_slice(&src);
    h.extend_from_slice(&dst);
    let ck = internet_checksum(&h);
    h[10..12].copy_from_slice(&ck.to_be_bytes());
    h
}

fn tcp_segment(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut s = Vec::new();
    s.extend_from_slice(&src_port.to_be_bytes());
    s.extend_from_slice(&dst_port.to_be_bytes());
    s.extend_from_slice(&[0, 0, 1, 0, 0, 0, 0, 0]); // seq, ack
    s.extend_from_slice(&0x5018u16.to_be_bytes()); // data offset 5, PSH|ACK
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

#[test]
fn ftp_pasv_reply_carries_the_port_as_text_with_no_data_channel_stream_fabricated() {
    // RFC 959 §4.1.2's classic example reply: the negotiated data-channel
    // port (200,13 -> 51213) is plain text in `arg` (D15) — this plugin
    // never turns it into a stream of its own.
    let pasv_reply = b"227 Entering Passive Mode (127,0,0,1,200,13)\r\n".to_vec();

    let mut packet = eth(0x0800);
    let tcp = tcp_segment(21, 55000, &pasv_reply);
    packet.extend_from_slice(&ipv4_header(
        6,
        (20 + tcp.len()) as u16,
        [10, 0, 0, 1],
        [10, 0, 0, 2],
    ));
    packet.extend_from_slice(&tcp);

    let engine = Arc::new(pktflow_plugins::default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());
    let dissected = engine.dissect(&packet, meta(packet.len(), 0), ParseOpts::default());
    let protocols: Vec<_> = dissected.layers.iter().map(|l| l.protocol).collect();
    assert_eq!(protocols, ["ethernet", "ipv4", "tcp", "ftp"]);
    assert_eq!(dissected.stop, StopReason::Complete);
    agg.ingest(&dissected);

    // Exactly one ftp stream (the control connection's app-stream child)
    // and exactly one tcp stream — no fabricated data-channel stream for
    // the port PASV announced, the D15 criterion proved mechanically.
    assert_eq!(agg.at_layer("tcp").len(), 1, "one TCP stream (control)");
    assert_eq!(agg.at_layer("ftp").len(), 1, "one ftp app-stream");
}

#[test]
fn tftp_data_packet_on_an_unclaimed_ephemeral_port_stops_at_udp() {
    // RRQ dispatches via the static UdpPort(69) claim and parses cleanly.
    let mut rrq = 1u16.to_be_bytes().to_vec(); // opcode RRQ
    rrq.extend_from_slice(b"boot.img\0octet\0");
    let mut rrq_packet = eth(0x0800);
    let rrq_udp = udp_datagram(50000, 69, &rrq);
    rrq_packet.extend_from_slice(&ipv4_header(
        17,
        (20 + rrq_udp.len()) as u16,
        [10, 0, 0, 1],
        [10, 0, 0, 2],
    ));
    rrq_packet.extend_from_slice(&rrq_udp);

    // The server's DATA reply rides a server-chosen ephemeral port on
    // *both* sides (D15) — neither UDP candidate (dst 50000, src 50000)
    // is a claimed route, so the gate stops rather than guessing.
    let mut data = 3u16.to_be_bytes().to_vec(); // opcode DATA
    data.extend_from_slice(&1u16.to_be_bytes()); // block 1
    data.extend_from_slice(&[0xAB; 16]);
    let mut data_packet = eth(0x0800);
    let data_udp = udp_datagram(50000, 50000, &data);
    data_packet.extend_from_slice(&ipv4_header(
        17,
        (20 + data_udp.len()) as u16,
        [10, 0, 0, 2],
        [10, 0, 0, 1],
    ));
    data_packet.extend_from_slice(&data_udp);

    let engine = Arc::new(pktflow_plugins::default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    let rrq_dissected =
        engine.dissect(&rrq_packet, meta(rrq_packet.len(), 0), ParseOpts::default());
    let rrq_protocols: Vec<_> = rrq_dissected.layers.iter().map(|l| l.protocol).collect();
    assert_eq!(rrq_protocols, ["ethernet", "ipv4", "udp", "tftp"]);
    assert_eq!(rrq_dissected.stop, StopReason::Complete);
    agg.ingest(&rrq_dissected);

    let data_dissected = engine.dissect(
        &data_packet,
        meta(data_packet.len(), 1),
        ParseOpts::default(),
    );
    let data_protocols: Vec<_> = data_dissected.layers.iter().map(|l| l.protocol).collect();
    assert_eq!(
        data_protocols,
        ["ethernet", "ipv4", "udp"],
        "the DATA packet stops at UDP: no claimed route named it (D15)"
    );
    assert_eq!(
        data_dissected.stop,
        StopReason::UnclaimedRoute(RouteId::UdpPort(50000))
    );
    agg.ingest(&data_dissected);

    // `tftp` declares no `stream_identity()` at all (module doc: an
    // identity would be vacuous given the D15 ceiling) — so it never
    // forms a stream of its own, even for the successfully-dissected RRQ;
    // both packets' bytes land on their respective (different) UDP
    // 5-tuples instead.
    assert_eq!(agg.at_layer("tftp").len(), 0, "tftp forms no stream");
    assert_eq!(
        agg.at_layer("udp").len(),
        2,
        "one UDP stream per distinct 5-tuple"
    );
}
