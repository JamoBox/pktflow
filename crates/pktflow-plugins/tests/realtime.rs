//! Voice/video real-time stream behavior (11.10): proves D15's RTP/RTCP
//! reachability limitation mechanically, not just in prose — a `sip`
//! `INVITE` (whose SDP body, unparsed per D7, would name an RTP port)
//! followed by RTP-shaped packets on that port shows those packets
//! **stopping** at the UDP layer with `StopReason::UnclaimedRoute`, the
//! same gate-behaving-as-designed shape `tests/transport.rs`'s
//! `encrypted_udp_no_phantom` proves for 03.4 in general.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use pktflow_core::{LinkType, PacketMeta, ParseOpts, RouteId, StopReason, Value};
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

fn udp_datagram(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut d = Vec::new();
    d.extend_from_slice(&src_port.to_be_bytes());
    d.extend_from_slice(&dst_port.to_be_bytes());
    d.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    d.extend_from_slice(&[0x00, 0x00]);
    d.extend_from_slice(payload);
    d
}

/// A minimal SIP INVITE with an SDP body naming an RTP media port — the
/// body is unparsed remainder (D7); this fixture only needs `sip` itself
/// to route and parse correctly.
fn sip_invite_with_sdp(rtp_port: u16) -> Vec<u8> {
    let mut msg = "INVITE sip:bob@biloxi.example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bK776asdhds\r\n\
To: Bob <sip:bob@biloxi.example.com>\r\n\
From: Alice <sip:alice@atlanta.example.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.example.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Type: application/sdp\r\n\
\r\n"
        .as_bytes()
        .to_vec();
    // The SDP body: unparsed by `sip` (D7), but realistic enough to show
    // where the negotiated RTP port lives — "m=audio <port> RTP/AVP 0".
    msg.extend_from_slice(format!("m=audio {rtp_port} RTP/AVP 0\r\n").as_bytes());
    msg
}

/// V=2, no padding/extension/CSRC, PT=0 (PCMU) — an ordinary RTP frame,
/// the same shape `rtp.rs`'s own fixtures use.
fn rtp_frame(seq: u16, ssrc: u32) -> Vec<u8> {
    let mut b = vec![0x80, 0x00];
    b.extend_from_slice(&seq.to_be_bytes());
    b.extend_from_slice(&0xAABB_CCDDu32.to_be_bytes());
    b.extend_from_slice(&ssrc.to_be_bytes());
    b
}

#[test]
fn sip_invite_dispatches_while_the_negotiated_rtp_port_stops_unclaimed() {
    const RTP_PORT: u16 = 40000;

    let sip_payload = sip_invite_with_sdp(RTP_PORT);
    let mut sip_packet = eth(0x0800);
    let sip_udp = udp_datagram(5060, 5060, &sip_payload);
    sip_packet.extend_from_slice(&ipv4_header(
        17,
        (20 + sip_udp.len()) as u16,
        [10, 0, 0, 1],
        [10, 0, 0, 2],
    ));
    sip_packet.extend_from_slice(&sip_udp);

    let rtp_payload = rtp_frame(1000, 0x1234_5678);
    let mut rtp_packet = eth(0x0800);
    let rtp_udp = udp_datagram(RTP_PORT, RTP_PORT, &rtp_payload);
    rtp_packet.extend_from_slice(&ipv4_header(
        17,
        (20 + rtp_udp.len()) as u16,
        [10, 0, 0, 2],
        [10, 0, 0, 1],
    ));
    rtp_packet.extend_from_slice(&rtp_udp);

    let engine = Arc::new(pktflow_plugins::default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    let sip_dissected =
        engine.dissect(&sip_packet, meta(sip_packet.len(), 0), ParseOpts::default());
    let sip_protocols: Vec<_> = sip_dissected.layers.iter().map(|l| l.protocol).collect();
    assert_eq!(
        sip_protocols,
        ["ethernet", "ipv4", "udp", "sip"],
        "SIP INVITE dispatches all the way through"
    );
    assert_eq!(sip_dissected.stop, StopReason::Terminal);
    agg.ingest(&sip_dissected);

    let rtp_dissected =
        engine.dissect(&rtp_packet, meta(rtp_packet.len(), 1), ParseOpts::default());
    let rtp_protocols: Vec<_> = rtp_dissected.layers.iter().map(|l| l.protocol).collect();
    assert_eq!(
        rtp_protocols,
        ["ethernet", "ipv4", "udp"],
        "the RTP-shaped packet stops at UDP: no route named it (D15)"
    );
    assert_eq!(
        rtp_dissected.stop,
        StopReason::UnclaimedRoute(RouteId::UdpPort(RTP_PORT))
    );
    agg.ingest(&rtp_dissected);

    assert_eq!(agg.at_layer("sip").len(), 1, "one SIP dialog stream");
    assert_eq!(agg.at_layer("rtp").len(), 0, "zero rtp streams: gate held");

    let udp_streams = agg.at_layer("udp");
    assert_eq!(udp_streams.len(), 2, "one UDP stream per 5-tuple");
    let rtp_udp_stream = udp_streams
        .iter()
        .find(|s| s.key_fields.get("dst_port") == Some(&Value::U64(u64::from(RTP_PORT))))
        .expect("the RTP-port UDP stream exists");
    assert_eq!(
        rtp_udp_stream.opaque_bytes,
        rtp_payload.len() as u64,
        "the RTP frame lands as opaque bytes on its UDP stream"
    );
}
