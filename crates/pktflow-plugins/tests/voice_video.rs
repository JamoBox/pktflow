//! Voice, video & real-time (11.10): SIP's Call-ID-keyed dialog folding
//! with call-progress ordering, and the D15 gate proven mechanically — an
//! RTP port SIP's SDP names is still unclaimed, so RTP traffic on it stops
//! at UDP rather than being guessed at.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use pktflow_core::{LinkType, PacketMeta, ParseOpts, RouteId, StopReason};
use pktflow_flows::{Aggregator, AggregatorConfig, Rollup};
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

fn eth() -> Vec<u8> {
    let mut f = vec![0xAA; 6];
    f.extend_from_slice(&[0xBB; 6]);
    f.extend_from_slice(&0x0800u16.to_be_bytes());
    f
}

fn ipv4_udp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut h = vec![
        0x45, 0x00, 0x00, 0x3C, 0x1C, 0x46, 0x40, 0x00, 0x40, 17, 0, 0,
    ];
    h.extend_from_slice(&src);
    h.extend_from_slice(&dst);
    let ck = internet_checksum(&h);
    h[10..12].copy_from_slice(&ck.to_be_bytes());
    h.extend_from_slice(&sport.to_be_bytes());
    h.extend_from_slice(&dport.to_be_bytes());
    h.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    h.extend_from_slice(&[0, 0]);
    h.extend_from_slice(payload);
    h
}

fn sip_frame(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, msg: &[u8]) -> Vec<u8> {
    let mut f = eth();
    f.extend_from_slice(&ipv4_udp(src, dst, sport, dport, msg));
    f
}

#[test]
fn sip_dialog_folds_into_one_call_id_stream_with_status_code_series_in_order() {
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    let call_id = "a84b4c76e66710@pc1.example.com";
    let invite = format!(
        "INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc1.example.com;branch=z9hG4bK1\r\n\
From: Alice <sip:alice@example.com>;tag=1928301774\r\n\
To: Bob <sip:bob@example.com>\r\n\
Call-ID: {call_id}\r\n\
CSeq: 1 INVITE\r\n\
\r\n"
    );
    let trying = format!("SIP/2.0 100 Trying\r\nCall-ID: {call_id}\r\nCSeq: 1 INVITE\r\n\r\n");
    let ringing = format!("SIP/2.0 180 Ringing\r\nCall-ID: {call_id}\r\nCSeq: 1 INVITE\r\n\r\n");
    let ok = format!("SIP/2.0 200 OK\r\nCall-ID: {call_id}\r\nCSeq: 1 INVITE\r\n\r\n");
    let ack =
        format!("ACK sip:bob@example.com SIP/2.0\r\nCall-ID: {call_id}\r\nCSeq: 1 ACK\r\n\r\n");
    let bye =
        format!("BYE sip:alice@example.com SIP/2.0\r\nCall-ID: {call_id}\r\nCSeq: 2 BYE\r\n\r\n");

    let dialog: [(bool, String); 6] = [
        (true, invite),
        (false, trying),
        (false, ringing),
        (false, ok),
        (true, ack),
        (true, bye),
    ];
    for (i, (from_caller, msg)) in dialog.iter().enumerate() {
        let frame = if *from_caller {
            sip_frame([10, 0, 0, 1], [10, 0, 0, 2], 5060, 5060, msg.as_bytes())
        } else {
            sip_frame([10, 0, 0, 2], [10, 0, 0, 1], 5060, 5060, msg.as_bytes())
        };
        agg.ingest(&engine.dissect(&frame, meta(frame.len(), i as u64), ParseOpts::default()));
    }

    let sip_streams = agg.at_layer("sip");
    assert_eq!(sip_streams.len(), 1, "one dialog stream per Call-ID");

    match sip_streams[0].rollups.get("method") {
        Some(Rollup::Accumulate { values, .. }) => {
            assert!(values
                .iter()
                .any(|v| *v == pktflow_core::Value::from("INVITE")));
            assert!(values
                .iter()
                .any(|v| *v == pktflow_core::Value::from("ACK")));
            assert!(values
                .iter()
                .any(|v| *v == pktflow_core::Value::from("BYE")));
        }
        other => panic!("wrong rollup: {other:?}"),
    }

    match sip_streams[0].rollups.get("status_code") {
        Some(Rollup::Series {
            ring, truncated, ..
        }) => {
            assert!(!truncated);
            let sequence: Vec<u64> = ring
                .iter()
                .map(|p| match &p.value {
                    pktflow_core::Value::U64(v) => *v,
                    other => panic!("unexpected {other:?}"),
                })
                .collect();
            assert_eq!(sequence, [100, 180, 200], "call-progress order preserved");
        }
        other => panic!("wrong rollup: {other:?}"),
    }
}

#[test]
fn rtp_port_named_in_sip_sdp_still_stops_unclaimed_at_udp_d15_gate() {
    // D15's clearest instance, proven mechanically: even though a SIP
    // INVITE's SDP body would name an RTP port in a real exchange, this
    // plugin never parses the SDP body (D7) and rtp/rtcp declare no
    // claims() — so RTP traffic on that "negotiated" port still gates shut
    // at UDP, exactly as designed, not silently guessed at.
    let engine = Arc::new(default_engine());

    let mut rtp_bytes = vec![0x80, 0x00]; // V2, payload_type 0 (PCMU)
    rtp_bytes.extend_from_slice(&1u16.to_be_bytes()); // sequence_number
    rtp_bytes.extend_from_slice(&8000u32.to_be_bytes()); // timestamp
    rtp_bytes.extend_from_slice(&0xCAFE_BABEu32.to_be_bytes()); // ssrc
    rtp_bytes.extend_from_slice(&[0xAB; 160]); // PCMU payload

    let frame = sip_frame([10, 0, 0, 1], [10, 0, 0, 2], 40000, 40002, &rtp_bytes);
    let packet = engine.dissect(&frame, meta(frame.len(), 0), ParseOpts::default());
    let protocols: Vec<_> = packet.layers.iter().map(|l| l.protocol).collect();
    assert_eq!(protocols, ["ethernet", "ipv4", "udp"]);
    assert_eq!(
        packet.stop,
        StopReason::UnclaimedRoute(RouteId::UdpPort(40002))
    );
}
