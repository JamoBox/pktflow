//! Application-layer behavior (06.6): DNS/DHCP/NTP fixtures, the
//! app-stream pattern, DORA ordering, and the DNS parser-bomb defenses
//! (with a proptest fuzz of the name decoder).

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use pktflow_core::{LinkType, PacketMeta, ParseOpts, StopReason, Value};
use pktflow_flows::{Aggregator, AggregatorConfig, Rollup};
use pktflow_plugins::default_engine;
use pktflow_plugins::dns::decode_name;
use pktflow_plugins::ipv4::internet_checksum;
use proptest::prelude::*;

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

/// Standard query for `<name>` (A record).
fn dns_query(id: u16, name_labels: &[&str]) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(&id.to_be_bytes());
    m.extend_from_slice(&[0x01, 0x00]); // RD
    m.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name_labels {
        m.push(label.len() as u8);
        m.extend_from_slice(label.as_bytes());
    }
    m.push(0);
    m.extend_from_slice(&[0, 1, 0, 1]); // A, IN
    m
}

fn dns_frame(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, msg: &[u8]) -> Vec<u8> {
    let mut f = eth();
    f.extend_from_slice(&ipv4_udp(src, dst, sport, dport, msg));
    f
}

#[test]
fn dns_query_and_compressed_response_parse_exactly() {
    let engine = Arc::new(default_engine());

    // Query: example.com A.
    let query = dns_query(0x1234, &["example", "com"]);
    let frame = dns_frame([10, 0, 0, 1], [10, 0, 0, 53], 34567, 53, &query);
    let packet = engine.dissect(&frame, meta(frame.len(), 0), ParseOpts::default());
    let protocols: Vec<_> = packet.layers.iter().map(|l| l.protocol).collect();
    assert_eq!(protocols, ["ethernet", "ipv4", "udp", "dns"]);
    assert_eq!(packet.stop, StopReason::Complete);
    let dns_layer = &packet.layers[3];
    assert_eq!(
        dns_layer.fields.get("qname"),
        Some(&Value::from("example.com"))
    );
    assert_eq!(
        dns_layer.fields.get("is_response"),
        Some(&Value::Bool(false))
    );
    assert_eq!(dns_layer.fields.get("qtype"), Some(&Value::U64(1)));

    // Response with a compression pointer (answer name -> offset 12) and
    // an A record 93.184.216.34.
    let mut response = dns_query(0x1234, &["example", "com"]);
    response[2] = 0x81; // QR|RD
    response[3] = 0x80; // RA
    response[7] = 1; // ancount = 1
    response.extend_from_slice(&[0xC0, 0x0C]); // name: pointer to question
    response.extend_from_slice(&[0, 1, 0, 1]); // A, IN
    response.extend_from_slice(&[0, 0, 0, 60]); // ttl
    response.extend_from_slice(&[0, 4, 93, 184, 216, 34]);
    let frame = dns_frame([10, 0, 0, 53], [10, 0, 0, 1], 53, 34567, &response);
    let packet = engine.dissect(&frame, meta(frame.len(), 1), ParseOpts::default());
    let dns_layer = &packet.layers[3];
    assert_eq!(
        dns_layer.fields.get("is_response"),
        Some(&Value::Bool(true))
    );
    assert_eq!(dns_layer.fields.get("rcode"), Some(&Value::U64(0)));
    assert_eq!(
        dns_layer.fields.get("answers"),
        Some(&Value::List(vec![Value::from("93.184.216.34")]))
    );
}

#[test]
fn dns_bombs_decline_safely() {
    // Self-pointing compression pointer at the question name.
    let mut type_loop = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    type_loop.extend_from_slice(&[0xC0, 0x0C]); // points at itself (offset 12)
    type_loop.extend_from_slice(&[0, 1, 0, 1]);

    // Forward pointer: targets beyond its own position.
    let mut forward = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    forward.extend_from_slice(&[0xC0, 0x20]);
    forward.extend_from_slice(&[0, 1, 0, 1]);

    let engine = Arc::new(default_engine());
    for msg in [type_loop, forward] {
        let frame = dns_frame([10, 0, 0, 1], [10, 0, 0, 53], 34567, 53, &msg);
        let packet = engine.dissect(&frame, meta(frame.len(), 0), ParseOpts::default());
        // The DNS layer declines; port-claimed traffic that fails parse is
        // a PluginError stop (03.4 row 3) — counted, visible, no guessing.
        let protocols: Vec<_> = packet.layers.iter().map(|l| l.protocol).collect();
        assert_eq!(protocols, ["ethernet", "ipv4", "udp"]);
        assert_eq!(packet.stop, StopReason::PluginError);
    }
}

proptest! {
    /// The name decoder is the classic parser bomb (06.6): arbitrary
    /// bytes and start offsets must terminate without panicking.
    #[test]
    fn decode_name_never_panics_or_hangs(
        msg in proptest::collection::vec(any::<u8>(), 0..300),
        start in 0usize..300,
    ) {
        let _ = decode_name(&msg, start);
    }
}

#[test]
fn app_stream_pattern_one_dns_child_with_accumulated_qnames() {
    // The PRD §4.A use case: query names observed in a UDP stream.
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    for (i, labels) in [
        &["example", "com"][..],
        &["rust-lang", "org"][..],
        &["example", "com"][..], // repeat: no new distinct value
    ]
    .iter()
    .enumerate()
    {
        let msg = dns_query(0x1000 + i as u16, labels);
        let frame = dns_frame([10, 0, 0, 1], [10, 0, 0, 53], 34567, 53, &msg);
        agg.ingest(&engine.dissect(&frame, meta(frame.len(), i as u64), ParseOpts::default()));
    }

    // Exactly one dns child under the UDP stream.
    let udp_stream = agg.at_layer("udp")[0];
    let dns_streams = agg.at_layer("dns");
    assert_eq!(dns_streams.len(), 1, "one app-stream per transport stream");
    assert_eq!(dns_streams[0].parent, Some(udp_stream.id));

    match dns_streams[0].rollups.get("qname") {
        Some(Rollup::Accumulate { values, count, .. }) => {
            assert_eq!(*count, 3);
            assert_eq!(
                values.as_slice(),
                [Value::from("example.com"), Value::from("rust-lang.org")]
            );
        }
        other => panic!("wrong rollup: {other:?}"),
    }
}

/// BOOTP + magic cookie + options (53 = msg_type, then END).
fn dhcp_msg(op: u8, xid: u32, msg_type: u8) -> Vec<u8> {
    let mut m = vec![op, 1, 6, 0];
    m.extend_from_slice(&xid.to_be_bytes());
    m.extend_from_slice(&[0; 8]); // secs, flags, ciaddr
    m.extend_from_slice(&[0; 12]); // yiaddr, siaddr, giaddr
    m.extend_from_slice(&[0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E]); // chaddr
    m.extend_from_slice(&[0; 10]);
    m.extend_from_slice(&[0; 192]); // sname + file
    m.extend_from_slice(&0x63825363u32.to_be_bytes());
    m.extend_from_slice(&[53, 1, msg_type]);
    m.extend_from_slice(&[255]);
    m
}

#[test]
fn dhcp_dora_series_preserves_order() {
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    // Discover/Offer/Request/Ack: client broadcasts from :68, server :67.
    let dora = [(1u8, true), (2, false), (3, true), (5, false)];
    for (i, (msg_type, from_client)) in dora.iter().enumerate() {
        let msg = dhcp_msg(if *from_client { 1 } else { 2 }, 0xDEAD, *msg_type);
        let (src, dst, sport, dport) = if *from_client {
            ([0, 0, 0, 0], [255, 255, 255, 255], 68, 67)
        } else {
            ([10, 0, 0, 53], [10, 0, 0, 1], 67, 68)
        };
        let mut frame = eth();
        frame.extend_from_slice(&ipv4_udp(src, dst, sport, dport, &msg));
        agg.ingest(&engine.dissect(&frame, meta(frame.len(), i as u64), ParseOpts::default()));
    }

    let dhcp_streams = agg.at_layer("dhcp");
    // Two transport streams (broadcast + unicast paths) — check the DORA
    // order across their series combined by time.
    let mut observed: Vec<(SystemTime, u64)> = Vec::new();
    for s in &dhcp_streams {
        if let Some(Rollup::Series {
            ring, truncated, ..
        }) = s.rollups.get("msg_type")
        {
            assert!(!truncated);
            for point in ring {
                match &point.value {
                    Value::U64(v) => observed.push((point.ts, *v)),
                    other => panic!("unexpected {other:?}"),
                }
            }
        }
    }
    observed.sort_by_key(|(ts, _)| *ts);
    let sequence: Vec<u64> = observed.into_iter().map(|(_, v)| v).collect();
    assert_eq!(sequence, [1, 2, 3, 5], "the DORA sequence, in order");
}

#[test]
fn ntp_exchange_parses_and_rolls_up() {
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    let ntp_msg = |mode: u8, stratum: u8| {
        let mut m = vec![0x23 & !0x07 | mode, stratum, 6, 0xEC]; // v4
        m.extend_from_slice(&[0; 8]); // root delay + dispersion
        m.extend_from_slice(b"GPS\0"); // ref id
        m.extend_from_slice(&[0; 32]); // four timestamps
        m
    };

    for (i, (mode, stratum, from_client)) in [(3u8, 0u8, true), (4, 2, false)].iter().enumerate() {
        let (src, dst, sport, dport) = if *from_client {
            ([10, 0, 0, 1], [10, 0, 0, 123], 45000, 123)
        } else {
            ([10, 0, 0, 123], [10, 0, 0, 1], 123, 45000)
        };
        let mut frame = eth();
        frame.extend_from_slice(&ipv4_udp(src, dst, sport, dport, &ntp_msg(*mode, *stratum)));
        agg.ingest(&engine.dissect(&frame, meta(frame.len(), i as u64), ParseOpts::default()));
    }

    let ntp_streams = agg.at_layer("ntp");
    assert_eq!(ntp_streams.len(), 1, "one app-stream on the UDP stream");
    match ntp_streams[0].rollups.get("mode") {
        Some(Rollup::Accumulate { values, .. }) => {
            assert_eq!(values.as_slice(), [Value::U64(3), Value::U64(4)]);
        }
        other => panic!("wrong rollup: {other:?}"),
    }
    match ntp_streams[0].rollups.get("stratum") {
        Some(Rollup::Sample { first, last }) => {
            assert_eq!(first, &Some(Value::U64(0)));
            assert_eq!(last, &Some(Value::U64(2)));
        }
        other => panic!("wrong rollup: {other:?}"),
    }
}
