//! Application-layer behavior (06.6, 11.11): DNS/DHCP/NTP/Syslog/SNMP
//! fixtures, the app-stream pattern, DORA ordering, and the DNS
//! parser-bomb defenses (with proptest fuzzes of the DNS name decoder and
//! the syslog/SNMP dissectors).

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use pktflow_core::{
    Depth, LayerPlugin, LinkType, PacketMeta, ParseCtx, ParseOpts, StopReason, Value,
};
use pktflow_flows::{Aggregator, AggregatorConfig, Rollup};
use pktflow_plugins::default_engine;
use pktflow_plugins::dns::decode_name;
use pktflow_plugins::ipv4::internet_checksum;
use pktflow_plugins::wireguard::Wireguard;
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

/// RFC 6762 standard query for `<name>` (A record), sent to the mDNS
/// multicast group's port. `qu` sets the question's QU bit (§5.4).
fn mdns_query(id: u16, name_labels: &[&str], qu: bool) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(&id.to_be_bytes());
    m.extend_from_slice(&[0x00, 0x00]);
    m.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name_labels {
        m.push(label.len() as u8);
        m.extend_from_slice(label.as_bytes());
    }
    m.push(0);
    m.extend_from_slice(&[0, 1]); // type A
    let class = if qu { 0x8001u16 } else { 0x0001 };
    m.extend_from_slice(&class.to_be_bytes());
    m
}

#[test]
fn mdns_app_stream_is_distinct_from_dns_and_accumulates_qnames() {
    // The PRD §4.A pattern, applied to mDNS's `.local` namespace instead of
    // the resolver-hierarchy names `dns_query_and_compressed_response_parse_exactly`
    // covers — same UDP-multicast destination (5353) across every packet.
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    for (i, (labels, qu)) in [
        (&["printer", "local"][..], true),
        (&["nas", "local"][..], false),
        (&["printer", "local"][..], true), // repeat: no new distinct value
    ]
    .iter()
    .enumerate()
    {
        let msg = mdns_query(0x0000, labels, *qu);
        let mut frame = eth();
        frame.extend_from_slice(&ipv4_udp([10, 0, 0, 5], [224, 0, 0, 251], 5353, 5353, &msg));
        agg.ingest(&engine.dissect(&frame, meta(frame.len(), i as u64), ParseOpts::default()));
    }

    let mdns_streams = agg.at_layer("mdns");
    assert_eq!(mdns_streams.len(), 1, "one app-stream per transport stream");
    assert!(
        agg.at_layer("dns").is_empty(),
        "mdns must not fold into dns's app-stream constant"
    );

    match mdns_streams[0].rollups.get("qname") {
        Some(Rollup::Accumulate { values, count, .. }) => {
            assert_eq!(*count, 3);
            assert_eq!(
                values.as_slice(),
                [Value::from("printer.local"), Value::from("nas.local")]
            );
        }
        other => panic!("wrong rollup: {other:?}"),
    }
}

#[test]
fn mdns_response_reports_cache_flush_bit() {
    let engine = Arc::new(default_engine());

    let mut response = mdns_query(0x0000, &["printer", "local"], false);
    response[2] = 0x84; // QR|AA
    response[7] = 1; // ancount = 1
    response.extend_from_slice(&[0xC0, 0x0C]); // name: pointer to question
    response.extend_from_slice(&[0, 1, 0x80, 0x01]); // type A, class IN | cache-flush bit
    response.extend_from_slice(&[0, 0, 0, 120]); // ttl
    response.extend_from_slice(&[0, 4, 192, 0, 2, 5]); // rdlength + A record
    let mut frame = eth();
    frame.extend_from_slice(&ipv4_udp(
        [10, 0, 0, 5],
        [224, 0, 0, 251],
        5353,
        5353,
        &response,
    ));
    let packet = engine.dissect(&frame, meta(frame.len(), 0), ParseOpts::default());
    let protocols: Vec<_> = packet.layers.iter().map(|l| l.protocol).collect();
    assert_eq!(protocols, ["ethernet", "ipv4", "udp", "mdns"]);
    let mdns_layer = &packet.layers[3];
    assert_eq!(
        mdns_layer.fields.get("cache_flush"),
        Some(&Value::Bool(true))
    );
    assert_eq!(
        mdns_layer.fields.get("answers"),
        Some(&Value::List(vec![Value::from("192.0.2.5")]))
    );
}

fn ssdp_frame(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, msg: &[u8]) -> Vec<u8> {
    let mut f = eth();
    f.extend_from_slice(&ipv4_udp(src, dst, sport, dport, msg));
    f
}

#[test]
fn ssdp_app_stream_accumulates_nts_and_samples_location() {
    // A device's ssdp:alive announcement followed by its ssdp:byebye
    // withdrawal (UPnP DA v2.0 §1.2.1/§1.2.3), both multicast from the
    // same source — one app-stream, `nts` accumulating both distinct
    // values, `location` sampling first/last (byebye carries none, so
    // `last` stays the alive announcement's URL).
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    let alive = b"NOTIFY * HTTP/1.1\r\n\
HOST: 239.255.255.250:1900\r\n\
LOCATION: http://192.168.1.20:8080/description.xml\r\n\
NT: upnp:rootdevice\r\n\
NTS: ssdp:alive\r\n\
USN: uuid:4d696e69::upnp:rootdevice\r\n\
\r\n";
    let byebye = b"NOTIFY * HTTP/1.1\r\n\
HOST: 239.255.255.250:1900\r\n\
NT: upnp:rootdevice\r\n\
NTS: ssdp:byebye\r\n\
USN: uuid:4d696e69::upnp:rootdevice\r\n\
\r\n";

    for (i, msg) in [alive.as_slice(), byebye.as_slice()].iter().enumerate() {
        let frame = ssdp_frame([10, 0, 0, 20], [239, 255, 255, 250], 1900, 1900, msg);
        agg.ingest(&engine.dissect(&frame, meta(frame.len(), i as u64), ParseOpts::default()));
    }

    let udp_stream = agg.at_layer("udp")[0];
    let ssdp_streams = agg.at_layer("ssdp");
    assert_eq!(ssdp_streams.len(), 1, "one app-stream per transport stream");
    assert_eq!(ssdp_streams[0].parent, Some(udp_stream.id));

    match ssdp_streams[0].rollups.get("nts") {
        Some(Rollup::Accumulate { values, count, .. }) => {
            assert_eq!(*count, 2);
            assert_eq!(
                values.as_slice(),
                [Value::from("ssdp:alive"), Value::from("ssdp:byebye")]
            );
        }
        other => panic!("wrong rollup: {other:?}"),
    }
    match ssdp_streams[0].rollups.get("location") {
        Some(Rollup::Sample { first, last }) => {
            let url = Some(Value::from("http://192.168.1.20:8080/description.xml"));
            assert_eq!(first, &url);
            assert_eq!(last, &url);
        }
        other => panic!("wrong rollup: {other:?}"),
    }
}

#[test]
fn ssdp_m_search_and_response_are_declined_as_ssdp_by_a_get_request() {
    // Claim-honesty check (06.6's port-claim note, applied here): a
    // non-SSDP payload on port 1900 must decline as `ssdp`, not silently
    // misparse as one.
    let engine = Arc::new(default_engine());
    let bogus = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let frame = ssdp_frame([10, 0, 0, 1], [10, 0, 0, 2], 1900, 1900, bogus);
    let packet = engine.dissect(&frame, meta(frame.len(), 0), ParseOpts::default());
    let protocols: Vec<_> = packet.layers.iter().map(|l| l.protocol).collect();
    assert_eq!(protocols, ["ethernet", "ipv4", "udp"]);
    assert_eq!(packet.stop, StopReason::PluginError);
}

proptest! {
    /// Same parser-bomb discipline as syslog/SNMP: arbitrary bytes behind
    /// the claimed port must never panic the header-block/line scanner.
    #[test]
    fn ssdp_parse_never_panics(payload in proptest::collection::vec(any::<u8>(), 0..300)) {
        let engine = Arc::new(default_engine());
        let frame = ssdp_frame([10, 0, 0, 1], [10, 0, 0, 2], 1900, 1900, &payload);
        let _ = engine.dissect(&frame, meta(frame.len(), 0), ParseOpts::default());
    }
}

/// RFC 4795 standard query for `<name>` (A record). `flags` sets the raw
/// flags word so tests can flip the `C`/`T` bits LLMNR repurposes from
/// DNS's `AA`/`RD` positions (§2.1.1).
fn llmnr_query(id: u16, name_labels: &[&str], flags: u16) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(&id.to_be_bytes());
    m.extend_from_slice(&flags.to_be_bytes());
    m.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name_labels {
        m.push(label.len() as u8);
        m.extend_from_slice(label.as_bytes());
    }
    m.push(0);
    m.extend_from_slice(&[0, 1, 0, 1]); // type A, class IN
    m
}

#[test]
fn llmnr_app_stream_is_distinct_from_dns_and_mdns_and_accumulates_qnames() {
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    for (i, labels) in [&["host-a"][..], &["host-b"][..], &["host-a"][..]]
        .iter()
        .enumerate()
    {
        let msg = llmnr_query(0x0000, labels, 0x0000);
        let mut frame = eth();
        frame.extend_from_slice(&ipv4_udp([10, 0, 0, 5], [224, 0, 0, 252], 5355, 5355, &msg));
        agg.ingest(&engine.dissect(&frame, meta(frame.len(), i as u64), ParseOpts::default()));
    }

    let llmnr_streams = agg.at_layer("llmnr");
    assert_eq!(
        llmnr_streams.len(),
        1,
        "one app-stream per transport stream"
    );
    assert!(
        agg.at_layer("dns").is_empty(),
        "llmnr must not fold into dns's app-stream constant"
    );
    assert!(
        agg.at_layer("mdns").is_empty(),
        "llmnr must not fold into mdns's app-stream constant"
    );

    match llmnr_streams[0].rollups.get("qname") {
        Some(Rollup::Accumulate { values, count, .. }) => {
            assert_eq!(*count, 3);
            assert_eq!(
                values.as_slice(),
                [Value::from("host-a"), Value::from("host-b")]
            );
        }
        other => panic!("wrong rollup: {other:?}"),
    }
}

#[test]
fn llmnr_response_reports_conflict_and_tentative_bits() {
    let engine = Arc::new(default_engine());

    // QR|C: responder has detected the queried name is not unique on this
    // link (RFC 4795 §7.1).
    let mut response = llmnr_query(0x0000, &["host-a"], 0x8400);
    response[7] = 1; // ancount = 1
    response.extend_from_slice(&[0xC0, 0x0C]); // name: pointer to question
    response.extend_from_slice(&[0, 1, 0, 1]); // type A, class IN
    response.extend_from_slice(&[0, 0, 0, 120]); // ttl
    response.extend_from_slice(&[0, 4, 192, 0, 2, 5]); // rdlength + A record
    let mut frame = eth();
    frame.extend_from_slice(&ipv4_udp(
        [10, 0, 0, 5],
        [224, 0, 0, 252],
        5355,
        5355,
        &response,
    ));
    let packet = engine.dissect(&frame, meta(frame.len(), 0), ParseOpts::default());
    let protocols: Vec<_> = packet.layers.iter().map(|l| l.protocol).collect();
    assert_eq!(protocols, ["ethernet", "ipv4", "udp", "llmnr"]);
    let llmnr_layer = &packet.layers[3];
    assert_eq!(llmnr_layer.fields.get("conflict"), Some(&Value::Bool(true)));
    assert_eq!(
        llmnr_layer.fields.get("tentative"),
        Some(&Value::Bool(false))
    );
    assert_eq!(
        llmnr_layer.fields.get("answers"),
        Some(&Value::List(vec![Value::from("192.0.2.5")]))
    );
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

fn syslog_frame(src: [u8; 4], dst: [u8; 4], sport: u16, msg: &[u8]) -> Vec<u8> {
    let mut f = eth();
    f.extend_from_slice(&ipv4_udp(src, dst, sport, 514, msg));
    f
}

/// RFC 5424 §6.5 Example 1, verbatim (the `BOM` placeholder in the RFC
/// text is the literal 3-byte UTF-8 byte order mark, EF BB BF).
#[test]
fn syslog_rfc5424_example_parses_exactly() {
    let mut msg = b"<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - ".to_vec();
    msg.extend_from_slice(&[0xEF, 0xBB, 0xBF]);
    msg.extend_from_slice(b"'su root' failed for lonvick on /dev/pts/8");

    let engine = Arc::new(default_engine());
    let frame = syslog_frame([10, 0, 0, 1], [10, 0, 0, 53], 45000, &msg);
    let packet = engine.dissect(&frame, meta(frame.len(), 0), ParseOpts::default());

    let protocols: Vec<_> = packet.layers.iter().map(|l| l.protocol).collect();
    assert_eq!(protocols, ["ethernet", "ipv4", "udp", "syslog"]);
    assert_eq!(packet.stop, StopReason::Complete);

    let layer = &packet.layers[3];
    assert_eq!(layer.fields.get("facility"), Some(&Value::U64(4)));
    assert_eq!(layer.fields.get("severity"), Some(&Value::U64(2)));
    assert_eq!(layer.fields.get("version"), Some(&Value::U64(1)));
    assert_eq!(
        layer.fields.get("hostname"),
        Some(&Value::from("mymachine.example.com"))
    );
    assert_eq!(layer.fields.get("app_name"), Some(&Value::from("su")));
    assert_eq!(
        layer.fields.get("msg"),
        Some(&Value::from(
            "\u{FEFF}'su root' failed for lonvick on /dev/pts/8"
        ))
    );
}

/// RFC 3164 §5.4 Example 1, verbatim.
#[test]
fn syslog_rfc3164_legacy_example_parses_exactly() {
    let msg = b"<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8";

    let engine = Arc::new(default_engine());
    let frame = syslog_frame([10, 0, 0, 1], [10, 0, 0, 53], 45000, msg);
    let packet = engine.dissect(&frame, meta(frame.len(), 0), ParseOpts::default());

    let protocols: Vec<_> = packet.layers.iter().map(|l| l.protocol).collect();
    assert_eq!(protocols, ["ethernet", "ipv4", "udp", "syslog"]);
    assert_eq!(packet.stop, StopReason::Complete);

    let layer = &packet.layers[3];
    assert_eq!(layer.fields.get("facility"), Some(&Value::U64(4)));
    assert_eq!(layer.fields.get("severity"), Some(&Value::U64(2)));
    assert_eq!(layer.fields.get("version"), Some(&Value::U64(0)));
    assert_eq!(
        layer.fields.get("hostname"),
        Some(&Value::from("mymachine"))
    );
    assert_eq!(layer.fields.get("app_name"), Some(&Value::from("su")));
    assert_eq!(
        layer.fields.get("msg"),
        Some(&Value::from("'su root' failed for lonvick on /dev/pts/8"))
    );
}

/// TAG with an explicit PID suffix, a common real-world variant of
/// RFC 3164's TAG (`sshd[1234]:`).
#[test]
fn syslog_rfc3164_tag_with_pid_parses() {
    let msg = b"<38>Jan  5 03:00:00 server1 sshd[1234]: Accepted publickey for root";
    let engine = Arc::new(default_engine());
    let frame = syslog_frame([10, 0, 0, 1], [10, 0, 0, 53], 45000, msg);
    let packet = engine.dissect(&frame, meta(frame.len(), 0), ParseOpts::default());

    let layer = &packet.layers[3];
    assert_eq!(layer.fields.get("app_name"), Some(&Value::from("sshd")));
    assert_eq!(
        layer.fields.get("msg"),
        Some(&Value::from("Accepted publickey for root"))
    );
}

/// Malformed syslog on the claimed port declines cleanly (03.4 row 3):
/// a missing PRI marker, a dangling escape in structured data, and a
/// legacy timestamp too short to be the fixed 15-byte field.
#[test]
fn syslog_malformed_input_declines_safely() {
    let engine = Arc::new(default_engine());
    let bad_inputs: [&[u8]; 3] = [
        b"34>1 2003-10-11T22:14:15.003Z host app - - -",
        b"<34>1 2003-10-11T22:14:15.003Z host app - - [id\\",
        b"<34>Oct 11 22:1",
    ];
    for msg in bad_inputs {
        let frame = syslog_frame([10, 0, 0, 1], [10, 0, 0, 53], 45000, msg);
        let packet = engine.dissect(&frame, meta(frame.len(), 0), ParseOpts::default());
        let protocols: Vec<_> = packet.layers.iter().map(|l| l.protocol).collect();
        assert_eq!(protocols, ["ethernet", "ipv4", "udp"]);
        assert_eq!(packet.stop, StopReason::PluginError);
    }
}

/// App-stream pattern (06.6): one `syslog` child per UDP stream, with
/// `severity` accumulated across messages from both RFC framings.
#[test]
fn app_stream_pattern_one_syslog_child_with_accumulated_severity() {
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    let messages: [&[u8]; 3] = [
        b"<34>1 2003-10-11T22:14:15.003Z host1 su - - -",
        b"<13>Oct 11 22:14:16 host1 cron:",
        b"<34>1 2003-10-11T22:14:17.003Z host1 su - - -", // repeat severity: no new distinct value
    ];
    for (i, msg) in messages.iter().enumerate() {
        let frame = syslog_frame([10, 0, 0, 1], [10, 0, 0, 53], 45000, msg);
        agg.ingest(&engine.dissect(&frame, meta(frame.len(), i as u64), ParseOpts::default()));
    }

    let udp_stream = agg.at_layer("udp")[0];
    let syslog_streams = agg.at_layer("syslog");
    assert_eq!(
        syslog_streams.len(),
        1,
        "one app-stream per transport stream"
    );
    assert_eq!(syslog_streams[0].parent, Some(udp_stream.id));

    match syslog_streams[0].rollups.get("severity") {
        Some(Rollup::Accumulate { values, count, .. }) => {
            assert_eq!(*count, 3);
            assert_eq!(values.as_slice(), [Value::U64(2), Value::U64(5)]);
        }
        other => panic!("wrong rollup: {other:?}"),
    }
}

proptest! {
    /// The dissector must decline or succeed on arbitrary bytes behind a
    /// claimed port — never panic (parser-bomb discipline, same standard
    /// as `decode_name_never_panics_or_hangs`).
    #[test]
    fn syslog_parse_never_panics(payload in proptest::collection::vec(any::<u8>(), 0..300)) {
        let engine = Arc::new(default_engine());
        let frame = syslog_frame([10, 0, 0, 1], [10, 0, 0, 53], 45000, &payload);
        let _ = engine.dissect(&frame, meta(frame.len(), 0), ParseOpts::default());
    }
}

fn snmp_frame(src: [u8; 4], dst: [u8; 4], sport: u16, msg: &[u8]) -> Vec<u8> {
    let mut f = eth();
    f.extend_from_slice(&ipv4_udp(src, dst, sport, 161, msg));
    f
}

/// v1 GetRequest for `sysDescr.0` (RFC 1213), community `"public"`,
/// request-id 1 — same bytes as `snmp.rs`'s and `conformance.rs`'s
/// fixtures, verified against RFC 1157 §4.1.1/§4.1.2.
fn snmp_get_request_v1() -> Vec<u8> {
    vec![
        0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6C, 0x69, 0x63, 0xA0, 0x19,
        0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0E, 0x30, 0x0C, 0x06, 0x08,
        0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00,
    ]
}

/// v2c SNMPv2-Trap (tag `[7]`), same bytes as `conformance.rs`'s fixture.
fn snmp_v2_trap() -> Vec<u8> {
    vec![
        0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6C, 0x69, 0x63, 0xA7, 0x19,
        0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0E, 0x30, 0x0C, 0x06, 0x08,
        0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00, 0x05, 0x00,
    ]
}

#[test]
fn snmp_get_request_v1_parses_exactly() {
    let engine = Arc::new(default_engine());
    let msg = snmp_get_request_v1();
    let frame = snmp_frame([10, 0, 0, 5], [10, 0, 0, 1], 45000, &msg);
    let packet = engine.dissect(&frame, meta(frame.len(), 0), ParseOpts::default());

    let protocols: Vec<_> = packet.layers.iter().map(|l| l.protocol).collect();
    assert_eq!(protocols, ["ethernet", "ipv4", "udp", "snmp"]);
    assert_eq!(packet.stop, StopReason::Complete);

    let layer = &packet.layers[3];
    assert_eq!(layer.fields.get("version"), Some(&Value::U64(0)));
    assert_eq!(layer.fields.get("community"), Some(&Value::from("public")));
    assert_eq!(layer.fields.get("pdu_type"), Some(&Value::U64(0)));
    assert_eq!(layer.fields.get("request_id"), Some(&Value::U64(1)));
}

/// Also reachable via the trap port (161 is the query/response port, 162
/// is the trap-receiver port — both are `claims()`ed, RFC 1157 §5).
#[test]
fn snmp_trap_reaches_dissector_on_port_162() {
    let engine = Arc::new(default_engine());
    let msg = snmp_v2_trap();
    let mut f = eth();
    let mut h = vec![
        0x45, 0x00, 0x00, 0x3C, 0x1C, 0x46, 0x40, 0x00, 0x40, 17, 0, 0,
    ];
    h.extend_from_slice(&[10, 0, 0, 1]);
    h.extend_from_slice(&[10, 0, 0, 255]);
    let ck = internet_checksum(&h);
    h[10..12].copy_from_slice(&ck.to_be_bytes());
    h.extend_from_slice(&162u16.to_be_bytes()); // src: agent's trap source port
    h.extend_from_slice(&162u16.to_be_bytes()); // dst: trap-receiver's well-known port
    h.extend_from_slice(&((8 + msg.len()) as u16).to_be_bytes());
    h.extend_from_slice(&[0, 0]);
    h.extend_from_slice(&msg);
    f.extend_from_slice(&h);

    let packet = engine.dissect(&f, meta(f.len(), 0), ParseOpts::default());
    let protocols: Vec<_> = packet.layers.iter().map(|l| l.protocol).collect();
    assert_eq!(protocols, ["ethernet", "ipv4", "udp", "snmp"]);
    let layer = &packet.layers[3];
    assert_eq!(layer.fields.get("pdu_type"), Some(&Value::U64(7)));
}

/// Malformed SNMP on the claimed port declines cleanly (03.4 row 3): a
/// non-SEQUENCE outer tag, a length claiming more bytes than the message
/// holds, and an indefinite-length outer TLV.
#[test]
fn snmp_malformed_input_declines_safely() {
    let engine = Arc::new(default_engine());
    let bad_inputs: [&[u8]; 3] = [
        &[0x31, 0x03, 0x02, 0x01, 0x00],             // SET, not SEQUENCE
        &[0x30, 0x7F, 0x02, 0x01, 0x00],             // declared length far exceeds available bytes
        &[0x30, 0x80, 0x02, 0x01, 0x00, 0x00, 0x00], // indefinite length, unsupported
    ];
    for msg in bad_inputs {
        let frame = snmp_frame([10, 0, 0, 5], [10, 0, 0, 1], 45000, msg);
        let packet = engine.dissect(&frame, meta(frame.len(), 0), ParseOpts::default());
        let protocols: Vec<_> = packet.layers.iter().map(|l| l.protocol).collect();
        assert_eq!(protocols, ["ethernet", "ipv4", "udp"]);
        assert_eq!(packet.stop, StopReason::PluginError);
    }
}

/// App-stream pattern (06.6): one `snmp` child per UDP stream, with
/// `pdu_type` accumulated and `community` sampled across messages.
#[test]
fn app_stream_pattern_one_snmp_child_with_rollups() {
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    let messages = [snmp_get_request_v1(), snmp_v2_trap()];
    for (i, msg) in messages.iter().enumerate() {
        let frame = snmp_frame([10, 0, 0, 5], [10, 0, 0, 1], 45000, msg);
        agg.ingest(&engine.dissect(&frame, meta(frame.len(), i as u64), ParseOpts::default()));
    }

    let udp_stream = agg.at_layer("udp")[0];
    let snmp_streams = agg.at_layer("snmp");
    assert_eq!(snmp_streams.len(), 1, "one app-stream per transport stream");
    assert_eq!(snmp_streams[0].parent, Some(udp_stream.id));

    match snmp_streams[0].rollups.get("pdu_type") {
        Some(Rollup::Accumulate { values, count, .. }) => {
            assert_eq!(*count, 2);
            assert_eq!(values.as_slice(), [Value::U64(0), Value::U64(7)]);
        }
        other => panic!("wrong rollup: {other:?}"),
    }
    match snmp_streams[0].rollups.get("community") {
        Some(Rollup::Sample { first, last }) => {
            assert_eq!(first, &Some(Value::from("public")));
            assert_eq!(last, &Some(Value::from("public")));
        }
        other => panic!("wrong rollup: {other:?}"),
    }
}

proptest! {
    /// The dissector must decline or succeed on arbitrary bytes behind a
    /// claimed port — never panic (parser-bomb discipline, same standard
    /// as `decode_name_never_panics_or_hangs`).
    #[test]
    fn snmp_parse_never_panics(payload in proptest::collection::vec(any::<u8>(), 0..300)) {
        let engine = Arc::new(default_engine());
        let frame = snmp_frame([10, 0, 0, 5], [10, 0, 0, 1], 45000, &payload);
        let _ = engine.dissect(&frame, meta(frame.len(), 0), ParseOpts::default());
    }
}

fn radius_frame(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, msg: &[u8]) -> Vec<u8> {
    let mut f = eth();
    f.extend_from_slice(&ipv4_udp(src, dst, sport, dport, msg));
    f
}

fn radius_attr(attr_type: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![attr_type, (value.len() + 2) as u8];
    out.extend_from_slice(value);
    out
}

/// Access-Request (RFC 2865 §4.1): identifier 1, `User-Name` "bob" —
/// same shape as `radius.rs`'s and `conformance.rs`'s fixtures.
fn radius_access_request() -> Vec<u8> {
    let attrs = radius_attr(1, b"bob");
    let mut out = vec![1, 1];
    out.extend_from_slice(&((20 + attrs.len()) as u16).to_be_bytes());
    out.extend_from_slice(&[0xAA; 16]);
    out.extend_from_slice(&attrs);
    out
}

/// Access-Accept answering the request above, carrying `NAS-IP-Address`.
fn radius_access_accept() -> Vec<u8> {
    let attrs = radius_attr(4, &[10, 0, 0, 1]);
    let mut out = vec![2, 1];
    out.extend_from_slice(&((20 + attrs.len()) as u16).to_be_bytes());
    out.extend_from_slice(&[0xBB; 16]);
    out.extend_from_slice(&attrs);
    out
}

#[test]
fn radius_access_request_parses_exactly() {
    let engine = Arc::new(default_engine());
    let msg = radius_access_request();
    let frame = radius_frame([10, 0, 0, 5], [10, 0, 0, 1], 45000, 1812, &msg);
    let packet = engine.dissect(&frame, meta(frame.len(), 0), ParseOpts::default());

    let protocols: Vec<_> = packet.layers.iter().map(|l| l.protocol).collect();
    assert_eq!(protocols, ["ethernet", "ipv4", "udp", "radius"]);
    assert_eq!(packet.stop, StopReason::Complete);

    let layer = &packet.layers[3];
    assert_eq!(layer.fields.get("code"), Some(&Value::U64(1)));
    assert_eq!(layer.fields.get("identifier"), Some(&Value::U64(1)));
    assert_eq!(layer.fields.get("user_name"), Some(&Value::from("bob")));
}

/// Also reachable via the accounting port (1812 is auth, 1813 is
/// accounting, RFC 2866 §1's current IANA assignment).
#[test]
fn radius_reaches_dissector_on_accounting_port_1813() {
    let engine = Arc::new(default_engine());
    let attrs = radius_attr(40, &1u32.to_be_bytes());
    let mut msg = vec![4, 7];
    msg.extend_from_slice(&((20 + attrs.len()) as u16).to_be_bytes());
    msg.extend_from_slice(&[0xCC; 16]);
    msg.extend_from_slice(&attrs);

    let frame = radius_frame([10, 0, 0, 5], [10, 0, 0, 1], 45000, 1813, &msg);
    let packet = engine.dissect(&frame, meta(frame.len(), 0), ParseOpts::default());
    let protocols: Vec<_> = packet.layers.iter().map(|l| l.protocol).collect();
    assert_eq!(protocols, ["ethernet", "ipv4", "udp", "radius"]);
    let layer = &packet.layers[3];
    assert_eq!(layer.fields.get("code"), Some(&Value::U64(4)));
    assert_eq!(layer.fields.get("acct_status_type"), Some(&Value::U64(1)));
}

/// Malformed RADIUS on the claimed port declines cleanly (03.4 row 3): a
/// Length field below the RFC 2865 §3 minimum, one claiming more bytes
/// than the message holds, and an attribute whose Length is `< 2`.
#[test]
fn radius_malformed_input_declines_safely() {
    let engine = Arc::new(default_engine());
    let mut auth_only = vec![1, 1, 0, 19];
    auth_only.extend_from_slice(&[0xAA; 15]); // Length 19 < min 20, one byte short too
    let mut length_below_min = vec![1, 1, 0, 19];
    length_below_min.extend_from_slice(&[0xAA; 16]);
    let mut length_exceeds_buffer = vec![1, 1, 0, 100];
    length_exceeds_buffer.extend_from_slice(&[0xAA; 16]);
    let mut bad_attr_len = vec![1, 1, 0, 22];
    bad_attr_len.extend_from_slice(&[0xAA; 16]);
    bad_attr_len.extend_from_slice(&[1, 1]); // attr length 1, invalid (< 2)

    let bad_inputs: [&[u8]; 4] = [
        &auth_only,
        &length_below_min,
        &length_exceeds_buffer,
        &bad_attr_len,
    ];
    for msg in bad_inputs {
        let frame = radius_frame([10, 0, 0, 5], [10, 0, 0, 1], 45000, 1812, msg);
        let packet = engine.dissect(&frame, meta(frame.len(), 0), ParseOpts::default());
        let protocols: Vec<_> = packet.layers.iter().map(|l| l.protocol).collect();
        assert_eq!(protocols, ["ethernet", "ipv4", "udp"]);
        assert_eq!(packet.stop, StopReason::PluginError);
    }
}

/// App-stream pattern (06.6): one `radius` child per UDP stream, with
/// `code` accumulated and `user_name` sampled across messages.
#[test]
fn app_stream_pattern_one_radius_child_with_rollups() {
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    let messages = [radius_access_request(), radius_access_accept()];
    for (i, msg) in messages.iter().enumerate() {
        let frame = radius_frame([10, 0, 0, 5], [10, 0, 0, 1], 45000, 1812, msg);
        agg.ingest(&engine.dissect(&frame, meta(frame.len(), i as u64), ParseOpts::default()));
    }

    let udp_stream = agg.at_layer("udp")[0];
    let radius_streams = agg.at_layer("radius");
    assert_eq!(
        radius_streams.len(),
        1,
        "one app-stream per transport stream"
    );
    assert_eq!(radius_streams[0].parent, Some(udp_stream.id));

    match radius_streams[0].rollups.get("code") {
        Some(Rollup::Accumulate { values, count, .. }) => {
            assert_eq!(*count, 2);
            assert_eq!(values.as_slice(), [Value::U64(1), Value::U64(2)]);
        }
        other => panic!("wrong rollup: {other:?}"),
    }
    match radius_streams[0].rollups.get("user_name") {
        Some(Rollup::Sample { first, last }) => {
            // access_accept carries no user_name AVP; an absent field is a
            // no-op (05.4), so `last` still reflects the first observation.
            assert_eq!(first, &Some(Value::from("bob")));
            assert_eq!(last, &Some(Value::from("bob")));
        }
        other => panic!("wrong rollup: {other:?}"),
    }
}

proptest! {
    /// The dissector must decline or succeed on arbitrary bytes behind a
    /// claimed port — never panic (parser-bomb discipline, same standard
    /// as `decode_name_never_panics_or_hangs`).
    #[test]
    fn radius_parse_never_panics(payload in proptest::collection::vec(any::<u8>(), 0..300)) {
        let engine = Arc::new(default_engine());
        let frame = radius_frame([10, 0, 0, 5], [10, 0, 0, 1], 45000, 1812, &payload);
        let _ = engine.dissect(&frame, meta(frame.len(), 0), ParseOpts::default());
    }
}

fn netflow9_frame(src: [u8; 4], dst: [u8; 4], sport: u16, msg: &[u8]) -> Vec<u8> {
    let mut f = eth();
    f.extend_from_slice(&ipv4_udp(src, dst, sport, 2055, msg));
    f
}

/// A NetFlow v9 Export Packet header (RFC 3954 §5.1) plus zero or more
/// FlowSet bytes appended by the caller.
fn netflow9_header(count: u16, sequence: u32, source_id: u32) -> Vec<u8> {
    let mut m = vec![0, 9];
    m.extend_from_slice(&count.to_be_bytes());
    m.extend_from_slice(&1_000u32.to_be_bytes()); // sys_uptime
    m.extend_from_slice(&1_700_000_000u32.to_be_bytes()); // unix_secs
    m.extend_from_slice(&sequence.to_be_bytes());
    m.extend_from_slice(&source_id.to_be_bytes());
    m
}

/// A Template FlowSet (id=0) with one record: `template_id`, two fields
/// (IN_BYTES/4, IN_PKTS/4).
fn template_flowset(template_id: u16) -> Vec<u8> {
    let mut record = template_id.to_be_bytes().to_vec();
    record.extend_from_slice(&2u16.to_be_bytes()); // field_count
    record.extend_from_slice(&8u16.to_be_bytes());
    record.extend_from_slice(&4u16.to_be_bytes());
    record.extend_from_slice(&4u16.to_be_bytes());
    record.extend_from_slice(&4u16.to_be_bytes());
    let mut fs = 0u16.to_be_bytes().to_vec();
    fs.extend_from_slice(&((4 + record.len()) as u16).to_be_bytes());
    fs.extend_from_slice(&record);
    fs
}

/// An opaque Data FlowSet using `template_id`, carrying `body` bytes.
fn data_flowset(template_id: u16, body: &[u8]) -> Vec<u8> {
    let mut fs = template_id.to_be_bytes().to_vec();
    fs.extend_from_slice(&((4 + body.len()) as u16).to_be_bytes());
    fs.extend_from_slice(body);
    fs
}

/// 11.11's stateless-boundary proof: a Data FlowSet decoded against
/// `template_id` 256 stays opaque raw bytes even though its Template
/// FlowSet appears immediately before it in the *same* packet — the
/// dissector never opens a Data FlowSet's body regardless of whether a
/// template for it happens to be locally visible, since the general case
/// (template on an earlier packet, or never) can't be told apart from
/// this one without cross-packet state (netflow9.rs's module doc).
#[test]
fn netflow9_data_flowset_stays_opaque_even_immediately_after_its_template() {
    let engine = Arc::new(default_engine());
    let mut msg = netflow9_header(2, 42, 7);
    msg.extend_from_slice(&template_flowset(256));
    let data_body = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    msg.extend_from_slice(&data_flowset(256, &data_body));

    let frame = netflow9_frame([10, 0, 0, 1], [10, 0, 0, 53], 51234, &msg);
    let packet = engine.dissect(&frame, meta(frame.len(), 0), ParseOpts::default());
    let protocols: Vec<_> = packet.layers.iter().map(|l| l.protocol).collect();
    assert_eq!(protocols, ["ethernet", "ipv4", "udp", "netflow9"]);

    let layer = &packet.layers[3];
    assert_eq!(layer.fields.get("version"), Some(&Value::U64(9)));
    let Some(Value::List(flowsets)) = layer.fields.get("flowsets") else {
        panic!("missing flowsets field");
    };
    assert_eq!(flowsets.len(), 2, "template FlowSet + data FlowSet");

    let Value::List(template_entry) = &flowsets[0] else {
        panic!("wrong shape");
    };
    assert_eq!(template_entry[0], Value::U64(0), "template FlowSet id");
    assert!(
        matches!(&template_entry[2], Value::List(records) if records.len() == 1),
        "template field-definitions decode as a nested List"
    );

    let Value::List(data_entry) = &flowsets[1] else {
        panic!("wrong shape");
    };
    assert_eq!(
        data_entry[0],
        Value::U64(256),
        "data FlowSet id == template_id"
    );
    assert_eq!(
        data_entry[2],
        Value::from(&data_body[..]),
        "data FlowSet stays opaque raw bytes, template seen or not"
    );
}

#[test]
fn netflow9_stream_accumulates_source_id_and_rejects_bad_version() {
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    for (i, source_id) in [7u32, 7, 11].iter().enumerate() {
        let msg = netflow9_header(0, i as u32, *source_id);
        let frame = netflow9_frame([10, 0, 0, 1], [10, 0, 0, 53], 51234, &msg);
        agg.ingest(&engine.dissect(&frame, meta(frame.len(), i as u64), ParseOpts::default()));
    }

    let udp_stream = agg.at_layer("udp")[0];
    let netflow_streams = agg.at_layer("netflow9");
    assert_eq!(
        netflow_streams.len(),
        1,
        "one app-stream per transport stream"
    );
    assert_eq!(netflow_streams[0].parent, Some(udp_stream.id));
    match netflow_streams[0].rollups.get("source_id") {
        Some(Rollup::Accumulate { values, count, .. }) => {
            assert_eq!(*count, 3);
            assert_eq!(values.as_slice(), [Value::U64(7), Value::U64(11)]);
        }
        other => panic!("wrong rollup: {other:?}"),
    }

    // A version other than 9 (RFC 3954 §5.1) is the one cheap sanity
    // check available without templates — it must decline, not guess.
    let mut bad_version = netflow9_header(0, 99, 1);
    bad_version[1] = 10;
    let frame = netflow9_frame([10, 0, 0, 1], [10, 0, 0, 53], 51234, &bad_version);
    let packet = engine.dissect(&frame, meta(frame.len(), 3), ParseOpts::default());
    let protocols: Vec<_> = packet.layers.iter().map(|l| l.protocol).collect();
    assert_eq!(protocols, ["ethernet", "ipv4", "udp"]);
    assert_eq!(packet.stop, StopReason::PluginError);
}

proptest! {
    #[test]
    fn netflow9_parse_never_panics(payload in proptest::collection::vec(any::<u8>(), 0..300)) {
        let engine = Arc::new(default_engine());
        let frame = netflow9_frame([10, 0, 0, 1], [10, 0, 0, 53], 51234, &payload);
        let _ = engine.dissect(&frame, meta(frame.len(), 0), ParseOpts::default());
    }
}

fn ipfix_frame(src: [u8; 4], dst: [u8; 4], sport: u16, msg: &[u8]) -> Vec<u8> {
    let mut f = eth();
    f.extend_from_slice(&ipv4_udp(src, dst, sport, 4739, msg));
    f
}

/// An IPFIX Message header (RFC 7011 §3.1); `length` is the caller's
/// responsibility (total header + Sets), unlike `netflow9_header`'s
/// FlowSet-agnostic `count`.
fn ipfix_header(length: u16, sequence: u32, domain_id: u32) -> Vec<u8> {
    let mut m = vec![0, 10];
    m.extend_from_slice(&length.to_be_bytes());
    m.extend_from_slice(&1_700_000_000u32.to_be_bytes()); // export_time
    m.extend_from_slice(&sequence.to_be_bytes());
    m.extend_from_slice(&domain_id.to_be_bytes());
    m
}

/// A Template Set (id=2) with one record: `template_id`, one field
/// (IE 8/IN_BYTES, length 4, no Enterprise bit).
fn ipfix_template_set(template_id: u16) -> Vec<u8> {
    let mut record = template_id.to_be_bytes().to_vec();
    record.extend_from_slice(&1u16.to_be_bytes()); // field_count
    record.extend_from_slice(&8u16.to_be_bytes());
    record.extend_from_slice(&4u16.to_be_bytes());
    let mut set = 2u16.to_be_bytes().to_vec();
    set.extend_from_slice(&((4 + record.len()) as u16).to_be_bytes());
    set.extend_from_slice(&record);
    set
}

/// An opaque Data Set using `template_id`, carrying `body` bytes.
fn ipfix_data_set(template_id: u16, body: &[u8]) -> Vec<u8> {
    let mut set = template_id.to_be_bytes().to_vec();
    set.extend_from_slice(&((4 + body.len()) as u16).to_be_bytes());
    set.extend_from_slice(body);
    set
}

/// 11.11's stateless-boundary proof for IPFIX, the same shape as
/// `netflow9`'s: a Data Set decoded against `template_id` 256 stays
/// opaque raw bytes even though its Template Set appears immediately
/// before it in the *same* Message (ipfix.rs's module doc).
#[test]
fn ipfix_data_set_stays_opaque_even_immediately_after_its_template() {
    let engine = Arc::new(default_engine());
    let template_set = ipfix_template_set(256);
    let data_body = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    let data_set = ipfix_data_set(256, &data_body);
    let total_len = 16 + template_set.len() + data_set.len();

    let mut msg = ipfix_header(total_len as u16, 42, 7);
    msg.extend_from_slice(&template_set);
    msg.extend_from_slice(&data_set);

    let frame = ipfix_frame([10, 0, 0, 1], [10, 0, 0, 53], 51234, &msg);
    let packet = engine.dissect(&frame, meta(frame.len(), 0), ParseOpts::default());
    let protocols: Vec<_> = packet.layers.iter().map(|l| l.protocol).collect();
    assert_eq!(protocols, ["ethernet", "ipv4", "udp", "ipfix"]);

    let layer = &packet.layers[3];
    assert_eq!(layer.fields.get("version"), Some(&Value::U64(10)));
    assert_eq!(
        layer.fields.get("length"),
        Some(&Value::U64(total_len as u64))
    );
    let Some(Value::List(sets)) = layer.fields.get("sets") else {
        panic!("missing sets field");
    };
    assert_eq!(sets.len(), 2, "template Set + data Set");

    let Value::List(template_entry) = &sets[0] else {
        panic!("wrong shape");
    };
    assert_eq!(template_entry[0], Value::U64(2), "template Set id");
    assert!(
        matches!(&template_entry[2], Value::List(records) if records.len() == 1),
        "template field-definitions decode as a nested List"
    );

    let Value::List(data_entry) = &sets[1] else {
        panic!("wrong shape");
    };
    assert_eq!(data_entry[0], Value::U64(256), "data Set id == template_id");
    assert_eq!(
        data_entry[2],
        Value::from(&data_body[..]),
        "data Set stays opaque raw bytes, template seen or not"
    );
}

/// Unlike `netflow9` (no total-length field, so its FlowSet walk is
/// untracked trailing payload), IPFIX's own `length` field lets the
/// dissector bound the Message exactly — a second Message coalesced into
/// the same datagram must stay untouched.
#[test]
fn ipfix_coalesced_second_message_in_one_datagram_stays_untouched() {
    let engine = Arc::new(default_engine());
    let mut msg = ipfix_header(16, 1, 1); // first message: header only
    msg.extend_from_slice(&ipfix_header(16, 2, 2)); // second message, same datagram

    let frame = ipfix_frame([10, 0, 0, 1], [10, 0, 0, 53], 51234, &msg);
    let packet = engine.dissect(&frame, meta(frame.len(), 0), ParseOpts::default());
    let protocols: Vec<_> = packet.layers.iter().map(|l| l.protocol).collect();
    assert_eq!(protocols, ["ethernet", "ipv4", "udp", "ipfix"]);
    let layer = &packet.layers[3];
    assert_eq!(
        layer.fields.get("sequence"),
        Some(&Value::U64(1)),
        "only the first message parsed"
    );
}

#[test]
fn ipfix_stream_accumulates_domain_id_and_rejects_bad_version() {
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    for (i, domain_id) in [7u32, 7, 11].iter().enumerate() {
        let msg = ipfix_header(16, i as u32, *domain_id);
        let frame = ipfix_frame([10, 0, 0, 1], [10, 0, 0, 53], 51234, &msg);
        agg.ingest(&engine.dissect(&frame, meta(frame.len(), i as u64), ParseOpts::default()));
    }

    let udp_stream = agg.at_layer("udp")[0];
    let ipfix_streams = agg.at_layer("ipfix");
    assert_eq!(
        ipfix_streams.len(),
        1,
        "one app-stream per transport stream"
    );
    assert_eq!(ipfix_streams[0].parent, Some(udp_stream.id));
    match ipfix_streams[0].rollups.get("domain_id") {
        Some(Rollup::Accumulate { values, count, .. }) => {
            assert_eq!(*count, 3);
            assert_eq!(values.as_slice(), [Value::U64(7), Value::U64(11)]);
        }
        other => panic!("wrong rollup: {other:?}"),
    }

    // A version other than 10 (RFC 7011 §3.1) is the one cheap sanity
    // check available without templates — it must decline, not guess.
    let mut bad_version = ipfix_header(16, 99, 1);
    bad_version[1] = 9;
    let frame = ipfix_frame([10, 0, 0, 1], [10, 0, 0, 53], 51234, &bad_version);
    let packet = engine.dissect(&frame, meta(frame.len(), 3), ParseOpts::default());
    let protocols: Vec<_> = packet.layers.iter().map(|l| l.protocol).collect();
    assert_eq!(protocols, ["ethernet", "ipv4", "udp"]);
    assert_eq!(packet.stop, StopReason::PluginError);
}

proptest! {
    #[test]
    fn ipfix_parse_never_panics(payload in proptest::collection::vec(any::<u8>(), 0..300)) {
        let engine = Arc::new(default_engine());
        let frame = ipfix_frame([10, 0, 0, 1], [10, 0, 0, 53], 51234, &payload);
        let _ = engine.dissect(&frame, meta(frame.len(), 0), ParseOpts::default());
    }
}

/// WireGuard Handshake Initiation (wireguard.com/protocol/): message_type
/// 1, 3 reserved bytes, then `sender_index` and the fixed-size Noise
/// payload this test never needs to fabricate meaningfully (11.5 parses
/// only sender_index, everything else is opaque cryptographic material).
fn wg_handshake_initiation(sender_index: u32) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(&1u32.to_le_bytes());
    m.extend_from_slice(&sender_index.to_le_bytes());
    m.extend(std::iter::repeat_n(0xAB, 148 - 8));
    m
}

/// WireGuard Handshake Response: message_type 2, `sender_index` and
/// `receiver_index`, then the fixed-size remainder.
fn wg_handshake_response(sender_index: u32, receiver_index: u32) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(&2u32.to_le_bytes());
    m.extend_from_slice(&sender_index.to_le_bytes());
    m.extend_from_slice(&receiver_index.to_le_bytes());
    m.extend(std::iter::repeat_n(0xCD, 92 - 12));
    m
}

/// WireGuard Transport Data: message_type 4, `receiver_index`, a 64-bit
/// counter, then `encrypted_len` bytes of AEAD ciphertext this plugin must
/// never look inside (D12 — the ESP precedent, 11.5).
fn wg_transport_data(receiver_index: u32, counter: u64, encrypted_len: usize) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(&4u32.to_le_bytes());
    m.extend_from_slice(&receiver_index.to_le_bytes());
    m.extend_from_slice(&counter.to_le_bytes());
    m.extend(std::iter::repeat_n(0x11, encrypted_len));
    m
}

#[test]
fn wireguard_app_stream_accumulates_msg_type_across_handshake() {
    // Mirrors mdns's app-stream pattern (11.12): no endpoint identity of
    // its own (sender/receiver indices are per-session, RFC-less
    // whitepaper §5's own rationale), so one `wireguard` child stream
    // forms per outer UDP stream, with the handshake lifecycle mix
    // visible on the `msg_type` rollup.
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    let msgs = [
        wg_handshake_initiation(0x1111_1111),
        wg_handshake_response(0x2222_2222, 0x1111_1111),
        wg_transport_data(0x1111_1111, 0, 16),
    ];
    for (i, msg) in msgs.iter().enumerate() {
        let mut frame = eth();
        frame.extend_from_slice(&ipv4_udp([10, 0, 0, 5], [10, 0, 0, 6], 51820, 51820, msg));
        agg.ingest(&engine.dissect(&frame, meta(frame.len(), i as u64), ParseOpts::default()));
    }

    let wg_streams = agg.at_layer("wireguard");
    assert_eq!(wg_streams.len(), 1, "one app-stream per transport stream");

    match wg_streams[0].rollups.get("msg_type") {
        Some(Rollup::Accumulate { values, count, .. }) => {
            assert_eq!(*count, 3);
            assert_eq!(
                values.as_slice(),
                [
                    Value::from("handshake_initiation"),
                    Value::from("handshake_response"),
                    Value::from("transport_data"),
                ]
            );
        }
        other => panic!("wrong rollup: {other:?}"),
    }
}

#[test]
fn wireguard_transport_data_stops_terminal_before_ciphertext_no_phantom_stream() {
    // D12's "no phantom streams" honesty, applied to WireGuard's session
    // traffic (11.5's real-encrypted-tunnel case, alongside ESP's):
    // ciphertext trailing the 16-byte fixed prefix is never dissected,
    // however plausible it looks.
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    let msg = wg_transport_data(0x4242_4242, 9, 64);
    let mut frame = eth();
    frame.extend_from_slice(&ipv4_udp([10, 0, 0, 5], [10, 0, 0, 6], 51820, 51820, &msg));

    let packet = engine.dissect(&frame, meta(frame.len(), 0), ParseOpts::default());
    let protocols: Vec<_> = packet.layers.iter().map(|l| l.protocol).collect();
    assert_eq!(protocols, ["ethernet", "ipv4", "udp", "wireguard"]);
    assert_eq!(packet.stop, StopReason::Terminal);

    agg.ingest(&packet);
    let wg_stream = &agg.at_layer("wireguard")[0];
    assert_eq!(wg_stream.opaque_bytes, 64, "ciphertext never dissected");
}

#[test]
fn wireguard_claim_path_and_probe_admitted_path_parse_identically() {
    // 11.5 acceptance criterion: the default-port static claim and a
    // non-default-port, probe-based fallback-pool admission must reach
    // the same plugin and produce the same parsed fields. The engine's
    // `Hint::Candidates` gate (03.4, `udp.rs`) only ever opens the
    // fallback pool via `Hint::Unknown` — mirroring how 11.13's `dnp3`
    // proves its own non-standard-port probe (a direct `probe()`/`parse()`
    // check, not a full unclaimed-UDP-port dissect) — so this proves the
    // invariant the acceptance criterion actually cares about: `parse()`
    // is a pure function of bytes and depth, so whichever path admits
    // these bytes, the extracted fields are identical.
    let bytes = wg_handshake_initiation(0x1111_1111);
    let engine = Arc::new(default_engine());

    // Path 1: default port 51820, the static `claims()` route.
    let mut claimed_frame = eth();
    claimed_frame.extend_from_slice(&ipv4_udp(
        [10, 0, 0, 5],
        [10, 0, 0, 6],
        51820,
        51820,
        &bytes,
    ));
    let packet = engine.dissect(
        &claimed_frame,
        meta(claimed_frame.len(), 0),
        ParseOpts::default(),
    );
    let claimed_layer = packet.layers.last().expect("wireguard layer");
    assert_eq!(claimed_layer.protocol, "wireguard");

    // Path 2: probe-admitted (any other port routes here in the fallback
    // pool once `Hint::Unknown` opens it, e.g. entry-point identification,
    // 04.2) — same bytes, same depth, no port involved in `parse()` at all.
    let probe_meta = meta(bytes.len(), 0);
    let full_ctx = ParseCtx::new(&[], Depth::Full, &probe_meta);
    assert!(
        Wireguard.probe(&bytes, &full_ctx).is_some(),
        "must be probe-admissible for the fallback pool to ever reach it"
    );
    let probe_admitted = Wireguard
        .parse(&bytes, &full_ctx)
        .expect("valid handshake initiation");

    assert_eq!(claimed_layer.fields, probe_admitted.fields);
    assert_eq!(claimed_layer.header_len, probe_admitted.header_len);
}
