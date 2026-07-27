//! Data-center & application messaging (11.14): AMQP 0-9-1's Method/Header/
//! Body frame sequence, Redis/RESP's command extraction, and MQTT's
//! CONNECT/PUBLISH pair, each forming its app-stream child under the TCP
//! session (06.6 pattern) — the domain's "all three" acceptance criterion,
//! proven through the real engine rather than only at the unit-test level.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use pktflow_core::{LinkType, PacketMeta, ParseOpts};
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

fn ipv4_tcp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let total = 20 + 20 + payload.len();
    let mut h = vec![
        0x45,
        0x00,
        (total >> 8) as u8,
        (total & 0xff) as u8,
        0x1C,
        0x46,
        0x40,
        0x00,
        0x40,
        6,
        0,
        0,
    ];
    h.extend_from_slice(&src);
    h.extend_from_slice(&dst);
    let ck = internet_checksum(&h);
    h[10..12].copy_from_slice(&ck.to_be_bytes());
    let mut seg = Vec::new();
    seg.extend_from_slice(&sport.to_be_bytes());
    seg.extend_from_slice(&dport.to_be_bytes());
    seg.extend_from_slice(&[0, 0, 1, 0, 0, 0, 0, 0]);
    seg.extend_from_slice(&[0x50, 0x18]);
    seg.extend_from_slice(&[0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00]);
    seg.extend_from_slice(payload);
    h.extend_from_slice(&seg);
    h
}

// --- MQTT (already implemented; verified here at the engine level) -----

fn mqtt_variable_byte_int(mut value: usize) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (value % 128) as u8;
        value /= 128;
        if value > 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
    out
}

fn mqtt_frame(message_type: u8, flags: u8, body: &[u8]) -> Vec<u8> {
    let mut b = vec![(message_type << 4) | flags];
    b.extend_from_slice(&mqtt_variable_byte_int(body.len()));
    b.extend_from_slice(body);
    b
}

fn mqtt_utf8(s: &str) -> Vec<u8> {
    let mut b = (s.len() as u16).to_be_bytes().to_vec();
    b.extend_from_slice(s.as_bytes());
    b
}

#[test]
fn mqtt_connect_then_publish_forms_one_app_stream() {
    const CONNECT: u8 = 1;
    const PUBLISH: u8 = 3;

    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    let mut connect_body = mqtt_utf8("MQTT");
    connect_body.push(4); // protocol level 3.1.1
    connect_body.push(0x02); // clean session
    connect_body.extend_from_slice(&60u16.to_be_bytes()); // keep_alive
    connect_body.extend_from_slice(&mqtt_utf8("sensor-1"));
    let connect = mqtt_frame(CONNECT, 0x00, &connect_body);

    let mut publish_body = mqtt_utf8("sensors/temp");
    publish_body.extend_from_slice(b"21.5");
    let publish = mqtt_frame(PUBLISH, 0x01, &publish_body); // QoS 0, retain

    for (i, msg) in [connect, publish].iter().enumerate() {
        let mut f = eth();
        f.extend_from_slice(&ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 50000, 1883, msg));
        agg.ingest(&engine.dissect(&f, meta(f.len(), i as u64), ParseOpts::default()));
    }

    let mqtt_streams = agg.at_layer("mqtt");
    assert_eq!(mqtt_streams.len(), 1, "one app-stream per TCP session");
    match mqtt_streams[0].rollups.get("message_type") {
        Some(Rollup::Accumulate { values, count, .. }) => {
            assert_eq!(*count, 2);
            assert!(values.contains(&pktflow_core::Value::U64(u64::from(CONNECT))));
            assert!(values.contains(&pktflow_core::Value::U64(u64::from(PUBLISH))));
        }
        other => panic!("wrong rollup: {other:?}"),
    }
}

// --- AMQP 0-9-1 ----------------------------------------------------------

fn amqp_frame(ty: u8, channel: u16, payload: &[u8]) -> Vec<u8> {
    let mut b = vec![ty];
    b.extend_from_slice(&channel.to_be_bytes());
    b.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    b.extend_from_slice(payload);
    b.push(0xCE);
    b
}

#[test]
fn amqp_method_header_body_sequence_parses_and_forms_one_app_stream() {
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    // Basic.Publish (class 60, method 40), then a content Header frame,
    // then a Body frame — the message content itself is unparsed payload.
    let mut method_payload = 60u16.to_be_bytes().to_vec();
    method_payload.extend_from_slice(&40u16.to_be_bytes());
    method_payload.extend_from_slice(b"exchange-args"); // unparsed arguments

    let frames: [(u8, &[u8]); 3] = [
        (1, &method_payload),
        (2, &[0u8; 14]), // Header frame: class-id + weight + body-size + props, unparsed
        (3, b"the actual message body, opaque payload"),
    ];

    let mut last_layer = None;
    for (i, (ty, payload)) in frames.iter().enumerate() {
        let msg = amqp_frame(*ty, 1, payload);
        let mut f = eth();
        f.extend_from_slice(&ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 50000, 5672, &msg));
        let packet = engine.dissect(&f, meta(f.len(), i as u64), ParseOpts::default());
        last_layer = packet.layers.last().cloned();
        agg.ingest(&packet);
    }
    let last_layer = last_layer.expect("amqp layer");
    assert_eq!(last_layer.protocol, "amqp");
    assert_eq!(
        last_layer.fields.get("frame_type"),
        Some(&pktflow_core::Value::from("body"))
    );

    let amqp_streams = agg.at_layer("amqp");
    assert_eq!(amqp_streams.len(), 1, "one app-stream per TCP session");
    match amqp_streams[0].rollups.get("frame_type") {
        Some(Rollup::Accumulate { values, count, .. }) => {
            assert_eq!(*count, 3);
            assert!(values
                .iter()
                .any(|v| *v == pktflow_core::Value::from("method")));
            assert!(values
                .iter()
                .any(|v| *v == pktflow_core::Value::from("header")));
            assert!(values
                .iter()
                .any(|v| *v == pktflow_core::Value::from("body")));
        }
        other => panic!("wrong rollup: {other:?}"),
    }
    match amqp_streams[0].rollups.get("class_id") {
        Some(Rollup::Accumulate { values, .. }) => {
            assert!(values.contains(&pktflow_core::Value::U64(60)));
        }
        other => panic!("wrong rollup: {other:?}"),
    }
}

// --- Redis / RESP ---------------------------------------------------------

fn bulk(s: &str) -> Vec<u8> {
    format!("${}\r\n{s}\r\n", s.len()).into_bytes()
}

fn array_command(parts: &[&str]) -> Vec<u8> {
    let mut b = format!("*{}\r\n", parts.len()).into_bytes();
    for p in parts {
        b.extend_from_slice(&bulk(p));
    }
    b
}

#[test]
fn redis_set_command_and_ok_response_form_one_app_stream() {
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    let set_cmd = array_command(&["SET", "foo", "bar"]);
    let mut req = eth();
    req.extend_from_slice(&ipv4_tcp(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        50000,
        6379,
        &set_cmd,
    ));
    let packet = engine.dissect(&req, meta(req.len(), 0), ParseOpts::default());
    let layer = packet.layers.last().expect("redis layer");
    assert_eq!(layer.protocol, "redis");
    assert_eq!(
        layer.fields.get("command"),
        Some(&pktflow_core::Value::from("SET"))
    );
    assert_eq!(
        layer.fields.get("resp_type"),
        Some(&pktflow_core::Value::from("array"))
    );
    agg.ingest(&packet);

    let ok_reply = b"+OK\r\n";
    let mut resp = eth();
    resp.extend_from_slice(&ipv4_tcp(
        [10, 0, 0, 2],
        [10, 0, 0, 1],
        6379,
        50000,
        ok_reply,
    ));
    let packet = engine.dissect(&resp, meta(resp.len(), 1), ParseOpts::default());
    let layer = packet.layers.last().expect("redis layer");
    assert_eq!(
        layer.fields.get("resp_type"),
        Some(&pktflow_core::Value::from("simple_string"))
    );
    agg.ingest(&packet);

    let redis_streams = agg.at_layer("redis");
    assert_eq!(redis_streams.len(), 1, "one app-stream per TCP session");
    match redis_streams[0].rollups.get("command") {
        Some(Rollup::Accumulate { values, .. }) => {
            assert!(values.contains(&pktflow_core::Value::from("SET")));
        }
        other => panic!("wrong rollup: {other:?}"),
    }
}

#[test]
fn redis_multi_exec_pipeline_nested_array_yields_top_level_command_no_nested_walk() {
    // MULTI queues, then a nested array reply for EXEC results — the
    // top-level shape a pipeline produces. This proves the "no attempt at
    // a nested walk" stance end-to-end, not just via a direct parse() call.
    let engine = Arc::new(default_engine());

    let multi = array_command(&["MULTI"]);
    let mut f = eth();
    f.extend_from_slice(&ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 50000, 6379, &multi));
    let packet = engine.dissect(&f, meta(f.len(), 0), ParseOpts::default());
    let layer = packet.layers.last().expect("redis layer");
    assert_eq!(
        layer.fields.get("command"),
        Some(&pktflow_core::Value::from("MULTI"))
    );

    // EXEC's reply: an array of two nested arrays (two queued commands'
    // results) — first element is itself an array, not a bulk string.
    let mut exec_reply = b"*2\r\n".to_vec();
    exec_reply.extend_from_slice(&array_command(&["OK"]));
    exec_reply.extend_from_slice(&array_command(&["OK"]));
    let mut f2 = eth();
    f2.extend_from_slice(&ipv4_tcp(
        [10, 0, 0, 2],
        [10, 0, 0, 1],
        6379,
        50000,
        &exec_reply,
    ));
    let packet = engine.dissect(&f2, meta(f2.len(), 1), ParseOpts::default());
    let layer = packet.layers.last().expect("redis layer");
    assert_eq!(
        layer.fields.get("arg_count"),
        Some(&pktflow_core::Value::U64(2))
    );
    assert_eq!(layer.fields.get("command"), None);
}
