//! Web & RPC (11.8): the h2c cleartext-upgrade dispatch from `http` into
//! `http2`, WebSocket frame parsing (fed directly, per its documented
//! reachability limitation), and STUN/TURN's shared-format proof.

use std::sync::Arc;
use std::time::SystemTime;

use pktflow_core::{Depth, LayerPlugin, LinkType, PacketMeta, ParseCtx, ParseOpts, Value};
use pktflow_plugins::default_engine;
use pktflow_plugins::ipv4::internet_checksum;
use pktflow_plugins::stun::Stun;
use pktflow_plugins::websocket::WebSocket;

fn meta(len: usize) -> PacketMeta {
    PacketMeta {
        timestamp: SystemTime::UNIX_EPOCH,
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
    seg.extend_from_slice(&[0, 0, 1, 0, 0, 0, 0, 0]); // seq, ack
    seg.extend_from_slice(&[0x50, 0x18]); // doff 5, PSH|ACK
    seg.extend_from_slice(&[0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00]);
    seg.extend_from_slice(payload);
    h.extend_from_slice(&seg);
    h
}

fn frame(ty: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    let len = payload.len() as u32;
    b.extend_from_slice(&len.to_be_bytes()[1..]);
    b.push(ty);
    b.push(flags);
    b.extend_from_slice(&stream_id.to_be_bytes());
    b.extend_from_slice(payload);
    b
}

const H2C_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const TYPE_SETTINGS: u8 = 0x4;
const TYPE_HEADERS: u8 = 0x1;
const TYPE_DATA: u8 = 0x0;

#[test]
fn h2c_preface_dispatches_http_to_http2_and_frames_form_sibling_streams() {
    // 11.8's acceptance criterion: the connection preface is consumed
    // exactly as `http`'s `header_len`, dispatching by name to `http2` (D7:
    // only the first frame in the segment is then parsed — a real client
    // sends the preface immediately followed by a SETTINGS frame in the
    // same write, RFC 9113 §3.4).
    let mut settings = Vec::new();
    settings.extend_from_slice(&0u32.to_be_bytes()[1..]); // length 0
    settings.push(TYPE_SETTINGS);
    settings.push(0); // flags
    settings.extend_from_slice(&0u32.to_be_bytes()); // stream id 0

    let mut preface_frame = eth();
    let mut payload = H2C_PREFACE.to_vec();
    payload.extend_from_slice(&settings);
    preface_frame.extend_from_slice(&ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 50000, 80, &payload));
    let engine = Arc::new(default_engine());
    let packet = engine.dissect(
        &preface_frame,
        meta(preface_frame.len()),
        ParseOpts::default(),
    );
    let protocols: Vec<_> = packet.layers.iter().map(|l| l.protocol).collect();
    assert_eq!(protocols, ["ethernet", "ipv4", "tcp", "http", "http2"]);
    let http_layer = &packet.layers[3];
    assert_eq!(http_layer.header_len, H2C_PREFACE.len());
    let http2_layer = &packet.layers[4];
    assert_eq!(http2_layer.protocol, "http2");
    assert_eq!(
        http2_layer.fields.get("frame_type"),
        Some(&Value::from("SETTINGS"))
    );

    // A multi-stream fixture (06.5's two-VNIs shape): two HEADERS frames on
    // different stream ids, each its own packet (D7, first-frame-only).
    let mut s1 = eth();
    s1.extend_from_slice(&ipv4_tcp(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        50000,
        80,
        &frame(TYPE_HEADERS, 0, 1, b"hdrs-1"),
    ));
    let mut s3 = eth();
    s3.extend_from_slice(&ipv4_tcp(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        50000,
        80,
        &frame(TYPE_DATA, 0, 3, b"body-3"),
    ));
    let p1 = engine.dissect(&s1, meta(s1.len()), ParseOpts::default());
    let p3 = engine.dissect(&s3, meta(s3.len()), ParseOpts::default());
    // These reach `http2` only via the h2c preface dispatch, so on their
    // own (no preceding preface in this synthetic packet-at-a-time feed)
    // they parse as ordinary `http` requests/declines — the module doc's
    // documented ceiling. This confirms the http2 frame envelope itself
    // parses correctly when reached, using direct plugin calls instead.
    let _ = (p1, p3);

    let hdrs = frame(TYPE_HEADERS, 0, 1, b"hdrs-1");
    let data = frame(TYPE_DATA, 0, 3, b"body-3");
    let m = meta(hdrs.len());
    let ctx = ParseCtx::new(&[], Depth::Full, &m);
    let http2 = pktflow_plugins::http2::Http2;
    let parsed_hdrs = http2.parse(&hdrs, &ctx).expect("valid HEADERS frame");
    let parsed_data = http2.parse(&data, &ctx).expect("valid DATA frame");
    assert_eq!(parsed_hdrs.fields.get("stream_id"), Some(&Value::U64(1)));
    assert_eq!(parsed_data.fields.get("stream_id"), Some(&Value::U64(3)));
}

#[test]
fn h2c_settings_frame_envelope_parses_via_direct_dispatch() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&1u16.to_be_bytes());
    payload.extend_from_slice(&4096u32.to_be_bytes());
    let bytes = frame(TYPE_SETTINGS, 0, 0, &payload);
    let m = meta(bytes.len());
    let ctx = ParseCtx::new(&[], Depth::Full, &m);
    let parsed = pktflow_plugins::http2::Http2
        .parse(&bytes, &ctx)
        .expect("valid SETTINGS frame");
    assert_eq!(
        parsed.fields.get("frame_type"),
        Some(&Value::from("SETTINGS"))
    );
    assert_eq!(
        parsed.fields.get("settings_entries"),
        Some(&Value::List(vec![Value::from(&payload[..])]))
    );
}

// --- WebSocket (11.8, RFC 6455) ----------------------------------------
//
// Documented, material v1 reachability limitation (module doc, http2.rs's
// twin note): WS-framed packets on a TCP session `http` already claims
// route back to `http`, which declines binary frames it can't read as a
// request/status line — there is no session-scoped "this session changed
// protocol at byte N" mechanism. So these fixtures feed bytes directly to
// `parse()`, the documented way to exercise this plugin (09.1).

fn ws_frame(fin: bool, opcode: u8, mask: Option<[u8; 4]>, payload: &[u8]) -> Vec<u8> {
    let mut b = vec![(if fin { 0x80 } else { 0 }) | opcode];
    let len = payload.len();
    let mask_bit = if mask.is_some() { 0x80 } else { 0 };
    if len < 126 {
        b.push(mask_bit | len as u8);
    } else if len <= 0xFFFF {
        b.push(mask_bit | 126);
        b.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        b.push(mask_bit | 127);
        b.extend_from_slice(&(len as u64).to_be_bytes());
    }
    if let Some(key) = mask {
        b.extend_from_slice(&key);
        let masked: Vec<u8> = payload
            .iter()
            .enumerate()
            .map(|(i, &byte)| byte ^ key[i % 4])
            .collect();
        b.extend_from_slice(&masked);
    } else {
        b.extend_from_slice(payload);
    }
    b
}

#[test]
fn websocket_text_binary_close_ping_pong_masked_and_unmasked() {
    let m = meta(64);
    let ctx = ParseCtx::new(&[], Depth::Full, &m);

    // Unmasked text frame (server->client direction).
    let text = ws_frame(true, 0x1, None, b"hello");
    let parsed = WebSocket.parse(&text, &ctx).expect("valid text frame");
    assert_eq!(parsed.fields.get("opcode"), Some(&Value::U64(1)));
    assert_eq!(parsed.fields.get("mask_bit"), Some(&Value::Bool(false)));
    assert_eq!(parsed.fields.get("payload_len"), Some(&Value::U64(5)));

    // Masked binary frame (client->server direction, RFC 6455 §5.3
    // requires masking).
    let binary = ws_frame(
        true,
        0x2,
        Some([0x11, 0x22, 0x33, 0x44]),
        &[0xDE, 0xAD, 0xBE, 0xEF],
    );
    let parsed = WebSocket.parse(&binary, &ctx).expect("valid binary frame");
    assert_eq!(parsed.fields.get("opcode"), Some(&Value::U64(2)));
    assert_eq!(parsed.fields.get("mask_bit"), Some(&Value::Bool(true)));
    assert_eq!(
        parsed.fields.get("masking_key"),
        Some(&Value::from(&[0x11, 0x22, 0x33, 0x44][..]))
    );

    for (opcode, name) in [(0x8u8, "close"), (0x9, "ping"), (0xA, "pong")] {
        let f = ws_frame(true, opcode, None, &[]);
        let parsed = WebSocket
            .parse(&f, &ctx)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(
            parsed.fields.get("opcode"),
            Some(&Value::U64(u64::from(opcode)))
        );
    }
}

// --- STUN/TURN (11.8, RFC 8489/8656) -----------------------------------

const MAGIC_COOKIE: u32 = 0x2112_A442;

fn stun_header(class_method: u16, length: u16, transaction_id: &[u8; 12]) -> Vec<u8> {
    let mut b = class_method.to_be_bytes().to_vec();
    b.extend_from_slice(&length.to_be_bytes());
    b.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    b.extend_from_slice(transaction_id);
    b
}

fn stun_attr(attr_type: u16, value: &[u8]) -> Vec<u8> {
    let mut b = attr_type.to_be_bytes().to_vec();
    b.extend_from_slice(&(value.len() as u16).to_be_bytes());
    b.extend_from_slice(value);
    while !b.len().is_multiple_of(4) {
        b.push(0);
    }
    b
}

/// XOR-MAPPED-ADDRESS (RFC 8489 §14.2), IPv4 family: the port and address
/// are XORed with the magic cookie (and, for addresses, the transaction id
/// isn't needed for IPv4 — only the cookie).
fn xor_mapped_address_v4(port: u16, addr: [u8; 4]) -> Vec<u8> {
    let mut v = vec![0x00, 0x01]; // reserved(8) + family(8): IPv4
    let xport = port ^ (MAGIC_COOKIE >> 16) as u16;
    v.extend_from_slice(&xport.to_be_bytes());
    let cookie_bytes = MAGIC_COOKIE.to_be_bytes();
    for i in 0..4 {
        v.push(addr[i] ^ cookie_bytes[i]);
    }
    v
}

#[test]
fn stun_binding_request_response_recovers_xor_mapped_address() {
    let txn = [0x11u8; 12];
    let attrs = stun_attr(0x0020, &xor_mapped_address_v4(3478, [203, 0, 113, 5]));
    let mut response = stun_header(0x0101, attrs.len() as u16, &txn); // Binding Success Response
    response.extend_from_slice(&attrs);

    let m = meta(response.len());
    let ctx = ParseCtx::new(&[], Depth::Full, &m);
    let parsed = Stun.parse(&response, &ctx).expect("valid Binding Response");
    assert_eq!(
        parsed.fields.get("message_method"),
        Some(&Value::U64(0x001))
    );
    assert_eq!(
        parsed.fields.get("message_class"),
        Some(&Value::from("success_response"))
    );
    assert_eq!(
        parsed.fields.get("xor_mapped_address"),
        Some(&Value::from(&[203u8, 0, 113, 5][..]))
    );
}

#[test]
fn turn_allocate_create_permission_and_channel_bind_share_the_stun_plugin() {
    let txn = [0x22u8; 12];

    // Allocate request (method 0x003) carrying LIFETIME.
    let lifetime_attr = stun_attr(0x000D, &600u32.to_be_bytes());
    let mut allocate = stun_header(0x0003, lifetime_attr.len() as u16, &txn);
    allocate.extend_from_slice(&lifetime_attr);
    let m = meta(allocate.len());
    let ctx = ParseCtx::new(&[], Depth::Full, &m);
    let parsed = Stun.parse(&allocate, &ctx).expect("valid Allocate request");
    assert_eq!(
        parsed.fields.get("message_method"),
        Some(&Value::U64(0x003))
    );
    assert_eq!(parsed.fields.get("lifetime"), Some(&Value::U64(600)));

    // Allocate success response carrying XOR-RELAYED-ADDRESS.
    let relayed = stun_attr(0x0016, &xor_mapped_address_v4(50000, [198, 51, 100, 9]));
    let mut allocate_resp = stun_header(0x0103, relayed.len() as u16, &txn);
    allocate_resp.extend_from_slice(&relayed);
    let m = meta(allocate_resp.len());
    let ctx = ParseCtx::new(&[], Depth::Full, &m);
    let parsed = Stun
        .parse(&allocate_resp, &ctx)
        .expect("valid Allocate response");
    assert_eq!(
        parsed.fields.get("relayed_address"),
        Some(&Value::from(&[198u8, 51, 100, 9][..]))
    );

    // ChannelBind request (method 0x009) carrying CHANNEL-NUMBER.
    let mut channel_attr_value = vec![0x40, 0x00]; // channel number 0x4000
    channel_attr_value.extend_from_slice(&[0, 0]); // RFFU
    let channel_attr = stun_attr(0x000C, &channel_attr_value);
    let mut channel_bind = stun_header(0x0009, channel_attr.len() as u16, &txn);
    channel_bind.extend_from_slice(&channel_attr);
    let m = meta(channel_bind.len());
    let ctx = ParseCtx::new(&[], Depth::Full, &m);
    let parsed = Stun
        .parse(&channel_bind, &ctx)
        .expect("valid ChannelBind request");
    assert_eq!(
        parsed.fields.get("message_method"),
        Some(&Value::U64(0x009))
    );
    assert_eq!(
        parsed.fields.get("channel_number"),
        Some(&Value::U64(0x4000))
    );

    // No `turn`-specific claim exists: the same `Stun` plugin handled all
    // three, proving the "same format" design decision end-to-end.
    assert!(Stun
        .claims()
        .iter()
        .all(|r| format!("{r}") != "custom:turn:0"));
}

#[test]
fn stun_probe_honesty_magic_cookie_mismatch_scores_none() {
    let txn = [0x33u8; 12];
    let mut plausible_but_wrong_cookie = 0x0001u16.to_be_bytes().to_vec();
    plausible_but_wrong_cookie.extend_from_slice(&0u16.to_be_bytes());
    plausible_but_wrong_cookie.extend_from_slice(&0xDEAD_BEEFu32.to_be_bytes()); // wrong cookie
    plausible_but_wrong_cookie.extend_from_slice(&txn);

    let m = meta(plausible_but_wrong_cookie.len());
    let ctx = ParseCtx::new(&[], Depth::Full, &m);
    assert_eq!(Stun.probe(&plausible_but_wrong_cookie, &ctx), None);
}
