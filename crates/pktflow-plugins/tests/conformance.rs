//! Every reference plugin runs the 09.1 conformance kit here — one
//! `ConformanceCase` per plugin. Add yours when you copy template.rs.

mod kit;

use pktflow_core::{Hint, RouteId, Value};
use pktflow_plugins::arp::Arp;
use pktflow_plugins::ethernet::Ethernet;
use pktflow_plugins::icmpv4::Icmpv4;
use pktflow_plugins::igmp::Igmp;
use pktflow_plugins::ipv4::{internet_checksum, Ipv4};
use pktflow_plugins::ipv6::Ipv6;
use pktflow_plugins::template::Template;
use pktflow_plugins::vlan::Vlan;

use kit::{run_conformance, ConformanceCase, GoodPacket};

#[test]
fn template_conforms() {
    run_conformance(&ConformanceCase {
        plugin: Box::new(Template),
        good: vec![
            // Terminal PKTT frame: src=3 dst=7 type=2 len=8.
            GoodPacket {
                bytes: vec![0x00, 0x03, 0x00, 0x07, 0x00, 0x02, 0x00, 0x08],
                expected_header_len: 8,
                expected_full_fields: vec![
                    ("src", Value::U64(3)),
                    ("dst", Value::U64(7)),
                    ("type", Value::U64(2)),
                    ("len", Value::U64(8)),
                ],
                expected_hint: Hint::Terminal,
            },
            // Self-nesting frame: type=1 wraps another PKTT (16 bytes total).
            GoodPacket {
                bytes: vec![
                    0x00, 0x0A, 0x00, 0x0B, 0x00, 0x01, 0x00, 0x10, // outer
                    0x00, 0x01, 0x00, 0x02, 0x00, 0x02, 0x00, 0x08, // inner
                ],
                expected_header_len: 8,
                expected_full_fields: vec![
                    ("src", Value::U64(10)),
                    ("dst", Value::U64(11)),
                    ("type", Value::U64(1)),
                    ("len", Value::U64(16)),
                ],
                expected_hint: Hint::ByProtocol("template"),
            },
        ],
        outer_ctx: Vec::new(),
    });
}

#[test]
fn ethernet_conforms() {
    run_conformance(&ConformanceCase {
        plugin: Box::new(Ethernet),
        good: vec![
            // Ethernet II, IPv4 inside (dst, src, type per IEEE 802.3).
            GoodPacket {
                bytes: vec![
                    0x00, 0x1B, 0x44, 0x11, 0x3A, 0xB7, // dst
                    0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E, // src
                    0x08, 0x00, // IPv4
                ],
                expected_header_len: 14,
                expected_full_fields: vec![
                    (
                        "src_mac",
                        Value::from(&[0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E][..]),
                    ),
                    (
                        "dst_mac",
                        Value::from(&[0x00, 0x1B, 0x44, 0x11, 0x3A, 0xB7][..]),
                    ),
                    ("ethertype", Value::U64(0x0800)),
                ],
                expected_hint: Hint::Route(RouteId::EtherType(0x0800)),
            },
            // 802.3 length field (46): names nothing routable.
            GoodPacket {
                bytes: vec![
                    0x00, 0x1B, 0x44, 0x11, 0x3A, 0xB7, //
                    0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E, //
                    0x00, 0x2E,
                ],
                expected_header_len: 14,
                expected_full_fields: vec![
                    (
                        "src_mac",
                        Value::from(&[0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E][..]),
                    ),
                    (
                        "dst_mac",
                        Value::from(&[0x00, 0x1B, 0x44, 0x11, 0x3A, 0xB7][..]),
                    ),
                    ("ethertype", Value::U64(0x2E)),
                ],
                expected_hint: Hint::Unknown,
            },
        ],
        outer_ctx: Vec::new(),
    });
}

/// RFC 791 header with a valid checksum; `total_len` must equal the byte
/// count so the probe's sanity check holds on header-only samples.
fn ipv4_bytes(ihl: u8, total_len: u16, protocol: u8, options: &[u8]) -> Vec<u8> {
    let mut h = vec![0x40 | ihl, 0x00];
    h.extend_from_slice(&total_len.to_be_bytes());
    h.extend_from_slice(&[0x1C, 0x46, 0x40, 0x00, 0x40, protocol, 0x00, 0x00]);
    h.extend_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2]);
    h.extend_from_slice(options);
    let ck = internet_checksum(&h);
    h[10..12].copy_from_slice(&ck.to_be_bytes());
    h
}

#[test]
fn ipv4_conforms() {
    let plain = ipv4_bytes(5, 20, 6, &[]);
    let plain_ck = u16::from_be_bytes([plain[10], plain[11]]);
    let with_options = ipv4_bytes(6, 24, 17, &[0x01, 0x01, 0x01, 0x00]);
    let options_ck = u16::from_be_bytes([with_options[10], with_options[11]]);

    run_conformance(&ConformanceCase {
        plugin: Box::new(Ipv4),
        good: vec![
            GoodPacket {
                bytes: plain,
                expected_header_len: 20,
                expected_full_fields: vec![
                    ("src_addr", Value::from(&[10, 0, 0, 1][..])),
                    ("dst_addr", Value::from(&[10, 0, 0, 2][..])),
                    ("protocol", Value::U64(6)),
                    ("ttl", Value::U64(64)),
                    ("total_len", Value::U64(20)),
                    ("flags", Value::U64(2)),
                    ("frag_offset", Value::U64(0)),
                    ("ihl", Value::U64(5)),
                    ("dscp", Value::U64(0)),
                    ("ecn", Value::U64(0)),
                    ("id", Value::U64(0x1C46)),
                    ("checksum", Value::U64(u64::from(plain_ck))),
                ],
                expected_hint: Hint::Route(RouteId::IpProtocol(6)),
            },
            GoodPacket {
                bytes: with_options,
                expected_header_len: 24,
                expected_full_fields: vec![
                    ("src_addr", Value::from(&[10, 0, 0, 1][..])),
                    ("dst_addr", Value::from(&[10, 0, 0, 2][..])),
                    ("protocol", Value::U64(17)),
                    ("ttl", Value::U64(64)),
                    ("total_len", Value::U64(24)),
                    ("flags", Value::U64(2)),
                    ("frag_offset", Value::U64(0)),
                    ("ihl", Value::U64(6)),
                    ("dscp", Value::U64(0)),
                    ("ecn", Value::U64(0)),
                    ("id", Value::U64(0x1C46)),
                    ("checksum", Value::U64(u64::from(options_ck))),
                    ("options", Value::from(&[0x01, 0x01, 0x01, 0x00][..])),
                ],
                expected_hint: Hint::Route(RouteId::IpProtocol(17)),
            },
        ],
        outer_ctx: Vec::new(),
    });
}

#[test]
fn ipv6_conforms() {
    // RFC 8200 fixed header, experimental payload protocol 253.
    let mut plain = vec![0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 253, 0x40];
    plain.extend_from_slice(&[0x20; 16]);
    plain.extend_from_slice(&[0xFE; 16]);

    // Same, but next = hop-by-hop carrying an 8-byte PadN ext to protocol 6.
    let mut with_ext = vec![0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0, 0x40];
    with_ext.extend_from_slice(&[0x20; 16]);
    with_ext.extend_from_slice(&[0xFE; 16]);
    with_ext.extend_from_slice(&[6, 0, 1, 4, 0, 0, 0, 0]);

    let base_fields = |next: u64, payload_len: u64| {
        vec![
            ("src_addr", Value::from(&[0x20; 16][..])),
            ("dst_addr", Value::from(&[0xFE; 16][..])),
            ("next_header", Value::U64(next)),
            ("hop_limit", Value::U64(0x40)),
            ("payload_len", Value::U64(payload_len)),
            ("traffic_class", Value::U64(0)),
            ("flow_label", Value::U64(0)),
        ]
    };

    run_conformance(&ConformanceCase {
        plugin: Box::new(Ipv6),
        good: vec![
            GoodPacket {
                bytes: plain,
                expected_header_len: 40,
                expected_full_fields: base_fields(253, 0),
                expected_hint: Hint::Route(RouteId::IpProtocol(253)),
            },
            GoodPacket {
                bytes: with_ext,
                expected_header_len: 48,
                expected_full_fields: base_fields(6, 8),
                expected_hint: Hint::Route(RouteId::IpProtocol(6)),
            },
        ],
        outer_ctx: Vec::new(),
    });
}

#[test]
fn arp_conforms() {
    // RFC 826 who-has request for 10.0.0.2 from 00:1a:2b:3c:4d:5e.
    let bytes = vec![
        0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, // eth/ipv4, request
        0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 10, 0, 0, 1, // sender
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 10, 0, 0, 2, // target
    ];
    run_conformance(&ConformanceCase {
        plugin: Box::new(Arp),
        good: vec![GoodPacket {
            bytes,
            expected_header_len: 28,
            expected_full_fields: vec![
                ("opcode", Value::U64(1)),
                (
                    "sender_mac",
                    Value::from(&[0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E][..]),
                ),
                ("sender_ip", Value::from(&[10, 0, 0, 1][..])),
                ("target_mac", Value::from(&[0x00; 6][..])),
                ("target_ip", Value::from(&[10, 0, 0, 2][..])),
            ],
            expected_hint: Hint::Terminal,
        }],
        outer_ctx: Vec::new(),
    });
}

#[test]
fn icmpv4_conforms() {
    // Echo request, id 1, seq 0x37 (checksum not validated by the parser).
    let bytes = vec![0x08, 0x00, 0xF7, 0xC7, 0x00, 0x01, 0x00, 0x37];
    run_conformance(&ConformanceCase {
        plugin: Box::new(Icmpv4),
        good: vec![GoodPacket {
            bytes,
            expected_header_len: 8,
            expected_full_fields: vec![
                ("type", Value::U64(8)),
                ("code", Value::U64(0)),
                ("rest_of_header", Value::from(&[0x00, 0x01, 0x00, 0x37][..])),
            ],
            expected_hint: Hint::Terminal,
        }],
        outer_ctx: Vec::new(),
    });
}

#[test]
fn igmp_conforms() {
    // IGMPv2 general membership query (RFC 2236).
    let bytes = vec![0x11, 0x64, 0xEE, 0x9B, 0x00, 0x00, 0x00, 0x00];
    run_conformance(&ConformanceCase {
        plugin: Box::new(Igmp),
        good: vec![GoodPacket {
            bytes,
            expected_header_len: 8,
            expected_full_fields: vec![
                ("type", Value::U64(0x11)),
                ("max_resp", Value::U64(0x64)),
                ("group_addr", Value::from(&[0, 0, 0, 0][..])),
            ],
            expected_hint: Hint::Terminal,
        }],
        outer_ctx: Vec::new(),
    });
}

#[test]
fn vlan_conforms() {
    run_conformance(&ConformanceCase {
        plugin: Box::new(Vlan),
        good: vec![
            // Tag body: pcp=5 dei=0 vid=100, inner EtherType IPv4.
            GoodPacket {
                bytes: vec![0xA0, 0x64, 0x08, 0x00],
                expected_header_len: 4,
                expected_full_fields: vec![
                    ("vlan_id", Value::U64(100)),
                    ("pcp", Value::U64(5)),
                    ("dei", Value::Bool(false)),
                    ("ethertype", Value::U64(0x0800)),
                ],
                expected_hint: Hint::Route(RouteId::EtherType(0x0800)),
            },
            // QinQ S-tag body whose inner type is another 802.1Q tag.
            GoodPacket {
                bytes: vec![0x20, 0x0A, 0x81, 0x00],
                expected_header_len: 4,
                expected_full_fields: vec![
                    ("vlan_id", Value::U64(10)),
                    ("pcp", Value::U64(1)),
                    ("dei", Value::Bool(false)),
                    ("ethertype", Value::U64(0x8100)),
                ],
                expected_hint: Hint::Route(RouteId::EtherType(0x8100)),
            },
        ],
        outer_ctx: Vec::new(),
    });
}
