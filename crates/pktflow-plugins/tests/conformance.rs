//! Every reference plugin runs the 09.1 conformance kit here — one
//! `ConformanceCase` per plugin. Add yours when you copy template.rs.

mod kit;

use pktflow_core::{Canonicalize, FieldMap, KeyField, LayerRecord, StreamIdentity};
use pktflow_core::{Hint, RouteId, Value};
use pktflow_plugins::arp::Arp;
use pktflow_plugins::cdp::Cdp;
use pktflow_plugins::dhcp::Dhcp;
use pktflow_plugins::dns::Dns;
use pktflow_plugins::dot11::Dot11;
use pktflow_plugins::eapol::Eapol;
use pktflow_plugins::ethernet::Ethernet;
use pktflow_plugins::gre::Gre;
use pktflow_plugins::icmpv4::Icmpv4;
use pktflow_plugins::igmp::Igmp;
use pktflow_plugins::ipv4::{internet_checksum, Ipv4};
use pktflow_plugins::ipv6::Ipv6;
use pktflow_plugins::lacp::Lacp;
use pktflow_plugins::llc::Llc;
use pktflow_plugins::lldp::Lldp;
use pktflow_plugins::ntp::Ntp;
use pktflow_plugins::pvst_plus::PvstPlus;
use pktflow_plugins::radiotap::Radiotap;
use pktflow_plugins::stp::Stp;
use pktflow_plugins::tcp::Tcp;
use pktflow_plugins::template::Template;
use pktflow_plugins::udp::Udp;
use pktflow_plugins::vlan::Vlan;
use pktflow_plugins::vxlan::Vxlan;

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
fn tcp_conforms() {
    // SYN, 20-byte header, no payload: terminal until data flows.
    let syn = vec![
        0x87, 0x07, 0x01, 0xBB, // 34567 -> 443
        0x00, 0x00, 0x01, 0x00, // seq 256
        0x00, 0x00, 0x00, 0x00, // ack
        0x50, 0x02, // doff 5, SYN
        0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, // window, ck, urg
    ];
    // PSH|ACK data segment with 4 payload bytes: candidate ports.
    let mut data = syn.clone();
    data[13] = 0x18; // PSH|ACK
    data.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

    let base_fields = |flags: u64| {
        vec![
            ("src_port", Value::U64(34567)),
            ("dst_port", Value::U64(443)),
            ("flags", Value::U64(flags)),
            ("seq", Value::U64(256)),
            ("ack", Value::U64(0)),
            ("window", Value::U64(0xFFFF)),
            ("data_offset", Value::U64(5)),
            ("checksum", Value::U64(0)),
            ("urgent", Value::U64(0)),
        ]
    };

    run_conformance(&ConformanceCase {
        plugin: Box::new(Tcp),
        good: vec![
            GoodPacket {
                bytes: syn,
                expected_header_len: 20,
                expected_full_fields: base_fields(0x02),
                expected_hint: Hint::Terminal,
            },
            GoodPacket {
                bytes: data,
                expected_header_len: 20,
                expected_full_fields: base_fields(0x18),
                expected_hint: Hint::Candidates(smallvec::SmallVec::from_slice(&[
                    RouteId::TcpPort(443),
                    RouteId::TcpPort(34567),
                ])),
            },
        ],
        outer_ctx: Vec::new(),
    });
}

#[test]
fn udp_conforms() {
    // DNS-reply-shaped datagram: 53 -> 34567 with 4 payload bytes.
    let bytes = vec![
        0x00, 0x35, 0x87, 0x07, // 53 -> 34567
        0x00, 0x0C, 0x00, 0x00, // length 12, checksum 0
        0x12, 0x34, 0x56, 0x78,
    ];
    run_conformance(&ConformanceCase {
        plugin: Box::new(Udp),
        good: vec![GoodPacket {
            bytes,
            expected_header_len: 8,
            expected_full_fields: vec![
                ("src_port", Value::U64(53)),
                ("dst_port", Value::U64(34567)),
                ("length", Value::U64(12)),
                ("checksum", Value::U64(0)),
            ],
            expected_hint: Hint::Candidates(smallvec::SmallVec::from_slice(&[
                RouteId::UdpPort(34567),
                RouteId::UdpPort(53),
            ])),
        }],
        outer_ctx: Vec::new(),
    });
}

#[test]
fn gre_conforms() {
    run_conformance(&ConformanceCase {
        plugin: Box::new(Gre),
        good: vec![
            // Bare RFC 2784 header: no options, IPv4 inside.
            GoodPacket {
                bytes: vec![0x00, 0x00, 0x08, 0x00],
                expected_header_len: 4,
                expected_full_fields: vec![
                    ("key", Value::U64(0)),
                    ("flags", Value::U64(0)),
                    ("protocol", Value::U64(0x0800)),
                    ("version", Value::U64(0)),
                ],
                expected_hint: Hint::Route(RouteId::EtherType(0x0800)),
            },
            // RFC 2890 with C, K, and S words present.
            GoodPacket {
                bytes: vec![
                    0xB0, 0x00, 0x08, 0x00, // C|K|S, proto ipv4
                    0xAB, 0xCD, 0x00, 0x00, // checksum + reserved
                    0x00, 0x00, 0x00, 0x07, // key
                    0x00, 0x00, 0x00, 0x2A, // sequence
                ],
                expected_header_len: 16,
                expected_full_fields: vec![
                    ("key", Value::U64(7)),
                    ("flags", Value::U64(0xB)),
                    ("protocol", Value::U64(0x0800)),
                    ("version", Value::U64(0)),
                    ("checksum", Value::U64(0xABCD)),
                    ("sequence", Value::U64(42)),
                ],
                expected_hint: Hint::Route(RouteId::EtherType(0x0800)),
            },
        ],
        outer_ctx: Vec::new(),
    });
}

#[test]
fn vxlan_conforms() {
    run_conformance(&ConformanceCase {
        plugin: Box::new(Vxlan),
        good: vec![GoodPacket {
            // RFC 7348: I flag, VNI 5001.
            bytes: vec![0x08, 0x00, 0x00, 0x00, 0x00, 0x13, 0x89, 0x00],
            expected_header_len: 8,
            expected_full_fields: vec![("vni", Value::U64(5001)), ("flags", Value::U64(8))],
            expected_hint: Hint::ByProtocol("ethernet"),
        }],
        outer_ctx: Vec::new(),
    });
}

/// RFC 1035 standard query for example.com (A, IN), RD set.
fn dns_query_bytes() -> Vec<u8> {
    let mut m = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    m.extend_from_slice(&[7]);
    m.extend_from_slice(b"example");
    m.extend_from_slice(&[3]);
    m.extend_from_slice(b"com");
    m.extend_from_slice(&[0, 0, 1, 0, 1]);
    m
}

fn dns_query_fields() -> Vec<(&'static str, Value)> {
    vec![
        ("app", Value::from("dns")),
        ("id", Value::U64(0x1234)),
        ("is_response", Value::Bool(false)),
        ("opcode", Value::U64(0)),
        ("rcode", Value::U64(0)),
        ("qname", Value::from("example.com")),
        ("qtype", Value::U64(1)),
        ("answers", Value::List(vec![])),
        ("qdcount", Value::U64(1)),
        ("ancount", Value::U64(0)),
        ("nscount", Value::U64(0)),
        ("arcount", Value::U64(0)),
    ]
}

#[test]
fn dns_conforms_over_udp() {
    run_conformance(&ConformanceCase {
        plugin: Box::new(Dns),
        good: vec![GoodPacket {
            bytes: dns_query_bytes(),
            expected_header_len: 29,
            expected_full_fields: dns_query_fields(),
            expected_hint: Hint::Terminal,
        }],
        outer_ctx: Vec::new(),
    });
}

#[test]
fn dns_conforms_over_tcp_with_length_prefix() {
    let mut bytes = vec![0x00, 29];
    bytes.extend_from_slice(&dns_query_bytes());

    // The plugin looks at its predecessor to spot TCP framing.
    static TCP_KEY: &[KeyField] = &[KeyField {
        a: "src_port",
        b: Some("dst_port"),
    }];
    static TCP_IDENT: StreamIdentity = StreamIdentity {
        key: TCP_KEY,
        canonicalize: Canonicalize::EndpointSort,
        lifecycle: None,
        rollups: &[],
    };
    let _ = &TCP_IDENT; // context record needs only the protocol name
    let tcp_layer = LayerRecord {
        protocol: "tcp",
        offset: 34,
        header_len: 20,
        fields: FieldMap::new(),
    };

    run_conformance(&ConformanceCase {
        plugin: Box::new(Dns),
        good: vec![GoodPacket {
            bytes,
            expected_header_len: 31,
            expected_full_fields: dns_query_fields(),
            expected_hint: Hint::Terminal,
        }],
        outer_ctx: vec![tcp_layer],
    });
}

#[test]
fn dhcp_conforms() {
    // DHCPDISCOVER with requested-ip, server-id, and hostname options.
    let mut bytes = vec![1, 1, 6, 0];
    bytes.extend_from_slice(&0xDEADBEEFu32.to_be_bytes());
    bytes.extend_from_slice(&[0; 20]); // secs..giaddr
    bytes.extend_from_slice(&[0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E]);
    bytes.extend_from_slice(&[0; 10]); // chaddr padding
    bytes.extend_from_slice(&[0; 192]); // sname + file
    bytes.extend_from_slice(&0x63825363u32.to_be_bytes());
    bytes.extend_from_slice(&[53, 1, 1]); // DISCOVER
    bytes.extend_from_slice(&[50, 4, 10, 0, 0, 99]);
    bytes.extend_from_slice(&[54, 4, 10, 0, 0, 53]);
    bytes.extend_from_slice(&[12, 5]);
    bytes.extend_from_slice(b"host1");
    bytes.push(255);

    run_conformance(&ConformanceCase {
        plugin: Box::new(Dhcp),
        good: vec![GoodPacket {
            expected_header_len: bytes.len(),
            bytes,
            expected_full_fields: vec![
                ("app", Value::from("dhcp")),
                ("op", Value::U64(1)),
                ("msg_type", Value::U64(1)),
                ("xid", Value::U64(0xDEADBEEF)),
                (
                    "client_mac",
                    Value::from(&[0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E][..]),
                ),
                ("requested_ip", Value::from(&[10, 0, 0, 99][..])),
                ("server_id", Value::from(&[10, 0, 0, 53][..])),
                ("hostname", Value::from("host1")),
            ],
            expected_hint: Hint::Terminal,
        }],
        outer_ctx: Vec::new(),
    });
}

#[test]
fn ntp_conforms() {
    // v4 client poll (RFC 5905), stratum 0, GPS reference id.
    let mut bytes = vec![0x23, 0, 6, 0xEC];
    bytes.extend_from_slice(&[0; 8]);
    bytes.extend_from_slice(b"GPS\0");
    bytes.extend_from_slice(&[0; 32]);

    run_conformance(&ConformanceCase {
        plugin: Box::new(Ntp),
        good: vec![GoodPacket {
            bytes,
            expected_header_len: 48,
            expected_full_fields: vec![
                ("app", Value::from("ntp")),
                ("version", Value::U64(4)),
                ("mode", Value::U64(3)),
                ("stratum", Value::U64(0)),
                ("ref_id", Value::from(&b"GPS\0"[..])),
                ("ref_ts", Value::U64(0)),
                ("orig_ts", Value::U64(0)),
                ("recv_ts", Value::U64(0)),
                ("xmit_ts", Value::U64(0)),
            ],
            expected_hint: Hint::Terminal,
        }],
        outer_ctx: Vec::new(),
    });
}

/// One TLV: 2-byte header (7-bit type, 9-bit length) + value.
fn lldp_tlv(t: u8, value: &[u8]) -> Vec<u8> {
    let header = (u16::from(t) << 9) | (value.len() as u16);
    let mut out = header.to_be_bytes().to_vec();
    out.extend_from_slice(value);
    out
}

/// A real-shaped LLDPDU (IEEE 802.1AB-2016): MAC-address chassis ID,
/// interface-name port ID, TTL, system name/description, capabilities,
/// and a management address TLV, terminated by End-of-LLDPDU.
fn lldp_bytes() -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&lldp_tlv(1, &[4, 0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E])); // chassis: MAC
    b.extend_from_slice(&lldp_tlv(2, b"\x05Gi0/1")); // port: interface name
    b.extend_from_slice(&lldp_tlv(3, &120u16.to_be_bytes())); // ttl
    b.extend_from_slice(&lldp_tlv(5, b"switch1.example.net")); // system name
    b.extend_from_slice(&lldp_tlv(6, b"ExampleOS 1.0, Enterprise Switch")); // system description
    b.extend_from_slice(&lldp_tlv(7, &[0x00, 0x14, 0x00, 0x04])); // capabilities: bridge+router / bridge
    b.extend_from_slice(&lldp_tlv(8, &[5, 1, 192, 0, 2, 1, 2, 0, 0, 0, 5, 0])); // mgmt addr
    b.extend_from_slice(&lldp_tlv(0, &[])); // end
    b
}

#[test]
fn lldp_conforms() {
    let bytes = lldp_bytes();
    let expected_header_len = bytes.len();
    run_conformance(&ConformanceCase {
        plugin: Box::new(Lldp),
        good: vec![GoodPacket {
            bytes,
            expected_header_len,
            expected_full_fields: vec![
                ("chassis_id_subtype", Value::U64(4)),
                (
                    "chassis_id",
                    Value::from(&[0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E][..]),
                ),
                ("port_id_subtype", Value::U64(5)),
                ("port_id", Value::from(&b"Gi0/1"[..])),
                ("ttl", Value::U64(120)),
                ("system_name", Value::from("switch1.example.net")),
                (
                    "system_description",
                    Value::from("ExampleOS 1.0, Enterprise Switch"),
                ),
                ("capabilities", Value::U64(0x04)),
                (
                    "management_address",
                    Value::from(&[5u8, 1, 192, 0, 2, 1, 2, 0, 0, 0, 5, 0][..]),
                ),
            ],
            expected_hint: Hint::Terminal,
        }],
        outer_ctx: Vec::new(),
    });
}

#[test]
fn llc_conforms() {
    // STP-shaped: dsap=ssap=0x42 (802.1D Bridge Group SAP), U-format
    // control 0x03 -> routes via the llc_dsap Custom space.
    let stp_shaped = vec![0x42, 0x42, 0x03];
    // RFC 1042 IP-over-SNAP: dsap=ssap=0xAA, control 0x03, OUI 0 (reuses
    // the real EtherType space), PID 0x0800 (IPv4).
    let rfc1042_ip = vec![0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00];

    run_conformance(&ConformanceCase {
        plugin: Box::new(Llc),
        good: vec![
            GoodPacket {
                bytes: stp_shaped,
                expected_header_len: 3,
                expected_full_fields: vec![
                    ("dsap", Value::U64(0x42)),
                    ("ssap", Value::U64(0x42)),
                    ("control", Value::U64(0x03)),
                ],
                expected_hint: Hint::Route(RouteId::Custom {
                    space: "llc_dsap",
                    id: 0x42,
                }),
            },
            GoodPacket {
                bytes: rfc1042_ip,
                expected_header_len: 8,
                expected_full_fields: vec![
                    ("dsap", Value::U64(0xAA)),
                    ("ssap", Value::U64(0xAA)),
                    ("control", Value::U64(0x03)),
                    ("oui", Value::U64(0)),
                    ("pid", Value::U64(0x0800)),
                ],
                expected_hint: Hint::Route(RouteId::EtherType(0x0800)),
            },
        ],
        outer_ctx: Vec::new(),
    });
}

#[test]
fn stp_conforms() {
    // Classic Configuration BPDU (802.1D-2004 §9.3.1): version 0, this
    // bridge is not the root.
    let mut config = vec![0x00, 0x00, 0x00, 0x00];
    config.push(0x00); // flags
    config.extend_from_slice(&[0x80, 0x00, 0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E]); // root_id
    config.extend_from_slice(&4u32.to_be_bytes()); // root_path_cost
    config.extend_from_slice(&[0x80, 0x00, 0x00, 0x1B, 0x44, 0x11, 0x3A, 0xB7]); // bridge_id
    config.extend_from_slice(&0x8001u16.to_be_bytes()); // port_id
    config.extend_from_slice(&0u16.to_be_bytes()); // message_age
    config.extend_from_slice(&0x1400u16.to_be_bytes()); // max_age
    config.extend_from_slice(&0x0200u16.to_be_bytes()); // hello_time
    config.extend_from_slice(&0x0F00u16.to_be_bytes()); // forward_delay

    // TCN BPDU (§9.3.2): 4 bytes total, nothing more.
    let tcn = vec![0x00, 0x00, 0x00, 0x80];

    run_conformance(&ConformanceCase {
        plugin: Box::new(Stp),
        good: vec![
            GoodPacket {
                expected_header_len: config.len(),
                bytes: config,
                expected_full_fields: vec![
                    ("protocol_id", Value::U64(0)),
                    ("version", Value::U64(0)),
                    ("bpdu_type", Value::U64(0)),
                    ("flags", Value::U64(0)),
                    (
                        "root_id",
                        Value::from(&[0x80, 0x00, 0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E][..]),
                    ),
                    ("root_path_cost", Value::U64(4)),
                    (
                        "bridge_id",
                        Value::from(&[0x80, 0x00, 0x00, 0x1B, 0x44, 0x11, 0x3A, 0xB7][..]),
                    ),
                    ("port_id", Value::U64(0x8001)),
                    ("message_age", Value::U64(0)),
                    ("max_age", Value::U64(0x1400)),
                    ("hello_time", Value::U64(0x0200)),
                    ("forward_delay", Value::U64(0x0F00)),
                ],
                expected_hint: Hint::Terminal,
            },
            GoodPacket {
                expected_header_len: tcn.len(),
                bytes: tcn,
                expected_full_fields: vec![
                    ("protocol_id", Value::U64(0)),
                    ("version", Value::U64(0)),
                    ("bpdu_type", Value::U64(0x80)),
                ],
                expected_hint: Hint::Terminal,
            },
        ],
        outer_ctx: Vec::new(),
    });
}

#[test]
fn pvst_plus_conforms() {
    // Per-VLAN Configuration BPDU (version 0) for VLAN 100, same
    // root/bridge shape as stp's fixture, plus the Origin VLAN TLV.
    let mut bytes = vec![0x00, 0x00, 0x00, 0x00];
    bytes.push(0x00); // flags
    bytes.extend_from_slice(&[0x80, 0x00, 0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E]); // root_id
    bytes.extend_from_slice(&4u32.to_be_bytes()); // root_path_cost
    bytes.extend_from_slice(&[0x80, 0x00, 0x00, 0x1B, 0x44, 0x11, 0x3A, 0xB7]); // bridge_id
    bytes.extend_from_slice(&0x8001u16.to_be_bytes()); // port_id
    bytes.extend_from_slice(&0u16.to_be_bytes()); // message_age
    bytes.extend_from_slice(&0x1400u16.to_be_bytes()); // max_age
    bytes.extend_from_slice(&0x0200u16.to_be_bytes()); // hello_time
    bytes.extend_from_slice(&0x0F00u16.to_be_bytes()); // forward_delay
    bytes.extend_from_slice(&0x0000u16.to_be_bytes()); // TLV type
    bytes.extend_from_slice(&0x0002u16.to_be_bytes()); // TLV length
    bytes.extend_from_slice(&100u16.to_be_bytes()); // TLV value: VLAN 100

    run_conformance(&ConformanceCase {
        plugin: Box::new(PvstPlus),
        good: vec![GoodPacket {
            expected_header_len: bytes.len(),
            bytes,
            expected_full_fields: vec![
                ("protocol_id", Value::U64(0)),
                ("version", Value::U64(0)),
                ("bpdu_type", Value::U64(0)),
                ("flags", Value::U64(0)),
                (
                    "root_id",
                    Value::from(&[0x80, 0x00, 0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E][..]),
                ),
                ("root_path_cost", Value::U64(4)),
                (
                    "bridge_id",
                    Value::from(&[0x80, 0x00, 0x00, 0x1B, 0x44, 0x11, 0x3A, 0xB7][..]),
                ),
                ("port_id", Value::U64(0x8001)),
                ("message_age", Value::U64(0)),
                ("max_age", Value::U64(0x1400)),
                ("hello_time", Value::U64(0x0200)),
                ("forward_delay", Value::U64(0x0F00)),
                ("originating_vlan", Value::U64(100)),
            ],
            expected_hint: Hint::Terminal,
        }],
        outer_ctx: Vec::new(),
    });
}

#[test]
fn cdp_conforms() {
    fn tlv(t: u16, value: &[u8]) -> Vec<u8> {
        let mut out = t.to_be_bytes().to_vec();
        out.extend_from_slice(
            &u16::try_from(4 + value.len())
                .expect("tlv fits")
                .to_be_bytes(),
        );
        out.extend_from_slice(value);
        out
    }

    // Device id — the only TLV the plugin requires — is placed last so
    // every strict prefix is unambiguously truncated (CDP has no
    // explicit end-of-message marker the way LLDP/DHCP do).
    let mut bytes = vec![0x02, 0x3C, 0x00, 0x00]; // version 2, ttl 60s, checksum placeholder
    bytes.extend_from_slice(&tlv(0x0003, b"GigabitEthernet0/1")); // port id
    bytes.extend_from_slice(&tlv(0x0001, b"switch1.example.net")); // device id

    run_conformance(&ConformanceCase {
        plugin: Box::new(Cdp),
        good: vec![GoodPacket {
            expected_header_len: bytes.len(),
            bytes,
            expected_full_fields: vec![
                ("version", Value::U64(2)),
                ("ttl", Value::U64(60)),
                ("checksum", Value::U64(0)),
                ("port_id", Value::from("GigabitEthernet0/1")),
                ("device_id", Value::from("switch1.example.net")),
            ],
            expected_hint: Hint::Terminal,
        }],
        outer_ctx: Vec::new(),
    });
}

#[test]
fn lacp_conforms() {
    fn endpoint_tlv(t: u8, system: [u8; 6], key: u16, port: u16, state: u8) -> Vec<u8> {
        let mut b = vec![t, 0x14];
        b.extend_from_slice(&0x8000u16.to_be_bytes());
        b.extend_from_slice(&system);
        b.extend_from_slice(&key.to_be_bytes());
        b.extend_from_slice(&0x8000u16.to_be_bytes());
        b.extend_from_slice(&port.to_be_bytes());
        b.push(state);
        b.extend_from_slice(&[0, 0, 0]);
        b
    }

    let mut bytes = vec![0x01, 0x01]; // subtype LACP, version 1
    bytes.extend_from_slice(&endpoint_tlv(
        0x01,
        [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E],
        1,
        1,
        0x3D,
    ));
    bytes.extend_from_slice(&endpoint_tlv(
        0x02,
        [0x00, 0x1B, 0x44, 0x11, 0x3A, 0xB7],
        2,
        2,
        0x3D,
    ));
    bytes.push(0x03); // collector TLV
    bytes.push(0x10);
    bytes.extend_from_slice(&[0; 14]);
    bytes.push(0x00); // terminator TLV
    bytes.push(0x00);
    bytes.extend_from_slice(&[0; 50]); // reserved trailer

    run_conformance(&ConformanceCase {
        plugin: Box::new(Lacp),
        good: vec![GoodPacket {
            expected_header_len: bytes.len(),
            bytes,
            expected_full_fields: vec![
                (
                    "actor_system",
                    Value::from(&[0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E][..]),
                ),
                (
                    "partner_system",
                    Value::from(&[0x00, 0x1B, 0x44, 0x11, 0x3A, 0xB7][..]),
                ),
                ("actor_key", Value::U64(1)),
                ("actor_port", Value::U64(1)),
                ("actor_state", Value::U64(0x3D)),
                ("partner_key", Value::U64(2)),
                ("partner_port", Value::U64(2)),
                ("partner_state", Value::U64(0x3D)),
            ],
            expected_hint: Hint::Terminal,
        }],
        outer_ctx: Vec::new(),
    });
}

#[test]
fn eapol_conforms() {
    let mut body = Vec::new();
    body.push(0x02); // key_descriptor_type: RSN
    body.extend_from_slice(&0x008Au16.to_be_bytes()); // key_info
    body.extend_from_slice(&16u16.to_be_bytes()); // key_length
    body.extend_from_slice(&1u64.to_be_bytes()); // replay_counter
    body.extend_from_slice(&[0xAA; 32]); // nonce
    body.extend_from_slice(&[0; 16]); // key_iv
    body.extend_from_slice(&0u64.to_be_bytes()); // key_rsc
    body.extend_from_slice(&[0; 8]); // key id / reserved
    body.extend_from_slice(&[0; 16]); // key_mic
    body.extend_from_slice(&0u16.to_be_bytes()); // key_data_length

    let mut bytes = vec![0x01, 0x03]; // version 1, packet_type Key
    bytes.extend_from_slice(&u16::try_from(body.len()).expect("fits").to_be_bytes());
    bytes.extend_from_slice(&body);

    run_conformance(&ConformanceCase {
        plugin: Box::new(Eapol),
        good: vec![GoodPacket {
            expected_header_len: bytes.len(),
            bytes,
            expected_full_fields: vec![
                ("version", Value::U64(1)),
                ("packet_type", Value::U64(3)),
                ("body_length", Value::U64(95)),
                ("key_descriptor_type", Value::U64(2)),
                ("key_info", Value::U64(0x008A)),
                ("key_length", Value::U64(16)),
                ("replay_counter", Value::U64(1)),
                ("nonce", Value::from(&[0xAAu8; 32][..])),
                ("key_iv", Value::from(&[0u8; 16][..])),
                ("key_rsc", Value::U64(0)),
                ("key_mic", Value::from(&[0u8; 16][..])),
                ("key_data_length", Value::U64(0)),
            ],
            expected_hint: Hint::Terminal,
        }],
        outer_ctx: Vec::new(),
    });
}

#[test]
fn radiotap_conforms() {
    // Minimal header: no fields present, it_present = 0.
    let minimal = vec![
        0x00, 0x00, // it_version, it_pad
        0x08, 0x00, // it_len = 8 (LE)
        0x00, 0x00, 0x00, 0x00, // it_present: nothing set
    ];

    // Rate (bit 2) + Antenna Signal (bit 5) present, both 1-byte aligned
    // and contiguous right after the header.
    let present = (1u32 << 2) | (1u32 << 5);
    let mut rate_and_signal = vec![0x00, 0x00, 0x0A, 0x00];
    rate_and_signal.extend_from_slice(&present.to_le_bytes());
    rate_and_signal.push(0x02); // rate: 1 Mbps (500 kbps units)
    rate_and_signal.push((-71i8) as u8); // antenna_signal: -71 dBm

    run_conformance(&ConformanceCase {
        plugin: Box::new(Radiotap),
        good: vec![
            GoodPacket {
                expected_header_len: 8,
                bytes: minimal,
                expected_full_fields: vec![
                    ("it_version", Value::U64(0)),
                    ("it_len", Value::U64(8)),
                    ("it_present", Value::U64(0)),
                ],
                expected_hint: Hint::ByProtocol("dot11"),
            },
            GoodPacket {
                expected_header_len: 10,
                bytes: rate_and_signal,
                expected_full_fields: vec![
                    ("it_version", Value::U64(0)),
                    ("it_len", Value::U64(10)),
                    ("it_present", Value::U64(0x24)),
                    ("rate", Value::U64(2)),
                    ("antenna_signal", Value::I64(-71)),
                ],
                expected_hint: Hint::ByProtocol("dot11"),
            },
        ],
        outer_ctx: Vec::new(),
    });
}

#[test]
fn dot11_conforms() {
    const AP: [u8; 6] = [0x02, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E];
    const STA: [u8; 6] = [0x00, 0x1B, 0x44, 0x11, 0x3A, 0xB7];

    // Beacon (802.11-2020 §9.3.3.3): broadcast RA, AP as TA/BSSID, SSID
    // "ExampleNet" as the mandated first information element.
    let mut beacon = vec![0x80, 0x00]; // Management / Beacon
    beacon.extend_from_slice(&0x0000u16.to_le_bytes()); // duration
    beacon.extend_from_slice(&[0xFF; 6]); // addr1: broadcast
    beacon.extend_from_slice(&AP); // addr2: TA
    beacon.extend_from_slice(&AP); // addr3: BSSID
    beacon.extend_from_slice(&0x1230u16.to_le_bytes()); // seq_ctrl: frag 0, seq 0x123
    beacon.extend_from_slice(&[0u8; 8]); // timestamp
    beacon.extend_from_slice(&0x0064u16.to_le_bytes()); // beacon interval
    beacon.extend_from_slice(&0x0421u16.to_le_bytes()); // capability info
    beacon.push(0); // SSID element id
    beacon.push(10); // SSID length
    beacon.extend_from_slice(b"ExampleNet");

    // Unprotected QoS data, AP -> STA (from_ds), LLC/SNAP-encapsulated ARP
    // payload trailing beyond `header_len` — proves `ByProtocol("llc")`
    // hands off exactly where the fixed 802.11 header ends (11.1's `llc`
    // reused unmodified, task 11.2's central composition claim).
    let mut qos_data = vec![0x88, 0x02]; // Data / QoS Data, from_ds=1
    qos_data.extend_from_slice(&0x0000u16.to_le_bytes()); // duration
    qos_data.extend_from_slice(&STA); // addr1: DA
    qos_data.extend_from_slice(&AP); // addr2: TA/BSSID
    qos_data.extend_from_slice(&AP); // addr3: SA
    qos_data.extend_from_slice(&0x0470u16.to_le_bytes()); // seq_ctrl: seq 0x047
    qos_data.extend_from_slice(&0x0000u16.to_le_bytes()); // qos_control
    qos_data.extend_from_slice(&[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x06]); // LLC/SNAP -> ARP

    run_conformance(&ConformanceCase {
        plugin: Box::new(Dot11),
        good: vec![
            GoodPacket {
                bytes: beacon,
                expected_header_len: 48,
                expected_full_fields: vec![
                    ("frame_type", Value::U64(0)),
                    ("frame_subtype", Value::U64(0x8)),
                    ("flags", Value::U64(0)),
                    ("duration", Value::U64(0)),
                    ("addr1", Value::from(&[0xFF; 6][..])),
                    ("addr2", Value::from(&AP[..])),
                    ("addr3", Value::from(&AP[..])),
                    ("seq_num", Value::U64(0x123)),
                    ("ssid", Value::from("ExampleNet")),
                ],
                expected_hint: Hint::Terminal,
            },
            GoodPacket {
                bytes: qos_data,
                expected_header_len: 26,
                expected_full_fields: vec![
                    ("frame_type", Value::U64(2)),
                    ("frame_subtype", Value::U64(0x8)),
                    ("flags", Value::U64(0x02)),
                    ("duration", Value::U64(0)),
                    ("addr1", Value::from(&STA[..])),
                    ("addr2", Value::from(&AP[..])),
                    ("addr3", Value::from(&AP[..])),
                    ("seq_num", Value::U64(0x047)),
                    ("qos_control", Value::U64(0)),
                ],
                expected_hint: Hint::ByProtocol("llc"),
            },
        ],
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
