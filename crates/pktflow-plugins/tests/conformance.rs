//! Every reference plugin runs the 09.1 conformance kit here — one
//! `ConformanceCase` per plugin. Add yours when you copy template.rs.

mod kit;

use pktflow_core::{Canonicalize, FieldMap, KeyField, LayerRecord, StreamIdentity};
use pktflow_core::{Hint, RouteId, Value};
use pktflow_plugins::ah::Ah;
use pktflow_plugins::arp::Arp;
use pktflow_plugins::bacnet_ip::BacnetIp;
use pktflow_plugins::bfd::Bfd;
use pktflow_plugins::bgp::Bgp;
use pktflow_plugins::cdp::Cdp;
use pktflow_plugins::dhcp::Dhcp;
use pktflow_plugins::dhcpv6::Dhcpv6;
use pktflow_plugins::dnp3::Dnp3;
use pktflow_plugins::dns::Dns;
use pktflow_plugins::dot11::Dot11;
use pktflow_plugins::eapol::Eapol;
use pktflow_plugins::enip::Enip;
use pktflow_plugins::erspan::Erspan;
use pktflow_plugins::esp::Esp;
use pktflow_plugins::ethernet::Ethernet;
use pktflow_plugins::geneve::Geneve;
use pktflow_plugins::gre::Gre;
use pktflow_plugins::gtp_u::GtpU;
use pktflow_plugins::hsrp::Hsrp;
use pktflow_plugins::http::Http;
use pktflow_plugins::icmpv4::Icmpv4;
use pktflow_plugins::icmpv6::Icmpv6;
use pktflow_plugins::igmp::Igmp;
use pktflow_plugins::ipfix::Ipfix;
use pktflow_plugins::ipv4::{internet_checksum, Ipv4};
use pktflow_plugins::ipv6::Ipv6;
use pktflow_plugins::l2tpv3::L2tpv3;
use pktflow_plugins::lacp::Lacp;
use pktflow_plugins::llc::Llc;
use pktflow_plugins::lldp::Lldp;
use pktflow_plugins::llmnr::Llmnr;
use pktflow_plugins::mdns::Mdns;
use pktflow_plugins::mld::Mld;
use pktflow_plugins::modbus::Modbus;
use pktflow_plugins::mpls::Mpls;
use pktflow_plugins::mqtt::Mqtt;
use pktflow_plugins::ndp::Ndp;
use pktflow_plugins::netflow9::Netflow9;
use pktflow_plugins::ntp::Ntp;
use pktflow_plugins::ospf::Ospf;
use pktflow_plugins::ptp::Ptp;
use pktflow_plugins::pvst_plus::PvstPlus;
use pktflow_plugins::radiotap::Radiotap;
use pktflow_plugins::radius::Radius;
use pktflow_plugins::rocev2::Rocev2;
use pktflow_plugins::sctp::Sctp;
use pktflow_plugins::snmp::Snmp;
use pktflow_plugins::ssdp::Ssdp;
use pktflow_plugins::stp::Stp;
use pktflow_plugins::syslog::Syslog;
use pktflow_plugins::tcp::Tcp;
use pktflow_plugins::template::Template;
use pktflow_plugins::tls::Tls;
use pktflow_plugins::udp::Udp;
use pktflow_plugins::vlan::Vlan;
use pktflow_plugins::vrrp::Vrrp;
use pktflow_plugins::vxlan::Vxlan;
use pktflow_plugins::wireguard::Wireguard;

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
            // 802.3 length field (46): deterministically LLC-framed, so
            // it names an explicit route rather than nothing (11.1's
            // `llc` claims it).
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
                expected_hint: Hint::Route(RouteId::Custom {
                    space: "eth_llc_frame",
                    id: 0,
                }),
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
fn icmpv6_conforms() {
    // Every case shares the RFC 4443 §2.1 fixed shape: type(1) code(1)
    // checksum(2) rest_of_header(4, kept raw — layout is type-specific and
    // parsed no further here, same stance as icmpv4/06.3). Checksum bytes
    // are filler; the parser doesn't validate them (icmpv4 precedent).
    fn case(icmp_type: u8, code: u8, rest: [u8; 4], hint: Hint) -> GoodPacket {
        let mut bytes = vec![icmp_type, code, 0xBE, 0xEF];
        bytes.extend_from_slice(&rest);
        GoodPacket {
            bytes,
            expected_header_len: 8,
            expected_full_fields: vec![
                ("type", Value::U64(u64::from(icmp_type))),
                ("code", Value::U64(u64::from(code))),
                ("rest_of_header", Value::from(&rest[..])),
            ],
            expected_hint: hint,
        }
    }

    fn dispatch(icmp_type: u8) -> Hint {
        Hint::Route(RouteId::Custom {
            space: "icmpv6_type",
            id: u64::from(icmp_type),
        })
    }

    run_conformance(&ConformanceCase {
        plugin: Box::new(Icmpv6),
        good: vec![
            // RFC 4443 §3.1 Destination Unreachable, code 4 (port unreachable).
            case(1, 4, [0x00, 0x00, 0x00, 0x00], Hint::Terminal),
            // RFC 4443 §3.2 Packet Too Big, MTU = 1280 (IPv6 minimum link MTU).
            case(2, 0, [0x00, 0x00, 0x05, 0x00], Hint::Terminal),
            // RFC 4443 §3.3 Time Exceeded, code 0 (hop limit exceeded in transit).
            case(3, 0, [0x00, 0x00, 0x00, 0x00], Hint::Terminal),
            // RFC 4443 §3.4 Parameter Problem, pointer = 6 (Next Header octet).
            case(4, 0, [0x00, 0x00, 0x00, 0x06], Hint::Terminal),
            // RFC 4443 §4.1 Echo Request, id=0x1234 seq=0x0001.
            case(128, 0, [0x12, 0x34, 0x00, 0x01], Hint::Terminal),
            // RFC 4443 §4.2 Echo Reply, id=0x1234 seq=0x0001.
            case(129, 0, [0x12, 0x34, 0x00, 0x01], Hint::Terminal),
            // RFC 2710 §3 MLD Query -> mld (max resp delay 10000ms, reserved 0).
            case(130, 0, [0x27, 0x10, 0x00, 0x00], dispatch(130)),
            // RFC 2710 §3 MLDv1 Report -> mld.
            case(131, 0, [0x00, 0x00, 0x00, 0x00], dispatch(131)),
            // RFC 2710 §3 MLD Done -> mld.
            case(132, 0, [0x00, 0x00, 0x00, 0x00], dispatch(132)),
            // RFC 4861 §4.1 Router Solicitation -> ndp (reserved = 0).
            case(133, 0, [0x00, 0x00, 0x00, 0x00], dispatch(133)),
            // RFC 4861 §4.2 Router Advertisement -> ndp (cur hop limit 64,
            // M+O flags set, router lifetime 1800s).
            case(134, 0, [0x40, 0xC0, 0x07, 0x08], dispatch(134)),
            // RFC 4861 §4.3 Neighbor Solicitation -> ndp (reserved = 0).
            case(135, 0, [0x00, 0x00, 0x00, 0x00], dispatch(135)),
            // RFC 4861 §4.4 Neighbor Advertisement -> ndp (R/S/O flags set).
            case(136, 0, [0xE0, 0x00, 0x00, 0x00], dispatch(136)),
            // RFC 4861 §4.5 Redirect -> ndp (reserved = 0).
            case(137, 0, [0x00, 0x00, 0x00, 0x00], dispatch(137)),
            // RFC 3810 §5.2 MLDv2 Report -> mld (1 multicast address record).
            case(143, 0, [0x00, 0x00, 0x00, 0x01], dispatch(143)),
        ],
        outer_ctx: Vec::new(),
    });
}

/// A synthetic `icmpv6` predecessor carrying exactly the fields the real
/// plugin would have extracted at `Depth::Full` — `type` always, plus
/// `rest_of_header` for the two dispatch types (RA, NA) that pack extra
/// data into the word `icmpv6` already consumed (11.3's `ndp` module doc).
fn icmpv6_predecessor(icmp_type: u8, rest: Option<[u8; 4]>) -> LayerRecord {
    let mut fields = FieldMap::new();
    fields.insert("type", Value::U64(u64::from(icmp_type)));
    if let Some(r) = rest {
        fields.insert("rest_of_header", Value::from(&r[..]));
    }
    LayerRecord {
        protocol: "icmpv6",
        offset: 54,
        header_len: 8,
        fields,
    }
}

/// Zero-option fixtures only (11.3's `ndp` module doc): NDP has no
/// self-describing length or explicit end-of-options marker, so a capture
/// truncated exactly on an option boundary is indistinguishable from a
/// legitimately shorter message — the same limitation CDP (11.1)
/// documents for its own unterminated TLV walk. The kit's exhaustive
/// truncation sweep (rule 1) therefore only runs against messages whose
/// every byte belongs to a fixed-size read; the options walk itself
/// (link-layer address / SLAAC prefix-info extraction, multi-option
/// messages, the type=0/length=0 padding convention) is covered by
/// `ndp.rs`'s own unit tests instead.
#[test]
fn ndp_conforms() {
    // RFC 4861 §4.1 Router Solicitation: nothing left after icmpv6's
    // Reserved word, so a bare RS is the empty message.
    run_conformance(&ConformanceCase {
        plugin: Box::new(Ndp),
        good: vec![GoodPacket {
            bytes: vec![],
            expected_header_len: 0,
            expected_full_fields: vec![("msg_type", Value::U64(133))],
            expected_hint: Hint::Terminal,
        }],
        outer_ctx: vec![icmpv6_predecessor(133, None)],
    });

    // RFC 4861 §4.2 Router Advertisement: cur_hop_limit=64, M+O set,
    // router_lifetime=1800s (icmpv6_conforms' own RA fixture) — all
    // inside the already-consumed word — then reachable_time=7500ms,
    // retrans_timer=1000ms in this plugin's own bytes.
    run_conformance(&ConformanceCase {
        plugin: Box::new(Ndp),
        good: vec![GoodPacket {
            bytes: vec![0x00, 0x00, 0x1D, 0x4C, 0x00, 0x00, 0x03, 0xE8],
            expected_header_len: 8,
            expected_full_fields: vec![
                ("msg_type", Value::U64(134)),
                ("flags", Value::U64(0xC0)),
                ("router_lifetime", Value::U64(1800)),
                ("reachable_time", Value::U64(7500)),
                ("retrans_timer", Value::U64(1000)),
            ],
            expected_hint: Hint::Terminal,
        }],
        outer_ctx: vec![icmpv6_predecessor(134, Some([0x40, 0xC0, 0x07, 0x08]))],
    });

    // RFC 4861 §4.3 Neighbor Solicitation: 16-byte target, no flags.
    let ns_target: [u8; 16] = [
        0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
    ];
    run_conformance(&ConformanceCase {
        plugin: Box::new(Ndp),
        good: vec![GoodPacket {
            bytes: ns_target.to_vec(),
            expected_header_len: 16,
            expected_full_fields: vec![
                ("msg_type", Value::U64(135)),
                ("target_address", Value::from(&ns_target[..])),
            ],
            expected_hint: Hint::Terminal,
        }],
        outer_ctx: vec![icmpv6_predecessor(135, None)],
    });

    // RFC 4861 §4.4 Neighbor Advertisement: R/S/O flags set (0xE0, same
    // byte icmpv6_conforms' own NA fixture uses) plus a 16-byte target.
    let na_target: [u8; 16] = [
        0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02,
    ];
    run_conformance(&ConformanceCase {
        plugin: Box::new(Ndp),
        good: vec![GoodPacket {
            bytes: na_target.to_vec(),
            expected_header_len: 16,
            expected_full_fields: vec![
                ("msg_type", Value::U64(136)),
                ("flags", Value::U64(0xE0)),
                ("target_address", Value::from(&na_target[..])),
            ],
            expected_hint: Hint::Terminal,
        }],
        outer_ctx: vec![icmpv6_predecessor(136, Some([0xE0, 0, 0, 0]))],
    });

    // RFC 4861 §4.5 Redirect: target address then destination address —
    // only the target is in 11.3's field list for this plugin, but the
    // destination address must still be walked to keep header_len honest.
    let redirect_target = [0xAAu8; 16];
    let mut redirect_bytes = redirect_target.to_vec();
    redirect_bytes.extend_from_slice(&[0xBB; 16]);
    run_conformance(&ConformanceCase {
        plugin: Box::new(Ndp),
        good: vec![GoodPacket {
            bytes: redirect_bytes,
            expected_header_len: 32,
            expected_full_fields: vec![
                ("msg_type", Value::U64(137)),
                ("target_address", Value::from(&redirect_target[..])),
            ],
            expected_hint: Hint::Terminal,
        }],
        outer_ctx: vec![icmpv6_predecessor(137, None)],
    });
}

/// Zero-extension fixtures only, same rationale as `ndp_conforms`: the
/// MLDv2 Query extension and the MLDv2 Report's multi-record walk have no
/// self-describing outer length beyond what `N`/`M` themselves state, so
/// the kit's exhaustive truncation sweep (rule 1) only runs against
/// messages whose every byte belongs to a fixed-size read. The variable
/// walks (v2 query extension, multi-record v2 report, zero-record report)
/// are covered by `mld.rs`'s own unit tests instead.
#[test]
fn mld_conforms() {
    // RFC 2710 §3 MLD Query: max resp delay 10000ms (icmpv6_conforms'
    // own MLD Query fixture), multicast address = all-nodes (::) query.
    let group = [0xFFu8, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    run_conformance(&ConformanceCase {
        plugin: Box::new(Mld),
        good: vec![GoodPacket {
            bytes: group.to_vec(),
            expected_header_len: 16,
            expected_full_fields: vec![
                ("msg_type", Value::U64(130)),
                ("max_resp_delay", Value::U64(10000)),
                ("multicast_addr", Value::from(&group[..])),
            ],
            expected_hint: Hint::Terminal,
        }],
        outer_ctx: vec![icmpv6_predecessor(130, Some([0x27, 0x10, 0, 0]))],
    });

    // RFC 2710 §4 MLDv1 Report: max resp delay unused (0), same 16-byte
    // multicast-address body as Query.
    run_conformance(&ConformanceCase {
        plugin: Box::new(Mld),
        good: vec![GoodPacket {
            bytes: group.to_vec(),
            expected_header_len: 16,
            expected_full_fields: vec![
                ("msg_type", Value::U64(131)),
                ("max_resp_delay", Value::U64(0)),
                ("multicast_addr", Value::from(&group[..])),
            ],
            expected_hint: Hint::Terminal,
        }],
        outer_ctx: vec![icmpv6_predecessor(131, Some([0, 0, 0, 0]))],
    });

    // RFC 2710 §5 MLD Done: identical body shape to Report.
    run_conformance(&ConformanceCase {
        plugin: Box::new(Mld),
        good: vec![GoodPacket {
            bytes: group.to_vec(),
            expected_header_len: 16,
            expected_full_fields: vec![
                ("msg_type", Value::U64(132)),
                ("max_resp_delay", Value::U64(0)),
                ("multicast_addr", Value::from(&group[..])),
            ],
            expected_hint: Hint::Terminal,
        }],
        outer_ctx: vec![icmpv6_predecessor(132, Some([0, 0, 0, 0]))],
    });

    // RFC 3810 §5.2 MLDv2 Report, M=1 (icmpv6_conforms' own fixture):
    // one address record, MODE_IS_EXCLUDE(2), aux_data_len=0, N=0 sources.
    let mut record = vec![2u8, 0, 0x00, 0x00];
    record.extend_from_slice(&group);
    run_conformance(&ConformanceCase {
        plugin: Box::new(Mld),
        good: vec![GoodPacket {
            bytes: record.clone(),
            expected_header_len: record.len(),
            expected_full_fields: vec![
                ("msg_type", Value::U64(143)),
                ("multicast_addr", Value::from(&group[..])),
                ("num_sources", Value::U64(0)),
                ("source_addrs", Value::List(vec![])),
            ],
            expected_hint: Hint::Terminal,
        }],
        outer_ctx: vec![icmpv6_predecessor(143, Some([0, 0, 0, 1]))],
    });
}

/// Bare-header fixture only, same rationale as `ndp_conforms`/`mld_conforms`:
/// DHCPv6's options list (RFC 8415 §21.1) has no self-describing outer
/// length or end marker, so a capture truncated exactly on an option
/// boundary is indistinguishable from a legitimately shorter message. The
/// kit's exhaustive truncation sweep (rule 1) therefore only runs against a
/// message with zero options; the options walk itself (Client/Server
/// Identifier DUIDs, the nested IA_NA/IA_TA -> IAADDR walk, relay-message
/// rejection) is covered by `dhcpv6.rs`'s own unit tests instead.
#[test]
fn dhcpv6_conforms() {
    // RFC 8415 §18.2.2 INFORMATION-REQUEST: no address needed, so no IA
    // option — a legitimately option-free message.
    run_conformance(&ConformanceCase {
        plugin: Box::new(Dhcpv6),
        good: vec![GoodPacket {
            bytes: vec![11, 0x12, 0x34, 0x56],
            expected_header_len: 4,
            expected_full_fields: vec![
                ("app", Value::from("dhcpv6")),
                ("msg_type", Value::U64(11)),
                ("transaction_id", Value::U64(0x123456)),
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
fn vrrp_conforms() {
    // RFC 5798 VRRPv3 advertisement over IPv4: VRID 7, priority 255 (the
    // address owner), one virtual IP, Max Adver Int 100 centiseconds.
    let bytes = vec![0x31, 7, 255, 1, 0x00, 100, 0x00, 0x00, 10, 0, 0, 1];
    run_conformance(&ConformanceCase {
        plugin: Box::new(Vrrp),
        good: vec![GoodPacket {
            bytes,
            expected_header_len: 12,
            expected_full_fields: vec![
                ("vrid", Value::U64(7)),
                ("version", Value::U64(3)),
                ("type", Value::U64(1)),
                ("priority", Value::U64(255)),
                ("count_ip_addrs", Value::U64(1)),
                ("adver_int", Value::U64(100)),
                (
                    "ip_addresses",
                    Value::List(vec![Value::from(&[10u8, 0, 0, 1][..])]),
                ),
            ],
            expected_hint: Hint::Terminal,
        }],
        // The immediate predecessor VRRPv3 reads its address width from
        // (module doc) — an IPv4 layer here, so the fixture's 4-byte
        // address is interpreted correctly.
        outer_ctx: vec![LayerRecord {
            protocol: "ipv4",
            offset: 14,
            header_len: 20,
            fields: FieldMap::new(),
        }],
    });
}

#[test]
fn hsrp_conforms() {
    // RFC 2281 §5 Hello message: version 0, group 1, priority 100,
    // Active (16), hellotime 3s, holdtime 10s, "cisco" auth data padded
    // to 8 bytes, virtual IP 192.168.1.1.
    let mut bytes = vec![0, 0, 16, 3, 10, 100, 1, 0];
    bytes.extend_from_slice(b"cisco\0\0\0");
    bytes.extend_from_slice(&[192, 168, 1, 1]);
    run_conformance(&ConformanceCase {
        plugin: Box::new(Hsrp),
        good: vec![GoodPacket {
            bytes,
            expected_header_len: 20,
            expected_full_fields: vec![
                ("group", Value::U64(1)),
                ("version", Value::U64(0)),
                ("opcode", Value::U64(0)),
                ("state", Value::U64(16)),
                ("priority", Value::U64(100)),
                ("hellotime", Value::U64(3)),
                ("holdtime", Value::U64(10)),
                ("virtual_ip", Value::from(&[192u8, 168, 1, 1][..])),
                ("auth_data", Value::from(&b"cisco\0\0\0"[..])),
            ],
            expected_hint: Hint::Terminal,
        }],
        outer_ctx: Vec::new(),
    });
}

/// The OSPF common header (RFC 2328 A.3.1 / RFC 5340 A.3.1) with a zero
/// `packet_length` placeholder patched in by [`ospf_finish`].
fn ospf_header_prefix(version: u8, msg_type: u8) -> Vec<u8> {
    let mut b = vec![version, msg_type, 0, 0];
    b.extend_from_slice(&[10, 0, 0, 1]); // router_id
    b.extend_from_slice(&[0, 0, 0, 1]); // area_id
    b.extend_from_slice(&[0, 0]); // checksum
    if version == 2 {
        b.extend_from_slice(&[0, 0]); // AuType: none
        b.extend_from_slice(&[0; 8]); // Authentication
    } else {
        b.push(0); // Instance ID
        b.push(0); // reserved
    }
    b
}

/// Patches `packet_length` (bytes 2-3) to `b`'s final length.
fn ospf_finish(mut b: Vec<u8>) -> Vec<u8> {
    let len = u16::try_from(b.len()).expect("fixture fits in u16");
    b[2..4].copy_from_slice(&len.to_be_bytes());
    b
}

#[test]
fn ospf_conforms() {
    // RFC 2328 A.3.2 Hello: network mask, hello_interval 10s, options
    // 0x02, rtr_pri 1, router_dead_interval 40s, DR/BDR by interface
    // address, two neighbors.
    let mut hello_v2 = ospf_header_prefix(2, 1);
    hello_v2.extend_from_slice(&[255, 255, 255, 0]);
    hello_v2.extend_from_slice(&10u16.to_be_bytes());
    hello_v2.push(0x02);
    hello_v2.push(1);
    hello_v2.extend_from_slice(&40u32.to_be_bytes());
    hello_v2.extend_from_slice(&[10, 0, 0, 1]);
    hello_v2.extend_from_slice(&[10, 0, 0, 2]);
    hello_v2.extend_from_slice(&[10, 0, 0, 3]);
    hello_v2.extend_from_slice(&[10, 0, 0, 4]);
    let hello_v2 = ospf_finish(hello_v2);
    let hello_v2_len = hello_v2.len();

    run_conformance(&ConformanceCase {
        plugin: Box::new(Ospf),
        good: vec![GoodPacket {
            bytes: hello_v2,
            expected_header_len: hello_v2_len,
            expected_full_fields: vec![
                ("version", Value::U64(2)),
                ("type", Value::U64(1)),
                ("packet_length", Value::U64(hello_v2_len as u64)),
                ("router_id", Value::from(&[10u8, 0, 0, 1][..])),
                ("area_id", Value::from(&[0u8, 0, 0, 1][..])),
                ("hello_interval", Value::U64(10)),
                ("router_dead_interval", Value::U64(40)),
                ("designated_router", Value::from(&[10u8, 0, 0, 1][..])),
                (
                    "neighbors",
                    Value::List(vec![
                        Value::from(&[10u8, 0, 0, 3][..]),
                        Value::from(&[10u8, 0, 0, 4][..]),
                    ]),
                ),
            ],
            expected_hint: Hint::Terminal,
        }],
        outer_ctx: Vec::new(),
    });

    // RFC 5340 A.3.2 Hello: no network mask, 24-bit options, DR/BDR by
    // Router ID, one neighbor.
    let mut hello_v3 = ospf_header_prefix(3, 1);
    hello_v3.extend_from_slice(&7u32.to_be_bytes()); // interface_id
    hello_v3.push(1); // rtr_pri
    hello_v3.extend_from_slice(&[0, 0, 0x02]); // options
    hello_v3.extend_from_slice(&10u16.to_be_bytes()); // hello_interval
    hello_v3.extend_from_slice(&40u16.to_be_bytes()); // router_dead_interval
    hello_v3.extend_from_slice(&[10, 0, 0, 1]); // designated_router
    hello_v3.extend_from_slice(&[10, 0, 0, 2]); // backup_designated_router
    hello_v3.extend_from_slice(&[10, 0, 0, 5]); // neighbor
    let hello_v3 = ospf_finish(hello_v3);
    let hello_v3_len = hello_v3.len();

    run_conformance(&ConformanceCase {
        plugin: Box::new(Ospf),
        good: vec![GoodPacket {
            bytes: hello_v3,
            expected_header_len: hello_v3_len,
            expected_full_fields: vec![
                ("version", Value::U64(3)),
                ("type", Value::U64(1)),
                ("packet_length", Value::U64(hello_v3_len as u64)),
                ("router_id", Value::from(&[10u8, 0, 0, 1][..])),
                ("area_id", Value::from(&[0u8, 0, 0, 1][..])),
                ("hello_interval", Value::U64(10)),
                ("router_dead_interval", Value::U64(40)),
                ("designated_router", Value::from(&[10u8, 0, 0, 1][..])),
                (
                    "neighbors",
                    Value::List(vec![Value::from(&[10u8, 0, 0, 5][..])]),
                ),
            ],
            expected_hint: Hint::Terminal,
        }],
        outer_ctx: Vec::new(),
    });

    // RFC 2328 A.3.3 Database Description: interface_mtu 1500,
    // dd_sequence, plus a trailing (unwalked) LSA-header entry —
    // header_len still covers it via packet_length (module doc).
    let mut dbd_v2 = ospf_header_prefix(2, 2);
    dbd_v2.extend_from_slice(&1500u16.to_be_bytes());
    dbd_v2.push(0x02); // options
    dbd_v2.push(0x07); // bits: I|M|MS
    dbd_v2.extend_from_slice(&0xAABB_CCDDu32.to_be_bytes());
    dbd_v2.extend_from_slice(&[0xEE; 20]); // unwalked LSA-header trailer
    let dbd_v2 = ospf_finish(dbd_v2);
    let dbd_v2_len = dbd_v2.len();

    run_conformance(&ConformanceCase {
        plugin: Box::new(Ospf),
        good: vec![GoodPacket {
            bytes: dbd_v2,
            expected_header_len: dbd_v2_len,
            expected_full_fields: vec![
                ("version", Value::U64(2)),
                ("type", Value::U64(2)),
                ("packet_length", Value::U64(dbd_v2_len as u64)),
                ("router_id", Value::from(&[10u8, 0, 0, 1][..])),
                ("area_id", Value::from(&[0u8, 0, 0, 1][..])),
                ("interface_mtu", Value::U64(1500)),
                ("dd_sequence", Value::U64(0xAABB_CCDD)),
            ],
            expected_hint: Hint::Terminal,
        }],
        outer_ctx: Vec::new(),
    });

    // RFC 5340 A.3.3 Database Description: leading reserved byte,
    // 24-bit options, same interface_mtu/dd_sequence pair.
    let mut dbd_v3 = ospf_header_prefix(3, 2);
    dbd_v3.push(0); // reserved1
    dbd_v3.extend_from_slice(&[0, 0, 0x02]); // options
    dbd_v3.extend_from_slice(&1500u16.to_be_bytes());
    dbd_v3.push(0); // reserved2
    dbd_v3.push(0x07); // bits
    dbd_v3.extend_from_slice(&0xAABB_CCDDu32.to_be_bytes());
    let dbd_v3 = ospf_finish(dbd_v3);
    let dbd_v3_len = dbd_v3.len();

    run_conformance(&ConformanceCase {
        plugin: Box::new(Ospf),
        good: vec![GoodPacket {
            bytes: dbd_v3,
            expected_header_len: dbd_v3_len,
            expected_full_fields: vec![
                ("version", Value::U64(3)),
                ("type", Value::U64(2)),
                ("packet_length", Value::U64(dbd_v3_len as u64)),
                ("router_id", Value::from(&[10u8, 0, 0, 1][..])),
                ("area_id", Value::from(&[0u8, 0, 0, 1][..])),
                ("interface_mtu", Value::U64(1500)),
                ("dd_sequence", Value::U64(0xAABB_CCDD)),
            ],
            expected_hint: Hint::Terminal,
        }],
        outer_ctx: Vec::new(),
    });

    // RFC 2328 A.3.5 / RFC 5340 A.4.1/A.4.2.1 Link State Update: one LSA,
    // a 20-byte header plus a 4-byte body this plugin skips by the
    // header's own `length` field without decoding it. The kit's rule-1
    // truncation sweep below exercises that internal length boundary.
    let mut lsa_header = vec![0x00, 0x01]; // age
    lsa_header.extend_from_slice(&[0x00, 0x01]); // type field (router-LSA)
    lsa_header.extend_from_slice(&[10, 0, 0, 9]); // link_state_id
    lsa_header.extend_from_slice(&[10, 0, 0, 1]); // advertising_router
    lsa_header.extend_from_slice(&0x8000_0001u32.to_be_bytes()); // sequence
    lsa_header.extend_from_slice(&[0xBE, 0xEF]); // checksum
    lsa_header.extend_from_slice(&24u16.to_be_bytes()); // length: 20 + 4
    let mut lsu = ospf_header_prefix(2, 4);
    lsu.extend_from_slice(&1u32.to_be_bytes()); // num_lsas
    lsu.extend_from_slice(&lsa_header);
    lsu.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // LSA body, undecoded
    let lsu = ospf_finish(lsu);
    let lsu_len = lsu.len();

    run_conformance(&ConformanceCase {
        plugin: Box::new(Ospf),
        good: vec![GoodPacket {
            bytes: lsu,
            expected_header_len: lsu_len,
            expected_full_fields: vec![
                ("version", Value::U64(2)),
                ("type", Value::U64(4)),
                ("packet_length", Value::U64(lsu_len as u64)),
                ("router_id", Value::from(&[10u8, 0, 0, 1][..])),
                ("area_id", Value::from(&[0u8, 0, 0, 1][..])),
                (
                    "lsa_headers",
                    Value::List(vec![Value::from(&lsa_header[..])]),
                ),
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
fn sctp_conforms() {
    // RFC 9260 §3.1 common header + §3.3.2 bare INIT chunk (20 bytes, no
    // optional parameters).
    let mut init_packet = vec![
        0x87, 0x07, 0x0F, 0x1C, // 34567 -> 3868
        0x11, 0x22, 0x33, 0x44, // verification tag
        0x00, 0x00, 0x00, 0x00, // checksum (not verified)
    ];
    init_packet.extend_from_slice(&[0x01, 0x00, 0x00, 0x14]); // INIT, flags 0, length 20
    init_packet.extend_from_slice(&0xAABB_CCDDu32.to_be_bytes()); // initiate tag
    init_packet.extend_from_slice(&0x0001_0000u32.to_be_bytes()); // a_rwnd
    init_packet.extend_from_slice(&10u16.to_be_bytes()); // outbound streams
    init_packet.extend_from_slice(&5u16.to_be_bytes()); // inbound streams
    init_packet.extend_from_slice(&0x1234_5678u32.to_be_bytes()); // initial tsn

    // RFC 9260 §3.3.8 SHUTDOWN: 4-byte Cumulative TSN Ack value, no
    // INIT-family fixed fields to extract.
    let mut shutdown_packet = vec![
        0x0F, 0x1C, 0x87, 0x07, // 3868 -> 34567
        0x99, 0x88, 0x77, 0x66, // verification tag
        0x00, 0x00, 0x00, 0x00, // checksum
    ];
    shutdown_packet.extend_from_slice(&[0x07, 0x00, 0x00, 0x08]); // SHUTDOWN, length 8
    shutdown_packet.extend_from_slice(&0xDEAD_BEEFu32.to_be_bytes());

    run_conformance(&ConformanceCase {
        plugin: Box::new(Sctp),
        good: vec![
            GoodPacket {
                bytes: init_packet,
                expected_header_len: 32,
                expected_full_fields: vec![
                    ("src_port", Value::U64(34567)),
                    ("dst_port", Value::U64(3868)),
                    ("verification_tag", Value::U64(0x1122_3344)),
                    ("first_chunk_type", Value::U64(1)),
                    ("initiate_tag", Value::U64(0xAABB_CCDD)),
                    ("a_rwnd", Value::U64(65536)),
                    ("num_outbound_streams", Value::U64(10)),
                    ("num_inbound_streams", Value::U64(5)),
                    ("initial_tsn", Value::U64(0x1234_5678)),
                ],
                expected_hint: Hint::Terminal,
            },
            GoodPacket {
                bytes: shutdown_packet,
                expected_header_len: 20,
                expected_full_fields: vec![
                    ("src_port", Value::U64(3868)),
                    ("dst_port", Value::U64(34567)),
                    ("verification_tag", Value::U64(0x9988_7766)),
                    ("first_chunk_type", Value::U64(7)),
                ],
                expected_hint: Hint::Terminal,
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

#[test]
fn gtp_u_conforms() {
    run_conformance(&ConformanceCase {
        plugin: Box::new(GtpU),
        good: vec![
            // TS 29.281 mandatory-only header: G-PDU, no E/S/PN.
            GoodPacket {
                bytes: vec![
                    0x30, 0xFF, // version 1, PT=1; message type 255 (G-PDU)
                    0x00, 0x04, // length
                    0xAA, 0xBB, 0xCC, 0xDD, // TEID
                    0x45, 0x00, 0x00, 0x14, // inner payload stand-in
                ],
                expected_header_len: 8,
                expected_full_fields: vec![
                    ("teid", Value::U64(0xAABB_CCDD)),
                    ("message_type", Value::U64(255)),
                    ("flags", Value::U64(0x30)),
                    ("length", Value::U64(4)),
                ],
                expected_hint: Hint::Unknown,
            },
            // Echo Request with S flag set: sequence number present and
            // meaningful, no extension headers (next_ext_type = 0).
            GoodPacket {
                bytes: vec![
                    0x32, 0x01, // version 1, PT=1, S=1; message type 1 (Echo Request)
                    0x00, 0x04, // length
                    0x00, 0x00, 0x00, 0x00, // TEID (0 before assignment)
                    0x12, 0x34, // sequence number
                    0x00, // N-PDU number (not meaningful, PN unset)
                    0x00, // next extension header type: none
                ],
                expected_header_len: 12,
                expected_full_fields: vec![
                    ("teid", Value::U64(0)),
                    ("message_type", Value::U64(1)),
                    ("flags", Value::U64(0x32)),
                    ("length", Value::U64(4)),
                    ("sequence_number", Value::U64(0x1234)),
                ],
                expected_hint: Hint::Terminal,
            },
        ],
        outer_ctx: Vec::new(),
    });
}

#[test]
fn geneve_conforms() {
    run_conformance(&ConformanceCase {
        plugin: Box::new(Geneve),
        good: vec![
            // RFC 8926 bare header: no options, VNI 5001, IPv4 inside.
            GoodPacket {
                bytes: vec![0x00, 0x00, 0x08, 0x00, 0x00, 0x13, 0x89, 0x00],
                expected_header_len: 8,
                expected_full_fields: vec![
                    ("vni", Value::U64(5001)),
                    ("version", Value::U64(0)),
                    ("opt_len", Value::U64(0)),
                    ("o_bit", Value::Bool(false)),
                    ("c_bit", Value::Bool(false)),
                    ("protocol_type", Value::U64(0x0800)),
                    ("options", Value::from(&b""[..])),
                ],
                expected_hint: Hint::Route(RouteId::EtherType(0x0800)),
            },
            // One option word present, O and C bits set.
            GoodPacket {
                bytes: vec![
                    0x01, 0xC0, // Ver=0, Opt Len=1; O=1, C=1
                    0x08, 0x00, // protocol_type = IPv4
                    0x00, 0x13, 0x89, // VNI = 5001
                    0x00, // reserved
                    0xDE, 0xAD, 0xBE, 0xEF, // one 4-byte option word, opaque
                ],
                expected_header_len: 12,
                expected_full_fields: vec![
                    ("vni", Value::U64(5001)),
                    ("version", Value::U64(0)),
                    ("opt_len", Value::U64(1)),
                    ("o_bit", Value::Bool(true)),
                    ("c_bit", Value::Bool(true)),
                    ("protocol_type", Value::U64(0x0800)),
                    ("options", Value::from(&[0xDE, 0xAD, 0xBE, 0xEF][..])),
                ],
                expected_hint: Hint::Route(RouteId::EtherType(0x0800)),
            },
        ],
        outer_ctx: Vec::new(),
    });
}

#[test]
fn esp_conforms() {
    run_conformance(&ConformanceCase {
        plugin: Box::new(Esp),
        good: vec![GoodPacket {
            // RFC 4303 §2: SPI 0x1234_5678, sequence 42, then opaque
            // ciphertext this plugin must never interpret.
            bytes: vec![
                0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x2A, 0xDE, 0xAD, 0xBE, 0xEF,
            ],
            expected_header_len: 8,
            expected_full_fields: vec![
                ("spi", Value::U64(0x1234_5678)),
                ("sequence", Value::U64(42)),
            ],
            expected_hint: Hint::Terminal,
        }],
        outer_ctx: Vec::new(),
    });
}

#[test]
fn ah_conforms() {
    run_conformance(&ConformanceCase {
        plugin: Box::new(Ah),
        good: vec![
            // RFC 4302 §2: Next Header=TCP(6), Payload Len=4 (12-byte ICV,
            // the HMAC-SHA1-96 default per §5), SPI 0x1234_5678, sequence
            // 42, then the ICV — every byte cleartext.
            GoodPacket {
                bytes: vec![
                    0x06, 0x04, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x2A, 0xAA,
                    0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
                ],
                expected_header_len: 24,
                expected_full_fields: vec![
                    ("spi", Value::U64(0x1234_5678)),
                    ("next_header", Value::U64(6)),
                    ("payload_len", Value::U64(4)),
                    ("sequence", Value::U64(42)),
                    (
                        "icv",
                        Value::from(
                            &[
                                0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55,
                                0x66,
                            ][..],
                        ),
                    ),
                ],
                expected_hint: Hint::Route(RouteId::IpProtocol(6)),
            },
            // Next Header=UDP(17), Payload Len=1 (zero-length ICV): the
            // minimum syntactically valid header, no ICV bytes at all.
            GoodPacket {
                bytes: vec![0x11, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0, 0, 0, 1],
                expected_header_len: 12,
                expected_full_fields: vec![
                    ("spi", Value::U64(1)),
                    ("next_header", Value::U64(17)),
                    ("payload_len", Value::U64(1)),
                    ("sequence", Value::U64(1)),
                    ("icv", Value::from(&b""[..])),
                ],
                expected_hint: Hint::Route(RouteId::IpProtocol(17)),
            },
        ],
        outer_ctx: Vec::new(),
    });
}

// wireguard.com/protocol/ ("Messages"): every message shares message_type
// (1 byte) + 3 reserved bytes, encoded together as one little-endian u32
// (11.5) — these four builders cover all four message types, each a
// fixed-size, all-or-nothing Noise/AEAD message except Transport Data.

/// Handshake Initiation (148 bytes): sender_index, then ephemeral(32) +
/// encrypted static(48) + encrypted timestamp(28) + mac1(16) + mac2(16).
fn wg_handshake_initiation_bytes() -> Vec<u8> {
    let mut m = vec![0x01, 0x00, 0x00, 0x00]; // type=1, reserved=0
    m.extend_from_slice(&0x1111_1111u32.to_le_bytes()); // sender_index
    m.extend(std::iter::repeat_n(0xAB, 148 - 8));
    m
}

/// Handshake Response (92 bytes): sender_index, receiver_index, then
/// ephemeral(32) + encrypted-nothing(16) + mac1(16) + mac2(16).
fn wg_handshake_response_bytes() -> Vec<u8> {
    let mut m = vec![0x02, 0x00, 0x00, 0x00]; // type=2, reserved=0
    m.extend_from_slice(&0x2222_2222u32.to_le_bytes()); // sender_index
    m.extend_from_slice(&0x1111_1111u32.to_le_bytes()); // receiver_index
    m.extend(std::iter::repeat_n(0xCD, 92 - 12));
    m
}

/// Cookie Reply (64 bytes): receiver_index, then nonce(24) + encrypted
/// cookie(32) — a DoS-mitigation message (whitepaper §5.3), not session
/// traffic.
fn wg_cookie_reply_bytes() -> Vec<u8> {
    let mut m = vec![0x03, 0x00, 0x00, 0x00]; // type=3, reserved=0
    m.extend_from_slice(&0x1111_1111u32.to_le_bytes()); // receiver_index
    m.extend(std::iter::repeat_n(0xEF, 64 - 8));
    m
}

/// Transport Data: the one variable-length type. `header_len` covers only
/// the fixed 16-byte prefix (message_type+reserved, receiver_index,
/// counter) — the AEAD-encrypted payload past it is never counted as
/// header, the ESP precedent (D12, 11.5's `esp`).
fn wg_transport_data_bytes() -> Vec<u8> {
    let mut m = vec![0x04, 0x00, 0x00, 0x00]; // type=4, reserved=0
    m.extend_from_slice(&0x3333_3333u32.to_le_bytes()); // receiver_index
    m.extend_from_slice(&7u64.to_le_bytes()); // counter
    m.extend(std::iter::repeat_n(0x11, 16)); // Poly1305 tag, zero plaintext
    m
}

#[test]
fn wireguard_conforms() {
    run_conformance(&ConformanceCase {
        plugin: Box::new(Wireguard),
        good: vec![
            GoodPacket {
                expected_header_len: wg_handshake_initiation_bytes().len(),
                bytes: wg_handshake_initiation_bytes(),
                expected_full_fields: vec![
                    ("app", Value::from("wireguard")),
                    ("msg_type", Value::from("handshake_initiation")),
                    ("sender_index", Value::U64(0x1111_1111)),
                ],
                expected_hint: Hint::Terminal,
            },
            GoodPacket {
                expected_header_len: wg_handshake_response_bytes().len(),
                bytes: wg_handshake_response_bytes(),
                expected_full_fields: vec![
                    ("app", Value::from("wireguard")),
                    ("msg_type", Value::from("handshake_response")),
                    ("sender_index", Value::U64(0x2222_2222)),
                    ("receiver_index", Value::U64(0x1111_1111)),
                ],
                expected_hint: Hint::Terminal,
            },
            GoodPacket {
                expected_header_len: wg_cookie_reply_bytes().len(),
                bytes: wg_cookie_reply_bytes(),
                expected_full_fields: vec![
                    ("app", Value::from("wireguard")),
                    ("msg_type", Value::from("cookie_reply")),
                    ("receiver_index", Value::U64(0x1111_1111)),
                ],
                expected_hint: Hint::Terminal,
            },
            GoodPacket {
                // header_len (16) is deliberately shorter than the full
                // fixture (32 bytes: prefix + Poly1305 tag) — Transport
                // Data's ciphertext trails the header, uncounted (D12).
                expected_header_len: 16,
                bytes: wg_transport_data_bytes(),
                expected_full_fields: vec![
                    ("app", Value::from("wireguard")),
                    ("msg_type", Value::from("transport_data")),
                    ("receiver_index", Value::U64(0x3333_3333)),
                ],
                expected_hint: Hint::Terminal,
            },
        ],
        outer_ctx: Vec::new(),
    });
}

fn udp_predecessor_layer() -> LayerRecord {
    LayerRecord {
        protocol: "udp",
        offset: 34,
        header_len: 8,
        fields: FieldMap::new(),
    }
}

fn ipv4_predecessor_layer() -> LayerRecord {
    LayerRecord {
        protocol: "ipv4",
        offset: 14,
        header_len: 20,
        fields: FieldMap::new(),
    }
}

#[test]
fn l2tpv3_over_udp_data_conforms() {
    // RFC 3931 §3.2.2: T=0, Ver=3, reserved word, Session ID 0x1234_5678,
    // no cookie (11.5's documented v1 default), then pseudowire payload.
    let bytes = vec![
        0x00, 0x03, 0x00, 0x00, // T=0, Ver=3, reserved=0
        0x12, 0x34, 0x56, 0x78, // Session ID
        0xDE, 0xAD, 0xBE, 0xEF, // pseudowire payload (opaque to this plugin)
    ];
    run_conformance(&ConformanceCase {
        plugin: Box::new(L2tpv3),
        good: vec![GoodPacket {
            bytes,
            expected_header_len: 8,
            expected_full_fields: vec![
                ("session_id", Value::U64(0x1234_5678)),
                ("t_bit", Value::Bool(false)),
            ],
            expected_hint: Hint::ByProtocol("ethernet"),
        }],
        outer_ctx: vec![udp_predecessor_layer()],
    });
}

#[test]
fn l2tpv3_over_ip_data_conforms() {
    // RFC 3931 §4.1.1: direct IP encapsulation carries data messages only
    // and has no T/Ver word at all — Session ID is the entire header.
    let bytes = vec![
        0x00, 0x00, 0x00, 0x2A, // Session ID = 42
        0xAA, 0xBB, // pseudowire payload
    ];
    run_conformance(&ConformanceCase {
        plugin: Box::new(L2tpv3),
        good: vec![GoodPacket {
            bytes,
            expected_header_len: 4,
            expected_full_fields: vec![
                ("session_id", Value::U64(42)),
                ("t_bit", Value::Bool(false)),
            ],
            expected_hint: Hint::ByProtocol("ethernet"),
        }],
        outer_ctx: vec![ipv4_predecessor_layer()],
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

/// RFC 6762 standard query for example.local (A, IN), QU bit set on the
/// question's class field (§5.4) — mDNS's one class-field bit `dns`'s own
/// fixture never exercises.
fn mdns_query_bytes() -> Vec<u8> {
    let mut m = vec![0x00, 0x00, 0x00, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    m.extend_from_slice(&[7]);
    m.extend_from_slice(b"example");
    m.extend_from_slice(&[5]);
    m.extend_from_slice(b"local");
    m.extend_from_slice(&[0, 0, 1, 0x80, 0x01]); // type A, class IN | QU bit
    m
}

#[test]
fn mdns_conforms() {
    run_conformance(&ConformanceCase {
        plugin: Box::new(Mdns),
        good: vec![GoodPacket {
            expected_header_len: mdns_query_bytes().len(),
            bytes: mdns_query_bytes(),
            expected_full_fields: vec![
                ("app", Value::from("mdns")),
                ("id", Value::U64(0)),
                ("is_response", Value::Bool(false)),
                ("opcode", Value::U64(0)),
                ("rcode", Value::U64(0)),
                ("qname", Value::from("example.local")),
                ("qtype", Value::U64(1)),
                ("is_multicast_query", Value::Bool(true)),
                ("answers", Value::List(vec![])),
            ],
            expected_hint: Hint::Terminal,
        }],
        outer_ctx: Vec::new(),
    });
}

/// RFC 4795 §7.1 response for `host-a` (A, IN) with the `C` (conflict) bit
/// set on the flags word — the one LLMNR reuses from DNS's `AA` position
/// `mdns`'s own fixture never exercises (mdns reuses the class field's top
/// bit instead, not the flags word). Echoes the question (as `dns`'s own
/// compressed-response fixture does) so `qname`/`qtype` are populated too.
fn llmnr_response_bytes() -> Vec<u8> {
    let mut m = vec![0x00, 0x00, 0x84, 0x00, 0, 1, 0, 1, 0, 0, 0, 0];
    m.extend_from_slice(&[6]);
    m.extend_from_slice(b"host-a");
    m.push(0);
    m.extend_from_slice(&[0, 1, 0, 1]); // qtype A, qclass IN
    m.extend_from_slice(&[0xC0, 0x0C]); // answer name: pointer to question
    m.extend_from_slice(&[0, 1, 0, 1]); // type A, class IN
    m.extend_from_slice(&[0, 0, 0, 120]); // ttl
    m.extend_from_slice(&[0, 4, 192, 0, 2, 5]); // rdlength + A record
    m
}

#[test]
fn llmnr_conforms() {
    run_conformance(&ConformanceCase {
        plugin: Box::new(Llmnr),
        good: vec![GoodPacket {
            expected_header_len: llmnr_response_bytes().len(),
            bytes: llmnr_response_bytes(),
            expected_full_fields: vec![
                ("app", Value::from("llmnr")),
                ("id", Value::U64(0)),
                ("is_response", Value::Bool(true)),
                ("opcode", Value::U64(0)),
                ("rcode", Value::U64(0)),
                ("conflict", Value::Bool(true)),
                ("tentative", Value::Bool(false)),
                ("qname", Value::from("host-a")),
                ("qtype", Value::U64(1)),
                ("answers", Value::List(vec![Value::from("192.0.2.5")])),
            ],
            expected_hint: Hint::Terminal,
        }],
        outer_ctx: Vec::new(),
    });
}

#[test]
fn bgp_conforms() {
    // RFC 4271 §4.2 OPEN: version 4, AS 65001, hold time 180, router id
    // 10.0.0.1, no optional parameters.
    let mut bytes = vec![0xFFu8; 16]; // Marker
    bytes.extend_from_slice(&29u16.to_be_bytes()); // Length
    bytes.push(1); // Type: OPEN
    bytes.push(4); // Version
    bytes.extend_from_slice(&65001u16.to_be_bytes());
    bytes.extend_from_slice(&180u16.to_be_bytes());
    bytes.extend_from_slice(&[10, 0, 0, 1]);
    bytes.push(0); // Opt Parm Len

    // Like DNS, BGP's real identity is its TCP session (module doc).
    let tcp_layer = LayerRecord {
        protocol: "tcp",
        offset: 34,
        header_len: 20,
        fields: FieldMap::new(),
    };

    run_conformance(&ConformanceCase {
        plugin: Box::new(Bgp),
        good: vec![GoodPacket {
            bytes,
            expected_header_len: 29,
            expected_full_fields: vec![
                ("app", Value::from("bgp")),
                ("msg_type", Value::U64(1)),
                ("length", Value::U64(29)),
                ("my_as", Value::U64(65001)),
                ("hold_time", Value::U64(180)),
                ("bgp_identifier", Value::from(&[10u8, 0, 0, 1][..])),
            ],
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

/// MBAP header (transaction id, protocol id = 0, length, unit id) + PDU.
fn modbus_frame(unit_id: u8, pdu: &[u8]) -> Vec<u8> {
    let mut f = vec![0x00, 0x01, 0x00, 0x00];
    let length = (1 + pdu.len()) as u16; // unit_id + PDU
    f.extend_from_slice(&length.to_be_bytes());
    f.push(unit_id);
    f.extend_from_slice(pdu);
    f
}

#[test]
fn modbus_conforms() {
    // Read Holding Registers (0x03): start 0x0000, quantity 10.
    let read_holding_registers = modbus_frame(1, &[0x03, 0x00, 0x00, 0x00, 0x0A]);
    // Write Single Register (0x06): address 0x0001, value 0x0003.
    let write_single_register = modbus_frame(1, &[0x06, 0x00, 0x01, 0x00, 0x03]);
    // Exception response to a Read Holding Registers request: function
    // code with the top bit set, exception code 2 (Illegal Data Address).
    let exception = modbus_frame(1, &[0x83, 0x02]);

    run_conformance(&ConformanceCase {
        plugin: Box::new(Modbus),
        good: vec![
            GoodPacket {
                expected_header_len: read_holding_registers.len(),
                bytes: read_holding_registers,
                expected_full_fields: vec![
                    ("unit_id", Value::U64(1)),
                    ("function_code", Value::U64(0x03)),
                    ("is_exception", Value::Bool(false)),
                    ("start_address", Value::U64(0)),
                    ("quantity", Value::U64(10)),
                ],
                expected_hint: Hint::Terminal,
            },
            GoodPacket {
                expected_header_len: write_single_register.len(),
                bytes: write_single_register,
                expected_full_fields: vec![
                    ("unit_id", Value::U64(1)),
                    ("function_code", Value::U64(0x06)),
                    ("is_exception", Value::Bool(false)),
                    ("start_address", Value::U64(1)),
                    ("register_value", Value::U64(3)),
                ],
                expected_hint: Hint::Terminal,
            },
            GoodPacket {
                expected_header_len: exception.len(),
                bytes: exception,
                expected_full_fields: vec![
                    ("unit_id", Value::U64(1)),
                    ("function_code", Value::U64(0x83)),
                    ("is_exception", Value::Bool(true)),
                    ("exception_code", Value::U64(2)),
                ],
                expected_hint: Hint::Terminal,
            },
        ],
        outer_ctx: Vec::new(),
    });
}

/// Encodes `value` as an MQTT Variable Byte Integer (OASIS MQTT 5.0 §1.5.5).
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

/// Encodes an MQTT UTF-8 Encoded String (2-byte length prefix + bytes).
fn mqtt_utf8_field(s: &str) -> Vec<u8> {
    let mut out = (s.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(s.as_bytes());
    out
}

fn mqtt_frame(message_type: u8, flags: u8, body: &[u8]) -> Vec<u8> {
    let mut f = vec![(message_type << 4) | flags];
    f.extend_from_slice(&mqtt_variable_byte_int(body.len()));
    f.extend_from_slice(body);
    f
}

#[test]
fn mqtt_conforms() {
    // PUBLISH, QoS 1, RETAIN set (fixed-header flags 0x03): topic
    // "sensors/temp", packet id 7 (present because QoS > 0), payload "21.5"
    // (OASIS MQTT 5.0 §3.3 / 3.1.1 §3.3 — identical shape for this case).
    let mut publish_body = mqtt_utf8_field("sensors/temp");
    publish_body.extend_from_slice(&7u16.to_be_bytes());
    publish_body.extend_from_slice(b"21.5");
    let publish_remaining_length = publish_body.len() as u64;
    let publish = mqtt_frame(3, 0x03, &publish_body);

    // PUBLISH, QoS 0 (no packet id), RETAIN clear: topic "alerts/fire", empty payload.
    let publish_qos0_body = mqtt_utf8_field("alerts/fire");
    let publish_qos0_remaining_length = publish_qos0_body.len() as u64;
    let publish_qos0 = mqtt_frame(3, 0x00, &publish_qos0_body);

    run_conformance(&ConformanceCase {
        plugin: Box::new(Mqtt),
        good: vec![
            GoodPacket {
                expected_header_len: publish.len(),
                bytes: publish,
                expected_full_fields: vec![
                    ("app", Value::from("mqtt")),
                    ("message_type", Value::U64(3)),
                    ("remaining_length", Value::U64(publish_remaining_length)),
                    ("topic", Value::from("sensors/temp")),
                    ("qos", Value::U64(1)),
                    ("retain", Value::Bool(true)),
                ],
                expected_hint: Hint::Terminal,
            },
            GoodPacket {
                expected_header_len: publish_qos0.len(),
                bytes: publish_qos0,
                expected_full_fields: vec![
                    ("app", Value::from("mqtt")),
                    ("message_type", Value::U64(3)),
                    (
                        "remaining_length",
                        Value::U64(publish_qos0_remaining_length),
                    ),
                    ("topic", Value::from("alerts/fire")),
                    ("qos", Value::U64(0)),
                    ("retain", Value::Bool(false)),
                ],
                expected_hint: Hint::Terminal,
            },
        ],
        outer_ctx: Vec::new(),
    });
}

/// A DNP3 Data Link Layer frame: sync + length + control, little-endian
/// destination/source, a 2-byte header CRC (not validated), and — when
/// `pdu` is non-empty — a transport header + application control byte
/// ahead of it (IEEE 1815-2012 §9-10).
fn dnp3_frame(destination: u16, source: u16, control: u8, pdu: &[u8]) -> Vec<u8> {
    let user_data_len = if pdu.is_empty() { 0 } else { 1 + pdu.len() };
    let length = 5 + user_data_len;
    let mut f = vec![0x05, 0x64, length as u8, control];
    f.extend_from_slice(&destination.to_le_bytes());
    f.extend_from_slice(&source.to_le_bytes());
    f.extend_from_slice(&[0xAB, 0xCD]); // header CRC
    if !pdu.is_empty() {
        f.push(0xC1); // transport header: FIN|FIR, seq 1
        f.extend_from_slice(pdu);
    }
    f
}

#[test]
fn dnp3_conforms() {
    // Application Layer control byte + function code 1 (Read). The rollup
    // kit requires every "good" sample to carry every declared rollup
    // field (rule 3) — the no-user-data, link-layer-only shape (RESET_
    // LINK_STATES et al.) is covered instead by `dnp3.rs`'s own unit test.
    let read_request = dnp3_frame(1024, 3, 0xC4, &[0xC0, 0x01]);
    // Function code 0x81 (a response), different control/addresses.
    let response = dnp3_frame(3, 1024, 0x44, &[0xC0, 0x81]);

    run_conformance(&ConformanceCase {
        plugin: Box::new(Dnp3),
        good: vec![
            GoodPacket {
                expected_header_len: response.len(),
                bytes: response,
                expected_full_fields: vec![
                    ("source", Value::U64(1024)),
                    ("destination", Value::U64(3)),
                    ("start_bytes", Value::U64(0x0564)),
                    ("length", Value::U64(8)),
                    ("control", Value::U64(0x44)),
                    ("function_code", Value::U64(0x81)),
                ],
                expected_hint: Hint::Terminal,
            },
            GoodPacket {
                expected_header_len: read_request.len(),
                bytes: read_request,
                expected_full_fields: vec![
                    ("source", Value::U64(3)),
                    ("destination", Value::U64(1024)),
                    ("start_bytes", Value::U64(0x0564)),
                    ("length", Value::U64(8)),
                    ("control", Value::U64(0xC4)),
                    ("function_code", Value::U64(1)),
                ],
                expected_hint: Hint::Terminal,
            },
        ],
        outer_ctx: Vec::new(),
    });
}

/// A BACnet/IP (Annex J) message: 4-byte BVLC header (type `0x81`,
/// `function`, big-endian total-length) wrapping `npdu_and_after` (NPDU +
/// APDU, present only for `Original-Unicast-NPDU`/`Original-Broadcast-
/// NPDU`/`Forwarded-NPDU`).
fn bacnet_ip_frame(function: u8, npdu_and_after: &[u8]) -> Vec<u8> {
    let length = (4 + npdu_and_after.len()) as u16;
    let mut b = vec![0x81, function];
    b.extend_from_slice(&length.to_be_bytes());
    b.extend_from_slice(npdu_and_after);
    b
}

#[test]
fn bacnet_ip_conforms() {
    // Unrestricted Who-Is broadcast (Original-Broadcast-NPDU, 0x0B):
    // NPDU version 1, control 0x00 (no routing, local broadcast),
    // Unconfirmed-Request APDU, service choice 8 (Who-Is).
    let who_is = bacnet_ip_frame(0x0B, &[0x01, 0x00, 0x10, 0x08]);

    // Unicast ReadProperty (Original-Unicast-NPDU, 0x0A) answered by a
    // ComplexACK, both unsegmented, service choice 12 (ReadProperty),
    // trailing bytes are the (undecoded) object-identifier/property-value
    // parameters.
    let mut complex_ack_npdu = vec![0x01, 0x00, 0x30, 0x01, 0x0C];
    complex_ack_npdu.extend_from_slice(&[0x3E, 0x44, 0x00, 0x00, 0x00, 0x00, 0x3F]);
    let read_property_ack = bacnet_ip_frame(0x0A, &complex_ack_npdu);

    run_conformance(&ConformanceCase {
        plugin: Box::new(BacnetIp),
        good: vec![
            GoodPacket {
                expected_header_len: who_is.len(),
                bytes: who_is,
                expected_full_fields: vec![
                    ("app", Value::from("bacnet")),
                    ("bvlc_function", Value::U64(0x0B)),
                    ("npdu_control", Value::U64(0x00)),
                    ("apdu_type", Value::U64(1)),
                    ("service_choice", Value::U64(8)),
                ],
                expected_hint: Hint::Terminal,
            },
            GoodPacket {
                expected_header_len: read_property_ack.len(),
                bytes: read_property_ack,
                expected_full_fields: vec![
                    ("app", Value::from("bacnet")),
                    ("bvlc_function", Value::U64(0x0A)),
                    ("npdu_control", Value::U64(0x00)),
                    ("apdu_type", Value::U64(3)),
                    ("service_choice", Value::U64(12)),
                ],
                expected_hint: Hint::Terminal,
            },
        ],
        outer_ctx: Vec::new(),
    });
}

/// An EtherNet/IP encapsulation message: 24-byte little-endian header
/// (command, length, session handle, status = success, 8-byte sender
/// context, reserved options) plus `data` (Vol 2 §2-3.1).
fn enip_frame(command: u16, session_handle: u32, data: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(24 + data.len());
    b.extend_from_slice(&command.to_le_bytes());
    b.extend_from_slice(&(data.len() as u16).to_le_bytes());
    b.extend_from_slice(&session_handle.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes()); // status: success
    b.extend_from_slice(&[0u8; 8]); // sender context, opaque
    b.extend_from_slice(&0u32.to_le_bytes()); // options, reserved
    b.extend_from_slice(data);
    b
}

#[test]
fn enip_conforms() {
    // RegisterSession response: Protocol Version = 1, Option Flags = 0
    // (Vol 2 §2-4.9), a session handle the target just assigned.
    let register_session = enip_frame(0x0065, 0x2A2A, &[1, 0, 0, 0]);

    // SendRRData carrying an unconnected Get_Attribute_Single request
    // (service 0x0E) for Identity (class 1) instance 1 attribute 3, inside
    // a Null Address Item + Unconnected Data Item (CPF, Vol 2 §2-6).
    let cip_request = [0x0E, 0x02, 0x20, 0x01, 0x24, 0x01, 0x30, 0x03];
    let mut send_rr_data_body = Vec::new();
    send_rr_data_body.extend_from_slice(&0u32.to_le_bytes()); // interface handle
    send_rr_data_body.extend_from_slice(&5u16.to_le_bytes()); // timeout
    send_rr_data_body.extend_from_slice(&2u16.to_le_bytes()); // item count
    send_rr_data_body.extend_from_slice(&0x0000u16.to_le_bytes()); // Null Address Item
    send_rr_data_body.extend_from_slice(&0u16.to_le_bytes());
    send_rr_data_body.extend_from_slice(&0x00B2u16.to_le_bytes()); // Unconnected Data Item
    send_rr_data_body.extend_from_slice(&(cip_request.len() as u16).to_le_bytes());
    send_rr_data_body.extend_from_slice(&cip_request);
    let send_rr_data = enip_frame(0x006F, 0x2A2A, &send_rr_data_body);

    run_conformance(&ConformanceCase {
        plugin: Box::new(Enip),
        good: vec![
            GoodPacket {
                expected_header_len: register_session.len(),
                bytes: register_session,
                expected_full_fields: vec![
                    ("session_handle", Value::U64(0x2A2A)),
                    ("command", Value::U64(0x0065)),
                    ("length", Value::U64(4)),
                    ("status", Value::U64(0)),
                ],
                expected_hint: Hint::Terminal,
            },
            GoodPacket {
                expected_header_len: send_rr_data.len(),
                bytes: send_rr_data,
                expected_full_fields: vec![
                    ("session_handle", Value::U64(0x2A2A)),
                    ("command", Value::U64(0x006F)),
                    ("length", Value::U64(send_rr_data_body.len() as u64)),
                    ("status", Value::U64(0)),
                    ("cip_service", Value::U64(0x0E)),
                ],
                expected_hint: Hint::Terminal,
            },
        ],
        outer_ctx: Vec::new(),
    });
}

#[test]
fn syslog_conforms() {
    // Both samples are RFC 5424 §6.5 Example 1 / RFC 3164 §5.4 Example 1
    // (same PRI, same hostname/TAG in both RFCs), each truncated at its
    // last unambiguous, self-terminated token — see syslog.rs's module
    // doc for why the trailing `[SP MSG]`/CONTENT is exercised separately
    // in application.rs instead of here.
    let rfc5424 = b"<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 -".to_vec();
    let rfc3164 = b"<34>Oct 11 22:14:15 mymachine su:".to_vec();

    run_conformance(&ConformanceCase {
        plugin: Box::new(Syslog),
        good: vec![
            GoodPacket {
                expected_header_len: rfc5424.len(),
                bytes: rfc5424,
                expected_full_fields: vec![
                    ("app", Value::from("syslog")),
                    ("facility", Value::U64(4)),
                    ("severity", Value::U64(2)),
                    ("version", Value::U64(1)),
                    ("hostname", Value::from("mymachine.example.com")),
                    ("app_name", Value::from("su")),
                ],
                expected_hint: Hint::Terminal,
            },
            GoodPacket {
                expected_header_len: rfc3164.len(),
                bytes: rfc3164,
                expected_full_fields: vec![
                    ("app", Value::from("syslog")),
                    ("facility", Value::U64(4)),
                    ("severity", Value::U64(2)),
                    ("version", Value::U64(0)),
                    ("hostname", Value::from("mymachine")),
                    ("app_name", Value::from("su")),
                ],
                expected_hint: Hint::Terminal,
            },
        ],
        outer_ctx: Vec::new(),
    });
}

#[test]
fn radius_conforms() {
    // Hand-built and byte-verified against RFC 2865 §3/§4 (header, AVP
    // framing, Access-Request/Accept) and RFC 2866 §3/§4 (Accounting-
    // Request), not captured from a live NAS — see radius.rs's own fixture
    // builders for a byte-by-byte breakdown of the same structure.

    // Access-Request: identifier 1, User-Name "bob", Calling-Station-Id
    // "00-11-22-33-44-55".
    let mut access_request_attrs = vec![1, 5, b'b', b'o', b'b'];
    access_request_attrs.extend_from_slice(&[
        31, 19, b'0', b'0', b'-', b'1', b'1', b'-', b'2', b'2', b'-', b'3', b'3', b'-', b'4', b'4',
        b'-', b'5', b'5',
    ]);
    let mut access_request = vec![1, 1];
    access_request.extend_from_slice(&((20 + access_request_attrs.len()) as u16).to_be_bytes());
    access_request.extend_from_slice(&[0xAA; 16]);
    access_request.extend_from_slice(&access_request_attrs);

    // Accounting-Request: identifier 7, User-Name "bob", Acct-Status-Type
    // = Start (1).
    let mut accounting_request_attrs = vec![1, 5, b'b', b'o', b'b'];
    accounting_request_attrs.extend_from_slice(&[40, 6, 0, 0, 0, 1]);
    let mut accounting_request = vec![4, 7];
    accounting_request
        .extend_from_slice(&((20 + accounting_request_attrs.len()) as u16).to_be_bytes());
    accounting_request.extend_from_slice(&[0xCC; 16]);
    accounting_request.extend_from_slice(&accounting_request_attrs);

    run_conformance(&ConformanceCase {
        plugin: Box::new(Radius),
        good: vec![
            GoodPacket {
                expected_header_len: access_request.len(),
                bytes: access_request,
                expected_full_fields: vec![
                    ("app", Value::from("radius")),
                    ("code", Value::U64(1)),
                    ("identifier", Value::U64(1)),
                    ("user_name", Value::from("bob")),
                    ("calling_station_id", Value::from("00-11-22-33-44-55")),
                ],
                expected_hint: Hint::Terminal,
            },
            GoodPacket {
                expected_header_len: accounting_request.len(),
                bytes: accounting_request,
                expected_full_fields: vec![
                    ("app", Value::from("radius")),
                    ("code", Value::U64(4)),
                    ("identifier", Value::U64(7)),
                    ("user_name", Value::from("bob")),
                    ("acct_status_type", Value::U64(1)),
                ],
                expected_hint: Hint::Terminal,
            },
        ],
        outer_ctx: Vec::new(),
    });
}

#[test]
fn ssdp_conforms() {
    // Hand-built against the UPnP Device Architecture v2.0 §1.2 examples
    // (NOTIFY shape; ssdp.rs's own module doc has the full citation — there
    // is no ratified IETF RFC for SSDP). Both good samples are `ssdp:alive`
    // announcements (NOTIFY is the only message type that legally carries
    // both of ssdp's rollup fields, `nts` and `location`, at once — the
    // kit's rule 3 requires every rollup field on every good sample; the
    // M-SEARCH-request and search-response shapes, where `nts` is absent
    // by protocol design, are covered instead by ssdp.rs's own fixtures
    // and application.rs's app-stream test).
    let alive_root_device = b"NOTIFY * HTTP/1.1\r\n\
HOST: 239.255.255.250:1900\r\n\
CACHE-CONTROL: max-age=1800\r\n\
LOCATION: http://192.168.1.20:8080/description.xml\r\n\
NT: upnp:rootdevice\r\n\
NTS: ssdp:alive\r\n\
USN: uuid:4d696e69-1dd2-11b2-8349-e31881a5f45a::upnp:rootdevice\r\n\
\r\n"
        .to_vec();

    let alive_content_directory = b"NOTIFY * HTTP/1.1\r\n\
HOST: 239.255.255.250:1900\r\n\
CACHE-CONTROL: max-age=1800\r\n\
LOCATION: http://192.168.1.20:8080/description.xml\r\n\
NT: urn:schemas-upnp-org:service:ContentDirectory:1\r\n\
NTS: ssdp:alive\r\n\
USN: uuid:4d696e69-1dd2-11b2-8349-e31881a5f45a::urn:schemas-upnp-org:service:ContentDirectory:1\r\n\
\r\n"
        .to_vec();

    run_conformance(&ConformanceCase {
        plugin: Box::new(Ssdp),
        good: vec![
            GoodPacket {
                expected_header_len: alive_root_device.len(),
                bytes: alive_root_device,
                expected_full_fields: vec![
                    ("app", Value::from("ssdp")),
                    ("method", Value::from("NOTIFY")),
                    ("nts", Value::from("ssdp:alive")),
                    ("location", Value::from("http://192.168.1.20:8080/description.xml")),
                    (
                        "usn",
                        Value::from("uuid:4d696e69-1dd2-11b2-8349-e31881a5f45a::upnp:rootdevice"),
                    ),
                ],
                expected_hint: Hint::Terminal,
            },
            GoodPacket {
                expected_header_len: alive_content_directory.len(),
                bytes: alive_content_directory,
                expected_full_fields: vec![
                    ("app", Value::from("ssdp")),
                    ("method", Value::from("NOTIFY")),
                    ("nts", Value::from("ssdp:alive")),
                    ("location", Value::from("http://192.168.1.20:8080/description.xml")),
                    (
                        "usn",
                        Value::from(
                            "uuid:4d696e69-1dd2-11b2-8349-e31881a5f45a::urn:schemas-upnp-org:service:ContentDirectory:1",
                        ),
                    ),
                ],
                expected_hint: Hint::Terminal,
            },
        ],
        outer_ctx: Vec::new(),
    });
}

#[test]
fn snmp_conforms() {
    // Hand-built and byte-verified against RFC 1157 §4.1 (v1 PDUs/Trap-PDU),
    // RFC 3416 §3 (v2c PDUs), RFC 1213 (sysDescr.0/sysUpTime.0 OIDs), and
    // X.690 (BER TLV encoding) — not captured from a live agent. See
    // snmp.rs's own fixture builders for a byte-by-byte breakdown of the
    // same structure.

    // v1 GetRequest for sysDescr.0, community "public", request-id 1.
    let get_request_v1 = vec![
        0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6C, 0x69, 0x63, 0xA0, 0x19,
        0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0E, 0x30, 0x0C, 0x06, 0x08,
        0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00,
    ];

    // v2c GetResponse answering the request above with sysDescr.0 =
    // "Linux".
    let get_response_v2c = vec![
        0x30, 0x2B, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6C, 0x69, 0x63, 0xA2, 0x1E,
        0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x13, 0x30, 0x11, 0x06, 0x08,
        0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x04, 0x05, 0x4C, 0x69, 0x6E, 0x75, 0x78,
    ];

    // v2c SNMPv2-Trap (tag [7]) carrying sysUpTime.0.
    let snmpv2_trap = vec![
        0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6C, 0x69, 0x63, 0xA7, 0x19,
        0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0E, 0x30, 0x0C, 0x06, 0x08,
        0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00, 0x05, 0x00,
    ];

    // v1 Trap-PDU (tag [4]): structurally different from the other PDUs
    // (RFC 1157 §4.1.6) — its first element is an enterprise OID, not
    // request-id, so `request_id` is absent from the expected field set.
    let trap_v1 = vec![
        0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6C, 0x69, 0x63, 0xA4, 0x19,
        0x06, 0x06, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x09, 0x40, 0x04, 0xC0, 0x00, 0x02, 0x01, 0x02,
        0x01, 0x06, 0x02, 0x01, 0x00, 0x43, 0x01, 0x00, 0x30, 0x00,
    ];

    run_conformance(&ConformanceCase {
        plugin: Box::new(Snmp),
        good: vec![
            GoodPacket {
                expected_header_len: get_request_v1.len(),
                bytes: get_request_v1,
                expected_full_fields: vec![
                    ("app", Value::from("snmp")),
                    ("version", Value::U64(0)),
                    ("community", Value::from("public")),
                    ("pdu_type", Value::U64(0)),
                    ("request_id", Value::U64(1)),
                ],
                expected_hint: Hint::Terminal,
            },
            GoodPacket {
                expected_header_len: get_response_v2c.len(),
                bytes: get_response_v2c,
                expected_full_fields: vec![
                    ("app", Value::from("snmp")),
                    ("version", Value::U64(1)),
                    ("community", Value::from("public")),
                    ("pdu_type", Value::U64(2)),
                    ("request_id", Value::U64(1)),
                ],
                expected_hint: Hint::Terminal,
            },
            GoodPacket {
                expected_header_len: snmpv2_trap.len(),
                bytes: snmpv2_trap,
                expected_full_fields: vec![
                    ("app", Value::from("snmp")),
                    ("version", Value::U64(1)),
                    ("community", Value::from("public")),
                    ("pdu_type", Value::U64(7)),
                    ("request_id", Value::U64(0)),
                ],
                expected_hint: Hint::Terminal,
            },
            GoodPacket {
                expected_header_len: trap_v1.len(),
                bytes: trap_v1,
                expected_full_fields: vec![
                    ("app", Value::from("snmp")),
                    ("version", Value::U64(0)),
                    ("community", Value::from("public")),
                    ("pdu_type", Value::U64(4)),
                ],
                expected_hint: Hint::Terminal,
            },
        ],
        outer_ctx: Vec::new(),
    });
}

#[test]
fn netflow9_conforms() {
    // RFC 3954 §5.1 fixed header, count=1 (one FlowSet in this packet).
    let mut bytes = vec![0, 9, 0, 1];
    bytes.extend_from_slice(&1_000u32.to_be_bytes()); // sys_uptime
    bytes.extend_from_slice(&1_700_000_000u32.to_be_bytes()); // unix_secs
    bytes.extend_from_slice(&42u32.to_be_bytes()); // sequence
    bytes.extend_from_slice(&7u32.to_be_bytes()); // source_id

    // A single Template FlowSet (id=0), one record: template_id=256,
    // fields IN_BYTES(8)/4 and PROTOCOL(4)/4 (RFC 3954 §8's field-type
    // registry). Exactly one FlowSet — the module doc's truncation-
    // honesty note — so every strict prefix still declines.
    let mut record = 256u16.to_be_bytes().to_vec();
    record.extend_from_slice(&2u16.to_be_bytes()); // field_count
    record.extend_from_slice(&8u16.to_be_bytes());
    record.extend_from_slice(&4u16.to_be_bytes());
    record.extend_from_slice(&4u16.to_be_bytes());
    record.extend_from_slice(&4u16.to_be_bytes());
    let flowset_len = 4 + record.len();
    bytes.extend_from_slice(&0u16.to_be_bytes()); // flowset_id = 0 (Template)
    bytes.extend_from_slice(&(flowset_len as u16).to_be_bytes());
    bytes.extend_from_slice(&record);

    run_conformance(&ConformanceCase {
        plugin: Box::new(Netflow9),
        good: vec![GoodPacket {
            // Fixed 20-byte header only — FlowSets are optional
            // repetition and thus trailing payload beyond header_len
            // (module doc's truncation-honesty note).
            expected_header_len: 20,
            bytes: bytes.clone(),
            expected_full_fields: vec![
                ("app", Value::from("netflow9")),
                ("version", Value::U64(9)),
                ("count", Value::U64(1)),
                ("sequence", Value::U64(42)),
                ("source_id", Value::U64(7)),
                (
                    "flowsets",
                    Value::List(vec![Value::List(vec![
                        Value::U64(0),
                        Value::U64(flowset_len as u64),
                        Value::List(vec![Value::List(vec![
                            Value::U64(256),
                            Value::U64(2),
                            Value::List(vec![
                                Value::U64(8),
                                Value::U64(4),
                                Value::U64(4),
                                Value::U64(4),
                            ]),
                        ])]),
                    ])]),
                ),
            ],
            expected_hint: Hint::Terminal,
        }],
        outer_ctx: Vec::new(),
    });
}

#[test]
fn ipfix_conforms() {
    // RFC 7011 §3.1 fixed header (16 bytes) plus a single Template Set
    // (id=2), one record: template_id=256, one plain field (IE 8,
    // length 4) and one Enterprise-specific field (IE 12345 with the
    // Enterprise bit set, length 4, enterprise number 99999) — proves
    // the Enterprise-bit shift, not just the common case.
    let mut record = 256u16.to_be_bytes().to_vec();
    record.extend_from_slice(&2u16.to_be_bytes()); // field_count
    record.extend_from_slice(&8u16.to_be_bytes());
    record.extend_from_slice(&4u16.to_be_bytes());
    let enterprise_ie = 12345u16 | 0x8000;
    record.extend_from_slice(&enterprise_ie.to_be_bytes());
    record.extend_from_slice(&4u16.to_be_bytes());
    record.extend_from_slice(&99999u32.to_be_bytes());
    let set_len = 4 + record.len();
    let total_len = 16 + set_len;

    let mut bytes = vec![0, 10];
    bytes.extend_from_slice(&(total_len as u16).to_be_bytes());
    bytes.extend_from_slice(&1_700_000_000u32.to_be_bytes()); // export_time
    bytes.extend_from_slice(&42u32.to_be_bytes()); // sequence
    bytes.extend_from_slice(&7u32.to_be_bytes()); // domain_id
    bytes.extend_from_slice(&2u16.to_be_bytes()); // Set id = 2 (Template)
    bytes.extend_from_slice(&(set_len as u16).to_be_bytes());
    bytes.extend_from_slice(&record);

    run_conformance(&ConformanceCase {
        plugin: Box::new(Ipfix),
        good: vec![GoodPacket {
            expected_header_len: total_len,
            bytes,
            expected_full_fields: vec![
                ("app", Value::from("ipfix")),
                ("version", Value::U64(10)),
                ("length", Value::U64(total_len as u64)),
                ("sequence", Value::U64(42)),
                ("domain_id", Value::U64(7)),
                (
                    "sets",
                    Value::List(vec![Value::List(vec![
                        Value::U64(2),
                        Value::U64(set_len as u64),
                        Value::List(vec![Value::List(vec![
                            Value::U64(256),
                            Value::U64(2),
                            Value::List(vec![
                                Value::List(vec![Value::U64(8), Value::U64(4), Value::U64(0)]),
                                Value::List(vec![
                                    Value::U64(12345),
                                    Value::U64(4),
                                    Value::U64(99999),
                                ]),
                            ]),
                        ])]),
                    ])]),
                ),
            ],
            expected_hint: Hint::Terminal,
        }],
        outer_ctx: Vec::new(),
    });
}

#[test]
fn http_conforms() {
    // A GET request carrying both rollup fields (`method`, `host`) — the
    // canonical shape the 09.1 kit's rule 3 requires. A response (which has
    // `status_code` but no `method`) is covered by http.rs's own fixtures.
    let get = b"GET /index.html HTTP/1.1\r\n\
Host: example.com\r\n\
User-Agent: curl/8.4.0\r\n\
Accept: */*\r\n\
\r\n"
        .to_vec();

    // A POST with a body: header_len must stop at the blank line, leaving
    // the body as unparsed remainder (D7, no body reassembly).
    let post_body = b"{\"a\":\"b\"}";
    let mut post = b"POST /submit HTTP/1.1\r\n\
Host: api.example.com\r\n\
User-Agent: app/1.0\r\n\
Content-Type: application/json\r\n\
Content-Length: 9\r\n\
\r\n"
        .to_vec();
    let post_header_len = post.len();
    post.extend_from_slice(post_body);

    run_conformance(&ConformanceCase {
        plugin: Box::new(Http),
        good: vec![
            GoodPacket {
                expected_header_len: get.len(),
                bytes: get,
                expected_full_fields: vec![
                    ("app", Value::from("http")),
                    ("is_request", Value::Bool(true)),
                    ("method", Value::from("GET")),
                    ("version", Value::from("HTTP/1.1")),
                    ("host", Value::from("example.com")),
                    ("user_agent", Value::from("curl/8.4.0")),
                ],
                expected_hint: Hint::Terminal,
            },
            GoodPacket {
                expected_header_len: post_header_len,
                bytes: post,
                expected_full_fields: vec![
                    ("app", Value::from("http")),
                    ("is_request", Value::Bool(true)),
                    ("method", Value::from("POST")),
                    ("version", Value::from("HTTP/1.1")),
                    ("host", Value::from("api.example.com")),
                    ("user_agent", Value::from("app/1.0")),
                    ("content_type", Value::from("application/json")),
                    ("content_length", Value::U64(9)),
                ],
                expected_hint: Hint::Terminal,
            },
        ],
        outer_ctx: Vec::new(),
    });
}

/// Wraps a `handshake` body in TLS record + handshake framing (RFC 8446
/// §5.1 record, §4 handshake). Record version bytes are `0x0301`.
fn tls_handshake_record(hs_type: u8, body: &[u8]) -> Vec<u8> {
    let mut hs = vec![hs_type];
    let len = body.len();
    hs.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
    hs.extend_from_slice(body);
    let mut rec = vec![22u8, 0x03, 0x01];
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

/// A ClientHello for `example.com` with one cipher suite and a server_name
/// extension — carries both TLS rollup fields (`handshake_type`, `sni`).
fn tls_client_hello() -> Vec<u8> {
    let name = b"example.com";
    // ServerNameList: name_type(0) + name_len(2) + name.
    let mut entry = vec![0u8];
    entry.extend_from_slice(&(name.len() as u16).to_be_bytes());
    entry.extend_from_slice(name);
    let mut sni_data = (entry.len() as u16).to_be_bytes().to_vec();
    sni_data.extend_from_slice(&entry);
    // Extension: server_name (0).
    let mut sni_ext = 0u16.to_be_bytes().to_vec();
    sni_ext.extend_from_slice(&(sni_data.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(&sni_data);

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // legacy_version TLS 1.2
    body.extend_from_slice(&[0x11; 32]); // random
    body.push(0); // session_id length 0
    body.extend_from_slice(&[0x00, 0x02]); // cipher_suites length
    body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
    body.push(1); // compression_methods length
    body.push(0); // null compression
    body.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&sni_ext);

    tls_handshake_record(1, &body)
}

#[test]
fn tls_conforms() {
    let hello = tls_client_hello();
    run_conformance(&ConformanceCase {
        plugin: Box::new(Tls),
        good: vec![GoodPacket {
            expected_header_len: hello.len(),
            bytes: hello,
            expected_full_fields: vec![
                ("app", Value::from("tls")),
                ("content_type", Value::U64(22)),
                ("record_version", Value::U64(0x0301)),
                ("handshake_type", Value::U64(1)),
                ("cipher_suites", Value::List(vec![Value::U64(0x1301)])),
                ("sni", Value::from("example.com")),
            ],
            expected_hint: Hint::Terminal,
        }],
        outer_ctx: Vec::new(),
    });
}

#[test]
fn mpls_conforms() {
    run_conformance(&ConformanceCase {
        plugin: Box::new(Mpls),
        good: vec![
            // RFC 3032: single entry — label 16 (first unreserved), TC 5,
            // bottom of stack, TTL 64.
            GoodPacket {
                bytes: vec![0x00, 0x01, 0x0B, 0x40],
                expected_header_len: 4,
                expected_full_fields: vec![
                    ("label", Value::U64(16)),
                    ("tc", Value::U64(5)),
                    ("ttl", Value::U64(64)),
                    ("stack_depth", Value::U64(1)),
                    ("labels", Value::List(vec![Value::U64(16)])),
                ],
                expected_hint: Hint::Unknown,
            },
            // Transport label 100 over service label 200 (S only on the
            // bottom entry): top-entry fields, both labels listed.
            GoodPacket {
                bytes: vec![0x00, 0x06, 0x40, 0xFF, 0x00, 0x0C, 0x81, 0xFF],
                expected_header_len: 8,
                expected_full_fields: vec![
                    ("label", Value::U64(100)),
                    ("tc", Value::U64(0)),
                    ("ttl", Value::U64(255)),
                    ("stack_depth", Value::U64(2)),
                    (
                        "labels",
                        Value::List(vec![Value::U64(100), Value::U64(200)]),
                    ),
                ],
                expected_hint: Hint::Unknown,
            },
            // Transport label over IPv4 Explicit NULL (RFC 3032 §2.1 /
            // RFC 4182): the bottom label names the payload protocol.
            GoodPacket {
                bytes: vec![0x00, 0x06, 0x40, 0xFF, 0x00, 0x00, 0x01, 0xFF],
                expected_header_len: 8,
                expected_full_fields: vec![
                    ("label", Value::U64(100)),
                    ("tc", Value::U64(0)),
                    ("ttl", Value::U64(255)),
                    ("stack_depth", Value::U64(2)),
                    ("labels", Value::List(vec![Value::U64(100), Value::U64(0)])),
                ],
                expected_hint: Hint::ByProtocol("ipv4"),
            },
        ],
        outer_ctx: Vec::new(),
    });
}

#[test]
fn bfd_conforms() {
    // RFC 5880 §4.1 control packet: state Up (3), no flags, detect mult 3,
    // discriminator pair 7/9, 100ms tx/rx intervals, no echo.
    let mut bytes = vec![0x20, 0xC0, 3, 24];
    bytes.extend_from_slice(&7u32.to_be_bytes());
    bytes.extend_from_slice(&9u32.to_be_bytes());
    bytes.extend_from_slice(&100_000u32.to_be_bytes());
    bytes.extend_from_slice(&100_000u32.to_be_bytes());
    bytes.extend_from_slice(&0u32.to_be_bytes());
    run_conformance(&ConformanceCase {
        plugin: Box::new(Bfd),
        good: vec![GoodPacket {
            bytes,
            expected_header_len: 24,
            expected_full_fields: vec![
                ("my_discriminator", Value::U64(7)),
                ("your_discriminator", Value::U64(9)),
                ("version", Value::U64(1)),
                ("diag", Value::U64(0)),
                ("state", Value::U64(3)),
                ("flags", Value::U64(0)),
                ("detect_mult", Value::U64(3)),
                ("length", Value::U64(24)),
                ("desired_min_tx", Value::U64(100_000)),
                ("required_min_rx", Value::U64(100_000)),
                ("required_min_echo_rx", Value::U64(0)),
            ],
            expected_hint: Hint::Terminal,
        }],
        outer_ctx: Vec::new(),
    });
}

#[test]
fn rocev2_conforms() {
    // IBTA BTH: RC RDMA WRITE First (opcode 6), SE set, tver 0, default
    // pkey, dest QP 0xD2, ACK requested, PSN 0x123456.
    run_conformance(&ConformanceCase {
        plugin: Box::new(Rocev2),
        good: vec![GoodPacket {
            bytes: vec![
                6, 0x80, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0xD2, 0x80, 0x12, 0x34, 0x56,
            ],
            expected_header_len: 12,
            expected_full_fields: vec![
                ("dest_qp", Value::U64(0xD2)),
                ("opcode", Value::U64(6)),
                ("pkey", Value::U64(0xFFFF)),
                ("psn", Value::U64(0x123456)),
                ("pad_count", Value::U64(0)),
                ("solicited", Value::Bool(true)),
                ("mig_req", Value::Bool(false)),
                ("ack_req", Value::Bool(true)),
            ],
            expected_hint: Hint::Terminal,
        }],
        outer_ctx: Vec::new(),
    });
}

#[test]
fn ptp_conforms() {
    // IEEE 1588-2008 §13.3 Sync (type 0), domain 0, twoStepFlag, sequence
    // 0x1234, logMessageInterval -1, 10-byte originTimestamp body.
    let mut bytes = vec![0x00, 0x02];
    bytes.extend_from_slice(&44u16.to_be_bytes());
    bytes.extend_from_slice(&[0, 0]); // domain, reserved
    bytes.extend_from_slice(&0x0200u16.to_be_bytes()); // flags
    bytes.extend_from_slice(&0u64.to_be_bytes()); // correction
    bytes.extend_from_slice(&0u32.to_be_bytes()); // reserved
    bytes.extend_from_slice(&[0x00, 0x1B, 0x19, 0xFF, 0xFE, 0x00, 0x01, 0x02]);
    bytes.extend_from_slice(&1u16.to_be_bytes()); // source port id
    bytes.extend_from_slice(&0x1234u16.to_be_bytes());
    bytes.push(0); // control
    bytes.push(0xFF); // logMessageInterval -1
    bytes.extend_from_slice(&[0u8; 10]); // originTimestamp
    run_conformance(&ConformanceCase {
        plugin: Box::new(Ptp),
        good: vec![GoodPacket {
            bytes,
            expected_header_len: 44,
            expected_full_fields: vec![
                ("domain", Value::U64(0)),
                ("msg_type", Value::U64(0)),
                ("version", Value::U64(2)),
                ("sequence_id", Value::U64(0x1234)),
                (
                    "clock_identity",
                    Value::from(&[0x00, 0x1B, 0x19, 0xFF, 0xFE, 0x00, 0x01, 0x02][..]),
                ),
                ("source_port_id", Value::U64(1)),
                ("message_length", Value::U64(44)),
                ("flags", Value::U64(0x0200)),
                ("correction", Value::U64(0)),
                ("log_message_interval", Value::I64(-1)),
            ],
            expected_hint: Hint::Terminal,
        }],
        outer_ctx: Vec::new(),
    });
}

#[test]
fn erspan_conforms() {
    run_conformance(&ConformanceCase {
        plugin: Box::new(Erspan),
        good: vec![
            // Type II: VLAN 100, CoS 3, session 42, index 7.
            GoodPacket {
                bytes: vec![0x10, 0x64, 0x60, 0x2A, 0x00, 0x00, 0x00, 0x07],
                expected_header_len: 8,
                expected_full_fields: vec![
                    ("session_id", Value::U64(42)),
                    ("version", Value::U64(1)),
                    ("vlan", Value::U64(100)),
                    ("cos", Value::U64(3)),
                    ("index", Value::U64(7)),
                    ("truncated", Value::Bool(false)),
                ],
                expected_hint: Hint::ByProtocol("ethernet"),
            },
            // Type III: hardware timestamp, SGT 5, frame type Ethernet,
            // no platform subheader.
            GoodPacket {
                bytes: vec![
                    0x20, 0x64, 0x60, 0x2A, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x05, 0x00, 0x00,
                ],
                expected_header_len: 12,
                expected_full_fields: vec![
                    ("session_id", Value::U64(42)),
                    ("version", Value::U64(2)),
                    ("vlan", Value::U64(100)),
                    ("cos", Value::U64(3)),
                    ("timestamp", Value::U64(0xDEAD_BEEF)),
                    ("sgt", Value::U64(5)),
                    ("frame_type", Value::U64(0)),
                    ("truncated", Value::Bool(false)),
                ],
                expected_hint: Hint::ByProtocol("ethernet"),
            },
        ],
        outer_ctx: Vec::new(),
    });
}
