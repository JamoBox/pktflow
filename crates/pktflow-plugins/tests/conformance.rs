//! Every reference plugin runs the 09.1 conformance kit here — one
//! `ConformanceCase` per plugin. Add yours when you copy template.rs.

mod kit;

use pktflow_core::{Hint, RouteId, Value};
use pktflow_plugins::ethernet::Ethernet;
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
