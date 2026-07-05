//! Shared fixtures and harness helpers for the CLI integration tests
//! (the 09.2 named fixtures, built with pktflow-testkit).

#![allow(dead_code)] // each test binary uses a subset

pub mod expected;
pub mod named_fixtures;
pub mod schema;

use std::path::PathBuf;
use std::process::Output;

use pktflow_testkit::{flags, CaptureBuilder, PacketBuilder};

pub const MAC_A: &str = "aa:bb:cc:dd:ee:01";
pub const MAC_B: &str = "aa:bb:cc:dd:ee:02";
pub const MAC_C: &str = "aa:bb:cc:dd:ee:03";
pub const MAC_D: &str = "aa:bb:cc:dd:ee:04";

pub fn pktflow(args: &[&str]) -> Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_pktflow"))
        .args(args)
        .output()
        .expect("spawn pktflow")
}

pub fn tmp_pcap(name: &str, capture: &CaptureBuilder) -> PathBuf {
    let path =
        std::env::temp_dir().join(format!("pktflow-view-{}-{name}.pcap", std::process::id()));
    capture.write_pcap(&path);
    path
}

/// Compare stdout to a checked-in golden; `UPDATE_GOLDENS=1` rewrites.
pub fn assert_golden(actual: &str, golden: &str) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(golden);
    if std::env::var_os("UPDATE_GOLDENS").is_some() {
        std::fs::write(&path, actual).expect("write golden");
        return;
    }
    let expected = std::fs::read_to_string(&path).expect("golden file (UPDATE_GOLDENS=1 seeds)");
    assert_eq!(
        actual, expected,
        "{golden} drifted — if deliberate, rerun with UPDATE_GOLDENS=1"
    );
}

/// bidi TCP session (handshake → data → teardown) plus a DNS exchange:
/// the tree fixture (09.2 `bidi_tcp_session` + `dns_over_udp_session`).
pub fn tree_fixture() -> CaptureBuilder {
    let client = "10.0.0.5";
    let server = "93.184.216.34";
    let resolver = "10.0.0.1";
    CaptureBuilder::new()
        // DNS lookup first.
        .packet(
            PacketBuilder::at_secs(100)
                .eth(MAC_A, MAC_B)
                .ipv4(client, resolver)
                .udp(34567, 53)
                .dns_query(0x1a2b, "example.com"),
        )
        .packet(
            PacketBuilder::at_secs(100)
                .eth(MAC_B, MAC_A)
                .ipv4(resolver, client)
                .udp(53, 34567)
                .dns_response(0x1a2b, "example.com", server),
        )
        // TCP handshake, data, teardown.
        .packet(
            PacketBuilder::at_secs(101)
                .eth(MAC_A, MAC_B)
                .ipv4(client, server)
                .tcp(52341, 443, flags::SYN, 1),
        )
        .packet(
            PacketBuilder::at_secs(101)
                .eth(MAC_B, MAC_A)
                .ipv4(server, client)
                .tcp_ack(443, 52341, flags::SYN | flags::ACK, 900, 2),
        )
        .packet(
            PacketBuilder::at_secs(101)
                .eth(MAC_A, MAC_B)
                .ipv4(client, server)
                .tcp_ack(52341, 443, flags::ACK, 2, 901),
        )
        .packet(
            PacketBuilder::at_secs(102)
                .eth(MAC_A, MAC_B)
                .ipv4(client, server)
                .tcp_ack(52341, 443, flags::PSH | flags::ACK, 2, 901)
                .payload(120),
        )
        .packet(
            PacketBuilder::at_secs(103)
                .eth(MAC_B, MAC_A)
                .ipv4(server, client)
                .tcp_ack(443, 52341, flags::PSH | flags::ACK, 901, 122)
                .payload(400),
        )
        .packet(
            PacketBuilder::at_secs(104)
                .eth(MAC_A, MAC_B)
                .ipv4(client, server)
                .tcp_ack(52341, 443, flags::FIN | flags::ACK, 122, 1301),
        )
        .packet(
            PacketBuilder::at_secs(104)
                .eth(MAC_B, MAC_A)
                .ipv4(server, client)
                .tcp_ack(443, 52341, flags::FIN | flags::ACK, 1301, 123),
        )
}

/// GRE tunnel with an inner TCP flow, both directions through the same
/// outer tunnel (09.2 `gre_nested`).
pub fn gre_fixture() -> CaptureBuilder {
    CaptureBuilder::new()
        .packet(
            PacketBuilder::at_secs(200)
                .eth(MAC_A, MAC_B)
                .ipv4("192.168.1.1", "192.168.1.2")
                .gre()
                .ipv4("10.0.0.5", "10.0.0.9")
                .tcp(40000, 443, flags::SYN, 1),
        )
        .packet(
            PacketBuilder::at_secs(200)
                .eth(MAC_B, MAC_A)
                .ipv4("192.168.1.2", "192.168.1.1")
                .gre()
                .ipv4("10.0.0.9", "10.0.0.5")
                .tcp_ack(443, 40000, flags::SYN | flags::ACK, 500, 2),
        )
        .packet(
            PacketBuilder::at_secs(201)
                .eth(MAC_A, MAC_B)
                .ipv4("192.168.1.1", "192.168.1.2")
                .gre()
                .ipv4("10.0.0.5", "10.0.0.9")
                .tcp_ack(40000, 443, flags::ACK, 2, 501)
                .payload(64),
        )
}

/// The same IP pair under two MAC pairs (09.2 `dual_parent_ip`, D10).
pub fn dual_parent_fixture() -> CaptureBuilder {
    let mut capture = CaptureBuilder::new();
    for (secs, src_mac, dst_mac) in [(300, MAC_A, MAC_B), (301, MAC_C, MAC_D)] {
        capture = capture.packet(
            PacketBuilder::at_secs(secs)
                .eth(src_mac, dst_mac)
                .ipv4("10.0.0.5", "10.0.0.9")
                .udp(40001, 40002)
                .payload(24),
        );
    }
    capture
}

/// Rollup-cap stress (09.2 `malformed_zoo` cousin): 70 distinct DNS
/// qnames on one 5-tuple (accumulate overflow at 64) and a 30-point TCP
/// flag series (display elision beyond 20).
pub fn overflow_fixture() -> CaptureBuilder {
    let mut capture = CaptureBuilder::new();
    for i in 0..70u16 {
        capture = capture.packet(
            PacketBuilder::at_secs(400 + u64::from(i))
                .eth(MAC_A, MAC_B)
                .ipv4("10.0.0.5", "10.0.0.1")
                .udp(34567, 53)
                .dns_query(i, &format!("host-{i}.example.com")),
        );
    }
    for i in 0..30u32 {
        capture = capture.packet(
            PacketBuilder::at_secs(500 + u64::from(i))
                .eth(MAC_A, MAC_B)
                .ipv4("10.0.0.5", "10.0.0.9")
                .tcp_ack(41000, 8080, flags::PSH | flags::ACK, i, i),
        );
    }
    capture
}
