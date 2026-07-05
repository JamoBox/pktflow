//! 09.2 named synthetic fixtures: each function returns a `CaptureBuilder`
//! for a specific proof (see `specs/09-validation/02-fixtures.md`'s
//! table). Paired `ExpectedStreams` trees live with each fixture's test
//! in `tests/fixture_corpus.rs` — the pairing is the point, not the
//! fixture alone.

use std::time::{Duration, SystemTime};

use pktflow_testkit::{flags, CaptureBuilder, PacketBuilder};

use super::{MAC_A, MAC_B};

const MAC_C: &str = "aa:bb:cc:dd:ee:05";
const MAC_D: &str = "aa:bb:cc:dd:ee:06";

/// TCP handshake → data → teardown, one conversation (folding, lifecycle,
/// initiator: 05.x, 06.4).
pub fn bidi_tcp_session() -> CaptureBuilder {
    let client = "10.0.0.5";
    let server = "93.184.216.34";
    CaptureBuilder::new()
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

/// A WireGuard-shaped UDP flow to an unclaimed port: proves the gate
/// (03.4) — no plugin phantom-claims the encrypted payload.
pub fn encrypted_udp_no_phantom() -> CaptureBuilder {
    CaptureBuilder::new()
        .packet(
            PacketBuilder::at_secs(600)
                .eth(MAC_A, MAC_B)
                .ipv4("10.0.0.5", "10.0.0.9")
                .udp(51820, 51820)
                .payload(148),
        )
        .packet(
            PacketBuilder::at_secs(601)
                .eth(MAC_B, MAC_A)
                .ipv4("10.0.0.9", "10.0.0.5")
                .udp(51820, 51820)
                .payload(92),
        )
}

/// VXLAN overlay: outer VTEP-to-VTEP UDP/VXLAN wrapping an inner
/// Ethernet+IP+TCP conversation (06.5 tunnel hierarchy).
pub fn vxlan_nested() -> CaptureBuilder {
    let inner_a = "aa:bb:cc:dd:ee:11";
    let inner_b = "aa:bb:cc:dd:ee:12";
    CaptureBuilder::new()
        .packet(
            PacketBuilder::at_secs(700)
                .eth(MAC_A, MAC_B)
                .ipv4("172.16.0.1", "172.16.0.2")
                .udp(52000, 4789)
                .vxlan(5000)
                .eth(inner_a, inner_b)
                .ipv4("10.1.1.5", "10.1.1.9")
                .tcp(50000, 80, flags::SYN, 1),
        )
        .packet(
            PacketBuilder::at_secs(700)
                .eth(MAC_B, MAC_A)
                .ipv4("172.16.0.2", "172.16.0.1")
                .udp(4789, 52000)
                .vxlan(5000)
                .eth(inner_b, inner_a)
                .ipv4("10.1.1.9", "10.1.1.5")
                .tcp_ack(80, 50000, flags::SYN | flags::ACK, 500, 2),
        )
}

/// The same IP pair under two distinct MAC pairs: proves parent-scoped
/// nesting (D10) — two separate `ipv4` streams, not one merged stream.
pub fn dual_parent_ip() -> CaptureBuilder {
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

/// A DNS query/response over UDP (app-stream pattern + qname rollup,
/// 06.6).
pub fn dns_over_udp_session() -> CaptureBuilder {
    CaptureBuilder::new()
        .packet(
            PacketBuilder::at_secs(800)
                .eth(MAC_A, MAC_B)
                .ipv4("10.0.0.5", "10.0.0.1")
                .udp(34567, 53)
                .dns_query(0x1a2b, "example.com"),
        )
        .packet(
            PacketBuilder::at_secs(800)
                .eth(MAC_B, MAC_A)
                .ipv4("10.0.0.1", "10.0.0.5")
                .udp(53, 34567)
                .dns_response(0x1a2b, "example.com", "93.184.216.34"),
        )
}

/// A full DHCP DISCOVER/OFFER/REQUEST/ACK exchange: proves the
/// order-sensitive `msg_type` series rollup (05.4).
pub fn dhcp_dora() -> CaptureBuilder {
    let client_mac = "aa:bb:cc:dd:ee:50";
    let client_ip = "10.0.0.50";
    let server_ip = "10.0.0.1";
    let xid = 0xAABB_CCDDu32;
    CaptureBuilder::new()
        .packet(
            PacketBuilder::at_secs(900)
                .eth(MAC_A, MAC_B)
                .ipv4(client_ip, server_ip)
                .udp(68, 67)
                .dhcp(1, 1, xid, client_mac, &[]),
        )
        .packet(
            PacketBuilder::at_secs(900)
                .eth(MAC_B, MAC_A)
                .ipv4(server_ip, client_ip)
                .udp(67, 68)
                .dhcp(2, 2, xid, client_mac, &[(54, &[10, 0, 0, 1])]),
        )
        .packet(
            PacketBuilder::at_secs(901)
                .eth(MAC_A, MAC_B)
                .ipv4(client_ip, server_ip)
                .udp(68, 67)
                .dhcp(
                    1,
                    3,
                    xid,
                    client_mac,
                    &[(50, &[10, 0, 0, 50]), (54, &[10, 0, 0, 1])],
                ),
        )
        .packet(
            PacketBuilder::at_secs(901)
                .eth(MAC_B, MAC_A)
                .ipv4(server_ip, client_ip)
                .udp(67, 68)
                .dhcp(2, 5, xid, client_mac, &[(54, &[10, 0, 0, 1])]),
        )
}

/// One stream, then 100 seconds of unrelated traffic on a different
/// flow: enough packet-time clock advance to cross a short idle timeout
/// (D2, 05.6).
pub fn idle_eviction() -> CaptureBuilder {
    CaptureBuilder::new()
        .packet(
            PacketBuilder::at_secs(0)
                .eth(MAC_A, MAC_B)
                .ipv4("10.0.0.5", "10.0.0.9")
                .udp(40001, 40002)
                .payload(8),
        )
        .packet(
            PacketBuilder::at_secs(100)
                .eth(MAC_C, MAC_D)
                .ipv4("10.0.0.6", "10.0.0.10")
                .udp(50001, 50002)
                .payload(8),
        )
}

/// Three independent eth-only leaf streams (unclaimed ethertype payload,
/// so each stops right after `ethernet` with no children) — enough to
/// pressure a `max_streams: 2` cap into an LRU eviction (D2, 05.6).
pub fn lru_pressure() -> CaptureBuilder {
    CaptureBuilder::new()
        .packet(PacketBuilder::at_secs(0).eth(MAC_A, MAC_B).payload(4))
        .packet(PacketBuilder::at_secs(1).eth(MAC_C, MAC_D).payload(4))
        .packet(
            PacketBuilder::at_secs(2)
                .eth("aa:bb:cc:dd:ee:07", "aa:bb:cc:dd:ee:08")
                .payload(4),
        )
}

/// A QinQ stack (802.1ad S-tag + 802.1Q C-tag): proves innermost-wins
/// context (01.4, 06.2) — vlan is identity-less, so the stream tree
/// looks like a plain `eth -> ipv4 -> udp`; the interesting assertion is
/// on the dissected layer stack itself (two `vlan` `LayerRecord`s, outer
/// vid 200 then inner vid 100).
pub fn qinq_stack() -> CaptureBuilder {
    CaptureBuilder::new().packet(
        PacketBuilder::at_secs(1000)
            .eth(MAC_A, MAC_B)
            .vlan_stag(200)
            .vlan(100)
            .ipv4("10.0.0.5", "10.0.0.9")
            .udp(40010, 40020)
            .payload(16),
    )
}

fn ts(secs: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
}

/// A mixed bag of malformed/edge-case packets — truncation at the very
/// first layer, a transport header truncated mid-parse, an invalid IHL,
/// a non-first IPv4 fragment, and a self-referential DNS compression
/// pointer — proving the whole pipeline stays panic-free and classifies
/// each cleanly (09.1's per-plugin kit already proves this per-plugin in
/// isolation; this fixture proves it end-to-end on one realistic-looking
/// capture, for 09.3's e2e suite).
pub fn malformed_zoo() -> CaptureBuilder {
    let mut cap = CaptureBuilder::new();

    // 1. Truncated at the very first layer: fewer than 14 eth bytes.
    cap = cap.raw_packet(ts(1100), vec![0xAA; 6]);

    // 2. Truncated TCP header: IP claims protocol 6 (TCP) but only 8
    //    bytes follow it (TCP's minimum header is 20).
    let (meta, bytes) = PacketBuilder::at_secs(1101)
        .eth(MAC_A, MAC_B)
        .ipv4("10.0.0.5", "10.0.0.9")
        .bytes_claiming(6, vec![0; 8])
        .build();
    cap = cap.raw_packet(meta.timestamp, bytes);

    // 3. Bad IHL: patch the version/IHL byte to declare IHL=1 (4 bytes),
    //    below the mandatory 20-byte minimum.
    let (meta, mut bytes) = PacketBuilder::at_secs(1102)
        .eth(MAC_A, MAC_B)
        .ipv4("10.0.0.5", "10.0.0.9")
        .udp(1000, 2000)
        .payload(4)
        .build();
    bytes[14] = 0x41;
    cap = cap.raw_packet(meta.timestamp, bytes);

    // 4. Non-first IPv4 fragment: nonzero fragment offset, MF unset — a
    //    clean "no transport header here" stop, not a misparse.
    let (meta, mut bytes) = PacketBuilder::at_secs(1103)
        .eth(MAC_A, MAC_B)
        .ipv4("10.0.0.5", "10.0.0.9")
        .tcp(1000, 2000, flags::SYN, 1)
        .build();
    bytes[20] = 0x00;
    bytes[21] = 0x64; // frag_offset = 100 (x8 bytes), MF = 0
    cap = cap.raw_packet(meta.timestamp, bytes);

    // 5. DNS pointer bomb: the question name is a compression pointer
    //    that references its own offset.
    let mut dns = Vec::new();
    dns.extend_from_slice(&0x1234u16.to_be_bytes());
    dns.extend_from_slice(&0x0100u16.to_be_bytes());
    dns.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    dns.extend_from_slice(&[0xC0, 0x0C]); // pointer to offset 12 (itself)
    dns.extend_from_slice(&[0, 1, 0, 1]);
    cap.packet(
        PacketBuilder::at_secs(1104)
            .eth(MAC_A, MAC_B)
            .ipv4("10.0.0.5", "10.0.0.1")
            .udp(34567, 53)
            .bytes(dns),
    )
}

/// One packet per `StopReason` class this pipeline can actually reach
/// from realistic-looking bytes (04.3, 08.4 goldens): `Clean`
/// (ordinary packet), `UnknownPayload` (unclaimed UDP port),
/// `Malformed` (truncated header), `Suspicious` needs a self-nesting
/// depth-cap trip, which the `template` plugin's PKTT-in-PKTT space
/// (06.1) is the only reachable source of in the reference set — left
/// to that plugin's own tests since it needs `--entry`, not a plain
/// capture.
pub fn mixed_stop_reasons() -> CaptureBuilder {
    CaptureBuilder::new()
        // Clean: a DNS query parses all the way through.
        .packet(
            PacketBuilder::at_secs(1200)
                .eth(MAC_A, MAC_B)
                .ipv4("10.0.0.5", "10.0.0.1")
                .udp(34567, 53)
                .dns_query(0x2222, "example.net"),
        )
        // UnknownPayload: nothing claims port 51820.
        .packet(
            PacketBuilder::at_secs(1201)
                .eth(MAC_A, MAC_B)
                .ipv4("10.0.0.5", "10.0.0.9")
                .udp(51820, 51820)
                .payload(16),
        )
        // Malformed: fewer than 14 bytes, truncated before a full eth header.
        .raw_packet(ts(1202), vec![0xAA; 6])
}
