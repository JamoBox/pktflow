//! 08.2 golden tests: tree and flat views, the tunnel chain, the
//! `--merged` fold, and the `--watch` smoke — text output is a contract;
//! goldens are updated deliberately (`UPDATE_GOLDENS=1`).

use std::path::PathBuf;
use std::process::Output;

use pktflow_testkit::{flags, CaptureBuilder, PacketBuilder};

const MAC_A: &str = "aa:bb:cc:dd:ee:01";
const MAC_B: &str = "aa:bb:cc:dd:ee:02";
const MAC_C: &str = "aa:bb:cc:dd:ee:03";
const MAC_D: &str = "aa:bb:cc:dd:ee:04";

fn pktflow(args: &[&str]) -> Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_pktflow"))
        .args(args)
        .output()
        .expect("spawn pktflow")
}

fn tmp_pcap(name: &str, capture: &CaptureBuilder) -> PathBuf {
    let path =
        std::env::temp_dir().join(format!("pktflow-view-{}-{name}.pcap", std::process::id()));
    capture.write_pcap(&path);
    path
}

/// Compare stdout to a checked-in golden; `UPDATE_GOLDENS=1` rewrites.
fn assert_golden(actual: &str, golden: &str) {
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
fn tree_fixture() -> CaptureBuilder {
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
fn gre_fixture() -> CaptureBuilder {
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
fn dual_parent_fixture() -> CaptureBuilder {
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

#[test]
fn tree_view_matches_golden() {
    if cfg!(windows) {
        return; // Npcap SDK only on Windows CI
    }
    let path = tmp_pcap("tree", &tree_fixture());
    let out = pktflow(&["streams", "-r", &path.to_string_lossy()]);
    assert_eq!(out.status.code(), Some(0));
    assert_golden(&String::from_utf8_lossy(&out.stdout), "streams-tree.txt");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn flat_layer_view_matches_golden() {
    if cfg!(windows) {
        return;
    }
    let path = tmp_pcap("flat", &tree_fixture());
    let out = pktflow(&["streams", "-r", &path.to_string_lossy(), "--layer", "tcp"]);
    assert_eq!(out.status.code(), Some(0));
    assert_golden(
        &String::from_utf8_lossy(&out.stdout),
        "streams-flat-tcp.txt",
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn tunnel_fixture_renders_the_full_nested_chain() {
    if cfg!(windows) {
        return;
    }
    let path = tmp_pcap("gre", &gre_fixture());
    let out = pktflow(&["streams", "-r", &path.to_string_lossy()]);
    assert_eq!(out.status.code(), Some(0));
    let body = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_golden(&body, "streams-gre.txt");
    // The full chain is visible as nested lines, in order.
    let chain = ["ethernet", "ipv4", "gre", "ipv4", "tcp"];
    let mut pos = 0;
    for proto in chain {
        let line = body.lines().skip(pos).position(|l| {
            l.trim_start_matches(['│', '├', '└', '─', ' '])
                .starts_with(proto)
        });
        let line = line.unwrap_or_else(|| panic!("{proto} missing from chain:\n{body}"));
        pos += line + 1;
    }
    let _ = std::fs::remove_file(&path);
}

#[test]
fn merged_fold_collapses_dual_parents() {
    if cfg!(windows) {
        return;
    }
    let path = tmp_pcap("dual", &dual_parent_fixture());
    let p = path.to_string_lossy();

    // Unmerged: two ipv4 nodes (one per MAC-pair parent).
    let out = pktflow(&["streams", "-r", p.as_ref(), "--layer", "ipv4"]);
    assert_eq!(out.status.code(), Some(0));
    let flat = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_eq!(flat.lines().count(), 2, "two nodes unmerged:\n{flat}");

    // Merged: one row folding both nodes.
    let out = pktflow(&["streams", "-r", p.as_ref(), "--layer", "ipv4", "--merged"]);
    assert_eq!(out.status.code(), Some(0));
    let merged = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_golden(&merged, "streams-merged-ipv4.txt");
    assert_eq!(merged.lines().count(), 1, "one folded row:\n{merged}");
    assert!(merged.contains("nodes"), "folded node ids listed");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn watch_smoke_final_frame_matches_the_plain_tree() {
    if cfg!(windows) {
        return;
    }
    let path = tmp_pcap("watch", &tree_fixture());
    let p = path.to_string_lossy();

    let plain = pktflow(&["streams", "-r", p.as_ref()]);
    assert_eq!(plain.status.code(), Some(0));
    let plain_tree = String::from_utf8_lossy(&plain.stdout).into_owned();

    // Paced replay under --watch: no panic, and the final frame's tree
    // matches the non-watch output exactly.
    let watch = pktflow(&["streams", "-r", p.as_ref(), "--watch", "--pace-ms", "20"]);
    assert_eq!(
        watch.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&watch.stderr)
    );
    let out = String::from_utf8_lossy(&watch.stdout).into_owned();
    let final_frame = out
        .rsplit("\x1b[2J\x1b[H")
        .next()
        .expect("at least the final frame");
    let (tree, footer) = final_frame
        .rsplit_once("\nwatching ")
        .expect("footer present");
    assert_eq!(
        format!("{tree}\n"),
        format!("{plain_tree}\n"),
        "final frame tree"
    );
    assert!(
        footer.contains("packets 9"),
        "running totals in footer: {footer}"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn watch_rejects_json_for_now() {
    let out = pktflow(&["streams", "-r", "f.pcap", "--watch", "--format", "json"]);
    assert_eq!(out.status.code(), Some(2), "NDJSON events arrive with 08.5");
}
