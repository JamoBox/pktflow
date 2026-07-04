//! 08.4 golden tests: base/-v/-vv rendering, the --depth keys reduction,
//! and the throughput sanity check (packets --no-streams must not be
//! slower than the streams lens).

mod support;

use std::time::Instant;

use support::{assert_golden, pktflow, tmp_pcap, tree_fixture};

fn stdout(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// A mixed fixture with an unclaimed-port packet and a truncated packet
/// (08.4's required cases): a UDP datagram to an unassigned port with a
/// too-short header, alongside the plain TCP/DNS traffic.
fn mixed_stop_reasons_fixture() -> pktflow_testkit::CaptureBuilder {
    use pktflow_testkit::{flags, CaptureBuilder, PacketBuilder};
    CaptureBuilder::new()
        .packet(
            PacketBuilder::at_secs(600)
                .eth(support::MAC_A, support::MAC_B)
                .ipv4("10.0.0.5", "93.184.216.34")
                .tcp(52341, 443, flags::SYN, 1),
        )
        // Unclaimed UDP port: a clean "unknown payload" stop.
        .packet(
            PacketBuilder::at_secs(601)
                .eth(support::MAC_A, support::MAC_B)
                .ipv4("10.0.0.5", "10.0.0.9")
                .udp(40000, 51820)
                .payload(8),
        )
        // Truncated TCP header (only 8 of 20 bytes): a malformed stop.
        .packet(
            PacketBuilder::at_secs(602)
                .eth(support::MAC_A, support::MAC_B)
                .ipv4("10.0.0.5", "93.184.216.34")
                .bytes_claiming(6, vec![0x00, 0x50, 0x01, 0xBB, 0x00, 0x00, 0x00, 0x01]),
        )
}

#[test]
fn base_view_matches_golden() {
    if cfg!(windows) {
        return; // Npcap SDK only on Windows CI
    }
    let path = tmp_pcap("packets-base", &mixed_stop_reasons_fixture());
    let out = pktflow(&["packets", "-r", &path.to_string_lossy()]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let body = stdout(&out);
    assert_golden(&body, "packets-base.txt");
    assert!(body.contains("[unclaimed:"), "unclaimed port rendered");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn verbose_view_matches_golden() {
    if cfg!(windows) {
        return;
    }
    let path = tmp_pcap("packets-v", &mixed_stop_reasons_fixture());
    let out = pktflow(&["packets", "-r", &path.to_string_lossy(), "-v"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let body = stdout(&out);
    assert_golden(&body, "packets-v.txt");
    assert!(body.contains("@0 hdr"), "offsets and header lengths shown");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn double_verbose_view_matches_golden_with_hex_and_truncation() {
    if cfg!(windows) {
        return;
    }
    let path = tmp_pcap("packets-vv", &mixed_stop_reasons_fixture());
    let out = pktflow(&["packets", "-r", &path.to_string_lossy(), "-vv"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let body = stdout(&out);
    assert_golden(&body, "packets-vv.txt");
    assert!(body.contains("unparsed bytes"), "hex dump present");
    assert!(
        body.contains("[truncated: needed"),
        "truncated packet's exact shortfall rendered: {body}"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn depth_keys_visibly_reduces_verbose_field_blocks() {
    if cfg!(windows) {
        return;
    }
    let path = tmp_pcap("packets-depth", &tree_fixture());
    let p = path.to_string_lossy();

    let full = pktflow(&["packets", "-r", p.as_ref(), "-v"]);
    assert_eq!(full.status.code(), Some(0));
    let full_body = stdout(&full);

    let keys = pktflow(&["packets", "-r", p.as_ref(), "-v", "--depth", "keys"]);
    assert_eq!(keys.status.code(), Some(0));
    let keys_body = stdout(&keys);

    assert!(
        keys_body.len() < full_body.len(),
        "keys depth is visibly smaller: {} vs {} bytes",
        keys_body.len(),
        full_body.len()
    );
    // Structural-only fields (ttl, flags, protocol) drop out at Keys.
    assert!(full_body.contains("ttl="), "structural has ttl");
    assert!(!keys_body.contains("ttl="), "keys omits ttl");
    let _ = std::fs::remove_file(&path);
}

/// A large-ish synthetic capture: enough packets that per-packet
/// overhead dominates process-startup noise in the throughput check.
fn bulk_fixture(n: u32) -> pktflow_testkit::CaptureBuilder {
    use pktflow_testkit::PacketBuilder;
    let mut capture = pktflow_testkit::CaptureBuilder::new();
    for i in 0..n {
        capture = capture.packet(
            PacketBuilder::at_secs(u64::from(i))
                .eth(support::MAC_A, support::MAC_B)
                .ipv4("10.0.0.5", "93.184.216.34")
                .tcp(
                    50000 + u16::try_from(i % 1000).expect("i % 1000 fits u16"),
                    443,
                    pktflow_testkit::flags::ACK,
                    i,
                )
                .payload(32),
        );
    }
    capture
}

#[test]
fn no_streams_is_not_slower_than_streams_mode() {
    if cfg!(windows) {
        return;
    }
    let path = tmp_pcap("packets-throughput", &bulk_fixture(20_000));
    let p = path.to_string_lossy();

    // Best-of-5 for each to smooth scheduler noise; the cheap lens must
    // not be slower than the streams lens, not "usually about the same".
    // A 25% tolerance absorbs process-startup jitter without masking a
    // real regression (packets mode skips aggregation entirely; it has
    // no structural reason to be slower than streams mode, which does
    // full flow-key/rollup/lifecycle work on every packet).
    let best_of = |args: &[&str]| -> std::time::Duration {
        (0..5)
            .map(|_| {
                let start = Instant::now();
                let out = pktflow(args);
                assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
                start.elapsed()
            })
            .min()
            .expect("5 runs")
    };

    let streams_time = best_of(&["streams", "-r", p.as_ref()]);
    let packets_time = best_of(&["packets", "-r", p.as_ref(), "--no-streams"]);

    assert!(
        packets_time <= streams_time.mul_f64(1.25),
        "packets --no-streams ({packets_time:?}) must not be slower than \
         streams mode ({streams_time:?}) — it is the cheap lens"
    );
    let _ = std::fs::remove_file(&path);
}
