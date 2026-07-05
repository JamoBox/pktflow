//! 09.2 criterion 1's sanity anchor: every well-formed fixture's pcap
//! output opens in tshark without warnings. Skipped automatically when
//! tshark isn't on `PATH` — CI's base images don't have it installed,
//! so this mirrors the project's existing `windows_skips()` pattern for
//! environment-gated checks: a local/manual verification that runs for
//! real whenever the tool is available, rather than an `#[ignore]` that
//! nobody remembers to run.
//!
//! Deliberately excludes `malformed_zoo`/`mixed_stop_reasons`: those
//! fixtures are garbage on purpose, and tshark is *expected* to flag
//! them — this test is only about the checksummed, protocol-correct
//! fixtures 09.2's determinism criterion also covers.

mod support;

use std::process::Command;

use pktflow_testkit::CaptureBuilder;
use support::named_fixtures::{
    bidi_tcp_session, dhcp_dora, dns_over_udp_session, dual_parent_ip, encrypted_udp_no_phantom,
    qinq_stack, vxlan_nested,
};
use support::tmp_pcap;

fn tshark_available() -> bool {
    Command::new("tshark").arg("--version").output().is_ok()
}

fn assert_tshark_clean(name: &str, capture: &CaptureBuilder) {
    let path = tmp_pcap(name, capture);
    let out = Command::new("tshark")
        .args(["-r", &path.to_string_lossy(), "-V"])
        .output()
        .expect("spawn tshark");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "{name}: tshark exited nonzero: {stderr}"
    );
    for marker in ["Malformed Packet", "Exception occurred", "[Unreassembled"] {
        assert!(
            !stdout.contains(marker),
            "{name}: tshark flagged {marker:?} in a well-formed fixture:\n{stdout}"
        );
    }
    let _ = std::fs::remove_file(&path);
}

#[test]
fn well_formed_fixtures_open_in_tshark_without_warnings() {
    if !tshark_available() {
        eprintln!("tshark not on PATH — skipping (local sanity check, not a CI gate)");
        return;
    }
    for (name, capture) in [
        ("bidi-tcp", bidi_tcp_session()),
        ("encrypted-udp", encrypted_udp_no_phantom()),
        ("vxlan-nested", vxlan_nested()),
        ("dual-parent", dual_parent_ip()),
        ("dns-over-udp", dns_over_udp_session()),
        ("dhcp-dora", dhcp_dora()),
        ("qinq-stack", qinq_stack()),
    ] {
        assert_tshark_clean(name, &capture);
    }
}
