//! 08.3 drill-down tests: both selector forms, the ambiguity path,
//! section goldens, and the rollup overflow/elision markers.

mod support;

use support::{
    assert_golden, dual_parent_fixture, gre_fixture, overflow_fixture, pktflow, tmp_pcap,
    tree_fixture,
};

fn stdout(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn tcp_drilldown_matches_golden_via_both_selector_forms() {
    if cfg!(windows) {
        return; // Npcap SDK only on Windows CI
    }
    let path = tmp_pcap("drill-tcp", &tree_fixture());
    let p = path.to_string_lossy();

    let by_id = pktflow(&["stream", "-r", p.as_ref(), "#5"]);
    assert_eq!(by_id.status.code(), Some(0), "{}", stderr(&by_id));
    assert_golden(&stdout(&by_id), "drill-tcp.txt");

    // The same stream through a key expression, order-insensitive, with
    // addr:port composites resolved against the ancestry.
    for expr in [
        "tcp :52341 :443",
        "tcp :443 :52341",
        "tcp 10.0.0.5:52341 93.184.216.34:443",
        "tcp 93.184.216.34:443 10.0.0.5:52341",
    ] {
        let by_expr = pktflow(&["stream", "-r", p.as_ref(), expr]);
        assert_eq!(
            by_expr.status.code(),
            Some(0),
            "{expr}: {}",
            stderr(&by_expr)
        );
        assert_eq!(stdout(&by_expr), stdout(&by_id), "{expr} resolves to #5");
    }
    let _ = std::fs::remove_file(&path);
}

#[test]
fn dns_drilldown_shows_rollups_without_lifecycle() {
    if cfg!(windows) {
        return;
    }
    let path = tmp_pcap("drill-dns", &tree_fixture());
    let out = pktflow(&["stream", "-r", &path.to_string_lossy(), "#3"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let body = stdout(&out);
    assert_golden(&body, "drill-dns.txt");
    assert!(body.contains("qname"), "qname rollup rendered");
    assert!(!body.contains("state"), "no lifecycle section for dns");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn gre_drilldown_shows_the_inner_stack_as_children() {
    if cfg!(windows) {
        return;
    }
    let path = tmp_pcap("drill-gre", &gre_fixture());
    let out = pktflow(&["stream", "-r", &path.to_string_lossy(), "#2"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let body = stdout(&out);
    assert_golden(&body, "drill-gre.txt");
    assert!(
        body.contains("children  ipv4 #3") && body.contains("▸ tcp #4"),
        "inner stack visible: {body}"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn ambiguous_selector_exits_1_listing_candidates() {
    if cfg!(windows) {
        return;
    }
    let path = tmp_pcap("drill-ambiguous", &dual_parent_fixture());
    let out = pktflow(&["stream", "-r", &path.to_string_lossy(), "udp :40001 :40002"]);
    assert_eq!(out.status.code(), Some(1), "ambiguity is exit 1");
    let err = stderr(&out);
    assert!(err.contains("ambiguous"), "names the problem: {err}");
    assert!(
        err.contains("#2") && err.contains("#5"),
        "lists both candidates with ids: {err}"
    );
    assert!(
        err.contains("under"),
        "candidates carry their lineage: {err}"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn missing_stream_exits_1() {
    if cfg!(windows) {
        return;
    }
    let path = tmp_pcap("drill-missing", &tree_fixture());
    let p = path.to_string_lossy();
    let out = pktflow(&["stream", "-r", p.as_ref(), "#99"]);
    assert_eq!(out.status.code(), Some(1));
    let out = pktflow(&["stream", "-r", p.as_ref(), "tcp :1 :2"]);
    assert_eq!(out.status.code(), Some(1));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn overflow_and_elision_markers_do_not_lie_by_omission() {
    if cfg!(windows) {
        return;
    }
    let path = tmp_pcap("drill-overflow", &overflow_fixture());
    let p = path.to_string_lossy();

    // DNS qname accumulate: 70 distinct names against the cap of 64.
    let out = pktflow(&["stream", "-r", p.as_ref(), "#3"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let body = stdout(&out);
    assert_golden(&body, "drill-overflow-dns.txt");
    assert!(body.contains("≥64 values"), "overflow marker: {body}");
    assert!(
        body.contains("64 distinct / 70 obs"),
        "honest counts: {body}"
    );

    // TCP flag series: 30 points elide to head/tail 10s by default…
    let out = pktflow(&["stream", "-r", p.as_ref(), "tcp :41000 :8080"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let body = stdout(&out);
    assert!(body.contains("… 10 elided …"), "elision marker: {body}");

    // …and --full-series lifts the elision.
    let out = pktflow(&[
        "stream",
        "-r",
        p.as_ref(),
        "tcp :41000 :8080",
        "--full-series",
    ]);
    assert_eq!(out.status.code(), Some(0));
    let full = stdout(&out);
    assert!(!full.contains("elided"), "no elision with --full-series");
    assert_eq!(
        full.matches("PSH+ACK").count(),
        31, // 30 series points + 1 accumulate set entry
        "all 30 points rendered: {full}"
    );
    let _ = std::fs::remove_file(&path);
}
