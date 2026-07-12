//! `--where` integration: the query engine applied to real captures
//! through the real binary — tree narrowing with lineage kept, JSON
//! batch filtering, and usage-error paths.

mod support;

use support::{pktflow, tmp_pcap, tree_fixture};

#[test]
fn where_narrows_the_tree_but_keeps_lineage() {
    if cfg!(windows) {
        return; // Npcap SDK only on Windows CI
    }
    let path = tmp_pcap("where-tree", &tree_fixture());
    let out = pktflow(&[
        "streams",
        "-r",
        &path.to_string_lossy(),
        "--batch",
        "--where",
        "proto == dns",
    ]);
    assert_eq!(out.status.code(), Some(0));
    let body = String::from_utf8_lossy(&out.stdout);
    assert!(body.contains("dns #"), "the match itself:\n{body}");
    assert!(
        body.contains("udp #") && body.contains("ipv4 #"),
        "ancestors ride along:\n{body}"
    );
    assert!(!body.contains("tcp #"), "unrelated branch pruned:\n{body}");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn where_filters_the_json_batch_envelope() {
    if cfg!(windows) {
        return;
    }
    let path = tmp_pcap("where-json", &tree_fixture());
    let out = pktflow(&[
        "streams",
        "-r",
        &path.to_string_lossy(),
        "--batch",
        "--format",
        "json",
        "--where",
        "proto == tcp AND packets >= 1",
    ]);
    assert_eq!(out.status.code(), Some(0));
    let doc: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout is one JSON document");
    let streams = doc["streams"].as_array().expect("streams array");
    assert!(!streams.is_empty(), "fixture has tcp traffic");
    assert!(
        streams.iter().all(|s| s["protocol"] == "tcp"),
        "only matches in streams[]: {doc}"
    );
    assert!(
        doc["summary"]["packets"].as_u64().unwrap_or(0) > streams.len() as u64,
        "summary still covers the whole capture"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn bad_where_is_a_usage_error_before_any_output() {
    if cfg!(windows) {
        return;
    }
    let path = tmp_pcap("where-bad", &tree_fixture());
    let out = pktflow(&[
        "streams",
        "-r",
        &path.to_string_lossy(),
        "--batch",
        "--where",
        "bytes >",
    ]);
    assert_eq!(out.status.code(), Some(2), "usage error");
    assert!(out.stdout.is_empty(), "nothing reached stdout");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--where"), "error names the flag: {err}");

    // Live NDJSON events are unfiltered; the combination is refused.
    let out = pktflow(&[
        "streams",
        "-r",
        &path.to_string_lossy(),
        "--format",
        "json",
        "--where",
        "proto == dns",
    ]);
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--batch"), "error points at --batch: {err}");
    let _ = std::fs::remove_file(&path);
}
