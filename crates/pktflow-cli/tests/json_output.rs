//! 08.5 JSON tests: `--batch` envelope schema validation, determinism
//! (00.3's hook), and the (now default) NDJSON live events smoke-tested
//! via replay pacing.

mod support;

use serde_json::Value as Json;
use support::named_fixtures::{
    bidi_tcp_session, dhcp_dora, dns_over_udp_session, dual_parent_ip, encrypted_udp_no_phantom,
    idle_eviction, lru_pressure, malformed_zoo, mixed_stop_reasons, qinq_stack, vxlan_nested,
};
use support::schema::{load_schema, validate};
use support::{
    dual_parent_fixture, gre_fixture, overflow_fixture, pktflow, tmp_pcap, tree_fixture,
};

fn stdout(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn windows_skips() -> bool {
    cfg!(windows) // Npcap SDK only on Windows CI
}

/// Pretty-printed so a golden diff is readable; decouples the golden
/// from serde_json's exact single-line spacing while still pinning
/// every field name and value. `source` is the tmp_pcap path (PID +
/// process-specific tempdir), so it's normalized before comparing —
/// otherwise every run would mint a fresh "golden".
fn assert_json_golden(doc: &Json, golden: &str) {
    let mut doc = doc.clone();
    doc["source"] = Json::String("FIXTURE.pcap".into());
    let pretty = serde_json::to_string_pretty(&doc).expect("serializable");
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(golden);
    if std::env::var_os("UPDATE_GOLDENS").is_some() {
        std::fs::write(&path, &pretty).expect("write golden");
        return;
    }
    let expected = std::fs::read_to_string(&path).expect("golden file (UPDATE_GOLDENS=1 seeds)");
    assert_eq!(
        pretty, expected,
        "{golden} drifted — if deliberate, rerun with UPDATE_GOLDENS=1"
    );
}

#[test]
fn offline_json_validates_against_the_checked_in_schema() {
    if windows_skips() {
        return;
    }
    let schema = load_schema();
    for (name, fixture, golden) in [
        ("tree", tree_fixture(), "offline-json-tree.json"),
        ("gre", gre_fixture(), "offline-json-gre.json"),
    ] {
        let path = tmp_pcap(&format!("schema-{name}"), &fixture);
        let out = pktflow(&[
            "streams",
            "-r",
            &path.to_string_lossy(),
            "--format",
            "json",
            "--batch",
        ]);
        assert_eq!(out.status.code(), Some(0), "{name}: {}", stderr(&out));
        let doc: Json = serde_json::from_str(&stdout(&out)).expect("valid JSON");
        validate(&schema, "", &doc).unwrap_or_else(|e| panic!("{name} envelope: {e}"));
        for (i, s) in doc["streams"]
            .as_array()
            .expect("streams array")
            .iter()
            .enumerate()
        {
            validate(&schema, "stream", s).unwrap_or_else(|e| panic!("{name} streams[{i}]: {e}"));
        }
        assert_json_golden(&doc, golden);
        let _ = std::fs::remove_file(&path);
    }
}

#[test]
fn repeated_offline_runs_produce_byte_identical_json() {
    if windows_skips() {
        return;
    }
    let path = tmp_pcap("determinism", &tree_fixture());
    let p = path.to_string_lossy();

    let run = || {
        let out = pktflow(&["streams", "-r", p.as_ref(), "--format", "json", "--batch"]);
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        stdout(&out)
    };
    let (first, second) = (run(), run());
    assert_eq!(first, second, "two runs must be byte-identical (00.3 hook)");

    // Not merely "equal by accident": the document is nonempty and
    // actually carries real stream data, so the comparison has teeth.
    let doc: Json = serde_json::from_str(&first).expect("valid JSON");
    assert!(!doc["streams"].as_array().expect("array").is_empty());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn repeated_offline_runs_are_byte_identical_over_the_full_corpus() {
    // 09.3's determinism e2e, CLI half: the same property as
    // repeated_offline_runs_produce_byte_identical_json above, now over
    // every fixture in the 09.2 corpus, not just one.
    if windows_skips() {
        return;
    }
    for (name, capture) in [
        ("tree", tree_fixture()),
        ("gre", gre_fixture()),
        ("dual_parent", dual_parent_fixture()),
        ("overflow", overflow_fixture()),
        ("bidi_tcp_session", bidi_tcp_session()),
        ("encrypted_udp_no_phantom", encrypted_udp_no_phantom()),
        ("vxlan_nested", vxlan_nested()),
        ("dual_parent_ip", dual_parent_ip()),
        ("dns_over_udp_session", dns_over_udp_session()),
        ("dhcp_dora", dhcp_dora()),
        ("idle_eviction", idle_eviction()),
        ("lru_pressure", lru_pressure()),
        ("qinq_stack", qinq_stack()),
        ("malformed_zoo", malformed_zoo()),
        ("mixed_stop_reasons", mixed_stop_reasons()),
    ] {
        let path = tmp_pcap(&format!("corpus-determinism-{name}"), &capture);
        let p = path.to_string_lossy();
        let run = || {
            let out = pktflow(&["streams", "-r", p.as_ref(), "--format", "json", "--batch"]);
            assert_eq!(out.status.code(), Some(0), "{name}: {}", stderr(&out));
            stdout(&out)
        };
        let (first, second) = (run(), run());
        assert_eq!(first, second, "{name}: two runs must be byte-identical");
        let _ = std::fs::remove_file(&path);
    }
}

#[test]
fn ndjson_live_events_smoke_test_via_replay_pacing() {
    if windows_skips() {
        return;
    }
    let schema = load_schema();
    let path = tmp_pcap("ndjson-smoke", &tree_fixture());
    let out = pktflow(&[
        "streams",
        "-r",
        &path.to_string_lossy(),
        "--format",
        "json",
        "--idle-timeout",
        "1", // forces real mid-run stream_closed events (D2), not just at finish()
        "--pace-ms",
        "5",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let body = stdout(&out);
    let lines: Vec<&str> = body.lines().collect();
    assert!(lines.len() > 1, "more than just the summary line: {body}");

    let mut saw = std::collections::HashSet::new();
    for (i, line) in lines.iter().enumerate() {
        let doc: Json =
            serde_json::from_str(line).unwrap_or_else(|e| panic!("line {i}: {e}\n{line}"));
        let event = doc["event"]
            .as_str()
            .unwrap_or_else(|| panic!("line {i} has no event: {line}"));
        saw.insert(event.to_string());
        let is_last = i + 1 == lines.len();
        if event == "summary" {
            assert!(is_last, "summary must be the last line");
            validate(&schema, "summary", &doc).unwrap_or_else(|e| panic!("summary: {e}"));
        } else {
            assert!(
                matches!(event, "stream_new" | "stream_update" | "stream_closed"),
                "unexpected event {event:?}"
            );
            validate(&schema, "stream", &doc).unwrap_or_else(|e| panic!("{event} line {i}: {e}"));
            if event == "stream_closed" {
                assert!(
                    doc["close_reason"].is_string(),
                    "close_reason present: {line}"
                );
            }
        }
    }
    // The final line is always present (even in the Ctrl-C path, verified
    // manually against a live interface — 08.1's graceful stop still
    // reaches finish()).
    assert!(saw.contains("summary"), "final summary line present");
    assert!(saw.contains("stream_new"), "streams were announced");
    assert!(
        saw.contains("stream_closed"),
        "idle-timeout eviction produced a real close event"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn default_json_rejects_bad_input_same_as_batch_text() {
    if windows_skips() {
        return;
    }
    // The path itself is never touched (no fixture needed) — but
    // FileSource::open still calls into libpcap just to *report* the
    // file's missing, and Windows CI has no wpcap.dll runtime, so this
    // needs the same guard as every other file-opening test.
    let out = pktflow(&[
        "streams",
        "-r",
        "definitely-missing.pcap",
        "--format",
        "json",
    ]);
    assert_eq!(out.status.code(), Some(1));
}
