//! 08.1 surface tests: help snapshots, bare-path shorthand, exit codes,
//! and stdout/stderr pipe safety, all against the real binary.

use std::path::PathBuf;
use std::process::{Command, Output};

fn pktflow() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pktflow"))
}

fn run(args: &[&str]) -> Output {
    pktflow().args(args).output().expect("spawn pktflow")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

// ---- help snapshots (no libpcap calls: safe on every CI OS) ----------

/// Platform-neutral: Windows clap output is CRLF and names the binary
/// `pktflow.exe` (argv[0]-derived); goldens are checked in as LF with
/// the bare name.
fn normalize_help(s: &str) -> String {
    s.replace("\r\n", "\n").replace("pktflow.exe", "pktflow")
}

fn assert_help_matches(args: &[&str], golden: &str) {
    let out = run(args);
    assert!(out.status.success(), "--help exits 0");
    let expected = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/golden")
            .join(golden),
    )
    .expect("golden file");
    let actual = normalize_help(&stdout(&out));
    assert_eq!(
        actual,
        normalize_help(&expected),
        "help text drifted from {golden} — if deliberate, regenerate the golden"
    );
}

#[test]
fn help_snapshots_are_stable() {
    assert_help_matches(&["--help"], "help-main.txt");
    assert_help_matches(&["streams", "--help"], "help-streams.txt");
    assert_help_matches(&["stream", "--help"], "help-stream.txt");
    assert_help_matches(&["packets", "--help"], "help-packets.txt");
    assert_help_matches(&["ifaces", "--help"], "help-ifaces.txt");
}

// ---- exit codes that never touch libpcap ------------------------------

#[test]
fn missing_input_is_a_usage_error_exiting_2() {
    let out = run(&["streams"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("--read"), "clap names the gap");
}

#[test]
fn conflicting_inputs_exit_2() {
    let out = run(&["streams", "-r", "f.pcap", "-i", "eth0"]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn nonexistent_bare_path_falls_through_to_clap() {
    // Not a file, not a subcommand: clap's unrecognized-subcommand error.
    let out = run(&["definitely-not-a-file.pcap"]);
    assert_eq!(out.status.code(), Some(2));
}

// ---- fixture-backed runs (libpcap: SDK-only Windows CI skips) ---------

/// Ethernet(IPv4(UDP)) frame with an unclaimed dport — enough for real
/// streams without protocol fixtures (09.2 owns those).
fn frame(sport: u16) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&[0xAA; 6]);
    f.extend_from_slice(&[0xBB; 6]);
    f.extend_from_slice(&0x0800u16.to_be_bytes());
    let payload_len = 4u16;
    let total = 20 + 8 + payload_len;
    f.extend_from_slice(&[0x45, 0]);
    f.extend_from_slice(&total.to_be_bytes());
    f.extend_from_slice(&[0x00, 0x01, 0x40, 0x00, 64, 17]);
    f.extend_from_slice(&[0, 0]); // checksum
    f.extend_from_slice(&[10, 0, 0, 5]);
    f.extend_from_slice(&[10, 0, 0, 1]);
    f.extend_from_slice(&sport.to_be_bytes());
    f.extend_from_slice(&51820u16.to_be_bytes()); // unclaimed port
    f.extend_from_slice(&(8 + payload_len).to_be_bytes());
    f.extend_from_slice(&[0, 0]); // checksum
    f.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    f
}

fn write_fixture(name: &str) -> PathBuf {
    let mut out = Vec::new();
    out.extend_from_slice(&0xA1B2_C3D4u32.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&65535u32.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    for (i, f) in [frame(40001), frame(40002), frame(40001)]
        .iter()
        .enumerate()
    {
        out.extend_from_slice(&(100 + i as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(f.len() as u32).to_le_bytes());
        out.extend_from_slice(&(f.len() as u32).to_le_bytes());
        out.extend_from_slice(f);
    }
    let path = std::env::temp_dir().join(format!(
        "pktflow-surface-{}-{name}.pcap",
        std::process::id()
    ));
    std::fs::write(&path, out).expect("write fixture");
    path
}

macro_rules! windows_skips {
    () => {
        if cfg!(windows) {
            // Windows CI has the Npcap SDK but no runtime DLL.
            return;
        }
    };
}

#[test]
fn bare_path_shorthand_runs_the_streams_view() {
    windows_skips!();
    let path = write_fixture("shorthand");
    let out = pktflow().arg(&path).output().expect("spawn");
    assert_eq!(out.status.code(), Some(0));
    assert!(stdout(&out).contains("ethernet"), "tree rendered");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn summary_reaches_stderr_for_every_subcommand() {
    windows_skips!();
    let path = write_fixture("summary");
    let p = path.to_string_lossy();
    for args in [
        vec!["streams", "-r", p.as_ref()],
        vec!["stream", "-r", p.as_ref(), "#0"],
        vec!["packets", "-r", p.as_ref()],
    ] {
        let out = run(&args);
        assert_eq!(out.status.code(), Some(0), "{args:?}: {}", stderr(&out));
        let err = stderr(&out);
        assert!(
            err.contains("processed 3 packets"),
            "{args:?} summary on stderr, got: {err}"
        );
        assert!(err.contains("streams"), "{args:?} per-protocol counts");
    }
    let _ = std::fs::remove_file(&path);
}

#[test]
fn json_stdout_is_pipe_safe() {
    windows_skips!();
    let path = write_fixture("json");
    let out = run(&[
        "streams",
        "-r",
        &path.to_string_lossy(),
        "--format",
        "json",
        "--batch",
    ]);
    assert_eq!(out.status.code(), Some(0));

    // The whole of stdout must be one parseable JSON document.
    let doc: serde_json::Value =
        serde_json::from_str(&stdout(&out)).expect("stdout is valid JSON, nothing else");
    assert_eq!(doc["pktflow"], 1);
    assert_eq!(doc["mode"], "offline");
    assert_eq!(doc["summary"]["packets"], 3);
    // udp streams exist: two distinct source ports under one ipv4 pair.
    assert_eq!(doc["summary"]["streams"]["udp"], 2);

    // The summary still reached stderr.
    assert!(stderr(&out).contains("processed 3 packets"));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn packets_json_is_ndjson() {
    windows_skips!();
    let path = write_fixture("ndjson");
    let out = run(&["packets", "-r", &path.to_string_lossy(), "--format", "json"]);
    assert_eq!(out.status.code(), Some(0));
    let body = stdout(&out);
    let lines: Vec<&str> = body.lines().collect();
    assert_eq!(lines.len(), 3, "one line per packet");
    for line in lines {
        let doc: serde_json::Value = serde_json::from_str(line).expect("each line parses");
        assert_eq!(doc["stop_class"], "unknown_payload"); // port 51820 unclaimed
        assert_eq!(
            doc["layers"],
            serde_json::json!(["ethernet", "ipv4", "udp"])
        );
    }
    let _ = std::fs::remove_file(&path);
}

#[test]
fn count_flag_caps_the_run() {
    windows_skips!();
    let path = write_fixture("count");
    let out = run(&["packets", "-r", &path.to_string_lossy(), "-c", "2"]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(stdout(&out).lines().count(), 2);
    assert!(stderr(&out).contains("processed 2 packets"));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn runtime_errors_exit_1() {
    windows_skips!();
    let out = run(&["streams", "-r", "/definitely/not/here.pcap"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("pktflow:"), "error is prefixed");
}
