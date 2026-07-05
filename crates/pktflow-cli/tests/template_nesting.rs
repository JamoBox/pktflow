//! 06.1 criterion 2: a synthetic PKTT-in-PKTT capture shows a nested
//! stream in the CLI, proving the full pipeline with zero real-protocol
//! involvement. The `template` plugin claims only a `Custom` route
//! space (deliberately, so the tutorial never squats a real one), so it
//! is reachable solely via forced entry — hence `--entry` (added here to
//! make this criterion checkable at all).

mod support;

use support::pktflow;

fn stdout(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// One PKTT header: src, dst, type, len — u16 big-endian (see
/// `pktflow_plugins::template`). `ty = 0x0001` nests another PKTT header
/// by name; anything else is terminal.
fn pktt(src: u16, dst: u16, ty: u16, len: u16) -> Vec<u8> {
    let mut b = Vec::with_capacity(8);
    b.extend_from_slice(&src.to_be_bytes());
    b.extend_from_slice(&dst.to_be_bytes());
    b.extend_from_slice(&ty.to_be_bytes());
    b.extend_from_slice(&len.to_be_bytes());
    b
}

/// A raw (no link-layer) pcap: DLT 147 is reserved for private/local
/// use and no plugin claims it, matching `template`'s own claim of a
/// `Custom` space rather than a real link type.
fn write_raw_pcap(path: &std::path::Path, frame: &[u8]) {
    let mut out = Vec::new();
    out.extend_from_slice(&0xA1B2_C3D4u32.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&65535u32.to_le_bytes());
    out.extend_from_slice(&147u32.to_le_bytes()); // DLT_USER0
    out.extend_from_slice(&100u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
    out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
    out.extend_from_slice(frame);
    std::fs::write(path, out).expect("write fixture");
}

#[test]
fn pktt_in_pktt_nests_a_stream_under_its_parent_in_the_cli() {
    if cfg!(windows) {
        return; // Npcap SDK only on Windows CI
    }
    let outer = pktt(1, 2, 0x0001, 16); // type 1: nests another PKTT header
    let inner = pktt(10, 20, 0x0002, 8); // type 2: terminal
    let mut frame = outer;
    frame.extend_from_slice(&inner);

    let path =
        std::env::temp_dir().join(format!("pktflow-pktt-nested-{}.pcap", std::process::id()));
    write_raw_pcap(&path, &frame);

    let out = pktflow(&[
        "streams",
        "-r",
        &path.to_string_lossy(),
        "--entry",
        "template",
        "--batch",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let body = stdout(&out);

    // The outer stream (src=1 dst=2) is a root; the inner (src=10
    // dst=20) is its child, indented one level under it — the tree
    // grammar's own proof of nesting (08.2), not a special-cased check.
    let lines: Vec<&str> = body.lines().collect();
    assert_eq!(lines.len(), 2, "one root, one nested child: {body}");
    assert!(
        lines[0].starts_with("template #0")
            && lines[0].contains("src=1")
            && lines[0].contains("dst=2"),
        "outer stream at the root: {}",
        lines[0]
    );
    assert!(
        lines[1]
            .trim_start_matches(['│', '├', '└', '─', ' '])
            .starts_with("template #1")
            && lines[1].contains("src=10")
            && lines[1].contains("dst=20"),
        "inner stream nested as a child: {}",
        lines[1]
    );
    assert!(
        lines[1].starts_with("└─ "),
        "indentation proves it's a child, not a sibling: {}",
        lines[1]
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn entry_names_an_unregistered_plugin_cleanly() {
    let out = pktflow(&["streams", "-r", "f.pcap", "--entry", "not-a-real-plugin"]);
    assert_eq!(out.status.code(), Some(2), "a usage error, not a panic");
    assert!(stderr(&out).contains("not-a-real-plugin"));
}
