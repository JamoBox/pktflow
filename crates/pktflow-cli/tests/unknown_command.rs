//! `pktflow unknown` (10.3): table, drill-down, `--export`, `--scaffold`.
//!
//! Fixtures are hand-rolled raw frames (not `pktflow_testkit::PacketBuilder`,
//! which always fills in a routable EtherType) so we can engineer both
//! unknown-stop shapes precisely, each with a genuine near-miss: an
//! unclaimed UDP port whose payload is TCP-header-shaped (tcp's probe
//! scores it 60 without ever routing there), and a raw 802.3 length-typed
//! Ethernet frame whose payload passes ipv6's probe but fails its parse
//! (see `no_heuristic_winner_frame` for exactly how).

mod support;

use std::path::PathBuf;

use serde_json::Value as Json;
use support::schema::{load_unknown_schema, validate};
use support::{assert_golden, pktflow};

fn stdout(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Every test below spawns the real `pktflow` binary against a capture
/// file (`support::pktflow`'s libpcap-linked child process) — the same
/// class of test `surface.rs` skips on Windows CI, which has the Npcap
/// SDK for linking but no runtime DLL.
macro_rules! windows_skips {
    () => {
        if cfg!(windows) {
            return;
        }
    };
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header.len() {
        sum += u32::from(u16::from_be_bytes([header[i], header[i + 1]]));
        i += 2;
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn ipv4_header(total_len: u16, proto: u8, src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
    let mut h = vec![0x45, 0x00];
    h.extend_from_slice(&total_len.to_be_bytes());
    h.extend_from_slice(&[0x00, 0x01, 0x40, 0x00, 64, proto, 0x00, 0x00]);
    h.extend_from_slice(&src);
    h.extend_from_slice(&dst);
    let ck = ipv4_checksum(&h);
    h[10] = (ck >> 8) as u8;
    h[11] = (ck & 0xFF) as u8;
    h
}

/// eth/ipv4/udp, an unclaimed destination port, and a 20-byte payload
/// shaped exactly like a plausible TCP header — tcp's probe (02.3
/// honest-structural-checks) scores it 60 without this ever routing as
/// tcp (the 03.4 gate forbids it; 10.1's near-miss pass runs anyway).
fn unclaimed_udp_with_tcp_shaped_payload(sport: u16) -> Vec<u8> {
    let tcp_shaped: [u8; 20] = [
        0x00, 0x50, // src port (irrelevant to the probe)
        0x01, 0xBB, // dst port
        0, 0, 0, 0, // seq
        0, 0, 0, 0, // ack
        0x50, 0x02, // data_offset=5, flags=SYN
        0x20, 0x00, // window
        0x00, 0x00, // checksum
        0x00, 0x00, // urgent
    ];
    let mut udp = Vec::new();
    udp.extend_from_slice(&sport.to_be_bytes());
    udp.extend_from_slice(&55555u16.to_be_bytes()); // unclaimed
    udp.extend_from_slice(&(8 + tcp_shaped.len() as u16).to_be_bytes());
    udp.extend_from_slice(&[0x00, 0x00]); // checksum
    udp.extend_from_slice(&tcp_shaped);

    let ip = ipv4_header((20 + udp.len()) as u16, 17, [10, 0, 0, 5], [10, 0, 0, 1]);

    let mut frame = vec![0xBBu8; 6];
    frame.extend_from_slice(&[0xAAu8; 6]);
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&udp);
    frame
}

/// A raw 802.3 length-typed Ethernet frame (EtherType field < 0x0600):
/// `Hint::Unknown`. The 40-byte payload is a genuine `NoHeuristicWinner`
/// *with* a near-miss: it passes ipv6's probe (version nibble 6, a
/// `Hop-by-Hop` next-header, payload_len 0 fitting the 40-byte minimum —
/// scoring 75) but then fails ipv6's `parse()`, which — unlike the probe —
/// walks into that Hop-by-Hop extension header and runs out of bytes
/// reading it. `heuristic_fallback` tries its one candidate, drops the
/// failed winner, and reaches `UnknownHint` with the score still recorded
/// as a near-miss (10.1). Neither tcp (data_offset nibble reads as 0 from
/// the zeroed address fields) nor template (its length field reads > the
/// 40-byte buffer) score anything on these same bytes.
fn no_heuristic_winner_frame() -> Vec<u8> {
    let mut payload = vec![0x60, 0x00, 0x00, 0x00]; // version 6, traffic class/flow label 0
    payload.extend_from_slice(&0u16.to_be_bytes()); // payload_len = 0
    payload.push(0); // next_header = 0 (Hop-by-Hop Options)
    payload.push(64); // hop_limit
    payload.extend_from_slice(&[0u8; 16]); // src (zeroed: keeps tcp's probe from scoring)
    payload.extend_from_slice(&[0u8; 16]); // dst
    assert_eq!(
        payload.len(),
        40,
        "exactly the fixed ipv6 header, no room for the ext header body"
    );

    let mut frame = vec![0xBBu8; 6];
    frame.extend_from_slice(&[0xAAu8; 6]);
    frame.extend_from_slice(&0x0028u16.to_be_bytes()); // 802.3 length (40), not an EtherType
    frame.extend_from_slice(&payload);
    frame
}

fn write_pcap(name: &str, frames: &[(u32, Vec<u8>)]) -> PathBuf {
    let mut out = Vec::new();
    out.extend_from_slice(&0xA1B2_C3D4u32.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&65535u32.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    for (ts, frame) in frames {
        out.extend_from_slice(&ts.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        out.extend_from_slice(frame);
    }
    // Tests run in parallel and several share the same fixture `name`
    // (e.g. "mixed"); a counter keeps each call's file distinct so
    // concurrent runs never read/write/delete one another's fixture.
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "pktflow-unknown-cmd-{}-{name}-{n}.pcap",
        std::process::id()
    ));
    std::fs::write(&path, out).expect("write fixture");
    path
}

/// Two unclaimed-route packets (one group, count 2) and one
/// no-heuristic-winner packet (a second group) — the fixture every test
/// below shares.
fn mixed_fixture() -> PathBuf {
    write_pcap(
        "mixed",
        &[
            (100, unclaimed_udp_with_tcp_shaped_payload(40001)),
            (101, unclaimed_udp_with_tcp_shaped_payload(40002)),
            (102, no_heuristic_winner_frame()),
        ],
    )
}

fn clean_fixture() -> PathBuf {
    // A plain, fully-claimed eth/ipv4/udp packet to port 53: nothing
    // unknown about it (udp itself is terminal-ish via Hint::Candidates
    // resolving successfully — no plugin claims 53, so *this* also stops
    // unclaimed; use TCP's own well-known port pattern instead, terminal
    // and clean).
    let tcp_full: [u8; 20] = [
        0x01, 0xBB, 0x00, 0x50, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x10, 0x20, 0x00, 0, 0, 0, 0,
    ];
    let ip = ipv4_header(20 + tcp_full.len() as u16, 6, [10, 0, 0, 5], [10, 0, 0, 9]);
    let mut frame = vec![0xBBu8; 6];
    frame.extend_from_slice(&[0xAAu8; 6]);
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&tcp_full);
    write_pcap("clean", &[(200, frame)])
}

#[test]
fn table_lists_both_group_kinds_each_with_a_near_miss() {
    windows_skips!();
    let path = mixed_fixture();
    let out = pktflow(&["unknown", "-r", &path.to_string_lossy()]);
    assert_eq!(out.status.code(), Some(0));
    let text = stdout(&out);
    assert!(text.contains("UNKNOWN PROTOCOLS"));
    assert!(text.contains("udp → udp_port:55555"));
    assert!(text.contains("unclaimed route"));
    assert!(text.contains("ethernet"));
    assert!(text.contains("no heuristic winner"));
    assert!(text.contains("tcp(60)"), "the tcp-shaped payload near-miss");
    assert!(
        text.contains("ipv6(75)"),
        "the no-heuristic-winner near-miss"
    );
    assert_golden(&text, "unknown-table.txt");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn clean_fixture_prints_the_explicit_none_observed_line() {
    windows_skips!();
    let path = clean_fixture();
    let out = pktflow(&["unknown", "-r", &path.to_string_lossy()]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(stdout(&out), "no unknown protocols observed\n");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn drilldown_shows_the_full_near_miss_ranking() {
    windows_skips!();
    let path = mixed_fixture();
    let table = stdout(&pktflow(&["unknown", "-r", &path.to_string_lossy()]));
    // Row 1 is whichever group sorts first by count desc; the unclaimed
    // route group has count 2, the no-heuristic-winner group count 1.
    assert!(table.contains("1  udp"), "table:\n{table}");

    let out = pktflow(&["unknown", "-r", &path.to_string_lossy(), "#1"]);
    assert_eq!(out.status.code(), Some(0));
    let text = stdout(&out);
    assert!(text.contains("#1  udp → udp_port:55555"));
    assert!(text.contains("count     2"));
    assert!(text.contains("near misses"));
    assert!(text.contains("tcp(60)"));
    assert!(text.contains("samples"));
    assert!(
        text.contains("0000  00 50 01 bb"),
        "hex dump of the retained sample"
    );
    assert_golden(&text, "unknown-drilldown.txt");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn drilldown_shows_the_endpoint_overflow_marker_past_the_cap() {
    windows_skips!();
    // D4's ACCUMULATE_SET_CAP is 64; 66 distinct source ports on the same
    // unclaimed dest port fold into one unknown group but 66 distinct udp
    // stream keys (D10: udp's key is ports only) — past the cap.
    let frames: Vec<(u32, Vec<u8>)> = (0..66u16)
        .map(|i| {
            (
                300 + u32::from(i),
                unclaimed_udp_with_tcp_shaped_payload(50000 + i),
            )
        })
        .collect();
    let path = write_pcap("overflow", &frames);

    let out = pktflow(&["unknown", "-r", &path.to_string_lossy(), "#1"]);
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
    let text = stdout(&out);
    assert!(text.contains("count     66"));
    assert!(
        text.contains("≥64 distinct"),
        "overflow marker present, not silently dropped: {text}"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn table_and_drilldown_json_validate_against_the_schema() {
    windows_skips!();
    let path = mixed_fixture();
    let schema = load_unknown_schema();

    let out = pktflow(&["unknown", "-r", &path.to_string_lossy(), "--format", "json"]);
    assert_eq!(out.status.code(), Some(0));
    let doc: Json = serde_json::from_str(&stdout(&out)).expect("valid JSON");
    validate(&schema, "", &doc).unwrap_or_else(|e| panic!("table envelope: {e}"));
    let groups = doc["groups"].as_array().expect("groups array");
    assert_eq!(groups.len(), 2);
    for (i, g) in groups.iter().enumerate() {
        validate(&schema, "group", g).unwrap_or_else(|e| panic!("groups[{i}]: {e}"));
    }
    // D8 JSON/binary split: no raw sample bytes in the table view.
    assert!(doc.to_string().to_lowercase().find("\"sample").is_none());

    let out = pktflow(&[
        "unknown",
        "-r",
        &path.to_string_lossy(),
        "#1",
        "--format",
        "json",
    ]);
    assert_eq!(out.status.code(), Some(0));
    let doc: Json = serde_json::from_str(&stdout(&out)).expect("valid JSON");
    validate(&schema, "", &doc).unwrap_or_else(|e| panic!("drilldown envelope: {e}"));
    assert_eq!(
        doc["groups"][0]["near_misses"]
            .as_array()
            .expect("test setup")
            .len(),
        1
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn export_round_trips_byte_identical_samples_and_a_valid_manifest() {
    windows_skips!();
    let path = mixed_fixture();
    let dir = std::env::temp_dir().join(format!("pktflow-unknown-export-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let out = pktflow(&[
        "unknown",
        "-r",
        &path.to_string_lossy(),
        "#1",
        "--export",
        &dir.to_string_lossy(),
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));

    let manifest_path = dir.join("manifest.json");
    let manifest_text = std::fs::read_to_string(&manifest_path).expect("manifest.json written");
    let manifest: Json = serde_json::from_str(&manifest_text).expect("manifest is valid JSON");
    let schema = load_unknown_schema();
    validate(&schema, "manifest", &manifest).unwrap_or_else(|e| panic!("manifest: {e}"));

    let samples = manifest["samples"].as_array().expect("samples array");
    assert_eq!(samples.len(), 2, "both occurrences retained for this group");
    for entry in samples {
        let file_name = entry["file"].as_str().expect("file name");
        let bytes = std::fs::read(dir.join(file_name)).expect("sample file written");
        // Byte-identical to the exact UDP payload that stopped dissection.
        assert_eq!(bytes[0..4], [0x00, 0x50, 0x01, 0xBB]);
        assert_eq!(bytes.len(), 20);
    }

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn scaffold_writes_exactly_one_file_prefilled_from_the_route() {
    windows_skips!();
    let path = mixed_fixture();
    let plugins_dir =
        std::env::temp_dir().join(format!("pktflow-unknown-scaffold-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&plugins_dir);
    std::fs::create_dir_all(&plugins_dir).expect("test setup");
    let template_src = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../pktflow-plugins/src/template.rs"),
    )
    .expect("read the real template.rs");
    std::fs::write(plugins_dir.join("template.rs"), &template_src).expect("test setup");

    let out = pktflow(&[
        "unknown",
        "-r",
        &path.to_string_lossy(),
        "#1",
        "--scaffold",
        "scaffolded_proto",
        "--plugins-dir",
        &plugins_dir.to_string_lossy(),
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
    assert!(stdout(&out).contains("next: add"));

    // Exactly one new file: template.rs (pre-existing) plus the scaffold.
    let entries: Vec<_> = std::fs::read_dir(&plugins_dir)
        .expect("test setup")
        .map(|e| {
            e.expect("test setup")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    assert_eq!(
        entries.len(),
        2,
        "template.rs + the one new file: {entries:?}"
    );

    let generated =
        std::fs::read_to_string(plugins_dir.join("scaffolded_proto.rs")).expect("test setup");
    assert!(generated.contains("struct ScaffoldedProto"));
    assert!(generated.contains("\"scaffolded_proto\""));
    assert!(generated.contains("RouteId::UdpPort(55555)"));

    // Structural checks (09.1-style: name/claims present) without pulling
    // in the full conformance kit, which needs a `good` fixture the
    // scaffold's still-placeholder `parse()` can't satisfy yet.
    assert!(generated.contains("fn name(&self) -> ProtocolName"));
    assert!(generated.contains("fn claims(&self) -> &'static [RouteId]"));

    // Compiles standalone: a scratch crate depending only on pktflow-core
    // (exactly what the scaffold imports), `cargo check`ed in isolation.
    assert_scaffold_compiles(&generated);

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_dir_all(&plugins_dir);
}

#[test]
fn scaffold_refuses_to_clobber_an_existing_file() {
    windows_skips!();
    let path = mixed_fixture();
    let plugins_dir = std::env::temp_dir().join(format!(
        "pktflow-unknown-scaffold-clobber-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&plugins_dir);
    std::fs::create_dir_all(&plugins_dir).expect("test setup");
    let template_src = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../pktflow-plugins/src/template.rs"),
    )
    .expect("test setup");
    std::fs::write(plugins_dir.join("template.rs"), &template_src).expect("test setup");
    std::fs::write(
        plugins_dir.join("taken.rs"),
        "// pre-existing, do not touch",
    )
    .expect("test setup");

    let out = pktflow(&[
        "unknown",
        "-r",
        &path.to_string_lossy(),
        "#1",
        "--scaffold",
        "taken",
        "--plugins-dir",
        &plugins_dir.to_string_lossy(),
    ]);
    assert_eq!(out.status.code(), Some(2), "usage error: {}", stdout(&out));
    let untouched = std::fs::read_to_string(plugins_dir.join("taken.rs")).expect("test setup");
    assert_eq!(untouched, "// pre-existing, do not touch");

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_dir_all(&plugins_dir);
}

/// Builds a throwaway Cargo crate whose `src/lib.rs` *is* the scaffolded
/// source, depending on the workspace's real `pktflow-core` by path, and
/// `cargo check`s it in isolation — "compiles standalone" taken literally,
/// without mutating the real `pktflow-plugins` crate to prove it.
fn assert_scaffold_compiles(generated_source: &str) {
    let crate_dir = std::env::temp_dir().join(format!(
        "pktflow-scaffold-check-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .expect("test setup")
            .as_nanos()
    ));
    let src_dir = crate_dir.join("src");
    std::fs::create_dir_all(&src_dir).expect("test setup");

    let core_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../pktflow-core");
    let manifest = format!(
        "[package]\nname = \"pktflow-scaffold-check\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n\
         [dependencies]\npktflow-core = {{ path = {core_path:?} }}\n",
    );
    std::fs::write(crate_dir.join("Cargo.toml"), manifest).expect("test setup");
    std::fs::write(src_dir.join("lib.rs"), generated_source).expect("test setup");

    // --offline: pktflow-core's own dependencies are already in the local
    // registry cache from building the workspace itself, so this never
    // needs the network — faster, and one less way this test can flake.
    let status = std::process::Command::new("cargo")
        .args(["check", "--offline", "--manifest-path"])
        .arg(crate_dir.join("Cargo.toml"))
        .env_remove("CARGO_TARGET_DIR") // don't fight the workspace's own target dir
        .status()
        .expect("spawn cargo check");
    assert!(
        status.success(),
        "scaffolded plugin did not compile standalone"
    );

    let _ = std::fs::remove_dir_all(&crate_dir);
}
