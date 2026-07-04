//! 08.2 golden tests: tree and flat views, the tunnel chain, the
//! `--merged` fold, and the `--watch` smoke — text output is a contract;
//! goldens are updated deliberately (`UPDATE_GOLDENS=1`).

mod support;

use support::{assert_golden, dual_parent_fixture, gre_fixture, pktflow, tmp_pcap, tree_fixture};

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

// `--watch --format json` (NDJSON live events) is exercised in
// tests/json_output.rs (08.5), which supersedes this file's earlier
// placeholder that asserted it was rejected.
