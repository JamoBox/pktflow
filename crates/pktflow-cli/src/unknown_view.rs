//! The `pktflow unknown` lens (10.3): triage table, drill-down, export,
//! and scaffold — the dev/debug surface dedicated to 10.2's registry.

use std::path::{Path, PathBuf};

use pktflow_core::{Confidence, ProtocolName};
use pktflow_flows::{AggregatorSnapshot, UnknownGroup, UnknownKey};
use serde_json::{json, Value as Json};

use crate::error::CliError;
use crate::render::{hex_dump_lines, human_bytes, rfc3339, thousands};

/// How many near-misses the table view shows per row (drill-down is not
/// capped — full ranking there).
const TABLE_NEAR_MISS_CAP: usize = 3;

/// `predecessor → route` for `UnclaimedRoute`, bare `predecessor` for
/// `NoHeuristicWinner` (`RouteId::Display`, 03.1).
fn context_str(key: &UnknownKey) -> String {
    match key.route {
        Some(route) => format!("{} → {route}", key.predecessor),
        None => key.predecessor.to_string(),
    }
}

fn kind_str(key: &UnknownKey) -> &'static str {
    match key.route {
        Some(_) => "unclaimed route",
        None => "no heuristic winner",
    }
}

fn kind_json_key(key: &UnknownKey) -> &'static str {
    match key.route {
        Some(_) => "unclaimed_route",
        None => "no_heuristic_winner",
    }
}

fn near_misses_str(near_misses: &[(ProtocolName, Confidence)], cap: usize) -> String {
    let parts: Vec<String> = near_misses
        .iter()
        .take(cap)
        .map(|(name, score)| format!("{name}({})", score.get()))
        .collect();
    parts.join(" · ")
}

/// The groups a table view shows: filtered by `min_count`, capped at
/// `top`, in the registry's own deterministic order (10.2). Selector `#n`
/// numbers this exact list, 1-indexed.
fn visible_groups(snapshot: &AggregatorSnapshot, top: usize, min_count: u64) -> Vec<&UnknownGroup> {
    snapshot
        .unknowns
        .iter()
        .filter(|g| g.count >= min_count)
        .take(top)
        .collect()
}

/// Resolves `'#n'` against the same filtered/capped list a table view
/// with these `top`/`min_count` would print.
pub fn resolve_group<'a>(
    snapshot: &'a AggregatorSnapshot,
    selector: &str,
    top: usize,
    min_count: u64,
) -> Result<&'a UnknownGroup, CliError> {
    let Some(rest) = selector.strip_prefix('#') else {
        return Err(CliError::Usage(format!(
            "bad selector {selector:?}: unknown groups are selected with '#n' from a table view"
        )));
    };
    let Ok(n) = rest.parse::<usize>() else {
        return Err(CliError::Usage(format!(
            "bad selector {selector:?}: #n takes a number from a table view"
        )));
    };
    let groups = visible_groups(snapshot, top, min_count);
    if n == 0 || n > groups.len() {
        return Err(CliError::NotFound(format!(
            "no unknown group #{n} in this capture ({} shown)",
            groups.len()
        )));
    }
    Ok(groups[n - 1])
}

/// The default table (10.3): rows sorted by `count` desc (10.2's
/// `unknowns()` order), `--min-count`/`--top` applied. An explicit "none
/// observed" line replaces a bare empty table.
pub fn table_text(snapshot: &AggregatorSnapshot, top: usize, min_count: u64) -> String {
    let groups = visible_groups(snapshot, top, min_count);
    if groups.is_empty() {
        return "no unknown protocols observed\n".to_string();
    }

    let total_packets: u64 = groups.iter().map(|g| g.count).sum();
    let total_bytes: u64 = groups.iter().map(|g| g.bytes_total).sum();
    let mut out = format!(
        "UNKNOWN PROTOCOLS / STREAMS   ({} groups, {} packets, {} unclassified)\n\n",
        groups.len(),
        thousands(total_packets),
        human_bytes(total_bytes),
    );

    struct Row {
        n: String,
        context: String,
        kind: &'static str,
        count: String,
        bytes: String,
        span: String,
        near: String,
    }
    let rows: Vec<Row> = groups
        .iter()
        .enumerate()
        .map(|(i, g)| Row {
            n: (i + 1).to_string(),
            context: context_str(&g.key),
            kind: kind_str(&g.key),
            count: thousands(g.count),
            bytes: human_bytes(g.bytes_total),
            span: format!(
                "{} → {}",
                crate::render::time_of_day(g.first_seen),
                crate::render::time_of_day(g.last_seen)
            ),
            near: near_misses_str(&g.near_misses, TABLE_NEAR_MISS_CAP),
        })
        .collect();

    let n_w = rows.iter().map(|r| r.n.len()).max().unwrap_or(1).max(1);
    let ctx_w = rows
        .iter()
        .map(|r| r.context.chars().count())
        .max()
        .unwrap_or(0)
        .max("CONTEXT".len());
    let kind_w = rows
        .iter()
        .map(|r| r.kind.len())
        .max()
        .unwrap_or(0)
        .max("KIND".len());
    let count_w = rows
        .iter()
        .map(|r| r.count.len())
        .max()
        .unwrap_or(0)
        .max("COUNT".len());
    let bytes_w = rows
        .iter()
        .map(|r| r.bytes.len())
        .max()
        .unwrap_or(0)
        .max("BYTES".len());
    let span_w = rows
        .iter()
        .map(|r| r.span.chars().count())
        .max()
        .unwrap_or(0)
        .max("FIRST → LAST".len());

    out.push_str(&format!(
        "{:>n_w$}  {:<ctx_w$}  {:<kind_w$}  {:>count_w$}  {:>bytes_w$}  {:<span_w$}  NEAR MISSES\n",
        "#", "CONTEXT", "KIND", "COUNT", "BYTES", "FIRST → LAST",
    ));
    for r in &rows {
        out.push_str(&format!(
            "{:>n_w$}  {:<ctx_w$}  {:<kind_w$}  {:>count_w$}  {:>bytes_w$}  {:<span_w$}  {}\n",
            r.n, r.context, r.kind, r.count, r.bytes, r.span, r.near,
        ));
    }
    out
}

fn group_json(selector: usize, g: &UnknownGroup, near_miss_cap: Option<usize>) -> Json {
    let near_misses: Vec<Json> = g
        .near_misses
        .iter()
        .take(near_miss_cap.unwrap_or(g.near_misses.len()))
        .map(|(name, score)| json!({"protocol": name, "score": score.get()}))
        .collect();
    json!({
        "selector": selector,
        "predecessor": g.key.predecessor,
        "route": g.key.route.map(|r| r.to_string()),
        "kind": kind_json_key(&g.key),
        "count": g.count,
        "bytes_total": g.bytes_total,
        "bytes_min": g.bytes_min,
        "bytes_max": g.bytes_max,
        "first_seen": rfc3339(g.first_seen),
        "last_seen": rfc3339(g.last_seen),
        "near_misses": near_misses,
        "endpoints_overflow": g.endpoints_overflow,
    })
}

/// `--format json` table view (D8): same filter/cap as [`table_text`],
/// deliberately no raw sample bytes (`--export` covers those).
pub fn table_json(snapshot: &AggregatorSnapshot, top: usize, min_count: u64) -> Json {
    let groups = visible_groups(snapshot, top, min_count);
    let entries: Vec<Json> = groups
        .iter()
        .enumerate()
        .map(|(i, g)| group_json(i + 1, g, Some(TABLE_NEAR_MISS_CAP)))
        .collect();
    json!({ "pktflow": 1, "groups": entries })
}

/// `--format json` drill-down (D8): the full near-miss ranking, still no
/// raw bytes.
pub fn drilldown_json(selector: usize, group: &UnknownGroup) -> Json {
    json!({ "pktflow": 1, "groups": [group_json(selector, group, None)] })
}

/// Drill-down (10.3): full key, stats, bounded endpoint set (overflow
/// marker), full near-miss ranking, and up to `samples` retained samples
/// hex-dumped (`full_samples` lifts that display cap, bounded by what the
/// registry actually retained).
pub fn drilldown_text(
    selector: usize,
    g: &UnknownGroup,
    samples: usize,
    full_samples: bool,
) -> String {
    let mut out = format!(
        "#{selector}  {}   {}\n",
        context_str(&g.key),
        kind_str(&g.key)
    );
    out.push_str(&format!(
        "count     {}\nbytes     total {}  min {}  max {}\n",
        thousands(g.count),
        human_bytes(g.bytes_total),
        human_bytes(u64::from(g.bytes_min)),
        human_bytes(u64::from(g.bytes_max)),
    ));
    out.push_str(&format!(
        "seen      first {}  last {}\n",
        rfc3339(g.first_seen),
        rfc3339(g.last_seen),
    ));

    if g.endpoints.is_empty() {
        out.push_str("endpoints (none retained)\n");
    } else {
        let marker = if g.endpoints_overflow {
            " (≥64 distinct)"
        } else {
            ""
        };
        out.push_str(&format!("endpoints{marker}\n"));
        for e in &g.endpoints {
            out.push_str(&format!("  {} {:x?}\n", e.protocol, e.key.as_bytes()));
        }
    }

    if g.near_misses.is_empty() {
        out.push_str("near misses (none)\n");
    } else {
        out.push_str("near misses\n");
        for (name, score) in &g.near_misses {
            out.push_str(&format!("  {name}({})\n", score.get()));
        }
    }

    let show_n = if full_samples {
        g.samples.len()
    } else {
        samples.min(g.samples.len())
    };
    if g.samples.is_empty() {
        out.push_str("samples   (none retained)\n");
    } else {
        out.push_str(&format!(
            "samples   ({show_n} of {} retained)\n",
            g.samples.len()
        ));
        for (i, sample) in g.samples.iter().take(show_n).enumerate() {
            out.push_str(&format!("  sample {}: {} bytes\n", i + 1, sample.len()));
            for line in hex_dump_lines(sample) {
                out.push_str(&format!("    {line}\n"));
            }
        }
        if g.samples.len() > show_n {
            out.push_str(&format!(
                "  … {} more retained sample(s) not shown (--full-samples to show all)\n",
                g.samples.len() - show_n
            ));
        }
    }
    out
}

/// A filesystem-safe, human-legible slug for one `UnknownKey` — the
/// `--export` filename stem.
pub fn slug_for(key: &UnknownKey) -> String {
    let route = match key.route {
        Some(r) => r.to_string(),
        None => "no_heuristic_winner".to_string(),
    };
    let raw = format!("{}-{route}", key.predecessor);
    raw.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

/// `--export DIR` (10.3): every retained sample as `DIR/<slug>-<n>.bin`,
/// byte-identical to what the registry holds, plus `manifest.json`
/// (schema `schema/unknown-v1.json#/$defs/manifest`) — never original
/// byte offsets, which aren't recoverable post-hoc.
pub fn export_group(group: &UnknownGroup, dir: &Path, source: &str) -> Result<PathBuf, CliError> {
    std::fs::create_dir_all(dir)?;
    let slug = slug_for(&group.key);
    let mut sample_entries = Vec::new();
    for (i, sample) in group.samples.iter().enumerate() {
        let file_name = format!("{slug}-{}.bin", i + 1);
        std::fs::write(dir.join(&file_name), sample)?;
        sample_entries.push(json!({ "file": file_name, "bytes": sample.len() }));
    }
    let manifest = json!({
        "pktflow": 1,
        "key": {
            "predecessor": group.key.predecessor,
            "route": group.key.route.map(|r| r.to_string()),
        },
        "source": source,
        "count": group.count,
        "bytes_min": group.bytes_min,
        "bytes_max": group.bytes_max,
        "samples": sample_entries,
    });
    let manifest_path = dir.join("manifest.json");
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest)
            .map_err(|e| CliError::Internal(format!("manifest serialization: {e}")))?,
    )?;
    Ok(manifest_path)
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use pktflow_core::{FlowKey, RouteId};
    use pktflow_flows::EndpointKey;
    use smallvec::SmallVec;

    use super::*;

    fn group(predecessor: ProtocolName, route: Option<RouteId>, count: u64) -> UnknownGroup {
        UnknownGroup {
            key: UnknownKey { predecessor, route },
            count,
            bytes_total: count * 10,
            bytes_min: 5,
            bytes_max: 20,
            first_seen: SystemTime::UNIX_EPOCH,
            last_seen: SystemTime::UNIX_EPOCH + Duration::from_secs(5),
            endpoints: vec![EndpointKey {
                protocol: "ip",
                key: FlowKey::from_bytes(&[1, 2, 3, 4]),
            }],
            endpoints_overflow: false,
            near_misses: SmallVec::from_slice(&[("wireguard", Confidence::new(31))]),
            samples: [vec![0xAA, 0xBB].into_boxed_slice()].into_iter().collect(),
        }
    }

    fn snapshot(groups: Vec<UnknownGroup>) -> AggregatorSnapshot {
        AggregatorSnapshot {
            streams: Vec::new(),
            roots: Vec::new(),
            summary: pktflow_flows::AggregateSummary {
                packets: 0,
                bytes: 0,
                streams_created: 0,
                streams_live: 0,
                key_errors: 0,
                per_protocol: Vec::new(),
                stop_classes: [
                    (pktflow_core::StopClass::Clean, 0),
                    (pktflow_core::StopClass::UnknownPayload, 0),
                    (pktflow_core::StopClass::Malformed, 0),
                    (pktflow_core::StopClass::Suspicious, 0),
                ],
            },
            clock: SystemTime::UNIX_EPOCH,
            unknowns: groups,
        }
    }

    #[test]
    fn empty_table_prints_the_explicit_none_observed_line() {
        let snap = snapshot(Vec::new());
        assert_eq!(table_text(&snap, 20, 1), "no unknown protocols observed\n");
    }

    #[test]
    fn table_lists_both_context_kinds() {
        let snap = snapshot(vec![
            group("udp", Some(RouteId::UdpPort(51820)), 812),
            group("udp", None, 190),
        ]);
        let text = table_text(&snap, 20, 1);
        assert!(text.contains("udp → udp_port:51820"));
        assert!(text.contains("unclaimed route"));
        assert!(text.contains("no heuristic winner"));
        assert!(text.contains("wireguard(31)"));
    }

    #[test]
    fn min_count_filters_and_top_caps() {
        let snap = snapshot(vec![
            group("a", None, 100),
            group("b", None, 5),
            group("c", None, 1),
        ]);
        let text = table_text(&snap, 20, 2);
        assert!(text.contains("100"));
        assert!(text.contains("5"));
        assert!(!text.contains("(3 groups"));
        assert!(text.contains("(2 groups"));

        let text = table_text(&snap, 1, 1);
        assert!(text.contains("(1 groups") || text.contains("1 groups"));
    }

    #[test]
    fn selector_resolves_against_the_same_filtered_capped_list() {
        let snap = snapshot(vec![group("a", None, 100), group("b", None, 5)]);
        let g = resolve_group(&snap, "#1", 20, 1).expect("row 1");
        assert_eq!(g.key.predecessor, "a");
        let g = resolve_group(&snap, "#2", 20, 1).expect("row 2");
        assert_eq!(g.key.predecessor, "b");
        assert!(resolve_group(&snap, "#3", 20, 1).is_err());
        assert!(resolve_group(&snap, "bogus", 20, 1).is_err());
    }

    #[test]
    fn drilldown_shows_full_near_misses_and_overflow_marker() {
        let mut g = group("udp", Some(RouteId::UdpPort(4433)), 10);
        g.endpoints_overflow = true;
        g.near_misses = SmallVec::from_slice(&[
            ("a", Confidence::new(90)),
            ("b", Confidence::new(80)),
            ("c", Confidence::new(70)),
            ("d", Confidence::new(60)),
            ("e", Confidence::new(50)),
        ]);
        let text = drilldown_text(1, &g, 3, false);
        for name in ["a", "b", "c", "d", "e"] {
            assert!(text.contains(name), "full ranking, not capped at 3");
        }
        assert!(text.contains("≥64 distinct"));
    }

    #[test]
    fn hex_dump_appears_for_shown_samples_and_elides_the_rest() {
        let mut g = group("udp", None, 5);
        g.samples = [
            vec![0x01, 0x02].into_boxed_slice(),
            vec![0x03, 0x04].into_boxed_slice(),
            vec![0x05, 0x06].into_boxed_slice(),
        ]
        .into_iter()
        .collect();
        let text = drilldown_text(1, &g, 2, false);
        assert!(text.contains("0000  01 02"));
        assert!(text.contains("0000  03 04"));
        assert!(!text.contains("0000  05 06"));
        assert!(text.contains("1 more retained sample"));

        let full = drilldown_text(1, &g, 2, true);
        assert!(full.contains("0000  05 06"));
        assert!(!full.contains("more retained sample"));
    }

    #[test]
    fn export_writes_byte_identical_samples_and_a_manifest() {
        let dir = std::env::temp_dir().join(format!("pktflow-export-test-{}", std::process::id()));
        let mut g = group("udp", Some(RouteId::UdpPort(53)), 3);
        g.samples = [
            vec![0xDE, 0xAD].into_boxed_slice(),
            vec![0xBE, 0xEF, 0x01].into_boxed_slice(),
        ]
        .into_iter()
        .collect();

        let manifest_path = export_group(&g, &dir, "test.pcap").expect("export succeeds");
        let manifest_text = std::fs::read_to_string(&manifest_path).expect("read manifest.json");
        let manifest: Json = serde_json::from_str(&manifest_text).expect("manifest is valid JSON");
        assert_eq!(
            manifest["samples"]
                .as_array()
                .expect("samples is an array")
                .len(),
            2
        );

        let slug = slug_for(&g.key);
        let f1 = std::fs::read(dir.join(format!("{slug}-1.bin"))).expect("read sample 1");
        let f2 = std::fs::read(dir.join(format!("{slug}-2.bin"))).expect("read sample 2");
        assert_eq!(f1, vec![0xDE, 0xAD]);
        assert_eq!(f2, vec![0xBE, 0xEF, 0x01]);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
