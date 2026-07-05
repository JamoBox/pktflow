//! 09.3 reference parity (PRD §8 "stream fidelity"): for each real capture
//! (09.2), a comparison harness asserts pktflow's per-layer packet/byte
//! accounting matches tshark's. tshark is a dev/CI dependency only — never
//! a runtime one (mirrors `pcap_sanity.rs`'s tool-availability gate).
//!
//! **Design note, and a documented model difference (per spec):** rather
//! than tshark's `-z conv,X` text report, this harness sums `frame.len`
//! over `tshark -Y <filter>` per layer. The conv report's byte columns
//! round to `kB`/`MB` once a conversation passes ~1000 bytes (e.g. 16847
//! exact bytes prints as `16 kB`) — fine for a human, useless for an exact
//! assertion. Filtered frame-length sums are exact and simpler.
//!
//! We compare *summed* packets/bytes per protocol layer, not individual
//! conversation rows: tshark resolves Ethernet addresses to vendor names
//! and renders TCP/UDP endpoints as `ip:port` strings, so pktflow's flow
//! keys don't share an exact string representation to match row-by-row
//! against. Nor do we compare conversation *counts* — `dhcp_dora.pcap` is
//! a real, expected case where they diverge: DHCP's client address
//! literally changes mid-exchange (`0.0.0.0` → the offered lease), so
//! tshark's address-based grouping sees two conversations where pktflow's
//! DHCP-aware flow key (correctly) sees one continuous exchange. Summed
//! packets/bytes still match exactly; only the grouping differs.
//!
//! `vxlan_overlay.pcap` needs one further adjustment. Per `DirStats`'s doc
//! comment in `pktflow-flows`, a frame's full wire length is counted once
//! per stream it belongs to — and a VXLAN frame belongs to *two* streams
//! per layer (outer + tunneled inner), so pktflow's `ethernet`/`ipv4`
//! totals are the sum of both, matching how tshark's own `-z conv,X`
//! report double-counts tunneled frames across its outer and inner rows.
//! A plain `-Y eth`/`-Y ip` frame-length sum only counts each frame once,
//! so this fixture needs the inner layer's contribution added explicitly:
//! every VXLAN frame carries a full inner Ethernet frame (`-Y vxlan`), but
//! only the ICMP-carrying ones carry an inner IPv4 header too (the ARP
//! ones don't — ARP has no IP layer), hence `vxlan && icmp` for the ipv4
//! adjustment specifically.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use pktflow_capture::{FileSource, PacketSource};
use pktflow_core::ParseOpts;
use pktflow_flows::{Aggregator, AggregatorConfig};

fn windows_skips() -> bool {
    cfg!(windows) // pktflow-capture needs the Npcap runtime at process start; CI installs only the SDK (see json_output.rs).
}

fn tshark_available() -> bool {
    Command::new("tshark").arg("--version").output().is_ok()
}

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/real")
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct LayerTotals {
    packets: u64,
    bytes: u64,
}

impl std::ops::Add for LayerTotals {
    type Output = LayerTotals;
    fn add(self, rhs: LayerTotals) -> LayerTotals {
        LayerTotals {
            packets: self.packets + rhs.packets,
            bytes: self.bytes + rhs.bytes,
        }
    }
}

/// tshark display filter -> pktflow protocol name, for the layers the
/// spec names (`conv,eth`/`conv,ip`/`conv,tcp`/`conv,udp`), plus ipv6
/// since two of our five real fixtures are IPv6.
const LAYERS: [(&str, &str); 5] = [
    ("eth", "ethernet"),
    ("ip", "ipv4"),
    ("ipv6", "ipv6"),
    ("tcp", "tcp"),
    ("udp", "udp"),
];

/// Sums `frame.len` over every frame tshark's filter matches — exact
/// packet/byte totals, no unit rounding.
fn tshark_frame_lens(pcap_path: &Path, filter: &str) -> LayerTotals {
    let out = Command::new("tshark")
        .arg("-r")
        .arg(pcap_path)
        .args(["-Y", filter, "-T", "fields", "-e", "frame.len"])
        .output()
        .expect("spawn tshark");
    assert!(
        out.status.success(),
        "tshark failed on {} (filter {filter:?}): {}",
        pcap_path.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    let mut totals = LayerTotals::default();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        totals.bytes += line.parse::<u64>().expect("frame.len is numeric");
        totals.packets += 1;
    }
    totals
}

/// Fixture-specific adjustments for known, documented model differences
/// (module doc comment above): `(protocol, extra tshark filter)` pairs
/// whose frame-length sum gets added to that protocol's base total.
fn known_adjustments(fixture: &str) -> &'static [(&'static str, &'static str)] {
    match fixture {
        "vxlan_overlay.pcap" => &[("ethernet", "vxlan"), ("ipv4", "vxlan && icmp")],
        _ => &[],
    }
}

fn tshark_layer_totals(pcap_path: &Path, fixture: &str) -> Vec<(&'static str, LayerTotals)> {
    let adjustments = known_adjustments(fixture);
    LAYERS
        .iter()
        .map(|&(filter, protocol)| {
            let mut total = tshark_frame_lens(pcap_path, filter);
            for &(adj_protocol, adj_filter) in adjustments {
                if adj_protocol == protocol {
                    total = total + tshark_frame_lens(pcap_path, adj_filter);
                }
            }
            (protocol, total)
        })
        .collect()
}

/// Runs a real capture through the actual engine + aggregator (no
/// eviction) and sums `at_layer_merged` per protocol layer — the D10 fold
/// that flattens pktflow's parent-scoped stream tree into the same
/// globally-counted shape tshark's conversation tables use, tunnels
/// included (module doc comment above).
fn pktflow_layer_totals(pcap_path: &Path) -> Vec<(&'static str, LayerTotals)> {
    let engine = Arc::new(pktflow_plugins::default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());
    let mut src = FileSource::open(pcap_path).expect("open real fixture");
    while let Some(raw) = src.next_packet().expect("read real fixture") {
        let dissected = engine.dissect(raw.bytes, raw.meta, ParseOpts::default());
        agg.ingest(&dissected);
    }

    LAYERS
        .iter()
        .map(|&(_, protocol)| {
            let mut t = LayerTotals::default();
            for row in agg.at_layer_merged(protocol) {
                for d in 0..2 {
                    t.packets += row.stats[d].packets;
                    t.bytes += row.stats[d].bytes;
                }
            }
            (protocol, t)
        })
        .collect()
}

fn assert_parity(fixture: &str) {
    let path = fixtures_dir().join(fixture);
    let tshark = tshark_layer_totals(&path, fixture);
    let pktflow = pktflow_layer_totals(&path);

    for ((protocol, want), (_, got)) in tshark.iter().zip(pktflow.iter()) {
        assert_eq!(got, want, "{fixture}: {protocol} layer parity vs tshark");
    }
}

#[test]
fn dhcp_dora_matches_tshark() {
    if windows_skips() || !tshark_available() {
        eprintln!("skipping: tshark unavailable or Windows without the Npcap runtime");
        return;
    }
    assert_parity("dhcp_dora.pcap");
}

#[test]
fn vxlan_overlay_matches_tshark() {
    if windows_skips() || !tshark_available() {
        eprintln!("skipping: tshark unavailable or Windows without the Npcap runtime");
        return;
    }
    assert_parity("vxlan_overlay.pcap");
}

#[test]
fn dns_lookup_matches_tshark() {
    if windows_skips() || !tshark_available() {
        eprintln!("skipping: tshark unavailable or Windows without the Npcap runtime");
        return;
    }
    assert_parity("dns_lookup.pcap");
}

#[test]
fn http_transaction_matches_tshark() {
    if windows_skips() || !tshark_available() {
        eprintln!("skipping: tshark unavailable or Windows without the Npcap runtime");
        return;
    }
    assert_parity("http_transaction.pcap");
}

#[test]
fn quic_unknown_matches_tshark() {
    if windows_skips() || !tshark_available() {
        eprintln!("skipping: tshark unavailable or Windows without the Npcap runtime");
        return;
    }
    assert_parity("quic_unknown.pcap");
}

/// The QUIC "honest-unknowns" §8 no-phantom metric, measured on real
/// traffic: pktflow has no QUIC plugin, so its payload must land as
/// opaque bytes on the UDP stream — never guessed at as some other
/// protocol, and never silently dropped from the accounting.
/// `quic_unknown.pcap` is a QUIC-only slice (filtered with tshark) of
/// Wireshark's own `quic-with-secrets.pcapng` test capture (see
/// `fixtures/real/README.md` for full provenance).
#[test]
fn quic_capture_produces_no_phantom_streams_beyond_udp() {
    if windows_skips() {
        eprintln!("skipping: Windows without the Npcap runtime");
        return;
    }
    let path = fixtures_dir().join("quic_unknown.pcap");
    let engine = Arc::new(pktflow_plugins::default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());
    let mut src = FileSource::open(&path).expect("open quic fixture");
    let mut total_packets = 0u64;
    while let Some(raw) = src.next_packet().expect("read quic fixture") {
        let dissected = engine.dissect(raw.bytes, raw.meta, ParseOpts::default());
        total_packets += 1;
        agg.ingest(&dissected);
    }
    let snapshot = agg.snapshot();

    assert_eq!(snapshot.summary.packets, total_packets);

    let allowed = ["ethernet", "ipv6", "udp"];
    for stream in &snapshot.streams {
        assert!(
            allowed.contains(&stream.protocol),
            "unexpected stream protocol {:?} — QUIC must never be misidentified as a claimed protocol",
            stream.protocol
        );
    }

    let udp_streams = agg.at_layer_merged("udp");
    assert_eq!(
        udp_streams.len(),
        1,
        "exactly one UDP conversation, no phantom splits"
    );
    let opaque: u64 = udp_streams
        .iter()
        .flat_map(|row| &row.nodes)
        .filter_map(|&id| snapshot.streams.iter().find(|s| s.id == id))
        .map(|s| s.opaque_bytes)
        .sum();
    assert!(
        opaque > 0,
        "QUIC's payload is unparsed application data — must be counted as opaque_bytes on the UDP stream"
    );

    let unknown_payload = snapshot
        .summary
        .stop_classes
        .iter()
        .find(|(class, _)| *class == pktflow_core::StopClass::UnknownPayload)
        .map(|(_, n)| *n)
        .unwrap_or(0);
    assert!(
        unknown_payload > 0,
        "QUIC frames stop at UDP with StopClass::UnknownPayload, never guessed at"
    );
}
