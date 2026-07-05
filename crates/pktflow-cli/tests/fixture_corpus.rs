//! 09.2: the named fixture corpus, each paired with the stream tree (or,
//! where tree shape isn't the interesting property, the specific
//! behavior) it must produce through the real engine + aggregator.

mod support;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use pktflow_core::{LinkType, ParseOpts, StopClass, Value};
use pktflow_flows::{AggregatorConfig, CloseReason, EvictionPolicy, Rollup};
use support::expected::{assert_tree, run, run_with_config, ExpectedStream as E};
use support::gre_fixture;
use support::named_fixtures::*;

#[test]
fn gre_nested_wraps_a_full_inner_tcp_conversation() {
    // gre_nested reuses the existing gre_fixture (support/mod.rs) rather
    // than duplicating it — pairing it with an ExpectedStreams tree is
    // 09.2's addition here.
    let snapshot = run(&gre_fixture());
    assert_tree(
        &snapshot,
        &[
            E::new("ethernet", [2, 1]).child(E::new("ipv4", [2, 1]).child(
                E::new("gre", [3, 0]).child(E::new("ipv4", [2, 1]).child(E::new("tcp", [1, 2]))),
            )),
        ],
    );
}

#[test]
fn bidi_tcp_session_folds_into_one_lifecycled_stream() {
    let snapshot = run(&bidi_tcp_session());
    assert_tree(
        &snapshot,
        &[E::new("ethernet", [4, 3]).child(E::new("ipv4", [4, 3]).child(E::new("tcp", [3, 4])))],
    );
}

#[test]
fn encrypted_udp_to_an_unclaimed_port_creates_no_phantom_stream() {
    let snapshot = run(&encrypted_udp_no_phantom());
    assert_tree(
        &snapshot,
        &[E::new("ethernet", [1, 1]).child(E::new("ipv4", [1, 1]).child(E::new("udp", [2, 0])))],
    );
}

#[test]
fn vxlan_nested_wraps_a_full_inner_ethernet_conversation() {
    let snapshot = run(&vxlan_nested());
    assert_tree(
        &snapshot,
        &[E::new("ethernet", [1, 1]).child(
            E::new("ipv4", [1, 1]).child(
                E::new("udp", [1, 1]).child(
                    E::new("vxlan", [2, 0]).child(
                        E::new("ethernet", [1, 1])
                            .child(E::new("ipv4", [1, 1]).child(E::new("tcp", [1, 1]))),
                    ),
                ),
            ),
        )],
    );
}

#[test]
fn dual_parent_ip_stays_two_streams_under_two_mac_parents() {
    let snapshot = run(&dual_parent_ip());
    let leaf =
        || E::new("ethernet", [1, 0]).child(E::new("ipv4", [1, 0]).child(E::new("udp", [1, 0])));
    assert_tree(&snapshot, &[leaf(), leaf()]);
}

#[test]
fn dns_over_udp_session_forms_a_single_dns_stream() {
    let snapshot = run(&dns_over_udp_session());
    assert_tree(
        &snapshot,
        &[E::new("ethernet", [1, 1]).child(
            E::new("ipv4", [1, 1]).child(E::new("udp", [1, 1]).child(E::new("dns", [2, 0]))),
        )],
    );
}

#[test]
fn dhcp_dora_series_rollup_captures_the_order() {
    let snapshot = run(&dhcp_dora());
    assert_tree(
        &snapshot,
        &[E::new("ethernet", [2, 2]).child(
            E::new("ipv4", [2, 2]).child(E::new("udp", [2, 2]).child(E::new("dhcp", [4, 0]))),
        )],
    );

    // The tree shape isn't the point here — the order is: DISCOVER(1),
    // OFFER(2), REQUEST(3), ACK(5), in that exact sequence (05.4).
    let dhcp = snapshot
        .streams
        .iter()
        .find(|s| s.protocol == "dhcp")
        .expect("a dhcp stream");
    let Some(Rollup::Series { ring, .. }) = dhcp.rollups.get("msg_type") else {
        panic!("dhcp stream has no msg_type series rollup");
    };
    let observed: Vec<_> = ring.iter().map(|p| p.value.clone()).collect();
    assert_eq!(
        observed,
        vec![Value::U64(1), Value::U64(2), Value::U64(3), Value::U64(5),],
        "DORA order must be preserved"
    );
}

#[test]
fn idle_timeout_evicts_the_stale_stream_once_the_clock_advances() {
    let evicted = Arc::new(Mutex::new(Vec::new()));
    let sink_evicted = Arc::clone(&evicted);
    let config = AggregatorConfig {
        eviction: EvictionPolicy::Live {
            idle_timeout: Duration::from_secs(10),
            close_linger: Duration::from_secs(0),
            max_streams: usize::MAX,
        },
        sink: Some(Box::new(move |e| {
            sink_evicted
                .lock()
                .expect("sink runs on a single thread")
                .push((e.stream.protocol, e.reason));
        })),
        ..AggregatorConfig::default()
    };
    let snapshot = run_with_config(&idle_eviction(), config);

    let evicted = evicted.lock().expect("sink runs on a single thread");
    assert!(
        evicted
            .iter()
            .any(|(proto, reason)| *proto == "udp" && *reason == CloseReason::IdleTimeout),
        "expected an idle-timeout eviction of the first flow's udp stream, got {evicted:?}"
    );

    // Only the second (recent) flow survives to the final snapshot.
    assert_eq!(snapshot.roots.len(), 1);
    let root = snapshot
        .streams
        .iter()
        .find(|s| s.id == snapshot.roots[0])
        .expect("the surviving root is in the snapshot");
    assert_eq!(root.protocol, "ethernet");
}

#[test]
fn lru_pressure_evicts_the_least_recently_used_leaf() {
    let evicted = Arc::new(Mutex::new(Vec::new()));
    let sink_evicted = Arc::clone(&evicted);
    let config = AggregatorConfig {
        eviction: EvictionPolicy::Live {
            idle_timeout: Duration::from_secs(3600),
            close_linger: Duration::from_secs(0),
            max_streams: 2,
        },
        sink: Some(Box::new(move |e| {
            sink_evicted
                .lock()
                .expect("sink runs on a single thread")
                .push((e.stream.protocol, e.reason));
        })),
        ..AggregatorConfig::default()
    };
    let snapshot = run_with_config(&lru_pressure(), config);

    let evicted = evicted.lock().expect("sink runs on a single thread");
    assert_eq!(
        evicted.len(),
        1,
        "exactly one stream should have been evicted to respect max_streams=2, got {evicted:?}"
    );
    assert_eq!(evicted[0], ("ethernet", CloseReason::LruEvicted));

    assert_eq!(
        snapshot.roots.len(),
        2,
        "live_count must respect max_streams"
    );
}

#[test]
fn qinq_stack_dissects_both_tags_innermost_last() {
    // vlan is identity-less (06.2): the stream tree ignores it entirely.
    let snapshot = run(&qinq_stack());
    assert_tree(
        &snapshot,
        &[E::new("ethernet", [1, 0]).child(E::new("ipv4", [1, 0]).child(E::new("udp", [1, 0])))],
    );

    // The interesting property is the layer *stack*: two vlan layers,
    // outer (S-tag) vid 200 first, inner (C-tag) vid 100 last.
    let engine = pktflow_plugins::default_engine();
    let (meta, bytes) = qinq_stack()
        .packets()
        .into_iter()
        .next()
        .map(|(ts, b)| {
            (
                pktflow_core::PacketMeta {
                    timestamp: ts,
                    caplen: b.len(),
                    origlen: b.len(),
                    link_type: LinkType::ETHERNET,
                },
                b,
            )
        })
        .expect("one packet");
    let dissected = engine.dissect(&bytes, meta, ParseOpts::default());
    let protocols: Vec<_> = dissected.layers.iter().map(|l| l.protocol).collect();
    assert_eq!(protocols, ["ethernet", "vlan", "vlan", "ipv4", "udp"]);
    assert_eq!(
        dissected.layers[1].fields.get("vlan_id"),
        Some(&Value::U64(200)),
        "outer S-tag"
    );
    assert_eq!(
        dissected.layers[2].fields.get("vlan_id"),
        Some(&Value::U64(100)),
        "inner C-tag: innermost wins"
    );
}

#[test]
fn malformed_zoo_never_panics_and_classifies_cleanly() {
    let snapshot = run(&malformed_zoo());
    assert_eq!(
        snapshot.summary.packets, 5,
        "all 5 zoo packets were ingested"
    );

    let malformed = snapshot
        .summary
        .stop_classes
        .iter()
        .find(|(class, _)| *class == StopClass::Malformed)
        .map(|(_, n)| *n)
        .unwrap_or(0);
    assert!(
        malformed >= 3,
        "expected at least 3 malformed packets (eth truncation, tcp truncation, bad IHL), got {malformed} \
         (stop classes: {:?})",
        snapshot.summary.stop_classes
    );
}

#[test]
fn mixed_stop_reasons_hits_clean_unknown_and_malformed() {
    let snapshot = run(&mixed_stop_reasons());
    assert_eq!(snapshot.summary.packets, 3);
    for class in [
        StopClass::Clean,
        StopClass::UnknownPayload,
        StopClass::Malformed,
    ] {
        let n = snapshot
            .summary
            .stop_classes
            .iter()
            .find(|(c, _)| *c == class)
            .map(|(_, n)| *n)
            .unwrap_or(0);
        assert!(
            n >= 1,
            "expected at least one {class:?} packet, stop classes: {:?}",
            snapshot.summary.stop_classes
        );
    }
}

#[test]
fn every_named_fixture_dissects_without_panicking() {
    // A cheap top-level sanity net: every fixture in the corpus round-trips
    // through the real engine with no panic, on top of each fixture's own
    // dedicated test above.
    let engine = pktflow_plugins::default_engine();
    for capture in [
        bidi_tcp_session(),
        encrypted_udp_no_phantom(),
        vxlan_nested(),
        dual_parent_ip(),
        dns_over_udp_session(),
        dhcp_dora(),
        idle_eviction(),
        lru_pressure(),
        qinq_stack(),
        malformed_zoo(),
        mixed_stop_reasons(),
    ] {
        for (ts, bytes) in capture.packets() {
            let meta = pktflow_core::PacketMeta {
                timestamp: ts,
                caplen: bytes.len(),
                origlen: bytes.len(),
                link_type: LinkType::ETHERNET,
            };
            let _ = engine.dissect(&bytes, meta, ParseOpts::default());
        }
    }
}

#[test]
fn every_named_fixture_is_deterministic_in_process() {
    // 09.3's determinism e2e, in-process half: every fixture run twice
    // through the real engine + aggregator must produce an identical
    // snapshot (streams, stats, rollups, summary — everything). The
    // CLI/JSON half is `repeated_offline_runs_produce_byte_identical_json`
    // (json_output.rs), which already covers the subprocess path.
    for (name, capture) in [
        ("bidi_tcp_session", bidi_tcp_session()),
        ("encrypted_udp_no_phantom", encrypted_udp_no_phantom()),
        ("gre_nested", gre_fixture()),
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
        let (a, b) = (run(&capture), run(&capture));
        assert_eq!(a, b, "{name}: two in-process runs must be identical");
    }
}
