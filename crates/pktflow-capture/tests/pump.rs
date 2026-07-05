//! 07.1: pump semantics over the MockSource — limits, totals,
//! backpressure, and the permission remediation text.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::sync_channel;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use pktflow_capture::{pump, CaptureError, MockSource, PERMISSION_REMEDIATION};
use pktflow_core::{Engine, LinkType, ParseOpts};

fn ts(ms: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_millis(ms)
}

/// PKTT frames (template plugin shape) so dissection is real but tiny.
fn frame(n: u16) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&n.to_be_bytes());
    f.extend_from_slice(&[0x00, 0x07, 0x00, 0x02, 0x00, 0x08]);
    f
}

fn engine() -> Engine {
    pktflow_plugins::default_engine()
}

fn opts() -> ParseOpts {
    ParseOpts {
        entry: Some("template"),
        ..ParseOpts::default()
    }
}

#[test]
fn pump_reports_totals_matching_the_fixture() {
    let packets: Vec<_> = (0..10u16).map(|n| (ts(u64::from(n)), frame(n))).collect();
    let total_bytes: u64 = packets.iter().map(|(_, b)| b.len() as u64).sum();
    let mut src = MockSource::new(packets, LinkType::ETHERNET);
    let engine = engine();
    let (tx, rx) = sync_channel(1024);

    let report = pump(&mut src, &engine, opts(), &tx, None).expect("pump");
    drop(tx);
    assert_eq!(report.packets, 10);
    assert_eq!(report.bytes, total_bytes);
    assert_eq!(report.timestamps_regressed, 0);
    assert_eq!(report.stats.received, 10);
    assert_eq!(rx.iter().count(), 10, "every packet reached the channel");
}

#[test]
fn pump_respects_the_limit_exactly() {
    let packets: Vec<_> = (0..100u16).map(|n| (ts(u64::from(n)), frame(n))).collect();
    let mut src = MockSource::new(packets, LinkType::ETHERNET);
    let engine = engine();
    let (tx, rx) = sync_channel(1024);

    let report = pump(&mut src, &engine, opts(), &tx, Some(7)).expect("pump");
    drop(tx);
    assert_eq!(report.packets, 7);
    assert_eq!(rx.iter().count(), 7);
}

#[test]
fn pump_counts_timestamp_regressions() {
    // 0, 5, 3 (regressed), 7, 6 (regressed): two regressions.
    let times = [0u64, 5, 3, 7, 6];
    let packets: Vec<_> = times
        .iter()
        .enumerate()
        .map(|(i, &t)| (ts(t), frame(i as u16)))
        .collect();
    let mut src = MockSource::new(packets, LinkType::ETHERNET);
    let engine = engine();
    let (tx, _rx) = sync_channel(1024);

    let report = pump(&mut src, &engine, opts(), &tx, None).expect("pump");
    assert_eq!(report.packets, 5, "regressed packets still ingest");
    assert_eq!(report.timestamps_regressed, 2);
}

#[test]
fn stalled_consumer_blocks_the_pump() {
    let packets: Vec<_> = (0..50u16).map(|n| (ts(u64::from(n)), frame(n))).collect();
    let engine = Arc::new(engine());
    // Capacity 2: without backpressure the pump would finish instantly.
    let (tx, rx) = sync_channel(2);
    let done = Arc::new(AtomicBool::new(false));

    let done_flag = Arc::clone(&done);
    let engine_ref = Arc::clone(&engine);
    let handle = std::thread::spawn(move || {
        let mut src = MockSource::new(packets, LinkType::ETHERNET);
        let report = pump(&mut src, &engine_ref, opts(), &tx, None).expect("pump");
        done_flag.store(true, Ordering::SeqCst);
        report
    });

    // Consumer stalls: the pump must be blocked, not buffering 50 packets.
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        !done.load(Ordering::SeqCst),
        "pump finished despite a stalled consumer — no backpressure"
    );

    // Drain; the pump completes with exact totals.
    let received = rx.iter().count();
    let report = handle.join().expect("pump thread");
    assert_eq!(received, 50);
    assert_eq!(report.packets, 50);
    assert!(done.load(Ordering::SeqCst));
}

#[test]
fn permission_remediation_covers_both_oses() {
    let err = CaptureError::PermissionDenied {
        device: "eth0".into(),
    };
    let text = err.to_string();
    assert!(text.contains("setcap"), "Linux remediation: {text}");
    assert!(text.contains("Npcap"), "Windows remediation: {text}");
    assert!(PERMISSION_REMEDIATION.contains("sudo"));
    assert!(PERMISSION_REMEDIATION.contains("Administrator"));
}
