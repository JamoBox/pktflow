//! 07.2: offline replay of hand-written `.pcap` and `.pcapng` fixtures —
//! exact counts, lens, timestamps; clean errors; determinism.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::mpsc::sync_channel;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use pktflow_capture::{pump, CaptureError, FileSource, PacketSource};
use pktflow_core::{LinkType, ParseOpts};
use pktflow_flows::{Aggregator, AggregatorConfig};

/// Three ethernet frames with distinct sizes and second-granular stamps.
fn fixture_frames() -> Vec<(u32, Vec<u8>)> {
    let mut frames = Vec::new();
    for (secs, extra) in [(100u32, 0usize), (101, 4), (102, 8)] {
        let mut f = vec![0xAA; 6];
        f.extend_from_slice(&[0xBB; 6]);
        f.extend_from_slice(&[0x99, 0x99]); // unclaimed ethertype
        f.extend_from_slice(&vec![0xCC; extra]);
        frames.push((secs, f));
    }
    frames
}

/// Classic pcap container (little-endian, DLT_EN10MB).
fn write_pcap(path: &Path, frames: &[(u32, Vec<u8>)]) {
    let mut out = Vec::new();
    out.extend_from_slice(&0xA1B2_C3D4u32.to_le_bytes()); // magic (µs)
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes()); // thiszone
    out.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    out.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
    out.extend_from_slice(&1u32.to_le_bytes()); // DLT_EN10MB
    for (secs, frame) in frames {
        out.extend_from_slice(&secs.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // µs
        out.extend_from_slice(&(frame.len() as u32).to_le_bytes()); // caplen
        out.extend_from_slice(&(frame.len() as u32).to_le_bytes()); // origlen
        out.extend_from_slice(frame);
    }
    fs::write(path, out).expect("write fixture");
}

/// Minimal pcapng: SHB + IDB(EN10MB) + one EPB per frame (µs resolution).
fn write_pcapng(path: &Path, frames: &[(u32, Vec<u8>)]) {
    let mut out = Vec::new();
    // Section Header Block.
    let shb_len = 28u32;
    out.extend_from_slice(&0x0A0D_0D0Au32.to_le_bytes());
    out.extend_from_slice(&shb_len.to_le_bytes());
    out.extend_from_slice(&0x1A2B_3C4Du32.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&u64::MAX.to_le_bytes()); // section length unknown
    out.extend_from_slice(&shb_len.to_le_bytes());
    // Interface Description Block.
    let idb_len = 20u32;
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&idb_len.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes()); // DLT_EN10MB
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&65535u32.to_le_bytes());
    out.extend_from_slice(&idb_len.to_le_bytes());
    // Enhanced Packet Blocks.
    for (secs, frame) in frames {
        let padded = frame.len().div_ceil(4) * 4;
        let epb_len = (32 + padded) as u32;
        let ts_micros = u64::from(*secs) * 1_000_000;
        out.extend_from_slice(&6u32.to_le_bytes());
        out.extend_from_slice(&epb_len.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // interface 0
        out.extend_from_slice(&((ts_micros >> 32) as u32).to_le_bytes());
        out.extend_from_slice(&(ts_micros as u32).to_le_bytes());
        out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        out.extend_from_slice(frame);
        out.resize(out.len() + (padded - frame.len()), 0);
        out.extend_from_slice(&epb_len.to_le_bytes());
    }
    fs::write(path, out).expect("write fixture");
}

fn tmp(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("pktflow-test-{}-{name}", std::process::id()));
    p
}

fn replay_and_collect(path: &Path) -> Vec<(SystemTime, usize)> {
    let mut src = FileSource::open(path).expect("open fixture");
    assert_eq!(src.link_type(), LinkType::ETHERNET);
    let mut seen = Vec::new();
    while let Some(raw) = src.next_packet().expect("read") {
        assert_eq!(raw.bytes.len(), raw.meta.caplen);
        seen.push((raw.meta.timestamp, raw.meta.origlen));
    }
    seen
}

#[test]
#[cfg_attr(
    windows,
    ignore = "requires the Npcap runtime, which CI installs only as an SDK"
)]
fn pcap_and_pcapng_replay_with_exact_counts_lens_and_timestamps() {
    let frames = fixture_frames();
    let expected: Vec<(SystemTime, usize)> = frames
        .iter()
        .map(|(secs, f)| {
            (
                SystemTime::UNIX_EPOCH + Duration::from_secs(u64::from(*secs)),
                f.len(),
            )
        })
        .collect();

    let pcap_path = tmp("fixture.pcap");
    write_pcap(&pcap_path, &frames);
    assert_eq!(replay_and_collect(&pcap_path), expected, ".pcap");
    let _ = fs::remove_file(&pcap_path);

    let ng_path = tmp("fixture.pcapng");
    write_pcapng(&ng_path, &frames);
    assert_eq!(replay_and_collect(&ng_path), expected, ".pcapng");
    let _ = fs::remove_file(&ng_path);
}

#[test]
#[cfg_attr(
    windows,
    ignore = "requires the Npcap runtime, which CI installs only as an SDK"
)]
fn bad_files_produce_clean_errors_and_empty_files_a_clean_run() {
    // Nonexistent.
    let missing = tmp("does-not-exist.pcap");
    assert!(matches!(
        FileSource::open(&missing),
        Err(CaptureError::FileFormat(_))
    ));

    // Not a capture file.
    let garbage = tmp("garbage.pcap");
    fs::write(&garbage, b"this is not a capture").expect("write");
    assert!(matches!(
        FileSource::open(&garbage),
        Err(CaptureError::FileFormat(_))
    ));
    let _ = fs::remove_file(&garbage);

    // Valid container, zero packets: clean empty run.
    let empty = tmp("empty.pcap");
    write_pcap(&empty, &[]);
    let mut src = FileSource::open(&empty).expect("open");
    assert!(src.next_packet().expect("eof").is_none());
    assert_eq!(src.stats().received, 0);
    let _ = fs::remove_file(&empty);
}

#[test]
#[cfg_attr(
    windows,
    ignore = "requires the Npcap runtime, which CI installs only as an SDK"
)]
fn out_of_order_timestamps_all_ingest_with_the_counter_set() {
    let mut frames = fixture_frames();
    frames.swap(0, 2); // 102, 101, 100: two regressions
    let path = tmp("ooo.pcap");
    write_pcap(&path, &frames);

    let engine = pktflow_plugins::default_engine();
    let mut src = FileSource::open(&path).expect("open");
    let (tx, rx) = sync_channel(1024);
    let report = pump(&mut src, &engine, ParseOpts::default(), &tx, None).expect("pump");
    drop(tx);

    assert_eq!(report.packets, 3, "all packets ingested");
    assert_eq!(report.timestamps_regressed, 2);
    assert_eq!(rx.iter().count(), 3);
    let _ = fs::remove_file(&path);
}

#[test]
#[cfg_attr(
    windows,
    ignore = "requires the Npcap runtime, which CI installs only as an SDK"
)]
fn two_replays_are_deterministic() {
    let path = tmp("determinism.pcap");
    write_pcap(&path, &fixture_frames());
    let engine = Arc::new(pktflow_plugins::default_engine());

    let run = || {
        let mut src = FileSource::open(&path).expect("open");
        let mut agg = Aggregator::new(&engine, AggregatorConfig::default());
        while let Some(raw) = src.next_packet().expect("read") {
            agg.ingest(&engine.dissect(raw.bytes, raw.meta, ParseOpts::default()));
        }
        agg.finish();
        format!("{:?}", agg.snapshot())
    };

    assert_eq!(run(), run(), "byte-identical serialized state");
    let _ = fs::remove_file(&path);
}
