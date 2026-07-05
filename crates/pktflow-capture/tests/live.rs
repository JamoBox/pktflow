//! 07.3: interface listing (unprivileged) and live-capture tests that
//! need capture rights (`#[ignore]` by default; run with
//! `cargo test -p pktflow-capture -- --ignored` where permitted).

use std::net::UdpSocket;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use pktflow_capture::{list_interfaces, LiveConfig, LiveSource, PacketSource};

#[test]
#[cfg_attr(
    windows,
    ignore = "requires the Npcap runtime, which CI installs only as an SDK"
)]
fn list_interfaces_returns_a_well_formed_list() {
    let interfaces = list_interfaces().expect("list");
    assert!(!interfaces.is_empty(), "at least loopback expected");
    for i in &interfaces {
        assert!(!i.name.is_empty());
    }
    assert!(
        interfaces.iter().any(|i| i.loopback),
        "a loopback interface is identifiable"
    );
}

/// The loopback device name isn't portable: Linux/macOS use a fixed
/// `lo`/`lo0`, but Npcap's Windows loopback adapter is identified by its
/// `loopback` flag rather than a fixed name (its NPF device string is
/// assigned per-install). Discovering it via `list_interfaces` avoids
/// hardcoding a name that doesn't hold across Windows installs.
fn loopback_device() -> String {
    if cfg!(windows) {
        list_interfaces()
            .expect("list")
            .into_iter()
            .find(|i| i.loopback)
            .expect("a loopback interface is present")
            .name
    } else if cfg!(target_os = "linux") {
        "lo".to_string()
    } else {
        "lo0".to_string()
    }
}

#[test]
#[ignore = "needs capture privileges (run as root / with cap_net_raw)"]
fn loopback_round_trip_captures_sent_udp() {
    const MARKER: &[u8] = b"pktflow-loopback-roundtrip";
    let device = loopback_device();
    let mut src = LiveSource::open(
        &device,
        LiveConfig {
            bpf: Some("udp and port 47999".into()),
            read_timeout: Duration::from_millis(100),
            ..LiveConfig::default()
        },
    )
    .expect("open loopback");

    // A timer arms the stop flag so a missed marker fails instead of
    // hanging, and markers are re-sent until then to defeat races
    // between activation and the first send.
    let stop = src.stop_handle();
    let timer_stop = stop.clone();
    let timer = std::thread::spawn(move || {
        let sender = UdpSocket::bind("127.0.0.1:0").expect("bind");
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline && !timer_stop.load(Ordering::SeqCst) {
            sender
                .send_to(MARKER, "127.0.0.1:47999")
                .expect("send marker");
            std::thread::sleep(Duration::from_millis(50));
        }
        timer_stop.store(true, Ordering::SeqCst);
    });

    let mut found = false;
    while let Some(raw) = src.next_packet().expect("capture read") {
        if raw.bytes.windows(MARKER.len()).any(|w| w == MARKER) {
            found = true;
            stop.store(true, Ordering::SeqCst);
            break;
        }
    }
    timer.join().expect("sender thread");
    assert!(found, "marker datagram captured on loopback");
}

#[test]
#[ignore = "needs capture privileges (run as root / with cap_net_raw)"]
fn stop_flag_shuts_down_a_quiet_capture_within_two_timeouts() {
    let device = loopback_device();
    let read_timeout = Duration::from_millis(200);
    let mut src = LiveSource::open(
        &device,
        LiveConfig {
            // A filter that matches nothing keeps the interface quiet.
            bpf: Some("udp and port 1".into()),
            read_timeout,
            ..LiveConfig::default()
        },
    )
    .expect("open loopback");

    let stop = src.stop_handle();
    let handle = std::thread::spawn(move || {
        let started = Instant::now();
        let result = src.next_packet().expect("clean stop");
        (result.is_none(), started.elapsed())
    });
    std::thread::sleep(read_timeout / 2);
    stop.store(true, Ordering::SeqCst);

    let (was_none, elapsed) = handle.join().expect("reader thread");
    assert!(was_none, "stop yields Ok(None), the clean end");
    assert!(
        elapsed <= read_timeout * 2,
        "shutdown within 2x read_timeout, took {elapsed:?}"
    );
}

#[test]
#[ignore = "needs capture privileges (run as root / with cap_net_raw)"]
fn invalid_bpf_on_a_real_device_names_the_filter() {
    let device = loopback_device();
    let err = match LiveSource::open(
        &device,
        LiveConfig {
            bpf: Some("nonsense filter syntax".into()),
            ..LiveConfig::default()
        },
    ) {
        Ok(_) => panic!("invalid filter must fail"),
        Err(e) => e,
    };
    assert!(err.to_string().contains("nonsense filter syntax"));
}
