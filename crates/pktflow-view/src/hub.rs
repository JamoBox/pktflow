//! The snapshot hub: the one-way bridge between the single-writer
//! aggregation thread (D5) and any number of UI readers (TUI panes, web
//! request handlers, SSE tickers). The writer publishes deep-copied
//! [`AggregatorSnapshot`]s; readers grab an `Arc` and render without ever
//! touching the aggregator.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::SystemTime;

use pktflow_flows::{AggregateSummary, AggregatorSnapshot, STOP_CLASSES};

/// A published snapshot never goes backwards: `generation` increments on
/// every publish, so readers can poll cheaply ("anything new?") without
/// cloning or comparing snapshots.
pub struct SnapshotHub {
    snapshot: RwLock<Arc<AggregatorSnapshot>>,
    generation: AtomicU64,
    finished: AtomicBool,
    error: Mutex<Option<String>>,
    source: String,
    mode: &'static str,
    /// Read progress over a file source (12.5): bytes consumed and the
    /// file's size. Total 0 = no progress to report (live capture).
    progress_read: AtomicU64,
    progress_total: AtomicU64,
}

/// The pre-first-publish snapshot: zero of everything.
fn empty_snapshot() -> AggregatorSnapshot {
    AggregatorSnapshot {
        streams: Vec::new(),
        roots: Vec::new(),
        summary: AggregateSummary {
            packets: 0,
            bytes: 0,
            streams_created: 0,
            streams_live: 0,
            flows_condensed: 0,
            key_errors: 0,
            per_protocol: Vec::new(),
            stop_classes: [
                (STOP_CLASSES[0], 0),
                (STOP_CLASSES[1], 0),
                (STOP_CLASSES[2], 0),
                (STOP_CLASSES[3], 0),
            ],
        },
        clock: SystemTime::UNIX_EPOCH,
        unknowns: Vec::new(),
    }
}

impl SnapshotHub {
    /// `source`/`mode` mirror the CLI `RunOutcome` naming: the capture
    /// file path or interface name, and `"offline"`/`"live"`.
    pub fn new(source: String, mode: &'static str) -> Self {
        Self {
            snapshot: RwLock::new(Arc::new(empty_snapshot())),
            generation: AtomicU64::new(0),
            finished: AtomicBool::new(false),
            error: Mutex::new(None),
            source,
            mode,
            progress_read: AtomicU64::new(0),
            progress_total: AtomicU64::new(0),
        }
    }

    /// Writer side (12.5): how far through the file the read is.
    /// `total` is set once at open; `read` advances with publishes.
    pub fn set_progress(&self, read: u64, total: u64) {
        self.progress_read.store(read, Ordering::Release);
        self.progress_total.store(total, Ordering::Release);
    }

    /// Reader side: `(bytes_read, bytes_total)`; `None` until a total is
    /// known (live captures never report one).
    pub fn progress(&self) -> Option<(u64, u64)> {
        let total = self.progress_total.load(Ordering::Acquire);
        (total > 0).then(|| {
            let read = self.progress_read.load(Ordering::Acquire).min(total);
            (read, total)
        })
    }

    /// Writer side: replace the published snapshot and bump the
    /// generation. Called from the aggregation thread only.
    pub fn publish(&self, snapshot: AggregatorSnapshot) {
        let arc = Arc::new(snapshot);
        match self.snapshot.write() {
            Ok(mut slot) => *slot = arc,
            Err(poisoned) => *poisoned.into_inner() = arc,
        }
        self.generation.fetch_add(1, Ordering::Release);
    }

    /// Reader side: the most recent published snapshot (cheap `Arc` clone).
    pub fn latest(&self) -> Arc<AggregatorSnapshot> {
        match self.snapshot.read() {
            Ok(slot) => Arc::clone(&slot),
            Err(poisoned) => Arc::clone(&poisoned.into_inner()),
        }
    }

    /// Monotonic publish counter; 0 = nothing published yet.
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// Writer side: the run reached its end (`finish()` ran, final
    /// snapshot published). Live UIs switch from "watching" to "done".
    pub fn mark_finished(&self) {
        self.finished.store(true, Ordering::Release);
    }

    pub fn is_finished(&self) -> bool {
        self.finished.load(Ordering::Acquire)
    }

    /// Writer side: the pipeline died. Readers surface this instead of an
    /// eternally-empty view.
    pub fn set_error(&self, message: String) {
        if let Ok(mut slot) = self.error.lock() {
            *slot = Some(message);
        }
        self.mark_finished();
    }

    pub fn error(&self) -> Option<String> {
        self.error.lock().ok().and_then(|slot| slot.clone())
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    pub fn mode(&self) -> &'static str {
        self.mode
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generations_advance_and_latest_tracks_publish() {
        let hub = SnapshotHub::new("test.pcap".into(), "offline");
        assert_eq!(hub.generation(), 0);
        assert_eq!(hub.latest().summary.packets, 0);
        assert!(!hub.is_finished());

        let mut snap = empty_snapshot();
        snap.summary.packets = 42;
        hub.publish(snap);
        assert_eq!(hub.generation(), 1);
        assert_eq!(hub.latest().summary.packets, 42);
    }

    #[test]
    fn error_marks_finished() {
        let hub = SnapshotHub::new("eth0".into(), "live");
        hub.set_error("no permission".into());
        assert!(hub.is_finished());
        assert_eq!(hub.error().as_deref(), Some("no permission"));
    }
}
