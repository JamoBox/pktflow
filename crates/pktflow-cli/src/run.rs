//! The shared run pipeline (08.1): open the selected source, pump packets
//! through the engine on a producer thread (07.1, D5), aggregate on this
//! one, and hand back the snapshot + totals every view renders from.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::sync_channel;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use pktflow_capture::{
    pump, CaptureError, FileSource, LiveConfig, LiveSource, PacketSource, PumpReport, RawPacket,
};
use pktflow_core::{DissectedPacket, LinkType, ParseOpts};
use pktflow_flows::{Aggregator, AggregatorConfig, AggregatorSnapshot, EvictionPolicy};

use crate::cli::SharedArgs;
use crate::error::CliError;

/// Channel capacity between pump and aggregation (07.1 backpressure).
const CHANNEL_CAPACITY: usize = 1024;

/// Ctrl-C wiring (08.1): one master flag plus every live source's own
/// stop handle, so a single trigger unblocks quiet interfaces too.
#[derive(Clone, Default)]
pub struct StopFlags {
    master: Arc<AtomicBool>,
    extra: Arc<Mutex<Vec<Arc<AtomicBool>>>>,
}

impl StopFlags {
    pub fn trigger(&self) {
        self.master.store(true, Ordering::SeqCst);
        if let Ok(extra) = self.extra.lock() {
            for flag in extra.iter() {
                flag.store(true, Ordering::SeqCst);
            }
        }
    }

    pub fn is_stopped(&self) -> bool {
        self.master.load(Ordering::SeqCst)
    }

    fn register(&self, flag: Arc<AtomicBool>) {
        if let Ok(mut extra) = self.extra.lock() {
            extra.push(flag);
        }
    }
}

/// Checks the master stop flag around a source with no flag of its own
/// (files); `Ok(None)` on stop is 07.1's clean end.
struct StopWrap<S> {
    inner: S,
    stop: Arc<AtomicBool>,
}

impl<S: PacketSource> PacketSource for StopWrap<S> {
    fn next_packet(&mut self) -> Result<Option<RawPacket<'_>>, CaptureError> {
        if self.stop.load(Ordering::SeqCst) {
            return Ok(None);
        }
        self.inner.next_packet()
    }

    fn link_type(&self) -> LinkType {
        self.inner.link_type()
    }

    fn stats(&self) -> pktflow_capture::CaptureStats {
        self.inner.stats()
    }
}

/// What a run was over, for summaries and JSON envelopes.
pub struct RunOutcome {
    pub snapshot: Option<AggregatorSnapshot>,
    pub report: PumpReport,
    pub elapsed: Duration,
    pub mode: &'static str,
    pub source_name: String,
}

fn open_source(
    shared: &SharedArgs,
    stop: &StopFlags,
) -> Result<(Box<dyn PacketSource + Send>, &'static str, String), CliError> {
    if let Some(path) = &shared.input.read {
        if shared.filter.is_some() {
            return Err(CliError::Usage(
                "-f/--filter applies to live capture (-i); filter files at capture time".into(),
            ));
        }
        let src = FileSource::open(path)?;
        let name = path.display().to_string();
        Ok((
            Box::new(StopWrap {
                inner: src,
                stop: Arc::clone(&stop.master),
            }),
            "offline",
            name,
        ))
    } else if let Some(iface) = &shared.input.iface {
        let src = LiveSource::open(
            iface,
            LiveConfig {
                bpf: shared.filter.clone(),
                ..LiveConfig::default()
            },
        )?;
        stop.register(src.stop_handle());
        Ok((Box::new(src), "live", iface.clone()))
    } else {
        // clap's required input group makes this unreachable in practice.
        Err(CliError::Usage(
            "one of -r FILE or -i IFACE is required".into(),
        ))
    }
}

fn aggregator_config(shared: &SharedArgs) -> AggregatorConfig {
    let eviction = if shared.wants_live_eviction() {
        EvictionPolicy::Live {
            idle_timeout: shared.idle_timeout(),
            close_linger: Duration::from_secs(15),
            max_streams: shared.max_streams(),
        }
    } else {
        EvictionPolicy::None
    };
    AggregatorConfig {
        eviction,
        ..AggregatorConfig::default()
    }
}

/// Runs the pipeline to completion. `on_packet` sees every dissected
/// packet in order (packets mode prints from it); `aggregate: false`
/// skips stream tracking entirely (`--no-streams`).
pub fn run(
    shared: &SharedArgs,
    stop: &StopFlags,
    aggregate: bool,
    mut on_packet: impl FnMut(u64, &DissectedPacket),
) -> Result<RunOutcome, CliError> {
    let engine = Arc::new(pktflow_plugins::default_engine());
    let (mut src, mode, source_name) = open_source(shared, stop)?;

    let opts = ParseOpts {
        depth: shared.depth.to_depth(),
        aggregation: aggregate,
        ..ParseOpts::default()
    };

    let started = Instant::now();
    let (tx, rx) = sync_channel::<DissectedPacket>(CHANNEL_CAPACITY);
    let pump_engine = Arc::clone(&engine);
    let limit = shared.count;
    let producer = std::thread::spawn(move || {
        let report = pump(&mut *src, &pump_engine, opts, &tx, limit);
        drop(tx); // closes the channel: the consumer's end-of-run signal
        report
    });

    let mut agg = aggregate.then(|| Aggregator::new(&engine, aggregator_config(shared)));
    for (index, packet) in rx.into_iter().enumerate() {
        on_packet(index as u64, &packet);
        if let Some(agg) = agg.as_mut() {
            agg.ingest(&packet);
        }
    }

    let report = producer
        .join()
        .map_err(|_| CliError::Internal("pump thread panicked".into()))??;

    let snapshot = agg.map(|mut agg| {
        agg.finish();
        agg.snapshot()
    });

    Ok(RunOutcome {
        snapshot,
        report,
        elapsed: started.elapsed(),
        mode,
        source_name,
    })
}
