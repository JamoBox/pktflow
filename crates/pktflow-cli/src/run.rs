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
use pktflow_flows::{
    Aggregator, AggregatorConfig, AggregatorSnapshot, EvictedStream, EvictionPolicy,
};
use pktflow_view::SnapshotHub;

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

/// Validates `--entry` against the registered plugin list before it
/// ever reaches the engine: an unknown forced-entry name is a call-time
/// panic there (04.2 — a programmer error, not a data error), so the
/// CLI must catch it here and turn it into a clean usage error instead.
fn resolve_opts(
    shared: &SharedArgs,
    engine: &pktflow_core::Engine,
    aggregate: bool,
    diagnose_unknown: bool,
) -> Result<ParseOpts, CliError> {
    let entry = match &shared.entry {
        Some(name) => Some(
            engine
                .plugin_by_name(name)
                .ok_or_else(|| {
                    CliError::Usage(format!("--entry {name:?} is not a registered plugin"))
                })?
                .name(), // the plugin's own &'static str, not the user's owned String
        ),
        None => None,
    };
    Ok(ParseOpts {
        depth: shared.depth.to_depth(),
        aggregation: aggregate,
        entry,
        diagnose_unknown,
        ..ParseOpts::default()
    })
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

/// Cap on the unparsed-tail sample carried across the packets-mode
/// channel for `-vv` hex dumps; the true length is `packet.opaque_len`.
const TAIL_SAMPLE_CAP: usize = 64;

/// One packets-mode event (08.4): the dissected packet plus what the
/// plain pump path doesn't preserve across its channel — per-layer
/// heuristic flags (03.3) and a capped sample of the unparsed tail.
pub struct PacketEvent {
    pub packet: DissectedPacket,
    pub heuristic: Vec<bool>,
    pub tail_sample: Vec<u8>,
}

/// The packets-mode pipeline (08.4): a producer thread reads and
/// dissects (driving [`pktflow_core::LayerIter`] directly, since the
/// plain `pump`/`DissectedPacket` path drops heuristic flags and raw
/// bytes at the channel boundary); the consumer formats, writes, and
/// optionally aggregates — mirroring [`run`]'s split so packets mode
/// stays the cheap lens instead of serializing read+dissect+format+write
/// on one thread.
pub fn run_packets(
    shared: &SharedArgs,
    stop: &StopFlags,
    aggregate: bool,
    mut on_packet: impl FnMut(u64, &PacketEvent),
) -> Result<RunOutcome, CliError> {
    let engine = Arc::new(pktflow_plugins::default_engine());
    let opts = resolve_opts(shared, &engine, aggregate, false)?;
    let (mut src, mode, source_name) = open_source(shared, stop)?;
    let limit = shared.count;

    let started = Instant::now();
    let (tx, rx) = sync_channel::<PacketEvent>(CHANNEL_CAPACITY);
    let pump_engine = Arc::clone(&engine);
    let producer = std::thread::spawn(move || -> Result<PumpReport, CaptureError> {
        let mut report = PumpReport::default();
        let mut last_ts: Option<std::time::SystemTime> = None;
        let mut heuristic_flags = Vec::new();

        while limit.is_none_or(|l| report.packets < l) {
            let Some(raw) = src.next_packet()? else {
                break;
            };
            if last_ts.is_some_and(|t| raw.meta.timestamp < t) {
                report.timestamps_regressed += 1;
            }
            last_ts = Some(last_ts.map_or(raw.meta.timestamp, |t| t.max(raw.meta.timestamp)));

            let mut layers = pump_engine.layers(raw.bytes, &raw.meta, opts);
            heuristic_flags.clear();
            for step in layers.by_ref() {
                heuristic_flags.push(step.via_heuristic);
            }
            let packet = layers.into_packet(raw.meta);
            let tail_start = raw.bytes.len() - packet.opaque_len;
            let sample_len = packet.opaque_len.min(TAIL_SAMPLE_CAP);
            let tail_sample = raw.bytes[tail_start..tail_start + sample_len].to_vec();

            report.packets += 1;
            report.bytes += raw.meta.origlen as u64;
            let event = PacketEvent {
                packet,
                heuristic: heuristic_flags.clone(),
                tail_sample,
            };
            if tx.send(event).is_err() {
                break; // consumer gone (e.g. broken pipe): stop reading
            }
        }
        report.stats = src.stats();
        Ok(report)
    });

    let mut agg = aggregate.then(|| Aggregator::new(&engine, aggregator_config(shared)));
    for (index, event) in rx.into_iter().enumerate() {
        on_packet(index as u64, &event);
        if let Some(agg) = agg.as_mut() {
            agg.ingest(&event.packet);
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

/// Runs the pipeline to completion. `on_packet` sees every dissected
/// packet in order (packets mode prints from it); `aggregate: false`
/// skips stream tracking entirely (`--no-streams`).
pub fn run(
    shared: &SharedArgs,
    stop: &StopFlags,
    aggregate: bool,
    on_packet: impl FnMut(u64, &DissectedPacket),
) -> Result<RunOutcome, CliError> {
    run_observed(shared, stop, aggregate, false, on_packet, |_| {})
}

/// The `unknown` subcommand's pipeline (10.3): the *only* place
/// `ParseOpts::diagnose_unknown` is set — every other lens leaves it off
/// so the probing cost this enables stays scoped to this one command.
pub fn run_unknown(shared: &SharedArgs, stop: &StopFlags) -> Result<RunOutcome, CliError> {
    run_observed(shared, stop, true, true, |_, _| {}, |_| {})
}

/// [`run`] plus an after-ingest observer: the default live view (08.2)
/// redraws from aggregator snapshots between packets, on this thread
/// (D5's single writer), never mid-ingest.
pub fn run_observed(
    shared: &SharedArgs,
    stop: &StopFlags,
    aggregate: bool,
    diagnose_unknown: bool,
    mut on_packet: impl FnMut(u64, &DissectedPacket),
    mut on_ingested: impl FnMut(&Aggregator),
) -> Result<RunOutcome, CliError> {
    let engine = Arc::new(pktflow_plugins::default_engine());
    let opts = resolve_opts(shared, &engine, aggregate, diagnose_unknown)?;
    let (mut src, mode, source_name) = open_source(shared, stop)?;

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
            on_ingested(agg);
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

/// How often the hub pipeline publishes a fresh snapshot while packets
/// are flowing: frequent enough to feel live, cheap enough that the
/// snapshot copy stays off the hot path (its cost is bounded by
/// `max_streams`, measured in 09.4).
const PUBLISH_INTERVAL: Duration = Duration::from_millis(250);

/// A hub named for this run's source — the TUI/web header line.
pub fn hub_for(shared: &SharedArgs) -> SnapshotHub {
    match (&shared.input.read, &shared.input.iface) {
        (Some(path), _) => SnapshotHub::new(path.display().to_string(), "offline"),
        (_, Some(iface)) => SnapshotHub::new(iface.clone(), "live"),
        // clap's required input group makes this unreachable in practice.
        _ => SnapshotHub::new(String::new(), "offline"),
    }
}

/// Runs the full pipeline on a background thread, publishing throttled
/// snapshots into `hub`: the TUI and web server render from the hub while
/// this thread stays the aggregator's single writer (D5). Unknown
/// diagnostics are on — the Unknown lens is a first-class pane in both
/// UIs. Errors land in the hub (`set_error`) so a UI already on screen
/// can display them, and are also returned for the process exit code.
pub fn spawn_hub_pipeline(
    shared: SharedArgs,
    stop: StopFlags,
    hub: Arc<SnapshotHub>,
) -> std::thread::JoinHandle<Result<(), CliError>> {
    std::thread::spawn(move || {
        let publish_hub = Arc::clone(&hub);
        let mut last_publish: Option<Instant> = None;
        let result = run_observed(
            &shared,
            &stop,
            true,
            true,
            |_, _| {},
            |agg| {
                // First snapshot ships immediately; then throttled.
                if last_publish.is_none_or(|t| t.elapsed() >= PUBLISH_INTERVAL) {
                    last_publish = Some(Instant::now());
                    publish_hub.publish(agg.snapshot());
                }
            },
        );
        match result {
            Ok(outcome) => {
                if let Some(snapshot) = outcome.snapshot {
                    hub.publish(snapshot);
                }
                hub.mark_finished();
                Ok(())
            }
            Err(e) => {
                hub.set_error(e.to_string());
                Err(e)
            }
        }
    })
}

/// The default `--format json` NDJSON pipeline (08.5): mirrors
/// [`run_observed`]'s producer/consumer split, but always aggregates
/// and wires `on_evicted` into the aggregator's eviction sink so
/// `stream_closed` events fire the moment D2 closes a stream — not just
/// at `finish()`. Live captures exercise this over `-i`; the same path
/// is smoke-tested over `-r` with `--idle-timeout`/`--pace-ms` (D2
/// eviction accepts overrides for file sources too, 08.1), since a real
/// interface isn't available in CI.
pub fn run_live(
    shared: &SharedArgs,
    stop: &StopFlags,
    mut on_packet: impl FnMut(u64, &DissectedPacket),
    mut on_ingested: impl FnMut(&Aggregator),
    on_evicted: impl FnMut(EvictedStream) + Send + 'static,
) -> Result<RunOutcome, CliError> {
    let engine = Arc::new(pktflow_plugins::default_engine());
    let opts = resolve_opts(shared, &engine, true, false)?;
    let (mut src, mode, source_name) = open_source(shared, stop)?;

    let started = Instant::now();
    let (tx, rx) = sync_channel::<DissectedPacket>(CHANNEL_CAPACITY);
    let pump_engine = Arc::clone(&engine);
    let limit = shared.count;
    let producer = std::thread::spawn(move || {
        let report = pump(&mut *src, &pump_engine, opts, &tx, limit);
        drop(tx);
        report
    });

    let mut config = aggregator_config(shared);
    config.sink = Some(Box::new(on_evicted));
    let mut agg = Aggregator::new(&engine, config);
    for (index, packet) in rx.into_iter().enumerate() {
        on_packet(index as u64, &packet);
        agg.ingest(&packet);
        on_ingested(&agg);
    }

    let report = producer
        .join()
        .map_err(|_| CliError::Internal("pump thread panicked".into()))??;

    agg.finish();
    let snapshot = agg.snapshot();

    Ok(RunOutcome {
        snapshot: Some(snapshot),
        report,
        elapsed: started.elapsed(),
        mode,
        source_name,
    })
}
