//! Library surface of the `pktflow` binary (08): argument grammar, run
//! pipeline, rendering, and dispatch — the binary is a thin `main`.

pub mod cli;
pub mod error;
pub mod render;
pub mod run;
pub mod summary;
pub mod views;

use std::io::Write;

use cli::{Cli, Command, Format};
use error::CliError;
use run::StopFlags;

/// Executes a parsed command line. Views print to stdout; the FR-27
/// summary always goes to stderr (pipe safety, 08.1).
pub fn dispatch(cli: Cli, stop: &StopFlags) -> Result<(), CliError> {
    match cli.command {
        Command::Streams(args) => {
            // The live view only ever redraws the tree; `--layer`'s flat
            // table (and `--merged`) has no live-redraw form, so it
            // implies --batch rather than silently ignoring the flag.
            if !args.batch && args.layer.is_none() {
                return match args.shared.format {
                    Format::Text => watch(&args, stop),
                    Format::Json => watch_json(&args, stop),
                };
            }
            let outcome = run_paced(&args, stop)?;
            match args.shared.format {
                Format::Text => {
                    let Some(snapshot) = &outcome.snapshot else {
                        return Err(CliError::Internal("streams run without snapshot".into()));
                    };
                    let body = match (&args.layer, args.merged) {
                        (Some(layer), false) => views::streams_flat(snapshot, layer),
                        (Some(layer), true) => views::streams_merged(snapshot, layer),
                        _ => views::streams_tree(snapshot, args.sort),
                    };
                    print!("{body}");
                }
                Format::Json => print_json(&views::json_envelope(&outcome))?,
            }
            eprint!("{}", summary::render(&outcome));
            Ok(())
        }
        Command::Stream(args) => {
            let outcome = run::run(&args.shared, stop, true, |_, _| {})?;
            let Some(snapshot) = &outcome.snapshot else {
                return Err(CliError::Internal("stream run without snapshot".into()));
            };
            // Resolve the selector in both formats so bad selectors exit
            // nonzero before anything reaches stdout.
            let detail = views::stream_detail(snapshot, &args.selector, args.full_series)?;
            match args.shared.format {
                Format::Text => print!("{detail}"),
                // 08.3 narrows the JSON to the selected stream.
                Format::Json => print_json(&views::json_envelope(&outcome))?,
            }
            eprint!("{}", summary::render(&outcome));
            Ok(())
        }
        Command::Packets(args) => {
            let stdout = std::io::stdout();
            // Stdout is line-buffered even when piped (a syscall per
            // line); this is meant to be the cheap, high-throughput
            // lens, so batch writes behind an explicit buffer instead.
            let mut out = std::io::BufWriter::with_capacity(64 * 1024, stdout.lock());
            let format = args.shared.format;
            let verbosity = args.verbose;
            let mut write_err: Option<std::io::Error> = None;
            let outcome =
                run::run_packets(&args.shared, stop, !args.no_streams, |index, event| {
                    if write_err.is_some() {
                        return;
                    }
                    let result = match format {
                        Format::Text => write!(
                            out,
                            "{}",
                            views::packet_block(
                                index,
                                &event.packet,
                                verbosity,
                                &event.tail_sample,
                                &event.heuristic,
                            )
                        ),
                        Format::Json => {
                            writeln!(out, "{}", views::packet_json(index, &event.packet))
                        }
                    };
                    if let Err(e) = result {
                        write_err = Some(e);
                    }
                })?;
            if write_err.is_none() {
                if let Err(e) = out.flush() {
                    write_err = Some(e);
                }
            }
            drop(out);
            if let Some(e) = write_err {
                // A closed pipe (e.g. `| head`) is a normal way to end.
                if e.kind() == std::io::ErrorKind::BrokenPipe {
                    return Ok(());
                }
                return Err(e.into());
            }
            eprint!("{}", summary::render(&outcome));
            Ok(())
        }
        Command::Ifaces => {
            let interfaces = pktflow_capture::list_interfaces()?;
            print!("{}", views::ifaces_text(&interfaces));
            Ok(())
        }
    }
}

/// `--batch` (08.2): the paced (or plain) end-of-run pipeline for
/// `streams` — run once, print a single final result. Opt-in; the
/// default is the live view below.
fn run_paced(args: &cli::StreamsArgs, stop: &StopFlags) -> Result<run::RunOutcome, CliError> {
    let pace = args.pace_ms.map(std::time::Duration::from_millis);
    run::run(&args.shared, stop, true, move |_, _| {
        if let Some(d) = pace {
            std::thread::sleep(d);
        }
    })
}

/// The default (08.2): full-screen redraw at least every second while
/// packets flow, plus a final frame after `finish()` that matches the
/// `--batch` tree. Snapshot-based; stdout only.
fn watch(args: &cli::StreamsArgs, stop: &StopFlags) -> Result<(), CliError> {
    use std::time::{Duration, Instant};
    let interval = Duration::from_secs(1);
    let pace = args.pace_ms.map(Duration::from_millis);
    let sort = args.sort;
    let source = args
        .shared
        .input
        .read
        .as_ref()
        .map(|p| p.display().to_string())
        .or_else(|| args.shared.input.iface.clone())
        .unwrap_or_default();

    let mut last_draw = Instant::now();
    let mut out = std::io::stdout();
    let outcome = run::run_observed(
        &args.shared,
        stop,
        true,
        move |_, _| {
            if let Some(d) = pace {
                std::thread::sleep(d);
            }
        },
        |agg| {
            if last_draw.elapsed() >= interval {
                last_draw = Instant::now();
                let frame = views::watch_frame(&agg.snapshot(), sort, &source);
                let _ = write!(out, "{frame}");
                let _ = out.flush();
            }
        },
    )?;

    // The final frame: exactly the --batch tree plus the footer.
    let Some(snapshot) = &outcome.snapshot else {
        return Err(CliError::Internal("watch run without snapshot".into()));
    };
    let source = &outcome.source_name;
    print!("{}", views::watch_frame(snapshot, args.sort, source));
    eprint!("{}", summary::render(&outcome));
    Ok(())
}

/// The default `--format json` (08.5): the NDJSON equivalent of
/// [`watch`] — `stream_new`/`stream_update`/`stream_closed` events as
/// the run progresses, a `summary` line always last (even after Ctrl-C's
/// graceful stop, which still reaches `finish()`). One `NdjsonTracker`
/// shared between the after-ingest poll and the aggregator's own
/// eviction sink — both run on this thread, never concurrently, so the
/// `Mutex` is a formality to satisfy the sink's `Send` bound.
fn watch_json(args: &cli::StreamsArgs, stop: &StopFlags) -> Result<(), CliError> {
    let pace = args.pace_ms.map(std::time::Duration::from_millis);
    let tracker = std::sync::Arc::new(std::sync::Mutex::new(views::NdjsonTracker::new()));

    let poll_tracker = std::sync::Arc::clone(&tracker);
    let evict_tracker = std::sync::Arc::clone(&tracker);

    let outcome = run::run_live(
        &args.shared,
        stop,
        move |_, _| {
            if let Some(d) = pace {
                std::thread::sleep(d);
            }
        },
        move |agg| {
            if let Ok(mut t) = poll_tracker.lock() {
                for event in t.poll(agg) {
                    println!("{event}");
                }
            }
        },
        move |ev| {
            if let Ok(mut t) = evict_tracker.lock() {
                println!("{}", t.on_evicted(&ev));
            }
        },
    )?;

    let Some(snapshot) = &outcome.snapshot else {
        return Err(CliError::Internal("watch json run without snapshot".into()));
    };
    println!(
        "{}",
        views::NdjsonTracker::summary_event(&outcome, snapshot)
    );
    eprint!("{}", summary::render(&outcome));
    Ok(())
}

fn print_json(doc: &serde_json::Value) -> Result<(), CliError> {
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, doc)
        .map_err(|e| CliError::Internal(format!("JSON serialization: {e}")))?;
    writeln!(stdout)?;
    Ok(())
}
