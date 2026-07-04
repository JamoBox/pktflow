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
            if args.watch {
                return Err(CliError::Usage(
                    "--watch arrives with 08.2; run without it for the end-of-run view".into(),
                ));
            }
            let outcome = run::run(&args.shared, stop, true, |_, _| {})?;
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
            let detail = views::stream_detail(snapshot, &args.selector)?;
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
            let mut out = stdout.lock();
            let format = args.shared.format;
            let mut write_err: Option<std::io::Error> = None;
            let outcome = run::run(&args.shared, stop, !args.no_streams, |index, pkt| {
                if write_err.is_some() {
                    return;
                }
                let line = match format {
                    Format::Text => views::packet_line(index, pkt),
                    Format::Json => views::packet_json(index, pkt).to_string(),
                };
                if let Err(e) = writeln!(out, "{line}") {
                    write_err = Some(e);
                }
            })?;
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

fn print_json(doc: &serde_json::Value) -> Result<(), CliError> {
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, doc)
        .map_err(|e| CliError::Internal(format!("JSON serialization: {e}")))?;
    writeln!(stdout)?;
    Ok(())
}
