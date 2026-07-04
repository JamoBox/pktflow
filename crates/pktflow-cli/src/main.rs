//! `pktflow` — network traffic stream-understanding CLI (task 08).
//! Thin `main`: shorthand rewrite, clap parse (usage errors exit 2),
//! Ctrl-C wiring, dispatch, exit-code mapping (08.1).

use std::sync::atomic::{AtomicUsize, Ordering};

use clap::Parser;
use pktflow_cli::cli::{apply_bare_path_shorthand, Cli};
use pktflow_cli::run::StopFlags;

fn main() {
    let argv = apply_bare_path_shorthand(std::env::args().collect());
    let cli = Cli::parse_from(argv); // clap exits 2 on usage errors

    let stop = StopFlags::default();
    let handler_stop = stop.clone();
    let presses = AtomicUsize::new(0);
    // First press: graceful (stop pump → finish() → final report).
    // Second press: immediate exit.
    let installed = ctrlc::set_handler(move || {
        if presses.fetch_add(1, Ordering::SeqCst) == 0 {
            eprintln!("\nstopping — finishing streams (Ctrl-C again to exit now)");
            handler_stop.trigger();
        } else {
            std::process::exit(130);
        }
    });
    if let Err(e) = installed {
        eprintln!("pktflow: Ctrl-C handler unavailable: {e}");
    }

    if let Err(e) = pktflow_cli::dispatch(cli, &stop) {
        eprintln!("pktflow: {e}");
        std::process::exit(e.exit_code());
    }
}
