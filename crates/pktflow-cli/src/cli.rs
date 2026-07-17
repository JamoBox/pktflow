//! The argument grammar (08.1): subcommands map one-to-one onto the
//! product's lenses; input selection and shared flags factored once.

use std::path::PathBuf;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};

/// Network traffic as streams, not packets.
#[derive(Parser, Debug)]
#[command(
    name = "pktflow",
    version,
    about = "Network traffic as streams, not packets",
    long_about = "Dissects captured traffic into a hierarchy of streams \
                  (conversations) at every protocol layer.\n\
                  Shorthand: `pktflow FILE` = `pktflow streams -r FILE`."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Stream hierarchy view — the default lens
    Streams(StreamsArgs),
    /// Everything about one stream
    Stream(StreamArgs),
    /// Per-packet debug lens
    Packets(PacketsArgs),
    /// Interactive terminal UI: browse and drill into streams
    Tui(TuiArgs),
    /// Web UI + JSON API over the stream hierarchy
    Serve(ServeArgs),
    /// List capturable interfaces
    Ifaces,
    /// Dev/debug lens over unclassified traffic (10)
    Unknown(UnknownArgs),
}

/// Names accepted as a subcommand, used by the bare-path shorthand to
/// decide whether the first argument is a path.
pub const SUBCOMMANDS: [&str; 7] = [
    "streams", "stream", "packets", "tui", "serve", "ifaces", "unknown",
];

#[derive(Args, Debug)]
pub struct StreamsArgs {
    #[command(flatten)]
    pub shared: SharedArgs,
    /// Flat table of one protocol's streams instead of the tree
    #[arg(long, value_name = "PROTO")]
    pub layer: Option<String>,
    /// Fold same-key streams across parents (needs --layer)
    #[arg(long, requires = "layer")]
    pub merged: bool,
    /// Run once and print a single final result instead of the default
    /// live view (full-screen text, redrawn every second; NDJSON events
    /// for `--format json`)
    #[arg(long)]
    pub batch: bool,
    /// Testing hook: sleep N ms per packet to simulate replay pacing
    #[arg(long, value_name = "MS", hide = true)]
    pub pace_ms: Option<u64>,
    /// Sibling sort order in the tree
    #[arg(long, value_enum, default_value_t = SortOrder::Bytes)]
    pub sort: SortOrder,
    /// Show only streams matching a query expression: free text,
    /// /regex/, and field comparisons combined with AND/OR/NOT — e.g.
    /// 'proto == dns AND bytes > 10k' (see docs/query-language.md)
    #[arg(long = "where", value_name = "QUERY")]
    pub where_: Option<String>,
}

#[derive(Args, Debug)]
pub struct StreamArgs {
    #[command(flatten)]
    pub shared: SharedArgs,
    /// `#id` from a streams view, or `PROTO A B` endpoint expression
    #[arg(value_name = "STREAM-SELECTOR")]
    pub selector: String,
    /// Render every series point (default elides beyond 20)
    #[arg(long)]
    pub full_series: bool,
}

#[derive(Args, Debug)]
pub struct PacketsArgs {
    #[command(flatten)]
    pub shared: SharedArgs,
    /// -v: per-layer field blocks; -vv: + hex dump of unparsed payload
    #[arg(short, action = clap::ArgAction::Count)]
    pub verbose: u8,
    /// Skip stream aggregation (maximum-throughput triage)
    #[arg(long)]
    pub no_streams: bool,
}

/// The dev/debug lens over the unknown registry (10.3).
///
/// No selector: the triage table. `'#n'`: drill-down, optionally paired
/// with `--export` (dump retained samples) or `--scaffold` (starter
/// plugin file) — both require a selector, since they act on one group.
#[derive(Args, Debug)]
pub struct UnknownArgs {
    #[command(flatten)]
    pub shared: SharedArgs,
    /// `#n` from a prior table view; omit for the table itself
    #[arg(value_name = "SELECTOR")]
    pub selector: Option<String>,
    /// Table: cap the number of rows shown
    #[arg(long, value_name = "N", default_value_t = 20)]
    pub top: usize,
    /// Table: hide groups seen fewer than N times
    #[arg(long, value_name = "N", default_value_t = 1)]
    pub min_count: u64,
    /// Drill-down: how many retained samples to hex-dump
    #[arg(long, value_name = "N", default_value_t = 3)]
    pub samples: usize,
    /// Drill-down: lift the display cap on shown samples (still bounded
    /// by what the registry actually retained)
    #[arg(long, requires = "selector")]
    pub full_samples: bool,
    /// Drill-down: write every retained sample plus a manifest.json to DIR
    #[arg(
        long,
        value_name = "DIR",
        requires = "selector",
        conflicts_with = "scaffold"
    )]
    pub export: Option<PathBuf>,
    /// Drill-down: scaffold a starter plugin file named NAME from this group
    #[arg(long, value_name = "NAME", requires = "selector")]
    pub scaffold: Option<String>,
    /// Testing hook: scaffold into this directory instead of the real
    /// `pktflow-plugins` crate
    #[arg(long, hide = true)]
    pub plugins_dir: Option<PathBuf>,
}

/// The interactive TUI (12.1): same input grammar as `streams`, full
/// unknown diagnostics on (the Unknown tab is a first-class pane).
#[derive(Args, Debug)]
pub struct TuiArgs {
    #[command(flatten)]
    pub shared: SharedArgs,
}

/// The web UI + JSON API (12.2).
#[derive(Args, Debug)]
pub struct ServeArgs {
    #[command(flatten)]
    pub shared: SharedArgs,
    /// Address to bind the web UI + API on
    #[arg(long, value_name = "ADDR", default_value = "127.0.0.1:8320")]
    pub listen: String,
}

/// Exactly one input: a capture file or a live interface.
#[derive(Args, Clone, Debug)]
#[group(id = "input", required = true, multiple = false)]
pub struct InputArgs {
    /// Read packets from a capture file (offline replay)
    #[arg(short = 'r', long = "read", value_name = "FILE")]
    pub read: Option<PathBuf>,
    /// Capture live from a named interface
    #[arg(short = 'i', long = "iface", value_name = "IFACE")]
    pub iface: Option<String>,
}

#[derive(Args, Clone, Debug)]
pub struct SharedArgs {
    #[command(flatten)]
    pub input: InputArgs,
    /// Kernel BPF filter string
    #[arg(short = 'f', long = "filter", value_name = "BPF")]
    pub filter: Option<String>,
    /// Stop after N packets
    #[arg(short = 'c', long = "count", value_name = "N")]
    pub count: Option<u64>,
    /// Field extraction depth
    #[arg(long, value_enum, default_value_t = DepthArg::Structural)]
    pub depth: DepthArg,
    /// Output format
    #[arg(long, value_enum, default_value_t = Format::Text)]
    pub format: Format,
    /// Live mode: seconds of quiet before a stream is evicted
    #[arg(long, value_name = "SECS")]
    pub idle_timeout: Option<u64>,
    /// Live mode: hard cap on concurrently tracked streams
    #[arg(long, value_name = "N")]
    pub max_streams: Option<usize>,
    /// Clamp per-stream series rollups to N points (0 = unclamped).
    /// Default: unclamped for batch runs; 128 under `tui`/`serve`.
    #[arg(long, value_name = "N")]
    pub series_cap: Option<usize>,
    /// Show every flow individually: disable high-cardinality
    /// condensation (D16)
    #[arg(long)]
    pub no_condense: bool,
    /// Live same-anchor flows shown individually before further ones
    /// condense into one node [default: 256]
    #[arg(long, value_name = "K", conflicts_with = "no_condense")]
    pub condense_threshold: Option<usize>,
    /// Force the first layer to a named plugin instead of routing by
    /// link type — for protocols reached only by direct-by-name
    /// encapsulation (06.1's tutorial "pktt" space) or a raw capture of
    /// a single known protocol with no link-layer framing.
    #[arg(long, value_name = "PLUGIN")]
    pub entry: Option<String>,
}

impl SharedArgs {
    /// Live eviction defaults (D2), with the two override flags applied.
    /// Offline (`-r`) runs use `EvictionPolicy::None` unless overridden.
    pub fn wants_live_eviction(&self) -> bool {
        self.input.iface.is_some() || self.idle_timeout.is_some() || self.max_streams.is_some()
    }

    pub fn idle_timeout(&self) -> Duration {
        Duration::from_secs(self.idle_timeout.unwrap_or(300))
    }

    pub fn max_streams(&self) -> usize {
        self.max_streams.unwrap_or(1_000_000)
    }

    /// The 12.2 series clamp: `--series-cap 0` = explicitly unclamped;
    /// unset = unclamped here (the hub pipelines apply their own
    /// interactive default before this is read).
    pub fn series_max_cap(&self) -> Option<usize> {
        match self.series_cap {
            Some(0) => None,
            other => other,
        }
    }

    /// D16's K, with `--no-condense` mapping to 0 (off).
    pub fn condense_threshold(&self) -> usize {
        if self.no_condense {
            0
        } else {
            self.condense_threshold
                .unwrap_or(pktflow_flows::DEFAULT_CONDENSE_THRESHOLD)
        }
    }
}

#[derive(ValueEnum, Clone, Copy, PartialEq, Eq, Debug)]
pub enum DepthArg {
    Keys,
    Structural,
    Full,
}

impl DepthArg {
    pub fn to_depth(self) -> pktflow_core::Depth {
        match self {
            DepthArg::Keys => pktflow_core::Depth::Keys,
            DepthArg::Structural => pktflow_core::Depth::Structural,
            DepthArg::Full => pktflow_core::Depth::Full,
        }
    }
}

#[derive(ValueEnum, Clone, Copy, PartialEq, Eq, Debug)]
pub enum Format {
    Text,
    Json,
}

#[derive(ValueEnum, Clone, Copy, PartialEq, Eq, Debug)]
pub enum SortOrder {
    Bytes,
    Packets,
    FirstSeen,
    Duration,
}

/// Rewrites `pktflow FILE` to `pktflow streams -r FILE` (the
/// zero-friction path). Applies only when the first free argument is not
/// a subcommand, not a flag, and names an existing file — anything else
/// falls through to clap for a proper usage error.
pub fn apply_bare_path_shorthand(mut argv: Vec<String>) -> Vec<String> {
    if let Some(first) = argv.get(1) {
        if !first.starts_with('-')
            && !SUBCOMMANDS.contains(&first.as_str())
            && std::path::Path::new(first).is_file()
        {
            argv.splice(1..2, ["streams".into(), "-r".into(), first.clone()]);
        }
    }
    argv
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn grammar_is_internally_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn read_and_iface_conflict() {
        let err = Cli::try_parse_from(["pktflow", "streams", "-r", "f.pcap", "-i", "eth0"])
            .expect_err("conflicting inputs");
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn an_input_is_required() {
        let err = Cli::try_parse_from(["pktflow", "streams"]).expect_err("no input");
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn merged_requires_layer() {
        let err = Cli::try_parse_from(["pktflow", "streams", "-r", "f.pcap", "--merged"])
            .expect_err("--merged without --layer");
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn defaults_follow_the_spec() {
        let cli = Cli::try_parse_from(["pktflow", "streams", "-r", "f.pcap"]).expect("parse");
        let Command::Streams(args) = cli.command else {
            panic!("streams subcommand");
        };
        assert_eq!(args.shared.depth, DepthArg::Structural);
        assert_eq!(args.shared.format, Format::Text);
        assert_eq!(args.sort, SortOrder::Bytes);
        assert!(!args.shared.wants_live_eviction());
        assert_eq!(args.shared.entry, None);
    }

    #[test]
    fn entry_flag_parses() {
        let cli =
            Cli::try_parse_from(["pktflow", "streams", "-r", "f.pcap", "--entry", "template"])
                .expect("parse");
        let Command::Streams(args) = cli.command else {
            panic!("streams subcommand");
        };
        assert_eq!(args.shared.entry.as_deref(), Some("template"));
    }

    #[test]
    fn shorthand_rewrites_only_existing_files() {
        let dir = std::env::temp_dir();
        let file = dir.join(format!("pktflow-shorthand-{}.pcap", std::process::id()));
        std::fs::write(&file, b"x").expect("fixture");
        let path = file.to_string_lossy().into_owned();

        let argv = apply_bare_path_shorthand(vec!["pktflow".into(), path.clone()]);
        assert_eq!(argv, vec!["pktflow", "streams", "-r", path.as_str()]);
        let _ = std::fs::remove_file(&file);

        // Nonexistent path: untouched, so clap reports the usage error.
        let argv = apply_bare_path_shorthand(vec!["pktflow".into(), "nope.pcap".into()]);
        assert_eq!(argv, vec!["pktflow", "nope.pcap"]);

        // Subcommands and flags: never rewritten.
        let argv = apply_bare_path_shorthand(vec!["pktflow".into(), "ifaces".into()]);
        assert_eq!(argv, vec!["pktflow", "ifaces"]);
        let argv = apply_bare_path_shorthand(vec!["pktflow".into(), "--help".into()]);
        assert_eq!(argv, vec!["pktflow", "--help"]);
    }
}
