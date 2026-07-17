//! End-of-run summary (FR-27), printed to stderr for every subcommand
//! (08.1) so it never contaminates piped stdout.

use pktflow_core::StopClass;
use pktflow_flows::AggregateSummary;

use crate::render::{human_bytes, thousands};
use crate::run::RunOutcome;

fn stop_class_label(class: StopClass) -> &'static str {
    match class {
        StopClass::Clean => "clean",
        StopClass::UnknownPayload => "unknown-payload",
        StopClass::Malformed => "malformed",
        StopClass::Suspicious => "suspicious",
    }
}

/// JSON key for a stop class (D8 stable names).
pub fn stop_class_key(class: StopClass) -> &'static str {
    match class {
        StopClass::Clean => "clean",
        StopClass::UnknownPayload => "unknown_payload",
        StopClass::Malformed => "malformed",
        StopClass::Suspicious => "suspicious",
    }
}

/// The FR-27 text block: packets, stop classes, streams per protocol
/// (ever/live), capture drops (loud when nonzero), elapsed + rate.
pub fn render(outcome: &RunOutcome) -> String {
    let mut out = String::new();
    let secs = outcome.elapsed.as_secs_f64();
    let rate = if secs > 0.0 {
        outcome.report.packets as f64 / secs
    } else {
        0.0
    };
    out.push_str(&format!(
        "processed {} packets · {} in {:.2} s ({:.0} pkts/s)\n",
        thousands(outcome.report.packets),
        human_bytes(outcome.report.bytes),
        secs,
        rate,
    ));
    if outcome.report.timestamps_regressed > 0 {
        out.push_str(&format!(
            "timestamps out of order: {}\n",
            thousands(outcome.report.timestamps_regressed)
        ));
    }

    if let Some(snapshot) = &outcome.snapshot {
        out.push_str(&stops_line(&snapshot.summary));
        out.push_str(&streams_line(&snapshot.summary));
    }

    let drops = outcome.report.stats.dropped_kernel + outcome.report.stats.dropped_iface;
    if drops > 0 {
        out.push_str(&format!(
            "!! capture drops: {} kernel, {} interface — stream stats may be incomplete\n",
            thousands(outcome.report.stats.dropped_kernel),
            thousands(outcome.report.stats.dropped_iface),
        ));
    }
    out
}

fn stops_line(summary: &AggregateSummary) -> String {
    let parts: Vec<String> = summary
        .stop_classes
        .iter()
        .filter(|(_, count)| *count > 0)
        .map(|(class, count)| format!("{} {}", stop_class_label(*class), thousands(*count)))
        .collect();
    if parts.is_empty() {
        String::new()
    } else {
        format!("stops     {}\n", parts.join(" · "))
    }
}

fn streams_line(summary: &AggregateSummary) -> String {
    if summary.per_protocol.is_empty() {
        return String::new();
    }
    let parts: Vec<String> = summary
        .per_protocol
        .iter()
        .map(|p| format!("{} {}/{}", p.protocol, p.ever, p.live))
        .collect();
    let condensed = if summary.flows_condensed > 0 {
        format!(
            "   · {} flows condensed (D16)",
            thousands(summary.flows_condensed)
        )
    } else {
        String::new()
    };
    format!("streams   {}   (ever/live){condensed}\n", parts.join(" · "))
}
