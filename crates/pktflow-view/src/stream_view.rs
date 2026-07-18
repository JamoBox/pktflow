//! Stream-level display derivations shared by every lens: canonical
//! A ↔ B endpoint rendering (08.2 line grammar), lineage chains, and the
//! per-stream totals each table column sums from.

use std::collections::HashMap;
use std::time::SystemTime;

use pktflow_core::PacketDirection;
use pktflow_flows::{AggregatorSnapshot, CloseReason, Stream, StreamId};

use crate::fmt::value_str;

/// Id → stream lookup for tree walks within one snapshot.
pub fn by_id(snapshot: &AggregatorSnapshot) -> HashMap<StreamId, &Stream> {
    snapshot.streams.iter().map(|s| (s.id, &**s)).collect()
}

pub fn total_packets(s: &Stream) -> u64 {
    s.stats[0].packets + s.stats[1].packets
}

pub fn total_bytes(s: &Stream) -> u64 {
    s.stats[0].bytes + s.stats[1].bytes
}

/// Rendered endpoint pair in canonical A ↔ B order (08.2 line grammar):
/// `key_fields` come from the creating packet, so `initiator` says which
/// side of each `src_*`/`dst_*` pair is endpoint A. Ports render with a
/// `:` prefix (their IP parent shows the addresses). Non-paired key
/// fields (`vni`, GRE `key`) render as `name=value`; the constant `app`
/// field is dropped — the protocol name already says it.
pub fn endpoints_str(s: &Stream) -> String {
    let (a_side, b_side, extras) = endpoint_sides(s);
    let mut out = String::new();
    if !a_side.is_empty() {
        out.push_str(&format!("{a_side} ↔ {b_side}"));
    }
    if !extras.is_empty() {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(&extras.join(" "));
    }
    out
}

/// The two rendered endpoint sides (canonical A, B) plus non-paired key
/// fields. Empty side strings = no endpoint pair (qualifier-keyed).
/// A condensed node (D16) renders its anchor as A and `*` as B — the
/// varying side is, by definition, many values.
pub fn endpoint_sides(s: &Stream) -> (String, String, Vec<String>) {
    if let Some(info) = s.condensed.as_deref() {
        let anchor = s
            .key_fields
            .get(info.ephemeral_field)
            .map(|v| {
                let text = value_str(info.ephemeral_field, v);
                if info.ephemeral_field.ends_with("port") {
                    format!(":{text}")
                } else {
                    text
                }
            })
            .unwrap_or_default();
        let star = if info.ephemeral_field.ends_with("port") {
            ":*"
        } else {
            "*"
        };
        return (anchor, star.into(), Vec::new());
    }
    let mut a_side = Vec::new();
    let mut b_side = Vec::new();
    let mut extras = Vec::new();
    for (name, value) in s.key_fields.iter() {
        if let Some(suffix) = name.strip_prefix("src_") {
            let dst_name = format!("dst_{suffix}");
            if let Some(dst_value) = s.key_fields.get(&dst_name) {
                let mut src_str = value_str(name, value);
                let mut dst_str = value_str(&dst_name, dst_value);
                if suffix.ends_with("port") {
                    src_str = format!(":{src_str}");
                    dst_str = format!(":{dst_str}");
                }
                match s.initiator {
                    PacketDirection::AtoB => {
                        a_side.push(src_str);
                        b_side.push(dst_str);
                    }
                    PacketDirection::BtoA => {
                        a_side.push(dst_str);
                        b_side.push(src_str);
                    }
                }
                continue;
            }
        }
        if name.starts_with("dst_") && s.key_fields.get(&format!("src_{}", &name[4..])).is_some() {
            continue; // consumed with its src_ partner
        }
        if *name != "app" {
            extras.push(format!("{name}={}", value_str(name, value)));
        }
    }
    (a_side.join(","), b_side.join(","), extras)
}

/// Row marker for a condensed node (D16): `× N flows`, with `≥` once
/// the member tally overflowed. `None` for ordinary streams.
pub fn condensed_marker(s: &Stream) -> Option<String> {
    let info = s.condensed.as_deref()?;
    let ge = if info.overflow { "≥" } else { "" };
    Some(format!(
        "× {ge}{} flows",
        crate::fmt::thousands(info.member_flows)
    ))
}

/// Root-to-parent ancestry as `proto #id (endpoints) ▸ …` — the
/// drill-down's breadcrumb.
pub fn lineage_str(s: &Stream, ids: &HashMap<StreamId, &Stream>) -> String {
    let mut lineage = Vec::new();
    let mut cursor = s.parent;
    while let Some(pid) = cursor {
        let Some(parent) = ids.get(&pid) else { break };
        let endpoints = endpoints_str(parent);
        let entry = if endpoints.is_empty() {
            format!("{} #{}", parent.protocol, parent.created_seq)
        } else {
            format!("{} #{} ({endpoints})", parent.protocol, parent.created_seq)
        };
        lineage.push(entry);
        cursor = parent.parent;
    }
    lineage.reverse();
    lineage.join(" ▸ ")
}

/// A child plus its single-child descendants: `ipv4 #3 (…) ▸ tcp #4 (…)`
/// — the inner stack of a tunnel visible from the drill-down.
pub fn child_chain_str(child: &Stream, ids: &HashMap<StreamId, &Stream>) -> String {
    let mut parts = Vec::new();
    let mut cursor = Some(child);
    while let Some(s) = cursor {
        let endpoints = endpoints_str(s);
        if endpoints.is_empty() {
            parts.push(format!("{} #{}", s.protocol, s.created_seq));
        } else {
            parts.push(format!("{} #{} ({endpoints})", s.protocol, s.created_seq));
        }
        cursor = match s.children.as_slice() {
            [only] => ids.get(only).copied(),
            _ => None,
        };
    }
    parts.join(" ▸ ")
}

/// The capture's observed time extent: earliest `first_seen` to latest
/// `last_seen` across all streams — the timeline views' x-axis. `None`
/// while no streams exist yet.
pub fn capture_span(snapshot: &AggregatorSnapshot) -> Option<(SystemTime, SystemTime)> {
    let start = snapshot.streams.iter().map(|s| s.first_seen).min()?;
    let end = snapshot.streams.iter().map(|s| s.last_seen).max()?;
    Some((start, end))
}

/// Close reasons as display strings (hyphenated display convention; the
/// wire names in [`crate::json`] use snake_case).
pub fn close_reason_str(reason: CloseReason) -> &'static str {
    match reason {
        CloseReason::ProtocolClose => "protocol-close",
        CloseReason::IdleTimeout => "idle-timeout",
        CloseReason::LruEvicted => "lru-evicted",
        CloseReason::CaptureEnd => "capture-end",
    }
}
