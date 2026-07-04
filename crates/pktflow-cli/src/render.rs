//! First-cut text rendering helpers. 08.5 owns the full FR-28 renderer
//! table (per-shape unit tests, IPv6 compression); these are the shared
//! primitives the views build on.

use std::time::{Duration, SystemTime};

use pktflow_core::{FieldMap, Value};

/// Protocol-aware value rendering (FR-28): the `(protocol, field)` table
/// entries, falling back to shape-based [`value_str`].
pub fn field_value_str(protocol: &str, name: &str, value: &Value) -> String {
    if protocol == "tcp" && name == "flags" {
        if let Value::U64(bits) = value {
            return tcp_flags_str(*bits);
        }
    }
    value_str(name, value)
}

/// Symbolic TCP flags: `SYN+ACK`, `PSH+ACK`, … (FR-28 table row).
pub fn tcp_flags_str(bits: u64) -> String {
    // ACK last: the conventional renderings are SYN+ACK, PSH+ACK, FIN+ACK.
    const NAMES: [(u64, &str); 8] = [
        (0x02, "SYN"),
        (0x01, "FIN"),
        (0x04, "RST"),
        (0x08, "PSH"),
        (0x20, "URG"),
        (0x40, "ECE"),
        (0x80, "CWR"),
        (0x10, "ACK"),
    ];
    let parts: Vec<&str> = NAMES
        .iter()
        .filter(|(bit, _)| bits & bit != 0)
        .map(|(_, name)| *name)
        .collect();
    if parts.is_empty() {
        "none".into()
    } else {
        parts.join("+")
    }
}

/// Human value rendering keyed on shape and field name (FR-28 sketch).
pub fn value_str(name: &str, value: &Value) -> String {
    match value {
        Value::Bytes(b) => bytes_str(name, b.as_slice()),
        Value::U64(v) => v.to_string(),
        Value::I64(v) => v.to_string(),
        Value::Bool(v) => v.to_string(),
        Value::Str(s) => s.to_string(),
        Value::List(items) => {
            let parts: Vec<String> = items.iter().map(|v| value_str(name, v)).collect();
            parts.join(",")
        }
        // Value is non_exhaustive: render future shapes via Debug rather
        // than failing to compile.
        other => format!("{other:?}"),
    }
}

fn bytes_str(name: &str, b: &[u8]) -> String {
    let mac_like = name.ends_with("_mac") || b.len() == 6;
    let addr_like = name.ends_with("_addr") || name.ends_with("_ip");
    match b.len() {
        4 if addr_like => format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]),
        16 if addr_like => {
            let mut segs = Vec::with_capacity(8);
            for chunk in b.chunks_exact(2) {
                segs.push(format!("{:x}", u16::from_be_bytes([chunk[0], chunk[1]])));
            }
            segs.join(":")
        }
        6 if mac_like => {
            let parts: Vec<String> = b.iter().map(|x| format!("{x:02x}")).collect();
            parts.join(":")
        }
        _ => {
            let mut s: String = b.iter().take(32).map(|x| format!("{x:02x}")).collect();
            if b.len() > 32 {
                s.push('…');
            }
            s
        }
    }
}

/// `field=value` pairs, insertion order — the raw endpoint summary until
/// 08.2's A ↔ B grammar lands.
pub fn fields_str(fields: &FieldMap) -> String {
    let parts: Vec<String> = fields
        .iter()
        .map(|(name, value)| format!("{name}={}", value_str(name, value)))
        .collect();
    parts.join(" ")
}

/// SI byte counts for tables: `987 B`, `12.3 kB`, `1.2 MB`.
pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "kB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut unit = 0;
    while v >= 1000.0 && unit < UNITS.len() - 1 {
        v /= 1000.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[unit])
    }
}

/// `HH:MM:SS` durations for tables.
pub fn human_duration(d: Duration) -> String {
    let s = d.as_secs();
    format!("{:02}:{:02}:{:02}", s / 3600, (s / 60) % 60, s % 60)
}

/// Time-of-day `HH:MM:SS.mmm` (UTC) for per-packet lines.
pub fn time_of_day(t: SystemTime) -> String {
    let since = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    let s = since.as_secs() % 86_400;
    format!(
        "{:02}:{:02}:{:02}.{:03}",
        s / 3600,
        (s / 60) % 60,
        s % 60,
        since.subsec_millis()
    )
}

/// Decimal with thousands separators for tables.
pub fn thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thousands_grouping() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1_000), "1,000");
        assert_eq!(thousands(1_234_567), "1,234,567");
    }

    #[test]
    fn byte_and_duration_scales() {
        assert_eq!(human_bytes(987), "987 B");
        assert_eq!(human_bytes(12_300), "12.3 kB");
        assert_eq!(human_bytes(1_200_000), "1.2 MB");
        assert_eq!(human_duration(Duration::from_secs(4 * 60 + 12)), "00:04:12");
        assert_eq!(human_duration(Duration::from_secs(3661)), "01:01:01");
    }

    #[test]
    fn shaped_bytes_render_as_addresses() {
        assert_eq!(
            value_str(
                "src_mac",
                &Value::from(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff][..])
            ),
            "aa:bb:cc:dd:ee:ff"
        );
        assert_eq!(
            value_str("src_addr", &Value::from(&[10, 0, 0, 5][..])),
            "10.0.0.5"
        );
        assert_eq!(value_str("id", &Value::from(&[0x01, 0x02][..])), "0102");
    }
}
