use std::sync::RwLock;
use std::time::{Duration, SystemTime};

use pktflow_core::{FieldMap, RouteId, Value};

type RouteResolver = Box<dyn Fn(RouteId) -> Option<String> + Send + Sync>;

static RESOLVER: RwLock<Option<RouteResolver>> = RwLock::new(None);

pub fn register_route_resolver<F>(f: F)
where
    F: Fn(RouteId) -> Option<String> + Send + Sync + 'static,
{
    if let Ok(mut guard) = RESOLVER.write() {
        *guard = Some(Box::new(f));
    }
}

pub fn resolve_route_name(route_id: RouteId) -> Option<String> {
    if let Ok(guard) = RESOLVER.read() {
        if let Some(resolver) = guard.as_ref() {
            return resolver(route_id);
        }
    }
    None
}

fn get_u64(value: &Value) -> Option<u64> {
    match value {
        Value::U64(v) => Some(*v),
        Value::I64(v) => u64::try_from(*v).ok(),
        _ => None,
    }
}

fn format_protocol_display_name(name: &str) -> String {
    match name {
        "ipv4" => "IPv4".to_string(),
        "ipv6" => "IPv6".to_string(),
        "icmpv4" => "ICMPv4".to_string(),
        "icmpv6" => "ICMPv6".to_string(),
        "dhcpv6" => "DHCPv6".to_string(),
        "bacnet_ip" => "BACnet/IP".to_string(),
        "pvst_plus" => "PVST+".to_string(),
        "netflow9" => "NetFlow 9".to_string(),
        other => other.to_uppercase(),
    }
}

fn resolve_field_route_id(protocol: &str, name: &str, val: u64) -> Option<RouteId> {
    if name == "ethertype"
        || (protocol == "gre" && name == "protocol")
        || (protocol == "llc" && name == "pid")
    {
        if let Ok(v) = u16::try_from(val) {
            return Some(RouteId::EtherType(v));
        }
    }
    if name == "next_header" || (protocol == "ipv4" && name == "protocol") {
        if let Ok(v) = u8::try_from(val) {
            return Some(RouteId::IpProtocol(v));
        }
    }
    if protocol == "udp" && (name == "src_port" || name == "dst_port" || name == "port") {
        if let Ok(v) = u16::try_from(val) {
            return Some(RouteId::UdpPort(v));
        }
    }
    if protocol == "tcp" && (name == "src_port" || name == "dst_port" || name == "port") {
        if let Ok(v) = u16::try_from(val) {
            return Some(RouteId::TcpPort(v));
        }
    }
    if protocol == "llc" && (name == "dsap" || name == "ssap") {
        return Some(RouteId::Custom {
            space: "llc_dsap",
            id: val,
        });
    }
    if protocol == "icmpv6" && name == "type" {
        return Some(RouteId::Custom {
            space: "icmpv6_type",
            id: val,
        });
    }
    None
}

fn format_resolved_value(route_id: &RouteId, name: &str) -> String {
    let display_name = format_protocol_display_name(name);
    match route_id {
        RouteId::EtherType(val) => format!("{display_name} (0x{val:04x})"),
        RouteId::Custom {
            space: "snap_pid",
            id,
        } => format!("{display_name} (0x{id:04x})"),
        RouteId::Custom {
            space: "llc_dsap",
            id,
        } => format!("{display_name} (0x{id:02x})"),
        RouteId::IpProtocol(val) => format!("{display_name} ({val})"),
        RouteId::UdpPort(val) => format!("{display_name} ({val})"),
        RouteId::TcpPort(val) => format!("{display_name} ({val})"),
        RouteId::LinkType(val) => format!("{display_name} ({val})"),
        RouteId::Custom { id, .. } => format!("{display_name} ({id})"),
    }
}

fn format_unresolved_value(route_id: &RouteId) -> String {
    match route_id {
        RouteId::EtherType(val) => format!("0x{val:04x}"),
        RouteId::Custom {
            space: "snap_pid",
            id,
        } => format!("0x{id:04x}"),
        RouteId::Custom {
            space: "llc_dsap",
            id,
        } => format!("0x{id:02x}"),
        RouteId::IpProtocol(val) => val.to_string(),
        RouteId::UdpPort(val) => val.to_string(),
        RouteId::TcpPort(val) => val.to_string(),
        RouteId::LinkType(val) => val.to_string(),
        RouteId::Custom { id, .. } => id.to_string(),
    }
}

/// RFC 3339 UTC (D8 JSON timestamps): `2026-07-02T12:04:01Z`, with a
/// fractional-second suffix only when the packet timestamp carries one.
pub fn rfc3339(t: SystemTime) -> String {
    time::OffsetDateTime::from(t)
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
}

/// Protocol-aware value rendering (FR-28): the `(protocol, field)` table
/// entries, falling back to shape-based [`value_str`].
pub fn field_value_str(protocol: &str, name: &str, value: &Value) -> String {
    if protocol == "tcp" && name == "flags" {
        if let Value::U64(bits) = value {
            return tcp_flags_str(*bits);
        }
    }

    if let Some(val) = get_u64(value) {
        if let Some(route_id) = resolve_field_route_id(protocol, name, val) {
            if let Some(resolved_name) = resolve_route_name(route_id) {
                return format_resolved_value(&route_id, &resolved_name);
            } else {
                return format_unresolved_value(&route_id);
            }
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
            let mut a = [0u8; 16];
            a.copy_from_slice(b);
            ipv6_compressed_str(&a)
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

/// RFC 5952 canonical IPv6 text form: lowercase, no leading zeros per
/// group, the longest run of ≥2 all-zero groups collapsed to `::`
/// (leftmost run wins a tie, §4.2.3), IPv4-mapped addresses
/// (`::ffff:0:0/96`) written with a dotted-quad tail (§5).
fn ipv6_compressed_str(b: &[u8; 16]) -> String {
    let mut groups = [0u16; 8];
    for (i, g) in groups.iter_mut().enumerate() {
        *g = u16::from_be_bytes([b[2 * i], b[2 * i + 1]]);
    }

    if groups[0..5] == [0, 0, 0, 0, 0] && groups[5] == 0xffff {
        return format!("::ffff:{}.{}.{}.{}", b[12], b[13], b[14], b[15]);
    }

    let mut best: Option<(usize, usize)> = None; // (start, len), longest run ≥2, leftmost tie
    let mut i = 0;
    while i < groups.len() {
        if groups[i] == 0 {
            let start = i;
            while i < groups.len() && groups[i] == 0 {
                i += 1;
            }
            let len = i - start;
            if len >= 2 && best.is_none_or(|(_, best_len)| len > best_len) {
                best = Some((start, len));
            }
        } else {
            i += 1;
        }
    }

    match best {
        Some((start, len)) => {
            let head: Vec<String> = groups[..start].iter().map(|g| format!("{g:x}")).collect();
            let tail: Vec<String> = groups[start + len..]
                .iter()
                .map(|g| format!("{g:x}"))
                .collect();
            format!("{}::{}", head.join(":"), tail.join(":"))
        }
        None => groups
            .iter()
            .map(|g| format!("{g:x}"))
            .collect::<Vec<_>>()
            .join(":"),
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

/// Offset-prefixed hex dump lines (10.3): 16 bytes/line, 4-hex-digit
/// offset, lowercase byte pairs — the shared shape every hex-dumping view
/// builds on.
pub fn hex_dump_lines(bytes: &[u8]) -> Vec<String> {
    bytes
        .chunks(16)
        .enumerate()
        .map(|(i, chunk)| {
            let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
            format!("{:04x}  {}", i * 16, hex.join(" "))
        })
        .collect()
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
    fn hex_dump_lines_are_offset_prefixed_sixteen_per_line() {
        let bytes: Vec<u8> = (0..20u8).collect();
        let lines = hex_dump_lines(&bytes);
        assert_eq!(lines.len(), 2);
        assert_eq!(
            lines[0],
            "0000  00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f"
        );
        assert_eq!(lines[1], "0010  10 11 12 13");
    }

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

    fn v6(name: &str, groups: [u16; 8]) -> String {
        let mut b = [0u8; 16];
        for (i, g) in groups.iter().enumerate() {
            b[2 * i..2 * i + 2].copy_from_slice(&g.to_be_bytes());
        }
        value_str(name, &Value::from(&b[..]))
    }

    #[test]
    fn ipv6_unspecified_and_loopback() {
        assert_eq!(v6("src_addr", [0; 8]), "::");
        assert_eq!(v6("src_addr", [0, 0, 0, 0, 0, 0, 0, 1]), "::1");
    }

    #[test]
    fn ipv6_compresses_the_longest_zero_run() {
        // 2001:db8::1:0:0:1 — a single zero-group is never compressed,
        // so only the two-group run compresses.
        assert_eq!(
            v6("src_addr", [0x2001, 0x0db8, 0, 0, 1, 0, 0, 1]),
            "2001:db8::1:0:0:1"
        );
    }

    #[test]
    fn ipv6_leftmost_run_wins_a_length_tie() {
        // Two runs of length 2 (groups 1-2 and groups 4-5): RFC 5952
        // §4.2.3 requires the leftmost.
        assert_eq!(
            v6("dst_addr", [0x2001, 0, 0, 1, 0, 0, 1, 1]),
            "2001::1:0:0:1:1"
        );
    }

    #[test]
    fn ipv6_embedded_v4_uses_dotted_quad_tail() {
        assert_eq!(
            v6("dst_addr", [0, 0, 0, 0, 0, 0xffff, 0xc000, 0x0201]),
            "::ffff:192.0.2.1"
        );
    }

    #[test]
    fn ipv6_no_leading_zeros_and_lowercase() {
        assert_eq!(
            v6("src_addr", [0x2001, 0x0db8, 0xabcd, 0, 0, 0, 0, 1]),
            "2001:db8:abcd::1"
        );
    }

    #[test]
    fn tcp_flags_render_symbolically() {
        assert_eq!(tcp_flags_str(0x02), "SYN");
        assert_eq!(tcp_flags_str(0x12), "SYN+ACK");
        assert_eq!(tcp_flags_str(0x18), "PSH+ACK");
        assert_eq!(tcp_flags_str(0x11), "FIN+ACK");
        assert_eq!(tcp_flags_str(0), "none");
        assert_eq!(
            field_value_str("tcp", "flags", &Value::U64(0x12)),
            "SYN+ACK"
        );
        // Non-tcp or non-flags fields fall through to shape rendering.
        assert_eq!(field_value_str("udp", "flags", &Value::U64(2)), "2");
    }

    #[test]
    fn other_bytes_are_lowercase_hex_with_elision_past_32() {
        let exactly_32 = [0xABu8; 32];
        let rendered = value_str("opaque", &Value::from(&exactly_32[..]));
        assert_eq!(rendered.len(), 64, "32 bytes = 64 hex chars, no ellipsis");
        assert!(!rendered.contains('…'));

        let over_32 = [0xCDu8; 33];
        let rendered = value_str("opaque", &Value::from(&over_32[..]));
        assert_eq!(rendered.len(), 64 + '…'.len_utf8());
        assert!(rendered.ends_with('…'));
        assert!(rendered.starts_with("cdcd"));
    }

    #[test]
    fn decimal_values_render_plain() {
        assert_eq!(value_str("count", &Value::U64(42)), "42");
        assert_eq!(value_str("delta", &Value::I64(-7)), "-7");
    }

    #[test]
    fn rfc3339_formats_utc_timestamps() {
        assert_eq!(rfc3339(SystemTime::UNIX_EPOCH), "1970-01-01T00:00:00Z");
        assert_eq!(
            rfc3339(SystemTime::UNIX_EPOCH + Duration::from_secs(100)),
            "1970-01-01T00:01:40Z"
        );
        assert_eq!(
            rfc3339(SystemTime::UNIX_EPOCH + Duration::from_millis(1_751_457_841_221)),
            "2025-07-02T12:04:01.221Z"
        );
    }

    #[test]
    fn generic_route_resolver_formatting() {
        register_route_resolver(|route| match route {
            RouteId::EtherType(0x0800) => Some("ipv4".to_string()),
            RouteId::EtherType(0x8847) => Some("mpls".to_string()),
            RouteId::IpProtocol(6) => Some("tcp".to_string()),
            RouteId::UdpPort(53) => Some("dns".to_string()),
            RouteId::Custom {
                space: "llc_dsap",
                id: 0x42,
            } => Some("stp".to_string()),
            _ => None,
        });

        // EtherType resolved
        assert_eq!(
            field_value_str("eth", "ethertype", &Value::U64(0x0800)),
            "IPv4 (0x0800)"
        );
        assert_eq!(
            field_value_str("eth", "ethertype", &Value::U64(0x8847)),
            "MPLS (0x8847)"
        );
        // EtherType unresolved
        assert_eq!(
            field_value_str("eth", "ethertype", &Value::U64(0x9999)),
            "0x9999"
        );

        // IP Protocol resolved
        assert_eq!(
            field_value_str("ipv4", "protocol", &Value::U64(6)),
            "TCP (6)"
        );
        // IP Protocol unresolved
        assert_eq!(field_value_str("ipv4", "protocol", &Value::U64(99)), "99");

        // Port resolved
        assert_eq!(
            field_value_str("udp", "src_port", &Value::U64(53)),
            "DNS (53)"
        );
        // Port unresolved
        assert_eq!(
            field_value_str("udp", "dst_port", &Value::U64(12345)),
            "12345"
        );

        // Custom space resolved
        assert_eq!(
            field_value_str("llc", "dsap", &Value::U64(0x42)),
            "STP (0x42)"
        );
        // Custom space unresolved
        assert_eq!(field_value_str("llc", "ssap", &Value::U64(0x55)), "0x55");
    }
}
