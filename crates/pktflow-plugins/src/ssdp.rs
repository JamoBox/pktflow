//! SSDP — Simple Service Discovery Protocol (11.12).
//!
//! **Standard citation (D14).** No ratified RFC: the original wire format
//! comes from `draft-cai-ssdp-v1-03` (IETF Internet-Draft, expired
//! 1999-12-05); the closest living authoritative document is the UPnP
//! Forum's *UPnP Device Architecture* specification (UDA 2.0 §1,
//! "Discovery"), which is what real devices on the wire actually
//! implement (Windows Network Discovery, DLNA/UPnP media renderers,
//! Chromecast, smart-home hubs). This dissector follows the UDA profile.
//!
//! SSDP reuses HTTP/1.1's request/response grammar (RFC 9112 §2-3)
//! verbatim, carried over UDP multicast (`239.255.255.250:1900` /
//! `[ff02::c]:1900` for search, unicast back to the searcher for
//! responses) instead of TCP: a start-line, zero or more `Name: value`
//! header lines, each CRLF-terminated, the block ending at the first bare
//! CRLFCRLF. SSDP carries no message body — `header_len` is the entire
//! datagram, matching this task's "cousin of 11.8's `http`, same
//! header-block-ends-at-CRLFCRLF framing idea" note.
//!
//! Three message forms, distinguished by the start-line (UDA §1.2):
//!  - `M-SEARCH * HTTP/1.1` — a multicast discovery request (UDA §1.2.2).
//!    Carries `ST` (Search Target: `ssdp:all`, a UPnP device/service type
//!    URN, or a specific `uuid:...`).
//!  - `NOTIFY * HTTP/1.1` — an unsolicited advertisement. `NTS:
//!    ssdp:alive` (UDA §1.2.1) announces a device and carries `NT`,
//!    `USN`, `LOCATION`; `NTS: ssdp:byebye` (UDA §1.2.3) announces its
//!    departure and typically omits `LOCATION` — the device is gone.
//!  - `HTTP/1.1 <code> <reason>` — a unicast M-SEARCH response (UDA
//!    §1.3.2), echoing `ST` and adding `USN`/`LOCATION`. In practice the
//!    code is always `200`; this dissector accepts any 3-digit code
//!    rather than special-casing `200`, the same latitude HTTP itself
//!    grants a status line.
//!
//! **Field-name mapping (v1 scope, this task's field table).** Real UDA
//! traffic sends `NT` (Notification Type) on `NOTIFY` where `M-SEARCH`
//! and the search response send `ST` (Search Target) — two header names
//! for the analogous "what kind of thing" value. This task's field table
//! declares only `st`, not `nt`, so `NT` is intentionally not extracted:
//! a `NOTIFY` message's `st` field is simply absent (a conditional field,
//! same shape as `mdns`'s optional `qname`), rather than this dissector
//! inventing an `NT`-into-`st` mapping the spec doesn't name. Header
//! names are matched case-insensitively (RFC 9110 §5.1); values are not
//! otherwise validated (e.g. `LOCATION` is stored as the raw URL text,
//! not parsed).
//!
//! **App-stream pattern (06.6).** SSDP has no endpoint identity of its
//! own beyond its UDP transport — `app = "ssdp"` is a shared constant
//! key, one child stream per UDP stream (searcher<->multicast group, or
//! searcher<->responder), the same shape as `dns`/`syslog`/`mdns`.

use pktflow_core::{
    Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx, ParseError,
    ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId, StreamIdentity, Value,
};

const APP: FieldName = "app";
const METHOD: FieldName = "method";
const STATUS_CODE: FieldName = "status_code";
const NTS: FieldName = "nts";
const ST: FieldName = "st";
const USN: FieldName = "usn";
const LOCATION: FieldName = "location";

static KEY: &[KeyField] = &[KeyField { a: APP, b: None }];
static ROLLUPS: &[RollupSpec] = &[
    RollupSpec {
        field: NTS,
        kind: RollupKind::Accumulate,
    },
    RollupSpec {
        field: LOCATION,
        kind: RollupKind::Sample,
    },
];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: ROLLUPS,
};

enum StartLine<'a> {
    /// `M-SEARCH` or `NOTIFY`.
    Request(&'a str),
    /// The numeric status code off `HTTP/1.1 <code> <reason>`.
    Response(u16),
}

/// The offset of the first `"\r\n\r\n"` — the header block's own
/// terminator, per this module's framing note. Because this is the
/// *first* such run, no strict prefix of `bytes[..that + 4]` can contain
/// a complete `"\r\n\r\n"` of its own: truncation always removes bytes
/// from at or before this terminator, so every short prefix declines
/// (the 09.1 kit's rule 1), the same invariant `syslog`'s self-
/// terminated-token framing relies on.
fn header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Splits `block` on exact `"\r\n"` runs (no bare-LF tolerance — SSDP is
/// strict-CRLF like the HTTP grammar it borrows). `block` never contains
/// the terminating blank line itself (see `header_end`), so this yields
/// exactly the start-line followed by each header line, none of them
/// carrying a trailing CRLF.
fn crlf_lines(block: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i + 1 < block.len() {
        if block[i] == b'\r' && block[i + 1] == b'\n' {
            out.push(&block[start..i]);
            i += 2;
            start = i;
        } else {
            i += 1;
        }
    }
    out.push(&block[start..]);
    out
}

/// The start-line: `METHOD SP "*" SP "HTTP/1.1"` for requests, or
/// `"HTTP/1.1" SP 3DIGIT SP reason-phrase` for the search response. Any
/// other shape (unknown method, non-`*` request-target, non-3-digit
/// code) is not SSDP.
fn parse_start_line(line: &[u8]) -> Result<StartLine<'_>, ParseError> {
    let s = std::str::from_utf8(line).map_err(|_| ParseError::Malformed("start line not utf-8"))?;
    let mut parts = s.splitn(3, ' ');
    let a = parts.next().filter(|t| !t.is_empty());
    let b = parts.next();
    let c = parts.next();
    match (a, b, c) {
        (Some(method @ ("M-SEARCH" | "NOTIFY")), Some("*"), Some("HTTP/1.1")) => {
            Ok(StartLine::Request(method))
        }
        (Some("HTTP/1.1"), Some(code), Some(_reason)) => {
            if code.len() == 3 && code.bytes().all(|d| d.is_ascii_digit()) {
                Ok(StartLine::Response(code.parse().expect("3 ascii digits")))
            } else {
                Err(ParseError::Malformed("SSDP status code not 3 digits"))
            }
        }
        _ => Err(ParseError::Malformed("unrecognized SSDP start line")),
    }
}

/// One `Name: value` header line, `OWS`-trimmed (RFC 9110 §5.1) on both
/// sides of the value. Lines without a `:` are skipped rather than
/// declining the whole message — real-world SSDP traffic occasionally
/// carries vendor extension lines this dissector doesn't otherwise care
/// about, and none of the four fields below are load-bearing enough to
/// justify failing the whole datagram over an unrelated stray line.
fn header(line: &[u8]) -> Option<(&str, &str)> {
    let colon = line.iter().position(|&b| b == b':')?;
    let name = std::str::from_utf8(&line[..colon]).ok()?;
    let mut value = &line[colon + 1..];
    while matches!(value.first(), Some(b' ' | b'\t')) {
        value = &value[1..];
    }
    while matches!(value.last(), Some(b' ' | b'\t')) {
        value = &value[..value.len() - 1];
    }
    Some((name, std::str::from_utf8(value).ok()?))
}

pub struct Ssdp;

impl LayerPlugin for Ssdp {
    fn name(&self) -> ProtocolName {
        "ssdp"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let term = header_end(bytes).ok_or(ParseError::Malformed("no CRLFCRLF terminator"))?;
        let header_len = term + 4;
        let block = &bytes[..term];
        let mut lines = crlf_lines(block).into_iter();
        let start = parse_start_line(lines.next().unwrap_or(&[]))?;

        let (mut nts, mut st, mut usn, mut location) = (None, None, None, None);
        for line in lines {
            match header(line) {
                Some((name, value)) if name.eq_ignore_ascii_case("NTS") => nts = Some(value),
                Some((name, value)) if name.eq_ignore_ascii_case("ST") => st = Some(value),
                Some((name, value)) if name.eq_ignore_ascii_case("USN") => usn = Some(value),
                Some((name, value)) if name.eq_ignore_ascii_case("LOCATION") => {
                    location = Some(value);
                }
                _ => {}
            }
        }

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(APP, Value::from("ssdp"));
        }
        if ctx.depth() >= Depth::Structural {
            match start {
                StartLine::Request(method) => {
                    fields.insert(METHOD, Value::from(method));
                }
                StartLine::Response(code) => {
                    fields.insert(STATUS_CODE, Value::U64(u64::from(code)));
                }
            }
            if let Some(nts) = nts {
                fields.insert(NTS, Value::from(nts));
            }
        }
        if ctx.depth() >= Depth::Full {
            if let Some(st) = st {
                fields.insert(ST, Value::from(st));
            }
            if let Some(usn) = usn {
                fields.insert(USN, Value::from(usn));
            }
            if let Some(location) = location {
                fields.insert(LOCATION, Value::from(location));
            }
        }

        Ok(ParsedLayer {
            header_len,
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::UdpPort(1900)]
    }

    fn stream_identity(&self) -> Option<&StreamIdentity> {
        Some(&IDENTITY)
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use pktflow_core::{LinkType, PacketMeta};

    use super::*;

    fn meta(len: usize) -> PacketMeta {
        PacketMeta {
            timestamp: SystemTime::UNIX_EPOCH,
            caplen: len,
            origlen: len,
            link_type: LinkType::ETHERNET,
        }
    }

    fn parse(bytes: &[u8]) -> Result<ParsedLayer, ParseError> {
        let m = meta(bytes.len());
        Ssdp.parse(bytes, &ParseCtx::new(&[], Depth::Full, &m))
    }

    /// UDA §1.2.2's `M-SEARCH`, real-world shape (Windows/`gssdp-discover`
    /// style): asks for all UPnP root devices.
    const MSEARCH: &[u8] = b"M-SEARCH * HTTP/1.1\r\n\
        HOST: 239.255.255.250:1900\r\n\
        MAN: \"ssdp:discover\"\r\n\
        MX: 2\r\n\
        ST: ssdp:all\r\n\
        \r\n";

    #[test]
    fn parses_msearch_request() {
        let parsed = parse(MSEARCH).expect("valid M-SEARCH");
        assert_eq!(parsed.header_len, MSEARCH.len());
        assert_eq!(parsed.fields.get(METHOD), Some(&Value::from("M-SEARCH")));
        assert_eq!(parsed.fields.get(ST), Some(&Value::from("ssdp:all")));
        assert_eq!(parsed.fields.get(NTS), None);
        assert_eq!(parsed.hint, Hint::Terminal);
    }

    /// UDA §1.2.1 `NOTIFY ssdp:alive`, a real Sonos-style advertisement
    /// shape.
    const NOTIFY_ALIVE: &[u8] = b"NOTIFY * HTTP/1.1\r\n\
        HOST: 239.255.255.250:1900\r\n\
        CACHE-CONTROL: max-age=1800\r\n\
        LOCATION: http://192.168.1.50:1400/xml/device_description.xml\r\n\
        NT: urn:schemas-upnp-org:device:ZonePlayer:1\r\n\
        NTS: ssdp:alive\r\n\
        SERVER: Linux/3.14 UPnP/1.0 Sonos/56.0\r\n\
        USN: uuid:RINCON_000E58B5A8E401400::urn:schemas-upnp-org:device:ZonePlayer:1\r\n\
        \r\n";

    #[test]
    fn parses_notify_alive() {
        let parsed = parse(NOTIFY_ALIVE).expect("valid NOTIFY alive");
        assert_eq!(parsed.header_len, NOTIFY_ALIVE.len());
        assert_eq!(parsed.fields.get(METHOD), Some(&Value::from("NOTIFY")));
        assert_eq!(parsed.fields.get(NTS), Some(&Value::from("ssdp:alive")));
        assert_eq!(
            parsed.fields.get(LOCATION),
            Some(&Value::from(
                "http://192.168.1.50:1400/xml/device_description.xml"
            ))
        );
        assert_eq!(
            parsed.fields.get(USN),
            Some(&Value::from(
                "uuid:RINCON_000E58B5A8E401400::urn:schemas-upnp-org:device:ZonePlayer:1"
            ))
        );
        // NT isn't in this task's field table (module doc) — not extracted.
        assert_eq!(parsed.fields.get(ST), None);
        assert_eq!(parsed.hint, Hint::Terminal);
    }

    /// UDA §1.2.3 `NOTIFY ssdp:byebye` — no `LOCATION`, the device left.
    const NOTIFY_BYEBYE: &[u8] = b"NOTIFY * HTTP/1.1\r\n\
        HOST: 239.255.255.250:1900\r\n\
        NT: urn:schemas-upnp-org:device:ZonePlayer:1\r\n\
        NTS: ssdp:byebye\r\n\
        USN: uuid:RINCON_000E58B5A8E401400::urn:schemas-upnp-org:device:ZonePlayer:1\r\n\
        \r\n";

    #[test]
    fn parses_notify_byebye() {
        let parsed = parse(NOTIFY_BYEBYE).expect("valid NOTIFY byebye");
        assert_eq!(parsed.fields.get(NTS), Some(&Value::from("ssdp:byebye")));
        assert_eq!(parsed.fields.get(LOCATION), None);
    }

    /// UDA §1.3.2's search response to an `M-SEARCH`.
    const SEARCH_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\n\
        CACHE-CONTROL: max-age=1800\r\n\
        DATE: Mon, 13 Jul 2026 10:00:00 GMT\r\n\
        EXT:\r\n\
        LOCATION: http://192.168.1.50:1400/xml/device_description.xml\r\n\
        SERVER: Linux/3.14 UPnP/1.0 Sonos/56.0\r\n\
        ST: urn:schemas-upnp-org:device:ZonePlayer:1\r\n\
        USN: uuid:RINCON_000E58B5A8E401400::urn:schemas-upnp-org:device:ZonePlayer:1\r\n\
        \r\n";

    #[test]
    fn parses_search_response() {
        let parsed = parse(SEARCH_RESPONSE).expect("valid search response");
        assert_eq!(parsed.fields.get(STATUS_CODE), Some(&Value::U64(200)));
        assert_eq!(parsed.fields.get(METHOD), None);
        assert_eq!(
            parsed.fields.get(ST),
            Some(&Value::from("urn:schemas-upnp-org:device:ZonePlayer:1"))
        );
        assert_eq!(
            parsed.fields.get(LOCATION),
            Some(&Value::from(
                "http://192.168.1.50:1400/xml/device_description.xml"
            ))
        );
    }

    #[test]
    fn truncated_header_declines() {
        for n in 0..MSEARCH.len() {
            assert!(
                parse(&MSEARCH[..n]).is_err(),
                "byte offset {n} should decline"
            );
        }
    }

    #[test]
    fn missing_terminator_declines() {
        assert!(parse(b"M-SEARCH * HTTP/1.1\r\nST: ssdp:all\r\n").is_err());
    }

    #[test]
    fn unknown_method_declines() {
        assert!(parse(b"GET * HTTP/1.1\r\n\r\n").is_err());
    }

    #[test]
    fn bad_request_target_declines() {
        assert!(parse(b"M-SEARCH /foo HTTP/1.1\r\n\r\n").is_err());
    }

    /// Header *names* are case-insensitive (RFC 9110 §5.1); the method
    /// token is not (RFC 9110 §9.1) — real SSDP senders always send it
    /// uppercase, so only the header-name side is exercised here.
    #[test]
    fn header_name_case_is_ignored() {
        let msg = b"M-SEARCH * HTTP/1.1\r\nst: ssdp:all\r\n\r\n";
        let parsed = parse(msg).expect("valid, lowercased header name");
        assert_eq!(parsed.fields.get(ST), Some(&Value::from("ssdp:all")));
    }

    #[test]
    fn depth_gating_hides_fields_below_full() {
        let m = meta(NOTIFY_ALIVE.len());
        let keys = Ssdp
            .parse(NOTIFY_ALIVE, &ParseCtx::new(&[], Depth::Keys, &m))
            .expect("valid");
        assert_eq!(keys.fields.get(APP), Some(&Value::from("ssdp")));
        assert_eq!(keys.fields.get(METHOD), None);
        assert_eq!(keys.fields.get(LOCATION), None);

        let structural = Ssdp
            .parse(NOTIFY_ALIVE, &ParseCtx::new(&[], Depth::Structural, &m))
            .expect("valid");
        assert_eq!(structural.fields.get(NTS), Some(&Value::from("ssdp:alive")));
        assert_eq!(structural.fields.get(LOCATION), None);
    }
}
