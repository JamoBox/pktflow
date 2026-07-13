//! SSDP — Simple Service Discovery Protocol (11.12, D14 citation: **no
//! ratified IETF RFC** — `draft-cai-ssdp-v1-03` expired without ever being
//! published as an RFC; the UPnP Forum's *UPnP Device Architecture*
//! specification (currently v2.0, §1.2 "Discovery",
//! <https://openconnectivity.org/upnp-specs/UPnP-arch-DeviceArchitecture-v2.0.pdf>)
//! is the closest authoritative document and the one real devices
//! implement against). HTTP/1.1 request/status-line syntax reused wholesale
//! over UDP multicast/unicast instead of TCP — structurally a cousin of
//! 11.8's `http` (same "header block ends at the blank line" framing idea,
//! same `method`/`status_code` split for request vs. response), but its
//! own plugin given the transport and verb-set differences (UPnP DA v2.0
//! §1.2.2-§1.2.3).
//!
//! Three message shapes ride the same port 1900:
//!  - `M-SEARCH * HTTP/1.1` (UPnP DA v2.0 §1.2.2): a control point's
//!    discovery request, usually multicast to `239.255.255.250:1900`.
//!  - `NOTIFY * HTTP/1.1` (UPnP DA v2.0 §1.2.1/§1.2.3): a device's
//!    unsolicited `ssdp:alive` announcement or `ssdp:byebye` withdrawal,
//!    also multicast.
//!  - `HTTP/1.1 200 OK` (UPnP DA v2.0 §1.2.2): a device's unicast reply to
//!    an `M-SEARCH`.
//!
//! **App-stream pattern (06.6).** SSDP has no endpoint identity of its
//! own — `app = "ssdp"` is a shared constant key, so one child stream
//! forms per UDP stream, the same shape as `dns`/`syslog`/`snmp`.
//!
//! **v1 scope.** Only the request/status line and the four headers this
//! task cares about (`ST`, `NTS`, `USN`, `LOCATION`) are decoded; every
//! other header (`HOST`, `MAN`, `MX`, `CACHE-CONTROL`, `SERVER`, `DATE`,
//! `EXT`, ...) is skipped over while walking to the blank-line terminator,
//! the same bounded-field-extraction ceiling this task already applies to
//! TLV/frame-envelope protocols (D12/D13). SSDP messages carry no body
//! (UPnP DA v2.0's examples all end at the blank line); if one somehow did,
//! it would be unparsed remainder past `header_len`, matching `http`'s own
//! stance (11.8) on bodies.

use pktflow_core::{
    Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx, ParseError,
    ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId, StreamIdentity, Truncated, Value,
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
        // The device-inventory signal: the URL names the specific device
        // (11.12's own rationale for this rollup choice).
        kind: RollupKind::Sample,
    },
];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: ROLLUPS,
};

/// Finds the header block's blank-line terminator (`CRLFCRLF`) and returns
/// the offset of its first byte. `None` means "not found in this segment"
/// — the same honest `Truncated` stance `http` (11.8) documents for a
/// header block split across TCP segments; here it just means more UDP
/// payload would be needed, which for a single datagram never arrives
/// (D7), so malformed/partial captures decline cleanly instead of hanging.
fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Splits a header block (no trailing CRLF) into CRLF-delimited lines.
fn split_lines(block: &[u8]) -> Vec<&[u8]> {
    let mut lines = Vec::new();
    let mut rest = block;
    while let Some(pos) = rest.windows(2).position(|w| w == b"\r\n") {
        let (line, after) = rest.split_at(pos);
        lines.push(line);
        rest = &after[2..];
    }
    lines.push(rest);
    lines
}

fn trim_spaces(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|&b| b != b' ').unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|&b| b != b' ')
        .map_or(start, |p| p + 1);
    &bytes[start..end]
}

/// Case-insensitive lookup of a `Name: value` header among the lines
/// following the start-line (`lines[0]`). Lines without a `:` (or any
/// unrecognized header) are skipped rather than rejected — SSDP responders
/// in the wild carry vendor headers (`SERVER`, `X-...`) this plugin has no
/// need to name.
fn header_value<'a>(lines: &[&'a [u8]], name: &str) -> Option<&'a [u8]> {
    lines.iter().skip(1).find_map(|line| {
        let colon = line.iter().position(|&b| b == b':')?;
        let (key, rest) = line.split_at(colon);
        key.eq_ignore_ascii_case(name.as_bytes())
            .then(|| trim_spaces(&rest[1..]))
    })
}

fn to_str(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// The start-line: either a request line (`M-SEARCH`/`NOTIFY * HTTP/1.1`)
/// or a status line (`HTTP/1.1 200 OK`, UPnP DA v2.0 §1.2.2). Only the two
/// SSDP request methods are accepted — anything else on port 1900 isn't
/// SSDP riding this port by coincidence, the same claim-honesty stance
/// `modbus`'s protocol-id check takes (11.13).
fn parse_start_line(line: &[u8]) -> Result<(Option<&'static str>, Option<u16>), ParseError> {
    let mut parts = line.splitn(3, |&b| b == b' ');
    let first = parts
        .next()
        .ok_or(ParseError::Malformed("empty start line"))?;

    if first == b"HTTP/1.1" {
        let code = parts
            .next()
            .ok_or(ParseError::Malformed("status line missing status code"))?;
        if code.len() != 3 || !code.iter().all(u8::is_ascii_digit) {
            return Err(ParseError::Malformed("status code must be 3 digits"));
        }
        let value = code
            .iter()
            .fold(0u16, |acc, &b| acc * 10 + u16::from(b - b'0'));
        Ok((None, Some(value)))
    } else if first == b"M-SEARCH" || first == b"NOTIFY" {
        let method = if first == b"M-SEARCH" {
            "M-SEARCH"
        } else {
            "NOTIFY"
        };
        let _request_uri = parts
            .next()
            .ok_or(ParseError::Malformed("request line missing Request-URI"))?;
        let version = parts
            .next()
            .ok_or(ParseError::Malformed("request line missing HTTP version"))?;
        if version != b"HTTP/1.1" {
            return Err(ParseError::Malformed("SSDP requires HTTP/1.1"));
        }
        Ok((Some(method), None))
    } else {
        Err(ParseError::Malformed(
            "start line is neither M-SEARCH/NOTIFY nor an HTTP/1.1 status line",
        ))
    }
}

pub struct Ssdp;

impl LayerPlugin for Ssdp {
    fn name(&self) -> ProtocolName {
        "ssdp"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let blank_pos = find_header_end(bytes).ok_or(ParseError::Truncated(Truncated {
            needed: bytes.len() + 1,
            have: bytes.len(),
        }))?;
        let header_len = blank_pos + 4;
        let lines = split_lines(&bytes[..blank_pos]);
        let start_line = *lines
            .first()
            .ok_or(ParseError::Malformed("empty header block"))?;
        let (method, status_code) = parse_start_line(start_line)?;

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(APP, Value::from("ssdp"));
        }
        if ctx.depth() >= Depth::Structural {
            if let Some(m) = method {
                fields.insert(METHOD, Value::from(m));
            }
            if let Some(code) = status_code {
                fields.insert(STATUS_CODE, Value::U64(u64::from(code)));
            }
            if method == Some("NOTIFY") {
                if let Some(v) = header_value(&lines, "NTS") {
                    fields.insert(NTS, Value::from(to_str(v).as_str()));
                }
            }
        }
        if ctx.depth() >= Depth::Full {
            if let Some(v) = header_value(&lines, "ST") {
                fields.insert(ST, Value::from(to_str(v).as_str()));
            }
            if let Some(v) = header_value(&lines, "USN") {
                fields.insert(USN, Value::from(to_str(v).as_str()));
            }
            if let Some(v) = header_value(&lines, "LOCATION") {
                fields.insert(LOCATION, Value::from(to_str(v).as_str()));
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

    fn ctx(depth: Depth, meta: &PacketMeta) -> ParseCtx<'_> {
        ParseCtx::new(&[], depth, meta)
    }

    /// UPnP DA v2.0 §1.2.2's `M-SEARCH` example, root-device search.
    fn m_search() -> Vec<u8> {
        b"M-SEARCH * HTTP/1.1\r\n\
HOST: 239.255.255.250:1900\r\n\
MAN: \"ssdp:discover\"\r\n\
MX: 2\r\n\
ST: upnp:rootdevice\r\n\
\r\n"
            .to_vec()
    }

    /// UPnP DA v2.0 §1.2.3's `ssdp:alive` announcement shape.
    fn notify_alive() -> Vec<u8> {
        b"NOTIFY * HTTP/1.1\r\n\
HOST: 239.255.255.250:1900\r\n\
CACHE-CONTROL: max-age=1800\r\n\
LOCATION: http://192.168.1.20:8080/description.xml\r\n\
NT: upnp:rootdevice\r\n\
NTS: ssdp:alive\r\n\
SERVER: Linux/5.0 UPnP/1.1 example/1.0\r\n\
USN: uuid:4d696e69-1dd2-11b2-8349-e31881a5f45a::upnp:rootdevice\r\n\
\r\n"
            .to_vec()
    }

    /// UPnP DA v2.0 §1.2.1's `ssdp:byebye` withdrawal — no `LOCATION`
    /// (the device is going away, not being described).
    fn notify_byebye() -> Vec<u8> {
        b"NOTIFY * HTTP/1.1\r\n\
HOST: 239.255.255.250:1900\r\n\
NT: upnp:rootdevice\r\n\
NTS: ssdp:byebye\r\n\
USN: uuid:4d696e69-1dd2-11b2-8349-e31881a5f45a::upnp:rootdevice\r\n\
\r\n"
            .to_vec()
    }

    /// UPnP DA v2.0 §1.2.2's unicast search-response shape.
    fn search_response() -> Vec<u8> {
        b"HTTP/1.1 200 OK\r\n\
CACHE-CONTROL: max-age=1800\r\n\
EXT:\r\n\
LOCATION: http://192.168.1.20:8080/description.xml\r\n\
SERVER: Linux/5.0 UPnP/1.1 example/1.0\r\n\
ST: upnp:rootdevice\r\n\
USN: uuid:4d696e69-1dd2-11b2-8349-e31881a5f45a::upnp:rootdevice\r\n\
\r\n"
            .to_vec()
    }

    #[test]
    fn m_search_reports_method_and_search_target() {
        let bytes = m_search();
        let m = meta(bytes.len());
        let parsed = Ssdp
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid M-SEARCH");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(APP), Some(&Value::from("ssdp")));
        assert_eq!(parsed.fields.get(METHOD), Some(&Value::from("M-SEARCH")));
        assert_eq!(parsed.fields.get(STATUS_CODE), None);
        assert_eq!(parsed.fields.get(ST), Some(&Value::from("upnp:rootdevice")));
        assert_eq!(parsed.fields.get(NTS), None);
    }

    #[test]
    fn notify_alive_reports_nts_usn_and_location() {
        let bytes = notify_alive();
        let m = meta(bytes.len());
        let parsed = Ssdp
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid NOTIFY ssdp:alive");
        assert_eq!(parsed.fields.get(METHOD), Some(&Value::from("NOTIFY")));
        assert_eq!(parsed.fields.get(NTS), Some(&Value::from("ssdp:alive")));
        assert_eq!(
            parsed.fields.get(USN),
            Some(&Value::from(
                "uuid:4d696e69-1dd2-11b2-8349-e31881a5f45a::upnp:rootdevice"
            ))
        );
        assert_eq!(
            parsed.fields.get(LOCATION),
            Some(&Value::from("http://192.168.1.20:8080/description.xml"))
        );
    }

    #[test]
    fn notify_byebye_has_no_location() {
        let bytes = notify_byebye();
        let m = meta(bytes.len());
        let parsed = Ssdp
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid NOTIFY ssdp:byebye");
        assert_eq!(parsed.fields.get(NTS), Some(&Value::from("ssdp:byebye")));
        assert_eq!(parsed.fields.get(LOCATION), None);
    }

    #[test]
    fn search_response_reports_status_code_not_method() {
        let bytes = search_response();
        let m = meta(bytes.len());
        let parsed = Ssdp
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid search response");
        assert_eq!(parsed.fields.get(METHOD), None);
        assert_eq!(parsed.fields.get(STATUS_CODE), Some(&Value::U64(200)));
        assert_eq!(parsed.fields.get(ST), Some(&Value::from("upnp:rootdevice")));
        // NTS is NOTIFY-only per the spec — a response must never report it,
        // even though this response happens to carry no NTS header anyway.
        assert_eq!(parsed.fields.get(NTS), None);
    }

    #[test]
    fn structural_depth_omits_full_only_fields() {
        let bytes = notify_alive();
        let m = meta(bytes.len());
        let parsed = Ssdp
            .parse(&bytes, &ctx(Depth::Structural, &m))
            .expect("valid NOTIFY ssdp:alive");
        assert_eq!(parsed.fields.get(NTS), Some(&Value::from("ssdp:alive")));
        assert_eq!(parsed.fields.get(LOCATION), None);
        assert_eq!(parsed.fields.get(USN), None);
    }

    #[test]
    fn keys_depth_only_has_app() {
        let bytes = m_search();
        let m = meta(bytes.len());
        let parsed = Ssdp
            .parse(&bytes, &ctx(Depth::Keys, &m))
            .expect("valid M-SEARCH");
        assert_eq!(parsed.fields.get(APP), Some(&Value::from("ssdp")));
        assert_eq!(parsed.fields.get(METHOD), None);
    }

    #[test]
    fn header_name_lookup_is_case_insensitive() {
        let bytes = b"NOTIFY * HTTP/1.1\r\nnts: ssdp:alive\r\nUsn: uuid:x\r\n\r\n".to_vec();
        let m = meta(bytes.len());
        let parsed = Ssdp
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid NOTIFY with lowercase header names");
        assert_eq!(parsed.fields.get(NTS), Some(&Value::from("ssdp:alive")));
        assert_eq!(parsed.fields.get(USN), Some(&Value::from("uuid:x")));
    }

    #[test]
    fn non_ssdp_method_declines() {
        let bytes = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
        let m = meta(bytes.len());
        assert!(Ssdp.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn non_http11_version_declines() {
        let bytes = b"M-SEARCH * HTTP/1.0\r\nST: upnp:rootdevice\r\n\r\n".to_vec();
        let m = meta(bytes.len());
        assert!(Ssdp.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn missing_blank_line_is_truncated_not_malformed() {
        let bytes = b"M-SEARCH * HTTP/1.1\r\nST: upnp:rootdevice\r\n".to_vec();
        let m = meta(bytes.len());
        assert!(matches!(
            Ssdp.parse(&bytes, &ctx(Depth::Full, &m)),
            Err(ParseError::Truncated(_))
        ));
    }

    #[test]
    fn truncated_frames_decline() {
        let bytes = notify_alive();
        let m = meta(bytes.len());
        for n in 0..bytes.len() {
            let full_ctx = ctx(Depth::Full, &m);
            assert!(
                Ssdp.parse(&bytes[..n], &full_ctx).is_err(),
                "prefix of {n}/{} bytes must decline",
                bytes.len()
            );
        }
    }
}
