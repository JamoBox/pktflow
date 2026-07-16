//! HTTP/1.x (11.8, RFC 9110/9112) — app-stream pattern (06.6): HTTP's
//! identity is its TCP session. Per D7 there is **no body reassembly** —
//! only the request/status line and headers are parsed; the message body is
//! unparsed remainder past `header_len`.
//!
//! **App-stream pattern (06.6).** HTTP has no endpoint identity of its own,
//! so the key is one shared constant field (`app = "http"`) — exactly one
//! child stream per TCP session, a clean home for rollups, the same shape as
//! `dns`/`ssdp`.
//!
//! **Known v1 gaps, stated plainly (11.8).** A header block split across TCP
//! segments yields `Truncated` (no reassembly, D7 — the blank-line
//! terminator simply isn't in this segment). WebSocket frames after an
//! `Upgrade: websocket` handshake still route through TCP's port claim back
//! to this plugin, which then declines the binary frames — a mid-session
//! protocol upgrade is invisible to per-packet, stateless routing (11.8's
//! documented architectural ceiling, same class as STARTTLS). The one
//! upgrade this plugin *can* follow is the HTTP/2 cleartext (h2c) connection
//! preface, which is a fixed 24-byte string dispatched by name (below).

use pktflow_core::{
    Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx, ParseError,
    ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId, StreamIdentity, Truncated, Value,
};

const APP: FieldName = "app";
const IS_REQUEST: FieldName = "is_request";
const METHOD: FieldName = "method";
const STATUS_CODE: FieldName = "status_code";
const VERSION: FieldName = "version";
const HOST: FieldName = "host";
const CONTENT_TYPE: FieldName = "content_type";
const CONTENT_LENGTH: FieldName = "content_length";
const USER_AGENT: FieldName = "user_agent";
const UPGRADE: FieldName = "upgrade";

/// HTTP/2's fixed cleartext (h2c) connection preface (RFC 9113 §3.4). Its
/// own internal `\r\n\r\n` at offset 14 means the ordinary header-block scan
/// would misread it as a `PRI * HTTP/2.0` request — so it is matched first,
/// whole, before any header parsing.
const H2C_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// The request methods this v1 recognizes (RFC 9110 §9.3 plus PATCH,
/// RFC 5789). A packet on port 80 whose start line is none of these — nor an
/// `HTTP/1.x` status line — isn't HTTP riding the port by coincidence and is
/// declined, the same claim-honesty stance `dns` takes on port 53 (06.6).
const METHODS: &[&str] = &[
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE",
];

static KEY: &[KeyField] = &[KeyField { a: APP, b: None }];
static ROLLUPS: &[RollupSpec] = &[
    // The request-method mix over the session (GET/POST/...). `status_code`
    // would be the response-side companion, but no single HTTP message
    // carries both `method` and `status_code`, and the 09.1 kit (rule 3)
    // requires every rollup field on every canonical sample — so
    // `status_code` stays a per-packet Structural field, not a rollup.
    RollupSpec {
        field: METHOD,
        kind: RollupKind::Accumulate,
    },
    // The hosts this session talked to — the device-inventory signal, the
    // same rationale as ssdp's `location` sampling.
    RollupSpec {
        field: HOST,
        kind: RollupKind::Sample,
    },
];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: ROLLUPS,
};

/// Offset of the header block's blank-line (`CRLFCRLF`) terminator, or
/// `None` when it isn't in this segment — a header block split across TCP
/// segments (D7, no reassembly), reported as `Truncated` by the caller.
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
/// following the start line. Unrecognized headers are skipped, not rejected.
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

/// Parses a decimal `Content-Length` value, saturating rather than
/// panicking on absurd input (hostile headers must never overflow, PRD §7).
fn parse_u64(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some(bytes.iter().fold(0u64, |acc, &b| {
        acc.saturating_mul(10).saturating_add(u64::from(b - b'0'))
    }))
}

/// An `HTTP/1.x` version token, e.g. `HTTP/1.1`. Only 1.0/1.1 are accepted —
/// binary HTTP/2 never reaches this text path (its h2c preface is handled
/// separately), so a non-`HTTP/1.x` token on port 80 declines.
fn is_http1_version(tok: &[u8]) -> bool {
    tok == b"HTTP/1.0" || tok == b"HTTP/1.1"
}

/// The parsed start line: request (method + version) or response
/// (status_code + version).
struct StartLine {
    is_request: bool,
    method: Option<&'static str>,
    status_code: Option<u16>,
    version: String,
}

fn parse_start_line(line: &[u8]) -> Result<StartLine, ParseError> {
    let mut parts = line.splitn(3, |&b| b == b' ');
    let first = parts
        .next()
        .ok_or(ParseError::Malformed("empty start line"))?;

    if first.starts_with(b"HTTP/") {
        // Status line: `HTTP-version SP status-code SP reason`.
        if !is_http1_version(first) {
            return Err(ParseError::Malformed("unsupported HTTP version"));
        }
        let code = parts
            .next()
            .ok_or(ParseError::Malformed("status line missing status code"))?;
        if code.len() != 3 || !code.iter().all(u8::is_ascii_digit) {
            return Err(ParseError::Malformed("status code must be 3 digits"));
        }
        let value = code
            .iter()
            .fold(0u16, |acc, &b| acc * 10 + u16::from(b - b'0'));
        Ok(StartLine {
            is_request: false,
            method: None,
            status_code: Some(value),
            version: to_str(first),
        })
    } else {
        // Request line: `method SP request-target SP HTTP-version`.
        let method: &'static str = METHODS
            .iter()
            .copied()
            .find(|m| m.as_bytes() == first)
            .ok_or(ParseError::Malformed("unrecognized request method"))?;
        let _target = parts
            .next()
            .ok_or(ParseError::Malformed("request line missing request-target"))?;
        let version = parts
            .next()
            .ok_or(ParseError::Malformed("request line missing HTTP version"))?;
        if !is_http1_version(version) {
            return Err(ParseError::Malformed("unsupported HTTP version"));
        }
        Ok(StartLine {
            is_request: true,
            method: Some(method),
            status_code: None,
            version: to_str(version),
        })
    }
}

pub struct Http;

impl LayerPlugin for Http {
    fn name(&self) -> ProtocolName {
        "http"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        // h2c connection preface (RFC 9113 §3.4): consumed whole and
        // dispatched to `http2` by name (VXLAN's direct-encapsulation
        // pattern, 06.5). Checked before header scanning because the preface
        // contains its own `\r\n\r\n`. When no `http2` plugin is registered
        // the router simply stops here — an honest end, not a crash.
        if bytes.starts_with(H2C_PREFACE) {
            let mut fields = FieldMap::new();
            if ctx.depth() >= Depth::Keys {
                fields.insert(APP, Value::from("http"));
            }
            if ctx.depth() >= Depth::Structural {
                fields.insert(IS_REQUEST, Value::Bool(true));
                fields.insert(VERSION, Value::from("HTTP/2.0"));
            }
            return Ok(ParsedLayer {
                header_len: H2C_PREFACE.len(),
                fields,
                hint: Hint::ByProtocol("http2"),
            });
        }

        let blank_pos = find_header_end(bytes).ok_or(ParseError::Truncated(Truncated {
            needed: bytes.len() + 1,
            have: bytes.len(),
        }))?;
        let header_len = blank_pos + 4;
        let lines = split_lines(&bytes[..blank_pos]);
        let start = *lines
            .first()
            .ok_or(ParseError::Malformed("empty header block"))?;
        let start = parse_start_line(start)?;

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(APP, Value::from("http"));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(IS_REQUEST, Value::Bool(start.is_request));
            fields.insert(VERSION, Value::from(start.version.as_str()));
            if let Some(m) = start.method {
                fields.insert(METHOD, Value::from(m));
            }
            if let Some(code) = start.status_code {
                fields.insert(STATUS_CODE, Value::U64(u64::from(code)));
            }
            // `host` is a rollup field, so it must reach the default
            // (Structural) view rather than only at Full (matching dns's
            // `qname` and tls's `sni`).
            if let Some(v) = header_value(&lines, "Host") {
                fields.insert(HOST, Value::from(to_str(v).as_str()));
            }
        }
        if ctx.depth() >= Depth::Full {
            if let Some(v) = header_value(&lines, "Content-Type") {
                fields.insert(CONTENT_TYPE, Value::from(to_str(v).as_str()));
            }
            if let Some(len) = header_value(&lines, "Content-Length").and_then(parse_u64) {
                fields.insert(CONTENT_LENGTH, Value::U64(len));
            }
            // User-Agent is a request-only header (RFC 9110 §10.1.5).
            if start.is_request {
                if let Some(v) = header_value(&lines, "User-Agent") {
                    fields.insert(USER_AGENT, Value::from(to_str(v).as_str()));
                }
            }
            if let Some(v) = header_value(&lines, "Upgrade") {
                fields.insert(UPGRADE, Value::from(to_str(v).as_str()));
            }
        }

        Ok(ParsedLayer {
            header_len,
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::TcpPort(80)]
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

    /// A GET request with the headers this plugin names.
    fn get_request() -> Vec<u8> {
        b"GET /index.html HTTP/1.1\r\n\
Host: example.com\r\n\
User-Agent: curl/8.4.0\r\n\
Accept: */*\r\n\
\r\n"
            .to_vec()
    }

    /// A POST request carrying a body (unparsed remainder past header_len).
    fn post_request() -> Vec<u8> {
        b"POST /submit HTTP/1.1\r\n\
Host: api.example.com\r\n\
User-Agent: app/1.0\r\n\
Content-Type: application/json\r\n\
Content-Length: 9\r\n\
\r\n\
{\"a\":\"b\"}"
            .to_vec()
    }

    /// A 200 response with a body.
    fn ok_response() -> Vec<u8> {
        b"HTTP/1.1 200 OK\r\n\
Content-Type: text/html; charset=utf-8\r\n\
Content-Length: 13\r\n\
\r\n\
Hello, world!"
            .to_vec()
    }

    #[test]
    fn get_request_reports_method_host_and_agent() {
        let bytes = get_request();
        let m = meta(bytes.len());
        let parsed = Http
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid GET");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(APP), Some(&Value::from("http")));
        assert_eq!(parsed.fields.get(IS_REQUEST), Some(&Value::Bool(true)));
        assert_eq!(parsed.fields.get(METHOD), Some(&Value::from("GET")));
        assert_eq!(parsed.fields.get(VERSION), Some(&Value::from("HTTP/1.1")));
        assert_eq!(parsed.fields.get(HOST), Some(&Value::from("example.com")));
        assert_eq!(
            parsed.fields.get(USER_AGENT),
            Some(&Value::from("curl/8.4.0"))
        );
        assert_eq!(parsed.fields.get(STATUS_CODE), None);
    }

    #[test]
    fn post_request_reports_content_type_and_length_and_stops_before_body() {
        let bytes = post_request();
        let m = meta(bytes.len());
        let parsed = Http
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid POST");
        // header_len ends at the blank line — the JSON body is remainder.
        assert_eq!(parsed.header_len, bytes.len() - b"{\"a\":\"b\"}".len());
        assert_eq!(parsed.fields.get(METHOD), Some(&Value::from("POST")));
        assert_eq!(
            parsed.fields.get(CONTENT_TYPE),
            Some(&Value::from("application/json"))
        );
        assert_eq!(parsed.fields.get(CONTENT_LENGTH), Some(&Value::U64(9)));
    }

    #[test]
    fn response_reports_status_code_not_method() {
        let bytes = ok_response();
        let m = meta(bytes.len());
        let parsed = Http
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid response");
        assert_eq!(parsed.fields.get(IS_REQUEST), Some(&Value::Bool(false)));
        assert_eq!(parsed.fields.get(STATUS_CODE), Some(&Value::U64(200)));
        assert_eq!(parsed.fields.get(METHOD), None);
        // User-Agent is request-only and must not appear on a response.
        assert_eq!(parsed.fields.get(USER_AGENT), None);
        assert_eq!(
            parsed.fields.get(CONTENT_TYPE),
            Some(&Value::from("text/html; charset=utf-8"))
        );
    }

    #[test]
    fn h2c_preface_dispatches_to_http2_by_name() {
        let m = meta(H2C_PREFACE.len());
        let parsed = Http
            .parse(H2C_PREFACE, &ctx(Depth::Full, &m))
            .expect("valid h2c preface");
        assert_eq!(parsed.header_len, 24);
        assert_eq!(parsed.hint, Hint::ByProtocol("http2"));
        assert_eq!(parsed.fields.get(VERSION), Some(&Value::from("HTTP/2.0")));
    }

    #[test]
    fn keys_depth_only_has_app() {
        let bytes = get_request();
        let m = meta(bytes.len());
        let parsed = Http
            .parse(&bytes, &ctx(Depth::Keys, &m))
            .expect("valid GET");
        assert_eq!(parsed.fields.get(APP), Some(&Value::from("http")));
        assert_eq!(parsed.fields.get(METHOD), None);
        assert_eq!(parsed.fields.get(HOST), None);
    }

    #[test]
    fn structural_depth_surfaces_host_but_omits_other_headers() {
        // `host` is a rollup field, so it must reach the default (Structural)
        // view; other headers (User-Agent, Content-Type) stay Full-only.
        let bytes = get_request();
        let m = meta(bytes.len());
        let parsed = Http
            .parse(&bytes, &ctx(Depth::Structural, &m))
            .expect("valid GET");
        assert_eq!(parsed.fields.get(METHOD), Some(&Value::from("GET")));
        assert_eq!(parsed.fields.get(HOST), Some(&Value::from("example.com")));
        assert_eq!(parsed.fields.get(USER_AGENT), None);
    }

    #[test]
    fn header_name_lookup_is_case_insensitive() {
        let bytes = b"GET / HTTP/1.1\r\nhOsT: example.org\r\n\r\n".to_vec();
        let m = meta(bytes.len());
        let parsed = Http
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid GET");
        assert_eq!(parsed.fields.get(HOST), Some(&Value::from("example.org")));
    }

    #[test]
    fn upgrade_header_is_captured() {
        let bytes = b"GET /chat HTTP/1.1\r\n\
Host: example.com\r\n\
Upgrade: websocket\r\n\
Connection: Upgrade\r\n\
\r\n"
            .to_vec();
        let m = meta(bytes.len());
        let parsed = Http
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid GET");
        assert_eq!(parsed.fields.get(UPGRADE), Some(&Value::from("websocket")));
    }

    #[test]
    fn unrecognized_method_declines() {
        // A non-HTTP payload on port 80 must decline, not misparse.
        let bytes = b"NOTAVERB / HTTP/1.1\r\nHost: x\r\n\r\n".to_vec();
        let m = meta(bytes.len());
        assert!(Http.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn http2_binary_bytes_on_port_80_decline() {
        // WebSocket/HTTP2 binary framing has no CRLFCRLF terminator here.
        let bytes = [0x00u8, 0x00, 0x12, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00];
        let m = meta(bytes.len());
        assert!(matches!(
            Http.parse(&bytes, &ctx(Depth::Full, &m)),
            Err(ParseError::Truncated(_))
        ));
    }

    #[test]
    fn missing_blank_line_is_truncated_not_malformed() {
        // A header block split across TCP segments (D7): no reassembly.
        let bytes = b"GET / HTTP/1.1\r\nHost: example.com\r\n".to_vec();
        let m = meta(bytes.len());
        assert!(matches!(
            Http.parse(&bytes, &ctx(Depth::Full, &m)),
            Err(ParseError::Truncated(_))
        ));
    }

    #[test]
    fn truncated_frames_decline() {
        let bytes = get_request();
        let m = meta(bytes.len());
        for n in 0..bytes.len() {
            let full = ctx(Depth::Full, &m);
            assert!(
                Http.parse(&bytes[..n], &full).is_err(),
                "prefix of {n}/{} bytes must decline",
                bytes.len()
            );
        }
    }
}
