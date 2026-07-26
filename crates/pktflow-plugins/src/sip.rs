//! SIP (11.10, RFC 3261) — text-based, HTTP-shaped (`http`, 11.8, is a
//! structural cousin: start line, `Name: value` headers, a blank-line
//! terminator, then an unparsed body). Per D7, the SDP body (if present)
//! is unparsed payload — which is exactly where the RTP port D15 names as
//! "would need cross-stream correlation" is announced; extracting it and
//! pre-registering a route for the resulting RTP stream is precisely the
//! future capability D15 describes, not attempted here.
//!
//! ## Framing
//! `header_len` is the offset of the blank-line (`CRLFCRLF`) terminator
//! plus 4; a header block split across segments yields `Truncated` (D7, no
//! reassembly — `http`'s own stance). The start line is either a
//! Request-Line (`METHOD sip:uri SIP/2.0`) or a Status-Line (`SIP/2.0
//! status-code reason-phrase`).
//!
//! ## Identity: the `Call-ID` header (RFC 3261 §8.1.1.4, mandatory on
//! ## every SIP message)
//! Rather than the generic app-stream constant (06.6), SIP already defines
//! what "one call" means: `Call-ID` spans an entire dialog
//! (`INVITE...200 OK...ACK...BYE`). A message without a `Call-ID` header
//! is not well-formed SIP and declines — the same "flow-key field must
//! always be extractable" floor 01.3 sets for every declared key field.

use pktflow_core::{
    Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx, ParseError,
    ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId, StreamIdentity, Truncated, Value,
};

const CALL_ID: FieldName = "call_id";
const IS_REQUEST: FieldName = "is_request";
const METHOD: FieldName = "method";
const STATUS_CODE: FieldName = "status_code";
const FROM: FieldName = "from";
const TO: FieldName = "to";
const VIA: FieldName = "via";
const CSEQ: FieldName = "cseq";

/// RFC 3261's core method set plus common extensions (RFC 3262/3265/3428/
/// 3515/3903/3311); Tier 1's "method ∈ {...}" is open-ended, so this list
/// covers the traffic actually seen in practice, the same closed-enough
/// stance `http`'s own method list takes (11.8).
const METHODS: &[&str] = &[
    "INVITE",
    "ACK",
    "BYE",
    "CANCEL",
    "REGISTER",
    "OPTIONS",
    "PRACK",
    "SUBSCRIBE",
    "NOTIFY",
    "PUBLISH",
    "INFO",
    "REFER",
    "MESSAGE",
    "UPDATE",
];

static KEY: &[KeyField] = &[KeyField {
    a: CALL_ID,
    b: None, // shared (non-endpoint) qualifier: one stream per SIP dialog
}];
static ROLLUPS: &[RollupSpec] = &[
    RollupSpec {
        field: METHOD,
        kind: RollupKind::Accumulate,
    },
    RollupSpec {
        field: STATUS_CODE,
        kind: RollupKind::Series { cap: 64 },
    },
];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: ROLLUPS,
};

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|w| w == b"\r\n\r\n")
}

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

struct StartLine {
    is_request: bool,
    method: Option<&'static str>,
    status_code: Option<u16>,
}

fn parse_start_line(line: &[u8]) -> Option<StartLine> {
    let mut parts = line.splitn(3, |&b| b == b' ');
    let first = parts.next()?;
    if first == b"SIP/2.0" {
        let code = parts.next()?;
        if code.len() != 3 || !code.iter().all(u8::is_ascii_digit) {
            return None;
        }
        let value = code
            .iter()
            .fold(0u16, |acc, &b| acc * 10 + u16::from(b - b'0'));
        return Some(StartLine {
            is_request: false,
            method: None,
            status_code: Some(value),
        });
    }
    let method: &'static str = METHODS.iter().copied().find(|m| m.as_bytes() == first)?;
    let _uri = parts.next()?;
    let version = parts.next()?;
    if version != b"SIP/2.0" {
        return None;
    }
    Some(StartLine {
        is_request: true,
        method: Some(method),
        status_code: None,
    })
}

pub struct Sip;

impl LayerPlugin for Sip {
    fn name(&self) -> ProtocolName {
        "sip"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let blank_pos = find_header_end(bytes).ok_or(ParseError::Truncated(Truncated {
            needed: bytes.len() + 1,
            have: bytes.len(),
        }))?;
        let header_len = blank_pos + 4;
        let lines = split_lines(&bytes[..blank_pos]);
        let start = *lines
            .first()
            .ok_or(ParseError::Malformed("empty header block"))?;
        let start = parse_start_line(start).ok_or(ParseError::Malformed("not a SIP start line"))?;

        let call_id = header_value(&lines, "Call-ID")
            .ok_or(ParseError::Malformed("SIP message missing Call-ID"))?;

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(CALL_ID, Value::from(to_str(call_id).as_str()));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(IS_REQUEST, Value::Bool(start.is_request));
            if let Some(m) = start.method {
                fields.insert(METHOD, Value::from(m));
            }
            if let Some(code) = start.status_code {
                fields.insert(STATUS_CODE, Value::U64(u64::from(code)));
            }
        }
        if ctx.depth() >= Depth::Full {
            if let Some(v) = header_value(&lines, "From") {
                fields.insert(FROM, Value::from(to_str(v).as_str()));
            }
            if let Some(v) = header_value(&lines, "To") {
                fields.insert(TO, Value::from(to_str(v).as_str()));
            }
            if let Some(v) = header_value(&lines, "Via") {
                fields.insert(VIA, Value::from(to_str(v).as_str()));
            }
            if let Some(v) = header_value(&lines, "CSeq") {
                fields.insert(CSEQ, Value::from(to_str(v).as_str()));
            }
        }

        Ok(ParsedLayer {
            header_len,
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::UdpPort(5060), RouteId::TcpPort(5060)]
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

    fn invite() -> Vec<u8> {
        b"INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc1.example.com;branch=z9hG4bK1\r\n\
From: Alice <sip:alice@example.com>;tag=1928301774\r\n\
To: Bob <sip:bob@example.com>\r\n\
Call-ID: a84b4c76e66710@pc1.example.com\r\n\
CSeq: 1 INVITE\r\n\
\r\n"
            .to_vec()
    }

    fn ok_200() -> Vec<u8> {
        b"SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP pc1.example.com;branch=z9hG4bK1\r\n\
From: Alice <sip:alice@example.com>;tag=1928301774\r\n\
To: Bob <sip:bob@example.com>;tag=a6c85cf\r\n\
Call-ID: a84b4c76e66710@pc1.example.com\r\n\
CSeq: 1 INVITE\r\n\
\r\n"
            .to_vec()
    }

    #[test]
    fn invite_request_parses_method_and_headers() {
        let bytes = invite();
        let m = meta(bytes.len());
        let parsed = Sip
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid INVITE");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(
            parsed.fields.get(CALL_ID),
            Some(&Value::from("a84b4c76e66710@pc1.example.com"))
        );
        assert_eq!(parsed.fields.get(IS_REQUEST), Some(&Value::Bool(true)));
        assert_eq!(parsed.fields.get(METHOD), Some(&Value::from("INVITE")));
        assert_eq!(parsed.fields.get(STATUS_CODE), None);
        assert_eq!(
            parsed.fields.get(FROM),
            Some(&Value::from("Alice <sip:alice@example.com>;tag=1928301774"))
        );
        assert_eq!(parsed.fields.get(CSEQ), Some(&Value::from("1 INVITE")));
    }

    #[test]
    fn ok_response_parses_status_code_not_method() {
        let bytes = ok_200();
        let m = meta(bytes.len());
        let parsed = Sip.parse(&bytes, &ctx(Depth::Full, &m)).expect("valid 200");
        assert_eq!(parsed.fields.get(IS_REQUEST), Some(&Value::Bool(false)));
        assert_eq!(parsed.fields.get(STATUS_CODE), Some(&Value::U64(200)));
        assert_eq!(parsed.fields.get(METHOD), None);
        assert_eq!(
            parsed.fields.get(CALL_ID),
            Some(&Value::from("a84b4c76e66710@pc1.example.com"))
        );
    }

    #[test]
    fn depth_gates_method_and_headers() {
        let bytes = invite();
        let m = meta(bytes.len());
        let keys = Sip.parse(&bytes, &ctx(Depth::Keys, &m)).expect("valid");
        assert_eq!(
            keys.fields.get(CALL_ID),
            Some(&Value::from("a84b4c76e66710@pc1.example.com"))
        );
        assert_eq!(keys.fields.get(METHOD), None);

        let structural = Sip
            .parse(&bytes, &ctx(Depth::Structural, &m))
            .expect("valid");
        assert_eq!(structural.fields.get(METHOD), Some(&Value::from("INVITE")));
        assert_eq!(structural.fields.get(FROM), None);
    }

    #[test]
    fn missing_call_id_declines() {
        let bytes = b"INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc1.example.com\r\n\
\r\n"
            .to_vec();
        let m = meta(bytes.len());
        assert!(Sip.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn unrecognized_method_declines() {
        let bytes = b"NOTAVERB sip:bob@example.com SIP/2.0\r\n\
Call-ID: x@y\r\n\
\r\n"
            .to_vec();
        let m = meta(bytes.len());
        assert!(Sip.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn missing_blank_line_is_truncated() {
        let bytes = b"INVITE sip:bob@example.com SIP/2.0\r\nCall-ID: x@y\r\n".to_vec();
        let m = meta(bytes.len());
        assert!(matches!(
            Sip.parse(&bytes, &ctx(Depth::Full, &m)),
            Err(ParseError::Truncated(_))
        ));
    }

    #[test]
    fn truncated_frames_decline_at_every_prefix() {
        let bytes = invite();
        let m = meta(bytes.len());
        let full = ctx(Depth::Full, &m);
        for n in 0..bytes.len() {
            assert!(
                Sip.parse(&bytes[..n], &full).is_err(),
                "prefix of {n}/{} bytes must decline",
                bytes.len()
            );
        }
    }
}
