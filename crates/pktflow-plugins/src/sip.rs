//! SIP (11.10, RFC 3261) — text-based, HTTP-shaped (`http`, 11.8, is a
//! structural cousin: start line + CRLF-delimited headers + blank-line
//! terminator + unparsed body). Per D7 the SDP body, when present, is
//! unparsed remainder past `header_len` — including the RTP port it
//! negotiates, which is exactly the port D15 says would need cross-stream
//! correlation to reach `rtp`/`rtcp` (not attempted here).
//!
//! **Call-ID identity, not the generic app-stream constant (11.10).** SIP
//! already defines what "one call" means: the `Call-ID` header, shared by
//! every request/response in a dialog (`INVITE ... 180 ... 200 ... ACK ...
//! BYE`), possibly spanning multiple TCP/UDP packets and even multiple
//! transport-layer streams (a SIP proxy hop). This plugin's stream key is
//! that header value — a shared (non-endpoint) qualifier, the same
//! `KeyField { b: None }` shape `gtp_u`'s TEID and `vxlan`'s VNI use — so
//! one `sip` stream forms per dialog rather than per transport session.
//!
//! **`status_code` stays a per-packet `Structural` field, not a rollup** —
//! the same constraint `http` (11.8) documents for its own `status_code`:
//! no single SIP message carries both `method` and `status_code` (a
//! request has the former, a response the latter), and the 09.1 kit's
//! rule 3 requires every declared rollup field on every canonical good
//! sample. A `Series` rollup tracking the 100/180/200 call-progress
//! sequence is exactly what the domain spec wants analytically, but it
//! cannot be validated against a single-message fixture the way
//! `method`'s `Accumulate` can — a real v2 candidate once the kit (or the
//! rollup declaration itself) grows a per-field applicability notion.

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

/// RFC 3261 §7.1's core method set (Tier-1 scope: the six named in the
/// domain spec table). Extension methods (INFO, PRACK, SUBSCRIBE, ...)
/// are out of v1 scope, the same tiering stance the domain README takes.
const METHODS: &[&str] = &["INVITE", "ACK", "BYE", "CANCEL", "REGISTER", "OPTIONS"];

const SIP_VERSION: &[u8] = b"SIP/2.0";

static KEY: &[KeyField] = &[KeyField {
    a: CALL_ID,
    b: None, // shared (non-endpoint) qualifier: one stream per dialog
}];
static ROLLUPS: &[RollupSpec] = &[RollupSpec {
    field: METHOD,
    kind: RollupKind::Accumulate,
}];
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

/// Case-insensitive lookup of a header, honoring RFC 3261 §7.3.3's compact
/// forms for the headers this plugin names (`i`=Call-ID, `f`=From,
/// `t`=To, `v`=Via).
fn header_value<'a>(lines: &[&'a [u8]], name: &str, compact: Option<&str>) -> Option<&'a [u8]> {
    lines.iter().skip(1).find_map(|line| {
        let colon = line.iter().position(|&b| b == b':')?;
        let (key, rest) = line.split_at(colon);
        let matches = key.eq_ignore_ascii_case(name.as_bytes())
            || compact.is_some_and(|c| key.eq_ignore_ascii_case(c.as_bytes()));
        matches.then(|| trim_spaces(&rest[1..]))
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

fn parse_start_line(line: &[u8]) -> Result<StartLine, ParseError> {
    let mut parts = line.splitn(3, |&b| b == b' ');
    let first = parts
        .next()
        .ok_or(ParseError::Malformed("empty start line"))?;

    if first == SIP_VERSION {
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
        })
    } else {
        let method: &'static str = METHODS
            .iter()
            .copied()
            .find(|m| m.as_bytes() == first)
            .ok_or(ParseError::Malformed("unrecognized SIP method"))?;
        let _request_uri = parts
            .next()
            .ok_or(ParseError::Malformed("request line missing Request-URI"))?;
        let version = parts
            .next()
            .ok_or(ParseError::Malformed("request line missing SIP-Version"))?;
        if version != SIP_VERSION {
            return Err(ParseError::Malformed("unsupported SIP version"));
        }
        Ok(StartLine {
            is_request: true,
            method: Some(method),
            status_code: None,
        })
    }
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
        let start = parse_start_line(start)?;

        let call_id = header_value(&lines, "Call-ID", Some("i")).ok_or(ParseError::Malformed(
            "SIP message missing mandatory Call-ID",
        ))?;

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
            if let Some(v) = header_value(&lines, "From", Some("f")) {
                fields.insert(FROM, Value::from(to_str(v).as_str()));
            }
            if let Some(v) = header_value(&lines, "To", Some("t")) {
                fields.insert(TO, Value::from(to_str(v).as_str()));
            }
            if let Some(v) = header_value(&lines, "Via", Some("v")) {
                fields.insert(VIA, Value::from(to_str(v).as_str()));
            }
            if let Some(v) = header_value(&lines, "CSeq", None) {
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
        b"INVITE sip:bob@biloxi.example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bK776asdhds\r\n\
To: Bob <sip:bob@biloxi.example.com>\r\n\
From: Alice <sip:alice@atlanta.example.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.example.com\r\n\
CSeq: 314159 INVITE\r\n\
\r\n"
            .to_vec()
    }

    fn ringing_180() -> Vec<u8> {
        b"SIP/2.0 180 Ringing\r\n\
Via: SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bK776asdhds\r\n\
To: Bob <sip:bob@biloxi.example.com>;tag=8321234356\r\n\
From: Alice <sip:alice@atlanta.example.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.example.com\r\n\
CSeq: 314159 INVITE\r\n\
\r\n"
            .to_vec()
    }

    fn ok_200() -> Vec<u8> {
        b"SIP/2.0 200 OK\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.example.com\r\n\
CSeq: 314159 INVITE\r\n\
\r\n"
            .to_vec()
    }

    fn bye() -> Vec<u8> {
        b"BYE sip:bob@biloxi.example.com SIP/2.0\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.example.com\r\n\
CSeq: 315 BYE\r\n\
\r\n"
            .to_vec()
    }

    #[test]
    fn invite_reports_method_and_call_id() {
        let bytes = invite();
        let m = meta(bytes.len());
        let parsed = Sip
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid INVITE");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(IS_REQUEST), Some(&Value::Bool(true)));
        assert_eq!(parsed.fields.get(METHOD), Some(&Value::from("INVITE")));
        assert_eq!(
            parsed.fields.get(CALL_ID),
            Some(&Value::from("a84b4c76e66710@pc33.atlanta.example.com"))
        );
        assert_eq!(
            parsed.fields.get(FROM),
            Some(&Value::from(
                "Alice <sip:alice@atlanta.example.com>;tag=1928301774"
            ))
        );
        assert_eq!(parsed.fields.get(STATUS_CODE), None);
    }

    #[test]
    fn responses_share_call_id_and_report_status_code() {
        for (bytes, code) in [(ringing_180(), 180u64), (ok_200(), 200)] {
            let m = meta(bytes.len());
            let parsed = Sip
                .parse(&bytes, &ctx(Depth::Full, &m))
                .expect("valid response");
            assert_eq!(parsed.fields.get(IS_REQUEST), Some(&Value::Bool(false)));
            assert_eq!(parsed.fields.get(STATUS_CODE), Some(&Value::U64(code)));
            assert_eq!(parsed.fields.get(METHOD), None);
            assert_eq!(
                parsed.fields.get(CALL_ID),
                Some(&Value::from("a84b4c76e66710@pc33.atlanta.example.com"))
            );
        }
    }

    #[test]
    fn bye_shares_call_id_with_the_dialog() {
        let bytes = bye();
        let m = meta(bytes.len());
        let parsed = Sip.parse(&bytes, &ctx(Depth::Full, &m)).expect("valid BYE");
        assert_eq!(parsed.fields.get(METHOD), Some(&Value::from("BYE")));
        assert_eq!(
            parsed.fields.get(CALL_ID),
            Some(&Value::from("a84b4c76e66710@pc33.atlanta.example.com"))
        );
    }

    #[test]
    fn keys_depth_only_has_call_id() {
        let bytes = invite();
        let m = meta(bytes.len());
        let parsed = Sip
            .parse(&bytes, &ctx(Depth::Keys, &m))
            .expect("valid INVITE");
        assert_eq!(parsed.fields.len(), 1);
        assert!(parsed.fields.get(CALL_ID).is_some());
    }

    #[test]
    fn structural_depth_omits_full_only_headers() {
        let bytes = invite();
        let m = meta(bytes.len());
        let parsed = Sip
            .parse(&bytes, &ctx(Depth::Structural, &m))
            .expect("valid INVITE");
        assert_eq!(parsed.fields.get(METHOD), Some(&Value::from("INVITE")));
        assert_eq!(parsed.fields.get(FROM), None);
        assert_eq!(parsed.fields.get(VIA), None);
    }

    #[test]
    fn missing_call_id_declines() {
        let bytes = b"OPTIONS sip:bob@biloxi.example.com SIP/2.0\r\n\r\n".to_vec();
        let m = meta(bytes.len());
        assert!(Sip.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn unrecognized_method_declines() {
        let bytes = b"NOTAMETHOD sip:bob@biloxi.example.com SIP/2.0\r\n\
Call-ID: x\r\n\r\n"
            .to_vec();
        let m = meta(bytes.len());
        assert!(Sip.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn missing_blank_line_is_truncated() {
        let bytes = b"BYE sip:bob@biloxi.example.com SIP/2.0\r\nCall-ID: x\r\n".to_vec();
        let m = meta(bytes.len());
        assert!(matches!(
            Sip.parse(&bytes, &ctx(Depth::Full, &m)),
            Err(ParseError::Truncated(_))
        ));
    }

    #[test]
    fn truncated_frames_decline() {
        let bytes = invite();
        let m = meta(bytes.len());
        for n in 0..bytes.len() {
            let full = ctx(Depth::Full, &m);
            assert!(
                Sip.parse(&bytes[..n], &full).is_err(),
                "prefix of {n}/{} bytes must decline",
                bytes.len()
            );
        }
    }
}
