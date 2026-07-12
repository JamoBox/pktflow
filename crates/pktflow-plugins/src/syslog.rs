//! Syslog — 11.11, D14 citation: RFC 5424 (the current IETF standard) and
//! RFC 3164 (informational; the legacy "BSD syslog" wire format still seen
//! from older devices). Both are plain-text, line-oriented protocols: the
//! only binary-ish piece is the leading `<PRI>` byte run.
//!
//! **Format disambiguation.** RFC 5424 §6.2 puts a `VERSION` field
//! (`NONZERO-DIGIT *2DIGIT SP`) directly after `<PRI>`; RFC 3164's
//! `TIMESTAMP` in that position always starts with a month-name letter
//! (`"Jan"`, `"Feb"`, ...). Trying the version pattern first and falling
//! back to the legacy shape on mismatch is exactly the test RFC 5424 itself
//! recommends relying on (a receiver "MUST" tolerate legacy input, and the
//! version token is how it tells the two apart).
//!
//! **App-stream pattern (06.6).** Syslog has no endpoint identity of its
//! own — `app = "syslog"` is a shared constant key, so one child stream
//! forms per UDP stream (sender -> collector), the same shape as
//! `dns`/`dhcp`/`ntp`.
//!
//! **v1 scope (D12/D13 note).** `STRUCTURED-DATA` (RFC 5424 §6.3) is walked
//! only far enough to find its end — SD-ID/PARAM-NAME/PARAM-VALUE are not
//! decoded into fields, the same "tag-level, not full-grammar" ceiling this
//! task already applies to its ASN.1/BER protocols. Multi-line messages,
//! non-transparent framing (RFC 6587's octet-counting over TCP), and
//! reverse-DNS/CEF/RFC5425-TLS variants are out of scope for this file.
//!
//! **Why every "good" fixture stops at STRUCTURED-DATA / the TAG colon.**
//! RFC 5424's trailing `[SP MSG]` (and this dissector's legacy analogue) is
//! wholly optional grammar: a header with nothing after it and a header
//! with content after it are *both* valid syslog messages. Any conformance
//! fixture that included trailing content would make some one-byte-shorter
//! prefix of it *also* a legal (if shorter) message — silently violating
//! the 09.1 kit's truncation invariant (every strict prefix of a good
//! sample must decline). Every fixed/delimited field up to and including
//! STRUCTURED-DATA's own terminator (`-`, or a SD-ELEMENT's `]`) has no
//! such escape hatch, so the kit's "good" samples end exactly there; the
//! `msg` field itself is exercised by full RFC-example messages in
//! `application.rs`, run through `Engine::dissect` rather than the
//! strict-truncation kit.

use pktflow_core::{
    ByteReader, Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx,
    ParseError, ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId, StreamIdentity, Value,
};

const APP: FieldName = "app";
const FACILITY: FieldName = "facility";
const SEVERITY: FieldName = "severity";
const VERSION: FieldName = "version";
const HOSTNAME: FieldName = "hostname";
const APP_NAME: FieldName = "app_name";
const MSG: FieldName = "msg";

/// RFC 3164 §4.1.2's fixed BSD timestamp width: `"Mmm dd hh:mm:ss"`.
const LEGACY_TIMESTAMP_LEN: usize = 15;
/// RFC 3164 §4.1.3: "the TAG... MUST NOT exceed 32 characters".
const MAX_TAG_LEN: usize = 32;

static KEY: &[KeyField] = &[KeyField { a: APP, b: None }];
static ROLLUPS: &[RollupSpec] = &[RollupSpec {
    field: SEVERITY,
    kind: RollupKind::Accumulate,
}];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: ROLLUPS,
};

/// `<PRI>`: `"<"` `1*3DIGIT` `">"`, value `<= 191` (`facility*8 +
/// severity`, facility `0..=23`, severity `0..=7`, RFC 5424 §6.2.1 / RFC
/// 3164 §4.1.1). Returns the PRI value and the position right after `'>'`.
fn read_pri(bytes: &[u8]) -> Result<(u8, usize), ParseError> {
    if bytes.first() != Some(&b'<') {
        return Err(ParseError::Malformed("missing PRI open bracket"));
    }
    let start = 1usize;
    let mut end = start;
    while end - start < 3 && bytes.get(end).is_some_and(u8::is_ascii_digit) {
        end += 1;
    }
    if end == start {
        return Err(ParseError::Malformed("PRI has no digits"));
    }
    if bytes.get(end) != Some(&b'>') {
        return Err(ParseError::Malformed("missing PRI close bracket"));
    }
    let digits = bytes
        .get(start..end)
        .ok_or(ParseError::Malformed("PRI digit slice out of range"))?;
    let value = digits
        .iter()
        .fold(0u32, |acc, &b| acc * 10 + u32::from(b - b'0'));
    if value > 191 {
        return Err(ParseError::Malformed("PRI exceeds facility*8+severity max"));
    }
    Ok((value as u8, end + 1))
}

/// RFC 5424 §6.2's `VERSION`: `NONZERO-DIGIT *2DIGIT` immediately followed
/// by a space. `None` means "does not look like 5424" — the caller falls
/// back to the legacy shape, per this module's format-disambiguation note.
fn read_version(bytes: &[u8], pos: usize) -> Option<(u8, usize)> {
    let first = *bytes.get(pos)?;
    if !first.is_ascii_digit() || first == b'0' {
        return None;
    }
    let mut end = pos + 1;
    while end - pos < 3 && bytes.get(end).is_some_and(u8::is_ascii_digit) {
        end += 1;
    }
    if bytes.get(end) != Some(&b' ') {
        return None;
    }
    let digits = bytes.get(pos..end)?;
    let value = digits
        .iter()
        .fold(0u32, |acc, &b| acc * 10 + u32::from(b - b'0'));
    Some((value.min(u32::from(u8::MAX)) as u8, end + 1))
}

/// One SP-delimited header field: `(start, end, next_pos)`, `end`
/// exclusive of the delimiting space. Every RFC 5424 header field is at
/// least a NILVALUE `"-"`, never truly empty, so a zero-length token is
/// malformed rather than skipped.
fn read_field(bytes: &[u8], pos: usize) -> Result<(usize, usize, usize), ParseError> {
    let rel = bytes
        .get(pos..)
        .and_then(|s| s.iter().position(|&b| b == b' '))
        .ok_or(ParseError::Malformed("expected SP-delimited header field"))?;
    let end = pos + rel;
    if end == pos {
        return Err(ParseError::Malformed("empty header field"));
    }
    Ok((pos, end, end + 1))
}

/// Walks one SD-ELEMENT (`"[" SD-ID *(SP SD-PARAM) "]"`) far enough to
/// find its closing bracket, honoring RFC 5424 §6.3's escaping rule so a
/// `\]`/`\"`/`\\` inside a PARAM-VALUE doesn't end the element early.
/// Field-level decode of SD-ID/PARAM-VALUE is out of v1 scope (module
/// doc).
fn skip_sd_element(bytes: &[u8], open: usize) -> Result<usize, ParseError> {
    let mut p = open + 1;
    loop {
        match bytes.get(p) {
            Some(b']') => return Ok(p + 1),
            Some(b'\\') => {
                p += 1;
                if bytes.get(p).is_none() {
                    return Err(ParseError::Malformed("dangling escape in structured data"));
                }
                p += 1;
            }
            Some(_) => p += 1,
            None => {
                return Err(ParseError::Malformed(
                    "unterminated structured-data element",
                ))
            }
        }
    }
}

/// `STRUCTURED-DATA` (RFC 5424 §6.3): the NILVALUE `"-"`, or one or more
/// back-to-back `[SD-ELEMENT]`s. Returns the position right after it.
fn skip_structured_data(bytes: &[u8], pos: usize) -> Result<usize, ParseError> {
    match bytes.get(pos) {
        Some(b'-') => Ok(pos + 1),
        Some(b'[') => {
            let mut p = pos;
            while bytes.get(p) == Some(&b'[') {
                p = skip_sd_element(bytes, p)?;
            }
            Ok(p)
        }
        _ => Err(ParseError::Malformed("invalid structured-data marker")),
    }
}

/// Optional trailing `SP MSG` / CONTENT: present only when at least one
/// more byte follows the separator. A dangling separator with nothing
/// after it is treated as malformed rather than an empty message — see
/// the module doc's truncation-invariant note for why "absent" and
/// "present-but-empty" can't both be legal here.
fn trailing_msg(bytes: &[u8], pos: usize) -> Result<Option<(usize, usize)>, ParseError> {
    match bytes.get(pos) {
        None => Ok(None),
        Some(&b' ') => {
            let msg_start = pos + 1;
            if msg_start >= bytes.len() {
                return Err(ParseError::Malformed(
                    "dangling separator with empty message",
                ));
            }
            Ok(Some((msg_start, bytes.len())))
        }
        Some(_) => Err(ParseError::Malformed("expected SP before message")),
    }
}

fn to_str(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

pub struct Syslog;

impl LayerPlugin for Syslog {
    fn name(&self) -> ProtocolName {
        "syslog"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let (pri, pos) = read_pri(bytes)?;
        let facility = pri >> 3;
        let severity = pri & 0x07;

        let (version, hostname, app_name, msg, header_len) =
            if let Some((version, pos)) = read_version(bytes, pos) {
                // RFC 5424 §6: VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME
                // SP PROCID SP MSGID SP STRUCTURED-DATA [SP MSG].
                let (_, _, pos) = read_field(bytes, pos)?; // TIMESTAMP
                let (hn_s, hn_e, pos) = read_field(bytes, pos)?; // HOSTNAME
                let (an_s, an_e, pos) = read_field(bytes, pos)?; // APP-NAME
                let (_, _, pos) = read_field(bytes, pos)?; // PROCID
                let (_, _, pos) = read_field(bytes, pos)?; // MSGID
                let sd_end = skip_structured_data(bytes, pos)?;
                let msg_range = trailing_msg(bytes, sd_end)?;
                let header_len = msg_range.map_or(sd_end, |(_, e)| e);
                let hostname = bytes.get(hn_s..hn_e).map(to_str);
                let app_name = bytes.get(an_s..an_e).map(to_str);
                let msg = msg_range.and_then(|(s, e)| bytes.get(s..e)).map(to_str);
                (Some(version), hostname, app_name, msg, header_len)
            } else {
                // Legacy RFC 3164 §4.1: fixed-width TIMESTAMP, HOSTNAME,
                // then TAG (`[PID]`)? ":" — the colon is this dissector's
                // chosen TAG/CONTENT boundary (a near-universal real-world
                // convention, not a strict RFC 3164 requirement, adopted
                // here as the unambiguous framing the plugin needs).
                let mut r = ByteReader::new(bytes.get(pos..).unwrap_or(&[]));
                let _timestamp = r.take(LEGACY_TIMESTAMP_LEN)?;
                let ts_end = pos + LEGACY_TIMESTAMP_LEN;
                if bytes.get(ts_end) != Some(&b' ') {
                    return Err(ParseError::Malformed("missing SP after legacy timestamp"));
                }
                let (hn_s, hn_e, tag_start) = read_field(bytes, ts_end + 1)?;

                let mut tag_end = tag_start;
                while tag_end - tag_start < MAX_TAG_LEN
                    && bytes.get(tag_end).is_some_and(u8::is_ascii_alphanumeric)
                {
                    tag_end += 1;
                }
                if tag_end == tag_start {
                    return Err(ParseError::Malformed("empty legacy TAG"));
                }

                let mut p = tag_end;
                if bytes.get(p) == Some(&b'[') {
                    let pid_start = p + 1;
                    let mut pid_end = pid_start;
                    while bytes.get(pid_end).is_some_and(u8::is_ascii_digit) {
                        pid_end += 1;
                    }
                    if pid_end == pid_start || bytes.get(pid_end) != Some(&b']') {
                        return Err(ParseError::Malformed("malformed legacy PID suffix"));
                    }
                    p = pid_end + 1;
                }
                if bytes.get(p) != Some(&b':') {
                    return Err(ParseError::Malformed("missing legacy TAG terminator"));
                }
                let colon_end = p + 1;

                let msg_range = trailing_msg(bytes, colon_end)?;
                let header_len = msg_range.map_or(colon_end, |(_, e)| e);
                let hostname = bytes.get(hn_s..hn_e).map(to_str);
                let app_name = bytes.get(tag_start..tag_end).map(to_str);
                let msg = msg_range.and_then(|(s, e)| bytes.get(s..e)).map(to_str);
                (None, hostname, app_name, msg, header_len)
            };

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(APP, Value::from("syslog"));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(FACILITY, Value::U64(u64::from(facility)));
            fields.insert(SEVERITY, Value::U64(u64::from(severity)));
            fields.insert(VERSION, Value::U64(u64::from(version.unwrap_or(0))));
        }
        if ctx.depth() >= Depth::Full {
            if let Some(h) = hostname {
                fields.insert(HOSTNAME, Value::from(h.as_str()));
            }
            if let Some(a) = app_name {
                fields.insert(APP_NAME, Value::from(a.as_str()));
            }
            if let Some(m) = msg {
                fields.insert(MSG, Value::from(m.as_str()));
            }
        }

        Ok(ParsedLayer {
            header_len,
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::UdpPort(514)]
    }

    fn stream_identity(&self) -> Option<&StreamIdentity> {
        Some(&IDENTITY)
    }
}
