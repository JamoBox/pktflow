//! Redis / RESP (11.14 — Redis Serialization Protocol, redis.io; *no
//! standards body*, the project's own documentation is the canonical
//! reference). App-stream pattern (06.6): Redis's identity is its TCP
//! session, the same shape `mqtt`/`http` use.
//!
//! ## Wire format
//!
//! Every RESP value starts with a one-byte type prefix followed by a
//! CRLF-terminated line, recursively for aggregates:
//!
//! ```text
//! +OK\r\n                     Simple String
//! -ERR message\r\n            Error
//! :1000\r\n                   Integer
//! $6\r\nfoobar\r\n            Bulk String (length-prefixed; $-1\r\n = null)
//! *2\r\n$3\r\nGET\r\n$3\r\nfoo\r\n   Array (element-count-prefixed; *-1\r\n = null)
//! ```
//!
//! Client commands are always sent as an Array of Bulk Strings; this
//! plugin walks the **entire** top-level value to compute an honest
//! `header_len` (RESP arrays nest — `MULTI`/`EXEC` pipelines, or a
//! command whose own argument happens to be an array-shaped bulk string
//! payload elsewhere in the protocol family this walk generalizes to),
//! but only *decodes* the array's first element into `command` — the
//! same bounded-depth stance `amqp`'s method arguments and `ldap`'s
//! `bind_dn` take (D12). Deeper argument values are consumed (so framing
//! stays correct) but never individually extracted.

use pktflow_core::{
    Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx, ParseError, ParsedLayer,
    ProtocolName, RollupKind, RollupSpec, RouteId, StreamIdentity, Truncated, Value,
};

use pktflow_core::Canonicalize;

const APP: FieldName = "app";
const RESP_TYPE: FieldName = "resp_type";
const COMMAND: FieldName = "command";
const ARG_COUNT: FieldName = "arg_count";

const SIMPLE_STRING: u8 = b'+';
const ERROR: u8 = b'-';
const INTEGER: u8 = b':';
const BULK_STRING: u8 = b'$';
const ARRAY: u8 = b'*';

static KEY: &[KeyField] = &[KeyField { a: APP, b: None }];
static ROLLUPS: &[RollupSpec] = &[RollupSpec {
    field: COMMAND,
    kind: RollupKind::Accumulate,
}];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: ROLLUPS,
};

fn truncated(needed: usize, have: usize) -> ParseError {
    ParseError::Truncated(Truncated { needed, have })
}

fn find_crlf(bytes: &[u8], from: usize) -> Option<usize> {
    bytes
        .get(from..)?
        .windows(2)
        .position(|w| w == b"\r\n")
        .map(|p| from + p)
}

/// Reads one CRLF-terminated line starting at `pos`; returns the line
/// (without the CRLF) and the position just past it.
fn read_line(bytes: &[u8], pos: usize) -> Result<(&[u8], usize), ParseError> {
    let end = find_crlf(bytes, pos).ok_or(truncated(pos + 1, bytes.len()))?;
    Ok((&bytes[pos..end], end + 2))
}

fn parse_i64_line(line: &[u8]) -> Result<i64, ParseError> {
    std::str::from_utf8(line)
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .ok_or(ParseError::Malformed("RESP: invalid integer line"))
}

/// Advances past one bulk string's length-prefixed value (assumes the
/// `$` type byte has already been consumed and `pos` points at the
/// length line). A negative length is RESP's null bulk string: no value
/// bytes follow.
fn skip_bulk_body(bytes: &[u8], pos: usize) -> Result<usize, ParseError> {
    let (line, next) = read_line(bytes, pos)?;
    let len = parse_i64_line(line)?;
    if len < 0 {
        return Ok(next);
    }
    let len = len as usize;
    let value_end = next
        .checked_add(len)
        .ok_or(ParseError::Malformed("RESP: bulk string length overflow"))?;
    if bytes.len() < value_end + 2 {
        return Err(truncated(value_end + 2, bytes.len()));
    }
    if &bytes[value_end..value_end + 2] != b"\r\n" {
        return Err(ParseError::Malformed(
            "RESP: bulk string missing CRLF terminator",
        ));
    }
    Ok(value_end + 2)
}

/// Recursively advances past exactly one RESP value starting at `pos`
/// (its own type byte included), the walk `header_len` relies on for
/// arbitrarily nested arrays.
fn skip_value(bytes: &[u8], pos: usize) -> Result<usize, ParseError> {
    let ty = *bytes.get(pos).ok_or(truncated(pos + 1, bytes.len()))?;
    let pos = pos + 1;
    match ty {
        SIMPLE_STRING | ERROR | INTEGER => Ok(read_line(bytes, pos)?.1),
        BULK_STRING => skip_bulk_body(bytes, pos),
        ARRAY => {
            let (line, next) = read_line(bytes, pos)?;
            let count = parse_i64_line(line)?;
            if count < 0 {
                return Ok(next); // null array
            }
            let mut cur = next;
            for _ in 0..count {
                cur = skip_value(bytes, cur)?;
            }
            Ok(cur)
        }
        _ => Err(ParseError::Malformed("RESP: unrecognized type byte")),
    }
}

pub struct Redis;

impl LayerPlugin for Redis {
    fn name(&self) -> ProtocolName {
        "redis"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let ty = *bytes.first().ok_or(truncated(1, bytes.len()))?;
        if !matches!(ty, SIMPLE_STRING | ERROR | INTEGER | BULK_STRING | ARRAY) {
            return Err(ParseError::Malformed("RESP: unrecognized type byte"));
        }

        // Validate + measure the whole top-level value first (D7's "walk
        // once, name where it ends" — also the truncation/malformed check
        // for anything nested beyond the first array element).
        let header_len = skip_value(bytes, 0)?;

        let mut arg_count = None;
        let mut command = None;
        if ty == ARRAY {
            let (line, next) = read_line(bytes, 1)?;
            let count = parse_i64_line(line)?;
            if count >= 0 {
                arg_count = Some(count as u64);
                if count > 0 && bytes.get(next) == Some(&BULK_STRING) {
                    let (len_line, val_start) = read_line(bytes, next + 1)?;
                    let len = parse_i64_line(len_line)?;
                    if len >= 0 {
                        let len = len as usize;
                        // Already proven present by the skip_value walk above.
                        command = Some(
                            String::from_utf8_lossy(&bytes[val_start..val_start + len])
                                .into_owned(),
                        );
                    }
                }
            }
        }

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(APP, Value::from("redis"));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(RESP_TYPE, Value::U64(u64::from(ty)));
        }
        if ctx.depth() >= Depth::Full {
            if let Some(n) = arg_count {
                fields.insert(ARG_COUNT, Value::U64(n));
            }
            if let Some(c) = command {
                fields.insert(COMMAND, Value::from(c.as_str()));
            }
        }

        Ok(ParsedLayer {
            header_len,
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::TcpPort(6379)]
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

    fn bulk(s: &str) -> Vec<u8> {
        format!("${}\r\n{}\r\n", s.len(), s).into_bytes()
    }

    fn command_array(parts: &[&str]) -> Vec<u8> {
        let mut b = format!("*{}\r\n", parts.len()).into_bytes();
        for p in parts {
            b.extend_from_slice(&bulk(p));
        }
        b
    }

    #[test]
    fn set_command_reports_command_and_arg_count() {
        let bytes = command_array(&["SET", "foo", "bar"]);
        let m = meta(bytes.len());
        let parsed = Redis
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid SET command");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(APP), Some(&Value::from("redis")));
        assert_eq!(
            parsed.fields.get(RESP_TYPE),
            Some(&Value::U64(u64::from(ARRAY)))
        );
        assert_eq!(parsed.fields.get(COMMAND), Some(&Value::from("SET")));
        assert_eq!(parsed.fields.get(ARG_COUNT), Some(&Value::U64(3)));
    }

    #[test]
    fn simple_string_ok_response_has_no_command() {
        let bytes = b"+OK\r\n".to_vec();
        let m = meta(bytes.len());
        let parsed = Redis
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid simple string");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(
            parsed.fields.get(RESP_TYPE),
            Some(&Value::U64(u64::from(SIMPLE_STRING)))
        );
        assert_eq!(parsed.fields.get(COMMAND), None);
        assert_eq!(parsed.fields.get(ARG_COUNT), None);
    }

    #[test]
    fn error_response_parses() {
        let bytes = b"-ERR unknown command\r\n".to_vec();
        let m = meta(bytes.len());
        let parsed = Redis
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid error");
        assert_eq!(
            parsed.fields.get(RESP_TYPE),
            Some(&Value::U64(u64::from(ERROR)))
        );
    }

    #[test]
    fn integer_response_parses() {
        let bytes = b":1000\r\n".to_vec();
        let m = meta(bytes.len());
        let parsed = Redis
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid integer");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(
            parsed.fields.get(RESP_TYPE),
            Some(&Value::U64(u64::from(INTEGER)))
        );
    }

    /// MULTI/EXEC-shaped nested array: the top-level `command` is still
    /// correctly extracted from the first element without attempting the
    /// nested array's own walk into fields.
    #[test]
    fn nested_array_command_yields_top_level_command_only() {
        let mut bytes = b"*2\r\n".to_vec();
        bytes.extend_from_slice(&bulk("MULTI"));
        // Second top-level element is itself an array (framing-only skip).
        bytes.extend_from_slice(&command_array(&["SET", "a", "b"]));

        let m = meta(bytes.len());
        let parsed = Redis
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid nested array");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.fields.get(COMMAND), Some(&Value::from("MULTI")));
        assert_eq!(parsed.fields.get(ARG_COUNT), Some(&Value::U64(2)));
    }

    #[test]
    fn null_bulk_string_first_element_has_no_command() {
        let bytes = b"*1\r\n$-1\r\n".to_vec();
        let m = meta(bytes.len());
        let parsed = Redis
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid array with null bulk string");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.fields.get(COMMAND), None);
        assert_eq!(parsed.fields.get(ARG_COUNT), Some(&Value::U64(1)));
    }

    #[test]
    fn null_array_has_arg_count_none() {
        let bytes = b"*-1\r\n".to_vec();
        let m = meta(bytes.len());
        let parsed = Redis
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid null array");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.fields.get(ARG_COUNT), None);
        assert_eq!(parsed.fields.get(COMMAND), None);
    }

    #[test]
    fn unrecognized_type_byte_declines() {
        let bytes = b"!5\r\nhello\r\n".to_vec(); // RESP3 verbatim string, out of v1 scope
        let m = meta(bytes.len());
        assert!(Redis.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn missing_terminator_is_truncated() {
        let bytes = b"$3\r\nfoo".to_vec(); // missing trailing CRLF
        let m = meta(bytes.len());
        assert!(matches!(
            Redis.parse(&bytes, &ctx(Depth::Full, &m)),
            Err(ParseError::Truncated(_))
        ));
    }

    #[test]
    fn truncated_frames_decline() {
        let bytes = command_array(&["GET", "foo"]);
        let m = meta(bytes.len());
        for n in 0..bytes.len() {
            let full = ctx(Depth::Full, &m);
            assert!(
                Redis.parse(&bytes[..n], &full).is_err(),
                "prefix of {n}/{} bytes must decline",
                bytes.len()
            );
        }
    }

    #[test]
    fn keys_depth_only_has_app() {
        let bytes = command_array(&["PING"]);
        let m = meta(bytes.len());
        let parsed = Redis
            .parse(&bytes, &ctx(Depth::Keys, &m))
            .expect("valid PING");
        assert_eq!(parsed.fields.len(), 1);
        assert_eq!(parsed.fields.get(APP), Some(&Value::from("redis")));
    }

    #[test]
    fn structural_depth_omits_command_and_arg_count() {
        let bytes = command_array(&["PING"]);
        let m = meta(bytes.len());
        let parsed = Redis
            .parse(&bytes, &ctx(Depth::Structural, &m))
            .expect("valid PING");
        assert_eq!(
            parsed.fields.get(RESP_TYPE),
            Some(&Value::U64(u64::from(ARRAY)))
        );
        assert_eq!(parsed.fields.get(COMMAND), None);
        assert_eq!(parsed.fields.get(ARG_COUNT), None);
    }
}
