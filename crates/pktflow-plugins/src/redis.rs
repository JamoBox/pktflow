//! Redis / RESP (11.14 — Redis Serialization Protocol, redis.io; *no
//! standards body*, the project's own documentation is the canonical
//! reference, D14) — app-stream pattern (06.6).
//!
//! ## RESP types (redis.io/docs/reference/protocol-spec)
//! Every value opens with a one-byte type marker: Simple String `+`,
//! Error `-`, Integer `:`, Bulk String `$`, Array `*`, each followed by
//! content and a `CRLF` terminator. `header_len` covers exactly one
//! top-level value — for `+`/`-`/`:` that is the single line; for `$` the
//! declared-length content plus its terminator (or, for a null bulk
//! string, `$-1\r\n`, just the count line); for `*` **only the count line
//! itself**, plus — best-effort — its first element when that element is
//! a bulk string (the command name), never the rest of the array. This
//! mirrors the field table's own "only enough of the array is walked to
//! read the command name" scope: a nested array, a null first element, or
//! a truncated first element all just leave `command` absent rather than
//! declining the whole array or attempting a deeper walk.

use pktflow_core::{
    Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx, ParseError,
    ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId, StreamIdentity, Truncated, Value,
};

const APP: FieldName = "app";
const RESP_TYPE: FieldName = "resp_type";
const COMMAND: FieldName = "command";
const ARG_COUNT: FieldName = "arg_count";

/// Finds the line's `CRLF` terminator; returns `(line, bytes-including-CRLF)`.
fn find_line(bytes: &[u8]) -> Option<(&[u8], usize)> {
    let pos = bytes.windows(2).position(|w| w == b"\r\n")?;
    Some((&bytes[..pos], pos + 2))
}

fn parse_int(bytes: &[u8]) -> Option<i64> {
    std::str::from_utf8(bytes).ok()?.parse().ok()
}

fn truncated(needed: usize, have: usize) -> ParseError {
    ParseError::Truncated(Truncated { needed, have })
}

/// Parses a bulk string whose `'$'` marker is `bytes[0]`. Returns
/// `(content if non-null, total bytes consumed)`.
fn parse_bulk_string(bytes: &[u8]) -> Result<(Option<&[u8]>, usize), ParseError> {
    let rest = &bytes[1..];
    let (line, line_consumed) = find_line(rest).ok_or(truncated(rest.len() + 1, rest.len()))?;
    let len = parse_int(line).ok_or(ParseError::Malformed("bad bulk string length"))?;
    if len < 0 {
        return Ok((None, 1 + line_consumed));
    }
    let len =
        usize::try_from(len).map_err(|_| ParseError::Malformed("bulk string length too large"))?;
    let content_start = 1 + line_consumed;
    let content_end = content_start + len;
    let content = bytes
        .get(content_start..content_end)
        .ok_or(truncated(content_end, bytes.len()))?;
    let trailing = bytes
        .get(content_end..content_end + 2)
        .ok_or(truncated(content_end + 2, bytes.len()))?;
    if trailing != b"\r\n" {
        return Err(ParseError::Malformed("bulk string missing CRLF terminator"));
    }
    Ok((Some(content), content_end + 2))
}

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

pub struct Redis;

impl LayerPlugin for Redis {
    fn name(&self) -> ProtocolName {
        "redis"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let type_byte = *bytes.first().ok_or(truncated(1, 0))?;
        let resp_type = match type_byte {
            b'+' => "simple_string",
            b'-' => "error",
            b':' => "integer",
            b'$' => "bulk_string",
            b'*' => "array",
            _ => return Err(ParseError::Malformed("not a recognized RESP type byte")),
        };
        let rest = &bytes[1..];

        let mut header_len;
        let mut command: Option<&str> = None;
        let mut arg_count = None;

        match type_byte {
            b'$' => {
                let (_content, consumed) = parse_bulk_string(bytes)?;
                header_len = consumed;
            }
            b'*' => {
                let (line, consumed) =
                    find_line(rest).ok_or(truncated(rest.len() + 1, rest.len()))?;
                let count = parse_int(line).ok_or(ParseError::Malformed("bad array count"))?;
                header_len = 1 + consumed;
                if count > 0 {
                    arg_count = Some(count as u64);
                    if bytes.get(header_len) == Some(&b'$') {
                        if let Ok((Some(text), elem_consumed)) =
                            parse_bulk_string(&bytes[header_len..])
                        {
                            if let Ok(s) = std::str::from_utf8(text) {
                                command = Some(s);
                                header_len += elem_consumed;
                            }
                        }
                    }
                } else if count == 0 {
                    arg_count = Some(0);
                }
                // count < 0 (null array): arg_count stays None, header_len
                // is already the count line only.
            }
            _ => {
                let (_line, consumed) =
                    find_line(rest).ok_or(truncated(rest.len() + 1, rest.len()))?;
                header_len = 1 + consumed;
            }
        }

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(APP, Value::from("redis"));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(RESP_TYPE, Value::from(resp_type));
        }
        if ctx.depth() >= Depth::Full {
            if let Some(cmd) = command {
                fields.insert(COMMAND, Value::from(cmd));
            }
            if let Some(n) = arg_count {
                fields.insert(ARG_COUNT, Value::U64(n));
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
        format!("${}\r\n{s}\r\n", s.len()).into_bytes()
    }

    fn array_command(parts: &[&str]) -> Vec<u8> {
        let mut b = format!("*{}\r\n", parts.len()).into_bytes();
        for p in parts {
            b.extend_from_slice(&bulk(p));
        }
        b
    }

    #[test]
    fn set_command_array_parses_command_and_arg_count() {
        let bytes = array_command(&["SET", "foo", "bar"]);
        let m = meta(bytes.len());
        let parsed = Redis
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid SET command");
        // header_len stops after the command element, not the whole array.
        let expected_header_len = "*3\r\n".len() + bulk("SET").len();
        assert_eq!(parsed.header_len, expected_header_len);
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(APP), Some(&Value::from("redis")));
        assert_eq!(parsed.fields.get(RESP_TYPE), Some(&Value::from("array")));
        assert_eq!(parsed.fields.get(COMMAND), Some(&Value::from("SET")));
        assert_eq!(parsed.fields.get(ARG_COUNT), Some(&Value::U64(3)));
    }

    #[test]
    fn simple_string_ok_response_parses() {
        let bytes = b"+OK\r\n".to_vec();
        let m = meta(bytes.len());
        let parsed = Redis.parse(&bytes, &ctx(Depth::Full, &m)).expect("valid");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(
            parsed.fields.get(RESP_TYPE),
            Some(&Value::from("simple_string"))
        );
        assert_eq!(parsed.fields.get(COMMAND), None);
    }

    #[test]
    fn error_and_integer_types_parse() {
        let err = b"-ERR unknown command\r\n".to_vec();
        let m = meta(err.len());
        let parsed = Redis.parse(&err, &ctx(Depth::Full, &m)).expect("valid");
        assert_eq!(parsed.fields.get(RESP_TYPE), Some(&Value::from("error")));

        let int = b":1000\r\n".to_vec();
        let m = meta(int.len());
        let parsed = Redis.parse(&int, &ctx(Depth::Full, &m)).expect("valid");
        assert_eq!(parsed.fields.get(RESP_TYPE), Some(&Value::from("integer")));
    }

    #[test]
    fn bare_bulk_string_parses_whole_value() {
        let bytes = bulk("foobar");
        let m = meta(bytes.len());
        let parsed = Redis.parse(&bytes, &ctx(Depth::Full, &m)).expect("valid");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(
            parsed.fields.get(RESP_TYPE),
            Some(&Value::from("bulk_string"))
        );
    }

    #[test]
    fn null_bulk_string_parses_count_line_only() {
        let bytes = b"$-1\r\n".to_vec();
        let m = meta(bytes.len());
        let parsed = Redis.parse(&bytes, &ctx(Depth::Full, &m)).expect("valid");
        assert_eq!(parsed.header_len, bytes.len());
    }

    /// A nested-array command (e.g. a MULTI/EXEC pipeline's reply, itself
    /// an array of arrays): the top-level `arg_count` still parses, but
    /// `command` stays absent since the first element isn't a bulk string
    /// — no attempt at the nested walk, no crash.
    #[test]
    fn nested_array_yields_top_level_arg_count_but_no_command() {
        let mut bytes = b"*1\r\n".to_vec();
        bytes.extend_from_slice(&array_command(&["GET", "x"]));
        let m = meta(bytes.len());
        let parsed = Redis
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid nested array");
        assert_eq!(parsed.fields.get(ARG_COUNT), Some(&Value::U64(1)));
        assert_eq!(parsed.fields.get(COMMAND), None);
        assert_eq!(parsed.header_len, "*1\r\n".len());
    }

    #[test]
    fn depth_gates_resp_type_and_command() {
        let bytes = array_command(&["GET", "foo"]);
        let m = meta(bytes.len());
        let keys = Redis.parse(&bytes, &ctx(Depth::Keys, &m)).expect("valid");
        assert_eq!(keys.fields.get(APP), Some(&Value::from("redis")));
        assert_eq!(keys.fields.get(RESP_TYPE), None);

        let structural = Redis
            .parse(&bytes, &ctx(Depth::Structural, &m))
            .expect("valid");
        assert_eq!(
            structural.fields.get(RESP_TYPE),
            Some(&Value::from("array"))
        );
        assert_eq!(structural.fields.get(COMMAND), None);
    }

    #[test]
    fn unrecognized_type_byte_declines() {
        let bytes = b"!weird\r\n".to_vec();
        let m = meta(bytes.len());
        assert!(Redis.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn truncated_bulk_string_declines_at_every_prefix() {
        // A bare bulk string has no optional lookahead (unlike an array's
        // best-effort command peek below): every byte up to its own
        // content+CRLF is mandatory, so truncation is monotonic here.
        let bytes = bulk("foobar");
        let m = meta(bytes.len());
        let full = ctx(Depth::Full, &m);
        for n in 0..bytes.len() {
            assert!(
                Redis.parse(&bytes[..n], &full).is_err(),
                "prefix of {n}/{} bytes must decline",
                bytes.len()
            );
        }
    }

    /// An array's first-element lookahead is optional/best-effort (module
    /// doc): its own truncation is swallowed, not propagated, so *any*
    /// buffer holding at least the count line is a legitimately valid
    /// parse — either the short form (`header_len == 4`, `command` absent)
    /// when the first element is missing or itself incomplete, or the full
    /// form once that element is genuinely complete. Only truncation
    /// *within the count line itself* is a real decline.
    #[test]
    fn array_count_line_alone_is_a_valid_shorter_parse_not_a_truncation() {
        let bytes = array_command(&["SET", "foo", "bar"]);
        let m = meta(bytes.len());
        let full = ctx(Depth::Full, &m);

        // Within the count line ("*3\r\n"): a genuine truncation.
        for n in 0..4 {
            assert!(
                Redis.parse(&bytes[..n], &full).is_err(),
                "prefix of {n}/4 count-line bytes must decline"
            );
        }

        // From the count line onward, every prefix is a valid parse: short
        // form while the first element is missing/incomplete, full form
        // once it's genuinely present.
        let full_header_len = Redis.parse(&bytes, &full).expect("valid").header_len;
        for n in 4..full_header_len {
            let parsed = Redis
                .parse(&bytes[..n], &full)
                .unwrap_or_else(|e| panic!("prefix of {n} bytes: {e}"));
            assert_eq!(parsed.header_len, 4, "prefix of {n} bytes: short form");
            assert_eq!(parsed.fields.get(COMMAND), None);
        }
        let complete = Redis
            .parse(&bytes[..full_header_len], &full)
            .expect("valid");
        assert_eq!(complete.header_len, full_header_len);
        assert_eq!(complete.fields.get(COMMAND), Some(&Value::from("SET")));
    }
}
