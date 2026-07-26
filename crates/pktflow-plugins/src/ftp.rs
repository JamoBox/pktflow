//! FTP (11.9, RFC 959) — app-stream pattern (06.6), the **tagged
//! command/response pattern** shared with `smtp`/`imap`/`pop3` in this
//! domain: a client sends a line-oriented command, the server replies with
//! a status code/word plus text. Per D7, the data that follows a
//! transfer-initiating command (the data channel itself) is not this
//! plugin's business — only the control-channel line is parsed.
//!
//! ## Line framing (RFC 959 §5.2 requires CRLF; a bare LF is tolerated)
//! `header_len` covers through the line terminator; a line with no
//! terminator in this segment is `Truncated` (D7, no reassembly — the same
//! shape `ssh`'s banner line and `http`'s header block take).
//!
//! ## Two line shapes
//! **Response**: three ASCII digits (`reply_code`) followed by `' '` or
//! `'-'` (RFC 959 §4.2's multi-line continuation marker; this plugin does
//! not distinguish a continuation line from the final line of a multi-line
//! reply — both parse the same way, since walking the whole multi-line
//! reply would need cross-packet state, D7) or nothing at all, then the
//! reply text. **Request**: an alphabetic command token, then an optional
//! `' '`-separated argument. Anything else declines — the port-claim-
//! honesty stance 06.6 documents for non-DNS traffic on port 53.
//!
//! ## Data channel (D15)
//! `PASV`/`PORT`'s negotiated port is readable as this plugin's raw `arg`
//! text (e.g. `"Entering Passive Mode (192,168,1,1,200,3)"`), but the
//! resulting data-channel session is not correlated back to this control
//! stream or auto-routed — it appears as an ordinary untagged TCP session
//! in v1, D15's documented ceiling.

use pktflow_core::{
    Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx, ParseError,
    ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId, StreamIdentity, Value,
};

const APP: FieldName = "app";
const IS_REQUEST: FieldName = "is_request";
const COMMAND: FieldName = "command";
const REPLY_CODE: FieldName = "reply_code";
const ARG: FieldName = "arg";

static KEY: &[KeyField] = &[KeyField { a: APP, b: None }];
static ROLLUPS: &[RollupSpec] = &[
    RollupSpec {
        field: COMMAND,
        kind: RollupKind::Accumulate,
    },
    RollupSpec {
        field: REPLY_CODE,
        kind: RollupKind::Accumulate,
    },
];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: ROLLUPS,
};

/// Finds the line terminator (`\r\n` preferred, bare `\n` tolerated) and
/// returns `(line-without-terminator, header_len)`.
fn split_line(bytes: &[u8]) -> Option<(&[u8], usize)> {
    let nl = bytes.iter().position(|&b| b == b'\n')?;
    let header_len = nl + 1;
    let line = if nl > 0 && bytes[nl - 1] == b'\r' {
        &bytes[..nl - 1]
    } else {
        &bytes[..nl]
    };
    Some((line, header_len))
}

/// A three-digit reply code shape: `DDD` then `' '`, `'-'`, or end of line.
fn parse_reply_code(line: &[u8]) -> Option<(u16, &[u8])> {
    if line.len() < 3 || !line[..3].iter().all(u8::is_ascii_digit) {
        return None;
    }
    let code = line[..3]
        .iter()
        .fold(0u16, |acc, &b| acc * 10 + u16::from(b - b'0'));
    let rest = match line.get(3) {
        None => &line[3..],
        Some(b' ' | b'-') => &line[4.min(line.len())..],
        Some(_) => return None,
    };
    Some((code, rest))
}

/// A command token: one or more ASCII alphabetic bytes, then `' '` or end.
fn parse_command(line: &[u8]) -> Option<(&[u8], &[u8])> {
    let end = line.iter().position(|&b| b == b' ').unwrap_or(line.len());
    if end == 0 || !line[..end].iter().all(u8::is_ascii_alphabetic) {
        return None;
    }
    let arg = if end < line.len() {
        &line[end + 1..]
    } else {
        &line[end..]
    };
    Some((&line[..end], arg))
}

pub struct Ftp;

impl LayerPlugin for Ftp {
    fn name(&self) -> ProtocolName {
        "ftp"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let (line, header_len) =
            split_line(bytes).ok_or(ParseError::Truncated(pktflow_core::Truncated {
                needed: bytes.len() + 1,
                have: bytes.len(),
            }))?;

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(APP, Value::from("ftp"));
        }

        if let Some((code, rest)) = parse_reply_code(line) {
            if ctx.depth() >= Depth::Structural {
                fields.insert(IS_REQUEST, Value::Bool(false));
                fields.insert(REPLY_CODE, Value::U64(u64::from(code)));
            }
            if ctx.depth() >= Depth::Full {
                fields.insert(ARG, Value::from(String::from_utf8_lossy(rest).as_ref()));
            }
        } else if let Some((cmd, arg)) = parse_command(line) {
            let mut upper = cmd.to_vec();
            upper.make_ascii_uppercase();
            let cmd_str = String::from_utf8_lossy(&upper).into_owned();
            if ctx.depth() >= Depth::Structural {
                fields.insert(IS_REQUEST, Value::Bool(true));
                fields.insert(COMMAND, Value::from(cmd_str.as_str()));
            }
            if ctx.depth() >= Depth::Full {
                fields.insert(ARG, Value::from(String::from_utf8_lossy(arg).as_ref()));
            }
        } else {
            return Err(ParseError::Malformed(
                "not an FTP reply code or command line",
            ));
        }

        Ok(ParsedLayer {
            header_len,
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::TcpPort(21)]
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

    #[test]
    fn user_command_parses() {
        let bytes = b"USER anonymous\r\n".to_vec();
        let m = meta(bytes.len());
        let parsed = Ftp
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid USER command");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(APP), Some(&Value::from("ftp")));
        assert_eq!(parsed.fields.get(IS_REQUEST), Some(&Value::Bool(true)));
        assert_eq!(parsed.fields.get(COMMAND), Some(&Value::from("USER")));
        assert_eq!(parsed.fields.get(ARG), Some(&Value::from("anonymous")));
    }

    #[test]
    fn argless_command_parses() {
        let bytes = b"PASV\r\n".to_vec();
        let m = meta(bytes.len());
        let parsed = Ftp.parse(&bytes, &ctx(Depth::Full, &m)).expect("valid");
        assert_eq!(parsed.fields.get(COMMAND), Some(&Value::from("PASV")));
        assert_eq!(parsed.fields.get(ARG), Some(&Value::from("")));
    }

    #[test]
    fn reply_code_parses() {
        let bytes = b"230 User logged in.\r\n".to_vec();
        let m = meta(bytes.len());
        let parsed = Ftp.parse(&bytes, &ctx(Depth::Full, &m)).expect("valid");
        assert_eq!(parsed.fields.get(IS_REQUEST), Some(&Value::Bool(false)));
        assert_eq!(parsed.fields.get(REPLY_CODE), Some(&Value::U64(230)));
        assert_eq!(
            parsed.fields.get(ARG),
            Some(&Value::from("User logged in."))
        );
    }

    #[test]
    fn pasv_reply_carries_the_negotiated_port_in_arg_with_no_data_stream() {
        let bytes = b"227 Entering Passive Mode (192,168,1,1,200,3).\r\n".to_vec();
        let m = meta(bytes.len());
        let parsed = Ftp.parse(&bytes, &ctx(Depth::Full, &m)).expect("valid");
        assert_eq!(parsed.fields.get(REPLY_CODE), Some(&Value::U64(227)));
        assert_eq!(
            parsed.fields.get(ARG),
            Some(&Value::from("Entering Passive Mode (192,168,1,1,200,3)."))
        );
    }

    #[test]
    fn multiline_continuation_marker_parses_like_a_normal_response() {
        let bytes = b"220-Welcome to the FTP service\r\n".to_vec();
        let m = meta(bytes.len());
        let parsed = Ftp.parse(&bytes, &ctx(Depth::Full, &m)).expect("valid");
        assert_eq!(parsed.fields.get(REPLY_CODE), Some(&Value::U64(220)));
        assert_eq!(
            parsed.fields.get(ARG),
            Some(&Value::from("Welcome to the FTP service"))
        );
    }

    #[test]
    fn command_is_case_normalized_to_uppercase() {
        let bytes = b"user anonymous\r\n".to_vec();
        let m = meta(bytes.len());
        let parsed = Ftp.parse(&bytes, &ctx(Depth::Full, &m)).expect("valid");
        assert_eq!(parsed.fields.get(COMMAND), Some(&Value::from("USER")));
    }

    #[test]
    fn depth_gates_command_and_arg() {
        let bytes = b"RETR file.txt\r\n".to_vec();
        let m = meta(bytes.len());
        let keys = Ftp.parse(&bytes, &ctx(Depth::Keys, &m)).expect("valid");
        assert_eq!(keys.fields.get(APP), Some(&Value::from("ftp")));
        assert_eq!(keys.fields.get(COMMAND), None);

        let structural = Ftp
            .parse(&bytes, &ctx(Depth::Structural, &m))
            .expect("valid");
        assert_eq!(structural.fields.get(COMMAND), Some(&Value::from("RETR")));
        assert_eq!(structural.fields.get(ARG), None);
    }

    #[test]
    fn non_command_non_reply_line_declines() {
        let bytes = b"123abc garbage\r\n".to_vec();
        let m = meta(bytes.len());
        assert!(Ftp.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn missing_terminator_is_truncated() {
        let bytes = b"USER anonymous".to_vec();
        let m = meta(bytes.len());
        assert!(matches!(
            Ftp.parse(&bytes, &ctx(Depth::Full, &m)),
            Err(ParseError::Truncated(_))
        ));
    }

    #[test]
    fn truncated_frames_decline_at_every_prefix() {
        let bytes = b"USER anonymous\r\n".to_vec();
        let m = meta(bytes.len());
        let full = ctx(Depth::Full, &m);
        for n in 0..bytes.len() {
            assert!(
                Ftp.parse(&bytes[..n], &full).is_err(),
                "prefix of {n}/{} bytes must decline",
                bytes.len()
            );
        }
    }
}
