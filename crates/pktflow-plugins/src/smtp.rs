//! SMTP (11.9, RFC 5321) — app-stream pattern (06.6), the tagged
//! command/response shape shared with `ftp`/`pop3` in this domain (11.9's
//! domain doc): reply lines are three ASCII digits plus text; command
//! lines are an alphabetic token plus an optional argument.
//!
//! Per D7, the `DATA` command's message body (terminated by a bare `.`
//! line) is payload, not parsed — this plugin only ever sees the `DATA`
//! command line itself, never walks into what follows.

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

pub struct Smtp;

impl LayerPlugin for Smtp {
    fn name(&self) -> ProtocolName {
        "smtp"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let (line, header_len) =
            split_line(bytes).ok_or(ParseError::Truncated(pktflow_core::Truncated {
                needed: bytes.len() + 1,
                have: bytes.len(),
            }))?;

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(APP, Value::from("smtp"));
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
                "not an SMTP reply code or command line",
            ));
        }

        Ok(ParsedLayer {
            header_len,
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::TcpPort(25)]
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
    fn ehlo_command_parses() {
        let bytes = b"EHLO client.example.com\r\n".to_vec();
        let m = meta(bytes.len());
        let parsed = Smtp
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid EHLO");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.fields.get(APP), Some(&Value::from("smtp")));
        assert_eq!(parsed.fields.get(IS_REQUEST), Some(&Value::Bool(true)));
        assert_eq!(parsed.fields.get(COMMAND), Some(&Value::from("EHLO")));
        assert_eq!(
            parsed.fields.get(ARG),
            Some(&Value::from("client.example.com"))
        );
    }

    #[test]
    fn data_command_line_parses_body_not_touched() {
        let mut bytes = b"DATA\r\n".to_vec();
        let header_len = bytes.len();
        bytes.extend_from_slice(b"Subject: hi\r\n\r\nbody\r\n.\r\n");
        let m = meta(bytes.len());
        let parsed = Smtp.parse(&bytes, &ctx(Depth::Full, &m)).expect("valid");
        assert_eq!(parsed.header_len, header_len);
        assert_eq!(parsed.fields.get(COMMAND), Some(&Value::from("DATA")));
    }

    #[test]
    fn reply_code_parses() {
        let bytes = b"250 OK\r\n".to_vec();
        let m = meta(bytes.len());
        let parsed = Smtp.parse(&bytes, &ctx(Depth::Full, &m)).expect("valid");
        assert_eq!(parsed.fields.get(IS_REQUEST), Some(&Value::Bool(false)));
        assert_eq!(parsed.fields.get(REPLY_CODE), Some(&Value::U64(250)));
        assert_eq!(parsed.fields.get(ARG), Some(&Value::from("OK")));
    }

    #[test]
    fn multiline_ehlo_response_continuation_parses() {
        let bytes = b"250-PIPELINING\r\n".to_vec();
        let m = meta(bytes.len());
        let parsed = Smtp.parse(&bytes, &ctx(Depth::Full, &m)).expect("valid");
        assert_eq!(parsed.fields.get(REPLY_CODE), Some(&Value::U64(250)));
        assert_eq!(parsed.fields.get(ARG), Some(&Value::from("PIPELINING")));
    }

    #[test]
    fn depth_gates_command_and_arg() {
        let bytes = b"MAIL FROM:<a@example.com>\r\n".to_vec();
        let m = meta(bytes.len());
        let keys = Smtp.parse(&bytes, &ctx(Depth::Keys, &m)).expect("valid");
        assert_eq!(keys.fields.get(COMMAND), None);
        let structural = Smtp
            .parse(&bytes, &ctx(Depth::Structural, &m))
            .expect("valid");
        assert_eq!(structural.fields.get(COMMAND), Some(&Value::from("MAIL")));
        assert_eq!(structural.fields.get(ARG), None);
    }

    #[test]
    fn missing_terminator_is_truncated() {
        let bytes = b"EHLO client".to_vec();
        let m = meta(bytes.len());
        assert!(matches!(
            Smtp.parse(&bytes, &ctx(Depth::Full, &m)),
            Err(ParseError::Truncated(_))
        ));
    }

    #[test]
    fn non_command_non_reply_line_declines() {
        let bytes = b"???\r\n".to_vec();
        let m = meta(bytes.len());
        assert!(Smtp.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn truncated_frames_decline_at_every_prefix() {
        let bytes = b"EHLO client.example.com\r\n".to_vec();
        let m = meta(bytes.len());
        let full = ctx(Depth::Full, &m);
        for n in 0..bytes.len() {
            assert!(
                Smtp.parse(&bytes[..n], &full).is_err(),
                "prefix of {n}/{} bytes must decline",
                bytes.len()
            );
        }
    }
}
