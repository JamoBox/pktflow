//! SMTP (11.9, RFC 5321) — the tagged command/response text protocol
//! shape `ftp.rs`'s module doc describes in full (11.9's domain doc): a
//! command line, a `<code><SP|'-'>text` reply line, both riding the
//! app-stream pattern (06.6). Per D7, the `DATA` command's message body
//! (terminated by a bare `.` line) is payload, not parsed — this plugin
//! stops at the `DATA` command line itself.
//!
//! **`command`, not `reply_code`, is the declared rollup** — the same
//! `ftp`/`http`/`sip` rule-3 constraint (11.8/11.9/11.10): no single SMTP
//! line carries both fields.

use pktflow_core::{
    Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx, ParseError,
    ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId, StreamIdentity, Truncated, Value,
};

const APP: FieldName = "app";
const IS_REQUEST: FieldName = "is_request";
const COMMAND: FieldName = "command";
const REPLY_CODE: FieldName = "reply_code";
const ARG: FieldName = "arg";

/// RFC 5321 §4.1.1 — the Tier-1 command vocabulary. A non-command line on
/// port 25 declines, the same claim-honesty stance `ftp`/`http` take.
const COMMANDS: &[&str] = &[
    "HELO", "EHLO", "MAIL", "RCPT", "DATA", "RSET", "VRFY", "EXPN", "HELP", "NOOP", "QUIT",
    "STARTTLS",
];

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

fn find_line_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(2).position(|w| w == b"\r\n")
}

fn to_str(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn as_reply_code(line: &[u8]) -> Option<u16> {
    let code = line.get(..3)?;
    if !code.iter().all(u8::is_ascii_digit) {
        return None;
    }
    match line.get(3) {
        None | Some(b' ') | Some(b'-') => Some(
            code.iter()
                .fold(0u16, |acc, &b| acc * 10 + u16::from(b - b'0')),
        ),
        _ => None,
    }
}

pub struct Smtp;

impl LayerPlugin for Smtp {
    fn name(&self) -> ProtocolName {
        "smtp"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let line_end = find_line_end(bytes).ok_or(ParseError::Truncated(Truncated {
            needed: bytes.len() + 1,
            have: bytes.len(),
        }))?;
        let header_len = line_end + 2;
        let line = &bytes[..line_end];

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(APP, Value::from("smtp"));
        }

        if let Some(code) = as_reply_code(line) {
            let arg = line.get(4..).unwrap_or(&[]);
            if ctx.depth() >= Depth::Structural {
                fields.insert(IS_REQUEST, Value::Bool(false));
                fields.insert(REPLY_CODE, Value::U64(u64::from(code)));
            }
            if ctx.depth() >= Depth::Full {
                fields.insert(ARG, Value::from(to_str(arg).as_str()));
            }
        } else {
            let mut parts = line.splitn(2, |&b| b == b' ');
            let cmd_word = parts
                .next()
                .ok_or(ParseError::Malformed("empty SMTP line"))?;
            // MAIL FROM:/RCPT TO: carry no space before the colon in some
            // clients ("MAIL FROM:<addr>"); splitting on the first space
            // still isolates the bare command word correctly either way.
            let command: &'static str = COMMANDS
                .iter()
                .copied()
                .find(|c| c.as_bytes().eq_ignore_ascii_case(cmd_word))
                .ok_or(ParseError::Malformed("unrecognized SMTP command"))?;
            let arg = parts.next().unwrap_or(&[]);
            if ctx.depth() >= Depth::Structural {
                fields.insert(IS_REQUEST, Value::Bool(true));
                fields.insert(COMMAND, Value::from(command));
            }
            if ctx.depth() >= Depth::Full {
                fields.insert(ARG, Value::from(to_str(arg).as_str()));
            }
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

    fn line(s: &str) -> Vec<u8> {
        format!("{s}\r\n").into_bytes()
    }

    #[test]
    fn ehlo_command_reports_command_and_arg() {
        let bytes = line("EHLO client.example.com");
        let m = meta(bytes.len());
        let parsed = Smtp
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid EHLO command");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(APP), Some(&Value::from("smtp")));
        assert_eq!(parsed.fields.get(IS_REQUEST), Some(&Value::Bool(true)));
        assert_eq!(parsed.fields.get(COMMAND), Some(&Value::from("EHLO")));
        assert_eq!(
            parsed.fields.get(ARG),
            Some(&Value::from("client.example.com"))
        );
    }

    #[test]
    fn mail_from_command_parses() {
        let bytes = line("MAIL FROM:<alice@example.com>");
        let m = meta(bytes.len());
        let parsed = Smtp
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid MAIL command");
        assert_eq!(parsed.fields.get(COMMAND), Some(&Value::from("MAIL")));
        assert_eq!(
            parsed.fields.get(ARG),
            Some(&Value::from("FROM:<alice@example.com>"))
        );
    }

    #[test]
    fn greeting_reply_reports_reply_code() {
        let bytes = line("220 mail.example.com ESMTP ready");
        let m = meta(bytes.len());
        let parsed = Smtp
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid 220 greeting");
        assert_eq!(parsed.fields.get(IS_REQUEST), Some(&Value::Bool(false)));
        assert_eq!(parsed.fields.get(REPLY_CODE), Some(&Value::U64(220)));
        assert_eq!(parsed.fields.get(COMMAND), None);
    }

    #[test]
    fn data_command_stops_before_the_message_body() {
        // D7: the DATA command line itself parses; the message body that
        // follows (terminated by a bare `.` line) is unparsed remainder.
        let mut bytes = line("DATA");
        bytes.extend_from_slice(b"Subject: hi\r\n\r\nbody\r\n.\r\n");
        let m = meta(bytes.len());
        let parsed = Smtp
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid DATA command");
        assert_eq!(parsed.header_len, line("DATA").len());
        assert_eq!(parsed.fields.get(COMMAND), Some(&Value::from("DATA")));
    }

    #[test]
    fn unrecognized_command_declines() {
        let bytes = line("FROBNICATE foo");
        let m = meta(bytes.len());
        assert!(Smtp.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn truncated_frames_decline() {
        let bytes = line("EHLO client.example.com");
        let m = meta(bytes.len());
        for n in 0..bytes.len() {
            let full = ctx(Depth::Full, &m);
            assert!(
                Smtp.parse(&bytes[..n], &full).is_err(),
                "prefix of {n}/{} bytes must decline",
                bytes.len()
            );
        }
    }

    #[test]
    fn keys_depth_only_has_app() {
        let bytes = line("QUIT");
        let m = meta(bytes.len());
        let parsed = Smtp
            .parse(&bytes, &ctx(Depth::Keys, &m))
            .expect("valid QUIT");
        assert_eq!(parsed.fields.len(), 1);
        assert_eq!(parsed.fields.get(APP), Some(&Value::from("smtp")));
    }

    #[test]
    fn structural_depth_omits_arg() {
        let bytes = line("EHLO client.example.com");
        let m = meta(bytes.len());
        let parsed = Smtp
            .parse(&bytes, &ctx(Depth::Structural, &m))
            .expect("valid EHLO command");
        assert_eq!(parsed.fields.get(COMMAND), Some(&Value::from("EHLO")));
        assert_eq!(parsed.fields.get(ARG), None);
    }
}
