//! POP3 (11.9, RFC 1939) — the tagged command/response text protocol
//! shape `ftp.rs`'s module doc describes (11.9's domain doc), with one
//! difference from `ftp`/`smtp`: POP3 has no numeric reply code, only the
//! fixed status words `+OK`/`-ERR` (RFC 1939 §3). Per D7, `RETR`'s
//! message body is payload, not parsed — this plugin stops at the `RETR`
//! command/`+OK` status line itself.

use pktflow_core::{
    Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx, ParseError,
    ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId, StreamIdentity, Truncated, Value,
};

const APP: FieldName = "app";
const IS_REQUEST: FieldName = "is_request";
const COMMAND: FieldName = "command";
const STATUS: FieldName = "status";
const ARG: FieldName = "arg";

/// RFC 1939 §4/§5/§7 — the Tier-1 command vocabulary.
const COMMANDS: &[&str] = &[
    "USER", "PASS", "APOP", "STAT", "LIST", "RETR", "DELE", "NOOP", "RSET", "QUIT", "TOP", "UIDL",
    "CAPA", "STLS",
];

const OK_STATUS: &str = "+OK";
const ERR_STATUS: &str = "-ERR";

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

fn split_first_word(line: &[u8]) -> (&[u8], &[u8]) {
    match line.iter().position(|&b| b == b' ') {
        Some(pos) => (&line[..pos], &line[pos + 1..]),
        None => (line, &[]),
    }
}

pub struct Pop3;

impl LayerPlugin for Pop3 {
    fn name(&self) -> ProtocolName {
        "pop3"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let line_end = find_line_end(bytes).ok_or(ParseError::Truncated(Truncated {
            needed: bytes.len() + 1,
            have: bytes.len(),
        }))?;
        let header_len = line_end + 2;
        let line = &bytes[..line_end];
        let (first_word, rest) = split_first_word(line);

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(APP, Value::from("pop3"));
        }

        if first_word == OK_STATUS.as_bytes() || first_word == ERR_STATUS.as_bytes() {
            let status = if first_word == OK_STATUS.as_bytes() {
                OK_STATUS
            } else {
                ERR_STATUS
            };
            if ctx.depth() >= Depth::Structural {
                fields.insert(IS_REQUEST, Value::Bool(false));
                fields.insert(STATUS, Value::from(status));
            }
            if ctx.depth() >= Depth::Full {
                fields.insert(ARG, Value::from(to_str(rest).as_str()));
            }
        } else {
            let command: &'static str = COMMANDS
                .iter()
                .copied()
                .find(|c| c.as_bytes().eq_ignore_ascii_case(first_word))
                .ok_or(ParseError::Malformed("unrecognized POP3 command"))?;
            if ctx.depth() >= Depth::Structural {
                fields.insert(IS_REQUEST, Value::Bool(true));
                fields.insert(COMMAND, Value::from(command));
            }
            if ctx.depth() >= Depth::Full {
                fields.insert(ARG, Value::from(to_str(rest).as_str()));
            }
        }

        Ok(ParsedLayer {
            header_len,
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::TcpPort(110)]
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
    fn user_command_reports_command_and_arg() {
        let bytes = line("USER alice");
        let m = meta(bytes.len());
        let parsed = Pop3
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid USER command");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(APP), Some(&Value::from("pop3")));
        assert_eq!(parsed.fields.get(IS_REQUEST), Some(&Value::Bool(true)));
        assert_eq!(parsed.fields.get(COMMAND), Some(&Value::from("USER")));
        assert_eq!(parsed.fields.get(ARG), Some(&Value::from("alice")));
    }

    #[test]
    fn ok_status_reports_status_and_text() {
        let bytes = line("+OK Password required");
        let m = meta(bytes.len());
        let parsed = Pop3
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid +OK response");
        assert_eq!(parsed.fields.get(IS_REQUEST), Some(&Value::Bool(false)));
        assert_eq!(parsed.fields.get(STATUS), Some(&Value::from("+OK")));
        assert_eq!(
            parsed.fields.get(ARG),
            Some(&Value::from("Password required"))
        );
        assert_eq!(parsed.fields.get(COMMAND), None);
    }

    #[test]
    fn err_status_reports_status() {
        let bytes = line("-ERR no such mailbox");
        let m = meta(bytes.len());
        let parsed = Pop3
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid -ERR response");
        assert_eq!(parsed.fields.get(STATUS), Some(&Value::from("-ERR")));
    }

    #[test]
    fn retr_stops_before_the_message_body() {
        let mut bytes = line("RETR 1");
        bytes.extend_from_slice(b"+OK 120 octets\r\nSubject: hi\r\n\r\nbody\r\n.\r\n");
        let m = meta(bytes.len());
        let parsed = Pop3
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid RETR command");
        assert_eq!(parsed.header_len, line("RETR 1").len());
        assert_eq!(parsed.fields.get(COMMAND), Some(&Value::from("RETR")));
    }

    #[test]
    fn unrecognized_command_declines() {
        let bytes = line("FROBNICATE foo");
        let m = meta(bytes.len());
        assert!(Pop3.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn truncated_frames_decline() {
        let bytes = line("USER alice");
        let m = meta(bytes.len());
        for n in 0..bytes.len() {
            let full = ctx(Depth::Full, &m);
            assert!(
                Pop3.parse(&bytes[..n], &full).is_err(),
                "prefix of {n}/{} bytes must decline",
                bytes.len()
            );
        }
    }

    #[test]
    fn keys_depth_only_has_app() {
        let bytes = line("QUIT");
        let m = meta(bytes.len());
        let parsed = Pop3
            .parse(&bytes, &ctx(Depth::Keys, &m))
            .expect("valid QUIT");
        assert_eq!(parsed.fields.len(), 1);
        assert_eq!(parsed.fields.get(APP), Some(&Value::from("pop3")));
    }

    #[test]
    fn structural_depth_omits_arg() {
        let bytes = line("USER alice");
        let m = meta(bytes.len());
        let parsed = Pop3
            .parse(&bytes, &ctx(Depth::Structural, &m))
            .expect("valid USER command");
        assert_eq!(parsed.fields.get(COMMAND), Some(&Value::from("USER")));
        assert_eq!(parsed.fields.get(ARG), None);
    }
}
