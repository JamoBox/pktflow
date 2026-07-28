//! POP3 (11.9, RFC 1939) — app-stream pattern (06.6), the tagged
//! command/response shape shared with `ftp`/`smtp` in this domain, with
//! one difference: POP3 replies open with a status *word* (`"+OK"` or
//! `"-ERR"`, RFC 1939 §3), not a three-digit numeric code.

use pktflow_core::{
    Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx, ParseError,
    ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId, StreamIdentity, Value,
};

const APP: FieldName = "app";
const IS_REQUEST: FieldName = "is_request";
const COMMAND: FieldName = "command";
const STATUS: FieldName = "status";
const ARG: FieldName = "arg";

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

/// RFC 1939 §3: a status indicator, `"+OK"` or `"-ERR"`, then `' '` or end.
fn parse_status(line: &[u8]) -> Option<(&[u8], &[u8])> {
    for status in [&b"+OK"[..], b"-ERR"] {
        if line.starts_with(status) {
            let rest = match line.get(status.len()) {
                None => &line[status.len()..],
                Some(b' ') => &line[(status.len() + 1).min(line.len())..],
                Some(_) => continue,
            };
            return Some((status, rest));
        }
    }
    None
}

/// RFC 1939's command set plus the standard extensions (RFC 2449 CAPA,
/// RFC 2595 STLS, RFC 1939 §7 APOP, RFC 5034 AUTH/USER SASL).
///
/// An **allow-list, not a shape test** — see `ftp`'s COMMANDS for the
/// reasoning (06.6's port-claim honesty).
const COMMANDS: &[&str] = &[
    "USER", "PASS", "APOP", "STAT", "LIST", "RETR", "DELE", "NOOP", "RSET", "QUIT", "TOP", "UIDL",
    "CAPA", "STLS", "AUTH",
];

/// The command token and its argument, or `None` when the token is not a
/// command this protocol defines (see [`COMMANDS`]).
fn parse_command(line: &[u8]) -> Option<(String, &[u8])> {
    let end = line.iter().position(|&b| b == b' ').unwrap_or(line.len());
    if end == 0 || !line[..end].iter().all(u8::is_ascii_alphabetic) {
        return None;
    }
    let mut upper = line[..end].to_vec();
    upper.make_ascii_uppercase();
    let command = String::from_utf8(upper).ok()?;
    if !COMMANDS.contains(&command.as_str()) {
        return None;
    }
    let arg = if end < line.len() {
        &line[end + 1..]
    } else {
        &line[end..]
    };
    Some((command, arg))
}

pub struct Pop3;

impl LayerPlugin for Pop3 {
    fn name(&self) -> ProtocolName {
        "pop3"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let (line, header_len) =
            split_line(bytes).ok_or(ParseError::Truncated(pktflow_core::Truncated {
                needed: bytes.len() + 1,
                have: bytes.len(),
            }))?;

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(APP, Value::from("pop3"));
        }

        if let Some((status, rest)) = parse_status(line) {
            if ctx.depth() >= Depth::Structural {
                fields.insert(IS_REQUEST, Value::Bool(false));
                fields.insert(
                    STATUS,
                    Value::from(String::from_utf8_lossy(status).as_ref()),
                );
            }
            if ctx.depth() >= Depth::Full {
                fields.insert(ARG, Value::from(String::from_utf8_lossy(rest).as_ref()));
            }
        } else if let Some((command, arg)) = parse_command(line) {
            if ctx.depth() >= Depth::Structural {
                fields.insert(IS_REQUEST, Value::Bool(true));
                fields.insert(COMMAND, Value::from(command.as_str()));
            }
            if ctx.depth() >= Depth::Full {
                fields.insert(ARG, Value::from(String::from_utf8_lossy(arg).as_ref()));
            }
        } else {
            return Err(ParseError::Malformed(
                "not a POP3 status line or command line",
            ));
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

    #[test]
    fn user_command_parses() {
        let bytes = b"USER alice\r\n".to_vec();
        let m = meta(bytes.len());
        let parsed = Pop3
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid USER");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.fields.get(APP), Some(&Value::from("pop3")));
        assert_eq!(parsed.fields.get(IS_REQUEST), Some(&Value::Bool(true)));
        assert_eq!(parsed.fields.get(COMMAND), Some(&Value::from("USER")));
        assert_eq!(parsed.fields.get(ARG), Some(&Value::from("alice")));
    }

    #[test]
    fn plus_ok_status_parses() {
        let bytes = b"+OK 2 messages\r\n".to_vec();
        let m = meta(bytes.len());
        let parsed = Pop3.parse(&bytes, &ctx(Depth::Full, &m)).expect("valid");
        assert_eq!(parsed.fields.get(IS_REQUEST), Some(&Value::Bool(false)));
        assert_eq!(parsed.fields.get(STATUS), Some(&Value::from("+OK")));
        assert_eq!(parsed.fields.get(ARG), Some(&Value::from("2 messages")));
    }

    #[test]
    fn minus_err_status_parses() {
        let bytes = b"-ERR no such mailbox\r\n".to_vec();
        let m = meta(bytes.len());
        let parsed = Pop3.parse(&bytes, &ctx(Depth::Full, &m)).expect("valid");
        assert_eq!(parsed.fields.get(STATUS), Some(&Value::from("-ERR")));
        assert_eq!(
            parsed.fields.get(ARG),
            Some(&Value::from("no such mailbox"))
        );
    }

    #[test]
    fn status_with_no_trailing_text_parses() {
        let bytes = b"+OK\r\n".to_vec();
        let m = meta(bytes.len());
        let parsed = Pop3.parse(&bytes, &ctx(Depth::Full, &m)).expect("valid");
        assert_eq!(parsed.fields.get(STATUS), Some(&Value::from("+OK")));
        assert_eq!(parsed.fields.get(ARG), Some(&Value::from("")));
    }

    #[test]
    fn depth_gates_command_and_arg() {
        let bytes = b"RETR 1\r\n".to_vec();
        let m = meta(bytes.len());
        let structural = Pop3
            .parse(&bytes, &ctx(Depth::Structural, &m))
            .expect("valid");
        assert_eq!(structural.fields.get(COMMAND), Some(&Value::from("RETR")));
        assert_eq!(structural.fields.get(ARG), None);
    }

    #[test]
    fn non_command_non_status_line_declines() {
        let bytes = b"~~~garbage\r\n".to_vec();
        let m = meta(bytes.len());
        assert!(Pop3.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn truncated_frames_decline_at_every_prefix() {
        let bytes = b"USER alice\r\n".to_vec();
        let m = meta(bytes.len());
        let full = ctx(Depth::Full, &m);
        for n in 0..bytes.len() {
            assert!(
                Pop3.parse(&bytes[..n], &full).is_err(),
                "prefix of {n}/{} bytes must decline",
                bytes.len()
            );
        }
    }

    /// `ftp`'s port-claim-honesty case, same reasoning.
    #[test]
    fn undefined_verb_declines_instead_of_fabricating_a_command() {
        let m = meta(32);
        for line in [&b"VSER alice\r\n"[..], &b"XYZZY now\r\n"[..]] {
            assert!(Pop3.parse(line, &ctx(Depth::Full, &m)).is_err());
        }
        for line in [&b"CAPA\r\n"[..], &b"STLS\r\n"[..]] {
            assert!(Pop3.parse(line, &ctx(Depth::Full, &m)).is_ok());
        }
    }
}
