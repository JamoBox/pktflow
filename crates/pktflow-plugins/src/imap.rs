//! IMAP (11.9, RFC 9051 rev2 / RFC 3501 rev1) — the one member of the
//! tagged command/response group (`ftp.rs`'s module doc, 11.9) with
//! client-chosen tags rather than a fixed status word: every line opens
//! with a tag (`a001`, or `*` for an untagged server response, or `+`
//! for a continuation request) followed by either a command (client
//! request) or a status word `OK`/`NO`/`BAD` (server response). Per D7,
//! `FETCH`'s returned message data (and any command's literal string
//! arguments, `{n}`-length-prefixed) is payload, not parsed further.

use pktflow_core::{
    Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx, ParseError,
    ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId, StreamIdentity, Truncated, Value,
};

const APP: FieldName = "app";
const TAG: FieldName = "tag";
const COMMAND: FieldName = "command";
const IS_RESPONSE: FieldName = "is_response";
const RESPONSE_STATUS: FieldName = "response_status";
const ARGS: FieldName = "args";

/// RFC 9051 §6 — the Tier-1 command vocabulary.
const COMMANDS: &[&str] = &[
    "LOGIN",
    "SELECT",
    "EXAMINE",
    "CREATE",
    "DELETE",
    "RENAME",
    "SUBSCRIBE",
    "UNSUBSCRIBE",
    "LIST",
    "LSUB",
    "STATUS",
    "APPEND",
    "CHECK",
    "CLOSE",
    "EXPUNGE",
    "SEARCH",
    "FETCH",
    "STORE",
    "COPY",
    "UID",
    "NOOP",
    "LOGOUT",
    "CAPABILITY",
    "STARTTLS",
    "IDLE",
    "AUTHENTICATE",
];

/// RFC 9051 §7.1 — the three completion-response statuses this v1
/// recognizes (untagged server status responses use the same words).
const RESPONSE_STATUSES: &[&str] = &["OK", "NO", "BAD"];

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

pub struct Imap;

impl LayerPlugin for Imap {
    fn name(&self) -> ProtocolName {
        "imap"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let line_end = find_line_end(bytes).ok_or(ParseError::Truncated(Truncated {
            needed: bytes.len() + 1,
            have: bytes.len(),
        }))?;
        let header_len = line_end + 2;
        let line = &bytes[..line_end];

        let mut parts = line.splitn(3, |&b| b == b' ');
        let tag = parts
            .next()
            .ok_or(ParseError::Malformed("empty IMAP line"))?;
        let second = parts.next().ok_or(ParseError::Malformed(
            "IMAP line missing command/status word",
        ))?;
        let rest = parts.next().unwrap_or(&[]);

        let status = RESPONSE_STATUSES
            .iter()
            .copied()
            .find(|s| s.as_bytes().eq_ignore_ascii_case(second));
        let command = COMMANDS
            .iter()
            .copied()
            .find(|c| c.as_bytes().eq_ignore_ascii_case(second));

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(APP, Value::from("imap"));
        }

        if let Some(status) = status {
            if ctx.depth() >= Depth::Structural {
                fields.insert(TAG, Value::from(to_str(tag).as_str()));
                fields.insert(IS_RESPONSE, Value::Bool(true));
                fields.insert(RESPONSE_STATUS, Value::from(status));
            }
        } else if let Some(command) = command {
            if ctx.depth() >= Depth::Structural {
                fields.insert(TAG, Value::from(to_str(tag).as_str()));
                fields.insert(IS_RESPONSE, Value::Bool(false));
                fields.insert(COMMAND, Value::from(command));
            }
        } else {
            return Err(ParseError::Malformed(
                "IMAP: second word is neither a recognized command nor a response status",
            ));
        }
        if ctx.depth() >= Depth::Full {
            fields.insert(ARGS, Value::from(to_str(rest).as_str()));
        }

        Ok(ParsedLayer {
            header_len,
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::TcpPort(143)]
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
    fn login_command_reports_tag_and_command() {
        let bytes = line("a001 LOGIN alice password");
        let m = meta(bytes.len());
        let parsed = Imap
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid LOGIN command");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(APP), Some(&Value::from("imap")));
        assert_eq!(parsed.fields.get(TAG), Some(&Value::from("a001")));
        assert_eq!(parsed.fields.get(IS_RESPONSE), Some(&Value::Bool(false)));
        assert_eq!(parsed.fields.get(COMMAND), Some(&Value::from("LOGIN")));
        assert_eq!(
            parsed.fields.get(ARGS),
            Some(&Value::from("alice password"))
        );
    }

    #[test]
    fn tagged_ok_response_reports_status_not_command() {
        let bytes = line("a001 OK LOGIN completed");
        let m = meta(bytes.len());
        let parsed = Imap
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid tagged OK response");
        assert_eq!(parsed.fields.get(TAG), Some(&Value::from("a001")));
        assert_eq!(parsed.fields.get(IS_RESPONSE), Some(&Value::Bool(true)));
        assert_eq!(parsed.fields.get(RESPONSE_STATUS), Some(&Value::from("OK")));
        assert_eq!(parsed.fields.get(COMMAND), None);
    }

    #[test]
    fn untagged_greeting_uses_asterisk_as_tag() {
        let bytes = line("* OK IMAP4rev1 Server ready");
        let m = meta(bytes.len());
        let parsed = Imap
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid untagged greeting");
        assert_eq!(parsed.fields.get(TAG), Some(&Value::from("*")));
        assert_eq!(parsed.fields.get(RESPONSE_STATUS), Some(&Value::from("OK")));
    }

    #[test]
    fn select_command_parses() {
        let bytes = line("a002 SELECT INBOX");
        let m = meta(bytes.len());
        let parsed = Imap
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid SELECT command");
        assert_eq!(parsed.fields.get(COMMAND), Some(&Value::from("SELECT")));
        assert_eq!(parsed.fields.get(ARGS), Some(&Value::from("INBOX")));
    }

    #[test]
    fn logout_command_with_no_args_parses() {
        let bytes = line("a003 LOGOUT");
        let m = meta(bytes.len());
        let parsed = Imap
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid LOGOUT command");
        assert_eq!(parsed.fields.get(COMMAND), Some(&Value::from("LOGOUT")));
        assert_eq!(parsed.fields.get(ARGS), Some(&Value::from("")));
    }

    #[test]
    fn unrecognized_second_word_declines() {
        let bytes = line("a001 FROBNICATE foo");
        let m = meta(bytes.len());
        assert!(Imap.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn truncated_frames_decline() {
        let bytes = line("a001 LOGIN alice password");
        let m = meta(bytes.len());
        for n in 0..bytes.len() {
            let full = ctx(Depth::Full, &m);
            assert!(
                Imap.parse(&bytes[..n], &full).is_err(),
                "prefix of {n}/{} bytes must decline",
                bytes.len()
            );
        }
    }

    #[test]
    fn keys_depth_only_has_app() {
        let bytes = line("a001 NOOP");
        let m = meta(bytes.len());
        let parsed = Imap
            .parse(&bytes, &ctx(Depth::Keys, &m))
            .expect("valid NOOP");
        assert_eq!(parsed.fields.len(), 1);
        assert_eq!(parsed.fields.get(APP), Some(&Value::from("imap")));
    }

    #[test]
    fn structural_depth_omits_args() {
        let bytes = line("a002 SELECT INBOX");
        let m = meta(bytes.len());
        let parsed = Imap
            .parse(&bytes, &ctx(Depth::Structural, &m))
            .expect("valid SELECT command");
        assert_eq!(parsed.fields.get(COMMAND), Some(&Value::from("SELECT")));
        assert_eq!(parsed.fields.get(ARGS), None);
    }
}
