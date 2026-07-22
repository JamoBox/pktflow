//! FTP (11.9, RFC 959) — one of four **tagged command/response** text
//! protocols sharing one shape (11.9's domain doc): a client sends a
//! line-oriented command, the server replies with a status code/word
//! plus text, both riding the app-stream pattern (06.6) — `ftp`/`smtp`/
//! `pop3` share this file's structure almost line for line; `imap`
//! differs only in swapping the fixed status word for a client-chosen
//! tag.
//!
//! Per D7, the data a transfer-initiating command opens (here, the
//! separate data channel `PASV`/`PORT` negotiate) is never parsed — only
//! this control-connection line is. **D15 applies directly**: the port
//! `PASV`/`PORT` announces is visible as plain text in `arg`, but the
//! resulting data-channel session is not correlated back to this control
//! stream or auto-routed — it appears as an ordinary untagged TCP session
//! in v1, the same honest ceiling `sip`'s SDP-negotiated RTP port faces
//! (11.10).
//!
//! **`command`, not `reply_code`, is the declared rollup.** The domain
//! spec names both, but no single FTP line carries both fields (a
//! request has `command`, a response has `reply_code`) — the same
//! `http`/`sip` constraint (11.8/11.10): the 09.1 kit's rule 3 requires
//! every declared rollup field on every canonical good sample, so only
//! one side's field can be a rollup without a per-field applicability
//! notion the kit doesn't have yet.

use pktflow_core::{
    Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx, ParseError,
    ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId, StreamIdentity, Truncated, Value,
};

const APP: FieldName = "app";
const IS_REQUEST: FieldName = "is_request";
const COMMAND: FieldName = "command";
const REPLY_CODE: FieldName = "reply_code";
const ARG: FieldName = "arg";

/// RFC 959 §4 (plus common extensions) — the Tier-1 command vocabulary.
/// A line whose first word isn't here, on port 21, isn't FTP riding the
/// port by coincidence and declines, the same claim-honesty stance `http`
/// takes on port 80 (11.8/06.6).
const COMMANDS: &[&str] = &[
    "USER", "PASS", "ACCT", "CWD", "CDUP", "SMNT", "QUIT", "REIN", "PORT", "PASV", "TYPE", "STRU",
    "MODE", "RETR", "STOR", "STOU", "APPE", "ALLO", "REST", "RNFR", "RNTO", "ABOR", "DELE", "RMD",
    "MKD", "PWD", "LIST", "NLST", "SITE", "SYST", "STAT", "HELP", "NOOP", "FEAT",
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

/// A reply line's first three bytes are ASCII digits, followed by `' '`
/// or `'-'` (multi-line continuation, RFC 959 §4.2) or end-of-line.
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

pub struct Ftp;

impl LayerPlugin for Ftp {
    fn name(&self) -> ProtocolName {
        "ftp"
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
            fields.insert(APP, Value::from("ftp"));
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
                .ok_or(ParseError::Malformed("empty FTP line"))?;
            let command: &'static str = COMMANDS
                .iter()
                .copied()
                .find(|c| c.as_bytes().eq_ignore_ascii_case(cmd_word))
                .ok_or(ParseError::Malformed("unrecognized FTP command"))?;
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

    fn line(s: &str) -> Vec<u8> {
        format!("{s}\r\n").into_bytes()
    }

    #[test]
    fn user_command_reports_command_and_arg() {
        let bytes = line("USER anonymous");
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
    fn lowercase_command_is_recognized_case_insensitively() {
        let bytes = line("user anonymous");
        let m = meta(bytes.len());
        let parsed = Ftp
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid lowercase command");
        assert_eq!(parsed.fields.get(COMMAND), Some(&Value::from("USER")));
    }

    #[test]
    fn welcome_reply_reports_reply_code_and_text() {
        let bytes = line("220 Service ready for new user");
        let m = meta(bytes.len());
        let parsed = Ftp
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid 220 reply");
        assert_eq!(parsed.fields.get(IS_REQUEST), Some(&Value::Bool(false)));
        assert_eq!(parsed.fields.get(REPLY_CODE), Some(&Value::U64(220)));
        assert_eq!(
            parsed.fields.get(ARG),
            Some(&Value::from("Service ready for new user"))
        );
        assert_eq!(parsed.fields.get(COMMAND), None);
    }

    #[test]
    fn pasv_reply_carries_the_negotiated_port_as_plain_text_arg() {
        // D15: the port is visible in `arg`; no data-channel stream is
        // fabricated (that's an aggregator/routing property, verified
        // structurally by this plugin declaring no such identity).
        let bytes = line("227 Entering Passive Mode (127,0,0,1,200,13)");
        let m = meta(bytes.len());
        let parsed = Ftp
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid PASV reply");
        assert_eq!(parsed.fields.get(REPLY_CODE), Some(&Value::U64(227)));
        assert_eq!(
            parsed.fields.get(ARG),
            Some(&Value::from("Entering Passive Mode (127,0,0,1,200,13)"))
        );
    }

    #[test]
    fn multiline_reply_first_line_only() {
        let mut bytes = line("230-Welcome");
        bytes.extend_from_slice(&line("230 Logged in"));
        let m = meta(bytes.len());
        let parsed = Ftp
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid multiline reply");
        assert_eq!(parsed.header_len, line("230-Welcome").len());
        assert_eq!(parsed.fields.get(REPLY_CODE), Some(&Value::U64(230)));
        assert_eq!(parsed.fields.get(ARG), Some(&Value::from("Welcome")));
    }

    #[test]
    fn unrecognized_command_declines() {
        let bytes = line("NOTACOMMAND foo");
        let m = meta(bytes.len());
        assert!(Ftp.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn missing_crlf_is_truncated() {
        let bytes = b"USER anonymous".to_vec();
        let m = meta(bytes.len());
        assert!(matches!(
            Ftp.parse(&bytes, &ctx(Depth::Full, &m)),
            Err(ParseError::Truncated(_))
        ));
    }

    #[test]
    fn truncated_frames_decline() {
        let bytes = line("USER anonymous");
        let m = meta(bytes.len());
        for n in 0..bytes.len() {
            let full = ctx(Depth::Full, &m);
            assert!(
                Ftp.parse(&bytes[..n], &full).is_err(),
                "prefix of {n}/{} bytes must decline",
                bytes.len()
            );
        }
    }

    #[test]
    fn keys_depth_only_has_app() {
        let bytes = line("QUIT");
        let m = meta(bytes.len());
        let parsed = Ftp
            .parse(&bytes, &ctx(Depth::Keys, &m))
            .expect("valid QUIT");
        assert_eq!(parsed.fields.len(), 1);
        assert_eq!(parsed.fields.get(APP), Some(&Value::from("ftp")));
    }

    #[test]
    fn structural_depth_omits_arg() {
        let bytes = line("USER anonymous");
        let m = meta(bytes.len());
        let parsed = Ftp
            .parse(&bytes, &ctx(Depth::Structural, &m))
            .expect("valid USER command");
        assert_eq!(parsed.fields.get(COMMAND), Some(&Value::from("USER")));
        assert_eq!(parsed.fields.get(ARG), None);
    }
}
