//! IMAP (11.9, RFC 9051 rev2 / RFC 3501 rev1) — app-stream pattern (06.6),
//! the one member of this domain's tagged command/response group with
//! client-chosen tags rather than a fixed status word: every line opens
//! with a tag (a client-chosen token, `"*"` for untagged server data, or
//! `"+"` for a continuation request), then a second token that is either a
//! command (request) or one of `OK`/`NO`/`BAD` (a tagged response).
//!
//! `header_len` covers through the line terminator (D7, no reassembly —
//! the same shape `ftp`/`smtp`/`pop3` take); only the tag and second token
//! are inspected structurally, the remainder of the line is kept as a
//! single raw `args` string, not walked (IMAP's command grammar is far too
//! rich for a bounded TLV-style walk).

use pktflow_core::{
    Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx, ParseError,
    ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId, StreamIdentity, Value,
};

const APP: FieldName = "app";
const TAG: FieldName = "tag";
const COMMAND: FieldName = "command";
const IS_RESPONSE: FieldName = "is_response";
const RESPONSE_STATUS: FieldName = "response_status";
const ARGS: FieldName = "args";

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

/// Splits `line` into its first two space-delimited tokens plus whatever
/// remains (the raw `args`). Every IMAP line has at least a tag and a
/// second token (RFC 9051 §2.2.1); a line without both declines.
fn split_tag_and_second_token(line: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
    let tag_end = line.iter().position(|&b| b == b' ')?;
    if tag_end == 0 {
        return None;
    }
    let tag = &line[..tag_end];
    let rest = &line[tag_end + 1..];
    let second_end = rest.iter().position(|&b| b == b' ').unwrap_or(rest.len());
    if second_end == 0 {
        return None;
    }
    let second = &rest[..second_end];
    let args = if second_end < rest.len() {
        &rest[second_end + 1..]
    } else {
        &rest[second_end..]
    };
    Some((tag, second, args))
}

fn is_response_status(token: &[u8]) -> bool {
    matches!(token, b"OK" | b"NO" | b"BAD")
}

pub struct Imap;

impl LayerPlugin for Imap {
    fn name(&self) -> ProtocolName {
        "imap"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let (line, header_len) =
            split_line(bytes).ok_or(ParseError::Truncated(pktflow_core::Truncated {
                needed: bytes.len() + 1,
                have: bytes.len(),
            }))?;
        let (tag, second, args) = split_tag_and_second_token(line)
            .ok_or(ParseError::Malformed("not a tag + token IMAP line"))?;

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(APP, Value::from("imap"));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(TAG, Value::from(String::from_utf8_lossy(tag).as_ref()));
            if is_response_status(second) {
                fields.insert(IS_RESPONSE, Value::Bool(true));
                fields.insert(
                    RESPONSE_STATUS,
                    Value::from(String::from_utf8_lossy(second).as_ref()),
                );
            } else {
                fields.insert(IS_RESPONSE, Value::Bool(false));
                let mut upper = second.to_vec();
                upper.make_ascii_uppercase();
                fields.insert(
                    COMMAND,
                    Value::from(String::from_utf8_lossy(&upper).as_ref()),
                );
            }
        }
        if ctx.depth() >= Depth::Full {
            fields.insert(ARGS, Value::from(String::from_utf8_lossy(args).as_ref()));
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

    #[test]
    fn login_command_parses() {
        let bytes = b"A001 LOGIN alice password\r\n".to_vec();
        let m = meta(bytes.len());
        let parsed = Imap
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid LOGIN");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.fields.get(APP), Some(&Value::from("imap")));
        assert_eq!(parsed.fields.get(TAG), Some(&Value::from("A001")));
        assert_eq!(parsed.fields.get(IS_RESPONSE), Some(&Value::Bool(false)));
        assert_eq!(parsed.fields.get(COMMAND), Some(&Value::from("LOGIN")));
        assert_eq!(
            parsed.fields.get(ARGS),
            Some(&Value::from("alice password"))
        );
    }

    #[test]
    fn tagged_ok_response_parses() {
        let bytes = b"A001 OK LOGIN completed\r\n".to_vec();
        let m = meta(bytes.len());
        let parsed = Imap.parse(&bytes, &ctx(Depth::Full, &m)).expect("valid");
        assert_eq!(parsed.fields.get(IS_RESPONSE), Some(&Value::Bool(true)));
        assert_eq!(parsed.fields.get(RESPONSE_STATUS), Some(&Value::from("OK")));
        assert_eq!(parsed.fields.get(COMMAND), None);
        assert_eq!(
            parsed.fields.get(ARGS),
            Some(&Value::from("LOGIN completed"))
        );
    }

    #[test]
    fn no_and_bad_responses_recognized() {
        for (line, status) in [
            (&b"A002 NO permission denied\r\n"[..], "NO"),
            (&b"A003 BAD invalid command\r\n"[..], "BAD"),
        ] {
            let m = meta(line.len());
            let parsed = Imap
                .parse(line, &ctx(Depth::Full, &m))
                .unwrap_or_else(|e| panic!("{status}: {e}"));
            assert_eq!(
                parsed.fields.get(RESPONSE_STATUS),
                Some(&Value::from(status))
            );
        }
    }

    #[test]
    fn untagged_server_data_uses_star_as_tag() {
        let bytes = b"* 2 EXISTS\r\n".to_vec();
        let m = meta(bytes.len());
        let parsed = Imap.parse(&bytes, &ctx(Depth::Full, &m)).expect("valid");
        assert_eq!(parsed.fields.get(TAG), Some(&Value::from("*")));
        // "2" isn't OK/NO/BAD, so this reads as a (numeric-looking) command
        // token — an honest best-effort read of untagged data shapes IMAP
        // doesn't fit neatly into the tagged command/response model.
        assert_eq!(parsed.fields.get(IS_RESPONSE), Some(&Value::Bool(false)));
    }

    #[test]
    fn command_is_case_normalized_to_uppercase() {
        let bytes = b"a001 login alice pw\r\n".to_vec();
        let m = meta(bytes.len());
        let parsed = Imap.parse(&bytes, &ctx(Depth::Full, &m)).expect("valid");
        assert_eq!(parsed.fields.get(COMMAND), Some(&Value::from("LOGIN")));
    }

    #[test]
    fn depth_gates_tag_and_args() {
        let bytes = b"A001 LOGOUT\r\n".to_vec();
        let m = meta(bytes.len());
        let keys = Imap.parse(&bytes, &ctx(Depth::Keys, &m)).expect("valid");
        assert_eq!(keys.fields.get(TAG), None);
        let structural = Imap
            .parse(&bytes, &ctx(Depth::Structural, &m))
            .expect("valid");
        assert_eq!(structural.fields.get(TAG), Some(&Value::from("A001")));
        assert_eq!(structural.fields.get(COMMAND), Some(&Value::from("LOGOUT")));
        assert_eq!(structural.fields.get(ARGS), None);
    }

    #[test]
    fn line_without_a_second_token_declines() {
        let bytes = b"A001\r\n".to_vec();
        let m = meta(bytes.len());
        assert!(Imap.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn missing_terminator_is_truncated() {
        let bytes = b"A001 LOGIN alice".to_vec();
        let m = meta(bytes.len());
        assert!(matches!(
            Imap.parse(&bytes, &ctx(Depth::Full, &m)),
            Err(ParseError::Truncated(_))
        ));
    }

    #[test]
    fn truncated_frames_decline_at_every_prefix() {
        let bytes = b"A001 LOGIN alice password\r\n".to_vec();
        let m = meta(bytes.len());
        let full = ctx(Depth::Full, &m);
        for n in 0..bytes.len() {
            assert!(
                Imap.parse(&bytes[..n], &full).is_err(),
                "prefix of {n}/{} bytes must decline",
                bytes.len()
            );
        }
    }
}
