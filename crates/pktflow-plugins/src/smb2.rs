//! SMB2 (11.9, [MS-SMB2] — *no open standard*; Microsoft's published Open
//! Specification is the closest authoritative document, D14). 64-byte
//! fixed header, binary framing.
//!
//! ## Direct TCP transport (MS-SMB2 §2.1)
//! On the wire, SMB2-over-TCP-445 prepends every message with a 4-byte
//! NetBIOS-Session-Service-shaped length field: `Type(1, must be `0x00`
//! "Session Message") | Length(3, big-endian)`. This plugin reads that
//! prefix (a wire-format fact this domain's field table doesn't name
//! separately, but that a genuine port-445 capture always carries) before
//! the SMB2 header itself; `header_len` covers the whole prefixed message
//! (`4 + Length`), self-describing regardless of how far the fields below
//! reach. The legacy SMB1 negotiation prefix (`0xFF 'SMB'`) is out of v1
//! scope; SMB1 is deprecated and declines cleanly as unrecognized bytes
//! (the `ProtocolId` check below).
//!
//! ## Fixed header (MS-SMB2 §2.2.1, 64 bytes)
//! `ProtocolId(4, `0xFE 'S' 'M' 'B'`) | StructureSize(2) |
//! CreditCharge(2) | Status(4) | Command(2) | Credit(2) | Flags(4,
//! bit 0 = `SMB2_FLAGS_SERVER_TO_REDIR`, distinguishing a response from a
//! request) | NextCommand(4) | MessageId(8) | Reserved(4) | TreeId(4) |
//! SessionId(8) | Signature(16)`. This plugin reads the synchronous
//! (non-`SMB2_FLAGS_ASYNC_COMMAND`) header shape only — the async variant
//! replaces Reserved+TreeId with an 8-byte AsyncId, a real Tier 2 addition,
//! not attempted here.
//!
//! ## `file_id` (best-effort, bounded, D12-style partial extraction)
//! `FileId` sits at a **fixed offset within specific command bodies**
//! immediately after the 64-byte header — never walked from a general
//! parser, just read directly: `Create` response body offset 64 (after its
//! own fixed preamble, MS-SMB2 §2.2.14), `Read`/`Write` request body offset
//! 16 (§2.2.19/§2.2.21), `Close` request body offset 8 (§2.2.15). Anything
//! else (a `Create` request's filename, a `Read`/`Write`'s file data) is
//! not parsed further in v1 — file contents are explicitly out of scope
//! (D7).

use pktflow_core::{
    ByteReader, Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx,
    ParseError, ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId, StreamIdentity, Value,
};

const SESSION_ID: FieldName = "session_id";
const COMMAND: FieldName = "command";
const STATUS: FieldName = "status";
const FLAGS: FieldName = "flags";
const MESSAGE_ID: FieldName = "message_id";
const TREE_ID: FieldName = "tree_id";
const FILE_ID: FieldName = "file_id";

const PROTOCOL_ID: [u8; 4] = [0xFE, b'S', b'M', b'B'];
const FIXED_HEADER_LEN: usize = 64;
/// MS-SMB2 §2.2.1: bit 0 of Flags marks a response ("server to redirector").
const FLAG_SERVER_TO_REDIR: u32 = 0x0000_0001;

const CMD_CREATE: u16 = 5;
const CMD_CLOSE: u16 = 6;
const CMD_READ: u16 = 8;
const CMD_WRITE: u16 = 9;

static KEY: &[KeyField] = &[KeyField {
    a: SESSION_ID,
    b: None, // shared (non-endpoint) qualifier: one stream per SMB2 session id
}];
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

/// Best-effort `FileId` read at the fixed body offset the command shape
/// guarantees (module doc); any shape mismatch or short body yields `None`.
fn read_file_id(body: &[u8], command: u16, is_response: bool) -> Option<[u8; 16]> {
    let offset = match (command, is_response) {
        (CMD_CREATE, true) => 64,
        (CMD_READ, false) | (CMD_WRITE, false) => 16,
        (CMD_CLOSE, false) => 8,
        _ => return None,
    };
    let slice = body.get(offset..offset + 16)?;
    slice.try_into().ok()
}

pub struct Smb2;

impl LayerPlugin for Smb2 {
    fn name(&self) -> ProtocolName {
        "smb2"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let nbss_type = r.u8()?;
        if nbss_type != 0x00 {
            return Err(ParseError::Malformed(
                "not a NetBIOS Session Service message (0x00)",
            ));
        }
        let len_hi = r.take(3)?;
        let msg_len =
            (usize::from(len_hi[0]) << 16) | (usize::from(len_hi[1]) << 8) | usize::from(len_hi[2]);
        let message = r.take(msg_len)?;
        let header_len = 4 + msg_len;

        let mut mr = ByteReader::new(message);
        let protocol_id = mr.take(4)?;
        if protocol_id != PROTOCOL_ID {
            return Err(ParseError::Malformed(
                "not an SMB2 message (bad ProtocolId)",
            ));
        }
        let _structure_size = mr.u16_be()?;
        let _credit_charge = mr.u16_be()?;
        let status = mr.u32_be()?;
        let command = mr.u16_be()?;
        let _credit = mr.u16_be()?;
        let flags = mr.u32_be()?;
        let _next_command = mr.u32_be()?;
        let message_id = mr.u64_be()?;
        let _reserved = mr.u32_be()?;
        let tree_id = mr.u32_be()?;
        let session_id = mr.u64_be()?;
        let _signature = mr.take(16)?;

        let is_response = flags & FLAG_SERVER_TO_REDIR != 0;
        let body = &message[FIXED_HEADER_LEN.min(message.len())..];

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(SESSION_ID, Value::U64(session_id));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(COMMAND, Value::U64(u64::from(command)));
            fields.insert(STATUS, Value::U64(u64::from(status)));
            fields.insert(FLAGS, Value::U64(u64::from(flags)));
            fields.insert(MESSAGE_ID, Value::U64(message_id));
        }
        if ctx.depth() >= Depth::Full {
            fields.insert(TREE_ID, Value::U64(u64::from(tree_id)));
            if let Some(file_id) = read_file_id(body, command, is_response) {
                fields.insert(FILE_ID, Value::from(&file_id[..]));
            }
        }

        Ok(ParsedLayer {
            header_len,
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::TcpPort(445)]
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

    /// One synchronous SMB2 header (64 bytes) plus `body`, wrapped in the
    /// 4-byte NBSS-shaped length prefix.
    fn smb2_message(
        command: u16,
        flags: u32,
        message_id: u64,
        tree_id: u32,
        session_id: u64,
        body: &[u8],
    ) -> Vec<u8> {
        let mut h = PROTOCOL_ID.to_vec();
        h.extend_from_slice(&64u16.to_be_bytes()); // StructureSize
        h.extend_from_slice(&0u16.to_be_bytes()); // CreditCharge
        h.extend_from_slice(&0u32.to_be_bytes()); // Status
        h.extend_from_slice(&command.to_be_bytes());
        h.extend_from_slice(&0u16.to_be_bytes()); // Credit
        h.extend_from_slice(&flags.to_be_bytes());
        h.extend_from_slice(&0u32.to_be_bytes()); // NextCommand
        h.extend_from_slice(&message_id.to_be_bytes());
        h.extend_from_slice(&0u32.to_be_bytes()); // Reserved
        h.extend_from_slice(&tree_id.to_be_bytes());
        h.extend_from_slice(&session_id.to_be_bytes());
        h.extend_from_slice(&[0u8; 16]); // Signature
        h.extend_from_slice(body);

        let mut msg = vec![0x00];
        let len = h.len() as u32;
        msg.extend_from_slice(&len.to_be_bytes()[1..]);
        msg.extend_from_slice(&h);
        msg
    }

    #[test]
    fn negotiate_request_parses_fixed_fields() {
        let bytes = smb2_message(0, 0, 1, 0, 0, &[]);
        let m = meta(bytes.len());
        let parsed = Smb2
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid Negotiate request");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(SESSION_ID), Some(&Value::U64(0)));
        assert_eq!(parsed.fields.get(COMMAND), Some(&Value::U64(0)));
        assert_eq!(parsed.fields.get(MESSAGE_ID), Some(&Value::U64(1)));
        assert_eq!(parsed.fields.get(FLAGS), Some(&Value::U64(0)));
    }

    #[test]
    fn create_response_recovers_file_id() {
        let mut body = vec![0u8; 64]; // preamble up to FileId's offset
        let file_id = [0xAB; 16];
        body.extend_from_slice(&file_id);
        body.extend_from_slice(&[0u8; 8]); // CreateContextsOffset/Length
        let bytes = smb2_message(CMD_CREATE, FLAG_SERVER_TO_REDIR, 5, 3, 0xCAFE, &body);
        let m = meta(bytes.len());
        let parsed = Smb2
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid Create response");
        assert_eq!(parsed.fields.get(FILE_ID), Some(&Value::from(&file_id[..])));
        assert_eq!(parsed.fields.get(SESSION_ID), Some(&Value::U64(0xCAFE)));
    }

    #[test]
    fn read_request_recovers_file_id_write_request_does_too() {
        for command in [CMD_READ, CMD_WRITE] {
            let mut body = vec![0u8; 16]; // preamble up to FileId's offset
            let file_id = [0x11; 16];
            body.extend_from_slice(&file_id);
            let bytes = smb2_message(command, 0, 6, 3, 0xCAFE, &body);
            let m = meta(bytes.len());
            let parsed = Smb2
                .parse(&bytes, &ctx(Depth::Full, &m))
                .unwrap_or_else(|e| panic!("command {command}: {e}"));
            assert_eq!(
                parsed.fields.get(FILE_ID),
                Some(&Value::from(&file_id[..])),
                "command {command}"
            );
        }
    }

    #[test]
    fn close_request_recovers_file_id() {
        let mut body = vec![0u8; 8];
        let file_id = [0x22; 16];
        body.extend_from_slice(&file_id);
        let bytes = smb2_message(CMD_CLOSE, 0, 7, 3, 0xCAFE, &body);
        let m = meta(bytes.len());
        let parsed = Smb2
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid Close request");
        assert_eq!(parsed.fields.get(FILE_ID), Some(&Value::from(&file_id[..])));
    }

    #[test]
    fn create_request_has_no_file_id() {
        // FileId only appears on the Create *response*, not the request.
        let bytes = smb2_message(CMD_CREATE, 0, 5, 3, 0xCAFE, &[0u8; 80]);
        let m = meta(bytes.len());
        let parsed = Smb2
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid Create request");
        assert_eq!(parsed.fields.get(FILE_ID), None);
    }

    #[test]
    fn response_bit_is_readable_in_flags() {
        let bytes = smb2_message(1, FLAG_SERVER_TO_REDIR, 2, 0, 0xCAFE, &[]);
        let m = meta(bytes.len());
        let parsed = Smb2.parse(&bytes, &ctx(Depth::Full, &m)).expect("valid");
        assert_eq!(
            parsed.fields.get(FLAGS),
            Some(&Value::U64(u64::from(FLAG_SERVER_TO_REDIR)))
        );
    }

    #[test]
    fn depth_gates_command_and_tree_id() {
        let bytes = smb2_message(3, 0, 1, 9, 0, &[]);
        let m = meta(bytes.len());
        let keys = Smb2.parse(&bytes, &ctx(Depth::Keys, &m)).expect("valid");
        assert_eq!(keys.fields.get(SESSION_ID), Some(&Value::U64(0)));
        assert_eq!(keys.fields.get(COMMAND), None);

        let structural = Smb2
            .parse(&bytes, &ctx(Depth::Structural, &m))
            .expect("valid");
        assert_eq!(structural.fields.get(COMMAND), Some(&Value::U64(3)));
        assert_eq!(structural.fields.get(TREE_ID), None);
    }

    #[test]
    fn non_session_message_type_declines() {
        let mut bytes = vec![0x81]; // NBSS Session Request, not Session Message
        bytes.extend_from_slice(&[0, 0, 0]);
        let m = meta(bytes.len());
        assert!(Smb2.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn bad_protocol_id_declines() {
        let mut h = vec![0xFFu8, b'S', b'M', b'B']; // legacy SMB1 prefix
        h.extend_from_slice(&[0u8; 60]);
        let mut msg = vec![0x00];
        msg.extend_from_slice(&(h.len() as u32).to_be_bytes()[1..]);
        msg.extend_from_slice(&h);
        let m = meta(msg.len());
        assert!(Smb2.parse(&msg, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn truncated_frames_decline_at_every_prefix() {
        let bytes = smb2_message(0, 0, 1, 0, 0, &[]);
        let m = meta(bytes.len());
        let full = ctx(Depth::Full, &m);
        for n in 0..bytes.len() {
            assert!(
                Smb2.parse(&bytes[..n], &full).is_err(),
                "prefix of {n}/{} bytes must decline",
                bytes.len()
            );
        }
    }
}
