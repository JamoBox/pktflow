//! TFTP (11.9, RFC 1350). **D15 applies directly**: only the initial
//! `RRQ`/`WRQ` (client → the well-known port 69) is reachable via the
//! static claim below — the server's reply and every subsequent
//! `DATA`/`ACK`/`ERROR` packet uses a server-chosen ephemeral port on
//! *both* sides, so neither UDP's `Candidates([UdpPort(dst), UdpPort(src)])`
//! check (06.4) nor any claimed route matches, and the gate stops rather
//! than guessing (`StopReason::UnclaimedRoute`). The `DATA`/`ACK`/`ERROR`
//! shapes below are specified and fixture-tested by feeding bytes directly
//! to `parse()` (09.1), but are **not reachable via routing** in v1 — no
//! multi-packet exchange this plugin ever actually observes, so it
//! declares no [`pktflow_core::StreamIdentity`] (a declaration would be
//! vacuous).
//!
//! ## Opcodes (RFC 1350 §5)
//! `RRQ=1`, `WRQ=2`: `opcode(2) | filename (NUL-terminated) | mode
//! (NUL-terminated)`. `DATA=3`: `opcode(2) | block#(2) | data(0..512,
//! unparsed remainder — D7, the same "stop before the body" stance
//! `http`/`ftp` take)`. `ACK=4`: `opcode(2) | block#(2)`. `ERROR=5`:
//! `opcode(2) | error_code(2) | error_msg (NUL-terminated)`.

use pktflow_core::{
    ByteReader, Depth, FieldMap, FieldName, Hint, LayerPlugin, ParseCtx, ParseError, ParsedLayer,
    ProtocolName, RouteId, Value,
};

const OPCODE: FieldName = "opcode";
const FILENAME: FieldName = "filename";
const MODE: FieldName = "mode";
const BLOCK_NUM: FieldName = "block_num";
const ERROR_CODE: FieldName = "error_code";
const ERROR_MSG: FieldName = "error_msg";

const OP_RRQ: u16 = 1;
const OP_WRQ: u16 = 2;
const OP_DATA: u16 = 3;
const OP_ACK: u16 = 4;
const OP_ERROR: u16 = 5;

/// Reads bytes up to (and consuming) a NUL terminator.
fn read_cstring(r: &mut ByteReader) -> Result<Vec<u8>, ParseError> {
    let mut out = Vec::new();
    loop {
        let b = r.u8()?;
        if b == 0 {
            break;
        }
        out.push(b);
    }
    Ok(out)
}

pub struct Tftp;

impl LayerPlugin for Tftp {
    fn name(&self) -> ProtocolName {
        "tftp"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let opcode = r.u16_be()?;

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Structural {
            fields.insert(OPCODE, Value::U64(u64::from(opcode)));
        }

        let header_len = match opcode {
            OP_RRQ | OP_WRQ => {
                let filename = read_cstring(&mut r)?;
                let mode = read_cstring(&mut r)?;
                if ctx.depth() >= Depth::Structural {
                    fields.insert(
                        FILENAME,
                        Value::from(String::from_utf8_lossy(&filename).as_ref()),
                    );
                    fields.insert(MODE, Value::from(String::from_utf8_lossy(&mode).as_ref()));
                }
                bytes.len() - r.remaining()
            }
            OP_DATA | OP_ACK => {
                let block_num = r.u16_be()?;
                if ctx.depth() >= Depth::Full {
                    fields.insert(BLOCK_NUM, Value::U64(u64::from(block_num)));
                }
                4
            }
            OP_ERROR => {
                let error_code = r.u16_be()?;
                let error_msg = read_cstring(&mut r)?;
                if ctx.depth() >= Depth::Full {
                    fields.insert(ERROR_CODE, Value::U64(u64::from(error_code)));
                    fields.insert(
                        ERROR_MSG,
                        Value::from(String::from_utf8_lossy(&error_msg).as_ref()),
                    );
                }
                bytes.len() - r.remaining()
            }
            _ => return Err(ParseError::Malformed("unrecognized TFTP opcode")),
        };

        Ok(ParsedLayer {
            header_len,
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::UdpPort(69)]
    }

    // No `stream_identity` (module doc): no multi-packet exchange this
    // plugin ever actually observes via routing in v1.
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

    fn rrq(filename: &str, mode: &str) -> Vec<u8> {
        let mut b = OP_RRQ.to_be_bytes().to_vec();
        b.extend_from_slice(filename.as_bytes());
        b.push(0);
        b.extend_from_slice(mode.as_bytes());
        b.push(0);
        b
    }

    #[test]
    fn rrq_parses_filename_and_mode() {
        let bytes = rrq("boot.img", "octet");
        let m = meta(bytes.len());
        let parsed = Tftp
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid RRQ");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(OPCODE), Some(&Value::U64(1)));
        assert_eq!(parsed.fields.get(FILENAME), Some(&Value::from("boot.img")));
        assert_eq!(parsed.fields.get(MODE), Some(&Value::from("octet")));
    }

    #[test]
    fn wrq_parses() {
        let mut bytes = OP_WRQ.to_be_bytes().to_vec();
        bytes.extend_from_slice(b"upload.bin\0netascii\0");
        let m = meta(bytes.len());
        let parsed = Tftp
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid WRQ");
        assert_eq!(parsed.fields.get(OPCODE), Some(&Value::U64(2)));
        assert_eq!(
            parsed.fields.get(FILENAME),
            Some(&Value::from("upload.bin"))
        );
    }

    #[test]
    fn data_parses_block_num_and_stops_before_payload() {
        let mut bytes = OP_DATA.to_be_bytes().to_vec();
        bytes.extend_from_slice(&7u16.to_be_bytes());
        bytes.extend_from_slice(&[0xAA; 512]);
        let m = meta(bytes.len());
        let parsed = Tftp
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid DATA");
        assert_eq!(parsed.header_len, 4);
        assert_eq!(parsed.fields.get(BLOCK_NUM), Some(&Value::U64(7)));
    }

    #[test]
    fn ack_parses_block_num() {
        let mut bytes = OP_ACK.to_be_bytes().to_vec();
        bytes.extend_from_slice(&3u16.to_be_bytes());
        let m = meta(bytes.len());
        let parsed = Tftp
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid ACK");
        assert_eq!(parsed.header_len, 4);
        assert_eq!(parsed.fields.get(BLOCK_NUM), Some(&Value::U64(3)));
    }

    #[test]
    fn error_parses_code_and_message() {
        let mut bytes = OP_ERROR.to_be_bytes().to_vec();
        bytes.extend_from_slice(&1u16.to_be_bytes());
        bytes.extend_from_slice(b"File not found\0");
        let m = meta(bytes.len());
        let parsed = Tftp
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid ERROR");
        assert_eq!(parsed.fields.get(ERROR_CODE), Some(&Value::U64(1)));
        assert_eq!(
            parsed.fields.get(ERROR_MSG),
            Some(&Value::from("File not found"))
        );
    }

    #[test]
    fn depth_gates_filename_and_block_num() {
        let bytes = rrq("boot.img", "octet");
        let m = meta(bytes.len());
        let none = Tftp.parse(&bytes, &ctx(Depth::None, &m)).expect("valid");
        assert!(none.fields.is_empty());

        let mut ack = OP_ACK.to_be_bytes().to_vec();
        ack.extend_from_slice(&1u16.to_be_bytes());
        let m2 = meta(ack.len());
        let structural = Tftp
            .parse(&ack, &ctx(Depth::Structural, &m2))
            .expect("valid");
        assert_eq!(structural.fields.get(OPCODE), Some(&Value::U64(4)));
        assert_eq!(structural.fields.get(BLOCK_NUM), None);
    }

    #[test]
    fn unrecognized_opcode_declines() {
        let bytes = 9u16.to_be_bytes().to_vec();
        let m = meta(bytes.len());
        assert!(Tftp.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn truncated_rrq_declines() {
        let bytes = rrq("boot.img", "octet");
        let m = meta(bytes.len());
        let full = ctx(Depth::Full, &m);
        for n in 0..bytes.len() {
            assert!(
                Tftp.parse(&bytes[..n], &full).is_err(),
                "prefix of {n}/{} bytes must decline",
                bytes.len()
            );
        }
    }

    #[test]
    fn truncated_data_header_declines() {
        let bytes = OP_DATA.to_be_bytes().to_vec();
        let m = meta(bytes.len());
        assert!(Tftp.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn no_stream_identity_declared() {
        assert!(Tftp.stream_identity().is_none());
    }
}
