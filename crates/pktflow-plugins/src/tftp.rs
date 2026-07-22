//! TFTP (11.9, RFC 1350). **D15 applies directly, textbook case**: only
//! the initial `RRQ`/`WRQ` (client -> port 69) is reachable via the
//! static claim below — the server's reply and every subsequent `DATA`/
//! `ACK` packet uses a server-chosen ephemeral port on *both* sides, so
//! neither the `Candidates([UdpPort(dst), UdpPort(src)])` check (06.4)
//! nor any claimed route matches, and the gate stops rather than
//! guessing. `DATA`/`ACK`/`ERROR` fields below are specified and
//! fixture-tested by feeding bytes directly to `parse()` (09.1), but are
//! **not reachable via routing** in v1.
//!
//! **No `stream_identity()`.** Given the above, there is no multi-packet
//! exchange this plugin ever actually observes through ordinary routing —
//! an identity declaration would be vacuous, so this plugin (unlike
//! every app-stream plugin elsewhere in this task) forms no stream at all.
//!
//! ## Packet formats (RFC 1350 §5)
//!
//! ```text
//! RRQ/WRQ : opcode(2) filename(cstr) mode(cstr)
//! DATA    : opcode(2) block#(2) data(<=512, payload — not this header)
//! ACK     : opcode(2) block#(2)
//! ERROR   : opcode(2) error_code(2) error_msg(cstr)
//! ```
//!
//! A `DATA` packet's file-content bytes are payload past `header_len`
//! (D7) — the same "header ends, body doesn't get parsed" stance `http`'s
//! message body and `smtp`'s `DATA` command body take.

use pktflow_core::{
    ByteReader, Depth, FieldMap, FieldName, Hint, LayerPlugin, ParseCtx, ParseError, ParsedLayer,
    ProtocolName, RouteId, Truncated, Value,
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

fn truncated(needed: usize, have: usize) -> ParseError {
    ParseError::Truncated(Truncated { needed, have })
}

/// Reads a NUL-terminated ASCII string starting at `pos`; returns the
/// string bytes (without the NUL) and the position just past it.
fn read_cstr(bytes: &[u8], pos: usize) -> Result<(&[u8], usize), ParseError> {
    let rest = bytes.get(pos..).ok_or(truncated(pos, bytes.len()))?;
    let nul = rest
        .iter()
        .position(|&b| b == 0)
        .ok_or(truncated(bytes.len() + 1, bytes.len()))?;
    Ok((&rest[..nul], pos + nul + 1))
}

fn to_str(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
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
        let header_len = match opcode {
            OP_RRQ | OP_WRQ => {
                let (filename, after_filename) = read_cstr(bytes, 2)?;
                let (mode, after_mode) = read_cstr(bytes, after_filename)?;
                if ctx.depth() >= Depth::Structural {
                    fields.insert(OPCODE, Value::U64(u64::from(opcode)));
                    fields.insert(FILENAME, Value::from(to_str(filename).as_str()));
                    fields.insert(MODE, Value::from(to_str(mode).as_str()));
                }
                after_mode
            }
            OP_DATA | OP_ACK => {
                let block_num = r.u16_be()?;
                if ctx.depth() >= Depth::Structural {
                    fields.insert(OPCODE, Value::U64(u64::from(opcode)));
                }
                if ctx.depth() >= Depth::Full {
                    fields.insert(BLOCK_NUM, Value::U64(u64::from(block_num)));
                }
                4
            }
            OP_ERROR => {
                let error_code = r.u16_be()?;
                let (error_msg, after_msg) = read_cstr(bytes, 4)?;
                if ctx.depth() >= Depth::Structural {
                    fields.insert(OPCODE, Value::U64(u64::from(opcode)));
                }
                if ctx.depth() >= Depth::Full {
                    fields.insert(ERROR_CODE, Value::U64(u64::from(error_code)));
                    fields.insert(ERROR_MSG, Value::from(to_str(error_msg).as_str()));
                }
                after_msg
            }
            _ => return Err(ParseError::Malformed("TFTP: unrecognized opcode")),
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

    // No stream_identity(): see module doc (D15).
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

    fn cstr(s: &str) -> Vec<u8> {
        let mut v = s.as_bytes().to_vec();
        v.push(0);
        v
    }

    fn rrq(filename: &str, mode: &str) -> Vec<u8> {
        let mut b = OP_RRQ.to_be_bytes().to_vec();
        b.extend_from_slice(&cstr(filename));
        b.extend_from_slice(&cstr(mode));
        b
    }

    #[test]
    fn rrq_reports_filename_and_mode() {
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
        let bytes = {
            let mut b = OP_WRQ.to_be_bytes().to_vec();
            b.extend_from_slice(&cstr("upload.bin"));
            b.extend_from_slice(&cstr("netascii"));
            b
        };
        let parsed = Tftp
            .parse(&bytes, &ctx(Depth::Full, &meta(bytes.len())))
            .expect("valid WRQ");
        assert_eq!(parsed.fields.get(OPCODE), Some(&Value::U64(2)));
        assert_eq!(parsed.fields.get(MODE), Some(&Value::from("netascii")));
    }

    #[test]
    fn data_packet_stops_before_file_content() {
        let mut bytes = OP_DATA.to_be_bytes().to_vec();
        bytes.extend_from_slice(&7u16.to_be_bytes());
        bytes.extend_from_slice(b"file content bytes");
        let parsed = Tftp
            .parse(&bytes, &ctx(Depth::Full, &meta(bytes.len())))
            .expect("valid DATA packet");
        assert_eq!(parsed.header_len, 4);
        assert_eq!(parsed.fields.get(OPCODE), Some(&Value::U64(3)));
        assert_eq!(parsed.fields.get(BLOCK_NUM), Some(&Value::U64(7)));
    }

    #[test]
    fn ack_packet_parses() {
        let mut bytes = OP_ACK.to_be_bytes().to_vec();
        bytes.extend_from_slice(&9u16.to_be_bytes());
        let parsed = Tftp
            .parse(&bytes, &ctx(Depth::Full, &meta(bytes.len())))
            .expect("valid ACK packet");
        assert_eq!(parsed.header_len, 4);
        assert_eq!(parsed.fields.get(BLOCK_NUM), Some(&Value::U64(9)));
    }

    #[test]
    fn error_packet_reports_code_and_message() {
        let mut bytes = OP_ERROR.to_be_bytes().to_vec();
        bytes.extend_from_slice(&1u16.to_be_bytes());
        bytes.extend_from_slice(&cstr("File not found"));
        let parsed = Tftp
            .parse(&bytes, &ctx(Depth::Full, &meta(bytes.len())))
            .expect("valid ERROR packet");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.fields.get(ERROR_CODE), Some(&Value::U64(1)));
        assert_eq!(
            parsed.fields.get(ERROR_MSG),
            Some(&Value::from("File not found"))
        );
    }

    #[test]
    fn unrecognized_opcode_declines() {
        let bytes = 99u16.to_be_bytes().to_vec();
        assert!(Tftp
            .parse(&bytes, &ctx(Depth::Full, &meta(bytes.len())))
            .is_err());
    }

    #[test]
    fn no_stream_identity() {
        assert!(Tftp.stream_identity().is_none());
    }

    #[test]
    fn truncated_frames_decline() {
        let bytes = rrq("boot.img", "octet");
        let m = meta(bytes.len());
        for n in 0..bytes.len() {
            let full = ctx(Depth::Full, &m);
            assert!(
                Tftp.parse(&bytes[..n], &full).is_err(),
                "prefix of {n}/{} bytes must decline",
                bytes.len()
            );
        }
    }

    #[test]
    fn depth_none_yields_no_fields() {
        let bytes = rrq("boot.img", "octet");
        let parsed = Tftp
            .parse(&bytes, &ctx(Depth::None, &meta(bytes.len())))
            .expect("valid RRQ");
        assert!(parsed.fields.get(OPCODE).is_none());
    }

    #[test]
    fn structural_depth_omits_block_num() {
        let mut bytes = OP_DATA.to_be_bytes().to_vec();
        bytes.extend_from_slice(&7u16.to_be_bytes());
        let parsed = Tftp
            .parse(&bytes, &ctx(Depth::Structural, &meta(bytes.len())))
            .expect("valid DATA packet");
        assert_eq!(parsed.fields.get(OPCODE), Some(&Value::U64(3)));
        assert_eq!(parsed.fields.get(BLOCK_NUM), None);
    }
}
