//! DNS (06.6, RFC 1035): single-datagram metadata only (D7). Query names
//! observed in a UDP stream is the PRD's own §4.A example — the rollups
//! do that stream-level work.
//!
//! App-stream pattern: DNS has no endpoint identity of its own, so the
//! key is one shared constant field (`app = "dns"`) — exactly one child
//! stream per transport stream, a clean home for rollups.

use pktflow_core::{
    ByteReader, Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx,
    ParseError, ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId, StreamIdentity, Value,
};

const APP: FieldName = "app";
const ID: FieldName = "id";
const IS_RESPONSE: FieldName = "is_response";
const OPCODE: FieldName = "opcode";
const RCODE: FieldName = "rcode";
const QNAME: FieldName = "qname";
const QTYPE: FieldName = "qtype";
const ANSWERS: FieldName = "answers";
const QDCOUNT: FieldName = "qdcount";
const ANCOUNT: FieldName = "ancount";
const NSCOUNT: FieldName = "nscount";
const ARCOUNT: FieldName = "arcount";

/// Compression-pointer bounds: the classic parser bomb (06.6). Pointers
/// must go strictly backward and chains are capped.
const MAX_POINTER_JUMPS: usize = 64;
const MAX_NAME_LEN: usize = 255;
/// Hostile section counts must not turn into unbounded record walks.
const MAX_RECORDS_PER_SECTION: u16 = 128;

static KEY: &[KeyField] = &[KeyField { a: APP, b: None }];
static ROLLUPS: &[RollupSpec] = &[
    RollupSpec {
        field: QNAME,
        kind: RollupKind::Accumulate, // the PRD §4.A example
    },
    RollupSpec {
        field: RCODE,
        kind: RollupKind::Accumulate,
    },
];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: ROLLUPS,
};

/// Decodes a (possibly compressed) name starting at `start` within `msg`.
/// Returns the dotted name and the bytes consumed *at the start position*.
///
/// Safety bounds: pointers must target strictly earlier offsets, at most
/// [`MAX_POINTER_JUMPS`] jumps, and names cap at [`MAX_NAME_LEN`] chars —
/// loops and bombs decline instead of hanging.
pub fn decode_name(msg: &[u8], start: usize) -> Result<(String, usize), ParseError> {
    let mut pos = start;
    let mut consumed = None;
    let mut jumps = 0usize;
    let mut name = String::new();
    loop {
        let &len_byte = msg
            .get(pos)
            .ok_or(ParseError::Malformed("name runs past message"))?;
        match len_byte {
            0 => {
                // Lazy: after a backward jump `pos < start`, but then
                // `consumed` was already fixed at the first pointer.
                let consumed = consumed.unwrap_or_else(|| pos + 1 - start);
                return Ok((name, consumed));
            }
            l if l & 0xC0 == 0xC0 => {
                let &low = msg
                    .get(pos + 1)
                    .ok_or(ParseError::Malformed("pointer runs past message"))?;
                if consumed.is_none() {
                    consumed = Some(pos + 2 - start);
                }
                let target = usize::from(l & 0x3F) << 8 | usize::from(low);
                if target >= pos {
                    return Err(ParseError::Malformed("forward compression pointer"));
                }
                jumps += 1;
                if jumps > MAX_POINTER_JUMPS {
                    return Err(ParseError::Malformed("compression pointer chain too long"));
                }
                pos = target;
            }
            l if l & 0xC0 == 0 => {
                let label = msg
                    .get(pos + 1..pos + 1 + usize::from(l))
                    .ok_or(ParseError::Malformed("label runs past message"))?;
                if !name.is_empty() {
                    name.push('.');
                }
                for &c in label {
                    name.push(if c.is_ascii_graphic() && c != b'.' {
                        char::from(c)
                    } else {
                        '?'
                    });
                }
                if name.len() > MAX_NAME_LEN {
                    return Err(ParseError::Malformed("name too long"));
                }
                pos += 1 + usize::from(l);
            }
            _ => return Err(ParseError::Malformed("reserved label type")),
        }
    }
}

/// Renders one answer's RDATA (A/AAAA/CNAME/PTR; else the type number).
fn render_rdata(msg: &[u8], rtype: u16, rdata_offset: usize, rdata: &[u8]) -> String {
    match (rtype, rdata.len()) {
        (1, 4) => rdata
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join("."),
        (28, 16) => rdata
            .chunks(2)
            .map(|pair| format!("{:x}", u16::from_be_bytes([pair[0], pair[1]])))
            .collect::<Vec<_>>()
            .join(":"),
        (5 | 12, _) => decode_name(msg, rdata_offset)
            .map(|(n, _)| n)
            .unwrap_or_else(|_| format!("type{rtype}")),
        _ => format!("type{rtype}"),
    }
}

pub struct Dns;

impl LayerPlugin for Dns {
    fn name(&self) -> ProtocolName {
        "dns"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        // Over TCP a 2-byte length prefix precedes the message; only the
        // first message in a segment is parsed (D7, no reassembly).
        let over_tcp = ctx.prev().is_some_and(|l| l.protocol == "tcp");
        let (msg, prefix) = if over_tcp {
            let mut r = ByteReader::new(bytes);
            let msg_len = usize::from(r.u16_be()?);
            (r.take(msg_len)?, 2)
        } else {
            (bytes, 0)
        };

        let mut r = ByteReader::new(msg);
        let id = r.u16_be()?;
        let flags = r.u16_be()?;
        let counts = [r.u16_be()?, r.u16_be()?, r.u16_be()?, r.u16_be()?];
        if counts.iter().any(|&c| c > MAX_RECORDS_PER_SECTION) {
            return Err(ParseError::Malformed("implausible section count"));
        }

        // Walk every section so header_len covers exactly the message we
        // verified; answers are rendered, the rest is bounds-checked.
        let mut pos = 12usize;
        let mut qname = None;
        let mut qtype = None;
        for _ in 0..counts[0] {
            let (name, consumed) = decode_name(msg, pos)?;
            pos += consumed;
            let mut q = ByteReader::new(msg.get(pos..).unwrap_or(&[]));
            let t = q.u16_be()?;
            let _class = q.u16_be()?;
            pos += 4;
            if qname.is_none() {
                qname = Some(name);
                qtype = Some(t);
            }
        }
        let mut answers = Vec::new();
        for section in 0..3 {
            for _ in 0..counts[1 + section] {
                let (_, consumed) = decode_name(msg, pos)?;
                pos += consumed;
                let mut rec = ByteReader::new(msg.get(pos..).unwrap_or(&[]));
                let rtype = rec.u16_be()?;
                let _class = rec.u16_be()?;
                let _ttl = rec.u32_be()?;
                let rdlength = usize::from(rec.u16_be()?);
                let rdata = rec.take(rdlength)?;
                let rdata_offset = pos + 10;
                if section == 0 {
                    answers.push(Value::from(
                        render_rdata(msg, rtype, rdata_offset, rdata).as_str(),
                    ));
                }
                pos += 10 + rdlength;
            }
        }

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(APP, Value::from("dns"));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(ID, Value::U64(u64::from(id)));
            fields.insert(IS_RESPONSE, Value::Bool(flags & 0x8000 != 0));
            fields.insert(OPCODE, Value::U64(u64::from((flags >> 11) & 0xF)));
            fields.insert(RCODE, Value::U64(u64::from(flags & 0xF)));
            if let (Some(name), Some(t)) = (qname, qtype) {
                fields.insert(QNAME, Value::from(name.as_str()));
                fields.insert(QTYPE, Value::U64(u64::from(t)));
            }
        }
        if ctx.depth() >= Depth::Full {
            fields.insert(ANSWERS, Value::List(answers));
            fields.insert(QDCOUNT, Value::U64(u64::from(counts[0])));
            fields.insert(ANCOUNT, Value::U64(u64::from(counts[1])));
            fields.insert(NSCOUNT, Value::U64(u64::from(counts[2])));
            fields.insert(ARCOUNT, Value::U64(u64::from(counts[3])));
        }

        Ok(ParsedLayer {
            header_len: prefix + pos,
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::UdpPort(53), RouteId::TcpPort(53)]
    }

    fn stream_identity(&self) -> Option<&StreamIdentity> {
        Some(&IDENTITY)
    }
}
