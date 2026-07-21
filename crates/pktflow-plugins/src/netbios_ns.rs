//! NetBIOS Name Service (11.12, RFC 1001 §14 encoding / RFC 1002 §4.2
//! message format). The header shape echoes DNS's (id/flags/counts,
//! RFC 1035) but NetBIOS names use their own 16-byte "first-level"
//! encoding (RFC 1001 §14.1) rather than DNS label compression — this
//! plugin owns its own name decoder, unlike `mdns`/`llmnr` (11.12), which
//! genuinely reuse `dns`'s message-parsing routine because their wire
//! format for names *is* RFC 1035's.
//!
//! App-stream pattern (06.6): no endpoint identity of its own, so the key
//! is one shared constant field (`app = "netbios_ns"`).
//!
//! Query-shaped messages (Name Query/Registration/Release Request, WACK,
//! Name Refresh — RFC 1002 §4.2.2-.2.7) carry a Question section (NAME +
//! `QUESTION_TYPE` + `QUESTION_CLASS`); response-shaped messages (Name
//! Query/Registration Response, End-Node Challenge, Node Status Response
//! — RFC 1002 §4.2.11-.2.19) instead carry an Answer Resource Record
//! (`RR_NAME` + `RR_TYPE` + `RR_CLASS` + ...). Both share the identical
//! NAME/TYPE/CLASS prefix, so this plugin decodes whichever section is
//! present (Question first, else Answer) into one `rr_type`/`name` pair
//! and stops there — the RR's TTL/RDLENGTH/RDATA (relevant only to
//! responses) is Tier 2, an explicit, honestly-flagged limitation rather
//! than a silent gap, the same stance `l2tpv3` takes on control AVPs.

use pktflow_core::{
    ByteReader, Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx,
    ParseError, ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId, StreamIdentity, Value,
};

const APP: FieldName = "app";
const OPCODE: FieldName = "opcode";
const NM_FLAGS: FieldName = "nm_flags";
const RCODE: FieldName = "rcode";
const QUESTION_COUNT: FieldName = "question_count";
const ANSWER_COUNT: FieldName = "answer_count";
const NAME: FieldName = "name";
const NAME_TYPE: FieldName = "name_type";
const RR_TYPE: FieldName = "rr_type";

/// RFC 1001 §14.1: a first-level-encoded NetBIOS name is always exactly
/// 32 characters (16 bytes, 2 chars per byte).
const FIRST_LEVEL_LEN: usize = 32;

/// RFC 1001 §14.1: each half-octet is encoded as a letter `'A'..='P'`
/// (its value used as an index, 0-15). Decodes one 32-char label back to
/// its 16 raw bytes; any character outside that range means these bytes
/// aren't first-level-encoded at all.
fn decode_first_level(encoded: &[u8]) -> Result<[u8; 16], ParseError> {
    fn nibble(c: u8) -> Result<u8, ParseError> {
        if (b'A'..=b'P').contains(&c) {
            Ok(c - b'A')
        } else {
            Err(ParseError::Malformed(
                "netbios_ns: byte outside first-level encoding alphabet",
            ))
        }
    }
    let mut out = [0u8; 16];
    for (i, chunk) in encoded.chunks_exact(2).enumerate() {
        out[i] = (nibble(chunk[0])? << 4) | nibble(chunk[1])?;
    }
    Ok(out)
}

/// Best-effort text render of the 15-byte name portion (byte 16 is the
/// suffix, surfaced separately as `name_type`): trailing padding spaces
/// trimmed, non-graphic bytes rendered as `?` (same fallback as `dhcp`'s
/// hostname decode, 06.6).
fn render_name(name_bytes: &[u8]) -> String {
    let trimmed = {
        let end = name_bytes
            .iter()
            .rposition(|&b| b != b' ')
            .map_or(0, |i| i + 1);
        &name_bytes[..end]
    };
    trimmed
        .iter()
        .map(|&c| {
            if c.is_ascii_graphic() {
                char::from(c)
            } else {
                '?'
            }
        })
        .collect()
}

static KEY: &[KeyField] = &[KeyField { a: APP, b: None }];
static ROLLUPS: &[RollupSpec] = &[RollupSpec {
    field: NAME,
    kind: RollupKind::Accumulate,
}];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: ROLLUPS,
};

pub struct NetbiosNs;

impl LayerPlugin for NetbiosNs {
    fn name(&self) -> ProtocolName {
        "netbios_ns"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let _name_trn_id = r.u16_be()?; // consumed for framing, not in this plugin's field list (11.12)
        let flags = r.u16_be()?;
        let opcode = u64::from((flags >> 11) & 0x0F);
        let nm_flags = u64::from((flags >> 4) & 0x7F);
        let rcode = u64::from(flags & 0x0F);
        let qdcount = r.u16_be()?;
        let ancount = r.u16_be()?;
        let _nscount = r.u16_be()?;
        let _arcount = r.u16_be()?;

        // Question (query-shaped) or Answer (response-shaped) section:
        // both open with the same NAME/TYPE/CLASS shape (module doc), so
        // one decode covers either — first one present wins.
        let mut name = None;
        let mut name_type = None;
        let mut rr_type = None;
        if qdcount >= 1 || ancount >= 1 {
            let label_len = usize::from(r.u8()?);
            if label_len != FIRST_LEVEL_LEN {
                return Err(ParseError::Malformed(
                    "netbios_ns: name label is not the 32-char first-level form",
                ));
            }
            let encoded = r.take(FIRST_LEVEL_LEN)?;
            let decoded = decode_first_level(encoded)?;
            let terminator = r.u8()?;
            if terminator != 0 {
                // A non-empty scope id (RFC 1001 §14.3) would continue
                // the label chain here; decoding it is Tier 2 (module
                // doc), so decline rather than misreading it as data.
                return Err(ParseError::Malformed(
                    "netbios_ns: scoped names are not supported",
                ));
            }
            let ty = r.u16_be()?;
            let _class = r.u16_be()?;
            name = Some(render_name(&decoded[..15]));
            name_type = Some(u64::from(decoded[15]));
            rr_type = Some(u64::from(ty));
        }

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(APP, Value::from("netbios_ns"));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(OPCODE, Value::U64(opcode));
            fields.insert(NM_FLAGS, Value::U64(nm_flags));
            fields.insert(RCODE, Value::U64(rcode));
            fields.insert(QUESTION_COUNT, Value::U64(u64::from(qdcount)));
            fields.insert(ANSWER_COUNT, Value::U64(u64::from(ancount)));
        }
        if ctx.depth() >= Depth::Full {
            if let Some(n) = &name {
                fields.insert(NAME, Value::from(n.as_str()));
            }
            if let Some(t) = name_type {
                fields.insert(NAME_TYPE, Value::U64(t));
            }
            if let Some(t) = rr_type {
                fields.insert(RR_TYPE, Value::U64(t));
            }
        }

        Ok(ParsedLayer {
            header_len: bytes.len() - r.remaining(),
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::UdpPort(137)]
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

    fn ctx(depth: Depth, m: &PacketMeta) -> ParseCtx<'_> {
        ParseCtx::new(&[], depth, m)
    }

    /// RFC 1001 §14.1 encodes each half-octet as `'A' + nibble`.
    fn encode_first_level(raw: &[u8; 16]) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, &b) in raw.iter().enumerate() {
            out[2 * i] = b'A' + (b >> 4);
            out[2 * i + 1] = b'A' + (b & 0x0F);
        }
        out
    }

    /// A 16-byte NetBIOS name: `"WORKSTATION1"` space-padded to 15 bytes,
    /// suffix `0x00` (Workstation Service, RFC 1001 §14.2.1's classic
    /// example suffix).
    fn workstation1_name() -> [u8; 16] {
        let mut raw = [b' '; 16];
        raw[..12].copy_from_slice(b"WORKSTATION1");
        raw[15] = 0x00;
        raw
    }

    /// RFC 1002 §4.2.2: Name Query Request — opcode 0 (query), the `RD`
    /// bit set in NM_FLAGS (an arbitrary nonzero value, to prove raw
    /// extraction rather than a hardcoded zero), one question, NB record
    /// type.
    fn name_query_fixture() -> Vec<u8> {
        let mut b = vec![0x1A, 0x2B]; // NAME_TRN_ID
        let flags: u16 = 0x0100; // opcode=0, nm_flags=0x10 (RD bit), rcode=0
        b.extend_from_slice(&flags.to_be_bytes());
        b.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        b.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        b.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        b.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        b.push(FIRST_LEVEL_LEN as u8);
        b.extend_from_slice(&encode_first_level(&workstation1_name()));
        b.push(0x00); // name terminator, no scope id
        b.extend_from_slice(&0x0020u16.to_be_bytes()); // QUESTION_TYPE = NB
        b.extend_from_slice(&0x0001u16.to_be_bytes()); // QUESTION_CLASS = IN
        b
    }

    /// RFC 1002 §4.2.15: a response with zero questions/answers (e.g. a
    /// WACK) — the honest "identified, no name decoded" branch.
    fn empty_response_fixture() -> Vec<u8> {
        let mut b = vec![0x00, 0x01];
        let flags: u16 = 0xF800; // R=1, opcode=0xF (WACK), rest 0
        b.extend_from_slice(&flags.to_be_bytes());
        b.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]); // all four counts zero
        b
    }

    #[test]
    fn name_query_decodes_name_and_suffix() {
        let bytes = name_query_fixture();
        let m = meta(bytes.len());
        let parsed = NetbiosNs
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid Name Query Request");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(APP), Some(&Value::from("netbios_ns")));
        assert_eq!(parsed.fields.get(OPCODE), Some(&Value::U64(0)));
        assert_eq!(parsed.fields.get(NM_FLAGS), Some(&Value::U64(0x10)));
        assert_eq!(parsed.fields.get(QUESTION_COUNT), Some(&Value::U64(1)));
        assert_eq!(parsed.fields.get(ANSWER_COUNT), Some(&Value::U64(0)));
        assert_eq!(parsed.fields.get(NAME), Some(&Value::from("WORKSTATION1")));
        assert_eq!(parsed.fields.get(NAME_TYPE), Some(&Value::U64(0)));
        assert_eq!(parsed.fields.get(RR_TYPE), Some(&Value::U64(0x0020)));
    }

    #[test]
    fn zero_count_response_has_no_name_fields() {
        let bytes = empty_response_fixture();
        let m = meta(bytes.len());
        let parsed = NetbiosNs
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid empty response");
        assert_eq!(parsed.header_len, 12);
        assert_eq!(parsed.fields.get(OPCODE), Some(&Value::U64(0x0F)));
        assert_eq!(parsed.fields.get(NAME), None);
        assert_eq!(parsed.fields.get(NAME_TYPE), None);
        assert_eq!(parsed.fields.get(RR_TYPE), None);
    }

    #[test]
    fn app_key_field_present_at_keys_depth() {
        let bytes = empty_response_fixture();
        let m = meta(bytes.len());
        let parsed = NetbiosNs
            .parse(&bytes, &ctx(Depth::Keys, &m))
            .expect("valid");
        assert_eq!(parsed.fields.len(), 1);
        assert_eq!(parsed.fields.get(APP), Some(&Value::from("netbios_ns")));
    }

    #[test]
    fn non_first_level_alphabet_byte_declines() {
        let mut bytes = name_query_fixture();
        // Header (12) + label-length byte (1) = 13: the first encoded
        // char. Must be 'A'..='P'; 'Z' is outside that range.
        let first_encoded_char = 13;
        bytes[first_encoded_char] = b'Z';
        let m = meta(bytes.len());
        assert!(NetbiosNs.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn non_32_char_label_length_declines() {
        let mut bytes = name_query_fixture();
        bytes[12] = 0x10; // label length byte (right after the 12-byte header), claims 16 instead of 32
        let m = meta(bytes.len());
        assert!(NetbiosNs.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn scoped_name_declines() {
        let mut bytes = name_query_fixture();
        // Header (12) + label-length byte (1) + encoded label (32) = 45:
        // the terminator byte. Nonzero means a scope-id label follows (Tier 2).
        bytes[45] = 0x01;
        let m = meta(bytes.len());
        assert!(NetbiosNs.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn truncated_name_query_declines() {
        let bytes = name_query_fixture();
        let m = meta(bytes.len());
        let full_ctx = ctx(Depth::Full, &m);
        for n in 0..bytes.len() {
            assert!(
                NetbiosNs.parse(&bytes[..n], &full_ctx).is_err(),
                "prefix of {n}/{} header bytes must decline",
                bytes.len()
            );
        }
    }

    #[test]
    fn truncated_empty_response_declines() {
        let bytes = empty_response_fixture();
        let m = meta(bytes.len());
        let full_ctx = ctx(Depth::Full, &m);
        for n in 0..12 {
            assert!(
                NetbiosNs.parse(&bytes[..n], &full_ctx).is_err(),
                "prefix of {n}/12 header bytes must decline"
            );
        }
    }
}
