//! IPFIX — 11.11, D14 citation: RFC 7011. The IETF-standardized successor
//! to NetFlow v9 (`netflow9.rs`): a Message carries a fixed header plus a
//! sequence of self-delimiting Sets (§3.1, §3.3).
//!
//! **Stateful-template ceiling (D12/D13), same as NetFlow v9.** Set ID `2`
//! is a Template Set (§3.3.2): it defines a Data Set's field layout
//! entirely from bytes present in *this* packet, so it decodes in full.
//! Set ID `3` (Options Template Set, §3.3.3) and every Data Set (`256`-
//! `65535`, matching a previously-defined Template ID) need the matching
//! template, which may have arrived on an *earlier* packet (or never).
//! That's cross-packet state a stateless plugin (02.1 rule 5) doesn't
//! carry — the same class of gap `netflow9` documents — so this
//! dissector reads every non-Template Set's `id`/`length` framing and
//! retains its body as opaque bytes.
//!
//! **Why the message boundary is exact here, unlike NetFlow v9's.** RFC
//! 3954's header has no total-byte-length field (only a *record* count,
//! ambiguous against FlowSets), forcing `netflow9` to leave its Sets as
//! untracked trailing payload. RFC 7011 §3.1 closes that gap: the
//! `Length` field is "the total length of the IPFIX Message, measured in
//! octets, including the Message header" — authoritative, the same
//! self-describing-length shape `bgp`'s `Length` uses (11.4). So the Set
//! walk here is bounded by `length - HEADER_LEN`, not `bytes.len()`
//! (`r.remaining()`), and `header_len` is set to `length` itself — a
//! coalesced second Message in the same buffer stays untouched, exactly
//! `bgp`'s "bound the body to the message's own Length" precedent, not
//! `netflow9`'s "stop at the fixed header, Sets are untracked payload"
//! fallback.
//!
//! **Field Specifier's Enterprise bit (§3.2).** Unlike NetFlow v9's fixed
//! 4-byte-per-field Template Record, IPFIX's Field Specifier reserves the
//! top bit of the 16-bit Information Element identifier as an Enterprise
//! bit: when set, a 4-byte Enterprise Number immediately follows that
//! field's Length, shifting every subsequent field in the record. Getting
//! this wrong silently desyncs the rest of the record, so it's handled
//! here even though 11.11's Tier-1 field list doesn't call it out by
//! name — it's part of RFC 7011's fixed Template Record framing, not an
//! optional extension.
//!
//! **App-stream pattern (06.6).** Like `netflow9`, IPFIX has no endpoint
//! identity of its own — `app = "ipfix"` is a shared constant key, one
//! child stream per UDP stream (exporter -> collector).

use pktflow_core::{
    ByteReader, Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx,
    ParseError, ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId, StreamIdentity, Value,
};

const APP: FieldName = "app";
const VERSION: FieldName = "version";
const LENGTH: FieldName = "length";
const SEQUENCE: FieldName = "sequence";
const DOMAIN_ID: FieldName = "domain_id";
const SETS: FieldName = "sets";

/// RFC 7011 §3.1: Version Number(2) + Length(2) + Export Time(4) +
/// Sequence Number(4) + Observation Domain ID(4).
const HEADER_LEN: usize = 16;

/// RFC 7011 §3.3.2: Set ID `2` always names a Template Set.
const TEMPLATE_SET_ID: u16 = 2;

/// RFC 7011 §3.2: the top bit of the Information Element identifier
/// marks an Enterprise-specific IE, adding a 4-byte Enterprise Number
/// after that field's Length.
const ENTERPRISE_BIT: u16 = 0x8000;

static KEY: &[KeyField] = &[KeyField { a: APP, b: None }];
static ROLLUPS: &[RollupSpec] = &[RollupSpec {
    field: DOMAIN_ID,
    kind: RollupKind::Accumulate,
}];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: ROLLUPS,
};

/// Decodes a Template Set's body (RFC 7011 §3.4.1): one or more back-to-
/// back Template Records, each `template_id(2) + field_count(2)` followed
/// by `field_count` Field Specifiers (§3.2: `ie_id(2, Enterprise-bit
/// aware) + length(2) [+ enterprise_number(4) if the bit is set]`).
/// Trailing padding shorter than one more record's minimum size (4
/// bytes) is left alone. Each field is reported as a 3-element
/// `[ie_id (Enterprise bit masked off), length, enterprise_number (0 if
/// none)]` list, so the shape is stable whether or not any field in the
/// record is enterprise-specific.
fn decode_template_records(body: &[u8]) -> Result<Vec<Value>, ParseError> {
    let mut r = ByteReader::new(body);
    let mut records = Vec::new();
    while r.remaining() >= 4 {
        let template_id = r.u16_be()?;
        let field_count = r.u16_be()?;
        let mut field_defs = Vec::with_capacity(usize::from(field_count));
        for _ in 0..field_count {
            let raw_ie_id = r.u16_be()?;
            let field_length = r.u16_be()?;
            let (ie_id, enterprise_number) = if raw_ie_id & ENTERPRISE_BIT != 0 {
                (raw_ie_id & !ENTERPRISE_BIT, r.u32_be()?)
            } else {
                (raw_ie_id, 0u32)
            };
            field_defs.push(Value::List(vec![
                Value::U64(u64::from(ie_id)),
                Value::U64(u64::from(field_length)),
                Value::U64(u64::from(enterprise_number)),
            ]));
        }
        records.push(Value::List(vec![
            Value::U64(u64::from(template_id)),
            Value::U64(u64::from(field_count)),
            Value::List(field_defs),
        ]));
    }
    Ok(records)
}

pub struct Ipfix;

impl LayerPlugin for Ipfix {
    fn name(&self) -> ProtocolName {
        "ipfix"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let version = r.u16_be()?;
        if version != 10 {
            return Err(ParseError::Malformed("IPFIX: version is not 10"));
        }
        let length = usize::from(r.u16_be()?);
        let _export_time = r.u32_be()?;
        let sequence = r.u32_be()?;
        let domain_id = r.u32_be()?;
        if length < HEADER_LEN {
            return Err(ParseError::Malformed("IPFIX: length below fixed header"));
        }

        // Bounding the walk to the message's own `length` (not
        // `r.remaining()`) is what makes a coalesced second Message in
        // the same datagram stay untouched (module doc, `bgp`'s
        // precedent).
        let body = r.take(length - HEADER_LEN)?;
        let mut sr = ByteReader::new(body);
        let mut sets = Vec::new();
        while sr.remaining() >= 4 {
            let set_id = sr.u16_be()?;
            let set_len = usize::from(sr.u16_be()?);
            let set_body_len = set_len
                .checked_sub(4)
                .ok_or(ParseError::Malformed("IPFIX: Set length under 4"))?;
            let set_body = sr.take(set_body_len)?;

            let payload = if set_id == TEMPLATE_SET_ID {
                Value::List(decode_template_records(set_body)?)
            } else {
                Value::from(set_body)
            };
            sets.push(Value::List(vec![
                Value::U64(u64::from(set_id)),
                Value::U64(set_len as u64),
                payload,
            ]));
        }

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(APP, Value::from("ipfix"));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(VERSION, Value::U64(u64::from(version)));
            fields.insert(LENGTH, Value::U64(length as u64));
            fields.insert(SEQUENCE, Value::U64(u64::from(sequence)));
            fields.insert(DOMAIN_ID, Value::U64(u64::from(domain_id)));
        }
        if ctx.depth() >= Depth::Full {
            fields.insert(SETS, Value::List(sets));
        }

        Ok(ParsedLayer {
            header_len: length,
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::UdpPort(4739)]
    }

    fn stream_identity(&self) -> Option<&StreamIdentity> {
        Some(&IDENTITY)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pktflow_core::{LinkType, PacketMeta};
    use std::time::SystemTime;

    fn meta(len: usize) -> PacketMeta {
        PacketMeta {
            timestamp: SystemTime::UNIX_EPOCH,
            caplen: len,
            origlen: len,
            link_type: LinkType::ETHERNET,
        }
    }

    fn ctx(m: &PacketMeta) -> ParseCtx<'_> {
        ParseCtx::new(&[], Depth::Full, m)
    }

    /// Fixed 16-byte header only (RFC 7011 §3.1), `length` == 16 (no Sets).
    fn header(length: u16, sequence: u32, domain_id: u32) -> Vec<u8> {
        let mut b = vec![0, 10];
        b.extend_from_slice(&length.to_be_bytes());
        b.extend_from_slice(&1_700_000_000u32.to_be_bytes()); // export_time
        b.extend_from_slice(&sequence.to_be_bytes());
        b.extend_from_slice(&domain_id.to_be_bytes());
        b
    }

    #[test]
    fn non_ten_version_declines() {
        let mut bytes = vec![0, 9]; // version = 9, not 10
        bytes.extend_from_slice(&16u16.to_be_bytes());
        bytes.extend_from_slice(&[0u8; 12]);
        let m = meta(bytes.len());
        assert!(Ipfix.parse(&bytes, &ctx(&m)).is_err());
    }

    #[test]
    fn length_below_header_floor_declines() {
        let bytes = header(15, 1, 1); // length < 16
        let m = meta(bytes.len());
        assert!(Ipfix.parse(&bytes, &ctx(&m)).is_err());
    }

    #[test]
    fn zero_set_message_parses_at_exactly_the_fixed_header() {
        let bytes = header(16, 42, 7);
        let m = meta(bytes.len());
        let parsed = Ipfix
            .parse(&bytes, &ctx(&m))
            .expect("valid header, no Sets");
        assert_eq!(parsed.header_len, 16);
        assert_eq!(parsed.fields.get(VERSION), Some(&Value::U64(10)));
        assert_eq!(parsed.fields.get(LENGTH), Some(&Value::U64(16)));
        assert_eq!(parsed.fields.get(SEQUENCE), Some(&Value::U64(42)));
        assert_eq!(parsed.fields.get(DOMAIN_ID), Some(&Value::U64(7)));
        assert_eq!(parsed.fields.get(SETS), Some(&Value::List(vec![])));
    }

    #[test]
    fn a_second_coalesced_message_stays_untouched() {
        let mut bytes = header(16, 1, 1);
        bytes.extend_from_slice(&header(16, 2, 2)); // a second Message, same datagram
        let m = meta(bytes.len());
        let parsed = Ipfix.parse(&bytes, &ctx(&m)).expect("valid first message");
        assert_eq!(parsed.header_len, 16, "only the first message consumed");
    }

    #[test]
    fn set_length_under_four_declines() {
        let mut bytes = header(20, 1, 1);
        bytes.extend_from_slice(&TEMPLATE_SET_ID.to_be_bytes());
        bytes.extend_from_slice(&3u16.to_be_bytes()); // length = 3, under the 4-byte minimum
        let m = meta(bytes.len());
        assert!(Ipfix.parse(&bytes, &ctx(&m)).is_err());
    }

    /// One Template Set (id=2): a single record (template_id=256) with a
    /// plain field (IE 8, length 4) and an Enterprise-specific field (IE
    /// 12345 with the Enterprise bit set, length 4, enterprise number
    /// 99999) — proves the Enterprise-bit shift is handled, not just the
    /// common case.
    #[test]
    fn template_set_with_enterprise_field_decodes_and_data_set_stays_opaque() {
        let mut record = 256u16.to_be_bytes().to_vec();
        record.extend_from_slice(&2u16.to_be_bytes()); // field_count = 2
        record.extend_from_slice(&8u16.to_be_bytes()); // IE 8 (IN_BYTES), no Enterprise bit
        record.extend_from_slice(&4u16.to_be_bytes());
        let enterprise_ie = 12345u16 | ENTERPRISE_BIT;
        record.extend_from_slice(&enterprise_ie.to_be_bytes());
        record.extend_from_slice(&4u16.to_be_bytes());
        record.extend_from_slice(&99999u32.to_be_bytes());
        let template_set_len = 4 + record.len();

        let data_body = [0xDE, 0xAD, 0xBE, 0xEF];
        let data_set_len = 4 + data_body.len();

        let total_len = HEADER_LEN + template_set_len + data_set_len;
        let mut bytes = header(total_len as u16, 1, 1);
        bytes.extend_from_slice(&TEMPLATE_SET_ID.to_be_bytes());
        bytes.extend_from_slice(&(template_set_len as u16).to_be_bytes());
        bytes.extend_from_slice(&record);
        bytes.extend_from_slice(&256u16.to_be_bytes()); // Data Set id == template_id
        bytes.extend_from_slice(&(data_set_len as u16).to_be_bytes());
        bytes.extend_from_slice(&data_body);

        let m = meta(bytes.len());
        let parsed = Ipfix.parse(&bytes, &ctx(&m)).expect("valid message");
        assert_eq!(parsed.header_len, total_len);

        let Some(Value::List(sets)) = parsed.fields.get(SETS) else {
            panic!("missing sets field");
        };
        assert_eq!(sets.len(), 2);

        let Value::List(template_entry) = &sets[0] else {
            panic!("wrong shape");
        };
        assert_eq!(template_entry[0], Value::U64(2));
        let Value::List(records) = &template_entry[2] else {
            panic!("template payload should decode as a nested List");
        };
        let Value::List(record_entry) = &records[0] else {
            panic!("wrong shape");
        };
        let Value::List(fields) = &record_entry[2] else {
            panic!("wrong shape");
        };
        assert_eq!(
            fields[0],
            Value::List(vec![Value::U64(8), Value::U64(4), Value::U64(0)]),
            "plain field: no enterprise number"
        );
        assert_eq!(
            fields[1],
            Value::List(vec![Value::U64(12345), Value::U64(4), Value::U64(99999)]),
            "Enterprise-bit field: id masked, enterprise number captured"
        );

        let Value::List(data_entry) = &sets[1] else {
            panic!("wrong shape");
        };
        assert_eq!(data_entry[0], Value::U64(256));
        assert_eq!(
            data_entry[2],
            Value::from(&data_body[..]),
            "Data Set stays opaque even though its template was just seen"
        );
    }

    #[test]
    fn truncated_messages_decline_at_every_length() {
        let bytes = header(16, 42, 7);
        for n in 0..bytes.len() {
            assert!(Ipfix.parse(&bytes[..n], &ctx(&meta(n))).is_err());
        }
    }

    proptest::proptest! {
        #[test]
        fn parse_never_panics(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..300)) {
            let m = meta(bytes.len());
            let _ = Ipfix.parse(&bytes, &ctx(&m));
        }
    }
}
