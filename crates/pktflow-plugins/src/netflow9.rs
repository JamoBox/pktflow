//! NetFlow v9 — 11.11, D14 citation: RFC 3954 (informational). Cisco's
//! flow-export protocol: an Export Packet carries a fixed header plus a
//! sequence of self-delimiting FlowSets (§5).
//!
//! **Stateful-template ceiling (D12/D13), stated plainly.** FlowSet id `0`
//! is a *Template* FlowSet (§5.2): it defines a Data FlowSet's field
//! layout entirely from bytes present in *this* packet, so it decodes in
//! full. Every other FlowSet id (`1`-`65535`) is a *Data* FlowSet (§5.3)
//! — or, for id `1`, an Options Template (§8), which this Tier-1 plugin
//! doesn't special-case — whose bytes are meaningless without the
//! matching Template FlowSet, which may have arrived on an *earlier*
//! packet (or never, if the capture starts mid-stream). That's
//! cross-packet state a stateless plugin (02.1 rule 5) doesn't carry, the
//! same class of gap as HTTP/2's HPACK dynamic table (11.8) — so this
//! dissector reads every non-Template FlowSet's `id`/`length` framing and
//! retains its body as opaque bytes, never attempting a template lookup
//! it can't perform correctly.
//!
//! **Why the FlowSet walk doesn't use the header's `count`.** RFC 3954
//! §5.1 defines `Count` as "the total number of records in the Export
//! Packet" — records, not FlowSets: one Data FlowSet can carry many
//! records under a single `id`/`length` framing, and this plugin (by
//! design) never opens a Data FlowSet to count what's inside. So `Count`
//! is reported as a field but never drives the walk; instead, each
//! FlowSet is self-delimiting (`length` includes its own 4-byte
//! `id`+`length` header), and the walk consumes them back to back until
//! fewer than 4 bytes remain — the same "trust the self-declared length,
//! not an outer counter" shape as DHCP's option walk (06.6).
//!
//! **Why `header_len` stops at the fixed 20-byte header, never inside the
//! FlowSet walk.** FlowSets are "zero or more" — an Export Packet with no
//! FlowSets at all is wire-format-valid — so a capture truncated to
//! exactly the fixed header is byte-for-byte a genuinely complete
//! zero-FlowSet packet, and a capture truncated right after any one
//! FlowSet's declared length is a genuinely complete packet with one
//! fewer FlowSet. Both are the same "valid shorter message" ambiguity
//! `syslog`'s optional trailing MSG has (11.11): there's no way to tell a
//! truncated capture from a legitimately shorter one once you're past
//! that boundary. So `header_len` is exactly the fixed header (20 bytes)
//! — the FlowSet walk still runs and populates `flowsets`, but entirely
//! in the "trailing payload beyond header_len" territory the 09.1 kit's
//! `GoodPacket` doc comment allows, the same design `syslog` uses for
//! `msg`. FlowSet coverage (a Template FlowSet decoding in full, and a
//! Data FlowSet immediately after it in the same packet staying opaque
//! even though its template was just seen) lives in the non-strict
//! `netflow9_data_flowset_stays_opaque_even_immediately_after_its_template`
//! test (`tests/application.rs`) instead.
//!
//! **App-stream pattern (06.6).** NetFlow has no endpoint identity of its
//! own — `app = "netflow9"` is a shared constant key, one child stream
//! per UDP stream (exporter -> collector), the same shape as
//! `dns`/`syslog`/`snmp`.

use pktflow_core::{
    ByteReader, Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx,
    ParseError, ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId, StreamIdentity, Value,
};

const APP: FieldName = "app";
const VERSION: FieldName = "version";
const COUNT: FieldName = "count";
const SEQUENCE: FieldName = "sequence";
const SOURCE_ID: FieldName = "source_id";
const FLOWSETS: FieldName = "flowsets";

/// RFC 3954 §5.2: FlowSet id `0` always names a Template FlowSet.
const TEMPLATE_FLOWSET_ID: u16 = 0;

static KEY: &[KeyField] = &[KeyField { a: APP, b: None }];
static ROLLUPS: &[RollupSpec] = &[RollupSpec {
    field: SOURCE_ID,
    kind: RollupKind::Accumulate,
}];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: ROLLUPS,
};

/// Decodes a Template FlowSet's body (RFC 3954 §5.2): one or more back-to-
/// back Template Records, each `template_id(2) + field_count(2) +
/// field_count * (field_type(2) + field_length(2))`. Trailing padding
/// shorter than one more record's minimum size (4 bytes) is left alone.
fn decode_template_records(body: &[u8]) -> Result<Vec<Value>, ParseError> {
    let mut r = ByteReader::new(body);
    let mut records = Vec::new();
    while r.remaining() >= 4 {
        let template_id = r.u16_be()?;
        let field_count = r.u16_be()?;
        let mut field_defs = Vec::with_capacity(usize::from(field_count) * 2);
        for _ in 0..field_count {
            let field_type = r.u16_be()?;
            let field_length = r.u16_be()?;
            field_defs.push(Value::U64(u64::from(field_type)));
            field_defs.push(Value::U64(u64::from(field_length)));
        }
        records.push(Value::List(vec![
            Value::U64(u64::from(template_id)),
            Value::U64(u64::from(field_count)),
            Value::List(field_defs),
        ]));
    }
    Ok(records)
}

pub struct Netflow9;

impl LayerPlugin for Netflow9 {
    fn name(&self) -> ProtocolName {
        "netflow9"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let version = r.u16_be()?;
        if version != 9 {
            return Err(ParseError::Malformed("NetFlow: version is not 9"));
        }
        let count = r.u16_be()?;
        let _sys_uptime = r.u32_be()?;
        let _unix_secs = r.u32_be()?;
        let sequence = r.u32_be()?;
        let source_id = r.u32_be()?;
        // FlowSets are optional repetition — see the module doc's
        // truncation-honesty note — so header_len stops here, before the
        // FlowSet walk, even though `r` keeps reading past it below.
        let header_len = bytes.len() - r.remaining();

        let mut flowsets = Vec::new();
        while r.remaining() >= 4 {
            let flowset_id = r.u16_be()?;
            let length = usize::from(r.u16_be()?);
            let body_len = length
                .checked_sub(4)
                .ok_or(ParseError::Malformed("NetFlow: FlowSet length under 4"))?;
            let body = r.take(body_len)?;

            let payload = if flowset_id == TEMPLATE_FLOWSET_ID {
                Value::List(decode_template_records(body)?)
            } else {
                Value::from(body)
            };
            flowsets.push(Value::List(vec![
                Value::U64(u64::from(flowset_id)),
                Value::U64(length as u64),
                payload,
            ]));
        }

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(APP, Value::from("netflow9"));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(VERSION, Value::U64(u64::from(version)));
            fields.insert(COUNT, Value::U64(u64::from(count)));
            fields.insert(SEQUENCE, Value::U64(u64::from(sequence)));
            fields.insert(SOURCE_ID, Value::U64(u64::from(source_id)));
        }
        if ctx.depth() >= Depth::Full {
            fields.insert(FLOWSETS, Value::List(flowsets));
        }

        Ok(ParsedLayer {
            header_len,
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        // 2055 is the common default export port, not an IANA-fixed
        // assignment — several deployments use others (the same
        // claim-honesty note `wireguard` would need for 11.5). No
        // `probe()`: the 4-byte version+count header is too generic to
        // guess safely.
        &[RouteId::UdpPort(2055)]
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

    #[test]
    fn non_nine_version_declines() {
        let mut bytes = vec![0, 10]; // version = 10
        bytes.extend_from_slice(&[0u8; 18]); // rest of the fixed header
        let m = meta(bytes.len());
        assert!(Netflow9.parse(&bytes, &ctx(&m)).is_err());
    }

    #[test]
    fn flowset_length_under_four_declines() {
        let mut bytes = vec![0, 9]; // version = 9
        bytes.extend_from_slice(&[0u8; 18]); // count, uptime, secs, seq, source_id
        bytes.extend_from_slice(&[0, 0]); // flowset_id = 0
        bytes.extend_from_slice(&[0, 3]); // length = 3, less than the 4-byte minimum
        let m = meta(bytes.len());
        assert!(Netflow9.parse(&bytes, &ctx(&m)).is_err());
    }

    #[test]
    fn template_records_decode_and_data_flowset_left_opaque_in_one_packet() {
        // Header (count=2: one Template FlowSet, one Data FlowSet).
        let mut bytes = vec![0, 9, 0, 2];
        bytes.extend_from_slice(&1_000u32.to_be_bytes()); // sys_uptime
        bytes.extend_from_slice(&1_700_000_000u32.to_be_bytes()); // unix_secs
        bytes.extend_from_slice(&42u32.to_be_bytes()); // sequence
        bytes.extend_from_slice(&7u32.to_be_bytes()); // source_id

        // Template FlowSet (id=0): one record, template_id=256, 2 fields.
        let mut template_flowset = vec![0, 0]; // flowset_id = 0
        let mut record = 256u16.to_be_bytes().to_vec();
        record.extend_from_slice(&2u16.to_be_bytes()); // field_count
        record.extend_from_slice(&8u16.to_be_bytes()); // IN_BYTES
        record.extend_from_slice(&4u16.to_be_bytes());
        record.extend_from_slice(&4u16.to_be_bytes()); // IN_PKTS
        record.extend_from_slice(&4u16.to_be_bytes());
        let template_len = 4 + record.len();
        template_flowset.extend_from_slice(&(template_len as u16).to_be_bytes());
        template_flowset.extend_from_slice(&record);
        bytes.extend_from_slice(&template_flowset);

        // Data FlowSet using template 256, right after — must stay opaque.
        let data_body = [0xAA, 0xBB, 0xCC, 0xDD];
        let mut data_flowset = 256u16.to_be_bytes().to_vec(); // flowset_id = 256
        let data_len = 4 + data_body.len();
        data_flowset.extend_from_slice(&(data_len as u16).to_be_bytes());
        data_flowset.extend_from_slice(&data_body);
        bytes.extend_from_slice(&data_flowset);

        let m = meta(bytes.len());
        let parsed = Netflow9.parse(&bytes, &ctx(&m)).expect("valid packet");
        assert_eq!(
            parsed.header_len, 20,
            "fixed header only, FlowSets are trailing payload"
        );

        let Some(Value::List(flowsets)) = parsed.fields.get(FLOWSETS) else {
            panic!("missing flowsets field");
        };
        assert_eq!(flowsets.len(), 2);

        let Value::List(tmpl_entry) = &flowsets[0] else {
            panic!("wrong shape");
        };
        assert_eq!(tmpl_entry[0], Value::U64(0));
        assert_eq!(tmpl_entry[1], Value::U64(template_len as u64));
        let Value::List(records) = &tmpl_entry[2] else {
            panic!("template payload should decode as a nested List");
        };
        assert_eq!(records.len(), 1);

        let Value::List(data_entry) = &flowsets[1] else {
            panic!("wrong shape");
        };
        assert_eq!(data_entry[0], Value::U64(256));
        assert_eq!(data_entry[1], Value::U64(data_len as u64));
        assert_eq!(data_entry[2], Value::from(&data_body[..]));
    }

    proptest::proptest! {
        #[test]
        fn parse_never_panics(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..300)) {
            let m = meta(bytes.len());
            let _ = Netflow9.parse(&bytes, &ctx(&m));
        }
    }
}
