//! NTP (06.6, RFC 5905): fixed 48-byte header, raw timestamps — analysis
//! belongs to consumers, not the dissector.

use pktflow_core::{
    ByteReader, Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx,
    ParseError, ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId, StreamIdentity, Value,
};

const APP: FieldName = "app";
const VERSION: FieldName = "version";
const MODE: FieldName = "mode";
const STRATUM: FieldName = "stratum";
const REF_ID: FieldName = "ref_id";
const REF_TS: FieldName = "ref_ts";
const ORIG_TS: FieldName = "orig_ts";
const RECV_TS: FieldName = "recv_ts";
const XMIT_TS: FieldName = "xmit_ts";

static KEY: &[KeyField] = &[KeyField { a: APP, b: None }];
static ROLLUPS: &[RollupSpec] = &[
    RollupSpec {
        field: MODE,
        kind: RollupKind::Accumulate,
    },
    RollupSpec {
        field: STRATUM,
        kind: RollupKind::Sample,
    },
];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: ROLLUPS,
};

pub struct Ntp;

impl LayerPlugin for Ntp {
    fn name(&self) -> ProtocolName {
        "ntp"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let li_vn_mode = r.u8()?;
        let mode = li_vn_mode & 0x07;
        if mode == 0 {
            return Err(ParseError::Malformed("reserved NTP mode 0"));
        }
        let stratum = r.u8()?;
        let _poll = r.u8()?;
        let _precision = r.u8()?;
        let _root_delay = r.u32_be()?;
        let _root_dispersion = r.u32_be()?;
        let ref_id = r.take(4)?;
        let ref_ts = r.u64_be()?;
        let orig_ts = r.u64_be()?;
        let recv_ts = r.u64_be()?;
        let xmit_ts = r.u64_be()?;

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(APP, Value::from("ntp"));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(VERSION, Value::U64(u64::from((li_vn_mode >> 3) & 0x07)));
            fields.insert(MODE, Value::U64(u64::from(mode)));
            fields.insert(STRATUM, Value::U64(u64::from(stratum)));
        }
        if ctx.depth() >= Depth::Full {
            fields.insert(REF_ID, Value::from(ref_id));
            fields.insert(REF_TS, Value::U64(ref_ts));
            fields.insert(ORIG_TS, Value::U64(orig_ts));
            fields.insert(RECV_TS, Value::U64(recv_ts));
            fields.insert(XMIT_TS, Value::U64(xmit_ts));
        }

        Ok(ParsedLayer {
            header_len: 48,
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::UdpPort(123)]
    }

    fn stream_identity(&self) -> Option<&StreamIdentity> {
        Some(&IDENTITY)
    }
}
