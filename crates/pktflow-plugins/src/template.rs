//! Template plugin — **copy this file** to add a protocol (FR-20).
//!
//! "PKTT" is fictional so it never collides with reality. 8-byte header:
//! `| src | dst | type | len |`, u16 each, big-endian. Sections below are
//! ordered the way you should fill them in; see docs/adding-a-protocol.md.

use pktflow_core::{
    ByteReader, Canonicalize, Confidence, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin,
    ParseCtx, ParseError, ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId,
    StreamIdentity, Value,
};

// 1. Field-name constants: snake_case, protocol-local.
const SRC: FieldName = "src";
const DST: FieldName = "dst";
const TYPE: FieldName = "type";
const LEN: FieldName = "len";

// 5. Stream identity: the fields identifying each end, plus rollups.
//    Declaring this turns a dissector into a conversation source.
static KEY: &[KeyField] = &[KeyField {
    a: SRC,
    b: Some(DST),
}];
static ROLLUPS: &[RollupSpec] = &[RollupSpec {
    field: TYPE,
    kind: RollupKind::Accumulate,
}];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None, // see the tcp plugin for a lifecycle example
    rollups: ROLLUPS,
};

pub struct Template;

impl LayerPlugin for Template {
    fn name(&self) -> ProtocolName {
        "template"
    }

    // 2. Parse exactly one header via ByteReader (never index bytes), gate
    //    fields on depth, and return the most explicit hint you can.
    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let src = r.u16_be()?;
        let dst = r.u16_be()?;
        let ty = r.u16_be()?;
        let len = r.u16_be()?;

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            // Flow-key fields must always be present at >= Keys (01.3).
            fields.insert(SRC, Value::U64(u64::from(src)));
            fields.insert(DST, Value::U64(u64::from(dst)));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(TYPE, Value::U64(u64::from(ty)));
            fields.insert(LEN, Value::U64(u64::from(len)));
        }

        // type 0x0001 = PKTT-in-PKTT: direct-by-name encapsulation.
        let hint = if ty == 0x0001 {
            Hint::ByProtocol("template")
        } else {
            Hint::Terminal
        };
        Ok(ParsedLayer {
            header_len: 8,
            fields,
            hint,
        })
    }

    // 3. Claims: a Custom space, so the tutorial never squats a real id.
    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::Custom {
            space: "pktt",
            id: 0,
        }]
    }

    // 4. Probe: honest and cheap — verify the len field against the
    //    buffer. Random bytes almost never pass (a u16 len must land in
    //    8..=bytes.len()), which is exactly what 02.3 demands.
    fn has_probe(&self) -> bool {
        true
    }

    fn probe(&self, bytes: &[u8], _ctx: &ParseCtx) -> Option<Confidence> {
        let mut r = ByteReader::new(bytes);
        let _src_dst_type = r.take(6).ok()?;
        let len = r.u16_be().ok()?;
        (usize::from(len) >= 8 && usize::from(len) <= bytes.len()).then(|| Confidence::new(60))
    }

    fn stream_identity(&self) -> Option<&StreamIdentity> {
        Some(&IDENTITY)
    }
}

// 6. Tests to copy: fixture parse, truncation, hint. The heavy contract
//    checks run through the 09.1 kit in tests/conformance.rs — add yours.
#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use pktflow_core::{LinkType, PacketMeta};

    use super::*;

    // src=3, dst=7, type=2 (terminal), len=8.
    const FRAME: [u8; 8] = [0x00, 0x03, 0x00, 0x07, 0x00, 0x02, 0x00, 0x08];

    fn parse(bytes: &[u8]) -> Result<ParsedLayer, ParseError> {
        let meta = PacketMeta {
            timestamp: SystemTime::UNIX_EPOCH,
            caplen: bytes.len(),
            origlen: bytes.len(),
            link_type: LinkType::ETHERNET,
        };
        Template.parse(bytes, &ParseCtx::new(&[], Depth::Full, &meta))
    }

    #[test]
    fn parses_the_fixture_frame() {
        let parsed = parse(&FRAME).expect("valid frame");
        assert_eq!(parsed.header_len, 8);
        assert_eq!(parsed.fields.get(SRC), Some(&Value::U64(3)));
        assert_eq!(parsed.fields.get(DST), Some(&Value::U64(7)));
        assert_eq!(parsed.fields.get(TYPE), Some(&Value::U64(2)));
        assert_eq!(parsed.hint, Hint::Terminal);
    }

    #[test]
    fn truncated_header_declines() {
        assert!(parse(&FRAME[..7]).is_err());
    }

    #[test]
    fn type_one_nests_by_name() {
        let mut nested = FRAME;
        nested[5] = 0x01; // type = 1: PKTT-in-PKTT
        assert_eq!(
            parse(&nested).expect("valid frame").hint,
            Hint::ByProtocol("template")
        );
    }
}
