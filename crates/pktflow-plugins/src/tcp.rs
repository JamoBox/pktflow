//! TCP (06.4, RFC 9293): sessions with the FR-6 reference lifecycle.
//! Deliberately coarse — session bookkeeping, not a sequence-number-
//! correct state machine (no reassembly, D7).

use pktflow_core::{
    ByteReader, Canonicalize, Confidence, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin,
    LifecycleSpec, PacketDirection, ParseCtx, ParseError, ParsedLayer, ProtocolName, RollupKind,
    RollupSpec, RouteId, StateName, StreamIdentity, Value,
};
use smallvec::SmallVec;

const SRC_PORT: FieldName = "src_port";
const DST_PORT: FieldName = "dst_port";
const FLAGS: FieldName = "flags";
const SEQ: FieldName = "seq";
const ACK: FieldName = "ack";
const WINDOW: FieldName = "window";
const DATA_OFFSET: FieldName = "data_offset";
const CHECKSUM: FieldName = "checksum";
const URGENT: FieldName = "urgent";
const OPTIONS: FieldName = "options";

const FIN: u64 = 0x01;
const SYN: u64 = 0x02;
const RST: u64 = 0x04;
const ACK_F: u64 = 0x10;

/// The FR-6 reference lifecycle. Unrecognized input keeps the current
/// state (pure and total, 05.5).
fn advance(fields: &FieldMap, state: StateName, _dir: PacketDirection) -> StateName {
    let Some(Value::U64(flags)) = fields.get(FLAGS) else {
        return state;
    };
    if flags & RST != 0 {
        return "reset"; // any --RST--> reset
    }
    let (syn, ack, fin) = (flags & SYN != 0, flags & ACK_F != 0, flags & FIN != 0);
    match state {
        "new" if syn && !ack => "syn_sent",
        // Capture began mid-session: any non-SYN first packet.
        "new" if !syn => "established_midstream",
        "syn_sent" if syn && ack => "syn_received",
        "syn_received" if ack && !syn && !fin => "established",
        "established" | "established_midstream" if fin => "closing",
        // The other side's FIN(+ACK) completes the teardown.
        "closing" if fin && ack => "closed",
        _ => state,
    }
}

static KEY: &[KeyField] = &[KeyField {
    a: SRC_PORT,
    b: Some(DST_PORT),
}];
// FR-5's example (set of flag combinations) plus the handshake/teardown
// timeline (05.5 note).
static ROLLUPS: &[RollupSpec] = &[
    RollupSpec {
        field: FLAGS,
        kind: RollupKind::Accumulate,
    },
    RollupSpec {
        field: FLAGS,
        kind: RollupKind::Series { cap: 1024 },
    },
];
static IDENTITY: StreamIdentity = StreamIdentity {
    // Ports only: the 5-tuple is the (IP-pair parent, port-pair) tree
    // path (D10, 02.4).
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: Some(LifecycleSpec {
        initial: "new",
        advance,
        closed_states: &["closed", "reset"],
    }),
    rollups: ROLLUPS,
};

pub struct Tcp;

impl LayerPlugin for Tcp {
    fn name(&self) -> ProtocolName {
        "tcp"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let src_port = r.u16_be()?;
        let dst_port = r.u16_be()?;
        let seq = r.u32_be()?;
        let ack = r.u32_be()?;
        let offset_flags = r.u16_be()?;
        let data_offset = u64::from(offset_flags >> 12);
        if data_offset < 5 {
            return Err(ParseError::Malformed("data offset below 5"));
        }
        let window = r.u16_be()?;
        let checksum = r.u16_be()?;
        let urgent = r.u16_be()?;
        let header_len = (data_offset * 4) as usize;
        let options = r.take(header_len - 20)?;

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(SRC_PORT, Value::U64(u64::from(src_port)));
            fields.insert(DST_PORT, Value::U64(u64::from(dst_port)));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(FLAGS, Value::U64(u64::from(offset_flags & 0x01FF)));
            fields.insert(SEQ, Value::U64(u64::from(seq)));
            fields.insert(ACK, Value::U64(u64::from(ack)));
            fields.insert(WINDOW, Value::U64(u64::from(window)));
            fields.insert(DATA_OFFSET, Value::U64(data_offset));
        }
        if ctx.depth() >= Depth::Full {
            fields.insert(CHECKSUM, Value::U64(u64::from(checksum)));
            fields.insert(URGENT, Value::U64(u64::from(urgent)));
            if !options.is_empty() {
                fields.insert(OPTIONS, Value::from(options));
            }
        }

        let hint = if bytes.len() == header_len {
            Hint::Terminal
        } else {
            Hint::Candidates(SmallVec::from_slice(&[
                RouteId::TcpPort(dst_port),
                RouteId::TcpPort(src_port),
            ]))
        };
        Ok(ParsedLayer {
            header_len,
            fields,
            hint,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::IpProtocol(6)]
    }

    fn expected_predecessors(&self) -> &'static [ProtocolName] {
        &["ipv4", "ipv6"]
    }

    fn has_probe(&self) -> bool {
        true
    }

    /// Honest structural checks: header shape, zeroed reserved bits, a
    /// plausible flag combination, and no urgent pointer without URG.
    /// Random bytes essentially never pass all four (02.3).
    fn probe(&self, bytes: &[u8], _ctx: &ParseCtx) -> Option<Confidence> {
        if bytes.len() < 20 {
            return None;
        }
        let offset_flags = u16::from_be_bytes([*bytes.get(12)?, *bytes.get(13)?]);
        let data_offset = usize::from(offset_flags >> 12);
        if !(5..=15).contains(&data_offset) || data_offset * 4 > bytes.len() {
            return None;
        }
        if offset_flags & 0x0F00 != 0 {
            return None; // reserved/NS bits set
        }
        let f = u64::from(offset_flags & 0xFF);
        let (syn, rst, fin) = (f & SYN != 0, f & RST != 0, f & FIN != 0);
        if f == 0 || (syn && fin) || (syn && rst) || (fin && rst) {
            return None; // nonsensical combinations score nothing
        }
        let urgent = u16::from_be_bytes([*bytes.get(18)?, *bytes.get(19)?]);
        if urgent != 0 && f & 0x20 == 0 {
            return None; // urgent pointer without URG
        }
        Some(Confidence::new(60))
    }

    fn stream_identity(&self) -> Option<&StreamIdentity> {
        Some(&IDENTITY)
    }
}
