//! SCTP (11.6, RFC 9260 — obsoletes RFC 4960): the multi-homed,
//! multi-stream transport, given the same coarse association-lifecycle
//! treatment TCP gets (06.4) — bookkeeping, not a retransmission-correct
//! state machine (no reassembly, D7).
//!
//! ## Framing (RFC 9260 §3)
//! A packet is a 12-byte common header (`Source Port`, `Destination Port`,
//! `Verification Tag`, `Checksum`) followed by one or more *chunks*, each
//! `Type(1) + Flags(1) + Length(2, header-inclusive, padding-exclusive) +
//! Value` and padded to a 4-byte boundary on the wire (RFC 9260 §3.2). Per
//! D7 (no cross-packet reassembly) and this task's "first message only"
//! convention (matching `bgp`'s coalesced-message stance, 11.4, and
//! `dns`-over-TCP, 06.6) **only the first chunk is parsed**; `header_len`
//! is bounded by that chunk's own declared `Length`, so a packet bundling
//! further chunks stops cleanly at the first chunk's boundary rather than
//! walking (or even skipping over) the rest — the same honesty stance, not
//! a crash or a silent partial read.
//!
//! ## Checksum (RFC 9260 Appendix B)
//! The 32-bit checksum is CRC32c in RFC 9260 (it was Adler-32 under the
//! obsoleted RFC 2960/4960). This plugin consumes the field for
//! `header_len` correctness but does not verify it and does not surface
//! it — no Tier-1 field names it (11.6's field table), the same
//! consumed-not-verified stance `vrrp`/`igmp` take on their own checksums
//! (11.4/06.3).
//!
//! ## INIT / INIT-ACK (RFC 9260 §3.3.2, §3.3.3)
//! Both chunk types open with the same 16-byte fixed block — `Initiate
//! Tag`, `Advertised Receiver Window Credit (a_rwnd)`, `Number of
//! Outbound Streams`, `Number of Inbound Streams`, `Initial TSN` — before
//! their own variable parts (INIT's optional parameters; INIT-ACK's
//! mandatory State Cookie plus optional parameters). Only that shared
//! fixed block is Tier 1; the variable parts are not walked.
//!
//! ## Association lifecycle (RFC 9260 §4 initialization, §9 shutdown)
//! The four-way handshake (INIT / INIT-ACK / COOKIE-ECHO / COOKIE-ACK,
//! §4) and the three-way shutdown (SHUTDOWN / SHUTDOWN-ACK /
//! SHUTDOWN-COMPLETE, §9.2) are each collapsed to their *first* observed
//! trigger chunk, exactly as coarse as TCP's own handshake/teardown
//! bookkeeping (06.4) — this is association-shape tracking, not a
//! sequence-number- or retransmission-correct state machine. ABORT (§3.3.7)
//! ends the association from any state, mirroring TCP's RST handling.

use pktflow_core::{
    ByteReader, Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin,
    LifecycleSpec, PacketDirection, ParseCtx, ParseError, ParsedLayer, ProtocolName, RollupKind,
    RollupSpec, RouteId, StateName, StreamIdentity, Value,
};

const SRC_PORT: FieldName = "src_port";
const DST_PORT: FieldName = "dst_port";
const VERIFICATION_TAG: FieldName = "verification_tag";
const FIRST_CHUNK_TYPE: FieldName = "first_chunk_type";
const INITIATE_TAG: FieldName = "initiate_tag";
const A_RWND: FieldName = "a_rwnd";
const NUM_OUTBOUND_STREAMS: FieldName = "num_outbound_streams";
const NUM_INBOUND_STREAMS: FieldName = "num_inbound_streams";
const INITIAL_TSN: FieldName = "initial_tsn";

/// RFC 9260 §3.1: Source Port(2) + Destination Port(2) + Verification
/// Tag(4) + Checksum(4).
const COMMON_HEADER_LEN: usize = 12;
/// RFC 9260 §3.2: Chunk Type(1) + Chunk Flags(1) + Chunk Length(2).
const CHUNK_HEADER_LEN: usize = 4;
/// RFC 9260 §3.3.2/§3.3.3: Initiate Tag(4) + a_rwnd(4) + OS(2) + MIS(2) +
/// Initial TSN(4), the block INIT and INIT-ACK share before diverging.
const INIT_FIXED_LEN: usize = 16;

/// RFC 9260 §3.2 chunk type codes (IANA "Chunk Types" registry).
const TYPE_INIT: u8 = 1;
const TYPE_INIT_ACK: u8 = 2;
const TYPE_ABORT: u8 = 6;
const TYPE_SHUTDOWN: u8 = 7;
const TYPE_SHUTDOWN_ACK: u8 = 8;
const TYPE_COOKIE_ECHO: u8 = 10;
const TYPE_COOKIE_ACK: u8 = 11;
const TYPE_SHUTDOWN_COMPLETE: u8 = 14;

/// The 11.6 lifecycle diagram, collapsed the same way TCP's is (06.4):
/// unrecognized input keeps the current state (pure and total, 05.5).
/// ABORT (§3.3.7) ends the association from any state, checked first.
fn advance(fields: &FieldMap, state: StateName, _dir: PacketDirection) -> StateName {
    let Some(Value::U64(chunk_type)) = fields.get(FIRST_CHUNK_TYPE) else {
        return state;
    };
    let chunk_type = u8::try_from(*chunk_type).unwrap_or(u8::MAX);
    if chunk_type == TYPE_ABORT {
        return "aborted"; // any --ABORT--> aborted
    }
    match state {
        "new" if chunk_type == TYPE_INIT => "init_sent",
        // Capture began mid-session: any non-INIT first chunk.
        "new" => "established_midstream",
        "init_sent" if chunk_type == TYPE_INIT_ACK => "cookie_wait",
        "cookie_wait" if chunk_type == TYPE_COOKIE_ECHO => "cookie_echoed",
        "cookie_echoed" if chunk_type == TYPE_COOKIE_ACK => "established",
        "established" | "established_midstream" if chunk_type == TYPE_SHUTDOWN => {
            "shutdown_pending"
        }
        // The shutdown handshake's second or third leg both mean "done"
        // at this coarseness (§9.2) — same simplification TCP's
        // `closing` -> `closed` single-packet-per-side collapse takes.
        "shutdown_pending"
            if chunk_type == TYPE_SHUTDOWN_ACK || chunk_type == TYPE_SHUTDOWN_COMPLETE =>
        {
            "closed"
        }
        _ => state,
    }
}

static KEY: &[KeyField] = &[KeyField {
    a: SRC_PORT,
    b: Some(DST_PORT),
}];
static ROLLUPS: &[RollupSpec] = &[RollupSpec {
    field: FIRST_CHUNK_TYPE,
    kind: RollupKind::Accumulate,
}];
static IDENTITY: StreamIdentity = StreamIdentity {
    // Ports only, same D10 stance as tcp/udp: the IP-pair parent supplies
    // the addresses, this key is the (parent, port-pair) tree path.
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: Some(LifecycleSpec {
        initial: "new",
        advance,
        closed_states: &["closed", "aborted"],
    }),
    rollups: ROLLUPS,
};

pub struct Sctp;

impl LayerPlugin for Sctp {
    fn name(&self) -> ProtocolName {
        "sctp"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let src_port = r.u16_be()?;
        let dst_port = r.u16_be()?;
        let verification_tag = r.u32_be()?;
        let _checksum = r.u32_be()?; // CRC32c (Appendix B); framing only.

        let chunk_type = r.u8()?;
        let _chunk_flags = r.u8()?;
        let chunk_length = r.u16_be()?;
        if usize::from(chunk_length) < CHUNK_HEADER_LEN {
            return Err(ParseError::Malformed(
                "chunk length below the 4-byte chunk header",
            ));
        }
        let value_len = usize::from(chunk_length) - CHUNK_HEADER_LEN;
        let value = r.take(value_len)?;

        // INIT and INIT-ACK share a 16-byte fixed block (§3.3.2/§3.3.3);
        // this bound is a protocol-structure check, independent of depth
        // (rule 2), so it runs even when the fields it guards won't be
        // extracted at this depth.
        let is_init_family = chunk_type == TYPE_INIT || chunk_type == TYPE_INIT_ACK;
        let init_fixed = if is_init_family {
            if value.len() < INIT_FIXED_LEN {
                return Err(ParseError::Malformed(
                    "INIT/INIT-ACK chunk shorter than its fixed fields",
                ));
            }
            let mut vr = ByteReader::new(value);
            Some((
                vr.u32_be()?,
                vr.u32_be()?,
                vr.u16_be()?,
                vr.u16_be()?,
                vr.u32_be()?,
            ))
        } else {
            None
        };

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(SRC_PORT, Value::U64(u64::from(src_port)));
            fields.insert(DST_PORT, Value::U64(u64::from(dst_port)));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(VERIFICATION_TAG, Value::U64(u64::from(verification_tag)));
            fields.insert(FIRST_CHUNK_TYPE, Value::U64(u64::from(chunk_type)));
        }
        if ctx.depth() >= Depth::Full {
            if let Some((initiate_tag, a_rwnd, num_outbound, num_inbound, initial_tsn)) = init_fixed
            {
                fields.insert(INITIATE_TAG, Value::U64(u64::from(initiate_tag)));
                fields.insert(A_RWND, Value::U64(u64::from(a_rwnd)));
                fields.insert(NUM_OUTBOUND_STREAMS, Value::U64(u64::from(num_outbound)));
                fields.insert(NUM_INBOUND_STREAMS, Value::U64(u64::from(num_inbound)));
                fields.insert(INITIAL_TSN, Value::U64(u64::from(initial_tsn)));
            }
        }

        Ok(ParsedLayer {
            header_len: COMMON_HEADER_LEN + usize::from(chunk_length),
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::IpProtocol(132)]
    }

    fn expected_predecessors(&self) -> &'static [ProtocolName] {
        &["ipv4", "ipv6"]
    }

    // No probe (11.6): an 8-byte-ish common header with a plausible
    // verification tag is not distinguishable enough to guess safely,
    // the same stance `udp` takes (06.4) — explicit `IpProtocol(132)`
    // routing only.

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

    fn parse(bytes: &[u8], depth: Depth) -> Result<ParsedLayer, ParseError> {
        let m = meta(bytes.len());
        Sctp.parse(bytes, &ParseCtx::new(&[], depth, &m))
    }

    fn common_header(src: u16, dst: u16, tag: u32) -> Vec<u8> {
        let mut h = Vec::with_capacity(COMMON_HEADER_LEN);
        h.extend_from_slice(&src.to_be_bytes());
        h.extend_from_slice(&dst.to_be_bytes());
        h.extend_from_slice(&tag.to_be_bytes());
        h.extend_from_slice(&0u32.to_be_bytes()); // checksum, not verified
        h
    }

    /// RFC 9260 §3.3.2: bare INIT, no optional parameters.
    fn init_chunk() -> Vec<u8> {
        let mut c = vec![TYPE_INIT, 0x00, 0x00, 0x14]; // type, flags, length=20
        c.extend_from_slice(&0xAABB_CCDDu32.to_be_bytes()); // initiate tag
        c.extend_from_slice(&0x0001_0000u32.to_be_bytes()); // a_rwnd = 65536
        c.extend_from_slice(&10u16.to_be_bytes()); // outbound streams
        c.extend_from_slice(&5u16.to_be_bytes()); // inbound streams
        c.extend_from_slice(&0x1234_5678u32.to_be_bytes()); // initial tsn
        c
    }

    /// RFC 9260 §3.3.8: SHUTDOWN, 4-byte Cumulative TSN Ack value.
    fn shutdown_chunk() -> Vec<u8> {
        let mut c = vec![TYPE_SHUTDOWN, 0x00, 0x00, 0x08]; // length=8
        c.extend_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
        c
    }

    #[test]
    fn init_chunk_parses_fixed_fields() {
        let mut bytes = common_header(34567, 3868, 0x1122_3344);
        bytes.extend_from_slice(&init_chunk());
        let parsed = parse(&bytes, Depth::Full).expect("valid INIT packet");
        assert_eq!(parsed.header_len, COMMON_HEADER_LEN + 20);
        assert_eq!(parsed.fields.get(SRC_PORT), Some(&Value::U64(34567)));
        assert_eq!(parsed.fields.get(DST_PORT), Some(&Value::U64(3868)));
        assert_eq!(
            parsed.fields.get(VERIFICATION_TAG),
            Some(&Value::U64(0x1122_3344))
        );
        assert_eq!(parsed.fields.get(FIRST_CHUNK_TYPE), Some(&Value::U64(1)));
        assert_eq!(
            parsed.fields.get(INITIATE_TAG),
            Some(&Value::U64(0xAABB_CCDD))
        );
        assert_eq!(parsed.fields.get(A_RWND), Some(&Value::U64(65536)));
        assert_eq!(
            parsed.fields.get(NUM_OUTBOUND_STREAMS),
            Some(&Value::U64(10))
        );
        assert_eq!(parsed.fields.get(NUM_INBOUND_STREAMS), Some(&Value::U64(5)));
        assert_eq!(
            parsed.fields.get(INITIAL_TSN),
            Some(&Value::U64(0x1234_5678))
        );
        assert_eq!(parsed.hint, Hint::Terminal);
    }

    #[test]
    fn non_init_chunk_exposes_only_the_common_fields() {
        let mut bytes = common_header(3868, 34567, 0x9988_7766);
        bytes.extend_from_slice(&shutdown_chunk());
        let parsed = parse(&bytes, Depth::Full).expect("valid SHUTDOWN packet");
        assert_eq!(parsed.header_len, COMMON_HEADER_LEN + 8);
        assert_eq!(parsed.fields.get(FIRST_CHUNK_TYPE), Some(&Value::U64(7)));
        assert_eq!(parsed.fields.get(INITIATE_TAG), None);
        assert_eq!(parsed.fields.get(A_RWND), None);
    }

    #[test]
    fn truncated_header_declines() {
        let mut bytes = common_header(1, 2, 0);
        bytes.extend_from_slice(&init_chunk());
        assert!(parse(&bytes[..bytes.len() - 1], Depth::Full).is_err());
        assert!(parse(&bytes[..COMMON_HEADER_LEN], Depth::Full).is_err());
    }

    /// A too-short chunk length is a structural violation, not merely a
    /// short capture, and must decline the same way at every depth (rule
    /// 2's depth-independent validity — no field-extraction shortcut
    /// hides a malformed INIT).
    #[test]
    fn init_chunk_shorter_than_fixed_fields_declines_at_every_depth() {
        let mut bytes = common_header(1, 2, 0);
        // Declares only 8 value bytes: not enough for the 16-byte fixed
        // block INIT requires.
        bytes.extend_from_slice(&[TYPE_INIT, 0x00, 0x00, 0x0C]);
        bytes.extend_from_slice(&[0u8; 8]);
        for depth in [Depth::None, Depth::Keys, Depth::Structural, Depth::Full] {
            assert!(parse(&bytes, depth).is_err(), "depth {depth:?}");
        }
    }

    /// D7 / 11.6: a packet bundling a second chunk stops at the first
    /// chunk's own declared boundary — the second chunk is never walked,
    /// the same "first message only" stance `bgp` takes on a coalesced
    /// TCP segment (11.4).
    #[test]
    fn a_bundled_second_chunk_is_left_untouched() {
        let mut bytes = common_header(34567, 3868, 0x1122_3344);
        bytes.extend_from_slice(&init_chunk());
        let first_chunk_end = bytes.len();
        bytes.extend_from_slice(&shutdown_chunk());

        let parsed = parse(&bytes, Depth::Full).expect("first chunk (INIT) parses");
        assert_eq!(parsed.header_len, first_chunk_end);
        assert_eq!(parsed.fields.get(FIRST_CHUNK_TYPE), Some(&Value::U64(1)));
        assert_eq!(parsed.hint, Hint::Terminal);
    }

    #[test]
    fn depth_none_omits_every_field() {
        let mut bytes = common_header(34567, 3868, 0x1122_3344);
        bytes.extend_from_slice(&init_chunk());
        let parsed = parse(&bytes, Depth::None).expect("valid packet");
        assert!(parsed.fields.get(SRC_PORT).is_none());
        assert!(parsed.fields.get(FIRST_CHUNK_TYPE).is_none());
    }
}
