//! SCTP (11.6, RFC 9260, obsoletes RFC 4960): multi-homed, multi-stream
//! **association** bookkeeping over IP protocol 132 — the same
//! "session-shaped" precedent TCP (06.4) already sets, ported to SCTP's own
//! four-way handshake (INIT / INIT ACK / COOKIE ECHO / COOKIE ACK, RFC 9260
//! §5.1) instead of TCP's three-way one.
//!
//! Per D7 (no cross-packet reassembly) and the same stance BGP/DNS-over-TCP
//! take in this task and 06.6: an SCTP packet may bundle several chunks
//! back-to-back (RFC 9260 §3.2), but only the **first** chunk is parsed.
//! `header_len` is bounded by that chunk's own `Length` field (not
//! `bytes.len()` and not rounded up to the 4-byte padding boundary RFC 9260
//! §3.2 describes for a chunk that isn't last) — the same "own length field,
//! not the wire's" honesty BGP's module doc already states, chosen because
//! this plugin never looks past the first chunk to need the padding anyway.
//!
//! The Checksum (RFC 9260 §3.1, CRC32c over the whole packet) is consumed
//! for framing correctness but neither verified nor surfaced — the same
//! "consumed, not re-derived" stance `vrrp`/`igmp` already take on their own
//! checksums (11.4/06.3): a passive dissector has no session state to
//! re-run CRC32c against, and getting it wrong would be worse than not
//! reporting it.
//!
//! Only INIT (type 1) and INIT ACK (type 2) carry Tier-1 fields beyond the
//! common header + first-chunk-type (RFC 9260 §3.3.2/§3.3.3's shared fixed
//! parameters: Initiate Tag, `a_rwnd`, Number of Outbound/Inbound Streams,
//! Initial TSN); every other chunk type still gets its `header_len` bounded
//! correctly by the common Type/Flags/Length triplet but exposes nothing
//! further — the same stance `bgp`/`ospf` take on their own
//! not-Tier-1 message types (11.4).
//!
//! No `probe()` (like UDP, 06.4): SCTP's ~12-byte common header is a
//! plausible-looking port pair plus a verification tag with no structural
//! invariant a passive observer can lean on, so this plugin claims
//! `IpProtocol(132)` explicitly and nothing else.

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
/// RFC 9260 §3.2: Chunk Type(1) + Chunk Flags(1) + Chunk Length(2), before
/// the (possibly zero-length) Chunk Value.
const CHUNK_HEADER_LEN: usize = 4;

/// RFC 9260 §3.2 (IANA "SCTP Chunk Types" registry): the subset this
/// plugin's lifecycle and Tier-1 field extraction care about.
const CHUNK_INIT: u8 = 1;
const CHUNK_INIT_ACK: u8 = 2;
const CHUNK_ABORT: u8 = 6;
const CHUNK_SHUTDOWN: u8 = 7;
const CHUNK_SHUTDOWN_ACK: u8 = 8;
const CHUNK_COOKIE_ECHO: u8 = 10;
const CHUNK_COOKIE_ACK: u8 = 11;
const CHUNK_SHUTDOWN_COMPLETE: u8 = 14;

/// The 11.6 association lifecycle (RFC 9260 §5.1's INIT/INIT-ACK/
/// COOKIE-ECHO/COOKIE-ACK handshake plus RFC 9260 §9's shutdown sequence),
/// as coarse as TCP's (06.4) — association bookkeeping from the chunk type
/// seen, not a retransmission- or verification-tag-correct state machine.
/// Unrecognized input keeps the current state (pure and total, 05.5).
fn advance(fields: &FieldMap, state: StateName, _dir: PacketDirection) -> StateName {
    let Some(Value::U64(chunk_type)) = fields.get(FIRST_CHUNK_TYPE) else {
        return state;
    };
    let ct = *chunk_type;
    if ct == u64::from(CHUNK_ABORT) {
        return "aborted"; // any --ABORT--> aborted
    }
    match state {
        "new" if ct == u64::from(CHUNK_INIT) => "init_sent",
        // Capture began mid-association: any non-INIT (e.g. DATA) first chunk.
        "new" => "established_midstream",
        "init_sent" if ct == u64::from(CHUNK_INIT_ACK) => "cookie_wait",
        "cookie_wait" if ct == u64::from(CHUNK_COOKIE_ECHO) => "cookie_echoed",
        "cookie_echoed" if ct == u64::from(CHUNK_COOKIE_ACK) => "established",
        "established" | "established_midstream" if ct == u64::from(CHUNK_SHUTDOWN) => {
            "shutdown_pending"
        }
        // Either half of the SHUTDOWN-ACK/SHUTDOWN-COMPLETE tail closes it
        // (deliberately coarse, same stance as the rest of this lifecycle).
        "shutdown_pending"
            if ct == u64::from(CHUNK_SHUTDOWN_ACK) || ct == u64::from(CHUNK_SHUTDOWN_COMPLETE) =>
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
    // Ports only, same tree-path reasoning as `tcp` (D10, 02.4): the
    // association is the (IP-pair parent, port-pair) path.
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
        let _checksum = r.u32_be()?;

        let chunk_type = r.u8()?;
        let _chunk_flags = r.u8()?;
        let chunk_length = usize::from(r.u16_be()?);
        let value_len = chunk_length
            .checked_sub(CHUNK_HEADER_LEN)
            .ok_or(ParseError::Malformed(
                "SCTP: chunk length below the 4-byte chunk header",
            ))?;
        let value = r.take(value_len)?;

        let mut initiate_tag = None;
        let mut a_rwnd = None;
        let mut num_outbound_streams = None;
        let mut num_inbound_streams = None;
        let mut initial_tsn = None;
        if matches!(chunk_type, CHUNK_INIT | CHUNK_INIT_ACK) {
            // RFC 9260 §3.3.2/§3.3.3: both INIT and INIT ACK share this
            // 16-byte fixed-parameters shape before their variable ones.
            let mut vr = ByteReader::new(value);
            initiate_tag = Some(u64::from(vr.u32_be()?));
            a_rwnd = Some(u64::from(vr.u32_be()?));
            num_outbound_streams = Some(u64::from(vr.u16_be()?));
            num_inbound_streams = Some(u64::from(vr.u16_be()?));
            initial_tsn = Some(u64::from(vr.u32_be()?));
        }

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
            if let Some(v) = initiate_tag {
                fields.insert(INITIATE_TAG, Value::U64(v));
            }
            if let Some(v) = a_rwnd {
                fields.insert(A_RWND, Value::U64(v));
            }
            if let Some(v) = num_outbound_streams {
                fields.insert(NUM_OUTBOUND_STREAMS, Value::U64(v));
            }
            if let Some(v) = num_inbound_streams {
                fields.insert(NUM_INBOUND_STREAMS, Value::U64(v));
            }
            if let Some(v) = initial_tsn {
                fields.insert(INITIAL_TSN, Value::U64(v));
            }
        }

        Ok(ParsedLayer {
            header_len: COMMON_HEADER_LEN + chunk_length,
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

    fn stream_identity(&self) -> Option<&StreamIdentity> {
        Some(&IDENTITY)
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use pktflow_core::{LayerRecord, LinkType, PacketMeta};

    use super::*;

    fn meta(len: usize) -> PacketMeta {
        PacketMeta {
            timestamp: SystemTime::UNIX_EPOCH,
            caplen: len,
            origlen: len,
            link_type: LinkType::ETHERNET,
        }
    }

    fn ctx<'a>(outer: &'a [LayerRecord], depth: Depth, m: &'a PacketMeta) -> ParseCtx<'a> {
        ParseCtx::new(outer, depth, m)
    }

    fn ip_predecessor() -> Vec<LayerRecord> {
        vec![LayerRecord {
            protocol: "ipv4",
            offset: 14,
            header_len: 20,
            fields: FieldMap::new(),
        }]
    }

    /// RFC 9260 §3.1 common header, followed by one chunk's own
    /// Type/Flags/Length/Value.
    fn packet(verification_tag: u32, chunk_type: u8, chunk_flags: u8, value: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&34567u16.to_be_bytes());
        b.extend_from_slice(&3868u16.to_be_bytes()); // Diameter-over-SCTP's registered port
        b.extend_from_slice(&verification_tag.to_be_bytes());
        b.extend_from_slice(&0u32.to_be_bytes()); // checksum, unverified
        b.push(chunk_type);
        b.push(chunk_flags);
        let length = (CHUNK_HEADER_LEN + value.len()) as u16;
        b.extend_from_slice(&length.to_be_bytes());
        b.extend_from_slice(value);
        b
    }

    /// RFC 9260 §3.3.2/§3.3.3: Initiate Tag + a_rwnd + OS + MIS + Initial TSN.
    fn init_fixed_params() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&0xCAFEBABEu32.to_be_bytes()); // Initiate Tag
        v.extend_from_slice(&65536u32.to_be_bytes()); // a_rwnd
        v.extend_from_slice(&10u16.to_be_bytes()); // Outbound Streams
        v.extend_from_slice(&10u16.to_be_bytes()); // Inbound Streams
        v.extend_from_slice(&42u32.to_be_bytes()); // Initial TSN
        v
    }

    #[test]
    fn init_chunk_parses_fixed_parameters() {
        let bytes = packet(0, CHUNK_INIT, 0, &init_fixed_params());
        let m = meta(bytes.len());
        let outer = ip_predecessor();
        let parsed = Sctp
            .parse(&bytes, &ctx(&outer, Depth::Full, &m))
            .expect("valid INIT");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(SRC_PORT), Some(&Value::U64(34567)));
        assert_eq!(parsed.fields.get(DST_PORT), Some(&Value::U64(3868)));
        assert_eq!(
            parsed.fields.get(FIRST_CHUNK_TYPE),
            Some(&Value::U64(u64::from(CHUNK_INIT)))
        );
        assert_eq!(
            parsed.fields.get(INITIATE_TAG),
            Some(&Value::U64(0xCAFE_BABE))
        );
        assert_eq!(parsed.fields.get(A_RWND), Some(&Value::U64(65536)));
        assert_eq!(
            parsed.fields.get(NUM_OUTBOUND_STREAMS),
            Some(&Value::U64(10))
        );
        assert_eq!(
            parsed.fields.get(NUM_INBOUND_STREAMS),
            Some(&Value::U64(10))
        );
        assert_eq!(parsed.fields.get(INITIAL_TSN), Some(&Value::U64(42)));
    }

    #[test]
    fn init_ack_chunk_parses_fixed_parameters() {
        let bytes = packet(0x1234_5678, CHUNK_INIT_ACK, 0, &init_fixed_params());
        let m = meta(bytes.len());
        let outer = ip_predecessor();
        let parsed = Sctp
            .parse(&bytes, &ctx(&outer, Depth::Full, &m))
            .expect("valid INIT ACK");
        assert_eq!(
            parsed.fields.get(VERIFICATION_TAG),
            Some(&Value::U64(0x1234_5678))
        );
        assert_eq!(
            parsed.fields.get(INITIATE_TAG),
            Some(&Value::U64(0xCAFE_BABE))
        );
    }

    #[test]
    fn cookie_ack_has_no_init_fields() {
        let bytes = packet(0x1111_1111, CHUNK_COOKIE_ACK, 0, &[]);
        let m = meta(bytes.len());
        let outer = ip_predecessor();
        let parsed = Sctp
            .parse(&bytes, &ctx(&outer, Depth::Full, &m))
            .expect("valid COOKIE ACK");
        assert_eq!(parsed.header_len, COMMON_HEADER_LEN + CHUNK_HEADER_LEN);
        assert_eq!(
            parsed.fields.get(FIRST_CHUNK_TYPE),
            Some(&Value::U64(u64::from(CHUNK_COOKIE_ACK)))
        );
        assert_eq!(parsed.fields.get(INITIATE_TAG), None);
    }

    #[test]
    fn a_second_bundled_chunk_is_left_untouched() {
        let mut bytes = packet(0, CHUNK_COOKIE_ACK, 0, &[]);
        bytes.extend_from_slice(&packet(0, CHUNK_SHUTDOWN, 0, &4u32.to_be_bytes()));
        let m = meta(bytes.len());
        let outer = ip_predecessor();
        let parsed = Sctp
            .parse(&bytes, &ctx(&outer, Depth::Full, &m))
            .expect("first chunk parses");
        assert_eq!(parsed.header_len, COMMON_HEADER_LEN + CHUNK_HEADER_LEN);
        assert_eq!(parsed.hint, Hint::Terminal);
    }

    #[test]
    fn keys_depth_has_only_ports() {
        let bytes = packet(0, CHUNK_INIT, 0, &init_fixed_params());
        let m = meta(bytes.len());
        let outer = ip_predecessor();
        let parsed = Sctp
            .parse(&bytes, &ctx(&outer, Depth::Keys, &m))
            .expect("valid INIT");
        assert_eq!(parsed.fields.len(), 2);
        assert_eq!(parsed.fields.get(SRC_PORT), Some(&Value::U64(34567)));
    }

    #[test]
    fn structural_depth_omits_init_fixed_parameters() {
        let bytes = packet(0, CHUNK_INIT, 0, &init_fixed_params());
        let m = meta(bytes.len());
        let outer = ip_predecessor();
        let parsed = Sctp
            .parse(&bytes, &ctx(&outer, Depth::Structural, &m))
            .expect("valid INIT");
        assert_eq!(
            parsed.fields.get(FIRST_CHUNK_TYPE),
            Some(&Value::U64(u64::from(CHUNK_INIT)))
        );
        assert_eq!(parsed.fields.get(INITIATE_TAG), None);
    }

    #[test]
    fn chunk_length_below_chunk_header_declines() {
        let mut bytes = packet(0, CHUNK_COOKIE_ACK, 0, &[]);
        bytes[14] = 0;
        bytes[15] = 2; // Chunk Length = 2, below the 4-byte chunk header floor
        let m = meta(bytes.len());
        let outer = ip_predecessor();
        assert!(Sctp.parse(&bytes, &ctx(&outer, Depth::Full, &m)).is_err());
    }

    #[test]
    fn truncated_init_frames_decline() {
        let bytes = packet(0, CHUNK_INIT, 0, &init_fixed_params());
        let m = meta(bytes.len());
        let outer = ip_predecessor();
        for n in 0..bytes.len() {
            let full_ctx = ctx(&outer, Depth::Full, &m);
            assert!(
                Sctp.parse(&bytes[..n], &full_ctx).is_err(),
                "prefix of {n}/{} bytes must decline",
                bytes.len()
            );
        }
    }

    #[test]
    fn truncated_cookie_ack_frames_decline() {
        let bytes = packet(0, CHUNK_COOKIE_ACK, 0, &[]);
        let m = meta(bytes.len());
        let outer = ip_predecessor();
        for n in 0..bytes.len() {
            let full_ctx = ctx(&outer, Depth::Full, &m);
            assert!(
                Sctp.parse(&bytes[..n], &full_ctx).is_err(),
                "prefix of {n}/{} bytes must decline",
                bytes.len()
            );
        }
    }

    #[test]
    fn data_chunk_declines_init_fixed_parameters() {
        // A DATA chunk (type 0) with an arbitrary 4-byte payload: no Tier-1
        // fields beyond the common ones, but header_len must still be exact.
        let bytes = packet(0, 0, 0, &[0xDE, 0xAD, 0xBE, 0xEF]);
        let m = meta(bytes.len());
        let outer = ip_predecessor();
        let parsed = Sctp
            .parse(&bytes, &ctx(&outer, Depth::Full, &m))
            .expect("valid DATA chunk framing");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.fields.get(INITIATE_TAG), None);
    }
}
