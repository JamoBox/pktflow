//! QUIC (11.6, RFC 8999 invariants; RFC 9000/9001 for context only) — this
//! plugin never implements QUIC's transport or crypto, purely the
//! invariant-level framing D12 permits: the handful of fields RFC 8999
//! guarantees are readable *without* removing QUIC's mandatory header
//! protection (RFC 9001 §5.4), which sits in front of everything else in a
//! Long Header packet and in front of the entirety of a Short Header one.
//!
//! ## Header Form (RFC 8999 §5)
//! Byte 0's top bit selects Long Header (`1`) or Short Header (`0`); bit
//! `0x40` is the Fixed Bit, expected `1` on real traffic (RFC 8999 §5.3
//! reserves the `0` value; Version Negotiation packets, out of Tier-1
//! scope, are the one place it may be anything).
//!
//! ## Long Header (RFC 8999 §5.1)
//! `Header Form(1 bit) | version-specific(7 bits) | Version(32) |
//! DCID Length(8) | DCID(0..255) | SCID Length(8) | SCID(0..255) |
//! version-specific data`. The two connection-ID length octets and their
//! payloads are the only invariant fields past the version; `header_len`
//! covers exactly this run — never the version-specific data behind it,
//! which sits behind header protection (RFC 9001 §5.4) this plugin does not
//! remove. `packet_type` (Initial/0-RTT/Handshake/Retry) is derived from
//! the Long Packet Type bits (byte 0, bits `0x30`) **and** `version`, since
//! QUICv2 (RFC 9369 §3.2) deliberately permutes the same four values to a
//! different bit pattern than QUICv1 (RFC 9000 §17.2) — recognized for
//! those two versions only; an unrecognized version still yields
//! `dcid`/`scid` (invariant, version-independent) but no `packet_type`.
//!
//! ## Short Header (RFC 8999 §5.2)
//! `Header Form(1 bit) | version-specific(7 bits) | Destination Connection
//! ID(..) | version-specific data`. The DCID has no self-describing length
//! here (only the endpoint that chose it knows how long it is) — RFC 8999
//! itself: "the length of the Destination Connection ID field... is not
//! provided by the invariants." So this plugin reads only byte 0 and stops:
//! `header_len == 1`, no fields beyond `header_form`/`fixed_bit`, matching
//! 11.8's stated ceiling exactly.
//!
//! ## Identity and reachability (D15-adjacent claim-honesty, 11.6)
//! Long-header packets key on `dcid` (a shared, non-endpoint qualifier —
//! the GRE/VXLAN/TEID shape, 06.5/11.15): one stream per destination
//! connection id observed. A connection migrating to a new DCID mid-session
//! (RFC 9000 §5.1.1) is observed as a new sibling stream, not folded into
//! the pre-migration one — a documented v1 limitation, not a crash or a
//! silent merge. Short-header packets carry no invariant DCID at all, so
//! they never reach `stream_identity`'s key extraction in the first place;
//! callers must not feed a short-header sample through anything that
//! demands the `dcid` flow-key field (this module's own tests don't).

use pktflow_core::{
    ByteReader, Canonicalize, Confidence, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin,
    ParseCtx, ParseError, ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId,
    StreamIdentity, Value,
};

const HEADER_FORM: FieldName = "header_form";
const FIXED_BIT: FieldName = "fixed_bit";
const VERSION: FieldName = "version";
const DCID: FieldName = "dcid";
const SCID: FieldName = "scid";
const PACKET_TYPE: FieldName = "packet_type";

/// RFC 9000 (QUIC version 1).
const VERSION_1: u32 = 0x0000_0001;
/// RFC 9369 §3 (QUIC version 2).
const VERSION_2: u32 = 0x6b33_43cf;
/// RFC 8999 §5.2.1 / RFC 9000 §17.2.1: the reserved value that identifies a
/// Version Negotiation packet.
const VERSION_NEGOTIATION: u32 = 0x0000_0000;

const HEADER_FORM_BIT: u8 = 0x80;
const FIXED_BIT_MASK: u8 = 0x40;
/// RFC 9000 §17.2: Long Packet Type occupies bits `0x30` of byte 0.
const LONG_TYPE_MASK: u8 = 0x30;
const LONG_TYPE_SHIFT: u32 = 4;

/// RFC 9000 §17.2's Long Packet Type -> name mapping (QUICv1).
fn packet_type_v1(bits: u8) -> &'static str {
    match bits {
        0 => "initial",
        1 => "0-rtt",
        2 => "handshake",
        _ => "retry",
    }
}

/// RFC 9369 §3.2's deliberately permuted mapping (QUICv2): the same four
/// meanings, different bit pattern than v1.
fn packet_type_v2(bits: u8) -> &'static str {
    match bits {
        0b01 => "initial",
        0b10 => "0-rtt",
        0b11 => "handshake",
        _ => "retry",
    }
}

/// RFC 9000 §15's reserved-for-negotiation-testing pattern: every nibble's
/// low bits fixed at `1010` — `0x?a?a?a?a`.
fn is_reserved_negotiation_pattern(version: u32) -> bool {
    version & 0x0F0F_0F0F == 0x0A0A_0A0A
}

fn is_recognized_version(version: u32) -> bool {
    matches!(version, VERSION_1 | VERSION_2 | VERSION_NEGOTIATION)
}

static KEY: &[KeyField] = &[KeyField {
    a: DCID,
    b: None, // shared (non-endpoint) qualifier: one stream per DCID observed
}];
static ROLLUPS: &[RollupSpec] = &[RollupSpec {
    field: PACKET_TYPE,
    kind: RollupKind::Accumulate,
}];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: ROLLUPS,
};

pub struct Quic;

impl LayerPlugin for Quic {
    fn name(&self) -> ProtocolName {
        "quic"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let byte0 = r.u8()?;
        let is_long = byte0 & HEADER_FORM_BIT != 0;
        let fixed_bit = byte0 & FIXED_BIT_MASK != 0;

        let mut fields = FieldMap::new();

        if !is_long {
            // Short Header (RFC 8999 §5.2): no invariant field beyond byte
            // 0 itself — the DCID has no self-describing length here.
            if ctx.depth() >= Depth::Structural {
                fields.insert(HEADER_FORM, Value::Bool(false));
                fields.insert(FIXED_BIT, Value::Bool(fixed_bit));
            }
            return Ok(ParsedLayer {
                header_len: 1,
                fields,
                hint: Hint::Terminal,
            });
        }

        let version = r.u32_be()?;
        let dcid_len = r.u8()?;
        let dcid = r.take(usize::from(dcid_len))?;
        let scid_len = r.u8()?;
        let scid = r.take(usize::from(scid_len))?;
        let header_len = 1 + 4 + 1 + usize::from(dcid_len) + 1 + usize::from(scid_len);

        let packet_type = match version {
            VERSION_1 => Some(packet_type_v1((byte0 & LONG_TYPE_MASK) >> LONG_TYPE_SHIFT)),
            VERSION_2 => Some(packet_type_v2((byte0 & LONG_TYPE_MASK) >> LONG_TYPE_SHIFT)),
            _ => None,
        };

        if ctx.depth() >= Depth::Keys {
            fields.insert(DCID, Value::from(dcid));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(HEADER_FORM, Value::Bool(true));
            fields.insert(FIXED_BIT, Value::Bool(fixed_bit));
        }
        if ctx.depth() >= Depth::Full {
            fields.insert(VERSION, Value::U64(u64::from(version)));
            fields.insert(SCID, Value::from(scid));
            if let Some(pt) = packet_type {
                fields.insert(PACKET_TYPE, Value::from(pt));
            }
        }

        Ok(ParsedLayer {
            header_len,
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        // Shared, contested space (11.6/D14's claim-honesty note, the
        // wireguard/stun precedent): the static claim covers the common
        // case, `probe()` covers the rest.
        &[RouteId::UdpPort(443)]
    }

    fn has_probe(&self) -> bool {
        true
    }

    fn probe(&self, bytes: &[u8], _ctx: &ParseCtx) -> Option<Confidence> {
        let mut r = ByteReader::new(bytes);
        let byte0 = r.u8().ok()?;
        let is_long = byte0 & HEADER_FORM_BIT != 0;
        let fixed_bit = byte0 & FIXED_BIT_MASK != 0;
        if !is_long || !fixed_bit {
            return None;
        }
        let version = r.u32_be().ok()?;
        // 11.6's domain spec calls this "40, deliberately modest" — but a
        // probe below `MIN_CONFIDENCE` (50, 03.3) is discarded by the
        // router outright and can never win a fallback-pool route (the
        // same "dead weight" note 11.8's `tls` spec entry states
        // explicitly). The domain spec's own acceptance criterion requires
        // a genuine QUIC Initial packet on a non-standard port to actually
        // be admitted via the fallback pool, which only holds at the
        // floor — corrected here the same way `gtp_u` corrects a domain
        // spec transcription slip (11.15) rather than reproducing it.
        (is_recognized_version(version) || is_reserved_negotiation_pattern(version))
            .then(|| Confidence::new(50))
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

    fn ctx(depth: Depth, meta: &PacketMeta) -> ParseCtx<'_> {
        ParseCtx::new(&[], depth, meta)
    }

    /// A Long Header packet: `type_bits` occupy byte0's `0x30`, DCID/SCID
    /// as given, then arbitrary version-specific trailing bytes.
    fn long_header(
        version: u32,
        type_bits: u8,
        dcid: &[u8],
        scid: &[u8],
        trailer: &[u8],
    ) -> Vec<u8> {
        let byte0 =
            HEADER_FORM_BIT | FIXED_BIT_MASK | ((type_bits << LONG_TYPE_SHIFT) & LONG_TYPE_MASK);
        let mut b = vec![byte0];
        b.extend_from_slice(&version.to_be_bytes());
        b.push(dcid.len() as u8);
        b.extend_from_slice(dcid);
        b.push(scid.len() as u8);
        b.extend_from_slice(scid);
        b.extend_from_slice(trailer);
        b
    }

    fn short_header(fixed_bit: bool, trailer: &[u8]) -> Vec<u8> {
        let byte0 = if fixed_bit { FIXED_BIT_MASK } else { 0 };
        let mut b = vec![byte0];
        b.extend_from_slice(trailer);
        b
    }

    #[test]
    fn v1_initial_parses_dcid_scid_and_packet_type() {
        let dcid = [0xAA, 0xBB, 0xCC, 0xDD];
        let scid = [0x11, 0x22];
        let bytes = long_header(VERSION_1, 0, &dcid, &scid, &[0xDE, 0xAD]);
        let m = meta(bytes.len());
        let parsed = Quic
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid Initial");
        assert_eq!(parsed.header_len, 1 + 4 + 1 + 4 + 1 + 2);
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(HEADER_FORM), Some(&Value::Bool(true)));
        assert_eq!(parsed.fields.get(FIXED_BIT), Some(&Value::Bool(true)));
        assert_eq!(
            parsed.fields.get(VERSION),
            Some(&Value::U64(u64::from(VERSION_1)))
        );
        assert_eq!(parsed.fields.get(DCID), Some(&Value::from(&dcid[..])));
        assert_eq!(parsed.fields.get(SCID), Some(&Value::from(&scid[..])));
        assert_eq!(
            parsed.fields.get(PACKET_TYPE),
            Some(&Value::from("initial"))
        );
    }

    #[test]
    fn v1_zero_rtt_handshake_and_retry_map_correctly() {
        for (bits, name) in [
            (0u8, "initial"),
            (1, "0-rtt"),
            (2, "handshake"),
            (3, "retry"),
        ] {
            let bytes = long_header(VERSION_1, bits, &[0x01], &[], &[0x00]);
            let m = meta(bytes.len());
            let parsed = Quic
                .parse(&bytes, &ctx(Depth::Full, &m))
                .unwrap_or_else(|e| panic!("type {bits}: {e}"));
            assert_eq!(
                parsed.fields.get(PACKET_TYPE),
                Some(&Value::from(name)),
                "type {bits}"
            );
        }
    }

    #[test]
    fn v2_permuted_bits_map_to_the_same_names() {
        // RFC 9369 §3.2: v2's bit pattern is a permutation of v1's, same
        // four meanings.
        for (bits, name) in [
            (0b01u8, "initial"),
            (0b10, "0-rtt"),
            (0b11, "handshake"),
            (0b00, "retry"),
        ] {
            let bytes = long_header(VERSION_2, bits, &[0x01], &[], &[0x00]);
            let m = meta(bytes.len());
            let parsed = Quic
                .parse(&bytes, &ctx(Depth::Full, &m))
                .unwrap_or_else(|e| panic!("type {bits}: {e}"));
            assert_eq!(
                parsed.fields.get(PACKET_TYPE),
                Some(&Value::from(name)),
                "type {bits}"
            );
        }
    }

    #[test]
    fn unrecognized_version_still_yields_dcid_scid_but_no_packet_type() {
        let bytes = long_header(0xFF00_00FF, 2, &[0xAB], &[0xCD], &[0x00]);
        let m = meta(bytes.len());
        let parsed = Quic
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("invariants parse regardless of version");
        assert_eq!(parsed.fields.get(DCID), Some(&Value::from(&[0xABu8][..])));
        assert_eq!(parsed.fields.get(SCID), Some(&Value::from(&[0xCDu8][..])));
        assert_eq!(parsed.fields.get(PACKET_TYPE), None);
    }

    #[test]
    fn zero_length_connection_ids_are_valid() {
        let bytes = long_header(VERSION_1, 0, &[], &[], &[0x00]);
        let m = meta(bytes.len());
        let parsed = Quic
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("zero-length DCID/SCID is legal");
        assert_eq!(parsed.header_len, 1 + 4 + 1 + 1);
        assert_eq!(parsed.fields.get(DCID), Some(&Value::from(&b""[..])));
    }

    #[test]
    fn short_header_stops_terminal_with_only_form_and_fixed_bit() {
        let bytes = short_header(true, &[0xDE, 0xAD, 0xBE, 0xEF]);
        let m = meta(bytes.len());
        let parsed = Quic
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("short header reads byte 0");
        assert_eq!(parsed.header_len, 1);
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(HEADER_FORM), Some(&Value::Bool(false)));
        assert_eq!(parsed.fields.get(FIXED_BIT), Some(&Value::Bool(true)));
        assert_eq!(parsed.fields.get(DCID), None);
        assert_eq!(parsed.fields.get(VERSION), None);
    }

    #[test]
    fn depth_ladder_gates_dcid_at_keys_and_version_at_full() {
        let bytes = long_header(VERSION_1, 0, &[0xAA], &[0xBB], &[0x00]);
        let m = meta(bytes.len());
        let keys = Quic.parse(&bytes, &ctx(Depth::Keys, &m)).expect("valid");
        assert_eq!(keys.fields.get(DCID), Some(&Value::from(&[0xAAu8][..])));
        assert_eq!(keys.fields.get(HEADER_FORM), None);
        assert_eq!(keys.fields.get(VERSION), None);

        let structural = Quic
            .parse(&bytes, &ctx(Depth::Structural, &m))
            .expect("valid");
        assert_eq!(structural.fields.get(HEADER_FORM), Some(&Value::Bool(true)));
        assert_eq!(structural.fields.get(VERSION), None);
    }

    #[test]
    fn truncated_long_header_declines() {
        let bytes = long_header(VERSION_1, 0, &[0xAA, 0xBB], &[0xCC], &[0x00]);
        let m = meta(bytes.len());
        let full = ctx(Depth::Full, &m);
        // Truncation short of the connection-ID payloads must decline;
        // trailing version-specific bytes are never required.
        let header_len_without_trailer = bytes.len() - 1;
        for n in 0..header_len_without_trailer {
            assert!(
                Quic.parse(&bytes[..n], &full).is_err(),
                "prefix of {n} bytes must decline"
            );
        }
    }

    #[test]
    fn truncated_short_header_declines() {
        let m = meta(0);
        assert!(Quic.parse(&[], &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn probe_scores_long_header_with_recognized_or_reserved_version() {
        let m = meta(64);
        let c = ctx(Depth::Full, &m);
        let v1 = long_header(VERSION_1, 0, &[0x01], &[], &[0x00]);
        assert_eq!(Quic.probe(&v1, &c).map(|c| c.get()), Some(50));

        let reserved = long_header(0x1A2A_3A4A, 0, &[0x01], &[], &[0x00]);
        assert_eq!(Quic.probe(&reserved, &c).map(|c| c.get()), Some(50));
    }

    #[test]
    fn probe_declines_short_header_and_missing_fixed_bit() {
        let m = meta(64);
        let c = ctx(Depth::Full, &m);
        let short = short_header(true, &[0, 0, 0, 0]);
        assert_eq!(Quic.probe(&short, &c), None);

        let mut no_fixed_bit = long_header(VERSION_1, 0, &[0x01], &[], &[0x00]);
        no_fixed_bit[0] &= !FIXED_BIT_MASK;
        assert_eq!(Quic.probe(&no_fixed_bit, &c), None);
    }

    #[test]
    fn probe_silent_on_unrecognized_version_without_reserved_pattern() {
        let m = meta(64);
        let c = ctx(Depth::Full, &m);
        let bogus = long_header(0x1234_5678, 0, &[0x01], &[], &[0x00]);
        assert_eq!(Quic.probe(&bogus, &c), None);
    }

    #[test]
    fn probe_silent_on_random_noise() {
        let m = meta(4);
        let c = ctx(Depth::Full, &m);
        assert_eq!(Quic.probe(&[0x00, 0x00, 0x00, 0x00], &c), None);
    }
}
