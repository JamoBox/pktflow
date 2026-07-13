//! QUIC invariants (11.6, RFC 8999 — *Version-Independent Properties of
//! QUIC*). RFC 9000/9001 (the "QUIC v1" transport and TLS mapping) are
//! cited for context only — this plugin implements neither; RFC 8999 §3
//! is explicit that everything past its own small invariant set is
//! version-specific and "MUST NOT be interpreted" by a version-unaware
//! observer. D12 draws the line here in its purest form of any protocol in
//! this task: even a Long-header **Initial** packet's frame content sits
//! behind mandatory header protection (RFC 9001 §5.4), a lightweight
//! cryptographic transform applied *before* TLS keys exist, so there is no
//! "read a bit further, it's still cleartext" concession to make — the
//! invariant fields below are the entire honest surface.
//!
//! RFC 8999 §5.2 (Long Header Packets) fixes exactly this shape across
//! every QUIC version, including the version-negotiation marker
//! (`version == 0`, RFC 9000 §6): Header Form (1 bit) + 7 version-specific
//! bits, Version (32 bits), then a length-prefixed Destination Connection
//! ID and a length-prefixed Source Connection ID. Nothing past SCID is
//! parsed — RFC 8999 doesn't guarantee it exists in the same shape for
//! every version, and for the one ratified version this plugin does
//! recognize (RFC 9000 §17.2), what follows (token, length, packet number,
//! frames) is exactly the header-protected region RFC 9001 covers.
//!
//! §5.1's "Fixed Bit" (the second-highest bit, required `1` in every
//! version defined so far — RFC 9000 §17.2) and the header-form bit are
//! read the same way regardless of header shape, so they're extracted
//! unconditionally; `packet_type` (RFC 9000 §17.2's 2-bit Long Packet Type)
//! is version-specific and is therefore only derived when `version`
//! matches a scheme this plugin actually knows (v1 today; see
//! [`KNOWN_LONG_HEADER_VERSIONS`]) — an unrecognized or negotiation
//! (`version == 0`) packet still yields `version`/`dcid`/`scid` honestly,
//! just no `packet_type` guess.
//!
//! RFC 8999 §5.3 (Short Header Packets): the destination connection id
//! carries **no self-describing length** at all — its length was agreed
//! out-of-band during the handshake this plugin never observes — so
//! nothing past the first byte is safely decodable. `header_len` is 1 and
//! `Hint::Terminal` unconditionally: there is no further protocol to route
//! to, ever, on any QUIC packet (D12).
//!
//! **Identity / D14 claim-honesty note (matching `wireguard`, 11.5):**
//! `dcid` is this plugin's stream key, so — like every other flow-key
//! field in this codebase (`esp`'s SPI, `gre`'s key, `vxlan`'s VNI) — it is
//! surfaced starting at `Depth::Keys`, ahead of `version`/`scid`/
//! `packet_type` at `Depth::Full`; only Long-header packets carry it, so a
//! Short-header packet's key build fails with
//! [`pktflow_core::KeyError::MissingField`] and forms no stream for that
//! packet — a documented, honest consequence of RFC 8999 §5.3 rather than
//! a bug. **Known v1 limitation** (the same shape as ESP's per-direction
//! SPI note, 11.5): a QUIC connection may migrate to a new connection id
//! mid-session (RFC 9000 §5.1.1); this plugin has no access to the
//! encrypted `NEW_CONNECTION_ID` frames that announce a migration, so a
//! post-migration DCID simply starts a new sibling `quic` stream under the
//! same parent UDP stream rather than folding into the pre-migration one.

use pktflow_core::{
    ByteReader, Canonicalize, Confidence, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin,
    ParseCtx, ParseError, ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId,
    StreamIdentity, Value,
};

const DCID: FieldName = "dcid";
const HEADER_FORM: FieldName = "header_form";
const FIXED_BIT: FieldName = "fixed_bit";
const VERSION: FieldName = "version";
const SCID: FieldName = "scid";
const PACKET_TYPE: FieldName = "packet_type";

/// RFC 8999 §5.1/§5.2: the top bit of byte 0, `1` for a Long Header.
const HEADER_FORM_BIT: u8 = 0x80;
/// RFC 9000 §17.2: the second-highest bit, required `1` in every version
/// defined so far. RFC 8999 itself treats this as one of the seven
/// "version-specific" bits, not a true cross-version invariant — read here
/// only because every known version happens to fix it, exactly the
/// `probe()` honesty the domain spec calls for (a thin, not a strong,
/// signal).
const FIXED_BIT_MASK: u8 = 0x40;
/// RFC 9000 §17.2: bits 5-4 of byte 0, meaningful only under the v1 scheme.
const LONG_PACKET_TYPE_MASK: u8 = 0x30;

/// QUIC version 1 (RFC 9000). The one ratified scheme whose Long Packet
/// Type bits this plugin knows how to read (RFC 9000 §17.2).
const QUIC_V1: u32 = 0x0000_0001;
/// QUIC version 2 (RFC 9369 §3): the same header shape and Long Packet
/// Type encoding as v1, deliberately permuted at the bit level (§3.2) so
/// naive middleboxes that hard-code v1's values don't mistake v2 traffic
/// for v1 — this plugin follows RFC 9369 §3.2's mapping rather than v1's.
const QUIC_V2: u32 = 0x6b33_43cf;

/// RFC 9000 §17.2's Long Packet Type values, used for `version == QUIC_V1`.
const V1_TYPE_INITIAL: u8 = 0x00;
const V1_TYPE_ZERO_RTT: u8 = 0x01;
const V1_TYPE_HANDSHAKE: u8 = 0x02;
const V1_TYPE_RETRY: u8 = 0x03;

/// RFC 9369 §3.2: v2 permutes the four Long Packet Type values relative to
/// v1 (Initial and Retry swap places, 0-RTT and Handshake swap places) —
/// specifically so the wire values differ from v1's.
const V2_TYPE_RETRY: u8 = 0x00;
const V2_TYPE_INITIAL: u8 = 0x01;
const V2_TYPE_ZERO_RTT: u8 = 0x02;
const V2_TYPE_HANDSHAKE: u8 = 0x03;

/// Versions this plugin will derive `packet_type` for (RFC 9000 §17.2,
/// RFC 9369 §3.2). Everything else — including the version-negotiation
/// marker `0x00000000` and any draft/unassigned value — still yields
/// `version`/`dcid`/`scid`, just no `packet_type` guess (D13: not
/// implementing a scheme this plugin hasn't been specified against).
const KNOWN_LONG_HEADER_VERSIONS: &[u32] = &[QUIC_V1, QUIC_V2];

/// RFC 9000 §15.3 forces endpoints to "grease" version negotiation with
/// reserved values of the pattern `0x?a?a?a?a`; a real implementation must
/// tolerate — and, per that section, itself emit — these. `probe()` treats
/// them as plausible QUIC alongside actually-assigned versions.
fn is_greased_version(version: u32) -> bool {
    version & 0x0F0F_0F0F == 0x0A0A_0A0A
}

fn long_packet_type(version: u32, type_bits: u8) -> Option<&'static str> {
    // `type_bits` is always the caller's `(byte & LONG_PACKET_TYPE_MASK) >>
    // 4`, so it only ever holds 0..=3 — but per the no-panic policy
    // (00.2), input-derived values are never trusted with an `unreachable!`
    // arm; the trailing `_` names the one value (RETRY) it maps to anyway
    // rather than asserting the others can't occur.
    match version {
        QUIC_V1 => Some(match type_bits {
            V1_TYPE_INITIAL => "initial",
            V1_TYPE_ZERO_RTT => "zero_rtt",
            V1_TYPE_HANDSHAKE => "handshake",
            V1_TYPE_RETRY => "retry",
            _ => "retry",
        }),
        QUIC_V2 => Some(match type_bits {
            V2_TYPE_INITIAL => "initial",
            V2_TYPE_ZERO_RTT => "zero_rtt",
            V2_TYPE_HANDSHAKE => "handshake",
            V2_TYPE_RETRY => "retry",
            _ => "retry",
        }),
        _ => None,
    }
}

static KEY: &[KeyField] = &[KeyField { a: DCID, b: None }];
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
        let first = r.u8()?;
        let fixed_bit = first & FIXED_BIT_MASK != 0;

        if first & HEADER_FORM_BIT == 0 {
            // Short Header (RFC 8999 §5.3): the connection id's length is
            // not self-describing at this layer, so nothing past byte 0
            // is decodable — see the module doc.
            let mut fields = FieldMap::new();
            if ctx.depth() >= Depth::Structural {
                fields.insert(HEADER_FORM, Value::from("short"));
                fields.insert(FIXED_BIT, Value::Bool(fixed_bit));
            }
            return Ok(ParsedLayer {
                header_len: 1,
                fields,
                hint: Hint::Terminal,
            });
        }

        // Long Header (RFC 8999 §5.2): Version + length-prefixed DCID +
        // length-prefixed SCID — guaranteed in this shape for every
        // version, including the version-negotiation marker (version 0).
        let version = r.u32_be()?;
        let dcid_len = usize::from(r.u8()?);
        let dcid = r.take(dcid_len)?;
        let scid_len = usize::from(r.u8()?);
        let scid = r.take(scid_len)?;
        let packet_type = long_packet_type(version, (first & LONG_PACKET_TYPE_MASK) >> 4);

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(DCID, Value::from(dcid));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(HEADER_FORM, Value::from("long"));
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
            header_len: 1 + 4 + 1 + dcid_len + 1 + scid_len,
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        // 443 is the common HTTP/3-over-QUIC deployment default, not an
        // exclusive claim (D14 claim-honesty note, domain spec): QUIC
        // shares this port space with negotiated HTTP/3 and is frequently
        // deployed on arbitrary ports. `probe()` covers the rest.
        &[RouteId::UdpPort(443)]
    }

    fn has_probe(&self) -> bool {
        true
    }

    fn probe(&self, bytes: &[u8], _ctx: &ParseCtx) -> Option<Confidence> {
        let mut r = ByteReader::new(bytes);
        let first = r.u8().ok()?;
        if first & FIXED_BIT_MASK == 0 {
            return None;
        }
        if first & HEADER_FORM_BIT == 0 {
            // Short Header: RFC 8999 leaves nothing else to lean on — the
            // domain spec's probe row is deliberately silent here rather
            // than guess from one bit alone.
            return None;
        }
        let version = r.u32_be().ok()?;
        let plausible =
            KNOWN_LONG_HEADER_VERSIONS.contains(&version) || is_greased_version(version);
        // Deliberately modest — QUIC's invariants are thin, an honest
        // reflection of how little a passive observer can lean on before
        // header protection removal — but set at exactly `MIN_CONFIDENCE`
        // (the router's own admission floor, `wireguard`'s precedent for
        // an analogously thin per-packet signal, 11.5) rather than below
        // it: a probe that can never clear the floor never actually admits
        // a non-standard-port deployment to the fallback pool, which
        // defeats the reason this plugin implements one at all.
        plausible.then(|| Confidence::new(pktflow_core::MIN_CONFIDENCE))
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

    /// A Long Header packet (RFC 8999 §5.2 / RFC 9000 §17.2) of the given
    /// v1 long-packet-type, with a trailing "payload" that this plugin
    /// never touches (header-protected, D12).
    fn long_header(
        type_bits: u8,
        version: u32,
        dcid: &[u8],
        scid: &[u8],
        payload: &[u8],
    ) -> Vec<u8> {
        let mut b = Vec::new();
        let first = HEADER_FORM_BIT | FIXED_BIT_MASK | (type_bits << 4) | 0x0F;
        b.push(first);
        b.extend_from_slice(&version.to_be_bytes());
        b.push(dcid.len() as u8);
        b.extend_from_slice(dcid);
        b.push(scid.len() as u8);
        b.extend_from_slice(scid);
        b.extend_from_slice(payload);
        b
    }

    fn short_header(fixed_bit: bool, payload: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        let mut first = 0x00u8; // header_form = 0 (short)
        if fixed_bit {
            first |= FIXED_BIT_MASK;
        }
        first |= 0x0F; // spin bit / key phase / packet-number-length: unread noise
        b.push(first);
        b.extend_from_slice(payload);
        b
    }

    #[test]
    fn long_header_initial_parses_dcid_scid_version_and_type() {
        let dcid = [0xAA; 8];
        let scid = [0xBB; 4];
        let bytes = long_header(V1_TYPE_INITIAL, QUIC_V1, &dcid, &scid, &[0xCC; 32]);
        let m = meta(bytes.len());
        let parsed = Quic
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid Long Header Initial");
        assert_eq!(parsed.header_len, 1 + 4 + 1 + 8 + 1 + 4);
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(DCID), Some(&Value::from(&dcid[..])));
        assert_eq!(parsed.fields.get(SCID), Some(&Value::from(&scid[..])));
        assert_eq!(
            parsed.fields.get(VERSION),
            Some(&Value::U64(u64::from(QUIC_V1)))
        );
        assert_eq!(parsed.fields.get(HEADER_FORM), Some(&Value::from("long")));
        assert_eq!(parsed.fields.get(FIXED_BIT), Some(&Value::Bool(true)));
        assert_eq!(
            parsed.fields.get(PACKET_TYPE),
            Some(&Value::from("initial"))
        );
    }

    #[test]
    fn long_header_v1_types_map_correctly() {
        let dcid = [0x01; 8];
        let scid = [0x02; 8];
        for (bits, name) in [
            (V1_TYPE_INITIAL, "initial"),
            (V1_TYPE_ZERO_RTT, "zero_rtt"),
            (V1_TYPE_HANDSHAKE, "handshake"),
            (V1_TYPE_RETRY, "retry"),
        ] {
            let bytes = long_header(bits, QUIC_V1, &dcid, &scid, &[0xEE; 16]);
            let m = meta(bytes.len());
            let parsed = Quic
                .parse(&bytes, &ctx(Depth::Full, &m))
                .expect("valid Long Header");
            assert_eq!(
                parsed.fields.get(PACKET_TYPE),
                Some(&Value::from(name)),
                "type_bits {bits:#04b}"
            );
        }
    }

    #[test]
    fn long_header_v2_types_use_the_permuted_mapping() {
        // RFC 9369 §3.2: v2's wire values are deliberately not v1's.
        let dcid = [0x03; 8];
        let scid = [0x04; 8];
        for (bits, name) in [
            (V2_TYPE_INITIAL, "initial"),
            (V2_TYPE_ZERO_RTT, "zero_rtt"),
            (V2_TYPE_HANDSHAKE, "handshake"),
            (V2_TYPE_RETRY, "retry"),
        ] {
            let bytes = long_header(bits, QUIC_V2, &dcid, &scid, &[0xEE; 16]);
            let m = meta(bytes.len());
            let parsed = Quic
                .parse(&bytes, &ctx(Depth::Full, &m))
                .expect("valid Long Header");
            assert_eq!(
                parsed.fields.get(PACKET_TYPE),
                Some(&Value::from(name)),
                "type_bits {bits:#04b}"
            );
        }
    }

    #[test]
    fn unknown_version_yields_no_packet_type_but_keeps_dcid_scid() {
        let dcid = [0x05; 6];
        let scid = [0x06; 6];
        // A draft/unassigned version this plugin doesn't map type bits for.
        let bytes = long_header(0b10, 0xFF00_001D, &dcid, &scid, &[]);
        let m = meta(bytes.len());
        let parsed = Quic
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid Long Header, unrecognized version");
        assert_eq!(parsed.fields.get(DCID), Some(&Value::from(&dcid[..])));
        assert_eq!(parsed.fields.get(SCID), Some(&Value::from(&scid[..])));
        assert_eq!(parsed.fields.get(PACKET_TYPE), None);
    }

    #[test]
    fn version_negotiation_marker_still_yields_dcid_scid() {
        let dcid = [0x07; 8];
        let scid = [0x08; 8];
        let bytes = long_header(0b11, 0x0000_0000, &dcid, &scid, &[]);
        let m = meta(bytes.len());
        let parsed = Quic
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid Long Header, version negotiation");
        assert_eq!(parsed.fields.get(VERSION), Some(&Value::U64(0)));
        assert_eq!(parsed.fields.get(DCID), Some(&Value::from(&dcid[..])));
        assert_eq!(parsed.fields.get(PACKET_TYPE), None);
    }

    #[test]
    fn zero_length_connection_ids_are_valid() {
        let bytes = long_header(V1_TYPE_INITIAL, QUIC_V1, &[], &[], &[0x01; 4]);
        let m = meta(bytes.len());
        let parsed = Quic
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("zero-length CIDs are structurally valid");
        assert_eq!(parsed.header_len, 1 + 4 + 1 + 1); // both CID lengths are 0
        assert_eq!(parsed.fields.get(DCID), Some(&Value::from(&[][..])));
        assert_eq!(parsed.fields.get(SCID), Some(&Value::from(&[][..])));
    }

    #[test]
    fn short_header_stops_after_one_byte_with_no_dcid() {
        let bytes = short_header(true, &[0xAB; 100]);
        let m = meta(bytes.len());
        let parsed = Quic
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid Short Header");
        assert_eq!(parsed.header_len, 1);
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(HEADER_FORM), Some(&Value::from("short")));
        assert_eq!(parsed.fields.get(FIXED_BIT), Some(&Value::Bool(true)));
        assert_eq!(parsed.fields.get(DCID), None);
        assert_eq!(parsed.fields.get(VERSION), None);
        assert_eq!(parsed.fields.get(SCID), None);
        assert_eq!(parsed.fields.get(PACKET_TYPE), None);
    }

    #[test]
    fn short_header_fixed_bit_unset_reports_false_not_absent() {
        let bytes = short_header(false, &[0xAB; 4]);
        let m = meta(bytes.len());
        let parsed = Quic
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid Short Header");
        assert_eq!(parsed.fields.get(FIXED_BIT), Some(&Value::Bool(false)));
    }

    #[test]
    fn depth_ladder_is_monotonic_for_long_header() {
        let dcid = [0x09; 8];
        let scid = [0x0A; 8];
        let bytes = long_header(V1_TYPE_HANDSHAKE, QUIC_V1, &dcid, &scid, &[0xFF; 8]);
        let m = meta(bytes.len());

        let keys_only = Quic.parse(&bytes, &ctx(Depth::Keys, &m)).expect("valid");
        assert_eq!(keys_only.fields.get(DCID), Some(&Value::from(&dcid[..])));
        assert_eq!(keys_only.fields.get(HEADER_FORM), None);
        assert_eq!(keys_only.fields.get(VERSION), None);

        let structural = Quic
            .parse(&bytes, &ctx(Depth::Structural, &m))
            .expect("valid");
        assert_eq!(structural.fields.get(DCID), Some(&Value::from(&dcid[..])));
        assert_eq!(
            structural.fields.get(HEADER_FORM),
            Some(&Value::from("long"))
        );
        assert_eq!(structural.fields.get(VERSION), None);
    }

    #[test]
    fn truncated_long_header_frames_decline() {
        let dcid = [0x0B; 8];
        let scid = [0x0C; 8];
        let bytes = long_header(V1_TYPE_INITIAL, QUIC_V1, &dcid, &scid, &[0xDD; 4]);
        let m = meta(bytes.len());
        let header_len = 1 + 4 + 1 + 8 + 1 + 8;
        for n in 0..header_len {
            let full_ctx = ctx(Depth::Full, &m);
            assert!(
                Quic.parse(&bytes[..n], &full_ctx).is_err(),
                "prefix of {n}/{header_len} bytes must decline"
            );
        }
    }

    #[test]
    fn truncated_short_header_declines() {
        let m = meta(0);
        assert!(Quic.parse(&[], &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn probe_scores_long_header_known_and_greased_versions() {
        let m = meta(0);
        let c = ctx(Depth::Full, &m);

        let v1 = long_header(V1_TYPE_INITIAL, QUIC_V1, &[0x01; 8], &[0x02; 8], &[]);
        assert_eq!(
            Quic.probe(&v1, &c).map(|s| s.get()),
            Some(pktflow_core::MIN_CONFIDENCE)
        );

        let v2 = long_header(V2_TYPE_INITIAL, QUIC_V2, &[0x01; 8], &[0x02; 8], &[]);
        assert_eq!(
            Quic.probe(&v2, &c).map(|s| s.get()),
            Some(pktflow_core::MIN_CONFIDENCE)
        );

        // RFC 9000 §15.3 greased pattern: 0x?a?a?a?a.
        let greased = long_header(0b00, 0x1a2a_3a4a, &[], &[], &[]);
        assert_eq!(
            Quic.probe(&greased, &c).map(|s| s.get()),
            Some(pktflow_core::MIN_CONFIDENCE)
        );

        // An arbitrary unassigned, non-greased version: no probe match.
        let unknown = long_header(0b00, 0x1234_5678, &[], &[], &[]);
        assert_eq!(Quic.probe(&unknown, &c), None);

        // Fixed bit unset: fails immediately regardless of the rest.
        let mut no_fixed_bit = v1.clone();
        no_fixed_bit[0] &= !FIXED_BIT_MASK;
        assert_eq!(Quic.probe(&no_fixed_bit, &c), None);

        // Short header: deliberately no signal.
        assert_eq!(Quic.probe(&short_header(true, &[]), &c), None);

        // Noise.
        assert_eq!(Quic.probe(&[0x00; 5], &c), None);
    }

    #[test]
    fn different_dcids_key_into_different_streams() {
        // The documented connection-migration limitation (module doc):
        // this is exercised at the identity-declaration level here; the
        // full aggregator-level sibling-stream behavior is covered by
        // `tests/transport.rs`'s conformance/migration fixture.
        let identity = Quic.stream_identity().expect("declares identity");
        assert_eq!(identity.key.len(), 1);
        assert_eq!(identity.key[0].a, DCID);
        assert_eq!(identity.key[0].b, None);
    }
}
