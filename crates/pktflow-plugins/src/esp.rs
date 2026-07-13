//! ESP (11.5, RFC 4303 — *IP Encapsulating Security Payload*, §2). Governed
//! by D12: this plugin extracts only the two cleartext fields ESP itself
//! exposes and declines `Terminal` on everything after them, rather than
//! guessing at ciphertext.
//!
//! RFC 4303 §2 lays out the ESP packet as SPI (4 bytes), Sequence Number
//! (4 bytes), then Payload Data, Padding, Pad Length, Next Header, and the
//! Integrity Check Value — all of the latter fall inside the encryption
//! boundary (§3.3.2: "encryption... covers... everything in the payload
//! field") or depend on decrypting it to even locate (Pad Length/Next
//! Header sit at the *end* of the ciphertext, ICV's length is
//! algorithm-negotiated out-of-band). None of that is a cleartext header
//! field this plugin can honestly parse, so the 8-byte SPI+Sequence Number
//! pair is the entire header.
//!
//! SPI is unidirectional by design (§2.1: each direction of a security
//! association picks its own SPI independently), so keying on it alone —
//! the same shared-qualifier shape as GRE's key/Geneve's VNI (06.5, 11.5)
//! — naturally yields two sibling `esp` streams per tunnel, one per
//! direction, under their common parent IP conversation. That is correct
//! ESP semantics (D10's parent-scoped node identity), not a modeling gap.

use pktflow_core::{
    ByteReader, Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx,
    ParseError, ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId, StreamIdentity, Value,
};

const SPI: FieldName = "spi";
const SEQUENCE: FieldName = "sequence";

static KEY: &[KeyField] = &[KeyField {
    a: SPI,
    b: None, // shared qualifier: SPI is unidirectional (RFC 4303 §2.1)
}];
static ROLLUPS: &[RollupSpec] = &[RollupSpec {
    field: SEQUENCE,
    kind: RollupKind::Sample, // first/last observed: a liveness signal, not a replay check
}];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: ROLLUPS,
};

pub struct Esp;

impl LayerPlugin for Esp {
    fn name(&self) -> ProtocolName {
        "esp"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let spi = r.u32_be()?;
        let sequence = r.u32_be()?;

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(SPI, Value::U64(u64::from(spi)));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(SEQUENCE, Value::U64(u64::from(sequence)));
        }
        // No Full fields: everything past these 8 bytes (ciphertext,
        // padding, pad length, next header, ICV) is encrypted or
        // encryption-dependent to locate (RFC 4303 §3.3.2) — D12 draws
        // the extraction ceiling exactly here.

        Ok(ParsedLayer {
            header_len: 8,
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::IpProtocol(50)]
    }

    // No probe: SPI/Sequence Number are both opaque 32-bit values with no
    // self-describing structure, and ESP is IANA-assigned IpProtocol(50)
    // (unlike WireGuard's ambiguous default UDP port) — explicit-claim-only
    // is honest here, the GRE/Geneve tunnel precedent (06.5, 11.5).

    fn stream_identity(&self) -> Option<&StreamIdentity> {
        Some(&IDENTITY)
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use pktflow_core::{LinkType, PacketMeta};

    use super::*;

    // SPI 0x1234_5678, sequence 42, followed by 12 bytes of "ciphertext"
    // this plugin must never look inside.
    const FRAME: [u8; 20] = [
        0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x2A, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA,
        0xBE, 0x00, 0x11, 0x22, 0x33,
    ];

    fn parse(bytes: &[u8]) -> Result<ParsedLayer, ParseError> {
        let meta = PacketMeta {
            timestamp: SystemTime::UNIX_EPOCH,
            caplen: bytes.len(),
            origlen: bytes.len(),
            link_type: LinkType::ETHERNET,
        };
        Esp.parse(bytes, &ParseCtx::new(&[], Depth::Full, &meta))
    }

    #[test]
    fn parses_spi_and_sequence_stops_terminal() {
        let parsed = parse(&FRAME).expect("valid header");
        assert_eq!(parsed.header_len, 8);
        assert_eq!(parsed.fields.get(SPI), Some(&Value::U64(0x1234_5678)));
        assert_eq!(parsed.fields.get(SEQUENCE), Some(&Value::U64(42)));
        assert_eq!(parsed.fields.len(), 2, "no Full fields past the header");
        assert_eq!(parsed.hint, Hint::Terminal);
    }

    #[test]
    fn truncated_header_declines() {
        for cut in 0..8 {
            assert!(parse(&FRAME[..cut]).is_err(), "cut at {cut}");
        }
    }

    #[test]
    fn header_len_is_fixed_regardless_of_trailing_ciphertext_length() {
        // Only the SPI+Sequence pair is ever consumed, no matter how much
        // (or how little) ciphertext trails it.
        assert_eq!(parse(&FRAME[..8]).expect("bare header").header_len, 8);
        assert_eq!(parse(&FRAME).expect("with ciphertext").header_len, 8);
    }

    #[test]
    fn depth_gating_hides_sequence_below_structural() {
        let meta = PacketMeta {
            timestamp: SystemTime::UNIX_EPOCH,
            caplen: FRAME.len(),
            origlen: FRAME.len(),
            link_type: LinkType::ETHERNET,
        };

        let keys_only = Esp
            .parse(&FRAME, &ParseCtx::new(&[], Depth::Keys, &meta))
            .expect("valid header");
        assert_eq!(keys_only.fields.get(SPI), Some(&Value::U64(0x1234_5678)));
        assert_eq!(keys_only.fields.get(SEQUENCE), None);
        assert_eq!(keys_only.header_len, 8);

        let none_depth = Esp
            .parse(&FRAME, &ParseCtx::new(&[], Depth::None, &meta))
            .expect("valid header");
        assert_eq!(none_depth.fields.get(SPI), None);
        assert_eq!(none_depth.header_len, 8);
    }
}
