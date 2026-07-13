//! AH (11.5, RFC 4302 — *IP Authentication Header*, §2). Unlike ESP
//! (11.5, RFC 4303 — same task, sibling module), AH authenticates but does
//! not encrypt: every field in its header is cleartext, including the
//! `next_header` field that names what follows, so this plugin routes
//! onward instead of stopping `Terminal` (D12 draws the extraction
//! ceiling at the encryption boundary — AH simply never crosses it).
//!
//! RFC 4302 §2 lays out the header as: Next Header (1 byte), Payload Len
//! (1 byte), Reserved (2 bytes, must be zero), SPI (4 bytes), Sequence
//! Number (4 bytes), then a variable-length Integrity Check Value (ICV).
//! §2.2: "Payload Len ... specifies the length of AH in 32-bit words (4-byte
//! units), minus 2" — i.e. `total_header_bytes = (Payload Len + 2) * 4 =
//! Payload Len * 4 + 8`. The three fixed 32-bit words (Next
//! Header/Payload Len/Reserved, SPI, Sequence Number) account for the
//! first 12 of those bytes; everything beyond is the ICV, whatever length
//! the negotiated authentication algorithm produced (commonly 96 bits /
//! 12 bytes for HMAC-SHA1-96 or HMAC-SHA-256-128, but the field itself is
//! the only honest source of that length — this plugin reads it from the
//! wire rather than assuming an algorithm).
//!
//! SPI is unidirectional by design (RFC 4302 §2.1, same as ESP's §2.1),
//! so this plugin keys on it alone — the shared-qualifier shape ESP,
//! GRE's key, and Geneve's VNI all use (06.5, 11.5) — which naturally
//! yields two sibling `ah` streams per security association, one per
//! direction, under their common parent IP conversation.

use pktflow_core::{
    ByteReader, Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx,
    ParseError, ParsedLayer, ProtocolName, RouteId, StreamIdentity, Value,
};

const SPI: FieldName = "spi";
const NEXT_HEADER: FieldName = "next_header";
const PAYLOAD_LEN: FieldName = "payload_len";
const SEQUENCE: FieldName = "sequence";
const ICV: FieldName = "icv";

/// The three fixed 32-bit words (Next Header/Payload Len/Reserved, SPI,
/// Sequence Number) — RFC 4302 §2, before the variable-length ICV.
const FIXED_HEADER_LEN: usize = 12;

static KEY: &[KeyField] = &[KeyField {
    a: SPI,
    b: None, // shared qualifier: SPI is unidirectional (RFC 4302 §2.1)
}];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: &[],
};

pub struct Ah;

impl LayerPlugin for Ah {
    fn name(&self) -> ProtocolName {
        "ah"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let next_header = r.u8()?;
        let payload_len = r.u8()?;
        let _reserved = r.u16_be()?;
        let spi = r.u32_be()?;
        let sequence = r.u32_be()?;

        // RFC 4302 §2.2: total AH length in bytes = payload_len*4 + 8.
        // Below the 3-word fixed portion (12 bytes) is a length that can't
        // hold Next Header/Payload Len/Reserved/SPI/Sequence at all —
        // decline rather than underflow computing the ICV length.
        let header_len = usize::from(payload_len) * 4 + 8;
        if header_len < FIXED_HEADER_LEN {
            return Err(ParseError::Malformed(
                "AH payload length too small for the fixed header",
            ));
        }
        let icv_len = header_len - FIXED_HEADER_LEN;
        let icv = r.take(icv_len)?;

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(SPI, Value::U64(u64::from(spi)));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(NEXT_HEADER, Value::U64(u64::from(next_header)));
            fields.insert(PAYLOAD_LEN, Value::U64(u64::from(payload_len)));
            fields.insert(SEQUENCE, Value::U64(u64::from(sequence)));
        }
        if ctx.depth() >= Depth::Full {
            fields.insert(ICV, Value::from(icv));
        }

        Ok(ParsedLayer {
            header_len,
            fields,
            hint: Hint::Route(RouteId::IpProtocol(next_header)),
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::IpProtocol(51)]
    }

    // No probe: SPI/Sequence Number are opaque, and AH is IANA-assigned
    // IpProtocol(51) — the ESP/GRE/Geneve tunnel precedent (06.5, 11.5) of
    // explicit-claim-only for a well-known protocol number.

    fn stream_identity(&self) -> Option<&StreamIdentity> {
        Some(&IDENTITY)
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use pktflow_core::{LinkType, PacketMeta};

    use super::*;

    /// Next Header = TCP(6), Payload Len = 4 (96-bit/12-byte ICV, the
    /// HMAC-SHA1-96 default per RFC 4302 §5 — total header = 4*4+8 = 24
    /// bytes: 12 fixed + 12 ICV), SPI 0x1000_0001, sequence 1, then the
    /// 12-byte ICV.
    const FRAME: [u8; 24] = [
        0x06, 0x04, 0x00, 0x00, 0x10, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0xAA, 0xBB, 0xCC,
        0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
    ];

    fn meta(len: usize) -> PacketMeta {
        PacketMeta {
            timestamp: SystemTime::UNIX_EPOCH,
            caplen: len,
            origlen: len,
            link_type: LinkType::ETHERNET,
        }
    }

    fn parse(bytes: &[u8]) -> Result<ParsedLayer, ParseError> {
        Ah.parse(bytes, &ParseCtx::new(&[], Depth::Full, &meta(bytes.len())))
    }

    #[test]
    fn parses_fixed_fields_and_routes_onward() {
        let parsed = parse(&FRAME).expect("valid AH header");
        assert_eq!(parsed.header_len, 24);
        assert_eq!(parsed.fields.get(SPI), Some(&Value::U64(0x1000_0001)));
        assert_eq!(parsed.fields.get(NEXT_HEADER), Some(&Value::U64(6)));
        assert_eq!(parsed.fields.get(PAYLOAD_LEN), Some(&Value::U64(4)));
        assert_eq!(parsed.fields.get(SEQUENCE), Some(&Value::U64(1)));
        assert_eq!(parsed.fields.get(ICV), Some(&Value::from(&FRAME[12..24])));
        assert_eq!(parsed.hint, Hint::Route(RouteId::IpProtocol(6)));
    }

    #[test]
    fn truncated_header_declines() {
        for cut in 0..FRAME.len() {
            assert!(parse(&FRAME[..cut]).is_err(), "cut at {cut}");
        }
    }

    #[test]
    fn zero_payload_len_declines_rather_than_underflow() {
        let mut bytes = FRAME;
        bytes[1] = 0; // payload_len = 0 -> header_len (8) < fixed header (12)
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn zero_length_icv_is_a_syntactically_valid_minimum() {
        // payload_len = 1 -> header_len = 12, icv_len = 0: unusual
        // (no real algorithm produces a null ICV) but not our call to
        // reject — the wire framing itself is self-consistent.
        let bytes = [0x06u8, 0x01, 0x00, 0x00, 0x10, 0x00, 0x00, 0x01, 0, 0, 0, 1];
        let parsed = parse(&bytes).expect("framing is self-consistent");
        assert_eq!(parsed.header_len, 12);
        assert_eq!(parsed.fields.get(ICV), Some(&Value::from(&[][..])));
    }

    #[test]
    fn depth_gating_hides_fields_below_their_tier() {
        let keys_only = Ah
            .parse(&FRAME, &ParseCtx::new(&[], Depth::Keys, &meta(FRAME.len())))
            .expect("valid header");
        assert_eq!(keys_only.fields.get(SPI), Some(&Value::U64(0x1000_0001)));
        assert_eq!(keys_only.fields.get(NEXT_HEADER), None);
        assert_eq!(keys_only.fields.get(ICV), None);
        assert_eq!(keys_only.header_len, 24);

        let structural = Ah
            .parse(
                &FRAME,
                &ParseCtx::new(&[], Depth::Structural, &meta(FRAME.len())),
            )
            .expect("valid header");
        assert_eq!(structural.fields.get(NEXT_HEADER), Some(&Value::U64(6)));
        assert_eq!(structural.fields.get(ICV), None, "ICV is Full-only");
    }

    #[test]
    fn reserved_field_is_read_but_not_validated() {
        // RFC 4302 §2.3 says Reserved "MUST be set to zero" by the sender
        // but says nothing about receiver validation, and real
        // implementations don't reject on a nonzero value — read and
        // ignore, don't decline traffic over a non-normative sender bug.
        let mut bytes = FRAME;
        bytes[2] = 0xFF;
        bytes[3] = 0xFF;
        assert!(parse(&bytes).is_ok());
    }
}
