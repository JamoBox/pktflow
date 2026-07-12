//! DNP3 (11.13, IEEE 1815-2012 — *IEEE Standard for Electric Power Systems
//! Communications: Distributed Network Protocol (DNP3)* §9-10, Data Link
//! Layer framing; wire-level details cross-checked against the DNP Users
//! Group's public *DNP3 Primer* r4). Link-layer header only in v1: the
//! transport-segment reassembly and full application-layer object-header
//! walk are out of scope (D7-consistent — no cross-segment reassembly).
//!
//! Every DNP3 frame starts with a fixed 10-byte Data Link Layer header:
//! 2 sync bytes (`0x05 0x64`), a 1-byte Length, a 1-byte Control, 2-byte
//! Destination and Source addresses (both little-endian, §9.2.3), and a
//! 2-byte CRC over the preceding 8 bytes. `length` counts Control +
//! Destination + Source (5 bytes) plus whatever user data follows — it
//! never encodes less than 5, even for a data-less link-layer-only frame
//! (ACK/NACK/RESET_LINK/TEST_LINK, §9.2.2).
//!
//! When `length` promises at least 3 bytes of user data, this segment's
//! own Transport Layer header (1 byte, §10) and Application Layer control
//! byte (1 byte, §10) are skipped to read the Application Layer function
//! code (1 byte) as a best-effort field — read directly when it falls
//! within this segment, exactly as it arrived, never guessed across a
//! transport-segment boundary this plugin cannot see.

use pktflow_core::{
    ByteReader, Canonicalize, Confidence, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin,
    ParseCtx, ParseError, ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId,
    StreamIdentity, Value,
};

const START_BYTES: FieldName = "start_bytes";
const LENGTH: FieldName = "length";
const CONTROL: FieldName = "control";
const DESTINATION: FieldName = "destination";
const SOURCE: FieldName = "source";
const FUNCTION_CODE: FieldName = "function_code";

// The two sync bytes, read as one big-endian u16 (IEEE 1815-2012 §9.2.2).
const SYNC: u16 = 0x0564;

// Length counts Control + Destination + Source (5 bytes) plus any user
// data; a frame can never promise fewer than those fixed fields.
const MIN_LENGTH: u8 = 5;

static KEY: &[KeyField] = &[KeyField {
    a: SOURCE,
    b: Some(DESTINATION),
}];
static ROLLUPS: &[RollupSpec] = &[RollupSpec {
    field: FUNCTION_CODE,
    kind: RollupKind::Accumulate,
}];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: ROLLUPS,
};

pub struct Dnp3;

impl LayerPlugin for Dnp3 {
    fn name(&self) -> ProtocolName {
        "dnp3"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let sync = r.u16_be()?;
        if sync != SYNC {
            return Err(ParseError::Malformed("DNP3 start bytes are not 0x0564"));
        }
        let length = r.u8()?;
        if length < MIN_LENGTH {
            return Err(ParseError::Malformed("DNP3 length field too small"));
        }
        let control = r.u8()?;
        let destination = r.u16_le()?;
        let source = r.u16_le()?;
        let _header_crc = r.take(2)?;
        let mut consumed = 10usize;

        // `length` covers control+destination+source (5) plus user data;
        // 3+ user-data bytes means a transport header + app control +
        // function code are present in THIS segment (best-effort, D7).
        let user_data_len = usize::from(length) - 5;
        let mut function_code = None;
        if user_data_len >= 3 {
            let _transport_and_app_control = r.take(2)?;
            function_code = Some(r.u8()?);
            consumed += 3;
        }

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(SOURCE, Value::U64(u64::from(source)));
            fields.insert(DESTINATION, Value::U64(u64::from(destination)));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(START_BYTES, Value::U64(u64::from(SYNC)));
            fields.insert(LENGTH, Value::U64(u64::from(length)));
            fields.insert(CONTROL, Value::U64(u64::from(control)));
        }
        if ctx.depth() >= Depth::Full {
            if let Some(fc) = function_code {
                fields.insert(FUNCTION_CODE, Value::U64(u64::from(fc)));
            }
        }

        Ok(ParsedLayer {
            header_len: consumed,
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::TcpPort(20000), RouteId::UdpPort(20000)]
    }

    // DNP3-over-serial-gateway deployments don't always land on the
    // standard port (11.13's own rationale for having this probe at all):
    // the sync bytes plus a self-consistent length are a strong,
    // deterministic signal worth running heuristically.
    fn has_probe(&self) -> bool {
        true
    }

    fn probe(&self, bytes: &[u8], _ctx: &ParseCtx) -> Option<Confidence> {
        let mut r = ByteReader::new(bytes);
        let sync = r.u16_be().ok()?;
        let length = r.u8().ok()?;
        (sync == SYNC && length >= MIN_LENGTH).then(|| Confidence::new(90))
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

    fn parse(bytes: &[u8]) -> Result<ParsedLayer, ParseError> {
        let meta = PacketMeta {
            timestamp: SystemTime::UNIX_EPOCH,
            caplen: bytes.len(),
            origlen: bytes.len(),
            link_type: LinkType::ETHERNET,
        };
        Dnp3.parse(bytes, &ParseCtx::new(&[], Depth::Full, &meta))
    }

    /// Link-layer header only, no user data: a RESET_LINK_STATES primary
    /// frame (control 0x40) from station 3 to station 1024, length 5.
    fn link_only_frame() -> Vec<u8> {
        let mut b = vec![0x05, 0x64, 0x05, 0x40];
        b.extend_from_slice(&1024u16.to_le_bytes()); // destination
        b.extend_from_slice(&3u16.to_le_bytes()); // source
        b.extend_from_slice(&[0xAB, 0xCD]); // header CRC (not validated)
        b
    }

    /// Same station pair, carrying a transport header + application
    /// control + function code 1 (Read) — length 8 (5 + 3).
    fn read_request_frame() -> Vec<u8> {
        let mut b = vec![0x05, 0x64, 0x08, 0xC4];
        b.extend_from_slice(&1024u16.to_le_bytes());
        b.extend_from_slice(&3u16.to_le_bytes());
        b.extend_from_slice(&[0xAB, 0xCD]); // header CRC
        b.push(0xC1); // transport header: FIN|FIR, seq 1
        b.push(0xC0); // application control: FIR|FIN, seq 0
        b.push(0x01); // function code: Read
        b
    }

    #[test]
    fn link_only_frame_parses_header_with_no_function_code() {
        let bytes = link_only_frame();
        let parsed = parse(&bytes).expect("valid frame");
        assert_eq!(parsed.header_len, 10);
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(SOURCE), Some(&Value::U64(3)));
        assert_eq!(parsed.fields.get(DESTINATION), Some(&Value::U64(1024)));
        assert_eq!(parsed.fields.get(START_BYTES), Some(&Value::U64(0x0564)));
        assert_eq!(parsed.fields.get(LENGTH), Some(&Value::U64(5)));
        assert_eq!(parsed.fields.get(CONTROL), Some(&Value::U64(0x40)));
        assert_eq!(parsed.fields.get(FUNCTION_CODE), None);
    }

    #[test]
    fn read_request_extracts_best_effort_function_code() {
        let bytes = read_request_frame();
        let parsed = parse(&bytes).expect("valid frame");
        assert_eq!(parsed.header_len, 13);
        assert_eq!(parsed.fields.get(FUNCTION_CODE), Some(&Value::U64(1)));
        assert_eq!(parsed.fields.get(SOURCE), Some(&Value::U64(3)));
        assert_eq!(parsed.fields.get(DESTINATION), Some(&Value::U64(1024)));
    }

    #[test]
    fn wrong_sync_bytes_decline() {
        let mut bytes = link_only_frame();
        bytes[0] = 0x00;
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn length_below_minimum_declines() {
        let mut bytes = link_only_frame();
        bytes[2] = 4; // below the 5-byte control+destination+source floor
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn truncated_frames_decline() {
        for bytes in [link_only_frame(), read_request_frame()] {
            let expected_len = parse(&bytes).expect("valid frame").header_len;
            assert!(parse(&bytes[..expected_len - 1]).is_err());
        }
    }

    #[test]
    fn probe_scores_confidently_on_sync_and_declines_on_noise() {
        let bytes = link_only_frame();
        let meta = PacketMeta {
            timestamp: SystemTime::UNIX_EPOCH,
            caplen: bytes.len(),
            origlen: bytes.len(),
            link_type: LinkType::ETHERNET,
        };
        let ctx = ParseCtx::new(&[], Depth::Full, &meta);
        assert_eq!(Dnp3.probe(&bytes, &ctx).map(|c| c.get()), Some(90));

        // Plausible-looking rest of header, wrong sync: honesty (11.13).
        let mut noise = bytes.clone();
        noise[0] = 0x06;
        assert_eq!(Dnp3.probe(&noise, &ctx), None);
    }

    #[test]
    fn depth_ladder_is_monotonic() {
        let bytes = read_request_frame();
        let meta = PacketMeta {
            timestamp: SystemTime::UNIX_EPOCH,
            caplen: bytes.len(),
            origlen: bytes.len(),
            link_type: LinkType::ETHERNET,
        };
        let keys = Dnp3
            .parse(&bytes, &ParseCtx::new(&[], Depth::Keys, &meta))
            .expect("valid");
        assert_eq!(keys.fields.get(SOURCE), Some(&Value::U64(3)));
        assert!(keys.fields.get(CONTROL).is_none());
        assert!(keys.fields.get(FUNCTION_CODE).is_none());

        let structural = Dnp3
            .parse(&bytes, &ParseCtx::new(&[], Depth::Structural, &meta))
            .expect("valid");
        assert!(structural.fields.get(CONTROL).is_some());
        assert!(structural.fields.get(FUNCTION_CODE).is_none());
    }
}
