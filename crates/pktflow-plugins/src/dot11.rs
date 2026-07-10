//! dot11 (11.2, IEEE 802.11-2020): the 802.11 MAC header — management,
//! control, and data frames — for a raw (non-radiotap-wrapped) capture,
//! and the destination of `radiotap`'s (11.2) unconditional `ByProtocol`
//! hint. The over-the-air analogue of Ethernet II (06.2): the same
//! two-address conversation shape, one layer up from the physical medium
//! rather than down at it.
//!
//! Multi-octet 802.11 fields (Duration/ID, Sequence Control, QoS Control)
//! are transmitted least-significant-octet first — **little-endian**,
//! unlike Ethernet/IP's network byte order (802.11-2020 §9.2.2,
//! "Conventions": fields are depicted MSB-last in the figures, which is
//! the standard's way of saying LSB-first on the wire; every public
//! dissector — Wireshark, tcpdump/tshark — reads these fields
//! little-endian, and so does this plugin).
//!
//! Header shape depends on frame type/subtype (§9.2.4, §9.3):
//! - **Management** (type 0): Frame Control, Duration, Address1 (DA),
//!   Address2 (SA), Address3 (BSSID), Sequence Control, then the frame
//!   body (fixed fields + information elements, §9.3.3). Always
//!   `Hint::Terminal` — this plugin does not walk arbitrary IEs, only the
//!   bounded SSID lookup below.
//! - **Control** (type 1): Frame Control, Duration, Address1 (RA), then
//!   Address2 (TA) *except* for ACK and CTS, which end after Address1
//!   (§9.3.1.5, §9.3.1.6 — RA is the only address either frame carries).
//!   No body. Always `Hint::Terminal`.
//! - **Data** (type 2): Frame Control, Duration, Address1, Address2,
//!   Address3, Sequence Control, then Address4 only when both To DS and
//!   From DS are set (WDS, §9.3.2.1), then a QoS Control field only when
//!   the subtype's bit 3 is set (the eight QoS subtypes, §9.2.4.5.1),
//!   then the frame body. `Hint::Terminal` when the `Protected Frame` bit
//!   is set (payload is encrypted at this layer — D12's stance applied
//!   one layer down: identify, don't guess past opacity) or the body is
//!   empty (Null/QoS-Null and the other body-less data subtypes carry no
//!   further protocol); otherwise `Hint::ByProtocol("llc")` — reusing
//!   11.1's LLC/SNAP demux, exactly like wired Ethernet, so IP traffic
//!   and the unprotected WPA/WPA3 4-way handshake (EAPOL-Key over
//!   LLC/SNAP EtherType 0x888E, 11.1's `eapol`, unmodified) fall through
//!   the same path.
//!
//! `header_len` covers only this fixed address/sequence/QoS shape for
//! control and data frames — the boundary the next layer (`llc`) starts
//! from. For management frames there is no next layer (always
//! `Terminal`), so — same stance as CDP/LLDP/STP (11.1) — the entire
//! frame is consumed as this layer's header; that is what makes reading
//! into the body for the SSID walk still "this header, not the payload"
//! under rule 1 (02.1): nothing else will ever look further.

use pktflow_core::{
    ByteReader, Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx,
    ParseError, ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId, StreamIdentity, Value,
};

const FRAME_TYPE: FieldName = "frame_type";
const FRAME_SUBTYPE: FieldName = "frame_subtype";
const FLAGS: FieldName = "flags";
const DURATION: FieldName = "duration";
const SEQ_NUM: FieldName = "seq_num";
const ADDR1: FieldName = "addr1";
const ADDR2: FieldName = "addr2";
const ADDR3: FieldName = "addr3";
const ADDR4: FieldName = "addr4";
const QOS_CONTROL: FieldName = "qos_control";
const SSID: FieldName = "ssid";

/// Frame Control `Type` subfield values (802.11-2020 Table 9-1).
const TYPE_MANAGEMENT: u8 = 0;
const TYPE_CONTROL: u8 = 1;
const TYPE_DATA: u8 = 2;

/// Management subtypes this plugin extracts `ssid` for (§9.3.3): Probe
/// Request has no fixed fields before its IEs, Beacon/Probe Response both
/// carry the same 12-byte fixed block (Timestamp + Beacon Interval +
/// Capability Info) first.
const SUBTYPE_PROBE_REQUEST: u8 = 0b0100;
const SUBTYPE_PROBE_RESPONSE: u8 = 0b0101;
const SUBTYPE_BEACON: u8 = 0b1000;

/// Control subtypes whose frame carries only Address1 — RA, no TA
/// (§9.3.1.5 CTS, §9.3.1.6 ACK). Every other control subtype (RTS,
/// PS-Poll, CF-End, Block Ack/Request, ...) carries both.
const SUBTYPE_CTS: u8 = 0b1100;
const SUBTYPE_ACK: u8 = 0b1101;

/// Beacon/Probe Response fixed fields preceding the IE chain (§9.3.3.2,
/// §9.3.3.3): Timestamp(8) + Beacon Interval(2) + Capability Info(2).
const MGMT_FIXED_FIELDS_LEN: usize = 12;

/// Frame Control flag-octet bit positions (802.11-2020 Figure 9-1), read
/// as one raw byte — this *is* the `flags` field's bit layout.
const FLAG_TO_DS: u8 = 0x01;
const FLAG_FROM_DS: u8 = 0x02;
const FLAG_PROTECTED: u8 = 0x40;

fn u16_le(r: &mut ByteReader) -> Result<u16, ParseError> {
    let b = r.take(2)?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

/// Bounded information-element walk (802.11-2020 §9.4.2.1: TLV-shaped,
/// 1-byte Element ID + 1-byte Length + value), stopping at the first SSID
/// element (Element ID 0, §9.4.2.2). Naturally bounded — like LLDP's TLV
/// walk (11.1) — because each iteration consumes at least 2 bytes or the
/// `ByteReader` errors; a malformed or absent SSID is `None`, not a parse
/// failure (this is an auxiliary Full-only field, not part of the header
/// contract).
fn extract_ssid(elements: &[u8]) -> Option<Value> {
    let mut r = ByteReader::new(elements);
    loop {
        let id = r.u8().ok()?;
        let len = r.u8().ok()?;
        let value = r.take(usize::from(len)).ok()?;
        if id == 0 {
            return Some(Value::from(decode_ssid(value).as_str()));
        }
    }
}

/// Best-effort text decode: SSIDs are conventionally UTF-8/ASCII but the
/// element permits arbitrary octets. Non-printable bytes render as `?`
/// rather than failing the field — same stance as LLDP's `decode_text`
/// (11.1) and DHCP's hostname option (06.6).
fn decode_ssid(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                char::from(b)
            } else {
                '?'
            }
        })
        .collect()
}

static KEY: &[KeyField] = &[KeyField {
    a: ADDR1,
    b: Some(ADDR2),
}];
static ROLLUPS: &[RollupSpec] = &[RollupSpec {
    field: FRAME_SUBTYPE,
    kind: RollupKind::Accumulate,
}];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: ROLLUPS,
};

pub struct Dot11;

impl LayerPlugin for Dot11 {
    fn name(&self) -> ProtocolName {
        "dot11"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let fc0 = r.u8()?;
        let fc1 = r.u8()?;
        let duration = u16_le(&mut r)?;
        let addr1 = r.take(6)?;

        let frame_type = (fc0 >> 2) & 0b11;
        let frame_subtype = (fc0 >> 4) & 0b1111;
        let to_ds = fc1 & FLAG_TO_DS != 0;
        let from_ds = fc1 & FLAG_FROM_DS != 0;
        let protected = fc1 & FLAG_PROTECTED != 0;

        let mut addr2: Option<&[u8]> = None;
        let mut addr3: Option<&[u8]> = None;
        let mut addr4: Option<&[u8]> = None;
        let mut seq_num: Option<u64> = None;
        let mut qos_control: Option<u64> = None;
        let mut ssid: Option<Value> = None;

        match frame_type {
            TYPE_MANAGEMENT => {
                addr2 = Some(r.take(6)?);
                addr3 = Some(r.take(6)?);
                let seq_ctl = u16_le(&mut r)?;
                seq_num = Some(u64::from(seq_ctl >> 4));

                // The whole remaining frame is this layer's header (see
                // the module doc: always Terminal, nothing looks further).
                let body = r.take(r.remaining())?;
                ssid = match frame_subtype {
                    SUBTYPE_PROBE_REQUEST => extract_ssid(body),
                    SUBTYPE_BEACON | SUBTYPE_PROBE_RESPONSE => {
                        body.get(MGMT_FIXED_FIELDS_LEN..).and_then(extract_ssid)
                    }
                    _ => None,
                };
            }
            TYPE_CONTROL => {
                if !matches!(frame_subtype, SUBTYPE_CTS | SUBTYPE_ACK) {
                    addr2 = Some(r.take(6)?);
                }
            }
            TYPE_DATA => {
                addr2 = Some(r.take(6)?);
                addr3 = Some(r.take(6)?);
                let seq_ctl = u16_le(&mut r)?;
                seq_num = Some(u64::from(seq_ctl >> 4));
                if to_ds && from_ds {
                    addr4 = Some(r.take(6)?);
                }
                if frame_subtype & 0b1000 != 0 {
                    qos_control = Some(u64::from(u16_le(&mut r)?));
                }
            }
            // Extension frames (type 3, §9.2.4.1.3: S1G-only in this
            // edition of the standard) are not modeled beyond the
            // Address1-only shape already read above — out of v1 scope,
            // same honesty stance as the domain spec's other tiering
            // notes (D13).
            _ => {}
        }

        let header_len = bytes.len() - r.remaining();

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(ADDR1, Value::from(addr1));
            if let Some(a2) = addr2 {
                fields.insert(ADDR2, Value::from(a2));
            }
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(FRAME_TYPE, Value::U64(u64::from(frame_type)));
            fields.insert(FRAME_SUBTYPE, Value::U64(u64::from(frame_subtype)));
            fields.insert(FLAGS, Value::U64(u64::from(fc1)));
            fields.insert(DURATION, Value::U64(u64::from(duration)));
            if let Some(s) = seq_num {
                fields.insert(SEQ_NUM, Value::U64(s));
            }
            if let Some(a3) = addr3 {
                fields.insert(ADDR3, Value::from(a3));
            }
        }
        if ctx.depth() >= Depth::Full {
            if let Some(a4) = addr4 {
                fields.insert(ADDR4, Value::from(a4));
            }
            if let Some(qc) = qos_control {
                fields.insert(QOS_CONTROL, Value::U64(qc));
            }
            if let Some(s) = ssid {
                fields.insert(SSID, s);
            }
        }

        let has_body = frame_type == TYPE_DATA && header_len < bytes.len();
        let hint = if !protected && has_body {
            Hint::ByProtocol("llc")
        } else {
            Hint::Terminal
        };

        Ok(ParsedLayer {
            header_len,
            fields,
            hint,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::LinkType(105 /* DLT_IEEE802_11 */)]
    }

    // No probe: explicit entry via LinkType, or explicit ByProtocol
    // dispatch from radiotap — both always name this plugin by id, never
    // by heuristic guess (11.2's documented stance).

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
            link_type: LinkType(105),
        }
    }

    fn ctx(depth: Depth, meta: &PacketMeta) -> ParseCtx<'_> {
        ParseCtx::new(&[], depth, meta)
    }

    fn parse(bytes: &[u8], depth: Depth) -> Result<ParsedLayer, ParseError> {
        let m = meta(bytes.len());
        Dot11.parse(bytes, &ctx(depth, &m))
    }

    const AP: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    const STA: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
    const BROADCAST: [u8; 6] = [0xFF; 6];

    fn fc(frame_type: u8, subtype: u8) -> u8 {
        (subtype << 4) | (frame_type << 2)
    }

    /// Beacon (mgmt, subtype 8): fixed fields all-zero timestamp, 100 TU
    /// beacon interval, ESS capability, then an SSID IE "TestNet" and a
    /// trailing Supported Rates IE (proves the walk finds SSID even when
    /// it isn't the last element).
    fn beacon_frame() -> Vec<u8> {
        let mut b = vec![fc(TYPE_MANAGEMENT, SUBTYPE_BEACON), 0x00];
        b.extend_from_slice(&0u16.to_le_bytes()); // duration
        b.extend_from_slice(&BROADCAST); // addr1 (DA)
        b.extend_from_slice(&AP); // addr2 (SA)
        b.extend_from_slice(&AP); // addr3 (BSSID)
        b.extend_from_slice(&0x0010u16.to_le_bytes()); // seq_ctl: seq=1
        b.extend_from_slice(&[0; 8]); // timestamp
        b.extend_from_slice(&100u16.to_le_bytes()); // beacon interval
        b.extend_from_slice(&0x0001u16.to_le_bytes()); // capability: ESS
        b.push(0); // SSID element id
        b.push(7);
        b.extend_from_slice(b"TestNet");
        b.push(1); // Supported Rates element id
        b.push(2);
        b.extend_from_slice(&[0x82, 0x84]);
        b
    }

    /// Probe Request (mgmt, subtype 4): no fixed fields, IEs start
    /// immediately — SSID first, wildcard-length-7 "TestNet".
    fn probe_request_frame() -> Vec<u8> {
        let mut b = vec![fc(TYPE_MANAGEMENT, SUBTYPE_PROBE_REQUEST), 0x00];
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&BROADCAST); // addr1
        b.extend_from_slice(&STA); // addr2
        b.extend_from_slice(&BROADCAST); // addr3 (wildcard BSSID)
        b.extend_from_slice(&0x0020u16.to_le_bytes());
        b.push(0);
        b.push(7);
        b.extend_from_slice(b"TestNet");
        b
    }

    /// RTS (control, subtype 11): RA + TA, no body.
    fn rts_frame() -> Vec<u8> {
        let mut b = vec![fc(TYPE_CONTROL, 0b1011), 0x00];
        b.extend_from_slice(&44u16.to_le_bytes());
        b.extend_from_slice(&AP); // addr1 (RA)
        b.extend_from_slice(&STA); // addr2 (TA)
        b
    }

    /// CTS (control, subtype 12): RA only.
    fn cts_frame() -> Vec<u8> {
        let mut b = vec![fc(TYPE_CONTROL, SUBTYPE_CTS), 0x00];
        b.extend_from_slice(&32u16.to_le_bytes());
        b.extend_from_slice(&STA);
        b
    }

    /// ACK (control, subtype 13): RA only.
    fn ack_frame() -> Vec<u8> {
        let mut b = vec![fc(TYPE_CONTROL, SUBTYPE_ACK), 0x00];
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&AP);
        b
    }

    /// QoS Data, unprotected, to-DS (STA -> AP), carrying an
    /// RFC-1042-shaped LLC/SNAP IPv4 payload — the "ordinary data frame"
    /// case that routes onward to `llc`.
    fn qos_data_frame(protected: bool) -> Vec<u8> {
        let mut flags = FLAG_TO_DS;
        if protected {
            flags |= FLAG_PROTECTED;
        }
        let mut b = vec![fc(TYPE_DATA, 0b1000), flags];
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&AP); // addr1 (BSSID)
        b.extend_from_slice(&STA); // addr2 (TA/SA)
        b.extend_from_slice(&[0x0A, 0, 0, 0, 0, 0x09]); // addr3 (DA)
        b.extend_from_slice(&0x0030u16.to_le_bytes()); // seq_ctl
        b.extend_from_slice(&0u16.to_le_bytes()); // qos_control
        if protected {
            b.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33]);
        } else {
            // LLC/SNAP, RFC 1042, EtherType 0x0800 (IPv4) — 11.1's llc.
            b.extend_from_slice(&[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00]);
        }
        b
    }

    /// QoS Null (data, subtype 12): no body at all.
    fn qos_null_frame() -> Vec<u8> {
        let mut b = vec![fc(TYPE_DATA, 0b1100), FLAG_TO_DS];
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&AP);
        b.extend_from_slice(&STA);
        b.extend_from_slice(&[0x0A, 0, 0, 0, 0, 0x09]);
        b.extend_from_slice(&0x0000u16.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes()); // qos_control
        b
    }

    /// Four-address WDS data frame (to-DS and from-DS both set).
    fn wds_data_frame() -> Vec<u8> {
        let mut b = vec![fc(TYPE_DATA, 0b0000), FLAG_TO_DS | FLAG_FROM_DS];
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&AP);
        b.extend_from_slice(&STA);
        b.extend_from_slice(&[0x0A, 0, 0, 0, 0, 0x09]);
        b.extend_from_slice(&0x0040u16.to_le_bytes());
        b.extend_from_slice(&[0x0A, 0, 0, 0, 0, 0x08]); // addr4
        b.extend_from_slice(&[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00]);
        b
    }

    #[test]
    fn parses_a_beacon_and_extracts_ssid_past_a_leading_ie() {
        let bytes = beacon_frame();
        let parsed = parse(&bytes, Depth::Full).expect("valid beacon");
        assert_eq!(
            parsed.header_len,
            bytes.len(),
            "mgmt consumes the whole frame"
        );
        assert_eq!(parsed.fields.get(ADDR1), Some(&Value::from(&BROADCAST[..])));
        assert_eq!(parsed.fields.get(ADDR2), Some(&Value::from(&AP[..])));
        assert_eq!(parsed.fields.get(ADDR3), Some(&Value::from(&AP[..])));
        assert_eq!(parsed.fields.get(FRAME_TYPE), Some(&Value::U64(0)));
        assert_eq!(
            parsed.fields.get(FRAME_SUBTYPE),
            Some(&Value::U64(u64::from(SUBTYPE_BEACON)))
        );
        assert_eq!(parsed.fields.get(SEQ_NUM), Some(&Value::U64(1)));
        assert_eq!(parsed.fields.get(SSID), Some(&Value::from("TestNet")));
        assert_eq!(parsed.hint, Hint::Terminal);
    }

    #[test]
    fn parses_a_probe_request_ssid_with_no_fixed_fields() {
        let bytes = probe_request_frame();
        let parsed = parse(&bytes, Depth::Full).expect("valid probe request");
        assert_eq!(parsed.fields.get(SSID), Some(&Value::from("TestNet")));
        assert_eq!(parsed.hint, Hint::Terminal);
    }

    #[test]
    fn control_frames_ack_rts_cts_are_terminal_with_no_body() {
        for (bytes, expect_addr2) in [
            (rts_frame(), true),
            (cts_frame(), false),
            (ack_frame(), false),
        ] {
            let parsed = parse(&bytes, Depth::Full).expect("valid control frame");
            assert_eq!(parsed.header_len, bytes.len());
            assert_eq!(parsed.hint, Hint::Terminal);
            assert_eq!(parsed.fields.get(ADDR2).is_some(), expect_addr2);
        }
    }

    #[test]
    fn qos_data_with_a_body_routes_to_llc() {
        let bytes = qos_data_frame(false);
        let parsed = parse(&bytes, Depth::Full).expect("valid QoS data");
        assert_eq!(parsed.header_len, 26, "FC2+Dur2+A1..3(18)+SeqCtl2+QoS2");
        assert_eq!(parsed.hint, Hint::ByProtocol("llc"));
        assert_eq!(parsed.fields.get(QOS_CONTROL), Some(&Value::U64(0)));
    }

    #[test]
    fn protected_data_frame_stops_at_dot11_never_reaching_llc() {
        let bytes = qos_data_frame(true);
        let parsed = parse(&bytes, Depth::Full).expect("valid protected QoS data");
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(
            parsed.fields.get(FLAGS),
            Some(&Value::U64(u64::from(FLAG_TO_DS | FLAG_PROTECTED)))
        );
    }

    #[test]
    fn qos_null_has_no_body_and_is_terminal() {
        let bytes = qos_null_frame();
        let parsed = parse(&bytes, Depth::Full).expect("valid QoS-Null");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.hint, Hint::Terminal);
    }

    #[test]
    fn wds_four_address_frame_extracts_addr4() {
        let bytes = wds_data_frame();
        let parsed = parse(&bytes, Depth::Full).expect("valid WDS frame");
        assert_eq!(
            parsed.fields.get(ADDR4),
            Some(&Value::from(&[0x0A, 0, 0, 0, 0, 0x08][..]))
        );
        assert_eq!(parsed.hint, Hint::ByProtocol("llc"));
    }

    #[test]
    fn structural_depth_omits_full_only_fields() {
        let bytes = beacon_frame();
        let parsed = parse(&bytes, Depth::Structural).expect("valid beacon");
        assert!(parsed.fields.get(FRAME_SUBTYPE).is_some());
        assert_eq!(parsed.fields.get(SSID), None);
    }

    #[test]
    fn keys_depth_carries_only_the_addresses() {
        let bytes = beacon_frame();
        let parsed = parse(&bytes, Depth::Keys).expect("valid beacon");
        assert_eq!(parsed.fields.get(ADDR1), Some(&Value::from(&BROADCAST[..])));
        assert_eq!(parsed.fields.get(FRAME_TYPE), None);
    }

    /// Control and data frames have a fully deterministic `header_len`
    /// (every field along the way is a fixed-size, unconditionally
    /// required read) — so, like `ethernet`/`icmpv4`, any prefix shorter
    /// than that boundary must decline outright.
    #[test]
    fn truncated_control_and_data_frames_decline() {
        for bytes in [
            rts_frame(),
            cts_frame(),
            ack_frame(),
            qos_data_frame(false),
            qos_data_frame(true),
            qos_null_frame(),
            wds_data_frame(),
        ] {
            let header_len = parse(&bytes, Depth::Full).expect("valid frame").header_len;
            for n in 0..header_len {
                assert!(
                    parse(&bytes[..n], Depth::Full).is_err(),
                    "prefix of {n}/{header_len} header bytes must decline"
                );
            }
        }
    }

    /// Management frames only *require* the fixed 24-byte MAC header
    /// (Frame Control, Duration, three addresses, Sequence Control) — a
    /// prefix shorter than that can never parse.
    #[test]
    fn management_frames_require_at_least_the_fixed_mac_header() {
        for bytes in [beacon_frame(), probe_request_frame()] {
            for n in 0..24 {
                assert!(
                    parse(&bytes[..n], Depth::Full).is_err(),
                    "prefix of {n}/24 fixed-header bytes must decline"
                );
            }
        }
    }

    /// Past the fixed header, a management frame's body/IE region is
    /// consumed best-effort (11.2: the whole frame is this Terminal
    /// layer's header, same stance as CDP/LLDP, 11.1) — a body cut short
    /// mid-IE still parses the frame; it just can't find the SSID that
    /// isn't fully there.
    #[test]
    fn beacon_with_a_body_cut_short_still_parses_without_the_ssid() {
        let bytes = beacon_frame();
        let truncated = &bytes[..30]; // fixed header (24) + 6 of 12 fixed fields
        let parsed = parse(truncated, Depth::Full).expect("fixed header still parses");
        assert_eq!(parsed.header_len, truncated.len());
        assert_eq!(parsed.fields.get(SSID), None);
    }

    #[test]
    fn header_is_self_contained() {
        for bytes in [
            beacon_frame(),
            rts_frame(),
            cts_frame(),
            qos_data_frame(false),
        ] {
            let parsed = parse(&bytes, Depth::Full).expect("valid frame");
            let reparsed = parse(&bytes[..parsed.header_len], Depth::Full)
                .expect("header must be self-contained");
            assert_eq!(reparsed.header_len, parsed.header_len);
        }
    }
}
