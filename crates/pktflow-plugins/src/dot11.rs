//! 802.11 frame (11.2, IEEE 802.11-2020 §9.2/§9.3, "MAC frame formats"): a
//! second link-layer entry point alongside Ethernet (06.2) — `LinkType`
//! generalizes past DLT_EN10MB with zero engine changes. Claims
//! `DLT_IEEE802_11` (raw 802.11, no radiotap wrapper); the radiotap-wrapped
//! case (`DLT_IEEE802_11_RADIOTAP`) is a separate plugin (`radiotap`) that
//! dispatches here by name via `Hint::ByProtocol("dot11")`.
//!
//! Three frame classes share one wire format family but diverge sharply in
//! header shape and in what happens next:
//!
//! - **Management** (Beacon/Probe/Auth/Assoc/...): always `Terminal` — no
//!   protocol rides on top of a management frame. Beacon, Probe Request,
//!   and Probe Response additionally carry an SSID information element
//!   (§9.4.2.2), which the standard mandates as the *first* element after
//!   each subtype's fixed fields — so reading exactly one bounded element
//!   at that fixed offset is spec-compliant, not a shortcut.
//! - **Control** (ACK/RTS/CTS/...): always `Terminal`, and carries no frame
//!   body at all — the addressing fields alone (RA, and TA where the
//!   subtype defines one) are the entire frame.
//! - **Data**: the interesting case. An unprotected, non-null data frame's
//!   body is LLC/SNAP-encapsulated (§9.2.4.3's "DSAP/SSAP as first two
//!   octets" framing, task 11.1's `llc`) — the same demux Ethernet uses,
//!   proving the two physical media compose through one layer without
//!   either side special-casing the other. A protected frame's body is
//!   encrypted at this layer itself (D12: identify the boundary, don't
//!   decode past it) and a Null-family frame (§9.2.4.1.3, subtype bit 2
//!   set) carries no body regardless — both cases are `Terminal`.
//!
//! The WPA2/WPA3 4-way handshake is *not* a separate plugin here: EAPOL-Key
//! messages 1-4 are ordinary unprotected data frames (the `protected` flag
//! isn't set until keys are installed) whose LLC/SNAP payload carries
//! EtherType `0x888E` — task 11.1's `eapol`, unmodified, reused verbatim:
//! `dot11 ▸ llc ▸ eapol`.
//!
//! Capture-layer note: offline replay of a `DLT_IEEE802_11` file works
//! against the existing capture source unchanged; live monitor-mode capture
//! is a separate, not-yet-built capability (task 07 follow-up), not a
//! blocker for this plugin or its fixture-based tests.
//!
//! Out of v1 scope, documented rather than silently mis-parsed: the
//! `+HTC`/Order bit (802.11-2020 §9.2.4.6) can insert a 4-byte HT Control
//! field before the frame body on QoS data and some management frames;
//! this plugin does not detect or skip it (no fixture in this codebase's
//! corpus sets it), so a `+HTC` frame's body offset would be wrong by 4
//! bytes — a known ceiling, not a silent guess, matching this task's
//! stance on protocol upgrades and other cross-packet/cross-field gaps.

use pktflow_core::{
    ByteReader, Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx,
    ParseError, ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId, StreamIdentity, Value,
};

const ADDR1: FieldName = "addr1";
const ADDR2: FieldName = "addr2";
const ADDR3: FieldName = "addr3";
const ADDR4: FieldName = "addr4";
const FRAME_TYPE: FieldName = "frame_type";
const FRAME_SUBTYPE: FieldName = "frame_subtype";
const FLAGS: FieldName = "flags";
const DURATION: FieldName = "duration";
const SEQ_NUM: FieldName = "seq_num";
const QOS_CONTROL: FieldName = "qos_control";
const SSID: FieldName = "ssid";

/// Frame Control `Type` subfield values (802.11-2020 §9.2.4.1.2, Table 9-1).
const TYPE_MANAGEMENT: u8 = 0;
const TYPE_CONTROL: u8 = 1;
const TYPE_DATA: u8 = 2;

/// Management `Subtype` values this plugin walks into for an SSID element
/// (§9.4.2.2: SSID is the mandated first element after each frame's fixed
/// fields in exactly these three subtypes).
const SUBTYPE_PROBE_REQUEST: u8 = 0x4;
const SUBTYPE_PROBE_RESPONSE: u8 = 0x5;
const SUBTYPE_BEACON: u8 = 0x8;

/// Control `Subtype` values whose format includes a TA (Address 2) field —
/// Block Ack Request, Block Ack, PS-Poll, RTS (802.11-2020 §9.3.1, Figures
/// 9-12–9-15 and 9-8). ACK/CTS/CF-End/CF-End+CF-Ack and Control Wrapper
/// carry only Address 1 (RA); Control Wrapper's carried-frame format is
/// otherwise out of v1 scope.
const CONTROL_SUBTYPES_WITH_ADDR2: [u8; 4] = [0x8, 0x9, 0xA, 0xB];

/// Data `Subtype` bit 3 (`0x08`): QoS Control field present
/// (§9.2.4.1.2/§9.3.2.3.4).
const DATA_SUBTYPE_QOS_BIT: u8 = 0x08;
/// Data `Subtype` bit 2 (`0x04`): a Null-family frame — no frame body,
/// regardless of the QoS bit (§9.2.4.1.3; covers Null, CF-Ack, CF-Poll,
/// CF-Ack+CF-Poll and their QoS counterparts including QoS Null).
const DATA_SUBTYPE_NO_BODY_BIT: u8 = 0x04;

/// SSID information element id (802.11-2020 §9.4.2.2).
const SSID_ELEMENT_ID: u8 = 0;
/// Beacon/Probe Response fixed fields preceding the element list:
/// Timestamp (8) + Beacon Interval (2) + Capability Information (2)
/// (§9.3.3.3, §9.3.3.10).
const BEACON_FIXED_FIELDS_LEN: usize = 12;

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

/// Best-effort text decode for the SSID element: 802.11-2020 §9.4.2.2
/// recommends UTF-8, but a legacy/non-conformant AP is a "decline, don't
/// guess" case for *routing*, not for a diagnostic string field — bytes
/// outside printable ASCII render as `?`, matching LLDP's `decode_text`
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

pub struct Dot11;

impl LayerPlugin for Dot11 {
    fn name(&self) -> ProtocolName {
        "dot11"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);

        // Frame Control (802.11-2020 §9.2.4.1, Figure 9-1): two octets,
        // little-endian bit numbering — the first octet on the wire carries
        // Protocol Version/Type/Subtype, the second carries the flag bits
        // in the exact to_ds/from_ds/more_frag/retry/pwr_mgt/more_data/
        // protected/order order the domain spec's `flags` field names.
        let fc0 = r.u8()?;
        let fc1 = r.u8()?;
        let frame_type = (fc0 >> 2) & 0x03;
        let frame_subtype = (fc0 >> 4) & 0x0F;
        let flags = u64::from(fc1);
        let to_ds = fc1 & 0x01 != 0;
        let from_ds = fc1 & 0x02 != 0;
        let protected = fc1 & 0x40 != 0;

        let duration = r.u16_le()?;
        let addr1 = r.take(6)?;

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Structural {
            fields.insert(FRAME_TYPE, Value::U64(u64::from(frame_type)));
            fields.insert(FRAME_SUBTYPE, Value::U64(u64::from(frame_subtype)));
            fields.insert(FLAGS, Value::U64(flags));
            fields.insert(DURATION, Value::U64(u64::from(duration)));
        }
        if ctx.depth() >= Depth::Keys {
            fields.insert(ADDR1, Value::from(addr1));
        }

        match frame_type {
            TYPE_CONTROL => {
                let addr2 = if CONTROL_SUBTYPES_WITH_ADDR2.contains(&frame_subtype) {
                    Some(r.take(6)?)
                } else {
                    None
                };
                if ctx.depth() >= Depth::Keys {
                    if let Some(a2) = addr2 {
                        fields.insert(ADDR2, Value::from(a2));
                    }
                }
                Ok(ParsedLayer {
                    header_len: bytes.len() - r.remaining(),
                    fields,
                    hint: Hint::Terminal,
                })
            }

            TYPE_MANAGEMENT => {
                let addr2 = r.take(6)?;
                let addr3 = r.take(6)?;
                let seq_ctrl = r.u16_le()?;
                // Sequence Control (§9.2.4.4, Figure 9-6): Fragment Number
                // in the low 4 bits, Sequence Number in the high 12.
                let seq_num = u64::from(seq_ctrl >> 4);

                if ctx.depth() >= Depth::Keys {
                    fields.insert(ADDR2, Value::from(addr2));
                }
                if ctx.depth() >= Depth::Structural {
                    fields.insert(ADDR3, Value::from(addr3));
                    fields.insert(SEQ_NUM, Value::U64(seq_num));
                }

                // SSID: only these three subtypes carry it, and only as
                // the mandated first element (§9.4.2.2 requires it present,
                // possibly zero-length for a wildcard) — reading one
                // bounded element at the fixed offset below is exactly
                // what the standard guarantees, not a heuristic scan, and
                // its absence/truncation is a malformed frame, not a frame
                // with no SSID. Attempted at every depth (header_len must
                // not depend on the caller's requested depth, 01.3),
                // inserted into fields only at Full.
                let mut ssid: Option<String> = None;
                if matches!(
                    frame_subtype,
                    SUBTYPE_BEACON | SUBTYPE_PROBE_REQUEST | SUBTYPE_PROBE_RESPONSE
                ) {
                    if matches!(frame_subtype, SUBTYPE_BEACON | SUBTYPE_PROBE_RESPONSE) {
                        r.take(BEACON_FIXED_FIELDS_LEN)?;
                    }
                    let el_id = r.u8()?;
                    let el_len = r.u8()?;
                    let value = r.take(usize::from(el_len))?;
                    if el_id == SSID_ELEMENT_ID {
                        ssid = Some(decode_ssid(value));
                    }
                }
                if ctx.depth() >= Depth::Full {
                    if let Some(s) = ssid {
                        fields.insert(SSID, Value::from(s.as_str()));
                    }
                }

                Ok(ParsedLayer {
                    header_len: bytes.len() - r.remaining(),
                    fields,
                    hint: Hint::Terminal,
                })
            }

            TYPE_DATA => {
                let addr2 = r.take(6)?;
                let addr3 = r.take(6)?;
                let seq_ctrl = r.u16_le()?;
                let seq_num = u64::from(seq_ctrl >> 4);

                // Address 4 (WDS only, §9.2.4.5.4): present iff both To DS
                // and From DS are set.
                let addr4 = if to_ds && from_ds {
                    Some(r.take(6)?)
                } else {
                    None
                };
                // QoS Control (§9.2.4.5.5, Figure 9-9): present for QoS
                // data subtypes (subtype bit 3 set), immediately after
                // Address 4 if present.
                let has_qos = frame_subtype & DATA_SUBTYPE_QOS_BIT != 0;
                let qos_control = if has_qos { Some(r.u16_le()?) } else { None };

                if ctx.depth() >= Depth::Keys {
                    fields.insert(ADDR2, Value::from(addr2));
                }
                if ctx.depth() >= Depth::Structural {
                    fields.insert(ADDR3, Value::from(addr3));
                    fields.insert(SEQ_NUM, Value::U64(seq_num));
                }
                if ctx.depth() >= Depth::Full {
                    if let Some(a4) = addr4 {
                        fields.insert(ADDR4, Value::from(a4));
                    }
                    if let Some(qc) = qos_control {
                        fields.insert(QOS_CONTROL, Value::U64(u64::from(qc)));
                    }
                }

                let no_body = frame_subtype & DATA_SUBTYPE_NO_BODY_BIT != 0;
                let hint = if protected || no_body {
                    Hint::Terminal
                } else {
                    Hint::ByProtocol("llc")
                };

                Ok(ParsedLayer {
                    header_len: bytes.len() - r.remaining(),
                    fields,
                    hint,
                })
            }

            // Extension frame types (S1G etc., 802.11-2020's later
            // amendments) are not modeled in v1 — decline rather than
            // guess at an unfamiliar frame shape.
            _ => Err(ParseError::Malformed(
                "dot11: unsupported frame type (Extension/reserved)",
            )),
        }
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::LinkType(105 /* DLT_IEEE802_11 */)]
    }

    // No probe: the link entry is explicit by link type (11.2), same as
    // Ethernet (06.2). Radiotap-wrapped frames arrive by `ByProtocol`,
    // also explicit — never through heuristic fallback.

    fn stream_identity(&self) -> Option<&StreamIdentity> {
        Some(&IDENTITY)
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use pktflow_core::{LinkType, PacketMeta};

    use super::*;

    const AP: [u8; 6] = [0x02, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E];
    const STA: [u8; 6] = [0x00, 0x1B, 0x44, 0x11, 0x3A, 0xB7];
    const BSSID: [u8; 6] = AP;

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

    fn parse_at(bytes: &[u8], depth: Depth) -> Result<ParsedLayer, ParseError> {
        let m = meta(bytes.len());
        Dot11.parse(bytes, &ctx(depth, &m))
    }

    fn parse(bytes: &[u8]) -> Result<ParsedLayer, ParseError> {
        parse_at(bytes, Depth::Full)
    }

    /// Beacon frame: FC(type=Management,subtype=Beacon)=0x80, flags=0x00,
    /// duration, addr1=broadcast, addr2=AP, addr3=BSSID, seq_ctrl, then the
    /// fixed fields (timestamp/interval/capability) and an SSID element.
    fn beacon_frame(ssid: &[u8]) -> Vec<u8> {
        let mut b = vec![0x80, 0x00]; // Management / Beacon
        b.extend_from_slice(&0x0000u16.to_le_bytes()); // duration
        b.extend_from_slice(&[0xFF; 6]); // addr1: broadcast
        b.extend_from_slice(&AP); // addr2: TA
        b.extend_from_slice(&BSSID); // addr3: BSSID
        b.extend_from_slice(&0x1230u16.to_le_bytes()); // seq_ctrl: frag 0, seq 0x123
        b.extend_from_slice(&[0u8; 8]); // timestamp
        b.extend_from_slice(&0x0064u16.to_le_bytes()); // beacon interval
        b.extend_from_slice(&0x0421u16.to_le_bytes()); // capability info
        b.push(SSID_ELEMENT_ID);
        b.push(u8::try_from(ssid.len()).expect("ssid fits"));
        b.extend_from_slice(ssid);
        b
    }

    /// Probe Request: no fixed fields before the element list, SSID first.
    fn probe_request_frame(ssid: &[u8]) -> Vec<u8> {
        let mut b = vec![0x40, 0x00]; // Management / Probe Request
        b.extend_from_slice(&0x0000u16.to_le_bytes());
        b.extend_from_slice(&BSSID); // addr1: AP (unicast probe) or broadcast
        b.extend_from_slice(&STA); // addr2: TA
        b.extend_from_slice(&[0xFF; 6]); // addr3: broadcast BSSID (wildcard)
        b.extend_from_slice(&0x0010u16.to_le_bytes());
        b.push(SSID_ELEMENT_ID);
        b.push(u8::try_from(ssid.len()).expect("ssid fits"));
        b.extend_from_slice(ssid);
        b
    }

    /// Authentication management frame (subtype 0xB): no SSID element, body
    /// left opaque (auth algorithm/seq/status fields not modeled in v1).
    fn authentication_frame() -> Vec<u8> {
        let mut b = vec![0xB0, 0x00]; // Management / Authentication
        b.extend_from_slice(&0x013Au16.to_le_bytes()); // duration
        b.extend_from_slice(&AP); // addr1
        b.extend_from_slice(&STA); // addr2
        b.extend_from_slice(&BSSID); // addr3
        b.extend_from_slice(&0x0050u16.to_le_bytes()); // seq_ctrl
        b.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x00, 0x00]); // opaque auth body
        b
    }

    fn ack_frame() -> Vec<u8> {
        let mut b = vec![0xD4, 0x00]; // Control / ACK
        b.extend_from_slice(&0x0000u16.to_le_bytes());
        b.extend_from_slice(&STA); // addr1: RA only
        b
    }

    fn cts_frame() -> Vec<u8> {
        let mut b = vec![0xC4, 0x00]; // Control / CTS
        b.extend_from_slice(&0x00B4u16.to_le_bytes());
        b.extend_from_slice(&STA);
        b
    }

    fn rts_frame() -> Vec<u8> {
        let mut b = vec![0xB4, 0x00]; // Control / RTS
        b.extend_from_slice(&0x013Au16.to_le_bytes());
        b.extend_from_slice(&AP); // addr1: RA
        b.extend_from_slice(&STA); // addr2: TA
        b
    }

    /// Unprotected QoS data frame: from-DS set (AP -> STA), non-null, so it
    /// hints onward to `llc`.
    fn qos_data_frame(protected: bool, body: &[u8]) -> Vec<u8> {
        let mut fc1 = 0x02; // from_ds = 1
        if protected {
            fc1 |= 0x40;
        }
        let mut b = vec![0x88, fc1]; // Data / QoS Data
        b.extend_from_slice(&0x002Cu16.to_le_bytes());
        b.extend_from_slice(&STA); // addr1: RA/DA
        b.extend_from_slice(&AP); // addr2: TA/BSSID
        b.extend_from_slice(&BSSID); // addr3: SA (from-DS)
        b.extend_from_slice(&0x0470u16.to_le_bytes()); // seq_ctrl
        b.extend_from_slice(&0x0000u16.to_le_bytes()); // qos_control
        b.extend_from_slice(body);
        b
    }

    fn qos_null_frame() -> Vec<u8> {
        let mut b = vec![0xC8, 0x02]; // Data / QoS Null, from_ds=1
        b.extend_from_slice(&0x0000u16.to_le_bytes());
        b.extend_from_slice(&STA);
        b.extend_from_slice(&AP);
        b.extend_from_slice(&BSSID);
        b.extend_from_slice(&0x0480u16.to_le_bytes());
        b.extend_from_slice(&0x0000u16.to_le_bytes()); // qos_control
        b
    }

    /// LLC/SNAP-encapsulated ARP request (matches `llc`'s RFC-1042 branch),
    /// the ordinary case an unprotected data frame's `ByProtocol("llc")`
    /// hint hands off to.
    fn llc_snap_arp_body() -> Vec<u8> {
        vec![0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x06]
    }

    // ---- management ----

    #[test]
    fn beacon_extracts_ssid_and_addressing_fields() {
        let bytes = beacon_frame(b"ExampleNet");
        let parsed = parse(&bytes).expect("valid beacon");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(FRAME_TYPE), Some(&Value::U64(0)));
        assert_eq!(parsed.fields.get(FRAME_SUBTYPE), Some(&Value::U64(0x8)));
        assert_eq!(parsed.fields.get(ADDR1), Some(&Value::from(&[0xFF; 6][..])));
        assert_eq!(parsed.fields.get(ADDR2), Some(&Value::from(&AP[..])));
        assert_eq!(parsed.fields.get(ADDR3), Some(&Value::from(&BSSID[..])));
        assert_eq!(parsed.fields.get(SEQ_NUM), Some(&Value::U64(0x123)));
        assert_eq!(parsed.fields.get(SSID), Some(&Value::from("ExampleNet")));
    }

    #[test]
    fn probe_request_has_no_fixed_fields_before_ssid() {
        let bytes = probe_request_frame(b"guestwifi");
        let parsed = parse(&bytes).expect("valid probe request");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.fields.get(SSID), Some(&Value::from("guestwifi")));
    }

    #[test]
    fn wildcard_zero_length_ssid_is_an_empty_string_not_absent() {
        let bytes = beacon_frame(b"");
        let parsed = parse(&bytes).expect("valid beacon");
        assert_eq!(parsed.fields.get(SSID), Some(&Value::from("")));
    }

    #[test]
    fn non_ssid_bearing_management_subtype_has_no_ssid_field() {
        // Auth's algorithm/sequence/status fields aren't modeled in v1
        // (D13 tiering): header_len covers only the fixed 24-byte
        // addressing header, same as ICMPv4's fixed-header-plus-opaque-
        // remainder stance (06.3) — the body isn't guessed at.
        let bytes = authentication_frame();
        let parsed = parse(&bytes).expect("valid authentication frame");
        assert_eq!(parsed.header_len, 24);
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(SSID), None);
        assert_eq!(parsed.fields.get(FRAME_SUBTYPE), Some(&Value::U64(0xB)));
    }

    #[test]
    fn structural_depth_omits_ssid() {
        let bytes = beacon_frame(b"ExampleNet");
        let parsed = parse_at(&bytes, Depth::Structural).expect("valid beacon");
        assert_eq!(parsed.fields.get(SEQ_NUM), Some(&Value::U64(0x123)));
        assert_eq!(parsed.fields.get(SSID), None);
        // header_len must not depend on requested depth (01.3).
        assert_eq!(parsed.header_len, bytes.len());
    }

    #[test]
    fn keys_depth_still_extracts_addr1_addr2() {
        let bytes = beacon_frame(b"ExampleNet");
        let parsed = parse_at(&bytes, Depth::Keys).expect("valid beacon");
        assert_eq!(parsed.fields.get(ADDR1), Some(&Value::from(&[0xFF; 6][..])));
        assert_eq!(parsed.fields.get(ADDR2), Some(&Value::from(&AP[..])));
        assert_eq!(parsed.fields.get(ADDR3), None);
    }

    #[test]
    fn beacon_with_malformed_ssid_element_length_declines() {
        let mut bytes = beacon_frame(b"x");
        let ssid_len_offset = bytes.len() - 1 /* 'x' */ - 1 /* len byte */;
        bytes[ssid_len_offset] = 200; // claims far more than present
        assert!(parse(&bytes).is_err());
    }

    // ---- control ----

    #[test]
    fn ack_is_terminal_with_only_addr1() {
        let bytes = ack_frame();
        let parsed = parse(&bytes).expect("valid ACK");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(ADDR1), Some(&Value::from(&STA[..])));
        assert_eq!(parsed.fields.get(ADDR2), None);
    }

    #[test]
    fn cts_is_terminal_with_only_addr1() {
        let bytes = cts_frame();
        let parsed = parse(&bytes).expect("valid CTS");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(ADDR2), None);
    }

    #[test]
    fn rts_is_terminal_with_addr1_and_addr2() {
        let bytes = rts_frame();
        let parsed = parse(&bytes).expect("valid RTS");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(ADDR1), Some(&Value::from(&AP[..])));
        assert_eq!(parsed.fields.get(ADDR2), Some(&Value::from(&STA[..])));
    }

    // ---- data ----

    #[test]
    fn unprotected_qos_data_frame_hints_to_llc() {
        let mut bytes = qos_data_frame(false, &[]);
        bytes.extend_from_slice(&llc_snap_arp_body());
        let parsed = parse(&bytes).expect("valid QoS data frame");
        assert_eq!(parsed.header_len, bytes.len() - llc_snap_arp_body().len());
        assert_eq!(parsed.hint, Hint::ByProtocol("llc"));
        assert_eq!(parsed.fields.get(ADDR1), Some(&Value::from(&STA[..])));
        assert_eq!(parsed.fields.get(ADDR2), Some(&Value::from(&AP[..])));
        assert_eq!(parsed.fields.get(ADDR3), Some(&Value::from(&BSSID[..])));
        assert_eq!(parsed.fields.get(QOS_CONTROL), Some(&Value::U64(0)));
    }

    #[test]
    fn protected_data_frame_stops_at_dot11_never_reaching_llc() {
        let mut bytes = qos_data_frame(true, &[]);
        bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00]); // opaque ciphertext
        let parsed = parse(&bytes).expect("valid protected data frame");
        assert_eq!(
            parsed.header_len,
            bytes.len() - 8,
            "header stops before the ciphertext, which is never handed to llc"
        );
        assert_eq!(parsed.hint, Hint::Terminal);
    }

    #[test]
    fn qos_null_data_frame_has_no_body_and_is_terminal() {
        let bytes = qos_null_frame();
        let parsed = parse(&bytes).expect("valid QoS Null frame");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(QOS_CONTROL), Some(&Value::U64(0)));
    }

    #[test]
    fn four_address_wds_frame_extracts_addr4() {
        let mut b = vec![0x08, 0x03]; // Data, to_ds=1, from_ds=1
        b.extend_from_slice(&0x0000u16.to_le_bytes());
        b.extend_from_slice(&STA); // addr1: RA
        b.extend_from_slice(&AP); // addr2: TA
        b.extend_from_slice(&BSSID); // addr3
        b.extend_from_slice(&0x0000u16.to_le_bytes()); // seq_ctrl
        let addr4 = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        b.extend_from_slice(&addr4); // addr4 (WDS)
        b.extend_from_slice(&llc_snap_arp_body());

        let parsed = parse(&b).expect("valid WDS frame");
        assert_eq!(parsed.fields.get(ADDR4), Some(&Value::from(&addr4[..])));
        assert_eq!(parsed.hint, Hint::ByProtocol("llc"));
    }

    // ---- 4-way handshake composition (dot11 ▸ llc ▸ eapol) ----

    #[test]
    fn unprotected_eapol_key_data_frame_hints_to_llc_which_would_reach_eapol() {
        // dot11 header + LLC/SNAP(EtherType 0x888E) + a minimal EAPOL-Start
        // body: proves the frame ends up exactly where `llc`'s own
        // RFC-1042 EtherType-space routing (11.1) would carry it to
        // `eapol` (11.1), unmodified — the cross-medium composition claim.
        let mut bytes = qos_data_frame(false, &[]);
        bytes.extend_from_slice(&[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E]); // LLC/SNAP -> EAPOL
        bytes.extend_from_slice(&[0x01, 0x01, 0x00, 0x00]); // EAPOL-Start
        let parsed = parse(&bytes).expect("valid unprotected EAPOL-over-802.11 frame");
        assert_eq!(parsed.hint, Hint::ByProtocol("llc"));
        assert!(!protected_flag(&bytes), "handshake frames are unprotected");
    }

    fn protected_flag(bytes: &[u8]) -> bool {
        bytes[1] & 0x40 != 0
    }

    // ---- truncation ----

    /// Fixtures whose `header_len` equals their full byte length — every
    /// shorter prefix must decline, no exceptions.
    #[test]
    fn truncated_frames_decline() {
        let fixtures = [
            beacon_frame(b"ExampleNet"),
            probe_request_frame(b"guestwifi"),
            ack_frame(),
            cts_frame(),
            rts_frame(),
            qos_null_frame(),
        ];
        for bytes in fixtures {
            for n in 0..bytes.len() {
                assert!(
                    parse(&bytes[..n]).is_err(),
                    "prefix of {n}/{} bytes must decline",
                    bytes.len()
                );
            }
        }
    }

    /// Non-SSID-bearing management subtypes only require the fixed
    /// 24-byte addressing header (§9.3.3.1's opaque-body stance, above):
    /// prefixes shorter than that decline, but a capture truncated right
    /// after the header — cutting off the (unmodeled) auth body — still
    /// parses, matching ICMPv4's fixed-header/opaque-remainder precedent.
    #[test]
    fn authentication_frame_only_requires_the_fixed_header() {
        let bytes = authentication_frame();
        for n in 0..24 {
            assert!(parse(&bytes[..n]).is_err(), "prefix of {n} bytes declines");
        }
        for n in 24..=bytes.len() {
            assert!(
                parse(&bytes[..n]).is_ok(),
                "prefix of {n} bytes has the full fixed header"
            );
        }
    }

    /// Symmetric case for data frames: the LLC/SNAP body handed off via
    /// `ByProtocol("llc")` is never touched by `dot11` itself, so
    /// truncating it doesn't affect whether `dot11`'s own header parses.
    #[test]
    fn qos_data_frame_only_requires_its_own_fixed_header() {
        let mut bytes = qos_data_frame(false, &[]);
        let header_len = bytes.len();
        bytes.extend_from_slice(&llc_snap_arp_body());
        for n in 0..header_len {
            assert!(parse(&bytes[..n]).is_err(), "prefix of {n} bytes declines");
        }
        for n in header_len..=bytes.len() {
            assert!(
                parse(&bytes[..n]).is_ok(),
                "prefix of {n} bytes has the full fixed header"
            );
        }
    }

    #[test]
    fn extension_frame_type_declines() {
        let mut b = vec![0x0C, 0x00]; // type=3 (Extension), subtype=0
        b.extend_from_slice(&0x0000u16.to_le_bytes());
        b.extend_from_slice(&STA);
        assert!(parse(&b).is_err());
    }

    // ---- claims / identity ----

    #[test]
    fn claims_the_802_11_link_type() {
        assert_eq!(Dot11.claims(), &[RouteId::LinkType(105)]);
    }

    #[test]
    fn declares_endpoint_sort_identity_on_addr1_addr2() {
        let identity = Dot11.stream_identity().expect("dot11 forms a stream");
        assert_eq!(identity.key.len(), 1);
        assert_eq!(identity.key[0].a, ADDR1);
        assert_eq!(identity.key[0].b, Some(ADDR2));
        assert!(matches!(identity.canonicalize, Canonicalize::EndpointSort));
        assert_eq!(identity.rollups.len(), 1);
        assert_eq!(identity.rollups[0].field, FRAME_SUBTYPE);
        assert_eq!(identity.rollups[0].kind, RollupKind::Accumulate);
    }
}
