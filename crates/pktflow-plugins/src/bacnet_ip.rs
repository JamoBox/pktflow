//! BACnet/IP (11.13, D14 citation: ANSI/ASHRAE 135 — *BACnet: A Data
//! Communication Protocol for Building Automation and Control Networks* —
//! Annex J "BACnet/IP", plus Clause 6 (Network Layer Protocol Data Unit,
//! NPDU) and Clause 20 (Application Layer encoding) for the two headers
//! Annex J wraps. ASHRAE sells the standard text itself, so — the same
//! cross-checking approach `dnp3.rs` uses for IEEE 1815-2012 against the
//! public DNP3 Primer — the exact byte/bit layout below is cross-checked
//! against two independent, publicly available implementations: the
//! Wireshark `packet-bvlc.c`/`packet-bacnet.c` dissectors and the
//! open-source `bacnet-stack` project (`bacenum.h`'s service-choice
//! numbers, `apdu.c`'s PDU-type handling), both long-standing
//! interoperability references for this protocol.
//!
//! # Frame shape
//!
//! Every BACnet/IP message starts with a 4-byte BVLC (BACnet Virtual Link
//! Control) header: `type` (1 byte, always `0x81` for Annex J), `function`
//! (1 byte), `length` (2 bytes, big-endian, the *entire* message length
//! including these 4 bytes — self-bounding, the same "authoritative
//! length field" shape `modbus`'s MBAP header and `dnp3`'s link header
//! already use in this task).
//!
//! Three BVLC functions carry an NPDU and are walked further:
//! `Original-Unicast-NPDU` (`0x0A`), `Original-Broadcast-NPDU` (`0x0B`),
//! and `Forwarded-NPDU` (`0x04`, which first repeats 6 bytes of the
//! original source's B/IP address — 4-byte IPv4 + 2-byte port, Annex J.4
//! — ahead of the NPDU, since a BBMD relays on the original sender's
//! behalf). The other eight functions (`BVLC-Result`,
//! `Write/Read-Broadcast-Distribution-Table[-Ack]`,
//! `Register/Read/Delete-Foreign-Device-Table[-Ack/-Entry]`,
//! `Distribute-Broadcast-To-Network`) are BBMD/foreign-device management
//! traffic with their own, unrelated payload shapes — `bvlc_function` is
//! still reported for them, but this dissector does not attempt an NPDU
//! walk on their payload, the same field-depth ceiling `modbus` documents
//! for PDU shapes it can't disambiguate.
//!
//! The NPDU itself (Clause 6): a 1-byte `version` (always `0x01`) and a
//! 1-byte `control`. `control`'s bit 7 is the network-layer-message flag;
//! bit 5 says a destination address follows (`DNET`/`DLEN`/`DADR`, plus a
//! trailing hop count once any destination routing is present); bit 3
//! says a source address follows (`SNET`/`SLEN`/`SADR`); bit 2 is
//! "expecting a reply"; bits 1-0 are network priority. When the
//! network-layer-message flag is set, a 1-byte message type follows (and,
//! for vendor-proprietary message types `>= 0x80`, a 2-byte vendor id) —
//! and there is no APDU at all in that NPDU, so no `apdu_type`/
//! `service_choice` is reported for it (matches the domain spec's own
//! wording: "network-layer-message-only NPDUs have none").
//!
//! Otherwise an APDU follows (Clause 20.1): the top nibble of its first
//! byte names one of eight PDU types (`Confirmed-Request`=0,
//! `Unconfirmed-Request`=1, `SimpleACK`=2, `ComplexACK`=3,
//! `SegmentACK`=4, `Error`=5, `Reject`=6, `Abort`=7). `service_choice` is
//! read best-effort, and only for the four PDU types whose header shape
//! this dissector fully understands: a `Confirmed-Request`/`ComplexACK`
//! skips past its optional segmentation fields (present when the header's
//! low-nibble `SEG` bit is set) before its service-choice byte;
//! `Unconfirmed-Request` and `SimpleACK` have a fixed, unconditional
//! offset. `SegmentACK`/`Error`/`Reject`/`Abort` each have their own,
//! different trailing shape (NAK flag, error-class/error-code, reject/
//! abort reason) with no service choice in it at all — `apdu_type` is
//! still reported for them, `service_choice` is not, a v1 scope limit
//! rather than a decode failure. Once `service_choice` (or, for the four
//! excluded PDU types, the raw APDU bytes) is located, whatever remains
//! up to the BVLC `length` — request/ACK parameters, tagged property
//! values, and so on — is consumed as an opaque tail: BACnet's own
//! tag-length-value application encoding (Clause 20.2) is a full,
//! open-ended walk, out of scope the same way SNMP's varbind list is
//! (D12/D13, `snmp.rs`).
//!
//! # App-stream pattern (06.6)
//! BACnet/IP has no endpoint identity of its own that fits a session
//! shape uniformly: a large share of real traffic is broadcast
//! Who-Is/I-Am discovery (STP/CDP-shaped, no natural "session"), the rest
//! is unicast ReadProperty/WriteProperty (session-shaped). `app =
//! "bacnet"` is a shared constant key, one child stream per UDP stream,
//! the same shape as `dns`/`syslog`/`snmp` — it keeps both traffic shapes
//! in one model rather than branching.

use pktflow_core::{
    ByteReader, Canonicalize, Confidence, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin,
    ParseCtx, ParseError, ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId,
    StreamIdentity, Value,
};

const APP: FieldName = "app";
const BVLC_FUNCTION: FieldName = "bvlc_function";
const NPDU_CONTROL: FieldName = "npdu_control";
const APDU_TYPE: FieldName = "apdu_type";
const SERVICE_CHOICE: FieldName = "service_choice";

/// Annex J.2's fixed BVLC type octet for BACnet/IP.
const BVLC_TYPE: u8 = 0x81;

const FN_RESULT: u8 = 0x00;
const FN_WRITE_BDT: u8 = 0x01;
const FN_READ_BDT: u8 = 0x02;
const FN_READ_BDT_ACK: u8 = 0x03;
const FN_FORWARDED_NPDU: u8 = 0x04;
const FN_REGISTER_FOREIGN_DEVICE: u8 = 0x05;
const FN_READ_FDT: u8 = 0x06;
const FN_READ_FDT_ACK: u8 = 0x07;
const FN_DELETE_FDT_ENTRY: u8 = 0x08;
const FN_DISTRIBUTE_BROADCAST: u8 = 0x09;
const FN_ORIGINAL_UNICAST_NPDU: u8 = 0x0A;
const FN_ORIGINAL_BROADCAST_NPDU: u8 = 0x0B;

/// Every BVLC function Annex J's core clauses define (later addenda's
/// `Secure-BVLL`/`Private-Transfer` extensions are out of v1 scope — no
/// well-known deployment relies on them for the discovery/ReadProperty
/// traffic this dissector targets).
const KNOWN_FUNCTIONS: [u8; 12] = [
    FN_RESULT,
    FN_WRITE_BDT,
    FN_READ_BDT,
    FN_READ_BDT_ACK,
    FN_FORWARDED_NPDU,
    FN_REGISTER_FOREIGN_DEVICE,
    FN_READ_FDT,
    FN_READ_FDT_ACK,
    FN_DELETE_FDT_ENTRY,
    FN_DISTRIBUTE_BROADCAST,
    FN_ORIGINAL_UNICAST_NPDU,
    FN_ORIGINAL_BROADCAST_NPDU,
];

/// Clause 6.1: the NPDU version number is always 1.
const NPDU_VERSION: u8 = 0x01;

const CONTROL_NETWORK_LAYER_MSG: u8 = 0x80;
const CONTROL_DEST_PRESENT: u8 = 0x20;
const CONTROL_SRC_PRESENT: u8 = 0x08;

/// Clause 20.1.2's `segmented-message` flag, the low nibble's top bit on a
/// `Confirmed-Request`/`ComplexACK`'s first byte.
const APDU_SEG_FLAG: u8 = 0x08;

const APDU_CONFIRMED_REQUEST: u8 = 0;
const APDU_UNCONFIRMED_REQUEST: u8 = 1;
const APDU_SIMPLE_ACK: u8 = 2;
const APDU_COMPLEX_ACK: u8 = 3;

static KEY: &[KeyField] = &[KeyField { a: APP, b: None }];
static ROLLUPS: &[RollupSpec] = &[RollupSpec {
    field: SERVICE_CHOICE,
    kind: RollupKind::Accumulate,
}];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: ROLLUPS,
};

pub struct BacnetIp;

impl LayerPlugin for BacnetIp {
    fn name(&self) -> ProtocolName {
        "bacnet_ip"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let bvlc_type = r.u8()?;
        if bvlc_type != BVLC_TYPE {
            return Err(ParseError::Malformed("BVLC type is not 0x81 (BACnet/IP)"));
        }
        let bvlc_function = r.u8()?;
        let declared_len = usize::from(r.u16_be()?);
        if declared_len < 4 {
            return Err(ParseError::Malformed(
                "BVLC length smaller than the BVLC header itself",
            ));
        }

        let mut npdu_control = None;
        let mut apdu_type = None;
        let mut service_choice = None;

        if matches!(
            bvlc_function,
            FN_ORIGINAL_UNICAST_NPDU | FN_ORIGINAL_BROADCAST_NPDU | FN_FORWARDED_NPDU
        ) {
            if bvlc_function == FN_FORWARDED_NPDU {
                // Annex J.4: the original source's B/IP address (4-byte
                // IPv4 + 2-byte UDP port) precedes the relayed NPDU.
                let _original_source_bip = r.take(6)?;
            }

            let version = r.u8()?;
            if version != NPDU_VERSION {
                return Err(ParseError::Malformed("NPDU version is not 1"));
            }
            let control = r.u8()?;
            npdu_control = Some(control);

            if control & CONTROL_DEST_PRESENT != 0 {
                let _dnet = r.u16_be()?;
                let dlen = r.u8()?;
                let _dadr = r.take(usize::from(dlen))?;
            }
            if control & CONTROL_SRC_PRESENT != 0 {
                let _snet = r.u16_be()?;
                let slen = r.u8()?;
                let _sadr = r.take(usize::from(slen))?;
            }
            if control & CONTROL_DEST_PRESENT != 0 {
                // Clause 6.2: a hop count trails the addressing fields
                // whenever routing (a destination) is present at all.
                let _hop_count = r.u8()?;
            }

            if control & CONTROL_NETWORK_LAYER_MSG != 0 {
                let message_type = r.u8()?;
                if message_type >= 0x80 {
                    let _vendor_id = r.u16_be()?;
                }
                // Network-layer message: no APDU follows (module doc).
            } else {
                let apdu_byte0 = r.u8()?;
                let pdu_type = apdu_byte0 >> 4;
                apdu_type = Some(pdu_type);

                match pdu_type {
                    APDU_CONFIRMED_REQUEST => {
                        let segmented = apdu_byte0 & APDU_SEG_FLAG != 0;
                        let _max_segments_and_apdu = r.u8()?;
                        let _invoke_id = r.u8()?;
                        if segmented {
                            let _sequence_number = r.u8()?;
                            let _proposed_window_size = r.u8()?;
                        }
                        service_choice = Some(r.u8()?);
                    }
                    APDU_UNCONFIRMED_REQUEST => {
                        service_choice = Some(r.u8()?);
                    }
                    APDU_SIMPLE_ACK => {
                        let _invoke_id = r.u8()?;
                        service_choice = Some(r.u8()?);
                    }
                    APDU_COMPLEX_ACK => {
                        let segmented = apdu_byte0 & APDU_SEG_FLAG != 0;
                        let _invoke_id = r.u8()?;
                        if segmented {
                            let _sequence_number = r.u8()?;
                            let _proposed_window_size = r.u8()?;
                        }
                        service_choice = Some(r.u8()?);
                    }
                    // SegmentACK/Error/Reject/Abort: each has its own
                    // distinct trailing shape with no service choice in
                    // it (module doc) — apdu_type alone is reported.
                    _ => {}
                }
            }
        }

        let consumed = bytes.len() - r.remaining();
        if declared_len < consumed {
            return Err(ParseError::Malformed(
                "BVLC length shorter than the fields it must contain",
            ));
        }
        // Whatever the BVLC length still promises beyond what was walked
        // above (BDT/FDT entries, APDU service parameters, tagged
        // property values, ...) is opaque payload this dissector doesn't
        // decode, but still accounts for in `header_len` — the same
        // "consume it, don't guess at it" shape `modbus`'s fallback
        // branch uses for PDU shapes it can't disambiguate.
        let _tail = r.take(declared_len - consumed)?;

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(APP, Value::from("bacnet"));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(BVLC_FUNCTION, Value::U64(u64::from(bvlc_function)));
            if let Some(c) = npdu_control {
                fields.insert(NPDU_CONTROL, Value::U64(u64::from(c)));
            }
        }
        if ctx.depth() >= Depth::Full {
            if let Some(t) = apdu_type {
                fields.insert(APDU_TYPE, Value::U64(u64::from(t)));
            }
            if let Some(s) = service_choice {
                fields.insert(SERVICE_CHOICE, Value::U64(u64::from(s)));
            }
        }

        Ok(ParsedLayer {
            header_len: bytes.len() - r.remaining(),
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::UdpPort(47808 /* 0xBAC0 */)]
    }

    // BACnet/IP devices occasionally show up on a non-standard UDP port
    // behind a NAT/forwarder; the BVLC magic type byte plus a defined
    // function code is a cheap, reasonably deterministic signal, the same
    // rationale `dnp3`'s probe documents for its own non-standard-port case.
    fn has_probe(&self) -> bool {
        true
    }

    fn probe(&self, bytes: &[u8], _ctx: &ParseCtx) -> Option<Confidence> {
        let mut r = ByteReader::new(bytes);
        let bvlc_type = r.u8().ok()?;
        let function = r.u8().ok()?;
        let length = r.u16_be().ok()?;
        (bvlc_type == BVLC_TYPE && KNOWN_FUNCTIONS.contains(&function) && usize::from(length) >= 4)
            .then(|| Confidence::new(60))
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
        BacnetIp.parse(bytes, &ParseCtx::new(&[], Depth::Full, &meta))
    }

    fn bvlc(function: u8, npdu_and_after: &[u8]) -> Vec<u8> {
        let length = (4 + npdu_and_after.len()) as u16;
        let mut b = vec![BVLC_TYPE, function];
        b.extend_from_slice(&length.to_be_bytes());
        b.extend_from_slice(npdu_and_after);
        b
    }

    /// Unrestricted Who-Is (Unconfirmed-Request, service choice 8, no
    /// range parameters): NPDU control 0x00 (no routing, local broadcast).
    fn who_is_broadcast() -> Vec<u8> {
        let npdu = [0x01, 0x00, 0x10, 0x08];
        bvlc(FN_ORIGINAL_BROADCAST_NPDU, &npdu)
    }

    /// I-Am response (Unconfirmed-Request, service choice 0) carrying a
    /// device-object-identifier parameter — opaque tail, not decoded.
    fn i_am_broadcast() -> Vec<u8> {
        let mut npdu = vec![0x01, 0x00, 0x10, 0x00];
        npdu.extend_from_slice(&[0xC4, 0x02, 0x00, 0x00, 0x01]); // opaque BACnet-tagged params
        bvlc(FN_ORIGINAL_BROADCAST_NPDU, &npdu)
    }

    /// Unicast Confirmed-Request, ReadProperty (service choice 12),
    /// unsegmented, invoke id 1, plus opaque object/property parameters.
    fn read_property_request() -> Vec<u8> {
        let mut npdu = vec![0x01, 0x04]; // control 0x04: expecting-reply, no routing
        npdu.extend_from_slice(&[0x00, 0x05, 0x01, 0x0C]); // apdu byte0, max-segs/apdu, invoke id, service choice
        npdu.extend_from_slice(&[0x0C, 0x02, 0x00, 0x00, 0x01]); // opaque object-identifier parameter
        bvlc(FN_ORIGINAL_UNICAST_NPDU, &npdu)
    }

    /// The matching ComplexACK (service choice 12), same invoke id.
    fn read_property_ack() -> Vec<u8> {
        let mut npdu = vec![0x01, 0x00]; // control 0x00: response, no routing
        npdu.extend_from_slice(&[0x30, 0x01, 0x0C]); // apdu byte0 (ComplexACK), invoke id, service choice
        npdu.extend_from_slice(&[0x3E, 0x44, 0x00, 0x00, 0x00, 0x00, 0x3F]); // opaque property value
        bvlc(FN_ORIGINAL_UNICAST_NPDU, &npdu)
    }

    /// A segmented Confirmed-Request: sequence number + window size sit
    /// between invoke id and service choice.
    fn segmented_read_property_request() -> Vec<u8> {
        let mut npdu = vec![0x01, 0x04];
        // apdu byte0 with SEG set, max-segs/apdu, invoke id, seq, window, service choice
        npdu.extend_from_slice(&[0x08, 0x05, 0x02, 0x00, 0x10, 0x0C]);
        bvlc(FN_ORIGINAL_UNICAST_NPDU, &npdu)
    }

    /// BVLC-Result: no NPDU at all, just a 2-byte result code payload.
    fn bvlc_result() -> Vec<u8> {
        bvlc(FN_RESULT, &[0x00, 0x00])
    }

    /// A network-layer message (Who-Is-Router-To-Network, type 0x00): the
    /// NPDU's own control byte has the network-layer-message flag set, so
    /// there is no APDU/service choice at all.
    fn network_layer_message() -> Vec<u8> {
        let npdu = [0x01, 0x80, 0x00]; // version, control (bit7 set), message type
        bvlc(FN_ORIGINAL_BROADCAST_NPDU, &npdu)
    }

    #[test]
    fn who_is_extracts_unconfirmed_request_service_choice() {
        let bytes = who_is_broadcast();
        let parsed = parse(&bytes).expect("valid frame");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(APP), Some(&Value::from("bacnet")));
        assert_eq!(
            parsed.fields.get(BVLC_FUNCTION),
            Some(&Value::U64(u64::from(FN_ORIGINAL_BROADCAST_NPDU)))
        );
        assert_eq!(parsed.fields.get(NPDU_CONTROL), Some(&Value::U64(0x00)));
        assert_eq!(
            parsed.fields.get(APDU_TYPE),
            Some(&Value::U64(u64::from(APDU_UNCONFIRMED_REQUEST)))
        );
        assert_eq!(parsed.fields.get(SERVICE_CHOICE), Some(&Value::U64(8)));
    }

    #[test]
    fn i_am_extracts_service_choice_and_leaves_params_opaque() {
        let bytes = i_am_broadcast();
        let parsed = parse(&bytes).expect("valid frame");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.fields.get(SERVICE_CHOICE), Some(&Value::U64(0)));
    }

    #[test]
    fn confirmed_request_read_property_extracts_service_choice() {
        let bytes = read_property_request();
        let parsed = parse(&bytes).expect("valid frame");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(
            parsed.fields.get(APDU_TYPE),
            Some(&Value::U64(u64::from(APDU_CONFIRMED_REQUEST)))
        );
        assert_eq!(parsed.fields.get(SERVICE_CHOICE), Some(&Value::U64(12)));
    }

    #[test]
    fn complex_ack_read_property_extracts_service_choice() {
        let bytes = read_property_ack();
        let parsed = parse(&bytes).expect("valid frame");
        assert_eq!(
            parsed.fields.get(APDU_TYPE),
            Some(&Value::U64(u64::from(APDU_COMPLEX_ACK)))
        );
        assert_eq!(parsed.fields.get(SERVICE_CHOICE), Some(&Value::U64(12)));
    }

    #[test]
    fn segmented_confirmed_request_skips_sequence_and_window_first() {
        let bytes = segmented_read_property_request();
        let parsed = parse(&bytes).expect("valid frame");
        // Honesty check (11.13 acceptance criteria): the segmentation
        // fields this dissector doesn't otherwise report must still be
        // skipped correctly, or service_choice would read the sequence
        // number (0x02) instead of the real value (0x0C).
        assert_eq!(parsed.fields.get(SERVICE_CHOICE), Some(&Value::U64(12)));
    }

    #[test]
    fn bvlc_result_has_no_npdu_fields() {
        let bytes = bvlc_result();
        let parsed = parse(&bytes).expect("valid frame");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(
            parsed.fields.get(BVLC_FUNCTION),
            Some(&Value::U64(u64::from(FN_RESULT)))
        );
        assert_eq!(parsed.fields.get(NPDU_CONTROL), None);
        assert_eq!(parsed.fields.get(APDU_TYPE), None);
        assert_eq!(parsed.fields.get(SERVICE_CHOICE), None);
    }

    #[test]
    fn network_layer_message_has_no_apdu_fields() {
        let bytes = network_layer_message();
        let parsed = parse(&bytes).expect("valid frame");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.fields.get(NPDU_CONTROL), Some(&Value::U64(0x80)));
        assert_eq!(parsed.fields.get(APDU_TYPE), None);
        assert_eq!(parsed.fields.get(SERVICE_CHOICE), None);
    }

    #[test]
    fn wrong_bvlc_type_declines() {
        let mut bytes = who_is_broadcast();
        bytes[0] = 0x82;
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn wrong_npdu_version_declines() {
        let mut bytes = who_is_broadcast();
        bytes[4] = 0x02; // NPDU version byte, right after the 4-byte BVLC header
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn declared_length_shorter_than_header_declines() {
        let mut bytes = who_is_broadcast();
        bytes[2..4].copy_from_slice(&3u16.to_be_bytes());
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn declared_length_shorter_than_walked_fields_declines() {
        // Claims a length that ends inside the APDU it also claims to carry.
        let mut bytes = who_is_broadcast();
        bytes[2..4].copy_from_slice(&5u16.to_be_bytes());
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn truncated_frames_decline() {
        for bytes in [
            who_is_broadcast(),
            i_am_broadcast(),
            read_property_request(),
            read_property_ack(),
            segmented_read_property_request(),
            bvlc_result(),
            network_layer_message(),
        ] {
            let expected_len = parse(&bytes).expect("valid frame").header_len;
            for n in 0..expected_len {
                assert!(
                    parse(&bytes[..n]).is_err(),
                    "expected decline at truncated length {n} of {expected_len}"
                );
            }
        }
    }

    #[test]
    fn probe_scores_confidently_on_good_bytes_and_declines_on_noise() {
        let bytes = who_is_broadcast();
        let meta = PacketMeta {
            timestamp: SystemTime::UNIX_EPOCH,
            caplen: bytes.len(),
            origlen: bytes.len(),
            link_type: LinkType::ETHERNET,
        };
        let ctx = ParseCtx::new(&[], Depth::Full, &meta);
        assert_eq!(BacnetIp.probe(&bytes, &ctx).map(|c| c.get()), Some(60));

        // Right type, undefined function: honesty (11.13's probe rationale).
        let mut undefined_function = bytes.clone();
        undefined_function[1] = 0xFF;
        assert_eq!(BacnetIp.probe(&undefined_function, &ctx), None);

        // Plausible-looking rest of header, wrong type byte.
        let mut wrong_type = bytes.clone();
        wrong_type[0] = 0x80;
        assert_eq!(BacnetIp.probe(&wrong_type, &ctx), None);
    }

    #[test]
    fn depth_ladder_is_monotonic() {
        let bytes = read_property_request();
        let meta = PacketMeta {
            timestamp: SystemTime::UNIX_EPOCH,
            caplen: bytes.len(),
            origlen: bytes.len(),
            link_type: LinkType::ETHERNET,
        };
        let keys = BacnetIp
            .parse(&bytes, &ParseCtx::new(&[], Depth::Keys, &meta))
            .expect("valid");
        assert_eq!(keys.fields.get(APP), Some(&Value::from("bacnet")));
        assert!(keys.fields.get(BVLC_FUNCTION).is_none());
        assert!(keys.fields.get(SERVICE_CHOICE).is_none());

        let structural = BacnetIp
            .parse(&bytes, &ParseCtx::new(&[], Depth::Structural, &meta))
            .expect("valid");
        assert!(structural.fields.get(BVLC_FUNCTION).is_some());
        assert!(structural.fields.get(NPDU_CONTROL).is_some());
        assert!(structural.fields.get(SERVICE_CHOICE).is_none());
    }
}
