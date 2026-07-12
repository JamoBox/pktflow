//! EtherNet/IP + CIP (11.13, D14 citation: ODVA's *The CIP Networks
//! Library, Volume 1: Common Industrial Protocol (CIP)* for the general
//! CIP message format, and *Volume 2: EtherNet/IP Adaptation of CIP* for
//! the encapsulation protocol this dissector actually parses). Both are
//! ODVA member-distributed documents (no free public download), so — the
//! same cross-checking approach `bacnet_ip.rs` uses for ASHRAE 135 and
//! `dnp3.rs` uses for IEEE 1815-2012 — the exact byte layout below is
//! cross-checked against Wireshark's open-source dissectors:
//! `packet-enip.c` (the `encap_cmd_vals[]`/`NOP`/`LIST_SERVICES`/...
//! command table, and its `ENC_LITTLE_ENDIAN` header field reads) and
//! `packet-cip.c` (`CIP_SC_MASK` (`0x7F`) / `CIP_SC_RESPONSE_MASK`
//! (`0x80`), the service byte's bit split), both long-standing
//! interoperability references for this protocol.
//!
//! # Frame shape
//!
//! Every EtherNet/IP message is a fixed 24-byte encapsulation header
//! followed by `length` bytes of command-specific data — **all
//! multi-byte header fields are little-endian** (Vol 2 §2-3.1), the
//! opposite byte order from the IP/TCP/UDP headers this plugin sits
//! under, and the one detail most worth getting wrong: `command` (UINT),
//! `length` (UINT, byte count of what follows, self-bounding the same
//! way `modbus`'s MBAP length and `bacnet_ip`'s BVLC length already are
//! in this task), `session_handle` (UDINT, `0` until a `RegisterSession`
//! response assigns one), `status` (UDINT, `0` = success), an 8-byte
//! Sender Context (opaque, echoed back by the target, not decoded here),
//! and a reserved `options` UDINT that Vol 2 §2-3.1 requires senders to
//! set to `0` — this dissector's one structural validity check, the same
//! "reserved-must-be-zero" shape `modbus`'s `protocol_id` field already
//! uses in this task.
//!
//! `command` names one of several encapsulation-level operations; this
//! dissector reports it raw and only walks further into the two that
//! carry an actual CIP message: `SendRRData` (`0x6F`, unconnected
//! messaging — the vast majority of explicit-messaging traffic) and
//! `SendUnitData` (`0x70`, connected messaging, once a Class 3 session's
//! Forward Open has established a connection). `RegisterSession`
//! (`0x65`)/`UnRegisterSession` (`0x66`) carry no CIP message at all
//! (their sole `session_handle`-lifecycle purpose is spec-visible from
//! `command`/`status` alone); `ListServices` (`0x04`)/`ListIdentity`
//! (`0x63`)/`ListInterfaces` (`0x64`) return device-discovery metadata
//! this Tier-1 dissector doesn't decode, the same field-depth ceiling
//! `bacnet_ip` documents for its non-NPDU-carrying BVLC functions.
//!
//! # CIP service extraction (best-effort, Full only)
//!
//! `SendRRData`/`SendUnitData`'s data is: Interface Handle (UDINT, `0`
//! for CIP), Timeout (UINT), then a Common Packet Format item list
//! (Vol 2 §2-6): Item Count (UINT) followed by that many `type_id(UINT) +
//! length(UINT) + data` items. Two item types carry a CIP message: an
//! `Unconnected Data Item` (`0x00B2`, `SendRRData`) has the message
//! starting at the item data's first byte; a `Connected Data Item`
//! (`0x00B1`, `SendUnitData`) has a 2-byte Connection Sequence Count
//! ahead of the message instead (Vol 2 §2-6.3.2, the Connected Transport
//! Packet) — this dissector reads past it rather than misreading the
//! sequence count's low byte as the service. A `Null Address Item`
//! (`0x0000`, `SendRRData`'s always-present "no connection" placeholder)
//! and a `Connected Address Item` (`0x00A1`, `SendUnitData`'s connection
//! id) carry no CIP message and are skipped.
//!
//! Once located, a CIP message's first byte is the Service field: bit 7
//! (`0x80`, `CIP_SC_RESPONSE_MASK`) marks a response, bits 0-6 (`0x7F`,
//! `CIP_SC_MASK`) are the service code — `cip_service` reports the byte
//! exactly as it sits on the wire (a request and its response share a
//! code that differs only by that top bit, e.g. `Get_Attribute_Single`
//! request `0x0E` vs. response `0x8E`). Everything past it — the request
//! path (a padded EPATH naming class/instance/attribute) or the
//! response's general-status/data — is CIP's own open-ended per-service
//! encoding, out of v1 scope the same way BACnet's tagged property
//! values are (`bacnet_ip.rs`) and LDAP's post-`bind_dn` payload is
//! (11.7). A CPF list this dissector can't walk cleanly (a bad item
//! length, an item count promising more than the body holds) simply
//! yields no `cip_service` rather than failing the encapsulation parse —
//! the 24-byte header plus `length` is already a fully validated,
//! self-contained frame by that point, so an unreadable CIP payload
//! inside it is a depth-ceiling case, not a malformed one.
//!
//! # Session-stream pattern
//!
//! `session_handle` is a shared qualifier key (like `modbus`'s
//! `unit_id`): a `RegisterSession` response assigns it, and every
//! subsequent `SendRRData`/`SendUnitData` in both directions carries it,
//! so one CIP session stream forms per handle within the parent TCP
//! session — exactly the "session multiplexed inside one transport
//! connection" shape 11.13's domain spec calls out.

use pktflow_core::{
    ByteReader, Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx,
    ParseError, ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId, StreamIdentity, Value,
};

const SESSION_HANDLE: FieldName = "session_handle";
const COMMAND: FieldName = "command";
const LENGTH: FieldName = "length";
const STATUS: FieldName = "status";
const CIP_SERVICE: FieldName = "cip_service";

/// Encapsulation command codes (Vol 2 §2-3.2) this dissector walks
/// further into, verified against `packet-enip.c`'s `encap_cmd_vals[]`.
/// Every other command (`RegisterSession`=`0x65`/`UnRegisterSession`=
/// `0x66`/`ListServices`=`0x04`/`ListIdentity`=`0x63`/... ) is reported
/// via the raw `command` field but carries no CIP message to walk
/// (module doc).
const CMD_SEND_RR_DATA: u16 = 0x006F;
const CMD_SEND_UNIT_DATA: u16 = 0x0070;

/// Common Packet Format item type ids (Vol 2 §2-6), verified against
/// `packet-enip.c`'s `CPF_ITEM_*` constants.
const CPF_UNCONNECTED_DATA: u16 = 0x00B2;
const CPF_CONNECTED_DATA: u16 = 0x00B1;

static KEY: &[KeyField] = &[KeyField {
    a: SESSION_HANDLE,
    b: None, // shared qualifier: one CIP session stream per session_handle,
             // assigned by RegisterSession, within the parent TCP session (11.13)
}];
static ROLLUPS: &[RollupSpec] = &[RollupSpec {
    field: COMMAND,
    kind: RollupKind::Accumulate,
}];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: ROLLUPS,
};

/// Walks a `SendRRData`/`SendUnitData` body's Common Packet Format item
/// list to find the CIP message's leading service byte. Best-effort: any
/// malformed/truncated CPF structure yields `None` rather than failing
/// the whole encapsulation parse (module doc).
fn leading_cip_service(body: &[u8]) -> Option<u8> {
    let mut r = ByteReader::new(body);
    let _interface_handle = r.u32_le().ok()?;
    let _timeout = r.u16_le().ok()?;
    let item_count = r.u16_le().ok()?;
    for _ in 0..item_count {
        let type_id = r.u16_le().ok()?;
        let item_len = usize::from(r.u16_le().ok()?);
        let data = r.take(item_len).ok()?;
        match type_id {
            CPF_UNCONNECTED_DATA => return data.first().copied(),
            // Connected Transport Packet (Vol 2 §2-6.3.2): a 2-byte
            // sequence count precedes the CIP message here, unlike the
            // Unconnected Data Item above.
            CPF_CONNECTED_DATA => return data.get(2).copied(),
            _ => {} // Null/Connected-Address/Sockaddr items carry no CIP message
        }
    }
    None
}

pub struct Enip;

impl LayerPlugin for Enip {
    fn name(&self) -> ProtocolName {
        "enip"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let command = r.u16_le()?;
        let length = usize::from(r.u16_le()?);
        let session_handle = r.u32_le()?;
        let status = r.u32_le()?;
        let _sender_context = r.take(8)?;
        let options = r.u32_le()?;
        if options != 0 {
            return Err(ParseError::Malformed(
                "Encapsulation Options is reserved and must be 0",
            ));
        }

        let body = r.take(length)?;
        let cip_service = matches!(command, CMD_SEND_RR_DATA | CMD_SEND_UNIT_DATA)
            .then(|| leading_cip_service(body))
            .flatten();

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(SESSION_HANDLE, Value::U64(u64::from(session_handle)));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(COMMAND, Value::U64(u64::from(command)));
            fields.insert(LENGTH, Value::U64(length as u64));
            fields.insert(STATUS, Value::U64(u64::from(status)));
        }
        if ctx.depth() >= Depth::Full {
            if let Some(s) = cip_service {
                fields.insert(CIP_SERVICE, Value::U64(u64::from(s)));
            }
        }

        Ok(ParsedLayer {
            header_len: bytes.len() - r.remaining(),
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::TcpPort(44818)]
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
        Enip.parse(bytes, &ParseCtx::new(&[], Depth::Full, &meta))
    }

    /// Builds one encapsulation message: 24-byte little-endian header +
    /// `data` (exactly `data.len()` bytes, matching the `length` field).
    fn encap(command: u16, session_handle: u32, status: u32, data: &[u8]) -> Vec<u8> {
        let mut b = Vec::with_capacity(24 + data.len());
        b.extend_from_slice(&command.to_le_bytes());
        b.extend_from_slice(&(data.len() as u16).to_le_bytes());
        b.extend_from_slice(&session_handle.to_le_bytes());
        b.extend_from_slice(&status.to_le_bytes());
        b.extend_from_slice(&[0u8; 8]); // sender context, opaque
        b.extend_from_slice(&0u32.to_le_bytes()); // options, reserved
        b.extend_from_slice(data);
        b
    }

    /// `RegisterSession` response: Protocol Version = 1, Option Flags = 0
    /// (Vol 2 §2-4.9), session handle freshly assigned by the target.
    fn register_session_response() -> Vec<u8> {
        let data = [1u16.to_le_bytes(), 0u16.to_le_bytes()].concat();
        encap(0x0065 /* RegisterSession */, 0x0000_2A2A, 0, &data)
    }

    /// `SendRRData` carrying an unconnected `Get_Attribute_Single` request
    /// (service `0x0E`) for Identity (class 1) instance 1, attribute 3
    /// (Serial Number) — a real, minimal explicit-messaging request.
    fn send_rr_data_request() -> Vec<u8> {
        let cip_message = [
            0x0E, // service: Get_Attribute_Single, request (bit 7 clear)
            0x02, // request path size, in words
            0x20, 0x01, // 8-bit class segment: class 0x01 (Identity)
            0x24, 0x01, // 8-bit instance segment: instance 1
            0x30, 0x03, // 8-bit attribute segment: attribute 3
        ];
        let mut data = Vec::new();
        data.extend_from_slice(&0u32.to_le_bytes()); // interface handle (CIP)
        data.extend_from_slice(&5u16.to_le_bytes()); // timeout (seconds)
        data.extend_from_slice(&2u16.to_le_bytes()); // item count
        data.extend_from_slice(&0x0000u16.to_le_bytes()); // Null Address Item
        data.extend_from_slice(&0u16.to_le_bytes()); // ...length 0
        data.extend_from_slice(&0x00B2u16.to_le_bytes()); // Unconnected Data Item
        data.extend_from_slice(&(cip_message.len() as u16).to_le_bytes());
        data.extend_from_slice(&cip_message);
        encap(CMD_SEND_RR_DATA, 0x0000_2A2A, 0, &data)
    }

    /// The matching `SendRRData` response: service `0x8E` (request `0x0E`
    /// with the response bit set), success, 4-byte serial number.
    fn send_rr_data_response() -> Vec<u8> {
        let cip_message = [
            0x8E, // service: Get_Attribute_Single, response
            0x00, // reserved
            0x00, // general status: success
            0x00, // additional status size, in words
            0xEF, 0xBE, 0xAD, 0xDE, // serial number data (opaque)
        ];
        let mut data = Vec::new();
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes()); // timeout: n/a on a response
        data.extend_from_slice(&2u16.to_le_bytes());
        data.extend_from_slice(&0x0000u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0x00B2u16.to_le_bytes());
        data.extend_from_slice(&(cip_message.len() as u16).to_le_bytes());
        data.extend_from_slice(&cip_message);
        encap(CMD_SEND_RR_DATA, 0x0000_2A2A, 0, &data)
    }

    /// `SendUnitData` over an already-open Class 3 connection: Connected
    /// Address Item (the connection id) + Connected Data Item, whose data
    /// is a 2-byte sequence count followed by the CIP message.
    fn send_unit_data() -> Vec<u8> {
        let cip_message = [0x81, 0x00, 0x00, 0x00]; // Get_Attribute_All response
        let mut connected_data = Vec::new();
        connected_data.extend_from_slice(&7u16.to_le_bytes()); // sequence count
        connected_data.extend_from_slice(&cip_message);

        let mut data = Vec::new();
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&2u16.to_le_bytes());
        data.extend_from_slice(&0x00A1u16.to_le_bytes()); // Connected Address Item
        data.extend_from_slice(&4u16.to_le_bytes());
        data.extend_from_slice(&0x00C0_FFEEu32.to_le_bytes()); // connection id
        data.extend_from_slice(&0x00B1u16.to_le_bytes()); // Connected Data Item
        data.extend_from_slice(&(connected_data.len() as u16).to_le_bytes());
        data.extend_from_slice(&connected_data);
        encap(CMD_SEND_UNIT_DATA, 0x0000_2A2A, 0, &data)
    }

    /// `ListServices` request: no CIP message at all (encapsulation-level
    /// command), even though it carries a nonzero session handle.
    fn list_services_request() -> Vec<u8> {
        encap(0x0004 /* ListServices */, 0, 0, &[])
    }

    #[test]
    fn register_session_response_extracts_session_and_status() {
        let bytes = register_session_response();
        let parsed = parse(&bytes).expect("valid frame");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(
            parsed.fields.get(SESSION_HANDLE),
            Some(&Value::U64(0x0000_2A2A))
        );
        assert_eq!(parsed.fields.get(COMMAND), Some(&Value::U64(0x0065)));
        assert_eq!(parsed.fields.get(LENGTH), Some(&Value::U64(4)));
        assert_eq!(parsed.fields.get(STATUS), Some(&Value::U64(0)));
        assert_eq!(parsed.fields.get(CIP_SERVICE), None);
    }

    #[test]
    fn send_rr_data_request_extracts_unconnected_service() {
        let bytes = send_rr_data_request();
        let parsed = parse(&bytes).expect("valid frame");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.fields.get(CIP_SERVICE), Some(&Value::U64(0x0E)));
    }

    #[test]
    fn send_rr_data_response_extracts_service_with_response_bit() {
        let bytes = send_rr_data_response();
        let parsed = parse(&bytes).expect("valid frame");
        assert_eq!(parsed.fields.get(CIP_SERVICE), Some(&Value::U64(0x8E)));
    }

    #[test]
    fn send_unit_data_skips_sequence_count_before_service() {
        let bytes = send_unit_data();
        let parsed = parse(&bytes).expect("valid frame");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(
            parsed.fields.get(COMMAND),
            Some(&Value::U64(u64::from(CMD_SEND_UNIT_DATA)))
        );
        // Honesty check (11.13 acceptance criteria): without skipping the
        // 2-byte sequence count first, this would read 0x07 (its low
        // byte) instead of the real service byte 0x81.
        assert_eq!(parsed.fields.get(CIP_SERVICE), Some(&Value::U64(0x81)));
    }

    #[test]
    fn non_cip_commands_report_no_service() {
        let bytes = list_services_request();
        let parsed = parse(&bytes).expect("valid frame");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.fields.get(COMMAND), Some(&Value::U64(0x0004)));
        assert_eq!(parsed.fields.get(CIP_SERVICE), None);
    }

    #[test]
    fn malformed_cpf_list_yields_no_service_but_still_parses() {
        // SendRRData claiming an item count of 5 when the body holds none:
        // the encapsulation frame itself is well-formed (length matches),
        // only the CPF walk inside it runs dry.
        let mut data = Vec::new();
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&5u16.to_le_bytes()); // item count: lies
        let bytes = encap(CMD_SEND_RR_DATA, 1, 0, &data);
        let parsed = parse(&bytes).expect("encapsulation frame is well-formed");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.fields.get(CIP_SERVICE), None);
    }

    #[test]
    fn non_zero_options_declines() {
        let mut bytes = register_session_response();
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes()); // options
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn declared_length_longer_than_available_declines() {
        let mut bytes = send_rr_data_request();
        let too_long = (bytes.len() as u16 - 24 + 1).to_le_bytes();
        bytes[2..4].copy_from_slice(&too_long);
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn truncated_frames_decline() {
        for bytes in [
            register_session_response(),
            send_rr_data_request(),
            send_rr_data_response(),
            send_unit_data(),
            list_services_request(),
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
    fn depth_ladder_is_monotonic() {
        let bytes = send_rr_data_request();
        let meta = PacketMeta {
            timestamp: SystemTime::UNIX_EPOCH,
            caplen: bytes.len(),
            origlen: bytes.len(),
            link_type: LinkType::ETHERNET,
        };
        let keys = Enip
            .parse(&bytes, &ParseCtx::new(&[], Depth::Keys, &meta))
            .expect("valid");
        assert!(keys.fields.get(SESSION_HANDLE).is_some());
        assert!(keys.fields.get(COMMAND).is_none());
        assert!(keys.fields.get(CIP_SERVICE).is_none());

        let structural = Enip
            .parse(&bytes, &ParseCtx::new(&[], Depth::Structural, &meta))
            .expect("valid");
        assert!(structural.fields.get(COMMAND).is_some());
        assert!(structural.fields.get(LENGTH).is_some());
        assert!(structural.fields.get(STATUS).is_some());
        assert!(structural.fields.get(CIP_SERVICE).is_none());
    }

    proptest::proptest! {
        #[test]
        fn parse_never_panics(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..256)) {
            let m = PacketMeta {
                timestamp: SystemTime::UNIX_EPOCH,
                caplen: bytes.len(),
                origlen: bytes.len(),
                link_type: LinkType::ETHERNET,
            };
            let _ = Enip.parse(&bytes, &ParseCtx::new(&[], Depth::Full, &m));
        }
    }
}
