//! DHCPv6 (11.3, RFC 8415): the app-stream pattern (06.6), same shape as
//! `dhcp`/`dns` — no endpoint identity of its own, one child stream per UDP
//! stream carrying it, rollups doing the stream-level work. The
//! SOLICIT->ADVERTISE->REQUEST->REPLY (RFC 8415 §18) sequence is the
//! order-sensitive motivating case, exactly DHCPv4's DORA precedent (06.6).
//!
//! Client/server messages (RFC 8415 §8, the shape this plugin parses) open
//! with `msg-type`(1) and `transaction-id`(3, not 4 like DHCPv4's `xid` —
//! DHCPv6 halves it to make room for a 16-bit option space) followed by a
//! flat, unterminated options list (§21.1: `option-code`(2) then
//! `option-len`(2) then data, back to back with no END marker, unlike
//! DHCPv4's TLV). Relay Agent/Server messages (RELAY-FORW/RELAY-REPL, §7.2)
//! replace `transaction-id` with `hop-count`(1), `link-address`(16), and
//! `peer-address`(16) — a different fixed layout this plugin declines
//! rather than misread as bogus options, the same tiering boundary 11.3
//! documents for IPv6 extension headers (relay-chain parsing is a v2
//! ergonomics question, not specified here).

use pktflow_core::{
    ByteReader, Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx,
    ParseError, ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId, StreamIdentity, Value,
};

const APP: FieldName = "app";
const MSG_TYPE: FieldName = "msg_type";
const TRANSACTION_ID: FieldName = "transaction_id";
const CLIENT_DUID: FieldName = "client_duid";
const SERVER_DUID: FieldName = "server_duid";
const REQUESTED_IP: FieldName = "requested_ip";
const PREFERRED_LIFETIME: FieldName = "preferred_lifetime";
const VALID_LIFETIME: FieldName = "valid_lifetime";

// RFC 8415 §7.3 message types (the client/server subset this plugin parses).
const RELAY_FORW: u8 = 12;
const RELAY_REPL: u8 = 13;

// RFC 8415 §21 option codes.
const OPTION_CLIENTID: u16 = 1;
const OPTION_SERVERID: u16 = 2;
const OPTION_IA_NA: u16 = 3;
const OPTION_IA_TA: u16 = 4;
const OPTION_IAADDR: u16 = 5;

static KEY: &[KeyField] = &[KeyField { a: APP, b: None }];
static ROLLUPS: &[RollupSpec] = &[RollupSpec {
    field: MSG_TYPE,
    kind: RollupKind::Series { cap: 64 }, // the SOLICIT..REPLY sequence, in order
}];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: ROLLUPS,
};

/// Walks one IA_NA/IA_TA option's own suboptions (§21.4/§21.5) for its first
/// IA Address suboption (§21.6), returning `(address, preferred, valid)`.
/// Every suboption is walked so a malformed later suboption still declines
/// the whole message — same "walked in full for bounds, first match kept"
/// stance `mld` (11.3) takes for repeated multicast-address records.
fn first_ia_address(data: &[u8]) -> Result<Option<([u8; 16], u32, u32)>, ParseError> {
    let mut r = ByteReader::new(data);
    let mut found = None;
    while r.remaining() > 0 {
        let code = r.u16_be()?;
        let len = usize::from(r.u16_be()?);
        let sub = r.take(len)?;
        if code == OPTION_IAADDR && found.is_none() {
            let mut sr = ByteReader::new(sub);
            let addr: [u8; 16] = sr
                .take(16)?
                .try_into()
                .map_err(|_| ParseError::Malformed("DHCPv6: short IA Address (RFC 8415 §21.6)"))?;
            let preferred = sr.u32_be()?;
            let valid = sr.u32_be()?;
            found = Some((addr, preferred, valid));
        }
    }
    Ok(found)
}

pub struct Dhcpv6;

impl LayerPlugin for Dhcpv6 {
    fn name(&self) -> ProtocolName {
        "dhcpv6"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let msg_type = r.u8()?;
        if msg_type == RELAY_FORW || msg_type == RELAY_REPL {
            return Err(ParseError::Malformed(
                "DHCPv6: relay message layout not supported (RFC 8415 §7.2)",
            ));
        }
        let xid = r.take(3)?;
        let transaction_id = u32::from(xid[0]) << 16 | u32::from(xid[1]) << 8 | u32::from(xid[2]);

        // Options walk (§21.1): code(2) + len(2) + data, back to back with
        // no end marker — the message boundary *is* the terminator, so any
        // leftover bytes that don't form a complete option are a truncated
        // or malformed packet, not padding to skip.
        let mut client_duid = None;
        let mut server_duid = None;
        let mut requested_ip = None;
        let mut preferred_lifetime = None;
        let mut valid_lifetime = None;
        while r.remaining() > 0 {
            let code = r.u16_be()?;
            let len = usize::from(r.u16_be()?);
            let data = r.take(len)?;
            match code {
                OPTION_CLIENTID if client_duid.is_none() => {
                    client_duid = Some(Value::from(data));
                }
                OPTION_SERVERID if server_duid.is_none() => {
                    server_duid = Some(Value::from(data));
                }
                OPTION_IA_NA if requested_ip.is_none() => {
                    let inner = data.get(12..).ok_or(ParseError::Malformed(
                        "DHCPv6: IA_NA shorter than IAID+T1+T2 (RFC 8415 §21.4)",
                    ))?;
                    if let Some((addr, preferred, valid)) = first_ia_address(inner)? {
                        requested_ip = Some(Value::from(&addr[..]));
                        preferred_lifetime = Some(preferred);
                        valid_lifetime = Some(valid);
                    }
                }
                OPTION_IA_TA if requested_ip.is_none() => {
                    let inner = data.get(4..).ok_or(ParseError::Malformed(
                        "DHCPv6: IA_TA shorter than IAID (RFC 8415 §21.5)",
                    ))?;
                    if let Some((addr, preferred, valid)) = first_ia_address(inner)? {
                        requested_ip = Some(Value::from(&addr[..]));
                        preferred_lifetime = Some(preferred);
                        valid_lifetime = Some(valid);
                    }
                }
                _ => {}
            }
        }

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(APP, Value::from("dhcpv6"));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(MSG_TYPE, Value::U64(u64::from(msg_type)));
            fields.insert(TRANSACTION_ID, Value::U64(u64::from(transaction_id)));
        }
        if ctx.depth() >= Depth::Full {
            if let Some(v) = client_duid {
                fields.insert(CLIENT_DUID, v);
            }
            if let Some(v) = server_duid {
                fields.insert(SERVER_DUID, v);
            }
            if let Some(v) = requested_ip {
                fields.insert(REQUESTED_IP, v);
            }
            if let Some(v) = preferred_lifetime {
                fields.insert(PREFERRED_LIFETIME, Value::U64(u64::from(v)));
            }
            if let Some(v) = valid_lifetime {
                fields.insert(VALID_LIFETIME, Value::U64(u64::from(v)));
            }
        }

        Ok(ParsedLayer {
            header_len: bytes.len(),
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::UdpPort(547), RouteId::UdpPort(546)]
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

    fn parse(bytes: &[u8]) -> Result<ParsedLayer, ParseError> {
        let outer = Vec::new();
        let m = meta(bytes.len());
        Dhcpv6.parse(bytes, &ParseCtx::new(&outer, Depth::Full, &m))
    }

    /// SOLICIT with Client Identifier only — the minimal valid message.
    fn solicit_bytes() -> Vec<u8> {
        let mut m = vec![1, 0xBE, 0xEF, 0x01]; // SOLICIT, xid=0xBEEF01
        m.extend_from_slice(&OPTION_CLIENTID.to_be_bytes());
        m.extend_from_slice(&4u16.to_be_bytes());
        m.extend_from_slice(&[0x00, 0x01, 0xAA, 0xBB]); // opaque DUID bytes
        m
    }

    #[test]
    fn solicit_parses_msg_type_and_transaction_id() {
        let bytes = solicit_bytes();
        let parsed = parse(&bytes).expect("SOLICIT parses");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.fields.get(APP), Some(&Value::from("dhcpv6")));
        assert_eq!(parsed.fields.get(MSG_TYPE), Some(&Value::U64(1)));
        assert_eq!(
            parsed.fields.get(TRANSACTION_ID),
            Some(&Value::U64(0xBEEF01))
        );
        assert_eq!(
            parsed.fields.get(CLIENT_DUID),
            Some(&Value::from(&[0x00, 0x01, 0xAA, 0xBB][..]))
        );
        assert_eq!(parsed.hint, Hint::Terminal);
    }

    #[test]
    fn advertise_extracts_server_duid_and_ia_na_address() {
        // ADVERTISE: Server Identifier + IA_NA(IAID, T1, T2, IAADDR(addr,
        // preferred=3600, valid=7200)) — RFC 8415 §21.4/§21.6 shapes.
        let mut m = vec![2, 0x00, 0x00, 0x02]; // ADVERTISE, xid=2
        m.extend_from_slice(&OPTION_SERVERID.to_be_bytes());
        m.extend_from_slice(&3u16.to_be_bytes());
        m.extend_from_slice(&[0x00, 0x02, 0x01]);

        let mut iaaddr = Vec::new();
        iaaddr.extend_from_slice(&OPTION_IAADDR.to_be_bytes());
        iaaddr.extend_from_slice(&24u16.to_be_bytes());
        let addr = [
            0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        iaaddr.extend_from_slice(&addr);
        iaaddr.extend_from_slice(&3600u32.to_be_bytes());
        iaaddr.extend_from_slice(&7200u32.to_be_bytes());

        let mut ia_na_data = Vec::new();
        ia_na_data.extend_from_slice(&0xAABBCCDDu32.to_be_bytes()); // IAID
        ia_na_data.extend_from_slice(&0u32.to_be_bytes()); // T1
        ia_na_data.extend_from_slice(&0u32.to_be_bytes()); // T2
        ia_na_data.extend_from_slice(&iaaddr);

        m.extend_from_slice(&OPTION_IA_NA.to_be_bytes());
        m.extend_from_slice(&(ia_na_data.len() as u16).to_be_bytes());
        m.extend_from_slice(&ia_na_data);

        let parsed = parse(&m).expect("ADVERTISE parses");
        assert_eq!(parsed.header_len, m.len());
        assert_eq!(parsed.fields.get(MSG_TYPE), Some(&Value::U64(2)));
        assert_eq!(
            parsed.fields.get(SERVER_DUID),
            Some(&Value::from(&[0x00, 0x02, 0x01][..]))
        );
        assert_eq!(
            parsed.fields.get(REQUESTED_IP),
            Some(&Value::from(&addr[..]))
        );
        assert_eq!(
            parsed.fields.get(PREFERRED_LIFETIME),
            Some(&Value::U64(3600))
        );
        assert_eq!(parsed.fields.get(VALID_LIFETIME), Some(&Value::U64(7200)));
    }

    #[test]
    fn ia_ta_address_is_read_with_the_shorter_four_byte_skip() {
        // IA_TA has no T1/T2 (§21.5): just a 4-byte IAID before suboptions.
        let mut iaaddr = Vec::new();
        iaaddr.extend_from_slice(&OPTION_IAADDR.to_be_bytes());
        iaaddr.extend_from_slice(&24u16.to_be_bytes());
        let addr = [0xFD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02];
        iaaddr.extend_from_slice(&addr);
        iaaddr.extend_from_slice(&100u32.to_be_bytes());
        iaaddr.extend_from_slice(&200u32.to_be_bytes());

        let mut ia_ta_data = vec![0x11, 0x22, 0x33, 0x44]; // IAID
        ia_ta_data.extend_from_slice(&iaaddr);

        let mut m = vec![5, 0, 0, 3]; // RENEW, xid=3
        m.extend_from_slice(&OPTION_IA_TA.to_be_bytes());
        m.extend_from_slice(&(ia_ta_data.len() as u16).to_be_bytes());
        m.extend_from_slice(&ia_ta_data);

        let parsed = parse(&m).expect("RENEW with IA_TA parses");
        assert_eq!(
            parsed.fields.get(REQUESTED_IP),
            Some(&Value::from(&addr[..]))
        );
        assert_eq!(
            parsed.fields.get(PREFERRED_LIFETIME),
            Some(&Value::U64(100))
        );
        assert_eq!(parsed.fields.get(VALID_LIFETIME), Some(&Value::U64(200)));
    }

    #[test]
    fn relay_forw_and_relay_repl_are_declined() {
        // A relay message's real layout (hop-count + two v6 addresses)
        // would otherwise be misread as transaction-id + bogus options —
        // this plugin declines instead (module doc).
        for relay_type in [RELAY_FORW, RELAY_REPL] {
            let mut m = vec![relay_type, 0]; // hop-count
            m.extend_from_slice(&[0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
            m.extend_from_slice(&[0xFF, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x00, 2]);
            assert!(parse(&m).is_err(), "relay type {relay_type} must decline");
        }
    }

    #[test]
    fn truncated_header_declines() {
        assert!(parse(&[1, 0, 0]).is_err()); // only 3 bytes: no full transaction-id
    }

    #[test]
    fn truncated_option_header_declines() {
        // A dangling 3-byte remainder can't be a full option header (4
        // bytes minimum) — no end marker to fall back on, so this is a
        // truncated/malformed message, not trailing padding.
        let mut m = vec![1, 0, 0, 1];
        m.extend_from_slice(&[0, 1, 0]);
        assert!(parse(&m).is_err());
    }

    #[test]
    fn declared_option_length_longer_than_available_declines() {
        let mut m = vec![1, 0, 0, 1];
        m.extend_from_slice(&OPTION_CLIENTID.to_be_bytes());
        m.extend_from_slice(&10u16.to_be_bytes()); // claims 10 bytes, none follow
        assert!(parse(&m).is_err());
    }

    #[test]
    fn short_ia_na_without_iaid_t1_t2_declines() {
        let mut m = vec![3, 0, 0, 1]; // REQUEST
        m.extend_from_slice(&OPTION_IA_NA.to_be_bytes());
        m.extend_from_slice(&4u16.to_be_bytes()); // shorter than the required 12
        m.extend_from_slice(&[0; 4]);
        assert!(parse(&m).is_err());
    }

    #[test]
    fn ia_na_with_no_iaaddr_suboption_leaves_requested_ip_absent() {
        let mut ia_na_data = vec![0; 12]; // IAID + T1 + T2, no suboptions
        let mut m = vec![3, 0, 0, 1]; // REQUEST
        m.extend_from_slice(&OPTION_IA_NA.to_be_bytes());
        m.extend_from_slice(&(ia_na_data.len() as u16).to_be_bytes());
        m.append(&mut ia_na_data);

        let parsed = parse(&m).expect("bare IA_NA parses");
        assert_eq!(parsed.fields.get(REQUESTED_IP), None);
    }

    #[test]
    fn bare_message_with_no_options_is_valid() {
        let bytes = vec![11, 0, 0, 9]; // INFORMATION-REQUEST, no options
        let parsed = parse(&bytes).expect("bare INFORMATION-REQUEST");
        assert_eq!(parsed.header_len, 4);
        assert_eq!(parsed.fields.get(MSG_TYPE), Some(&Value::U64(11)));
        assert_eq!(parsed.fields.get(CLIENT_DUID), None);
    }
}
