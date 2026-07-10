//! CDP (11.1, Cisco Discovery Protocol — *no open standard*; Cisco's
//! published CDP protocol reference is the closest authoritative
//! document, corroborated by the widely-deployed Wireshark `cdp`
//! dissector). A 4-byte common header (version, TTL, checksum) followed
//! by a strictly-bounded TLV walk — same discipline as DHCP's option walk
//! (06.6). Neighbor announcement, not a two-party conversation: no
//! stream of its own, same stance as `stp`/`lldp`.

use pktflow_core::{
    ByteReader, Depth, FieldMap, FieldName, Hint, LayerPlugin, ParseCtx, ParseError, ParsedLayer,
    ProtocolName, RouteId, StreamIdentity, Value,
};

const VERSION: FieldName = "version";
const TTL: FieldName = "ttl";
const CHECKSUM: FieldName = "checksum";
const DEVICE_ID: FieldName = "device_id";
const PORT_ID: FieldName = "port_id";
const PLATFORM: FieldName = "platform";
const CAPABILITIES: FieldName = "capabilities";
const NATIVE_VLAN: FieldName = "native_vlan";
const IP_ADDRESS: FieldName = "ip_address";

const TLV_DEVICE_ID: u16 = 0x0001;
const TLV_ADDRESS: u16 = 0x0002;
const TLV_PORT_ID: u16 = 0x0003;
const TLV_CAPABILITIES: u16 = 0x0004;
const TLV_PLATFORM: u16 = 0x0006;
const TLV_NATIVE_VLAN: u16 = 0x000A;

/// OUI 00-00-0C (Cisco), PID 0x2000 (CDP) under the SNAP `snap_pid`
/// Custom space `llc` (11.1) mints.
const OUI_CISCO: u64 = 0x00_000C;
const PID_CDP: u64 = 0x2000;

/// Best-effort text decode, same fallback as LLDP's optional strings
/// (11.1): non-graphic bytes render as `?` rather than failing the parse
/// over one cosmetic field.
fn decode_text(bytes: &[u8]) -> String {
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

/// The first entry of the Address TLV's nested address list (Cisco's
/// format: a 4-byte count, then per-address `protocol_type`(1) +
/// `protocol_length`(1) + `protocol`(variable) + `address_length`(2) +
/// `address`(variable)) — best-effort; a malformed nested structure just
/// means no `ip_address` field, not a failed CDP parse (it's a Full-only
/// supplementary field, not load-bearing for recognizing the protocol).
fn first_address(value: &[u8]) -> Option<&[u8]> {
    let mut r = ByteReader::new(value);
    let count = r.u32_be().ok()?;
    if count == 0 {
        return None;
    }
    let protocol_length = usize::from(r.u8().ok()?);
    r.u8().ok()?; // protocol_type
    r.take(protocol_length).ok()?;
    let address_length = usize::from(r.u16_be().ok()?);
    r.take(address_length).ok()
}

/// TLVs accumulated by the walk — an owned `Option` per field, so a
/// missing/duplicate/malformed-nested TLV just leaves it unset rather
/// than aborting the message.
#[derive(Default)]
struct Tlvs {
    device_id: Option<String>,
    port_id: Option<String>,
    platform: Option<String>,
    capabilities: Option<u32>,
    native_vlan: Option<u16>,
    ip_address: Option<Vec<u8>>,
}

impl Tlvs {
    fn record(&mut self, tlv_type: u16, value: &[u8]) {
        match tlv_type {
            TLV_DEVICE_ID => self.device_id = Some(decode_text(value)),
            TLV_PORT_ID => self.port_id = Some(decode_text(value)),
            TLV_PLATFORM => self.platform = Some(decode_text(value)),
            TLV_CAPABILITIES if value.len() == 4 => {
                self.capabilities =
                    Some(u32::from_be_bytes([value[0], value[1], value[2], value[3]]));
            }
            TLV_NATIVE_VLAN if value.len() == 2 => {
                self.native_vlan = Some(u16::from_be_bytes([value[0], value[1]]));
            }
            TLV_ADDRESS => {
                if let Some(addr) = first_address(value) {
                    self.ip_address = Some(addr.to_vec());
                }
            }
            _ => {}
        }
    }

    fn insert_full_fields(&self, fields: &mut FieldMap) {
        if let Some(v) = &self.device_id {
            fields.insert(DEVICE_ID, Value::from(v.as_str()));
        }
        if let Some(v) = &self.port_id {
            fields.insert(PORT_ID, Value::from(v.as_str()));
        }
        if let Some(v) = &self.platform {
            fields.insert(PLATFORM, Value::from(v.as_str()));
        }
        if let Some(v) = self.capabilities {
            fields.insert(CAPABILITIES, Value::U64(u64::from(v)));
        }
        if let Some(v) = self.native_vlan {
            fields.insert(NATIVE_VLAN, Value::U64(u64::from(v)));
        }
        if let Some(v) = &self.ip_address {
            fields.insert(IP_ADDRESS, Value::from(v.as_slice()));
        }
    }
}

pub struct Cdp;

impl LayerPlugin for Cdp {
    fn name(&self) -> ProtocolName {
        "cdp"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let version = r.u8()?;
        let ttl = r.u8()?;
        let checksum = r.u16_be()?;

        let mut tlvs = Tlvs::default();
        // Bounded TLV walk: type+length read before advancing, exactly
        // like DHCP's option walk. CDP has no explicit end-of-message
        // TLV, so two clean stopping points are structural rather than
        // guessed: fewer than 4 bytes remain (too short for even a TLV
        // header — Ethernet minimum-frame padding, harmless), or the
        // next TLV reads as type 0 / length 0 (no assigned CDP TLV is
        // ever either, so an all-zero header is unambiguously padding,
        // never a legitimate TLV this loop would otherwise misparse).
        let mut header_len = bytes.len() - r.remaining();
        while r.remaining() >= 4 {
            let before = r.remaining();
            let tlv_type = r.u16_be()?;
            let tlv_len = r.u16_be()?;
            if tlv_type == 0 && tlv_len == 0 {
                header_len = bytes.len() - before;
                break;
            }
            if tlv_len < 4 {
                return Err(ParseError::Malformed(
                    "CDP: TLV length shorter than its own header",
                ));
            }
            let value = r.take(usize::from(tlv_len) - 4)?;
            tlvs.record(tlv_type, value);
            header_len = bytes.len() - r.remaining();
        }

        // Every real CDP announcement carries a Device ID TLV — it's
        // effectively the message's identity. Requiring it rules out the
        // otherwise-structurally-valid-looking "just the 4-byte common
        // header, nothing else" case, which is truncation (rule 1), not
        // a legitimate empty CDP message.
        if tlvs.device_id.is_none() {
            return Err(ParseError::Malformed("CDP: missing Device ID TLV"));
        }

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Structural {
            fields.insert(VERSION, Value::U64(u64::from(version)));
            fields.insert(TTL, Value::U64(u64::from(ttl)));
            fields.insert(CHECKSUM, Value::U64(u64::from(checksum)));
        }
        if ctx.depth() >= Depth::Full {
            tlvs.insert_full_fields(&mut fields);
        }

        Ok(ParsedLayer {
            header_len,
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::Custom {
            space: "snap_pid",
            id: (OUI_CISCO << 16) | PID_CDP,
        }]
    }

    fn stream_identity(&self) -> Option<&StreamIdentity> {
        None
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

    fn tlv(t: u16, value: &[u8]) -> Vec<u8> {
        let mut out = t.to_be_bytes().to_vec();
        out.extend_from_slice(
            &(u16::try_from(4 + value.len()).expect("cdp tlv value fits")).to_be_bytes(),
        );
        out.extend_from_slice(value);
        out
    }

    /// A real-shaped CDP announcement: port id, platform, capabilities
    /// (router+switch), native VLAN, one IPv4 address, and device id.
    /// Device id — the only TLV `parse` requires — is placed *last* so
    /// every strict prefix of this fixture is unambiguously truncated
    /// (rule 1): CDP has no explicit end-of-message marker the way
    /// LLDP/DHCP do, so a prefix that happened to end exactly on an
    /// earlier TLV boundary with device_id already seen would otherwise
    /// be indistinguishable from a legitimately short message.
    fn fixture() -> Vec<u8> {
        let mut b = vec![0x02, 0x3C, 0x00, 0x00]; // version 2, ttl 60s, checksum placeholder
        b.extend_from_slice(&tlv(TLV_PORT_ID, b"GigabitEthernet0/1"));
        b.extend_from_slice(&tlv(TLV_PLATFORM, b"cisco WS-C3750"));
        b.extend_from_slice(&tlv(TLV_CAPABILITIES, &0x0000_0029u32.to_be_bytes())); // router+switch+IGMP
        b.extend_from_slice(&tlv(TLV_NATIVE_VLAN, &1u16.to_be_bytes()));
        let mut addr_value = 1u32.to_be_bytes().to_vec(); // one address
        addr_value.push(1); // protocol_type: NLPID
        addr_value.push(1); // protocol_length
        addr_value.push(0xCC); // protocol: IP
        addr_value.extend_from_slice(&4u16.to_be_bytes()); // address_length
        addr_value.extend_from_slice(&[192, 0, 2, 1]); // address
        b.extend_from_slice(&tlv(TLV_ADDRESS, &addr_value));
        b.extend_from_slice(&tlv(TLV_DEVICE_ID, b"switch1.example.net"));
        b
    }

    #[test]
    fn parses_the_fixture_frame() {
        let bytes = fixture();
        let m = meta(bytes.len());
        let parsed = Cdp.parse(&bytes, &ctx(Depth::Full, &m)).expect("valid CDP");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(VERSION), Some(&Value::U64(2)));
        assert_eq!(parsed.fields.get(TTL), Some(&Value::U64(60)));
        assert_eq!(
            parsed.fields.get(DEVICE_ID),
            Some(&Value::from("switch1.example.net"))
        );
        assert_eq!(
            parsed.fields.get(PORT_ID),
            Some(&Value::from("GigabitEthernet0/1"))
        );
        assert_eq!(
            parsed.fields.get(PLATFORM),
            Some(&Value::from("cisco WS-C3750"))
        );
        assert_eq!(parsed.fields.get(CAPABILITIES), Some(&Value::U64(0x29)));
        assert_eq!(parsed.fields.get(NATIVE_VLAN), Some(&Value::U64(1)));
        assert_eq!(
            parsed.fields.get(IP_ADDRESS),
            Some(&Value::from(&[192, 0, 2, 1][..]))
        );
    }

    #[test]
    fn structural_depth_omits_tlv_fields() {
        let bytes = fixture();
        let m = meta(bytes.len());
        let parsed = Cdp
            .parse(&bytes, &ctx(Depth::Structural, &m))
            .expect("valid CDP");
        assert_eq!(parsed.fields.get(VERSION), Some(&Value::U64(2)));
        assert_eq!(parsed.fields.get(DEVICE_ID), None);
    }

    #[test]
    fn unknown_tlv_is_skipped_by_its_own_length() {
        let mut b = vec![0x02, 0x3C, 0x00, 0x00];
        b.extend_from_slice(&tlv(0x0099, &[0xDE, 0xAD, 0xBE, 0xEF])); // unassigned type
        b.extend_from_slice(&tlv(TLV_DEVICE_ID, b"still-parsed"));
        let m = meta(b.len());
        let parsed = Cdp
            .parse(&b, &ctx(Depth::Full, &m))
            .expect("unknown TLV skipped, not fatal");
        assert_eq!(
            parsed.fields.get(DEVICE_ID),
            Some(&Value::from("still-parsed"))
        );
    }

    #[test]
    fn trailing_zero_padding_does_not_break_the_parse() {
        let mut b = fixture();
        let real_len = b.len();
        b.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Ethernet minimum-frame padding
        let m = meta(b.len());
        let parsed = Cdp.parse(&b, &ctx(Depth::Full, &m)).expect("valid CDP");
        assert_eq!(
            parsed.header_len, real_len,
            "padding excluded from header_len"
        );
    }

    #[test]
    fn malformed_tlv_length_declines_cleanly() {
        let mut b = vec![0x02, 0x3C, 0x00, 0x00];
        b.extend_from_slice(&TLV_DEVICE_ID.to_be_bytes());
        b.extend_from_slice(&2u16.to_be_bytes()); // length shorter than its own 4-byte header
        let m = meta(b.len());
        assert!(Cdp.parse(&b, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn oversized_tlv_length_declines_cleanly() {
        let mut b = vec![0x02, 0x3C, 0x00, 0x00];
        b.extend_from_slice(&TLV_DEVICE_ID.to_be_bytes());
        b.extend_from_slice(&200u16.to_be_bytes()); // claims far more than present
        b.extend_from_slice(b"short");
        let m = meta(b.len());
        assert!(Cdp.parse(&b, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn truncated_frames_decline() {
        let bytes = fixture();
        let m = meta(bytes.len());
        for n in 0..bytes.len() {
            let full_ctx = ctx(Depth::Full, &m);
            assert!(
                Cdp.parse(&bytes[..n], &full_ctx).is_err(),
                "prefix of {n}/{} bytes must decline",
                bytes.len()
            );
        }
    }
}
