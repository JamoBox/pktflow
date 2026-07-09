//! LLDP (11.1, IEEE 802.1AB-2016 "Station and Media Access Control
//! Connectivity Discovery"): a bounded TLV walk over the three mandatory
//! TLVs (Chassis ID, Port ID, TTL, in that fixed order — §8.2) followed by
//! zero or more optional TLVs and the End-of-LLDPDU sentinel (type 0,
//! length 0, §8.5.1). A periodic multicast neighbor announcement, not a
//! two-party conversation — same stance as CDP (11.1) and ARP (06.3): no
//! stream of its own, stats land on the parent MAC conversation.
//!
//! Standard destination MACs (802.1AB-2016 §7.1, Table 7-1): the "nearest
//! bridge" group address `01:80:C2:00:00:0E` is by far the most common
//! scope and is what real-world captures use; `dst_mac` is not consulted
//! here (LLDP is always unambiguously routed by its own EtherType, 0x88CC
//! — see 11.1's "Destination-MAC recognition" for why the other two
//! defined scopes don't create routing ambiguity).

use pktflow_core::{
    ByteReader, Depth, FieldMap, FieldName, Hint, LayerPlugin, ParseCtx, ParseError, ParsedLayer,
    ProtocolName, RouteId, StreamIdentity, Value,
};

const CHASSIS_ID_SUBTYPE: FieldName = "chassis_id_subtype";
const CHASSIS_ID: FieldName = "chassis_id";
const PORT_ID_SUBTYPE: FieldName = "port_id_subtype";
const PORT_ID: FieldName = "port_id";
const TTL: FieldName = "ttl";
const SYSTEM_NAME: FieldName = "system_name";
const SYSTEM_DESCRIPTION: FieldName = "system_description";
const MANAGEMENT_ADDRESS: FieldName = "management_address";
const CAPABILITIES: FieldName = "capabilities";

/// TLV type values (802.1AB-2016 §8.5, Table 8-1 basic management set).
const TLV_END: u8 = 0;
const TLV_CHASSIS_ID: u8 = 1;
const TLV_PORT_ID: u8 = 2;
const TLV_TTL: u8 = 3;
const TLV_SYSTEM_NAME: u8 = 5;
const TLV_SYSTEM_DESCRIPTION: u8 = 6;
const TLV_SYSTEM_CAPABILITIES: u8 = 7;
const TLV_MANAGEMENT_ADDRESS: u8 = 8;

pub struct Lldp;

/// Reads one TLV header (§8.1: 7-bit type in the high bits, 9-bit length
/// in the low bits of a big-endian u16) and its value, bounds-checked by
/// `ByteReader` — an oversized/truncated length declines cleanly rather
/// than looping or overrunning.
fn read_tlv<'a>(r: &mut ByteReader<'a>) -> Result<(u8, &'a [u8]), ParseError> {
    let header = r.u16_be()?;
    let tlv_type = (header >> 9) as u8;
    let tlv_len = usize::from(header & 0x01FF);
    let value = r.take(tlv_len)?;
    Ok((tlv_type, value))
}

/// Best-effort text decode for the optional string TLVs. §8.5.6/§8.5.7
/// specify UTF-8, but a malformed/legacy device is a "decline, don't
/// guess" case for *routing*, not for a diagnostic string field — bytes
/// outside printable ASCII render as `?`, matching DHCP's hostname option
/// (06.6) rather than failing the whole parse over one cosmetic field.
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

impl LayerPlugin for Lldp {
    fn name(&self) -> ProtocolName {
        "lldp"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);

        // Mandatory TLVs, fixed order (§8.2): Chassis ID, Port ID, TTL.
        // Wrong type or wrong position here is not LLDP at all.
        let (t, chassis) = read_tlv(&mut r)?;
        if t != TLV_CHASSIS_ID || chassis.is_empty() {
            return Err(ParseError::Malformed("LLDP: expected Chassis ID TLV"));
        }
        let chassis_id_subtype = chassis[0];
        let chassis_id = &chassis[1..];

        let (t, port) = read_tlv(&mut r)?;
        if t != TLV_PORT_ID || port.is_empty() {
            return Err(ParseError::Malformed("LLDP: expected Port ID TLV"));
        }
        let port_id_subtype = port[0];
        let port_id = &port[1..];

        let (t, ttl_bytes) = read_tlv(&mut r)?;
        if t != TLV_TTL || ttl_bytes.len() != 2 {
            return Err(ParseError::Malformed("LLDP: expected 2-byte TTL TLV"));
        }
        let ttl = u16::from_be_bytes([ttl_bytes[0], ttl_bytes[1]]);

        // Optional TLVs in any order, until End-of-LLDPDU (§8.5.1) or the
        // buffer runs out. Unknown/unhandled types (organizationally
        // specific TLVs, reserved types, a repeated optional TLV) are
        // skipped by their own length field — same discipline as CDP's
        // and LLDP's own mandatory walk above.
        let mut system_name = None;
        let mut system_description = None;
        let mut management_address = None;
        let mut capabilities = None;
        loop {
            let (t, value) = read_tlv(&mut r)?;
            match t {
                TLV_END => break,
                TLV_SYSTEM_NAME if system_name.is_none() => {
                    system_name = Some(decode_text(value));
                }
                TLV_SYSTEM_DESCRIPTION if system_description.is_none() => {
                    system_description = Some(decode_text(value));
                }
                TLV_SYSTEM_CAPABILITIES if capabilities.is_none() && value.len() == 4 => {
                    // §8.5.8.2, Table 8-4: the value is two 2-byte
                    // bitmaps, [system capabilities, enabled capabilities].
                    // The enabled word is the diagnostically useful one
                    // (which roles are actually active, not just
                    // advertised as supported).
                    capabilities = Some(u64::from(u16::from_be_bytes([value[2], value[3]])));
                }
                TLV_MANAGEMENT_ADDRESS if management_address.is_none() => {
                    management_address = Some(Value::from(value));
                }
                _ => {}
            }
        }

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Structural {
            fields.insert(
                CHASSIS_ID_SUBTYPE,
                Value::U64(u64::from(chassis_id_subtype)),
            );
            fields.insert(CHASSIS_ID, Value::from(chassis_id));
            fields.insert(PORT_ID_SUBTYPE, Value::U64(u64::from(port_id_subtype)));
            fields.insert(PORT_ID, Value::from(port_id));
            fields.insert(TTL, Value::U64(u64::from(ttl)));
        }
        if ctx.depth() >= Depth::Full {
            if let Some(v) = system_name {
                fields.insert(SYSTEM_NAME, Value::from(v.as_str()));
            }
            if let Some(v) = system_description {
                fields.insert(SYSTEM_DESCRIPTION, Value::from(v.as_str()));
            }
            if let Some(v) = management_address {
                fields.insert(MANAGEMENT_ADDRESS, v);
            }
            if let Some(v) = capabilities {
                fields.insert(CAPABILITIES, Value::U64(v));
            }
        }

        Ok(ParsedLayer {
            // Bytes actually consumed by the TLV walk (through the End
            // TLV); any Ethernet padding beyond it is not part of the
            // header.
            header_len: bytes.len() - r.remaining(),
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::EtherType(0x88CC)]
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

    fn tlv(t: u8, value: &[u8]) -> Vec<u8> {
        let header = (u16::from(t) << 9) | (value.len() as u16);
        let mut out = header.to_be_bytes().to_vec();
        out.extend_from_slice(value);
        out
    }

    /// A real-shaped LLDPDU: MAC-address chassis ID, interface-name port
    /// ID, TTL 120s, system name/description, capabilities (bridge
    /// enabled, router supported but not enabled), and a management
    /// address TLV — then the End sentinel.
    fn fixture() -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&tlv(
            TLV_CHASSIS_ID,
            &[4, 0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E], // subtype 4: MAC address
        ));
        b.extend_from_slice(&tlv(TLV_PORT_ID, b"\x05Gi0/1")); // subtype 5: interface name
        b.extend_from_slice(&tlv(TLV_TTL, &120u16.to_be_bytes()));
        b.extend_from_slice(&tlv(TLV_SYSTEM_NAME, b"switch1.example.net"));
        b.extend_from_slice(&tlv(
            TLV_SYSTEM_DESCRIPTION,
            b"ExampleOS 1.0, Enterprise Switch",
        ));
        // system caps: bridge(0x04)|router(0x10)=0x14; enabled: bridge only.
        b.extend_from_slice(&tlv(TLV_SYSTEM_CAPABILITIES, &[0x00, 0x14, 0x00, 0x04]));
        // Management address TLV (§8.5.9): addr-string-len(5) + subtype(1,
        // IPv4) + 192.0.2.1 + if-numbering-subtype(2, ifIndex) + if-num(5)
        // + OID-len(0).
        b.extend_from_slice(&tlv(
            TLV_MANAGEMENT_ADDRESS,
            &[5, 1, 192, 0, 2, 1, 2, 0, 0, 0, 5, 0],
        ));
        b.extend_from_slice(&tlv(TLV_END, &[]));
        b
    }

    fn ctx_for(depth: Depth, meta: &PacketMeta) -> ParseCtx<'_> {
        ParseCtx::new(&[], depth, meta)
    }

    fn meta(len: usize) -> PacketMeta {
        PacketMeta {
            timestamp: SystemTime::UNIX_EPOCH,
            caplen: len,
            origlen: len,
            link_type: LinkType::ETHERNET,
        }
    }

    #[test]
    fn parses_the_fixture_frame() {
        let bytes = fixture();
        let m = meta(bytes.len());
        let ctx = ctx_for(Depth::Full, &m);
        let parsed = Lldp.parse(&bytes, &ctx).expect("valid LLDPDU");

        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(CHASSIS_ID_SUBTYPE), Some(&Value::U64(4)));
        assert_eq!(
            parsed.fields.get(CHASSIS_ID),
            Some(&Value::from(&[0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E][..]))
        );
        assert_eq!(parsed.fields.get(PORT_ID_SUBTYPE), Some(&Value::U64(5)));
        assert_eq!(
            parsed.fields.get(PORT_ID),
            Some(&Value::from(&b"Gi0/1"[..]))
        );
        assert_eq!(parsed.fields.get(TTL), Some(&Value::U64(120)));
        assert_eq!(
            parsed.fields.get(SYSTEM_NAME),
            Some(&Value::from("switch1.example.net"))
        );
        assert_eq!(
            parsed.fields.get(SYSTEM_DESCRIPTION),
            Some(&Value::from("ExampleOS 1.0, Enterprise Switch"))
        );
        assert_eq!(parsed.fields.get(CAPABILITIES), Some(&Value::U64(0x04)));
        assert_eq!(
            parsed.fields.get(MANAGEMENT_ADDRESS),
            Some(&Value::from(&[5u8, 1, 192, 0, 2, 1, 2, 0, 0, 0, 5, 0][..]))
        );
    }

    #[test]
    fn structural_depth_omits_optional_fields() {
        let bytes = fixture();
        let m = meta(bytes.len());
        let ctx = ctx_for(Depth::Structural, &m);
        let parsed = Lldp.parse(&bytes, &ctx).expect("valid LLDPDU");

        assert_eq!(parsed.fields.get(TTL), Some(&Value::U64(120)));
        assert_eq!(parsed.fields.get(SYSTEM_NAME), None);
        assert_eq!(parsed.fields.get(CAPABILITIES), None);
    }

    #[test]
    fn minimal_lldpdu_with_no_optional_tlvs_still_parses() {
        let mut b = Vec::new();
        b.extend_from_slice(&tlv(TLV_CHASSIS_ID, &[7, b'e', b'0']));
        b.extend_from_slice(&tlv(TLV_PORT_ID, &[7, b'p', b'1']));
        b.extend_from_slice(&tlv(TLV_TTL, &30u16.to_be_bytes()));
        b.extend_from_slice(&tlv(TLV_END, &[]));

        let m = meta(b.len());
        let ctx = ctx_for(Depth::Full, &m);
        let parsed = Lldp.parse(&b, &ctx).expect("minimal LLDPDU parses");
        assert_eq!(parsed.header_len, b.len());
        assert_eq!(parsed.fields.get(SYSTEM_NAME), None);
    }

    #[test]
    fn unknown_optional_tlv_is_skipped_by_its_own_length() {
        let mut b = Vec::new();
        b.extend_from_slice(&tlv(TLV_CHASSIS_ID, &[7, b'e', b'0']));
        b.extend_from_slice(&tlv(TLV_PORT_ID, &[7, b'p', b'1']));
        b.extend_from_slice(&tlv(TLV_TTL, &30u16.to_be_bytes()));
        b.extend_from_slice(&tlv(127, &[0xDE, 0xAD, 0xBE, 0xEF])); // org-specific, unhandled
        b.extend_from_slice(&tlv(TLV_SYSTEM_NAME, b"still-parsed"));
        b.extend_from_slice(&tlv(TLV_END, &[]));

        let m = meta(b.len());
        let ctx = ctx_for(Depth::Full, &m);
        let parsed = Lldp
            .parse(&b, &ctx)
            .expect("unknown TLV skipped, not fatal");
        assert_eq!(
            parsed.fields.get(SYSTEM_NAME),
            Some(&Value::from("still-parsed"))
        );
    }

    #[test]
    fn wrong_mandatory_tlv_order_declines() {
        // Port ID TLV first: not LLDP's fixed order.
        let mut b = Vec::new();
        b.extend_from_slice(&tlv(TLV_PORT_ID, &[7, b'p', b'1']));
        b.extend_from_slice(&tlv(TLV_CHASSIS_ID, &[7, b'e', b'0']));
        b.extend_from_slice(&tlv(TLV_TTL, &30u16.to_be_bytes()));
        b.extend_from_slice(&tlv(TLV_END, &[]));

        let m = meta(b.len());
        let ctx = ctx_for(Depth::Full, &m);
        assert!(Lldp.parse(&b, &ctx).is_err());
    }

    #[test]
    fn missing_end_tlv_declines_instead_of_looping() {
        // No End-of-LLDPDU sentinel and no more bytes: bounded by
        // ByteReader, not an infinite loop.
        let mut b = Vec::new();
        b.extend_from_slice(&tlv(TLV_CHASSIS_ID, &[7, b'e', b'0']));
        b.extend_from_slice(&tlv(TLV_PORT_ID, &[7, b'p', b'1']));
        b.extend_from_slice(&tlv(TLV_TTL, &30u16.to_be_bytes()));

        let m = meta(b.len());
        let ctx = ctx_for(Depth::Full, &m);
        assert!(Lldp.parse(&b, &ctx).is_err());
    }

    #[test]
    fn oversized_tlv_length_declines_cleanly() {
        // TLV header claims more bytes than actually follow.
        let mut b = Vec::new();
        b.extend_from_slice(&tlv(TLV_CHASSIS_ID, &[7, b'e', b'0']));
        let header = (u16::from(TLV_PORT_ID) << 9) | 200; // claims 200 bytes
        b.extend_from_slice(&header.to_be_bytes());
        b.extend_from_slice(&[7, b'p', b'1']); // only 3 actually present

        let m = meta(b.len());
        let ctx = ctx_for(Depth::Full, &m);
        assert!(Lldp.parse(&b, &ctx).is_err());
    }

    #[test]
    fn truncated_frame_declines() {
        let bytes = fixture();
        let m = meta(bytes.len());
        for n in 0..bytes.len() {
            let ctx = ctx_for(Depth::Full, &m);
            assert!(
                Lldp.parse(&bytes[..n], &ctx).is_err(),
                "prefix of {n} bytes must decline"
            );
        }
    }
}
