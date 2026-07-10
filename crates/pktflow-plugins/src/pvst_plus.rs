//! PVST+ (11.1, Cisco Per-VLAN Spanning Tree Plus — *no open standard*;
//! Cisco's published PVST+ reference is the closest authoritative
//! document, corroborated by the widely-deployed Wireshark `stp`
//! dissector's PVST+ handling, since Cisco does not publish a formal
//! wire-format spec engineers can cite directly). Arguably more common
//! in real Cisco-switched enterprise networks than generic 802.1D STP
//! (11.1's `stp`), since PVST+ is Cisco's long-standing default: one
//! instance runs per VLAN, so the standard §9.3 BPDU (shared with `stp`
//! via [`crate::stp::parse_bpdu`]) gets an appended VLAN TLV identifying
//! which instance this is. Same identity-less stance as `stp`: no stream
//! of its own.

use pktflow_core::{
    ByteReader, Depth, FieldMap, FieldName, Hint, LayerPlugin, ParseCtx, ParseError, ParsedLayer,
    ProtocolName, RouteId, StreamIdentity, Value,
};

use crate::stp::{insert_bpdu_fields, parse_bpdu};

const ORIGINATING_VLAN: FieldName = "originating_vlan";

/// Cisco OUI, PID 0x010B (PVST+) under the SNAP `snap_pid` Custom space
/// `llc` (11.1) mints.
const OUI_CISCO: u64 = 0x00_000C;
const PID_PVST_PLUS: u64 = 0x010B;

pub struct PvstPlus;

impl LayerPlugin for PvstPlus {
    fn name(&self) -> ProtocolName {
        "pvst_plus"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let (bpdu, consumed) = parse_bpdu(bytes)?;

        // Cisco's trailing "Origin VLAN" TLV: 2-byte type (0x0000),
        // 2-byte length (0x0002), 2-byte VLAN ID — always present right
        // after the standard BPDU fields in a real PVST+ frame.
        let mut r = ByteReader::new(&bytes[consumed..]);
        let tlv_type = r.u16_be()?;
        let tlv_len = r.u16_be()?;
        if tlv_type != 0x0000 || tlv_len != 0x0002 {
            return Err(ParseError::Malformed(
                "PVST+: unrecognized originating-VLAN TLV",
            ));
        }
        let originating_vlan = r.u16_be()?;
        let total_consumed = consumed + 6;

        let mut fields = FieldMap::new();
        insert_bpdu_fields(&mut fields, ctx.depth(), &bpdu);
        if ctx.depth() >= Depth::Full {
            fields.insert(ORIGINATING_VLAN, Value::U64(u64::from(originating_vlan)));
        }

        Ok(ParsedLayer {
            header_len: total_consumed,
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::Custom {
            space: "snap_pid",
            id: (OUI_CISCO << 16) | PID_PVST_PLUS,
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

    /// A per-VLAN Configuration BPDU (version 0) for VLAN 100, same
    /// root/bridge shape as `stp`'s fixture, plus the Origin VLAN TLV.
    fn pvst_bpdu(vlan: u16) -> Vec<u8> {
        let mut b = vec![0x00, 0x00, 0x00, 0x00]; // protocol_id, version 0, type 0x00
        b.push(0x00); // flags
        b.extend_from_slice(&[0x80, 0x00, 0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E]); // root_id
        b.extend_from_slice(&4u32.to_be_bytes()); // root_path_cost
        b.extend_from_slice(&[0x80, 0x00, 0x00, 0x1B, 0x44, 0x11, 0x3A, 0xB7]); // bridge_id
        b.extend_from_slice(&0x8001u16.to_be_bytes()); // port_id
        b.extend_from_slice(&0u16.to_be_bytes()); // message_age
        b.extend_from_slice(&0x1400u16.to_be_bytes()); // max_age
        b.extend_from_slice(&0x0200u16.to_be_bytes()); // hello_time
        b.extend_from_slice(&0x0F00u16.to_be_bytes()); // forward_delay
        b.extend_from_slice(&0x0000u16.to_be_bytes()); // TLV type
        b.extend_from_slice(&0x0002u16.to_be_bytes()); // TLV length
        b.extend_from_slice(&vlan.to_be_bytes()); // TLV value: VLAN ID
        b
    }

    #[test]
    fn parses_a_per_vlan_bpdu() {
        let bytes = pvst_bpdu(100);
        let m = meta(bytes.len());
        let parsed = PvstPlus
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid PVST+ BPDU");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(ORIGINATING_VLAN), Some(&Value::U64(100)));
        assert_eq!(
            parsed.fields.get("root_id"),
            Some(&Value::from(
                &[0x80, 0x00, 0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E][..]
            ))
        );
    }

    #[test]
    fn structural_depth_omits_the_originating_vlan() {
        let bytes = pvst_bpdu(200);
        let m = meta(bytes.len());
        let parsed = PvstPlus
            .parse(&bytes, &ctx(Depth::Structural, &m))
            .expect("valid PVST+ BPDU");
        assert_eq!(parsed.fields.get(ORIGINATING_VLAN), None);
    }

    #[test]
    fn wrong_vlan_tlv_header_declines() {
        let mut bytes = pvst_bpdu(1);
        let tlv_type_offset = bytes.len() - 6;
        bytes[tlv_type_offset] = 0xFF; // corrupt the TLV type
        let m = meta(bytes.len());
        assert!(PvstPlus.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn different_vlan_ids_disambiguate_instances() {
        for vlan in [1u16, 100, 4094] {
            let bytes = pvst_bpdu(vlan);
            let m = meta(bytes.len());
            let parsed = PvstPlus
                .parse(&bytes, &ctx(Depth::Full, &m))
                .expect("valid PVST+ BPDU");
            assert_eq!(
                parsed.fields.get(ORIGINATING_VLAN),
                Some(&Value::U64(u64::from(vlan)))
            );
        }
    }

    #[test]
    fn truncated_frames_decline() {
        let bytes = pvst_bpdu(100);
        let m = meta(bytes.len());
        for n in 0..bytes.len() {
            let full_ctx = ctx(Depth::Full, &m);
            assert!(
                PvstPlus.parse(&bytes[..n], &full_ctx).is_err(),
                "prefix of {n}/{} bytes must decline",
                bytes.len()
            );
        }
    }

    #[test]
    fn claims_the_cisco_pvst_snap_pid() {
        assert_eq!(
            PvstPlus.claims(),
            &[RouteId::Custom {
                space: "snap_pid",
                id: (0x00_000Cu64 << 16) | 0x010B,
            }]
        );
    }
}
