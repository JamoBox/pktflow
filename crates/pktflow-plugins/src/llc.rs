//! LLC + SNAP demux (11.1, IEEE 802.2-1998; SNAP extension per IEEE 802 /
//! RFC 1042 encapsulation): infrastructure the rest of 11.1 needs, not a
//! named protocol from the taxonomy itself. STP and CDP predate
//! EtherType-based demultiplexing and arrive in classic 802.3 LLC frames
//! — the 802.3-length case (`ethertype < 0x0600`) IEEE 802.3-2018 §3.2.6
//! makes deterministic, never a guess, so ethernet (06.2) names it
//! explicitly as `Custom{"eth_llc_frame", 0}` and this plugin claims that
//! route directly. `probe()` stays as defense-in-depth for any other
//! future producer of raw 802.3-length-field-shaped bytes reaching the
//! heuristic fallback pool by a different path. The RFC 1042 branch
//! (SNAP, OUI 0) reuses the real `EtherType` space, so no existing
//! EtherType-claiming plugin needs to change to work over LLC/SNAP-
//! encapsulated media (notably 802.11 data frames, task 11.2).

use pktflow_core::{
    ByteReader, Confidence, Depth, FieldMap, FieldName, Hint, LayerPlugin, ParseCtx, ParseError,
    ParsedLayer, ProtocolName, RouteId, StreamIdentity, Value,
};

const DSAP: FieldName = "dsap";
const SSAP: FieldName = "ssap";
const CONTROL: FieldName = "control";
const OUI: FieldName = "oui";
const PID: FieldName = "pid";

/// The SAP LLC/SNAP encapsulation uses.
const SNAP_SAP: u8 = 0xAA;

/// SAPs this domain's protocols use (802.2 assigned SAPs): 0x42 STP,
/// 0xAA SNAP, 0xE0 IPX, 0xF0 NetBIOS.
const WELL_KNOWN_SAPS: [u8; 4] = [0x42, 0xAA, 0xE0, 0xF0];

/// IEEE Bridge Group Address block (802.1D Annex, "addresses a conformant
/// bridge must never forward"): `01:80:C2:00:00:00`-`0F`.
fn is_ieee_bridge_group(mac: &[u8]) -> bool {
    matches!(mac, [0x01, 0x80, 0xC2, 0x00, 0x00, last] if *last <= 0x0F)
}

/// Cisco's reserved control-plane multicast block: `01:00:0C:CC:CC:CC`
/// (most Cisco discovery/negotiation protocols) or `...CD` (PVST+).
fn is_cisco_multicast(mac: &[u8]) -> bool {
    matches!(mac, [0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC | 0xCD])
}

pub struct Llc;

impl LayerPlugin for Llc {
    fn name(&self) -> ProtocolName {
        "llc"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let dsap = r.u8()?;
        let ssap = r.u8()?;
        let control_first = r.u8()?;
        // IEEE 802.2-1998 §5.2: U-format (unnumbered) has a 1-byte
        // control field, low two bits both set. I/S-format (basic,
        // modulo-8 sequencing) has a 2-byte control field; the second
        // byte carries N(R)/P-F. STP and CDP are always U-format
        // (control 0x03), but the wire format itself supports either.
        let control = if control_first & 0x03 == 0x03 {
            u64::from(control_first)
        } else {
            let control_second = r.u8()?;
            u64::from(u16::from_be_bytes([control_first, control_second]))
        };

        let mut oui = None;
        let mut pid = None;
        if dsap == SNAP_SAP && ssap == SNAP_SAP {
            let oui_bytes = r.take(3)?;
            oui = Some(
                (u32::from(oui_bytes[0]) << 16)
                    | (u32::from(oui_bytes[1]) << 8)
                    | u32::from(oui_bytes[2]),
            );
            pid = Some(r.u16_be()?);
        }

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Structural {
            fields.insert(DSAP, Value::U64(u64::from(dsap)));
            fields.insert(SSAP, Value::U64(u64::from(ssap)));
            fields.insert(CONTROL, Value::U64(control));
        }
        if ctx.depth() >= Depth::Full {
            if let Some(o) = oui {
                fields.insert(OUI, Value::U64(u64::from(o)));
            }
            if let Some(p) = pid {
                fields.insert(PID, Value::U64(u64::from(p)));
            }
        }

        let hint = match (oui, pid) {
            // RFC 1042: OUI 0 means the PID *is* an EtherType.
            (Some(0), Some(pid)) => Hint::Route(RouteId::EtherType(pid)),
            (Some(oui), Some(pid)) => Hint::Route(RouteId::Custom {
                space: "snap_pid",
                id: (u64::from(oui) << 16) | u64::from(pid),
            }),
            _ => Hint::Route(RouteId::Custom {
                space: "llc_dsap",
                id: u64::from(dsap),
            }),
        };

        Ok(ParsedLayer {
            header_len: bytes.len() - r.remaining(),
            fields,
            hint,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::Custom {
            space: "eth_llc_frame",
            id: 0,
        }]
    }

    fn expected_predecessors(&self) -> &'static [ProtocolName] {
        &["ethernet", "dot11"]
    }

    fn has_probe(&self) -> bool {
        true
    }

    /// Base signal: both SAPs a well-known value and a structurally valid
    /// control field → 55. Cross-layer boost (FR-17, reading `ethernet`'s
    /// already-parsed `dst_mac`): a reserved-multicast destination → 90
    /// regardless of the base signal — a far stronger, standards-grounded
    /// signal than SAP pattern-matching alone (11.1's "Destination-MAC
    /// recognition"). `ethernet`'s own 802.3-length frames now reach
    /// `llc` through `claims()` above rather than this probe; kept as
    /// defense-in-depth for any other future producer of raw
    /// 802.3-length-field-shaped bytes that only offers `Hint::Unknown`.
    fn probe(&self, bytes: &[u8], ctx: &ParseCtx) -> Option<Confidence> {
        let &[dsap, ssap, control_first, ..] = bytes else {
            return None;
        };
        let base_saps = WELL_KNOWN_SAPS.contains(&dsap) && WELL_KNOWN_SAPS.contains(&ssap);
        // U-format needs only this byte; I/S-format needs a second,
        // checked for presence here (both encodings are legal LLC).
        let control_ok = control_first & 0x03 == 0x03 || bytes.len() >= 4;

        let boosted = ctx
            .field("ethernet", "dst_mac")
            .and_then(|v| match v {
                Value::Bytes(mac) => Some(mac.as_slice()),
                _ => None,
            })
            .is_some_and(|mac| is_ieee_bridge_group(mac) || is_cisco_multicast(mac));

        if boosted {
            Some(Confidence::new(90))
        } else if base_saps && control_ok {
            Some(Confidence::new(55))
        } else {
            None
        }
    }

    fn stream_identity(&self) -> Option<&StreamIdentity> {
        None
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use pktflow_core::{FieldMap as CoreFieldMap, LayerRecord, LinkType, PacketMeta};

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

    /// STP-shaped: dsap=ssap=0x42 (802.1D Bridge Group SAP), U-format
    /// control 0x03.
    fn stp_shaped() -> Vec<u8> {
        vec![0x42, 0x42, 0x03]
    }

    /// CDP-shaped SNAP: dsap=ssap=0xAA, control 0x03, OUI 00-00-0C
    /// (Cisco), PID 0x2000 (CDP).
    fn cdp_shaped() -> Vec<u8> {
        vec![0xAA, 0xAA, 0x03, 0x00, 0x00, 0x0C, 0x20, 0x00]
    }

    /// RFC 1042 IP-over-SNAP: OUI 0, PID 0x0800 (IPv4) — the branch that
    /// reuses the real EtherType space.
    fn rfc1042_ip() -> Vec<u8> {
        vec![0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00]
    }

    #[test]
    fn claims_the_eth_llc_frame_route() {
        assert_eq!(
            Llc.claims(),
            &[RouteId::Custom {
                space: "eth_llc_frame",
                id: 0
            }]
        );
    }

    #[test]
    fn stp_shaped_frame_routes_via_llc_dsap_custom_space() {
        let bytes = stp_shaped();
        let m = meta(bytes.len());
        let parsed = Llc.parse(&bytes, &ctx(Depth::Full, &m)).expect("valid LLC");
        assert_eq!(parsed.header_len, 3);
        assert_eq!(parsed.fields.get(DSAP), Some(&Value::U64(0x42)));
        assert_eq!(parsed.fields.get(SSAP), Some(&Value::U64(0x42)));
        assert_eq!(parsed.fields.get(CONTROL), Some(&Value::U64(0x03)));
        assert_eq!(parsed.fields.get(OUI), None);
        assert_eq!(
            parsed.hint,
            Hint::Route(RouteId::Custom {
                space: "llc_dsap",
                id: 0x42
            })
        );
    }

    #[test]
    fn cdp_shaped_frame_routes_via_snap_pid_custom_space() {
        let bytes = cdp_shaped();
        let m = meta(bytes.len());
        let parsed = Llc
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid SNAP");
        assert_eq!(parsed.header_len, 8);
        assert_eq!(parsed.fields.get(OUI), Some(&Value::U64(0x00000C)));
        assert_eq!(parsed.fields.get(PID), Some(&Value::U64(0x2000)));
        assert_eq!(
            parsed.hint,
            Hint::Route(RouteId::Custom {
                space: "snap_pid",
                id: (0x00000Cu64 << 16) | 0x2000,
            })
        );
    }

    #[test]
    fn rfc1042_snap_reuses_the_ethertype_space() {
        let bytes = rfc1042_ip();
        let m = meta(bytes.len());
        let parsed = Llc
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid SNAP");
        assert_eq!(parsed.hint, Hint::Route(RouteId::EtherType(0x0800)));
    }

    #[test]
    fn i_format_control_field_is_two_bytes() {
        // dsap/ssap = 0xE0 (IPX), control = I-format (low bits 0b00):
        // first byte N(S)<<1, second byte N(R)<<1|P.
        let bytes = vec![0xE0, 0xE0, 0b0000_0100, 0b0000_0010];
        let m = meta(bytes.len());
        let parsed = Llc.parse(&bytes, &ctx(Depth::Full, &m)).expect("valid LLC");
        assert_eq!(parsed.header_len, 4);
        assert_eq!(
            parsed.fields.get(CONTROL),
            Some(&Value::U64(0x0402)),
            "two control bytes combined big-endian"
        );
        assert_eq!(
            parsed.hint,
            Hint::Route(RouteId::Custom {
                space: "llc_dsap",
                id: 0xE0
            })
        );
    }

    #[test]
    fn structural_depth_omits_snap_fields() {
        let bytes = cdp_shaped();
        let m = meta(bytes.len());
        let parsed = Llc
            .parse(&bytes, &ctx(Depth::Structural, &m))
            .expect("valid SNAP");
        assert_eq!(parsed.fields.get(DSAP), Some(&Value::U64(0xAA)));
        assert_eq!(parsed.fields.get(OUI), None);
        assert_eq!(parsed.fields.get(PID), None);
    }

    #[test]
    fn truncated_frames_decline() {
        for bytes in [stp_shaped(), cdp_shaped(), rfc1042_ip()] {
            let m = meta(bytes.len());
            for n in 0..bytes.len() {
                let full_ctx = ctx(Depth::Full, &m);
                assert!(
                    Llc.parse(&bytes[..n], &full_ctx).is_err(),
                    "prefix of {n}/{} bytes must decline",
                    bytes.len()
                );
            }
        }
    }

    #[test]
    fn probe_scores_the_base_signal_on_well_known_saps() {
        let bytes = stp_shaped();
        let m = meta(bytes.len());
        let score = Llc
            .probe(&bytes, &ctx(Depth::Full, &m))
            .expect("well-known SAPs + valid control probe")
            .get();
        assert_eq!(score, 55);
    }

    #[test]
    fn probe_declines_on_an_unrecognized_sap() {
        let bytes = vec![0x01, 0x01, 0x03]; // not in WELL_KNOWN_SAPS
        let m = meta(bytes.len());
        assert_eq!(Llc.probe(&bytes, &ctx(Depth::Full, &m)), None);
    }

    #[test]
    fn probe_declines_on_a_short_buffer() {
        let m = meta(2);
        assert_eq!(Llc.probe(&[0x42, 0x42], &ctx(Depth::Full, &m)), None);
    }

    fn eth_layer_with_dst_mac(mac: [u8; 6]) -> LayerRecord {
        let mut fields = CoreFieldMap::new();
        fields.insert("dst_mac", Value::from(&mac[..]));
        LayerRecord {
            protocol: "ethernet",
            offset: 0,
            header_len: 14,
            fields,
        }
    }

    #[test]
    fn probe_boost_wins_on_ieee_bridge_group_destination_even_with_a_weak_base_signal() {
        // Atypical control byte (not U-format, and buffer too short for a
        // second control byte) — base signal alone would fail — but the
        // dst_mac boost still wins outright at 90.
        let bytes = vec![0x42, 0x42, 0x00];
        let outer = [eth_layer_with_dst_mac([0x01, 0x80, 0xC2, 0x00, 0x00, 0x00])];
        let m = meta(bytes.len());
        let parse_ctx = ParseCtx::new(&outer, Depth::Full, &m);
        let score = Llc.probe(&bytes, &parse_ctx).expect("boosted").get();
        assert_eq!(score, 90);
    }

    #[test]
    fn probe_boost_wins_on_cisco_multicast_destination() {
        let bytes = cdp_shaped();
        let outer = [eth_layer_with_dst_mac([0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC])];
        let m = meta(bytes.len());
        let parse_ctx = ParseCtx::new(&outer, Depth::Full, &m);
        let score = Llc.probe(&bytes, &parse_ctx).expect("boosted").get();
        assert_eq!(score, 90);
    }

    #[test]
    fn probe_base_signal_still_wins_with_an_unreserved_destination() {
        // Well-formed DSAP/control pattern but a dst_mac outside both
        // reserved blocks: the boost doesn't fire, but the base 55 still
        // gets it into the fallback pool (additive confidence, not a hard
        // requirement — verified as two independent cases).
        let bytes = stp_shaped();
        let outer = [eth_layer_with_dst_mac([0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E])];
        let m = meta(bytes.len());
        let parse_ctx = ParseCtx::new(&outer, Depth::Full, &m);
        let score = Llc.probe(&bytes, &parse_ctx).expect("base signal").get();
        assert_eq!(score, 55);
    }
}
