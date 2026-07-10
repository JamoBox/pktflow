//! LACP (11.1, IEEE 802.3-2018 Clause 43, formerly 802.3ad): Link
//! Aggregation Control Protocol negotiation over the Slow Protocols
//! EtherType. The one identity-bearing protocol in 11.1's link/LAN
//! domain — control-plane negotiation gets the same flow-key treatment
//! as a transport session, keyed on the two systems' MACs.
//!
//! The Slow Protocols EtherType (0x8809) is shared with other subtypes
//! (Marker protocol, subtype 0x02, Tier 2); this plugin claims the
//! EtherType alone and declines any non-LACP subtype from inside
//! `parse` — an explicit-route decline (`StopReason::PluginError`), not
//! an unclaimed route, per the domain spec.

use pktflow_core::{
    ByteReader, Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx,
    ParseError, ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId, StreamIdentity, Value,
};

const ACTOR_SYSTEM: FieldName = "actor_system";
const PARTNER_SYSTEM: FieldName = "partner_system";
const ACTOR_KEY: FieldName = "actor_key";
const ACTOR_PORT: FieldName = "actor_port";
const ACTOR_STATE: FieldName = "actor_state";
const PARTNER_KEY: FieldName = "partner_key";
const PARTNER_PORT: FieldName = "partner_port";
const PARTNER_STATE: FieldName = "partner_state";

/// Slow Protocols subtype 1 (LACP); subtype 2 is the Marker protocol
/// (Tier 2).
const LACP_SUBTYPE: u8 = 0x01;

const TLV_ACTOR: u8 = 0x01;
const TLV_PARTNER: u8 = 0x02;
const TLV_COLLECTOR: u8 = 0x03;
const TLV_TERMINATOR: u8 = 0x00;

/// Fixed length (type+length byte included) of the Actor/Partner
/// Information TLV (43.4.2/43.4.3): 2-byte system priority, 6-byte
/// system, 2-byte key, 2-byte port priority, 2-byte port, 1-byte state,
/// 3-byte reserved.
const ACTOR_PARTNER_TLV_LEN: u8 = 0x14;
/// Fixed length of the Collector Information TLV (43.4.4): 2-byte max
/// delay, 12-byte reserved.
const COLLECTOR_TLV_LEN: u8 = 0x10;
/// The LACPDU's trailing reserved region (43.4.6) after the Terminator
/// TLV, padding the whole PDU out to its standard-mandated fixed size —
/// consumed as header (it's genuinely part of the wire structure) but
/// exposed as no field of its own.
const RESERVED_TRAILER_LEN: usize = 50;

static KEY: &[KeyField] = &[KeyField {
    a: ACTOR_SYSTEM,
    b: Some(PARTNER_SYSTEM),
}];
static ROLLUPS: &[RollupSpec] = &[RollupSpec {
    field: ACTOR_STATE,
    kind: RollupKind::Accumulate,
}];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: ROLLUPS,
};

/// One Actor/Partner Information TLV: `(system, key, port, state)`.
fn read_endpoint_tlv<'a>(
    r: &mut ByteReader<'a>,
    expected_type: u8,
) -> Result<(&'a [u8], u16, u16, u8), ParseError> {
    let tlv_type = r.u8()?;
    if tlv_type != expected_type {
        return Err(ParseError::Malformed(
            "LACP: Actor/Partner TLV out of order",
        ));
    }
    let tlv_len = r.u8()?;
    if tlv_len != ACTOR_PARTNER_TLV_LEN {
        return Err(ParseError::Malformed(
            "LACP: unexpected Actor/Partner TLV length",
        ));
    }
    let _system_priority = r.u16_be()?;
    let system = r.take(6)?;
    let key = r.u16_be()?;
    let _port_priority = r.u16_be()?;
    let port = r.u16_be()?;
    let state = r.u8()?;
    r.take(3)?; // reserved
    Ok((system, key, port, state))
}

pub struct Lacp;

impl LayerPlugin for Lacp {
    fn name(&self) -> ProtocolName {
        "lacp"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let subtype = r.u8()?;
        if subtype != LACP_SUBTYPE {
            return Err(ParseError::Malformed(
                "LACP: not the LACP Slow Protocols subtype",
            ));
        }
        let _version = r.u8()?;

        let (actor_system, actor_key, actor_port, actor_state) =
            read_endpoint_tlv(&mut r, TLV_ACTOR)?;
        let (partner_system, partner_key, partner_port, partner_state) =
            read_endpoint_tlv(&mut r, TLV_PARTNER)?;

        let tlv_type = r.u8()?;
        if tlv_type != TLV_COLLECTOR {
            return Err(ParseError::Malformed("LACP: Collector TLV out of order"));
        }
        let tlv_len = r.u8()?;
        if tlv_len != COLLECTOR_TLV_LEN {
            return Err(ParseError::Malformed(
                "LACP: unexpected Collector TLV length",
            ));
        }
        r.take(usize::from(COLLECTOR_TLV_LEN) - 2)?; // max delay + reserved

        let terminator_type = r.u8()?;
        let terminator_len = r.u8()?;
        if terminator_type != TLV_TERMINATOR || terminator_len != 0 {
            return Err(ParseError::Malformed("LACP: missing Terminator TLV"));
        }
        r.take(RESERVED_TRAILER_LEN)?;

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(ACTOR_SYSTEM, Value::from(actor_system));
            fields.insert(PARTNER_SYSTEM, Value::from(partner_system));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(ACTOR_KEY, Value::U64(u64::from(actor_key)));
            fields.insert(ACTOR_PORT, Value::U64(u64::from(actor_port)));
            fields.insert(ACTOR_STATE, Value::U64(u64::from(actor_state)));
            fields.insert(PARTNER_KEY, Value::U64(u64::from(partner_key)));
            fields.insert(PARTNER_PORT, Value::U64(u64::from(partner_port)));
            fields.insert(PARTNER_STATE, Value::U64(u64::from(partner_state)));
        }

        Ok(ParsedLayer {
            header_len: bytes.len() - r.remaining(),
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::EtherType(0x8809)]
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

    fn ctx(depth: Depth, meta: &PacketMeta) -> ParseCtx<'_> {
        ParseCtx::new(&[], depth, meta)
    }

    fn endpoint_tlv(t: u8, system: [u8; 6], key: u16, port: u16, state: u8) -> Vec<u8> {
        let mut b = vec![t, ACTOR_PARTNER_TLV_LEN];
        b.extend_from_slice(&0x8000u16.to_be_bytes()); // system priority
        b.extend_from_slice(&system);
        b.extend_from_slice(&key.to_be_bytes());
        b.extend_from_slice(&0x8000u16.to_be_bytes()); // port priority
        b.extend_from_slice(&port.to_be_bytes());
        b.push(state);
        b.extend_from_slice(&[0, 0, 0]); // reserved
        b
    }

    /// A real-shaped LACPDU (802.3-2018 Clause 43): two aggregation-group
    /// members negotiating, both sides synchronized/collecting/
    /// distributing (state 0x3D: activity|aggregation|sync|collecting|
    /// distributing).
    fn fixture() -> Vec<u8> {
        let mut b = vec![LACP_SUBTYPE, 0x01]; // subtype, version 1
        b.extend_from_slice(&endpoint_tlv(
            TLV_ACTOR,
            [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E],
            1,
            1,
            0x3D,
        ));
        b.extend_from_slice(&endpoint_tlv(
            TLV_PARTNER,
            [0x00, 0x1B, 0x44, 0x11, 0x3A, 0xB7],
            2,
            2,
            0x3D,
        ));
        b.push(TLV_COLLECTOR);
        b.push(COLLECTOR_TLV_LEN);
        b.extend_from_slice(&[0; 14]); // max delay + reserved
        b.push(TLV_TERMINATOR);
        b.push(0x00);
        b.extend_from_slice(&[0; RESERVED_TRAILER_LEN]);
        b
    }

    #[test]
    fn parses_the_fixture_lacpdu() {
        let bytes = fixture();
        let m = meta(bytes.len());
        let parsed = Lacp
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid LACPDU");
        assert_eq!(parsed.header_len, 110, "fixed LACPDU size");
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(
            parsed.fields.get(ACTOR_SYSTEM),
            Some(&Value::from(&[0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E][..]))
        );
        assert_eq!(
            parsed.fields.get(PARTNER_SYSTEM),
            Some(&Value::from(&[0x00, 0x1B, 0x44, 0x11, 0x3A, 0xB7][..]))
        );
        assert_eq!(parsed.fields.get(ACTOR_KEY), Some(&Value::U64(1)));
        assert_eq!(parsed.fields.get(PARTNER_KEY), Some(&Value::U64(2)));
        assert_eq!(parsed.fields.get(ACTOR_STATE), Some(&Value::U64(0x3D)));
    }

    #[test]
    fn keys_depth_has_only_the_system_fields() {
        let bytes = fixture();
        let m = meta(bytes.len());
        let parsed = Lacp
            .parse(&bytes, &ctx(Depth::Keys, &m))
            .expect("valid LACPDU");
        assert_eq!(parsed.fields.len(), 2);
        assert_eq!(parsed.fields.get(ACTOR_KEY), None);
    }

    #[test]
    fn non_lacp_subtype_declines_not_route_miss() {
        let mut bytes = fixture();
        bytes[0] = 0x02; // Marker protocol subtype
        let m = meta(bytes.len());
        assert!(Lacp.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn actor_before_partner_is_enforced() {
        let mut bytes = fixture();
        bytes[2] = TLV_PARTNER; // swap the actor TLV's type byte
        let m = meta(bytes.len());
        assert!(Lacp.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn truncated_frames_decline() {
        let bytes = fixture();
        let m = meta(bytes.len());
        for n in 0..bytes.len() {
            let full_ctx = ctx(Depth::Full, &m);
            assert!(
                Lacp.parse(&bytes[..n], &full_ctx).is_err(),
                "prefix of {n}/{} bytes must decline",
                bytes.len()
            );
        }
    }
}
