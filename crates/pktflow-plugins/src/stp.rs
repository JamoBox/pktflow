//! STP/RSTP (11.1, IEEE 802.1D-2004 §9.3; RSTP folded in, MSTP is Tier 2
//! — see the note below): spanning-tree BPDUs, carried in classic 802.2
//! LLC frames (§9.3, dsap=ssap=0x42) rather than EtherType-demuxed. A
//! periodic multicast beacon to the fixed Bridge Group Address
//! (01:80:C2:00:00:00), not a two-party conversation — same stance as
//! ARP (06.3): no stream of its own, stats land on the parent MAC
//! conversation.

use pktflow_core::{
    ByteReader, Depth, FieldMap, FieldName, Hint, LayerPlugin, ParseCtx, ParseError, ParsedLayer,
    ProtocolName, RouteId, StreamIdentity, Value,
};

pub(crate) const PROTOCOL_ID: FieldName = "protocol_id";
pub(crate) const VERSION: FieldName = "version";
pub(crate) const BPDU_TYPE: FieldName = "bpdu_type";
pub(crate) const FLAGS: FieldName = "flags";
pub(crate) const ROOT_ID: FieldName = "root_id";
pub(crate) const ROOT_PATH_COST: FieldName = "root_path_cost";
pub(crate) const BRIDGE_ID: FieldName = "bridge_id";
pub(crate) const PORT_ID: FieldName = "port_id";
pub(crate) const MESSAGE_AGE: FieldName = "message_age";
pub(crate) const MAX_AGE: FieldName = "max_age";
pub(crate) const HELLO_TIME: FieldName = "hello_time";
pub(crate) const FORWARD_DELAY: FieldName = "forward_delay";

/// §9.3.2: Topology Change Notification — 4 bytes total, none of the
/// Configuration/RST fields below.
const TCN_BPDU_TYPE: u8 = 0x80;

/// Configuration/RST BPDU fields (§9.3.1, §9.3.3) — absent for a TCN BPDU.
pub(crate) struct ConfigFields<'a> {
    pub flags: u8,
    pub root_id: &'a [u8],
    pub root_path_cost: u32,
    pub bridge_id: &'a [u8],
    pub port_id: u16,
    pub message_age: u16,
    pub max_age: u16,
    pub hello_time: u16,
    pub forward_delay: u16,
}

/// The BPDU shape shared by classic STP/RSTP and Cisco's PVST+ (which
/// wraps the same §9.3 fields under its own SNAP PID plus a trailing
/// VLAN TLV) — factored out so `pvst_plus` doesn't duplicate this walk.
pub(crate) struct Bpdu<'a> {
    pub protocol_id: u16,
    pub version: u8,
    pub bpdu_type: u8,
    pub config: Option<ConfigFields<'a>>,
}

/// Parses the common BPDU header through the optional RSTP/MSTP Version 1
/// Length trailer. Returns the parsed fields alongside how many bytes
/// were consumed, so a caller with its own trailing data (PVST+'s VLAN
/// TLV) knows exactly where its own fields start.
pub(crate) fn parse_bpdu(bytes: &[u8]) -> Result<(Bpdu<'_>, usize), ParseError> {
    let mut r = ByteReader::new(bytes);
    let protocol_id = r.u16_be()?;
    if protocol_id != 0x0000 {
        return Err(ParseError::Malformed(
            "STP: unrecognized protocol identifier",
        ));
    }
    let version = r.u8()?;
    let bpdu_type = r.u8()?;

    // Configuration BPDU (§9.3.1, type 0x00) and RST BPDU (§9.3.3, type
    // 0x02) share this shape; TCN (§9.3.2, type 0x80) carries nothing
    // beyond the 4-byte common header parsed above — same
    // conditional-field discipline as DNS query-vs-response (06.6).
    let mut config = None;
    if bpdu_type != TCN_BPDU_TYPE {
        let flags = r.u8()?;
        let root_id = r.take(8)?;
        let root_path_cost = r.u32_be()?;
        let bridge_id = r.take(8)?;
        let port_id = r.u16_be()?;
        let message_age = r.u16_be()?;
        let max_age = r.u16_be()?;
        let hello_time = r.u16_be()?;
        let forward_delay = r.u16_be()?;

        // RSTP/MSTP (version >= 2, §9.3.3 / 802.1Q MSTP): a 1-byte
        // "Version 1 Length" trailer, 0 for pure RSTP. MSTP appends
        // region/instance TLVs after it — Tier 2, unparsed in v1 (11.1's
        // Planned table); left as opaque trailing bytes beyond
        // header_len rather than consumed here.
        if version >= 2 {
            let _version_1_length = r.u8()?;
        }

        config = Some(ConfigFields {
            flags,
            root_id,
            root_path_cost,
            bridge_id,
            port_id,
            message_age,
            max_age,
            hello_time,
            forward_delay,
        });
    }

    Ok((
        Bpdu {
            protocol_id,
            version,
            bpdu_type,
            config,
        },
        bytes.len() - r.remaining(),
    ))
}

/// Inserts the shared BPDU fields at their depth tiers — shared by `stp`
/// and `pvst_plus`.
pub(crate) fn insert_bpdu_fields(fields: &mut FieldMap, depth: Depth, bpdu: &Bpdu<'_>) {
    if depth >= Depth::Structural {
        fields.insert(PROTOCOL_ID, Value::U64(u64::from(bpdu.protocol_id)));
        fields.insert(VERSION, Value::U64(u64::from(bpdu.version)));
        fields.insert(BPDU_TYPE, Value::U64(u64::from(bpdu.bpdu_type)));
        if let Some(c) = &bpdu.config {
            fields.insert(FLAGS, Value::U64(u64::from(c.flags)));
            fields.insert(ROOT_ID, Value::from(c.root_id));
            fields.insert(BRIDGE_ID, Value::from(c.bridge_id));
        }
    }
    if depth >= Depth::Full {
        if let Some(c) = &bpdu.config {
            fields.insert(ROOT_PATH_COST, Value::U64(u64::from(c.root_path_cost)));
            fields.insert(PORT_ID, Value::U64(u64::from(c.port_id)));
            fields.insert(MESSAGE_AGE, Value::U64(u64::from(c.message_age)));
            fields.insert(MAX_AGE, Value::U64(u64::from(c.max_age)));
            fields.insert(HELLO_TIME, Value::U64(u64::from(c.hello_time)));
            fields.insert(FORWARD_DELAY, Value::U64(u64::from(c.forward_delay)));
        }
    }
}

pub struct Stp;

impl LayerPlugin for Stp {
    fn name(&self) -> ProtocolName {
        "stp"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let (bpdu, consumed) = parse_bpdu(bytes)?;
        let mut fields = FieldMap::new();
        insert_bpdu_fields(&mut fields, ctx.depth(), &bpdu);

        Ok(ParsedLayer {
            header_len: consumed,
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::Custom {
            space: "llc_dsap",
            id: 0x42,
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

    /// Classic STP Configuration BPDU (802.1D-2004 §9.3.1): version 0,
    /// this bridge is not the root (root priority 0x8000, root mac
    /// 00:1a:2b:3c:4d:5e; bridge priority 0x8000, bridge mac
    /// 00:1b:44:11:3a:b7), defaults for the timers (max age 20s, hello
    /// 2s, forward delay 15s, in 1/256s units).
    fn config_bpdu() -> Vec<u8> {
        let mut b = vec![0x00, 0x00, 0x00, 0x00]; // protocol_id, version 0, type 0x00
        b.push(0x00); // flags
        b.extend_from_slice(&[0x80, 0x00, 0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E]); // root_id
        b.extend_from_slice(&4u32.to_be_bytes()); // root_path_cost
        b.extend_from_slice(&[0x80, 0x00, 0x00, 0x1B, 0x44, 0x11, 0x3A, 0xB7]); // bridge_id
        b.extend_from_slice(&0x8001u16.to_be_bytes()); // port_id
        b.extend_from_slice(&0u16.to_be_bytes()); // message_age
        b.extend_from_slice(&0x1400u16.to_be_bytes()); // max_age (20s)
        b.extend_from_slice(&0x0200u16.to_be_bytes()); // hello_time (2s)
        b.extend_from_slice(&0x0F00u16.to_be_bytes()); // forward_delay (15s)
        b
    }

    /// RST BPDU (802.1D-2004 §9.3.3): version 2, type 0x02, same shape
    /// plus the trailing Version 1 Length byte (0 — no MSTP data).
    fn rst_bpdu() -> Vec<u8> {
        let mut b = config_bpdu();
        b[2] = 0x02; // version 2
        b[3] = 0x02; // RST BPDU type
        b[4] = 0x3C; // flags: forwarding+learning+designated role+proposal
        b.push(0x00); // Version 1 Length
        b
    }

    /// TCN BPDU (802.1D-2004 §9.3.2): 4 bytes total, nothing more.
    fn tcn_bpdu() -> Vec<u8> {
        vec![0x00, 0x00, 0x00, 0x80]
    }

    #[test]
    fn parses_the_configuration_bpdu() {
        let bytes = config_bpdu();
        let m = meta(bytes.len());
        let parsed = Stp
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid BPDU");
        assert_eq!(parsed.header_len, 35);
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(VERSION), Some(&Value::U64(0)));
        assert_eq!(parsed.fields.get(BPDU_TYPE), Some(&Value::U64(0)));
        assert_eq!(
            parsed.fields.get(ROOT_ID),
            Some(&Value::from(
                &[0x80, 0x00, 0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E][..]
            ))
        );
        assert_eq!(
            parsed.fields.get(BRIDGE_ID),
            Some(&Value::from(
                &[0x80, 0x00, 0x00, 0x1B, 0x44, 0x11, 0x3A, 0xB7][..]
            ))
        );
        assert_eq!(parsed.fields.get(ROOT_PATH_COST), Some(&Value::U64(4)));
        assert_eq!(parsed.fields.get(PORT_ID), Some(&Value::U64(0x8001)));
        assert_eq!(parsed.fields.get(MAX_AGE), Some(&Value::U64(0x1400)));
        assert_eq!(parsed.fields.get(HELLO_TIME), Some(&Value::U64(0x0200)));
        assert_eq!(parsed.fields.get(FORWARD_DELAY), Some(&Value::U64(0x0F00)));
    }

    #[test]
    fn parses_the_rst_bpdu_including_the_version_1_length_trailer() {
        let bytes = rst_bpdu();
        let m = meta(bytes.len());
        let parsed = Stp
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid BPDU");
        assert_eq!(parsed.header_len, 36, "35 + the version 1 length byte");
        assert_eq!(parsed.fields.get(VERSION), Some(&Value::U64(2)));
        assert_eq!(parsed.fields.get(BPDU_TYPE), Some(&Value::U64(2)));
        assert_eq!(parsed.fields.get(FLAGS), Some(&Value::U64(0x3C)));
    }

    #[test]
    fn parses_the_tcn_bpdu_with_no_configuration_fields() {
        let bytes = tcn_bpdu();
        let m = meta(bytes.len());
        let parsed = Stp.parse(&bytes, &ctx(Depth::Full, &m)).expect("valid TCN");
        assert_eq!(parsed.header_len, 4);
        assert_eq!(parsed.fields.get(BPDU_TYPE), Some(&Value::U64(0x80)));
        assert_eq!(parsed.fields.get(FLAGS), None);
        assert_eq!(parsed.fields.get(ROOT_ID), None);
        assert_eq!(parsed.fields.get(ROOT_PATH_COST), None);
    }

    #[test]
    fn structural_depth_omits_full_only_fields() {
        let bytes = config_bpdu();
        let m = meta(bytes.len());
        let parsed = Stp
            .parse(&bytes, &ctx(Depth::Structural, &m))
            .expect("valid BPDU");
        assert_eq!(
            parsed.fields.get(ROOT_ID),
            Some(&Value::from(
                &[0x80, 0x00, 0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E][..]
            ))
        );
        assert_eq!(parsed.fields.get(ROOT_PATH_COST), None);
        assert_eq!(parsed.fields.get(HELLO_TIME), None);
    }

    #[test]
    fn wrong_protocol_identifier_declines() {
        let mut bytes = config_bpdu();
        bytes[0] = 0xFF;
        let m = meta(bytes.len());
        assert!(Stp.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn truncated_frames_decline() {
        for bytes in [config_bpdu(), rst_bpdu(), tcn_bpdu()] {
            let m = meta(bytes.len());
            for n in 0..bytes.len() {
                let full_ctx = ctx(Depth::Full, &m);
                assert!(
                    Stp.parse(&bytes[..n], &full_ctx).is_err(),
                    "prefix of {n}/{} bytes must decline",
                    bytes.len()
                );
            }
        }
    }
}
