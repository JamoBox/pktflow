//! HSRP (11.4: RFC 2281 — Cisco's pre-standard, informational equivalent
//! of VRRP, IANA/Cisco UDP port 1985): the same group-beacon pattern
//! `vrrp` already establishes (11.4/06.5) — one **HSRP group** stream per
//! standby group number, aggregating every speaker's Hello/Coup/Resign
//! messages for that group regardless of which physical router currently
//! holds Active.
//!
//! RFC 2281 §5's message format is a single fixed 20-byte layout (no
//! version-dependent branching the way VRRPv2/v3 or OSPFv2/v3 need):
//!
//! ```text
//! Version | Op Code | State | Hellotime | Holdtime | Priority | Group | Reserved
//! Authentication Data (8 octets)
//! Virtual IP Address (4 octets)
//! ```
//!
//! - **Version** (RFC 2281 §5): this document defines version 0 only.
//!   HSRPv2 (undocumented, Cisco-only) is a from-scratch TLV redesign, not
//!   a version bump of this layout — RFC 2281's own successor note
//!   observes that a v1 receiver sees HSRPv2's leading TLV-type octet
//!   land in this same byte position and (correctly, per that receiver's
//!   contract) ignores it. This plugin makes the same call explicit:
//!   anything other than 0 here declines cleanly rather than
//!   misinterpreting a differently-shaped packet as v1 (D12's "decline on
//!   the part you can't honestly parse" stance, not a new stop-reason
//!   kind).
//! - **Op Code** (§5): 0 Hello, 1 Coup, 2 Resign — captured raw. RFC 2281
//!   reserves other values for future use without changing the header
//!   shape, so (unlike VRRP's single defined type) an unrecognized code
//!   here doesn't invalidate the rest of the fixed-format packet.
//! - **State** (§3, §5): the standby state machine's current state —
//!   0 Initial, 1 Learn, 2 Listen, 4 Speak, 8 Standby, 16 Active — also
//!   captured raw for the same reason.
//! - **Hellotime/Holdtime** (§5): whole seconds, meaningful only in Hello
//!   messages per the RFC but structurally present in every message type;
//!   defaults are 3s/10s but the wire always carries the sender's actual
//!   configured values.
//! - **Group** (§5): one octet, the standby group number (0-255 in this
//!   version); this is the shared qualifier the group-beacon key is built
//!   from, the same role VRRP's `vrid` plays.
//! - **Authentication Data** (§5): 8 octets, a cleartext plaintext-password
//!   scheme (Cisco IOS defaults this to `"cisco"`, zero-padded) — sent in
//!   the clear by the protocol itself, not a pktflow limitation (D12).
//! - **Virtual IP Address** (§5): 4 octets, the group's virtual IPv4
//!   address (HSRPv1 is IPv4-only; RFC 2281 predates any IPv6 variant).

use pktflow_core::{
    ByteReader, Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx,
    ParseError, ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId, StreamIdentity, Value,
};

const GROUP: FieldName = "group";
const VERSION: FieldName = "version";
const OPCODE: FieldName = "opcode";
const STATE: FieldName = "state";
const PRIORITY: FieldName = "priority";
const HELLOTIME: FieldName = "hellotime";
const HOLDTIME: FieldName = "holdtime";
const VIRTUAL_IP: FieldName = "virtual_ip";
const AUTH_DATA: FieldName = "auth_data";

/// RFC 2281 §5: the only version this document defines. Anything else
/// (notably HSRPv2's unrelated TLV format landing its type octet here,
/// module doc) is out of scope and declined rather than misparsed.
const VERSION_1: u8 = 0;

/// RFC 2281 §5: fixed header length — no options, no version-dependent
/// layout.
const HEADER_LEN: usize = 20;

/// RFC 2281 §5: Authentication Data is a fixed 8-octet cleartext field.
const AUTH_DATA_LEN: usize = 8;

/// RFC 2281 §5: Virtual IP Address is a fixed 4-octet IPv4 address
/// (HSRPv1 is IPv4-only).
const VIRTUAL_IP_LEN: usize = 4;

static KEY: &[KeyField] = &[KeyField {
    a: GROUP,
    b: None, // shared qualifier: one stream per standby group number
}];
static ROLLUPS: &[RollupSpec] = &[
    RollupSpec {
        field: STATE,
        kind: RollupKind::Accumulate,
    },
    RollupSpec {
        field: PRIORITY,
        kind: RollupKind::Accumulate,
    },
];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: ROLLUPS,
};

pub struct Hsrp;

impl LayerPlugin for Hsrp {
    fn name(&self) -> ProtocolName {
        "hsrp"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let version = r.u8()?;
        if version != VERSION_1 {
            return Err(ParseError::Malformed("HSRP: unsupported version"));
        }
        let opcode = r.u8()?;
        let state = r.u8()?;
        let hellotime = r.u8()?;
        let holdtime = r.u8()?;
        let priority = r.u8()?;
        let group = r.u8()?;
        let _reserved = r.u8()?;
        let auth_data = r.take(AUTH_DATA_LEN)?;
        let virtual_ip = r.take(VIRTUAL_IP_LEN)?;

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(GROUP, Value::U64(u64::from(group)));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(VERSION, Value::U64(u64::from(version)));
            fields.insert(OPCODE, Value::U64(u64::from(opcode)));
            fields.insert(STATE, Value::U64(u64::from(state)));
            fields.insert(PRIORITY, Value::U64(u64::from(priority)));
            fields.insert(HELLOTIME, Value::U64(u64::from(hellotime)));
            fields.insert(HOLDTIME, Value::U64(u64::from(holdtime)));
        }
        if ctx.depth() >= Depth::Full {
            fields.insert(VIRTUAL_IP, Value::from(virtual_ip));
            fields.insert(AUTH_DATA, Value::from(auth_data));
        }

        Ok(ParsedLayer {
            header_len: HEADER_LEN,
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::UdpPort(1985)]
    }

    fn stream_identity(&self) -> Option<&StreamIdentity> {
        Some(&IDENTITY)
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use pktflow_core::{Depth, LinkType, PacketMeta};

    use super::*;

    fn meta(len: usize) -> PacketMeta {
        PacketMeta {
            timestamp: SystemTime::UNIX_EPOCH,
            caplen: len,
            origlen: len,
            link_type: LinkType::ETHERNET,
        }
    }

    fn ctx<'a>(depth: Depth, m: &'a PacketMeta) -> ParseCtx<'a> {
        ParseCtx::new(&[], depth, m)
    }

    /// RFC 2281 §5: version 0, Hello (0), Active (16), hellotime 3s,
    /// holdtime 10s, priority 100, group 1, reserved 0, auth data
    /// `"cisco"` zero-padded to 8 bytes, virtual IP 192.168.1.1.
    fn hello_fixture() -> Vec<u8> {
        let mut b = vec![0, 0, 16, 3, 10, 100, 1, 0];
        b.extend_from_slice(b"cisco\0\0\0");
        b.extend_from_slice(&[192, 168, 1, 1]);
        b
    }

    #[test]
    fn hello_message_parses_exactly() {
        let bytes = hello_fixture();
        let m = meta(bytes.len());
        let parsed = Hsrp
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid HSRP Hello message");
        assert_eq!(parsed.header_len, HEADER_LEN);
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(GROUP), Some(&Value::U64(1)));
        assert_eq!(parsed.fields.get(VERSION), Some(&Value::U64(0)));
        assert_eq!(parsed.fields.get(OPCODE), Some(&Value::U64(0)));
        assert_eq!(parsed.fields.get(STATE), Some(&Value::U64(16)));
        assert_eq!(parsed.fields.get(PRIORITY), Some(&Value::U64(100)));
        assert_eq!(parsed.fields.get(HELLOTIME), Some(&Value::U64(3)));
        assert_eq!(parsed.fields.get(HOLDTIME), Some(&Value::U64(10)));
        assert_eq!(
            parsed.fields.get(VIRTUAL_IP),
            Some(&Value::from(&[192u8, 168, 1, 1][..]))
        );
        assert_eq!(
            parsed.fields.get(AUTH_DATA),
            Some(&Value::from(&b"cisco\0\0\0"[..]))
        );
    }

    #[test]
    fn keys_depth_has_only_group() {
        let bytes = hello_fixture();
        let m = meta(bytes.len());
        let parsed = Hsrp
            .parse(&bytes, &ctx(Depth::Keys, &m))
            .expect("valid HSRP Hello message");
        assert_eq!(parsed.fields.len(), 1);
        assert_eq!(parsed.fields.get(GROUP), Some(&Value::U64(1)));
    }

    #[test]
    fn structural_depth_omits_virtual_ip_and_auth_data() {
        let bytes = hello_fixture();
        let m = meta(bytes.len());
        let parsed = Hsrp
            .parse(&bytes, &ctx(Depth::Structural, &m))
            .expect("valid HSRP Hello message");
        assert_eq!(parsed.fields.get(VIRTUAL_IP), None);
        assert_eq!(parsed.fields.get(AUTH_DATA), None);
        assert_eq!(parsed.fields.get(PRIORITY), Some(&Value::U64(100)));
    }

    #[test]
    fn coup_and_resign_opcodes_parse_like_hello() {
        for opcode in [1u8, 2] {
            let mut bytes = hello_fixture();
            bytes[1] = opcode;
            let m = meta(bytes.len());
            let parsed = Hsrp
                .parse(&bytes, &ctx(Depth::Full, &m))
                .unwrap_or_else(|e| panic!("opcode {opcode} must parse: {e}"));
            assert_eq!(
                parsed.fields.get(OPCODE),
                Some(&Value::U64(u64::from(opcode)))
            );
        }
    }

    #[test]
    fn unrecognized_opcode_still_parses_fixed_format() {
        // RFC 2281 §5: opcodes other than 0/1/2 are reserved for future
        // use, not invalid — the fixed header shape doesn't depend on it.
        let mut bytes = hello_fixture();
        bytes[1] = 200;
        let m = meta(bytes.len());
        let parsed = Hsrp
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("reserved opcode still parses");
        assert_eq!(parsed.fields.get(OPCODE), Some(&Value::U64(200)));
    }

    #[test]
    fn unsupported_version_declines() {
        let mut bytes = hello_fixture();
        bytes[0] = 2; // e.g. HSRPv2's TLV-type octet landing here
        let m = meta(bytes.len());
        assert!(Hsrp.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn zero_group_is_valid() {
        let mut bytes = hello_fixture();
        bytes[6] = 0;
        let m = meta(bytes.len());
        let parsed = Hsrp
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("group 0 is a valid standby group number");
        assert_eq!(parsed.fields.get(GROUP), Some(&Value::U64(0)));
    }

    #[test]
    fn truncated_frames_decline() {
        let bytes = hello_fixture();
        let m = meta(bytes.len());
        for n in 0..bytes.len() {
            let full_ctx = ctx(Depth::Full, &m);
            assert!(
                Hsrp.parse(&bytes[..n], &full_ctx).is_err(),
                "prefix of {n}/{} bytes must decline",
                bytes.len()
            );
        }
    }

    #[test]
    fn exact_length_with_trailing_bytes_ignores_trailer() {
        let mut bytes = hello_fixture();
        bytes.extend_from_slice(&[0xAA, 0xBB]); // e.g. link-layer padding
        let m = meta(bytes.len());
        let parsed = Hsrp
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("trailing bytes beyond the fixed header are fine");
        assert_eq!(parsed.header_len, HEADER_LEN);
    }
}
