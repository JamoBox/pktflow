//! L2TPv3 (11.5, RFC 3931). v1 scope is the **data-message path** (the
//! actual pseudowire being tunneled); control messages (tunnel/session
//! setup AVPs) are identified but not decoded — an explicit, honestly
//! flagged limitation rather than a silent gap (11.5's domain spec).
//!
//! RFC 3931 defines two message classes sharing a common leading word
//! (§3.2.1 control / §3.2.2 data): bit 0 (`T`) selects control (1) vs.
//! data (0), and the low nibble of byte 1 (`Ver`) is always 3 for L2TPv3
//! (distinguishing it from L2TPv2's `Ver == 2`, RFC 2661 — a header this
//! size on port 1701 that isn't v3 is declined, not misread).
//!
//! Two independent encapsulations exist (§4.1.1/§4.1.2), disambiguated
//! here via `ctx.prev()` the same way `dns` reads TCP-vs-UDP framing
//! (06.6):
//! - **UDP** (`UdpPort(1701)`): carries both control and data messages,
//!   fronted by the shared T/Ver word above.
//! - **Direct IP** (`IpProtocol(115)`): data messages only (control
//!   messages MUST use UDP, §4.1.1) — no T/Ver word at all, the header
//!   *is* the Session ID (+ optional Cookie).
//!
//! Control messages (§3.2.1: Control Connection ID + Ns + Nr, then AVPs)
//! are identified — `t_bit`/`control_connection_id` are extracted — but
//! the AVP walk that would decode tunnel/session setup is Tier 2 (11's
//! README taxonomy): this plugin stops `Terminal` right after the fixed
//! 12-byte portion, an explicit limitation rather than a silent gap.
//! Because a control message carries no `session_id`, it also can't
//! satisfy this plugin's `session_id`-keyed [`StreamIdentity`] — no
//! stream forms for it (counted, not treated as a crash, per the
//! aggregator's standard missing-key handling), which is exactly the
//! "control path: identity None" the domain spec (11.5) asks for.
//!
//! Data messages (§3.2.2/§4.1.1) route onward `ByProtocol("ethernet")`:
//! L2TPv3's dominant real-world use is an Ethernet pseudowire (RFC 4719),
//! and unlike GRE/Geneve there is no protocol-type field to route by, so
//! this mirrors `vxlan`'s fixed-inner-protocol dispatch (06.5) rather
//! than GRE's field-driven one.
//!
//! **Known v1 limitation, documented not hidden** (matching AH/ESP's SPI
//! notes and QUIC's DCID-migration note elsewhere in 11): a data
//! message's optional Cookie (0/32/64 bits, §3.2.2/§4.1.1) is negotiated
//! out-of-band during control-channel setup (the L2-Specific Sublayer
//! choice is negotiated the same way, via the AVP in §4.6) and isn't
//! visible in the data header itself. Decoding the control-channel AVPs
//! that would reveal it is exactly the Tier-2 work this plugin declines
//! to do, so v1 assumes the common zero-length-cookie, no-sublayer
//! default rather than guessing a length. A deployment that negotiated a
//! non-zero cookie will have its leading cookie bytes misread as the
//! start of the inner Ethernet frame — a real, bounded misparse (no
//! panic, no phantom protocol invention), not a crash.

use pktflow_core::{
    ByteReader, Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx,
    ParseError, ParsedLayer, ProtocolName, RouteId, StreamIdentity, Value,
};

const T_BIT: FieldName = "t_bit";
const SESSION_ID: FieldName = "session_id";
const CONTROL_CONNECTION_ID: FieldName = "control_connection_id";

/// RFC 3931 §3.2.1/§3.2.2: both header shapes share this `Ver` value.
const L2TPV3_VERSION: u32 = 3;

/// §3.2.1/§3.2.2: the shared leading word (`T`/`L`/`S`/reserved bits,
/// `Ver`, then `Length` (control) or reserved (data)) — present only on
/// the UDP encapsulation.
const SHARED_WORD_LEN: usize = 4;
/// §4.1.1: the direct-IP Session Header is the Session ID alone before an
/// optional Cookie.
const SESSION_ID_LEN: usize = 4;
/// §3.2.1: Control Connection ID (4) + Ns (2) + Nr (2), present whenever
/// `T == 1` (control messages MUST carry them).
const CONTROL_TAIL_LEN: usize = 8;

static KEY: &[KeyField] = &[KeyField {
    a: SESSION_ID,
    b: None, // shared qualifier: one pseudowire stream per session id, the GRE-key/VXLAN-VNI shape (06.5/11.5)
}];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: &[],
};

pub struct L2tpv3;

impl LayerPlugin for L2tpv3 {
    fn name(&self) -> ProtocolName {
        "l2tpv3"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        // Direct-IP claim (§4.1.1) carries data messages only; the UDP
        // claim (§4.1.2) carries the shared T/Ver word up front (module
        // doc) — `ctx.prev()` is how this plugin tells the two apart, the
        // same mechanism `dns` uses for its TCP-vs-UDP framing (06.6).
        let over_udp = ctx.prev().is_some_and(|l| l.protocol == "udp");

        let mut r = ByteReader::new(bytes);
        let t_bit = if over_udp {
            let word1 = r.u32_be()?;
            let ver = (word1 >> 16) & 0x0F;
            if ver != L2TPV3_VERSION {
                return Err(ParseError::Malformed("L2TPv3: unsupported Ver"));
            }
            word1 & 0x8000_0000 != 0
        } else {
            false
        };

        let mut fields = FieldMap::new();
        let header_len;
        let hint;

        if t_bit {
            // Control path (§3.2.1): fixed portion only, AVPs are Tier 2
            // (module doc).
            let control_connection_id = r.u32_be()?;
            r.take(4)?; // Ns(2) + Nr(2): consumed for framing, not surfaced (01.3 has no use for them yet)
            header_len = SHARED_WORD_LEN + CONTROL_TAIL_LEN;
            hint = Hint::Terminal;
            if ctx.depth() >= Depth::Structural {
                fields.insert(T_BIT, Value::Bool(t_bit));
                fields.insert(
                    CONTROL_CONNECTION_ID,
                    Value::U64(u64::from(control_connection_id)),
                );
            }
        } else {
            // Data path (§3.2.2/§4.1.1): Session ID, then (module doc's
            // documented limitation) an assumed-absent Cookie.
            let session_id = r.u32_be()?;
            header_len = (if over_udp { SHARED_WORD_LEN } else { 0 }) + SESSION_ID_LEN;
            hint = Hint::ByProtocol("ethernet");
            if ctx.depth() >= Depth::Keys {
                fields.insert(SESSION_ID, Value::U64(u64::from(session_id)));
            }
            if ctx.depth() >= Depth::Structural {
                fields.insert(T_BIT, Value::Bool(t_bit));
            }
        }

        Ok(ParsedLayer {
            header_len,
            fields,
            hint,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::UdpPort(1701), RouteId::IpProtocol(115)]
    }

    fn stream_identity(&self) -> Option<&StreamIdentity> {
        Some(&IDENTITY)
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use pktflow_core::{LayerRecord, LinkType, PacketMeta};

    use super::*;

    fn meta(len: usize) -> PacketMeta {
        PacketMeta {
            timestamp: SystemTime::UNIX_EPOCH,
            caplen: len,
            origlen: len,
            link_type: LinkType::ETHERNET,
        }
    }

    fn ctx<'a>(outer: &'a [LayerRecord], depth: Depth, m: &'a PacketMeta) -> ParseCtx<'a> {
        ParseCtx::new(outer, depth, m)
    }

    fn udp_predecessor() -> Vec<LayerRecord> {
        vec![LayerRecord {
            protocol: "udp",
            offset: 34,
            header_len: 8,
            fields: FieldMap::new(),
        }]
    }

    fn ipv4_predecessor() -> Vec<LayerRecord> {
        vec![LayerRecord {
            protocol: "ipv4",
            offset: 14,
            header_len: 20,
            fields: FieldMap::new(),
        }]
    }

    /// §3.2.2: UDP-encapsulated data message, Session ID `session_id`,
    /// no cookie (v1's assumed default), then payload.
    fn udp_data_fixture(session_id: u32, payload: &[u8]) -> Vec<u8> {
        let mut b = vec![0x00, 0x03, 0x00, 0x00]; // T=0, Ver=3, reserved=0
        b.extend_from_slice(&session_id.to_be_bytes());
        b.extend_from_slice(payload);
        b
    }

    /// §3.2.1: UDP-encapsulated control message, `L`/`S` set (as real
    /// senders MUST), Length filled in, Control Connection ID, Ns, Nr,
    /// then an AVP region this plugin never walks.
    fn udp_control_fixture(ccid: u32, avps: &[u8]) -> Vec<u8> {
        let length = (12 + avps.len()) as u16;
        let mut b = vec![0x00, 0x03];
        b[0] = 0x80 | 0x40 | 0x08; // T=1, L=1, S=1
        b.extend_from_slice(&length.to_be_bytes());
        b.extend_from_slice(&ccid.to_be_bytes());
        b.extend_from_slice(&[0, 1]); // Ns
        b.extend_from_slice(&[0, 2]); // Nr
        b.extend_from_slice(avps);
        b
    }

    /// §4.1.1: direct-IP data message — Session ID only, no T/Ver word.
    fn ip_data_fixture(session_id: u32, payload: &[u8]) -> Vec<u8> {
        let mut b = session_id.to_be_bytes().to_vec();
        b.extend_from_slice(payload);
        b
    }

    #[test]
    fn udp_data_message_parses_session_id_and_stops_by_protocol() {
        let bytes = udp_data_fixture(0x1234_5678, &[0xAA, 0xBB, 0xCC, 0xDD]);
        let m = meta(bytes.len());
        let outer = udp_predecessor();
        let parsed = L2tpv3
            .parse(&bytes, &ctx(&outer, Depth::Full, &m))
            .expect("valid UDP data message");
        assert_eq!(parsed.header_len, 8);
        assert_eq!(parsed.hint, Hint::ByProtocol("ethernet"));
        assert_eq!(
            parsed.fields.get(SESSION_ID),
            Some(&Value::U64(0x1234_5678))
        );
        assert_eq!(parsed.fields.get(T_BIT), Some(&Value::Bool(false)));
        assert_eq!(parsed.fields.get(CONTROL_CONNECTION_ID), None);
    }

    #[test]
    fn ip_data_message_has_no_shared_word_and_parses_4_byte_header() {
        let bytes = ip_data_fixture(0x0000_002A, &[0xEE; 6]);
        let m = meta(bytes.len());
        let outer = ipv4_predecessor();
        let parsed = L2tpv3
            .parse(&bytes, &ctx(&outer, Depth::Full, &m))
            .expect("valid IP data message");
        assert_eq!(parsed.header_len, 4);
        assert_eq!(parsed.hint, Hint::ByProtocol("ethernet"));
        assert_eq!(parsed.fields.get(SESSION_ID), Some(&Value::U64(42)));
    }

    #[test]
    fn udp_control_message_stops_terminal_with_no_session_id() {
        let bytes = udp_control_fixture(0x0000_0007, &[0x00, 0x08, 0x00, 0x01]);
        let m = meta(bytes.len());
        let outer = udp_predecessor();
        let parsed = L2tpv3
            .parse(&bytes, &ctx(&outer, Depth::Full, &m))
            .expect("valid control message");
        assert_eq!(
            parsed.header_len, 12,
            "stops after the fixed portion, AVPs untouched"
        );
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(T_BIT), Some(&Value::Bool(true)));
        assert_eq!(
            parsed.fields.get(CONTROL_CONNECTION_ID),
            Some(&Value::U64(7))
        );
        assert_eq!(
            parsed.fields.get(SESSION_ID),
            None,
            "control messages carry no session_id: no stream can key on it"
        );
    }

    #[test]
    fn keys_depth_has_only_session_id_for_data_messages() {
        let bytes = udp_data_fixture(9, &[]);
        let m = meta(bytes.len());
        let outer = udp_predecessor();
        let parsed = L2tpv3
            .parse(&bytes, &ctx(&outer, Depth::Keys, &m))
            .expect("valid");
        assert_eq!(parsed.fields.len(), 1);
        assert_eq!(parsed.fields.get(SESSION_ID), Some(&Value::U64(9)));
    }

    #[test]
    fn keys_depth_has_no_fields_for_control_messages() {
        let bytes = udp_control_fixture(1, &[]);
        let m = meta(bytes.len());
        let outer = udp_predecessor();
        let parsed = L2tpv3
            .parse(&bytes, &ctx(&outer, Depth::Keys, &m))
            .expect("valid");
        assert!(
            parsed.fields.is_empty(),
            "t_bit/ccid are Structural, not Keys"
        );
    }

    #[test]
    fn l2tpv2_version_on_the_same_port_declines() {
        let mut bytes = udp_data_fixture(1, &[]);
        bytes[1] = 0x02; // Ver = 2 (RFC 2661, not this plugin's protocol)
        let m = meta(bytes.len());
        let outer = udp_predecessor();
        assert!(L2tpv3.parse(&bytes, &ctx(&outer, Depth::Full, &m)).is_err());
    }

    #[test]
    fn truncated_udp_data_frames_decline() {
        let bytes = udp_data_fixture(0xAABBCCDD, &[0x11, 0x22]);
        let m = meta(bytes.len());
        let outer = udp_predecessor();
        for n in 0..8 {
            let full_ctx = ctx(&outer, Depth::Full, &m);
            assert!(
                L2tpv3.parse(&bytes[..n], &full_ctx).is_err(),
                "prefix of {n}/8 header bytes must decline"
            );
        }
    }

    #[test]
    fn truncated_control_frames_decline() {
        let bytes = udp_control_fixture(5, &[0xFF, 0xFF]);
        let m = meta(bytes.len());
        let outer = udp_predecessor();
        for n in 0..12 {
            let full_ctx = ctx(&outer, Depth::Full, &m);
            assert!(
                L2tpv3.parse(&bytes[..n], &full_ctx).is_err(),
                "prefix of {n}/12 header bytes must decline"
            );
        }
    }

    #[test]
    fn truncated_ip_data_frames_decline() {
        let bytes = ip_data_fixture(3, &[0x01]);
        let m = meta(bytes.len());
        let outer = ipv4_predecessor();
        for n in 0..4 {
            let full_ctx = ctx(&outer, Depth::Full, &m);
            assert!(
                L2tpv3.parse(&bytes[..n], &full_ctx).is_err(),
                "prefix of {n}/4 header bytes must decline"
            );
        }
    }
}
