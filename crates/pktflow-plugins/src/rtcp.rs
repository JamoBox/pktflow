//! RTCP (11.10, RFC 3550, the same document as RTP — sender/receiver
//! reports, source description, bye). Same reachability stance as `rtp`:
//! no well-known port, no `probe()` (a `probe()` here would be dead code
//! under UDP's unconditional `Candidates` gate, D15) — real, specified,
//! and fixture-tested by feeding bytes directly to `parse()`.
//!
//! ## Common header (RFC 3550 §6.4.1 SR / §6.4.2 RR / §6.5 SDES / §6.6 BYE
//! ## / §6.7 APP)
//! `V(2)+P(1)+RC-or-SC(5) | PacketType(8) | length(16, in 32-bit words,
//! minus one)`. `header_len` is `(length+1)*4` — self-describing across
//! every packet type, the same "consume the declared unit" stance
//! `tls`/`sctp`/`stun` take, so it never needs a type-specific walk. Every
//! RTCP packet type places an SSRC (or, for `SDES`/`BYE`, the first
//! chunk's SSRC/CSRC) in the 4 bytes immediately following this common
//! header — the uniform `ssrc` Keys field this plugin reads regardless of
//! `packet_type`.
//!
//! ## `SR`-only fields (RFC 3550 §6.4.1)
//! `NTP timestamp(64) | RTP timestamp(32) | sender's packet count(32) |
//! sender's octet count(32)` follow the SSRC; the reception report blocks
//! after them are not walked (out of Tier-1 scope).
//!
//! ## `SDES`-only field (RFC 3550 §6.5)
//! The first chunk's SDES items are `type(8) + length(8) + text`,
//! terminated by a `type == 0` padding octet; this plugin walks only that
//! first chunk, best-effort, looking for `CNAME` (`type == 1`) — the
//! remaining chunks and any non-CNAME items are not extracted.

use pktflow_core::{
    ByteReader, Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx,
    ParseError, ParsedLayer, ProtocolName, RollupKind, RollupSpec, StreamIdentity, Value,
};

const SSRC: FieldName = "ssrc";
const PACKET_TYPE: FieldName = "packet_type";
const NTP_TIMESTAMP: FieldName = "ntp_timestamp";
const RTP_TIMESTAMP: FieldName = "rtp_timestamp";
const PACKET_COUNT: FieldName = "packet_count";
const OCTET_COUNT: FieldName = "octet_count";
const CNAME: FieldName = "cname";

const RTCP_VERSION: u8 = 2;
const PT_SR: u8 = 200;
const PT_RR: u8 = 201;
const PT_SDES: u8 = 202;
const PT_BYE: u8 = 203;
const PT_APP: u8 = 204;

const SDES_CNAME: u8 = 1;

static KEY: &[KeyField] = &[KeyField { a: SSRC, b: None }];
static ROLLUPS: &[RollupSpec] = &[RollupSpec {
    field: PACKET_TYPE,
    kind: RollupKind::Accumulate,
}];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: ROLLUPS,
};

/// Best-effort walk of the first SDES chunk's items for `CNAME` (module
/// doc); any truncation or absence yields `None`, never a decline.
fn read_first_cname(chunk_after_ssrc: &[u8]) -> Option<String> {
    let mut r = ByteReader::new(chunk_after_ssrc);
    loop {
        let item_type = r.u8().ok()?;
        if item_type == 0 {
            return None;
        }
        let item_len = r.u8().ok()?;
        let text = r.take(usize::from(item_len)).ok()?;
        if item_type == SDES_CNAME {
            return std::str::from_utf8(text).ok().map(String::from);
        }
    }
}

pub struct Rtcp;

impl LayerPlugin for Rtcp {
    fn name(&self) -> ProtocolName {
        "rtcp"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let byte0 = r.u8()?;
        let version = (byte0 & 0xC0) >> 6;
        if version != RTCP_VERSION {
            return Err(ParseError::Malformed("unsupported RTCP version"));
        }
        let packet_type = r.u8()?;
        let length_words = r.u16_be()?;
        let total_len = (usize::from(length_words) + 1) * 4;
        let body = r.take(total_len - 4)?;
        let header_len = total_len;

        let mut br = ByteReader::new(body);
        let ssrc = br.u32_be()?;

        let mut ntp_timestamp = None;
        let mut rtp_timestamp = None;
        let mut packet_count = None;
        let mut octet_count = None;
        let mut cname = None;
        match packet_type {
            PT_SR => {
                if let (Ok(ntp_sec), Ok(ntp_frac), Ok(rtp_ts), Ok(pkt_cnt), Ok(oct_cnt)) = (
                    br.u32_be(),
                    br.u32_be(),
                    br.u32_be(),
                    br.u32_be(),
                    br.u32_be(),
                ) {
                    ntp_timestamp = Some((u64::from(ntp_sec) << 32) | u64::from(ntp_frac));
                    rtp_timestamp = Some(rtp_ts);
                    packet_count = Some(pkt_cnt);
                    octet_count = Some(oct_cnt);
                }
            }
            PT_SDES => {
                cname = read_first_cname(&body[4.min(body.len())..]);
            }
            PT_RR | PT_BYE | PT_APP => {}
            _ => return Err(ParseError::Malformed("unrecognized RTCP packet type")),
        }

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(SSRC, Value::U64(u64::from(ssrc)));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(PACKET_TYPE, Value::U64(u64::from(packet_type)));
        }
        if ctx.depth() >= Depth::Full {
            if let Some(v) = ntp_timestamp {
                fields.insert(NTP_TIMESTAMP, Value::U64(v));
            }
            if let Some(v) = rtp_timestamp {
                fields.insert(RTP_TIMESTAMP, Value::U64(u64::from(v)));
            }
            if let Some(v) = packet_count {
                fields.insert(PACKET_COUNT, Value::U64(u64::from(v)));
            }
            if let Some(v) = octet_count {
                fields.insert(OCTET_COUNT, Value::U64(u64::from(v)));
            }
            if let Some(v) = cname {
                fields.insert(CNAME, Value::from(v.as_str()));
            }
        }

        Ok(ParsedLayer {
            header_len,
            fields,
            hint: Hint::Terminal,
        })
    }

    // No `claims()`, no probe (module doc): unreachable via routing in v1.

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

    fn common_header(packet_type: u8, length_words: u16) -> Vec<u8> {
        let mut b = vec![0x80]; // version 2, no padding, RC/SC = 0
        b.push(packet_type);
        b.extend_from_slice(&length_words.to_be_bytes());
        b
    }

    #[test]
    fn sr_parses_all_full_fields() {
        let mut bytes = common_header(PT_SR, 6); // (6+1)*4 = 28 bytes total
        bytes.extend_from_slice(&0x1234_5678u32.to_be_bytes()); // ssrc
        bytes.extend_from_slice(&0x1111_1111u32.to_be_bytes()); // ntp sec
        bytes.extend_from_slice(&0x2222_2222u32.to_be_bytes()); // ntp frac
        bytes.extend_from_slice(&999u32.to_be_bytes()); // rtp ts
        bytes.extend_from_slice(&10u32.to_be_bytes()); // packet count
        bytes.extend_from_slice(&2000u32.to_be_bytes()); // octet count
        let m = meta(bytes.len());
        let parsed = Rtcp.parse(&bytes, &ctx(Depth::Full, &m)).expect("valid SR");
        assert_eq!(parsed.header_len, 28);
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(SSRC), Some(&Value::U64(0x1234_5678)));
        assert_eq!(parsed.fields.get(PACKET_TYPE), Some(&Value::U64(200)));
        assert_eq!(
            parsed.fields.get(NTP_TIMESTAMP),
            Some(&Value::U64(0x1111_1111_2222_2222))
        );
        assert_eq!(parsed.fields.get(RTP_TIMESTAMP), Some(&Value::U64(999)));
        assert_eq!(parsed.fields.get(PACKET_COUNT), Some(&Value::U64(10)));
        assert_eq!(parsed.fields.get(OCTET_COUNT), Some(&Value::U64(2000)));
    }

    #[test]
    fn rr_parses_ssrc_only() {
        let mut bytes = common_header(PT_RR, 1); // (1+1)*4 = 8 bytes
        bytes.extend_from_slice(&0xAAAA_BBBBu32.to_be_bytes());
        let m = meta(bytes.len());
        let parsed = Rtcp.parse(&bytes, &ctx(Depth::Full, &m)).expect("valid RR");
        assert_eq!(parsed.header_len, 8);
        assert_eq!(parsed.fields.get(SSRC), Some(&Value::U64(0xAAAA_BBBB)));
        assert_eq!(parsed.fields.get(NTP_TIMESTAMP), None);
    }

    #[test]
    fn sdes_recovers_first_chunk_cname() {
        let mut items = vec![SDES_CNAME, 5];
        items.extend_from_slice(b"alice");
        items.push(0); // end of chunk
        while !items.len().is_multiple_of(4) {
            items.push(0); // pad chunk to 32-bit boundary (RFC 3550 §6.5)
        }
        // Total packet bytes = 4 (common header) + 4 (ssrc) + items; the
        // length field is that total in 32-bit words, minus one.
        let total_bytes = 4 + 4 + items.len();
        let length_words = (total_bytes / 4 - 1) as u16;
        let mut bytes = common_header(PT_SDES, length_words);
        bytes.extend_from_slice(&0x9999_9999u32.to_be_bytes());
        bytes.extend_from_slice(&items);
        let m = meta(bytes.len());
        let parsed = Rtcp
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid SDES");
        assert_eq!(parsed.fields.get(CNAME), Some(&Value::from("alice")));
    }

    #[test]
    fn bye_and_app_parse_ssrc_with_no_type_specific_fields() {
        for pt in [PT_BYE, PT_APP] {
            let mut bytes = common_header(pt, 1);
            bytes.extend_from_slice(&0x5555_5555u32.to_be_bytes());
            let m = meta(bytes.len());
            let parsed = Rtcp
                .parse(&bytes, &ctx(Depth::Full, &m))
                .unwrap_or_else(|e| panic!("pt {pt}: {e}"));
            assert_eq!(parsed.fields.get(SSRC), Some(&Value::U64(0x5555_5555)));
            assert_eq!(parsed.fields.get(CNAME), None);
        }
    }

    #[test]
    fn depth_gates_packet_type_and_sr_fields() {
        let mut bytes = common_header(PT_SR, 6);
        bytes.extend_from_slice(&[0u8; 24]);
        let m = meta(bytes.len());
        let keys = Rtcp.parse(&bytes, &ctx(Depth::Keys, &m)).expect("valid");
        assert_eq!(keys.fields.get(SSRC), Some(&Value::U64(0)));
        assert_eq!(keys.fields.get(PACKET_TYPE), None);

        let structural = Rtcp
            .parse(&bytes, &ctx(Depth::Structural, &m))
            .expect("valid");
        assert_eq!(structural.fields.get(PACKET_TYPE), Some(&Value::U64(200)));
        assert_eq!(structural.fields.get(NTP_TIMESTAMP), None);
    }

    #[test]
    fn wrong_version_declines() {
        let mut bytes = common_header(PT_RR, 1);
        bytes[0] = 0x00;
        bytes.extend_from_slice(&[0u8; 4]);
        let m = meta(bytes.len());
        assert!(Rtcp.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn unrecognized_packet_type_declines() {
        let mut bytes = common_header(199, 1);
        bytes.extend_from_slice(&[0u8; 4]);
        let m = meta(bytes.len());
        assert!(Rtcp.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn truncated_frames_decline_at_every_prefix() {
        let mut bytes = common_header(PT_SR, 6);
        bytes.extend_from_slice(&[0u8; 24]);
        let m = meta(bytes.len());
        let full = ctx(Depth::Full, &m);
        for n in 0..bytes.len() {
            assert!(
                Rtcp.parse(&bytes[..n], &full).is_err(),
                "prefix of {n}/{} bytes must decline",
                bytes.len()
            );
        }
    }

    #[test]
    fn no_claims_declared() {
        assert!(Rtcp.claims().is_empty());
        assert!(!Rtcp.has_probe());
    }
}
