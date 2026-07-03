//! GRE (06.5, RFC 2784/2890): a tunnel whose next protocol is *named* by
//! a field — GRE reuses the EtherType space, so no new route space is
//! needed (03.1).

use pktflow_core::{
    ByteReader, Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx,
    ParseError, ParsedLayer, ProtocolName, RouteId, StreamIdentity, Value,
};

const KEY_FIELD: FieldName = "key";
const FLAGS: FieldName = "flags";
const PROTOCOL: FieldName = "protocol";
const VERSION: FieldName = "version";
const CHECKSUM: FieldName = "checksum";
const SEQUENCE: FieldName = "sequence";

const C_BIT: u16 = 0x8000;
const K_BIT: u16 = 0x2000;
const S_BIT: u16 = 0x1000;

static KEY: &[KeyField] = &[KeyField {
    a: KEY_FIELD,
    b: None, // shared (non-endpoint) qualifier: one stream per GRE key
}];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: &[],
};

pub struct Gre;

impl LayerPlugin for Gre {
    fn name(&self) -> ProtocolName {
        "gre"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let flags_version = r.u16_be()?;
        let version = flags_version & 0x0007;
        if version != 0 {
            return Err(ParseError::Malformed("GRE version is not 0"));
        }
        let protocol = r.u16_be()?;

        let mut header_len = 4usize;
        let mut checksum = None;
        if flags_version & C_BIT != 0 {
            checksum = Some(r.u16_be()?);
            let _reserved = r.u16_be()?;
            header_len += 4;
        }
        // Keyless tunnels emit key = 0: an absent field would kill key
        // building (05.1), and keyless GRE between one IP pair genuinely
        // is one stream — nothing distinguishes them (06.5).
        let mut key = 0u32;
        if flags_version & K_BIT != 0 {
            key = r.u32_be()?;
            header_len += 4;
        }
        let mut sequence = None;
        if flags_version & S_BIT != 0 {
            sequence = Some(r.u32_be()?);
            header_len += 4;
        }

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(KEY_FIELD, Value::U64(u64::from(key)));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(FLAGS, Value::U64(u64::from(flags_version >> 12)));
            fields.insert(PROTOCOL, Value::U64(u64::from(protocol)));
            fields.insert(VERSION, Value::U64(u64::from(version)));
        }
        if ctx.depth() >= Depth::Full {
            if let Some(ck) = checksum {
                fields.insert(CHECKSUM, Value::U64(u64::from(ck)));
            }
            if let Some(seq) = sequence {
                fields.insert(SEQUENCE, Value::U64(u64::from(seq)));
            }
        }

        Ok(ParsedLayer {
            header_len,
            fields,
            hint: Hint::Route(RouteId::EtherType(protocol)),
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::IpProtocol(47)]
    }

    // No probe: tunnels are explicit-only (06.5).

    fn stream_identity(&self) -> Option<&StreamIdentity> {
        Some(&IDENTITY)
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use pktflow_core::{LinkType, PacketMeta};

    use super::*;

    fn parse(bytes: &[u8]) -> Result<ParsedLayer, ParseError> {
        let meta = PacketMeta {
            timestamp: SystemTime::UNIX_EPOCH,
            caplen: bytes.len(),
            origlen: bytes.len(),
            link_type: LinkType::ETHERNET,
        };
        Gre.parse(bytes, &ParseCtx::new(&[], Depth::Full, &meta))
    }

    /// GRE header with the requested option words present.
    fn header(c: bool, k: bool, s: bool) -> Vec<u8> {
        let mut flags = 0u16;
        if c {
            flags |= C_BIT;
        }
        if k {
            flags |= K_BIT;
        }
        if s {
            flags |= S_BIT;
        }
        let mut h = Vec::new();
        h.extend_from_slice(&flags.to_be_bytes());
        h.extend_from_slice(&0x0800u16.to_be_bytes());
        if c {
            h.extend_from_slice(&[0xAB, 0xCD, 0x00, 0x00]);
        }
        if k {
            h.extend_from_slice(&7u32.to_be_bytes());
        }
        if s {
            h.extend_from_slice(&42u32.to_be_bytes());
        }
        h
    }

    #[test]
    fn all_eight_flag_combinations_size_correctly() {
        for bits in 0..8u8 {
            let (c, k, s) = (bits & 4 != 0, bits & 2 != 0, bits & 1 != 0);
            let bytes = header(c, k, s);
            let expected = 4 + 4 * usize::from(c) + 4 * usize::from(k) + 4 * usize::from(s);
            let parsed = parse(&bytes).expect("valid header");
            assert_eq!(parsed.header_len, expected, "C={c} K={k} S={s}");
            assert_eq!(
                parsed.fields.get("key"),
                Some(&Value::U64(if k { 7 } else { 0 })),
                "key always present"
            );
            // Truncation inside the last optional word declines cleanly.
            assert!(parse(&bytes[..expected - 1]).is_err(), "C={c} K={k} S={s}");
        }
    }

    #[test]
    fn nonzero_version_declines() {
        let mut bytes = header(false, false, false);
        bytes[1] |= 0x01; // version 1 (PPTP's enhanced GRE): not ours
        assert!(parse(&bytes).is_err());
    }
}
