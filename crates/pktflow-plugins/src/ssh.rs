//! SSH (11.7, RFC 4251 architecture, RFC 4253 transport) — app-stream
//! pattern (06.6). Scope is narrowed to exactly what RFC 4253 guarantees is
//! cleartext: the identification banner exchange (§4.2), and each side's
//! first binary packet, `SSH_MSG_KEXINIT` — always message code 20 by
//! protocol definition (§7.1). Everything after key exchange is
//! ciphertext, including the packet-length framing itself under common
//! cipher modes, so this plugin carries no cross-packet "are we still in
//! cleartext" state (rule 5): it recognizes exactly these two shapes and
//! declines everything else, the same honest "port claimed, bytes weren't
//! ours" outcome 06.6 documents for non-DNS traffic on port 53.
//!
//! ## Identification string (RFC 4253 §4.2)
//! A single line, `SSH-protoversion-softwareversion[ SP comments]`,
//! terminated by CR LF (implementations tolerate a bare LF). Recognized by
//! the fixed `"SSH-"` prefix; `header_len` covers through the line
//! terminator.
//!
//! ## Binary Packet Protocol (RFC 4253 §6)
//! `packet_length(4, uint32, excludes itself) | padding_length(1) |
//! payload(packet_length - padding_length - 1) | random padding
//! (padding_length) | [mac]`. Before a cipher is negotiated (true for the
//! very first packets on a connection, including KEXINIT) the MAC
//! algorithm is `"none"` (§6.4), so no trailing MAC is present here.
//! `header_len` is `4 + packet_length` — self-describing framing,
//! independent of whether the payload turns out to be recognizable.
//! `payload`'s first byte is the message code; this plugin recognizes only
//! code `20` (`SSH_MSG_KEXINIT`, §7.1). Any other code — genuinely
//! encrypted post-KEX traffic wearing plausible-looking framing bytes by
//! coincidence — is declined.
//!
//! ## KEXINIT body (RFC 4253 §7.1)
//! `cookie(16, random) | 10 name-lists (RFC 4251 §5: uint32 length +
//! comma-separated ASCII, empty string = empty list) | first_kex_packet_
//! follows(bool) | reserved(uint32)`. Only the first five name-lists are
//! Tier-1 fields (`kex_algorithms`, `server_host_key_algorithms`,
//! `encryption_algorithms_client_to_server`,
//! `encryption_algorithms_server_to_client`,
//! `mac_algorithms_client_to_server`); the walk stops there — it never
//! needs to reach the remaining five lists or the trailing bool/uint32,
//! since `header_len` is already fixed by `packet_length` regardless.

use pktflow_core::{
    ByteReader, Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx,
    ParseError, ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId, StreamIdentity, Value,
};

const APP: FieldName = "app";
const BANNER: FieldName = "banner";
const MSG_TYPE: FieldName = "msg_type";
const KEX_ALGORITHMS: FieldName = "kex_algorithms";
const SERVER_HOST_KEY_ALGORITHMS: FieldName = "server_host_key_algorithms";
const ENC_C2S: FieldName = "encryption_algorithms_client_to_server";
const ENC_S2C: FieldName = "encryption_algorithms_server_to_client";
const MAC_C2S: FieldName = "mac_algorithms_client_to_server";

const SSH_MSG_KEXINIT: u8 = 20;
/// RFC 4253 §7.1: 16 random bytes preceding the name-lists.
const COOKIE_LEN: usize = 16;

static KEY: &[KeyField] = &[KeyField { a: APP, b: None }];
static ROLLUPS: &[RollupSpec] = &[RollupSpec {
    field: BANNER,
    kind: RollupKind::Sample,
}];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: ROLLUPS,
};

/// Trims a trailing CR and/or LF from an identification line.
fn trim_line_ending(mut line: &[u8]) -> &[u8] {
    if line.last() == Some(&b'\n') {
        line = &line[..line.len() - 1];
    }
    if line.last() == Some(&b'\r') {
        line = &line[..line.len() - 1];
    }
    line
}

/// RFC 4251 §5 name-list: uint32 length + comma-separated ASCII names.
fn read_name_list(r: &mut ByteReader) -> Option<Vec<Value>> {
    let len = r.u32_be().ok()?;
    let data = r.take(usize::try_from(len).ok()?).ok()?;
    let s = std::str::from_utf8(data).ok()?;
    if s.is_empty() {
        return Some(Vec::new());
    }
    Some(s.split(',').map(Value::from).collect())
}

struct Kexinit {
    kex_algorithms: Vec<Value>,
    server_host_key_algorithms: Vec<Value>,
    enc_c2s: Vec<Value>,
    enc_s2c: Vec<Value>,
    mac_c2s: Vec<Value>,
}

/// Best-effort: `header_len` is already fixed by `packet_length`
/// regardless of whether this walk succeeds, so a malformed body simply
/// omits the deep fields rather than declining the packet (rule 2's
/// depth-independent validity applies to framing, not to optional content).
fn parse_kexinit(payload: &[u8]) -> Option<Kexinit> {
    let mut r = ByteReader::new(payload);
    let _msg_type = r.u8().ok()?;
    let _cookie = r.take(COOKIE_LEN).ok()?;
    Some(Kexinit {
        kex_algorithms: read_name_list(&mut r)?,
        server_host_key_algorithms: read_name_list(&mut r)?,
        enc_c2s: read_name_list(&mut r)?,
        enc_s2c: read_name_list(&mut r)?,
        mac_c2s: read_name_list(&mut r)?,
    })
}

pub struct Ssh;

impl LayerPlugin for Ssh {
    fn name(&self) -> ProtocolName {
        "ssh"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(APP, Value::from("ssh"));
        }

        if bytes.starts_with(b"SSH-") {
            let nl = bytes
                .iter()
                .position(|&b| b == b'\n')
                .ok_or(ParseError::Truncated(pktflow_core::Truncated {
                    needed: bytes.len() + 1,
                    have: bytes.len(),
                }))?;
            let header_len = nl + 1;
            if ctx.depth() >= Depth::Structural {
                let line = trim_line_ending(&bytes[..header_len]);
                fields.insert(BANNER, Value::from(String::from_utf8_lossy(line).as_ref()));
            }
            return Ok(ParsedLayer {
                header_len,
                fields,
                hint: Hint::Terminal,
            });
        }

        let mut r = ByteReader::new(bytes);
        let packet_length = r.u32_be()?;
        if packet_length < 2 {
            return Err(ParseError::Malformed(
                "SSH packet_length too small for padding_length + payload",
            ));
        }
        let padding_length = r.u8()?;
        let body = r.take(usize::try_from(packet_length).unwrap_or(usize::MAX) - 1)?;
        if usize::from(padding_length) >= body.len() {
            return Err(ParseError::Malformed(
                "SSH padding_length leaves no room for payload",
            ));
        }
        let payload = &body[..body.len() - usize::from(padding_length)];
        let mut pr = ByteReader::new(payload);
        let msg_type = pr
            .u8()
            .map_err(|_| ParseError::Malformed("SSH payload is empty"))?;
        if msg_type != SSH_MSG_KEXINIT {
            return Err(ParseError::Malformed(
                "not an SSH identification line or a KEXINIT packet",
            ));
        }
        let header_len = 4 + usize::try_from(packet_length).unwrap_or(usize::MAX);

        if ctx.depth() >= Depth::Structural {
            fields.insert(MSG_TYPE, Value::U64(u64::from(msg_type)));
        }
        if ctx.depth() >= Depth::Full {
            if let Some(k) = parse_kexinit(payload) {
                fields.insert(KEX_ALGORITHMS, Value::List(k.kex_algorithms));
                fields.insert(
                    SERVER_HOST_KEY_ALGORITHMS,
                    Value::List(k.server_host_key_algorithms),
                );
                fields.insert(ENC_C2S, Value::List(k.enc_c2s));
                fields.insert(ENC_S2C, Value::List(k.enc_s2c));
                fields.insert(MAC_C2S, Value::List(k.mac_c2s));
            }
        }

        Ok(ParsedLayer {
            header_len,
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::TcpPort(22)]
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

    fn name_list(names: &[&str]) -> Vec<u8> {
        let joined = names.join(",");
        let mut out = (joined.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(joined.as_bytes());
        out
    }

    /// A KEXINIT packet with the five Tier-1 name-lists filled in and the
    /// remaining five left empty, followed by first_kex_packet_follows(0)
    /// and a zero reserved word — a complete, well-formed message.
    fn kexinit_packet() -> Vec<u8> {
        let mut payload = vec![SSH_MSG_KEXINIT];
        payload.extend_from_slice(&[0xAB; COOKIE_LEN]);
        payload.extend_from_slice(&name_list(&[
            "curve25519-sha256",
            "diffie-hellman-group14-sha1",
        ]));
        payload.extend_from_slice(&name_list(&["ssh-ed25519", "rsa-sha2-512"]));
        payload.extend_from_slice(&name_list(&["aes256-gcm@openssh.com"]));
        payload.extend_from_slice(&name_list(&["aes256-gcm@openssh.com"]));
        payload.extend_from_slice(&name_list(&["hmac-sha2-256"]));
        // Remaining five name-lists, empty.
        for _ in 0..5 {
            payload.extend_from_slice(&name_list(&[]));
        }
        payload.push(0); // first_kex_packet_follows
        payload.extend_from_slice(&0u32.to_be_bytes()); // reserved

        // padding_length chosen so (payload.len() + padding_length + 1) is
        // a multiple of 8 (RFC 4253 §6), minimum 4 padding bytes.
        let mut padding_length = 4u8;
        while !(1 + payload.len() + usize::from(padding_length)).is_multiple_of(8) {
            padding_length += 1;
        }
        let packet_length = (1 + payload.len() + usize::from(padding_length)) as u32;

        let mut packet = packet_length.to_be_bytes().to_vec();
        packet.push(padding_length);
        packet.extend_from_slice(&payload);
        packet.extend(std::iter::repeat_n(0u8, usize::from(padding_length)));
        packet
    }

    #[test]
    fn client_and_server_banners_parse() {
        for banner in [&b"SSH-2.0-OpenSSH_9.6\r\n"[..], b"SSH-2.0-libssh_0.10.6\n"] {
            let m = meta(banner.len());
            let parsed = Ssh
                .parse(banner, &ctx(Depth::Full, &m))
                .unwrap_or_else(|e| panic!("{banner:?}: {e}"));
            assert_eq!(parsed.header_len, banner.len());
            assert_eq!(parsed.hint, Hint::Terminal);
            assert_eq!(parsed.fields.get(APP), Some(&Value::from("ssh")));
            let expected = String::from_utf8_lossy(trim_line_ending(banner));
            assert_eq!(
                parsed.fields.get(BANNER),
                Some(&Value::from(expected.as_ref()))
            );
            assert_eq!(parsed.fields.get(MSG_TYPE), None);
        }
    }

    #[test]
    fn banner_with_trailing_bytes_stops_at_the_line() {
        let mut bytes = b"SSH-2.0-OpenSSH_9.6\r\n".to_vec();
        bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x10]); // start of a binary packet, unparsed here
        let m = meta(bytes.len());
        let parsed = Ssh
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid banner");
        assert_eq!(parsed.header_len, 21);
    }

    #[test]
    fn kexinit_parses_msg_type_and_five_name_lists() {
        let bytes = kexinit_packet();
        let m = meta(bytes.len());
        let parsed = Ssh
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid KEXINIT");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(MSG_TYPE), Some(&Value::U64(20)));
        assert_eq!(
            parsed.fields.get(KEX_ALGORITHMS),
            Some(&Value::List(vec![
                Value::from("curve25519-sha256"),
                Value::from("diffie-hellman-group14-sha1"),
            ]))
        );
        assert_eq!(
            parsed.fields.get(SERVER_HOST_KEY_ALGORITHMS),
            Some(&Value::List(vec![
                Value::from("ssh-ed25519"),
                Value::from("rsa-sha2-512"),
            ]))
        );
        assert_eq!(
            parsed.fields.get(ENC_C2S),
            Some(&Value::List(vec![Value::from("aes256-gcm@openssh.com")]))
        );
        assert_eq!(
            parsed.fields.get(ENC_S2C),
            Some(&Value::List(vec![Value::from("aes256-gcm@openssh.com")]))
        );
        assert_eq!(
            parsed.fields.get(MAC_C2S),
            Some(&Value::List(vec![Value::from("hmac-sha2-256")]))
        );
        assert_eq!(parsed.fields.get(BANNER), None);
    }

    #[test]
    fn structural_depth_has_msg_type_but_not_the_name_lists() {
        let bytes = kexinit_packet();
        let m = meta(bytes.len());
        let parsed = Ssh
            .parse(&bytes, &ctx(Depth::Structural, &m))
            .expect("valid KEXINIT");
        assert_eq!(parsed.fields.get(MSG_TYPE), Some(&Value::U64(20)));
        assert_eq!(parsed.fields.get(KEX_ALGORITHMS), None);
    }

    #[test]
    fn keys_depth_only_has_app() {
        let bytes = kexinit_packet();
        let m = meta(bytes.len());
        let parsed = Ssh
            .parse(&bytes, &ctx(Depth::Keys, &m))
            .expect("valid KEXINIT");
        assert_eq!(parsed.fields.get(APP), Some(&Value::from("ssh")));
        assert_eq!(parsed.fields.get(MSG_TYPE), None);
    }

    /// The port-claim-honesty criterion (ported from 06.6's DNS case,
    /// 11.7): a synthetic "encrypted-looking" packet on port 22, whose
    /// framing happens to parse but whose message code is not KEXINIT,
    /// declines rather than misreading ciphertext as a message type.
    #[test]
    fn encrypted_looking_packet_declines() {
        let mut bytes = 12u32.to_be_bytes().to_vec(); // packet_length
        bytes.push(4); // padding_length
        bytes.push(99); // msg_type: not KEXINIT
        bytes.extend_from_slice(&[0xAA, 0xBB, 0xCC]); // remaining payload
        bytes.extend_from_slice(&[0u8; 4]); // padding
        let m = meta(bytes.len());
        assert!(Ssh.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn neither_banner_nor_binary_packet_declines() {
        let bytes = b"NOT-SSH-AT-ALL".to_vec();
        let m = meta(bytes.len());
        // Doesn't start with "SSH-": falls to binary-packet parsing, whose
        // first four bytes here don't form a plausible packet_length/
        // padding_length/msg_type shape, so it declines either way (a
        // too-small packet_length or a wrong msg_type).
        assert!(Ssh.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn truncated_banner_declines() {
        let bytes = b"SSH-2.0-OpenSSH_9.6".to_vec(); // no line terminator
        let m = meta(bytes.len());
        assert!(Ssh.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn truncated_kexinit_declines_at_every_prefix() {
        let bytes = kexinit_packet();
        let m = meta(bytes.len());
        let full = ctx(Depth::Full, &m);
        for n in 0..bytes.len() {
            assert!(
                Ssh.parse(&bytes[..n], &full).is_err(),
                "prefix of {n}/{} bytes must decline",
                bytes.len()
            );
        }
    }

    #[test]
    fn padding_length_overrunning_packet_declines() {
        let mut bytes = 4u32.to_be_bytes().to_vec(); // packet_length = 4
        bytes.push(10); // padding_length > remaining body (3 bytes)
        bytes.extend_from_slice(&[0u8; 3]);
        let m = meta(bytes.len());
        assert!(Ssh.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }
}
