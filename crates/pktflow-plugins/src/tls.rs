//! TLS (11.7, RFC 8446 TLS 1.3 / RFC 5246 TLS 1.2) — app-stream pattern
//! (06.6): TLS's identity is its TCP session.
//!
//! **v1 scope / the encryption ceiling (D12).** Only the cleartext parts of
//! a session are decoded: the record framing on every record, and the
//! `ClientHello`/`ServerHello` handshake messages (which are sent in the
//! clear). `ApplicationData` records (`content_type == 23`) are opaque, and
//! handshake records past `ServerHello` (Certificate, KeyExchange, Finished)
//! are recognized by `content_type`/`handshake_type` but not decoded
//! further. STARTTLS upgrades (a plaintext-then-TLS transition mid-session)
//! cannot be detected by a single-packet, stateless plugin — an explicit,
//! documented v1 gap, not silently mishandled.
//!
//! **App-stream pattern (06.6).** TLS has no endpoint identity of its own,
//! so the key is one shared constant field (`app = "tls"`) — exactly one
//! child stream per TCP session, a clean home for rollups.
//!
//! Framing: `header_len` covers the whole TLS record (5-byte header +
//! `length` fragment). The full record is consumed via `ByteReader::take`,
//! so any truncated prefix declines cleanly (rule 1) and the header is
//! self-contained (rule 4). Only the first record in a segment is parsed —
//! the same single-message stance `dns`-over-TCP and `bgp` take (D7).

use pktflow_core::{
    ByteReader, Canonicalize, Confidence, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin,
    ParseCtx, ParseError, ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId,
    StreamIdentity, Value,
};

const APP: FieldName = "app";
const CONTENT_TYPE: FieldName = "content_type";
const RECORD_VERSION: FieldName = "record_version";
const HANDSHAKE_TYPE: FieldName = "handshake_type";
const SNI: FieldName = "sni";
const ALPN: FieldName = "alpn";
const CIPHER_SUITES: FieldName = "cipher_suites";
const SELECTED_CIPHER_SUITE: FieldName = "selected_cipher_suite";
const TLS_VERSION_SELECTED: FieldName = "tls_version_selected";

const CT_HANDSHAKE: u8 = 22;
const HS_CLIENT_HELLO: u8 = 1;
const HS_SERVER_HELLO: u8 = 2;

const EXT_SERVER_NAME: u16 = 0;
const EXT_ALPN: u16 = 16;
const EXT_SUPPORTED_VERSIONS: u16 = 43;

/// Valid TLS `ContentType`s (RFC 8446 §5.1): ChangeCipherSpec(20),
/// Alert(21), Handshake(22), ApplicationData(23).
fn is_content_type(ct: u8) -> bool {
    matches!(ct, 20..=23)
}

/// A plausible record `ProtocolVersion`: high byte `0x03`, low byte within
/// SSL 3.0 (`0x0300`) through TLS 1.3 (`0x0304`). The legacy record version
/// is often `0x0301` even in a 1.2/1.3 handshake, so the range stays wide.
fn is_record_version(v: u16) -> bool {
    (0x0300..=0x0304).contains(&v)
}

static KEY: &[KeyField] = &[KeyField { a: APP, b: None }];
static ROLLUPS: &[RollupSpec] = &[
    // The server name(s) this session negotiated — the analytic payoff for
    // otherwise-opaque HTTPS traffic (whom did this device talk to). A
    // session showing more than one SNI has renegotiated.
    RollupSpec {
        field: SNI,
        kind: RollupKind::Sample,
    },
    // The handshake types seen over the session (ClientHello, ServerHello,
    // ...). `selected_cipher_suite`/`tls_version_selected` would be natural
    // companions, but they appear only in the ServerHello while `sni`
    // appears only in the ClientHello — no single record carries both, and
    // the 09.1 kit (rule 3) requires every rollup field on every canonical
    // sample, so those stay per-packet Full fields rather than rollups.
    RollupSpec {
        field: HANDSHAKE_TYPE,
        kind: RollupKind::Accumulate,
    },
];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: ROLLUPS,
};

/// The cleartext handshake fields this v1 extracts, all best-effort: a
/// malformed inner length omits the affected field rather than failing the
/// whole record (the outer record framing already governs truncation).
#[derive(Default)]
struct Handshake {
    hs_type: u8,
    cipher_suites: Option<Vec<Value>>,
    sni: Option<String>,
    alpn: Option<Vec<Value>>,
    selected_cipher_suite: Option<u16>,
    tls_version_selected: Option<u16>,
}

/// Walks a TLS extensions block into `(ext_type, ext_data)` pairs,
/// stopping at the first malformed entry (best-effort, never panics).
fn walk_extensions(block: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    let mut r = ByteReader::new(block);
    while r.remaining() >= 4 {
        let Ok(ext_type) = r.u16_be() else { break };
        let Ok(ext_len) = r.u16_be() else { break };
        let Ok(data) = r.take(usize::from(ext_len)) else {
            break;
        };
        out.push((ext_type, data));
    }
    out
}

/// Extracts the first `host_name` from a server_name extension (RFC 6066 §3).
fn parse_sni(data: &[u8]) -> Option<String> {
    let mut r = ByteReader::new(data);
    let _list_len = r.u16_be().ok()?;
    // ServerNameList: at least one `NameType(1) + length(2) + name` entry.
    let name_type = r.u8().ok()?;
    let name_len = r.u16_be().ok()?;
    let name = r.take(usize::from(name_len)).ok()?;
    (name_type == 0).then(|| String::from_utf8_lossy(name).into_owned())
}

/// Extracts every protocol string from an ALPN extension (RFC 7301 §3.1).
fn parse_alpn(data: &[u8]) -> Option<Vec<Value>> {
    let mut r = ByteReader::new(data);
    let _list_len = r.u16_be().ok()?;
    let mut protos = Vec::new();
    while r.remaining() > 0 {
        let plen = r.u8().ok()?;
        let proto = r.take(usize::from(plen)).ok()?;
        protos.push(Value::from(
            String::from_utf8_lossy(proto).into_owned().as_str(),
        ));
    }
    (!protos.is_empty()).then_some(protos)
}

/// Parses a handshake fragment. `deep` gates the Full-only field walk
/// (extensions, cipher lists); the structural `hs_type` is always read.
fn parse_handshake(fragment: &[u8], deep: bool) -> Option<Handshake> {
    let mut r = ByteReader::new(fragment);
    let hs_type = r.u8().ok()?;
    let _hs_len = {
        // 24-bit handshake length; read to advance, framing is the record's.
        let hi = r.u8().ok()?;
        let mid = r.u8().ok()?;
        let lo = r.u8().ok()?;
        (usize::from(hi) << 16) | (usize::from(mid) << 8) | usize::from(lo)
    };
    let mut hs = Handshake {
        hs_type,
        ..Handshake::default()
    };
    if !deep || (hs_type != HS_CLIENT_HELLO && hs_type != HS_SERVER_HELLO) {
        return Some(hs);
    }

    // Both hellos: legacy_version(2) + random(32) + session_id(<=32).
    let legacy_version = r.u16_be().ok()?;
    let _random = r.take(32).ok()?;
    let sid_len = r.u8().ok()?;
    let _sid = r.take(usize::from(sid_len)).ok()?;

    if hs_type == HS_CLIENT_HELLO {
        let cs_len = r.u16_be().ok()?;
        let cs_bytes = r.take(usize::from(cs_len)).ok()?;
        let mut suites = Vec::new();
        let mut cs = ByteReader::new(cs_bytes);
        while let Ok(suite) = cs.u16_be() {
            suites.push(Value::U64(u64::from(suite)));
        }
        hs.cipher_suites = Some(suites);
        let comp_len = r.u8().ok()?;
        let _comp = r.take(usize::from(comp_len)).ok()?;
    } else {
        // ServerHello: single selected cipher suite, one compression byte.
        hs.selected_cipher_suite = Some(r.u16_be().ok()?);
        let _comp = r.u8().ok()?;
        hs.tls_version_selected = Some(legacy_version);
    }

    // Extensions are optional (a bare hello may omit them entirely).
    let exts = r
        .u16_be()
        .ok()
        .and_then(|ext_total| r.take(usize::from(ext_total)).ok())
        .map(walk_extensions)
        .unwrap_or_default();
    for (ext_type, data) in exts {
        match ext_type {
            EXT_SERVER_NAME if hs_type == HS_CLIENT_HELLO => hs.sni = parse_sni(data),
            EXT_ALPN if hs_type == HS_CLIENT_HELLO => hs.alpn = parse_alpn(data),
            EXT_SUPPORTED_VERSIONS if hs_type == HS_SERVER_HELLO => {
                // In a ServerHello this extension carries the single
                // negotiated version (RFC 8446 §4.2.1) — the real TLS 1.3
                // version, since legacy_version is pinned to 0x0303.
                if let Ok(v) = ByteReader::new(data).u16_be() {
                    hs.tls_version_selected = Some(v);
                }
            }
            _ => {}
        }
    }
    Some(hs)
}

pub struct Tls;

impl LayerPlugin for Tls {
    fn name(&self) -> ProtocolName {
        "tls"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let content_type = r.u8()?;
        if !is_content_type(content_type) {
            return Err(ParseError::Malformed("not a TLS content type"));
        }
        let record_version = r.u16_be()?;
        if !is_record_version(record_version) {
            return Err(ParseError::Malformed("implausible TLS record version"));
        }
        let length = usize::from(r.u16_be()?);
        // Consume the whole record so `header_len` is honest and every
        // truncated prefix declines.
        let fragment = r.take(length)?;
        let header_len = 5 + length;

        // Deep handshake fields are only extracted at Full depth.
        let handshake = (content_type == CT_HANDSHAKE)
            .then(|| parse_handshake(fragment, ctx.depth() >= Depth::Full))
            .flatten();

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(APP, Value::from("tls"));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(CONTENT_TYPE, Value::U64(u64::from(content_type)));
            fields.insert(RECORD_VERSION, Value::U64(u64::from(record_version)));
            if let Some(hs) = &handshake {
                fields.insert(HANDSHAKE_TYPE, Value::U64(u64::from(hs.hs_type)));
            }
        }
        if ctx.depth() >= Depth::Full {
            if let Some(hs) = handshake {
                if let Some(suites) = hs.cipher_suites {
                    fields.insert(CIPHER_SUITES, Value::List(suites));
                }
                if let Some(sni) = hs.sni {
                    fields.insert(SNI, Value::from(sni.as_str()));
                }
                if let Some(alpn) = hs.alpn {
                    fields.insert(ALPN, Value::List(alpn));
                }
                if let Some(cs) = hs.selected_cipher_suite {
                    fields.insert(SELECTED_CIPHER_SUITE, Value::U64(u64::from(cs)));
                }
                if let Some(v) = hs.tls_version_selected {
                    fields.insert(TLS_VERSION_SELECTED, Value::U64(u64::from(v)));
                }
            }
        }

        Ok(ParsedLayer {
            header_len,
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::TcpPort(443)]
    }

    fn has_probe(&self) -> bool {
        true
    }

    /// TLS runs on many ports beyond 443 (993, 995, 465/587, 636, 3389, ...),
    /// so an honest probe lets the fallback pool recognize it there. A valid
    /// content type plus a plausible record version is a specific-enough
    /// signal to clear `MIN_CONFIDENCE` (50) — the score at which the router
    /// actually acts on a probe — while staying near-silent on random bytes
    /// (the 09.1 kit's rule 5 verifies both).
    fn probe(&self, bytes: &[u8], _ctx: &ParseCtx) -> Option<Confidence> {
        let mut r = ByteReader::new(bytes);
        let content_type = r.u8().ok()?;
        let record_version = r.u16_be().ok()?;
        let length = r.u16_be().ok()?;
        // Reject a length that can't be a real record fragment given the
        // buffer we can see, tightening the signal further.
        let plausible_len = usize::from(length) <= bytes.len().saturating_sub(5) + 16;
        (is_content_type(content_type) && is_record_version(record_version) && plausible_len)
            .then(|| Confidence::new(55))
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

    /// Wraps a handshake `body` in a Handshake record (content_type 22).
    fn handshake_record(hs_type: u8, body: &[u8]) -> Vec<u8> {
        let mut hs = vec![hs_type];
        let len = body.len();
        hs.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
        hs.extend_from_slice(body);
        let mut rec = vec![CT_HANDSHAKE, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    fn ext(ext_type: u16, data: &[u8]) -> Vec<u8> {
        let mut e = ext_type.to_be_bytes().to_vec();
        e.extend_from_slice(&(data.len() as u16).to_be_bytes());
        e.extend_from_slice(data);
        e
    }

    /// A ClientHello for `example.com` offering ALPN h2/http1.1 and two
    /// cipher suites — hand-built against RFC 8446 §4.1.2.
    pub(super) fn client_hello() -> Vec<u8> {
        let sni_name = b"example.com";
        let mut server_name = Vec::new();
        server_name.push(0u8); // host_name
        server_name.extend_from_slice(&(sni_name.len() as u16).to_be_bytes());
        server_name.extend_from_slice(sni_name);
        let mut sni_ext_data = (server_name.len() as u16).to_be_bytes().to_vec();
        sni_ext_data.extend_from_slice(&server_name);

        let mut alpn_list = Vec::new();
        for p in [&b"h2"[..], &b"http/1.1"[..]] {
            alpn_list.push(p.len() as u8);
            alpn_list.extend_from_slice(p);
        }
        let mut alpn_ext_data = (alpn_list.len() as u16).to_be_bytes().to_vec();
        alpn_ext_data.extend_from_slice(&alpn_list);

        let mut exts = Vec::new();
        exts.extend_from_slice(&ext(EXT_SERVER_NAME, &sni_ext_data));
        exts.extend_from_slice(&ext(EXT_ALPN, &alpn_ext_data));

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy_version TLS 1.2
        body.extend_from_slice(&[0x11; 32]); // random
        body.push(0); // session_id length 0
        body.extend_from_slice(&[0x00, 0x04]); // cipher_suites length
        body.extend_from_slice(&[0x13, 0x01, 0x13, 0x02]); // TLS_AES_128/256_GCM
        body.push(1); // compression_methods length
        body.push(0); // null compression
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        handshake_record(HS_CLIENT_HELLO, &body)
    }

    /// A ServerHello selecting TLS_AES_128_GCM_SHA256 (0x1301), announcing
    /// TLS 1.3 via the supported_versions extension (RFC 8446 §4.2.1).
    fn server_hello() -> Vec<u8> {
        let sv_ext = ext(EXT_SUPPORTED_VERSIONS, &[0x03, 0x04]); // TLS 1.3
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy_version pinned 1.2
        body.extend_from_slice(&[0x22; 32]); // random
        body.push(0); // session_id length 0
        body.extend_from_slice(&[0x13, 0x01]); // selected cipher suite
        body.push(0); // null compression
        body.extend_from_slice(&(sv_ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&sv_ext);
        handshake_record(HS_SERVER_HELLO, &body)
    }

    #[test]
    fn client_hello_recovers_sni_alpn_and_ciphers() {
        let bytes = client_hello();
        let m = meta(bytes.len());
        let parsed = Tls
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid ClientHello");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(APP), Some(&Value::from("tls")));
        assert_eq!(parsed.fields.get(CONTENT_TYPE), Some(&Value::U64(22)));
        assert_eq!(parsed.fields.get(HANDSHAKE_TYPE), Some(&Value::U64(1)));
        assert_eq!(parsed.fields.get(SNI), Some(&Value::from("example.com")));
        assert_eq!(
            parsed.fields.get(ALPN),
            Some(&Value::List(vec![
                Value::from("h2"),
                Value::from("http/1.1")
            ]))
        );
        assert_eq!(
            parsed.fields.get(CIPHER_SUITES),
            Some(&Value::List(vec![Value::U64(0x1301), Value::U64(0x1302)]))
        );
        // ServerHello-only fields must be absent on a ClientHello.
        assert_eq!(parsed.fields.get(SELECTED_CIPHER_SUITE), None);
    }

    #[test]
    fn server_hello_recovers_selected_cipher_and_version() {
        let bytes = server_hello();
        let m = meta(bytes.len());
        let parsed = Tls
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid ServerHello");
        assert_eq!(parsed.fields.get(HANDSHAKE_TYPE), Some(&Value::U64(2)));
        assert_eq!(
            parsed.fields.get(SELECTED_CIPHER_SUITE),
            Some(&Value::U64(0x1301))
        );
        // supported_versions announces the real 1.3, not legacy 0x0303.
        assert_eq!(
            parsed.fields.get(TLS_VERSION_SELECTED),
            Some(&Value::U64(0x0304))
        );
        assert_eq!(parsed.fields.get(SNI), None);
    }

    #[test]
    fn application_data_is_opaque_terminal() {
        // content_type 23, TLS 1.2, 4-byte opaque fragment.
        let bytes = [0x17u8, 0x03, 0x03, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF];
        let m = meta(bytes.len());
        let parsed = Tls
            .parse(&bytes, &ctx(Depth::Full, &m))
            .expect("valid AppData");
        assert_eq!(parsed.header_len, bytes.len());
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(CONTENT_TYPE), Some(&Value::U64(23)));
        assert_eq!(parsed.fields.get(HANDSHAKE_TYPE), None);
        assert_eq!(parsed.fields.get(SNI), None);
    }

    #[test]
    fn keys_depth_only_has_app() {
        let bytes = client_hello();
        let m = meta(bytes.len());
        let parsed = Tls
            .parse(&bytes, &ctx(Depth::Keys, &m))
            .expect("valid ClientHello");
        assert_eq!(parsed.fields.get(APP), Some(&Value::from("tls")));
        assert_eq!(parsed.fields.get(CONTENT_TYPE), None);
        assert_eq!(parsed.fields.get(SNI), None);
    }

    #[test]
    fn structural_depth_omits_deep_handshake_fields() {
        let bytes = client_hello();
        let m = meta(bytes.len());
        let parsed = Tls
            .parse(&bytes, &ctx(Depth::Structural, &m))
            .expect("valid ClientHello");
        assert_eq!(parsed.fields.get(HANDSHAKE_TYPE), Some(&Value::U64(1)));
        assert_eq!(parsed.fields.get(SNI), None);
        assert_eq!(parsed.fields.get(CIPHER_SUITES), None);
    }

    #[test]
    fn non_tls_content_type_declines() {
        // 0x47 = 'G' (an HTTP GET on a mis-claimed port) is not a TLS record.
        let bytes = [0x47u8, 0x45, 0x54, 0x20, 0x2F];
        let m = meta(bytes.len());
        assert!(Tls.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn implausible_version_declines() {
        let bytes = [0x16u8, 0x99, 0x99, 0x00, 0x00];
        let m = meta(bytes.len());
        assert!(Tls.parse(&bytes, &ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn probe_is_confident_on_tls_and_silent_on_http() {
        let m = meta(64);
        let hello = client_hello();
        assert!(Tls.probe(&hello, &ctx(Depth::Full, &m)).is_some());
        // A cleartext HTTP request must not probe as TLS.
        let http = b"GET / HTTP/1.1\r\n\r\n";
        assert!(Tls.probe(http, &ctx(Depth::Full, &m)).is_none());
    }

    #[test]
    fn truncated_frames_decline() {
        let bytes = client_hello();
        let m = meta(bytes.len());
        for n in 0..bytes.len() {
            let full = ctx(Depth::Full, &m);
            assert!(
                Tls.parse(&bytes[..n], &full).is_err(),
                "prefix of {n}/{} bytes must decline",
                bytes.len()
            );
        }
    }
}
