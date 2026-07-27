//! NFS (11.9, RFC 1813 NFSv3, RFC 7530 NFSv4) — rides on ONC RPC (RFC
//! 5531). App-stream pattern (06.6); v1 reads only the RPC call/reply
//! envelope, not credentials/verifiers or NFS arguments.
//!
//! **NFSv3's dynamic-port ceiling (D15).** NFSv3 traditionally negotiates
//! its actual port via portmapper/rpcbind (port 111); only NFS traffic on
//! the fixed port 2049 (the common NFSv4 case, and modern NFSv3
//! deployments that pin it there too) is reachable via the static claim in
//! v1.
//!
//! ## Framing: UDP vs. TCP (RFC 5531 §10 vs. §11)
//! Over UDP, one datagram is exactly one RPC message. Over TCP, each
//! message is prefixed by a 4-byte record-marking fragment header (top bit
//! = last-fragment flag, low 31 bits = fragment length) — this plugin
//! reads that prefix (via `ctx.prev()`, the immediate predecessor's
//! protocol name, the same outer-context read `vrrp` uses for its address
//! width, 11.4) but does not otherwise treat it specially: both transports
//! converge on the same RPC message layout immediately after.
//!
//! ## RPC message envelope (RFC 5531 §9)
//! Every message opens `xid(4) | msg_type(4, 0=CALL/1=REPLY)`. A **Call**
//! continues `rpcvers(4, must be 2) | program(4) | program_version(4) |
//! procedure(4)`, then the opaque `cred`/`verf` (RFC 5531 §8.2's
//! `opaque_auth`, variable-length) and the procedure's own arguments —
//! none of which this plugin parses (`header_len` stops right before them,
//! the same "stop before the opaque/unparsed part" stance `http` takes
//! before its body). A **Reply** continues `reply_stat(4, must be 0
//! MSG_ACCEPTED or 1 MSG_DENIED)`; `program`/`program_version`/`procedure`
//! have no wire presence in a Reply (this plugin is stateless, rule 5 —
//! it never correlates a Reply back to its Call), so those fields are
//! simply absent there. NFSv4's `COMPOUND` (RFC 7530 §14.2, `procedure ==
//! 1`) is recognized as exactly that via the plain `procedure` field —
//! its nested operation list is not walked, a real Tier 2 candidate.

use pktflow_core::{
    ByteReader, Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx,
    ParseError, ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId, StreamIdentity, Value,
};

const APP: FieldName = "app";
const XID: FieldName = "xid";
const MSG_TYPE: FieldName = "msg_type";
const PROGRAM: FieldName = "program";
const PROGRAM_VERSION: FieldName = "program_version";
const PROCEDURE: FieldName = "procedure";

const RPC_CALL: u32 = 0;
const RPC_REPLY: u32 = 1;
/// RFC 5531 §9: the only defined ONC RPC version.
const RPC_VERSION_2: u32 = 2;
const MSG_ACCEPTED: u32 = 0;
const MSG_DENIED: u32 = 1;

static KEY: &[KeyField] = &[KeyField { a: APP, b: None }];
static ROLLUPS: &[RollupSpec] = &[RollupSpec {
    field: PROCEDURE,
    kind: RollupKind::Accumulate,
}];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: ROLLUPS,
};

pub struct Nfs;

impl LayerPlugin for Nfs {
    fn name(&self) -> ProtocolName {
        "nfs"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let is_tcp = ctx.prev().map(|l| l.protocol) == Some("tcp");
        let prefix_len = if is_tcp {
            let _record_marking = r.u32_be()?;
            4
        } else {
            0
        };

        let xid = r.u32_be()?;
        let msg_type = r.u32_be()?;

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(APP, Value::from("nfs"));
        }

        let header_len = match msg_type {
            RPC_CALL => {
                let rpcvers = r.u32_be()?;
                if rpcvers != RPC_VERSION_2 {
                    return Err(ParseError::Malformed("unsupported ONC RPC version"));
                }
                let program = r.u32_be()?;
                let program_version = r.u32_be()?;
                let procedure = r.u32_be()?;
                if ctx.depth() >= Depth::Structural {
                    fields.insert(XID, Value::U64(u64::from(xid)));
                    fields.insert(MSG_TYPE, Value::from("call"));
                    fields.insert(PROGRAM, Value::U64(u64::from(program)));
                    fields.insert(PROGRAM_VERSION, Value::U64(u64::from(program_version)));
                    fields.insert(PROCEDURE, Value::U64(u64::from(procedure)));
                }
                prefix_len + 24
            }
            RPC_REPLY => {
                let reply_stat = r.u32_be()?;
                if reply_stat != MSG_ACCEPTED && reply_stat != MSG_DENIED {
                    return Err(ParseError::Malformed("unrecognized RPC reply_stat"));
                }
                if ctx.depth() >= Depth::Structural {
                    fields.insert(XID, Value::U64(u64::from(xid)));
                    fields.insert(MSG_TYPE, Value::from("reply"));
                }
                prefix_len + 12
            }
            _ => return Err(ParseError::Malformed("unrecognized RPC msg_type")),
        };

        Ok(ParsedLayer {
            header_len,
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::UdpPort(2049), RouteId::TcpPort(2049)]
    }

    fn stream_identity(&self) -> Option<&StreamIdentity> {
        Some(&IDENTITY)
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

    fn udp_ctx<'a>(depth: Depth, meta: &'a PacketMeta) -> ParseCtx<'a> {
        ParseCtx::new(&[], depth, meta)
    }

    fn tcp_predecessor() -> Vec<LayerRecord> {
        vec![LayerRecord {
            protocol: "tcp",
            offset: 34,
            header_len: 20,
            fields: CoreFieldMap::new(),
        }]
    }

    fn call(xid: u32, program: u32, program_version: u32, procedure: u32) -> Vec<u8> {
        let mut b = xid.to_be_bytes().to_vec();
        b.extend_from_slice(&RPC_CALL.to_be_bytes());
        b.extend_from_slice(&RPC_VERSION_2.to_be_bytes());
        b.extend_from_slice(&program.to_be_bytes());
        b.extend_from_slice(&program_version.to_be_bytes());
        b.extend_from_slice(&procedure.to_be_bytes());
        b
    }

    fn reply(xid: u32, reply_stat: u32) -> Vec<u8> {
        let mut b = xid.to_be_bytes().to_vec();
        b.extend_from_slice(&RPC_REPLY.to_be_bytes());
        b.extend_from_slice(&reply_stat.to_be_bytes());
        b
    }

    #[test]
    fn nfsv3_getattr_call_over_udp_parses() {
        // GETATTR is NFSv3 procedure 1 (RFC 1813 §3.3.1).
        let bytes = call(0x1234_5678, 100_003, 3, 1);
        let m = meta(bytes.len());
        let parsed = Nfs
            .parse(&bytes, &udp_ctx(Depth::Full, &m))
            .expect("valid NFSv3 GETATTR call");
        assert_eq!(parsed.header_len, 24);
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(APP), Some(&Value::from("nfs")));
        assert_eq!(parsed.fields.get(XID), Some(&Value::U64(0x1234_5678)));
        assert_eq!(parsed.fields.get(MSG_TYPE), Some(&Value::from("call")));
        assert_eq!(parsed.fields.get(PROGRAM), Some(&Value::U64(100_003)));
        assert_eq!(parsed.fields.get(PROGRAM_VERSION), Some(&Value::U64(3)));
        assert_eq!(parsed.fields.get(PROCEDURE), Some(&Value::U64(1)));
    }

    #[test]
    fn nfsv3_lookup_reply_over_udp_has_no_program_fields() {
        let bytes = reply(0x1234_5678, MSG_ACCEPTED);
        let m = meta(bytes.len());
        let parsed = Nfs
            .parse(&bytes, &udp_ctx(Depth::Full, &m))
            .expect("valid reply");
        assert_eq!(parsed.header_len, 12);
        assert_eq!(parsed.fields.get(MSG_TYPE), Some(&Value::from("reply")));
        assert_eq!(parsed.fields.get(PROGRAM), None);
        assert_eq!(parsed.fields.get(PROCEDURE), None);
    }

    #[test]
    fn nfsv4_compound_call_recognized_via_procedure_one() {
        let bytes = call(0xAAAA_BBBB, 100_003, 4, 1);
        let m = meta(bytes.len());
        let parsed = Nfs
            .parse(&bytes, &udp_ctx(Depth::Full, &m))
            .expect("valid NFSv4 COMPOUND call");
        assert_eq!(parsed.fields.get(PROGRAM_VERSION), Some(&Value::U64(4)));
        assert_eq!(parsed.fields.get(PROCEDURE), Some(&Value::U64(1)));
    }

    #[test]
    fn tcp_transport_consumes_the_record_marking_prefix() {
        let mut bytes = vec![0x80, 0x00, 0x00, 24]; // last-fragment, length 24
        bytes.extend_from_slice(&call(1, 100_003, 3, 1));
        let m = meta(bytes.len());
        let layers = tcp_predecessor();
        let ctx = ParseCtx::new(&layers, Depth::Full, &m);
        let parsed = Nfs.parse(&bytes, &ctx).expect("valid TCP-framed call");
        assert_eq!(parsed.header_len, 4 + 24);
        assert_eq!(parsed.fields.get(PROCEDURE), Some(&Value::U64(1)));
    }

    #[test]
    fn depth_gates_program_fields() {
        let bytes = call(1, 100_003, 3, 1);
        let m = meta(bytes.len());
        let keys = Nfs.parse(&bytes, &udp_ctx(Depth::Keys, &m)).expect("valid");
        assert_eq!(keys.fields.get(APP), Some(&Value::from("nfs")));
        assert_eq!(keys.fields.get(PROCEDURE), None);
    }

    #[test]
    fn unsupported_rpc_version_declines() {
        let mut bytes = 1u32.to_be_bytes().to_vec();
        bytes.extend_from_slice(&RPC_CALL.to_be_bytes());
        bytes.extend_from_slice(&4u32.to_be_bytes()); // rpcvers = 4, invalid
        bytes.extend_from_slice(&[0u8; 12]);
        let m = meta(bytes.len());
        assert!(Nfs.parse(&bytes, &udp_ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn unrecognized_msg_type_declines() {
        let mut bytes = 1u32.to_be_bytes().to_vec();
        bytes.extend_from_slice(&2u32.to_be_bytes()); // msg_type 2: invalid
        let m = meta(bytes.len());
        assert!(Nfs.parse(&bytes, &udp_ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn unrecognized_reply_stat_declines() {
        let bytes = reply(1, 2); // reply_stat 2: invalid
        let m = meta(bytes.len());
        assert!(Nfs.parse(&bytes, &udp_ctx(Depth::Full, &m)).is_err());
    }

    #[test]
    fn truncated_frames_decline_at_every_prefix() {
        let bytes = call(1, 100_003, 3, 1);
        let m = meta(bytes.len());
        let full = udp_ctx(Depth::Full, &m);
        for n in 0..bytes.len() {
            assert!(
                Nfs.parse(&bytes[..n], &full).is_err(),
                "prefix of {n}/{} bytes must decline",
                bytes.len()
            );
        }
    }
}
