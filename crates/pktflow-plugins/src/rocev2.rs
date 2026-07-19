//! RoCEv2 (InfiniBand Base Transport Header over UDP 4791, IBTA
//! Annex A17): RDMA over Converged Ethernet — the storage and AI-cluster
//! transport of modern data centers. The BTH is 12 fixed bytes:
//! `opcode(8) | SE(1) M(1) pad(2) tver(4) | pkey(16) | resv(8) |
//! dest_qp(24) | A(1) resv(7) | psn(24)`.
//!
//! Everything after the BTH is opcode-specific (RETH/AETH extended
//! headers, then RDMA payload and an ICV) with no self-describing length
//! at this layer, so the hint is [`Hint::Terminal`] — the RDMA payload is
//! the conversation's cargo, not another protocol layer.
//!
//! Stream identity keys on the destination queue pair, the
//! shared-qualifier shape GRE's `key`/VXLAN's `vni` established (06.5):
//! a QP is the RDMA analogue of a port-pair flow, and one stream per QP
//! under the UDP flow is exactly how fabric operators reason about RoCE
//! traffic. The `opcode` rollup accumulates the verb mix (SEND, RDMA
//! WRITE, READ request/response, ACK) per QP.

use pktflow_core::{
    ByteReader, Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx,
    ParseError, ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId, StreamIdentity, Value,
};

const DEST_QP: FieldName = "dest_qp";
const OPCODE: FieldName = "opcode";
const PKEY: FieldName = "pkey";
const PSN: FieldName = "psn";
const PAD_COUNT: FieldName = "pad_count";
const SOLICITED: FieldName = "solicited";
const MIG_REQ: FieldName = "mig_req";
const ACK_REQ: FieldName = "ack_req";

/// IBTA §5.2.3: BTH transport version — only 0 is defined.
const TVER: u8 = 0;

static KEY: &[KeyField] = &[KeyField {
    a: DEST_QP,
    b: None, // shared qualifier: one stream per destination queue pair
}];
static ROLLUPS: &[RollupSpec] = &[RollupSpec {
    field: OPCODE,
    kind: RollupKind::Accumulate,
}];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: ROLLUPS,
};

pub struct Rocev2;

impl LayerPlugin for Rocev2 {
    fn name(&self) -> ProtocolName {
        "rocev2"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let opcode = r.u8()?;
        let se_m_pad_tver = r.u8()?;
        if se_m_pad_tver & 0x0F != TVER {
            return Err(ParseError::Malformed("RoCEv2: unknown transport version"));
        }
        let pkey = r.u16_be()?;
        let _reserved = r.u8()?;
        let dest_qp = r.take(3)?;
        let dest_qp = dest_qp
            .iter()
            .fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
        let ack_reserved = r.u8()?;
        let psn = r.take(3)?;
        let psn = psn.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b));

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(DEST_QP, Value::U64(dest_qp));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(OPCODE, Value::U64(u64::from(opcode)));
            fields.insert(PKEY, Value::U64(u64::from(pkey)));
        }
        if ctx.depth() >= Depth::Full {
            fields.insert(PSN, Value::U64(psn));
            fields.insert(PAD_COUNT, Value::U64(u64::from((se_m_pad_tver >> 4) & 0x3)));
            fields.insert(SOLICITED, Value::Bool(se_m_pad_tver & 0x80 != 0));
            fields.insert(MIG_REQ, Value::Bool(se_m_pad_tver & 0x40 != 0));
            fields.insert(ACK_REQ, Value::Bool(ack_reserved & 0x80 != 0));
        }

        Ok(ParsedLayer {
            header_len: 12,
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::UdpPort(4791)]
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

    fn parse(bytes: &[u8]) -> Result<ParsedLayer, ParseError> {
        let meta = PacketMeta {
            timestamp: SystemTime::UNIX_EPOCH,
            caplen: bytes.len(),
            origlen: bytes.len(),
            link_type: LinkType::ETHERNET,
        };
        Rocev2.parse(bytes, &ParseCtx::new(&[], Depth::Full, &meta))
    }

    /// BTH for the caller's opcode/QP/PSN: SE set, no migration, pad 0,
    /// tver 0, default pkey 0xFFFF, ACK requested.
    fn bth(opcode: u8, dest_qp: u32, psn: u32) -> Vec<u8> {
        let mut b = vec![opcode, 0x80, 0xFF, 0xFF, 0x00];
        b.extend_from_slice(&dest_qp.to_be_bytes()[1..]);
        b.push(0x80);
        b.extend_from_slice(&psn.to_be_bytes()[1..]);
        b
    }

    #[test]
    fn rdma_write_first_parses_exactly() {
        // RC RDMA WRITE First (opcode 6) to QP 0x0000D2, PSN 0x123456.
        let bytes = bth(6, 0xD2, 0x123456);
        let parsed = parse(&bytes).expect("valid BTH");
        assert_eq!(parsed.header_len, 12);
        assert_eq!(parsed.hint, Hint::Terminal);
        assert_eq!(parsed.fields.get(DEST_QP), Some(&Value::U64(0xD2)));
        assert_eq!(parsed.fields.get(OPCODE), Some(&Value::U64(6)));
        assert_eq!(parsed.fields.get(PKEY), Some(&Value::U64(0xFFFF)));
        assert_eq!(parsed.fields.get(PSN), Some(&Value::U64(0x123456)));
        assert_eq!(parsed.fields.get(SOLICITED), Some(&Value::Bool(true)));
        assert_eq!(parsed.fields.get(MIG_REQ), Some(&Value::Bool(false)));
        assert_eq!(parsed.fields.get(PAD_COUNT), Some(&Value::U64(0)));
        assert_eq!(parsed.fields.get(ACK_REQ), Some(&Value::Bool(true)));
    }

    #[test]
    fn payload_beyond_the_bth_stays_unread() {
        let mut bytes = bth(4, 0xD2, 1); // SEND Only
        bytes.extend_from_slice(&[0xAA; 32]); // RDMA payload + ICRC
        let parsed = parse(&bytes).expect("BTH with payload");
        assert_eq!(parsed.header_len, 12);
    }

    #[test]
    fn nonzero_transport_version_declines() {
        let mut bytes = bth(6, 0xD2, 1);
        bytes[1] = 0x81; // tver 1
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn truncated_bth_declines() {
        let bytes = bth(6, 0xD2, 1);
        for n in 0..bytes.len() {
            assert!(parse(&bytes[..n]).is_err(), "prefix of {n} bytes");
        }
    }
}
