//! DHCP (06.6, RFC 2131/2132): BOOTP header plus a strictly-bounded
//! options walk. The msg_type Series rollup captures the DORA sequence —
//! 05.4's order-sensitive motivating case.

use pktflow_core::{
    ByteReader, Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx,
    ParseError, ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId, StreamIdentity, Value,
};

const APP: FieldName = "app";
const OP: FieldName = "op";
const MSG_TYPE: FieldName = "msg_type";
const XID: FieldName = "xid";
const CLIENT_MAC: FieldName = "client_mac";
const REQUESTED_IP: FieldName = "requested_ip";
const SERVER_ID: FieldName = "server_id";
const HOSTNAME: FieldName = "hostname";

const MAGIC_COOKIE: u32 = 0x6382_5363;

static KEY: &[KeyField] = &[KeyField { a: APP, b: None }];
static ROLLUPS: &[RollupSpec] = &[
    RollupSpec {
        field: MSG_TYPE,
        kind: RollupKind::Series { cap: 64 }, // the DORA sequence, in order
    },
    RollupSpec {
        field: CLIENT_MAC,
        kind: RollupKind::Accumulate,
    },
];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: ROLLUPS,
};

pub struct Dhcp;

impl LayerPlugin for Dhcp {
    fn name(&self) -> ProtocolName {
        "dhcp"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let op = r.u8()?;
        let _htype = r.u8()?;
        let hlen = r.u8()?;
        let _hops = r.u8()?;
        let xid = r.u32_be()?;
        let _secs_flags = r.u32_be()?;
        let _ciaddr = r.take(4)?;
        let _yiaddr = r.take(4)?;
        let _siaddr = r.take(4)?;
        let _giaddr = r.take(4)?;
        let chaddr = r.take(16)?;
        let _sname = r.take(64)?;
        let _file = r.take(128)?;
        if r.u32_be()? != MAGIC_COOKIE {
            return Err(ParseError::Malformed("missing DHCP magic cookie"));
        }
        let client_mac = chaddr.get(..usize::from(hlen).min(16)).unwrap_or(chaddr);

        // Options TLV walk, strictly bounded by the reader; unknown
        // options are skipped. An END option is required — options
        // running off the buffer are a truncated packet, not a success.
        let mut consumed = 240usize;
        let mut msg_type = None;
        let mut requested_ip = None;
        let mut server_id = None;
        let mut hostname = None;
        loop {
            let code = r.u8()?;
            consumed += 1;
            match code {
                0 => continue, // PAD
                255 => break,  // END
                _ => {
                    let len = usize::from(r.u8()?);
                    let data = r.take(len)?;
                    consumed += 1 + len;
                    match (code, len) {
                        (53, 1) => msg_type = data.first().copied(),
                        (50, 4) => requested_ip = Some(Value::from(data)),
                        (54, 4) => server_id = Some(Value::from(data)),
                        (12, _) => {
                            let text: String = data
                                .iter()
                                .map(|&c| {
                                    if c.is_ascii_graphic() {
                                        char::from(c)
                                    } else {
                                        '?'
                                    }
                                })
                                .collect();
                            hostname = Some(Value::from(text.as_str()));
                        }
                        _ => {}
                    }
                }
            }
        }

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(APP, Value::from("dhcp"));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(OP, Value::U64(u64::from(op)));
            if let Some(mt) = msg_type {
                fields.insert(MSG_TYPE, Value::U64(u64::from(mt)));
            }
            fields.insert(XID, Value::U64(u64::from(xid)));
            fields.insert(CLIENT_MAC, Value::from(client_mac));
        }
        if ctx.depth() >= Depth::Full {
            if let Some(v) = requested_ip {
                fields.insert(REQUESTED_IP, v);
            }
            if let Some(v) = server_id {
                fields.insert(SERVER_ID, v);
            }
            if let Some(v) = hostname {
                fields.insert(HOSTNAME, v);
            }
        }

        Ok(ParsedLayer {
            header_len: consumed,
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::UdpPort(67), RouteId::UdpPort(68)]
    }

    fn stream_identity(&self) -> Option<&StreamIdentity> {
        Some(&IDENTITY)
    }
}
