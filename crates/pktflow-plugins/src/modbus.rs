//! Modbus/TCP (11.13, Modbus Organization — *Modbus Application Protocol
//! Specification V1.1b3*, <https://modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf>;
//! MBAP framing per *Modbus Messaging on TCP/IP Implementation Guide V1.0b*):
//! MBAP header (transaction id, protocol id, length, unit id) plus a PDU
//! (function code + data). The MBAP `length` field is authoritative and
//! self-bounding — no cross-packet state needed to find the frame's end.
//!
//! Request and single-write response PDUs share one fixed 4-byte shape
//! (address + quantity, or address + value), so `start_address`/`quantity`/
//! `register_value`/`coil_value` are decoded from that shape whichever side
//! sent it. Read-function *responses* (byte-count + register/coil data) and
//! any other less-common function code are a different, variable shape this
//! stateless plugin can't disambiguate from a request without seeing the
//! matching request first (D7: no cross-packet correlation) — those PDUs
//! are consumed for `header_len` correctness and left opaque, the same
//! field-depth ceiling as netflow9's Data FlowSets (11.11).

use pktflow_core::{
    ByteReader, Canonicalize, Depth, FieldMap, FieldName, Hint, KeyField, LayerPlugin, ParseCtx,
    ParseError, ParsedLayer, ProtocolName, RollupKind, RollupSpec, RouteId, StreamIdentity, Value,
};

const UNIT_ID: FieldName = "unit_id";
const FUNCTION_CODE: FieldName = "function_code";
const IS_EXCEPTION: FieldName = "is_exception";
const EXCEPTION_CODE: FieldName = "exception_code";
const START_ADDRESS: FieldName = "start_address";
const QUANTITY: FieldName = "quantity";
const REGISTER_VALUE: FieldName = "register_value";
const COIL_VALUE: FieldName = "coil_value";

/// Modbus/TCP's protocol identifier is always 0 (V1.1b3 §4.1, MBAP header);
/// a non-zero value means this isn't Modbus riding port 502 by coincidence.
const PROTOCOL_ID: u16 = 0;

/// Exception responses set the function code's top bit (V1.1b3 §7).
const EXCEPTION_BIT: u8 = 0x80;

/// Read requests (V1.1b3 §6.1-6.4): 2-byte starting address + 2-byte
/// quantity, an unambiguous fixed shape.
const READ_REQUESTS: [u8; 4] = [0x01, 0x02, 0x03, 0x04];
const WRITE_SINGLE_COIL: u8 = 0x05;
const WRITE_SINGLE_REGISTER: u8 = 0x06;
const WRITE_MULTIPLE_COILS: u8 = 0x0F;
const WRITE_MULTIPLE_REGISTERS: u8 = 0x10;

static KEY: &[KeyField] = &[KeyField {
    a: UNIT_ID,
    b: None, // shared qualifier: a Modbus/TCP gateway multiplexes several
             // downstream serial unit ids over one TCP session (11.13)
}];
static ROLLUPS: &[RollupSpec] = &[RollupSpec {
    field: FUNCTION_CODE,
    kind: RollupKind::Accumulate,
}];
static IDENTITY: StreamIdentity = StreamIdentity {
    key: KEY,
    canonicalize: Canonicalize::EndpointSort,
    lifecycle: None,
    rollups: ROLLUPS,
};

pub struct Modbus;

impl LayerPlugin for Modbus {
    fn name(&self) -> ProtocolName {
        "modbus"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let _transaction_id = r.u16_be()?;
        let protocol_id = r.u16_be()?;
        if protocol_id != PROTOCOL_ID {
            return Err(ParseError::Malformed("non-zero Modbus protocol id"));
        }
        let length = usize::from(r.u16_be()?);
        // `length` counts everything from unit_id onward; a legal PDU
        // needs at least unit_id + function_code.
        if length < 2 {
            return Err(ParseError::Malformed(
                "MBAP length too short for unit id + function code",
            ));
        }
        let unit_id = r.u8()?;
        let function_code = r.u8()?;
        let is_exception = function_code & EXCEPTION_BIT != 0;
        let data_len = length - 2;

        let mut exception_code = None;
        let mut start_address = None;
        let mut quantity = None;
        let mut register_value = None;
        let mut coil_value = None;

        if is_exception {
            // V1.1b3 §7: an exception PDU is always function_code + one
            // exception-code byte, nothing else.
            if data_len != 1 {
                return Err(ParseError::Malformed(
                    "exception PDU must carry exactly one data byte",
                ));
            }
            exception_code = Some(r.u8()?);
        } else if READ_REQUESTS.contains(&function_code) && data_len == 4 {
            start_address = Some(r.u16_be()?);
            quantity = Some(r.u16_be()?);
        } else if function_code == WRITE_SINGLE_COIL && data_len == 4 {
            start_address = Some(r.u16_be()?);
            coil_value = Some(r.u16_be()?);
        } else if function_code == WRITE_SINGLE_REGISTER && data_len == 4 {
            start_address = Some(r.u16_be()?);
            register_value = Some(r.u16_be()?);
        } else if matches!(
            function_code,
            WRITE_MULTIPLE_COILS | WRITE_MULTIPLE_REGISTERS
        ) && data_len >= 5
        {
            start_address = Some(r.u16_be()?);
            quantity = Some(r.u16_be()?);
            let _byte_count = r.u8()?;
            let _values = r.take(data_len - 5)?;
        } else {
            // Read-function responses (byte_count + register/coil data)
            // and anything else: shape this stateless plugin can't decide
            // without the matching request. Still consumed exactly, so
            // `header_len` stays honest.
            let _opaque = r.take(data_len)?;
        }

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Keys {
            fields.insert(UNIT_ID, Value::U64(u64::from(unit_id)));
        }
        if ctx.depth() >= Depth::Structural {
            fields.insert(FUNCTION_CODE, Value::U64(u64::from(function_code)));
            fields.insert(IS_EXCEPTION, Value::Bool(is_exception));
            if let Some(v) = exception_code {
                fields.insert(EXCEPTION_CODE, Value::U64(u64::from(v)));
            }
        }
        if ctx.depth() >= Depth::Full {
            if let Some(v) = start_address {
                fields.insert(START_ADDRESS, Value::U64(u64::from(v)));
            }
            if let Some(v) = quantity {
                fields.insert(QUANTITY, Value::U64(u64::from(v)));
            }
            if let Some(v) = register_value {
                fields.insert(REGISTER_VALUE, Value::U64(u64::from(v)));
            }
            if let Some(v) = coil_value {
                fields.insert(COIL_VALUE, Value::U64(u64::from(v)));
            }
        }

        Ok(ParsedLayer {
            header_len: bytes.len() - r.remaining(),
            fields,
            hint: Hint::Terminal,
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::TcpPort(502)]
    }

    fn stream_identity(&self) -> Option<&StreamIdentity> {
        Some(&IDENTITY)
    }
}
