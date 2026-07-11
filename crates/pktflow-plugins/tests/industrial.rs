//! Industrial/OT stream behavior (11.13): a Modbus/TCP gateway
//! multiplexing several downstream `unit_id`s over one TCP connection
//! folds into sibling streams under that connection, mirroring 06.5's
//! two-VNIs shared-qualifier shape.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use pktflow_core::{LinkType, PacketMeta, ParseOpts, Value};
use pktflow_flows::{Aggregator, AggregatorConfig, Rollup};
use pktflow_plugins::default_engine;
use pktflow_plugins::ipv4::internet_checksum;

fn meta(len: usize, ms: u64) -> PacketMeta {
    PacketMeta {
        timestamp: SystemTime::UNIX_EPOCH + Duration::from_millis(ms),
        caplen: len,
        origlen: len,
        link_type: LinkType::ETHERNET,
    }
}

fn eth() -> Vec<u8> {
    let mut f = vec![0xAA; 6];
    f.extend_from_slice(&[0xBB; 6]);
    f.extend_from_slice(&0x0800u16.to_be_bytes());
    f
}

fn ipv4_header(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
    let mut h = vec![
        0x45, 0x00, 0x00, 0x3C, 0x1C, 0x46, 0x40, 0x00, 0x40, 6, 0, 0,
    ];
    h.extend_from_slice(&src);
    h.extend_from_slice(&dst);
    let ck = internet_checksum(&h);
    h[10..12].copy_from_slice(&ck.to_be_bytes());
    h
}

fn tcp_segment(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut s = Vec::new();
    s.extend_from_slice(&src_port.to_be_bytes());
    s.extend_from_slice(&dst_port.to_be_bytes());
    s.extend_from_slice(&[0, 0, 1, 0, 0, 0, 0, 0]); // seq, ack
    s.extend_from_slice(&0x5018u16.to_be_bytes()); // PSH|ACK
    s.extend_from_slice(&[0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00]); // window, ck, urg
    s.extend_from_slice(payload);
    s
}

/// MBAP header (transaction id, protocol id = 0, length) + unit id + PDU.
fn modbus_frame(transaction_id: u16, unit_id: u8, pdu: &[u8]) -> Vec<u8> {
    let mut m = transaction_id.to_be_bytes().to_vec();
    m.extend_from_slice(&[0x00, 0x00]); // protocol id
    let length = (1 + pdu.len()) as u16;
    m.extend_from_slice(&length.to_be_bytes());
    m.push(unit_id);
    m.extend_from_slice(pdu);
    m
}

fn tcp_frame(client_to_server: bool, unit_id: u8, transaction_id: u16, pdu: &[u8]) -> Vec<u8> {
    let msg = modbus_frame(transaction_id, unit_id, pdu);
    let mut f = eth();
    if client_to_server {
        f.extend_from_slice(&ipv4_header([10, 0, 0, 1], [10, 0, 0, 99]));
        f.extend_from_slice(&tcp_segment(51000, 502, &msg));
    } else {
        f.extend_from_slice(&ipv4_header([10, 0, 0, 99], [10, 0, 0, 1]));
        f.extend_from_slice(&tcp_segment(502, 51000, &msg));
    }
    f
}

#[test]
fn two_unit_ids_over_one_tcp_connection_are_sibling_streams() {
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    // Two downstream serial devices (unit_id 1 and 2) polled through the
    // same gateway TCP connection: Read Holding Registers on each.
    let read_holding_registers = [0x03, 0x00, 0x00, 0x00, 0x0A];
    for (ms, unit_id) in [(0u64, 1u8), (1, 2)] {
        let frame = tcp_frame(true, unit_id, u16::from(unit_id), &read_holding_registers);
        agg.ingest(&engine.dissect(&frame, meta(frame.len(), ms), ParseOpts::default()));
    }

    let tcp_stream = agg.at_layer("tcp")[0];
    let modbus_streams = agg.at_layer("modbus");
    assert_eq!(
        modbus_streams.len(),
        2,
        "one stream per unit_id (shared-qualifier key)"
    );
    assert!(modbus_streams
        .iter()
        .all(|m| m.parent == Some(tcp_stream.id)));
    assert_ne!(modbus_streams[0].key, modbus_streams[1].key);
}

#[test]
fn function_code_accumulates_across_a_request_response_exchange() {
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    // Request: Write Single Register. "Response" here reuses the same
    // fixed 4-byte shape (address + value echoed back, V1.1b3 §6.6).
    let write_single_register = [0x06, 0x00, 0x01, 0x00, 0x03];
    let request = tcp_frame(true, 1, 1, &write_single_register);
    let response = tcp_frame(false, 1, 1, &write_single_register);
    agg.ingest(&engine.dissect(&request, meta(request.len(), 0), ParseOpts::default()));
    agg.ingest(&engine.dissect(&response, meta(response.len(), 1), ParseOpts::default()));

    let modbus_streams = agg.at_layer("modbus");
    assert_eq!(
        modbus_streams.len(),
        1,
        "one modbus stream, both directions"
    );
    match modbus_streams[0].rollups.get("function_code") {
        Some(Rollup::Accumulate { values, count, .. }) => {
            assert_eq!(*count, 2);
            assert_eq!(values.as_slice(), [Value::U64(0x06)]);
        }
        other => panic!("wrong rollup: {other:?}"),
    }
}
