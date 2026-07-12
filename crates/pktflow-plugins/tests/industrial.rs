//! Industrial/OT stream behavior (11.13): a Modbus/TCP gateway
//! multiplexing several downstream `unit_id`s over one TCP connection
//! folds into sibling streams under that connection, mirroring 06.5's
//! two-VNIs shared-qualifier shape. DNP3's station-pair identity, by
//! contrast, is a full endpoint key (`source`/`destination`) — the same
//! shape as TCP's own five-tuple — so a request/response exchange folds
//! into one session with direction flipping, not two. BACnet/IP's `app`
//! shared-constant key (the same app-stream pattern `dns`/`syslog`/`snmp`
//! use) folds a unicast request/ACK exchange into one stream via the
//! parent UDP stream's own endpoint-sort symmetry, while a broadcast
//! discovery message — with no reply on the same UDP 4-tuple — stays its
//! own single-packet stream.

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

/// DNP3 Data Link Layer frame: sync + length + control, little-endian
/// destination/source, a 2-byte header CRC (not validated). `pdu` (when
/// non-empty) rides after a 1-byte transport header, per IEEE 1815-2012
/// §9-10.
fn dnp3_frame(destination: u16, source: u16, control: u8, pdu: &[u8]) -> Vec<u8> {
    let user_data_len = if pdu.is_empty() { 0 } else { 1 + pdu.len() };
    let length = 5 + user_data_len;
    let mut f = vec![0x05, 0x64, length as u8, control];
    f.extend_from_slice(&destination.to_le_bytes());
    f.extend_from_slice(&source.to_le_bytes());
    f.extend_from_slice(&[0xAB, 0xCD]); // header CRC
    if !pdu.is_empty() {
        f.push(0xC1); // transport header: FIN|FIR, seq 1
        f.extend_from_slice(pdu);
    }
    f
}

fn dnp3_over_tcp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, dl_frame: &[u8]) -> Vec<u8> {
    let mut f = eth();
    f.extend_from_slice(&ipv4_header(src, dst));
    f.extend_from_slice(&tcp_segment(sport, dport, dl_frame));
    f
}

#[test]
fn dnp3_fixture_hierarchy_node_by_node() {
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    // Master (source 1) reads station 1024, function code 1 (Read).
    let frame = dnp3_over_tcp(
        [10, 0, 0, 1],
        [10, 0, 0, 99],
        51000,
        20000,
        &dnp3_frame(1024, 1, 0xC4, &[0xC0, 0x01]),
    );
    agg.ingest(&engine.dissect(&frame, meta(frame.len(), 0), ParseOpts::default()));

    let tcp_stream = agg.at_layer("tcp")[0];
    let dnp3_stream = agg.at_layer("dnp3")[0];
    assert_eq!(dnp3_stream.parent, Some(tcp_stream.id));
}

/// DNP3's station-pair identity is a full endpoint key (`source`,
/// `destination`), the same shape as TCP's own five-tuple — unlike
/// Modbus's shared-qualifier `unit_id`, a request/response exchange must
/// fold into ONE session with direction flipping, not two.
#[test]
fn request_and_response_fold_into_one_station_pair_session() {
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    // Master (1) -> outstation (1024): Read request.
    let request = dnp3_over_tcp(
        [10, 0, 0, 1],
        [10, 0, 0, 99],
        51000,
        20000,
        &dnp3_frame(1024, 1, 0xC4, &[0xC0, 0x01]),
    );
    // Outstation (1024) -> master (1): response, source/destination swapped.
    let response = dnp3_over_tcp(
        [10, 0, 0, 99],
        [10, 0, 0, 1],
        20000,
        51000,
        &dnp3_frame(1, 1024, 0x44, &[0xC0, 0x81]),
    );
    agg.ingest(&engine.dissect(&request, meta(request.len(), 0), ParseOpts::default()));
    agg.ingest(&engine.dissect(&response, meta(response.len(), 1), ParseOpts::default()));

    let dnp3_streams = agg.at_layer("dnp3");
    assert_eq!(
        dnp3_streams.len(),
        1,
        "one station-pair session, both directions"
    );
    match dnp3_streams[0].rollups.get("function_code") {
        Some(Rollup::Accumulate { values, count, .. }) => {
            assert_eq!(*count, 2);
            assert_eq!(values.as_slice(), [Value::U64(1), Value::U64(0x81)]);
        }
        other => panic!("wrong rollup: {other:?}"),
    }
}

fn ipv4_udp_header(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
    let mut h = vec![
        0x45, 0x00, 0x00, 0x3C, 0x1C, 0x46, 0x40, 0x00, 0x40, 17, 0, 0,
    ];
    h.extend_from_slice(&src);
    h.extend_from_slice(&dst);
    let ck = internet_checksum(&h);
    h[10..12].copy_from_slice(&ck.to_be_bytes());
    h
}

fn udp_datagram(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut d = Vec::new();
    d.extend_from_slice(&src_port.to_be_bytes());
    d.extend_from_slice(&dst_port.to_be_bytes());
    d.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    d.extend_from_slice(&[0x00, 0x00]); // checksum disabled (RFC 768, legal on IPv4)
    d.extend_from_slice(payload);
    d
}

/// A BACnet/IP (Annex J) message: 4-byte BVLC header wrapping `npdu_and_after`.
fn bacnet_ip_message(function: u8, npdu_and_after: &[u8]) -> Vec<u8> {
    let length = (4 + npdu_and_after.len()) as u16;
    let mut b = vec![0x81, function];
    b.extend_from_slice(&length.to_be_bytes());
    b.extend_from_slice(npdu_and_after);
    b
}

fn bacnet_udp_frame(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, msg: &[u8]) -> Vec<u8> {
    let mut f = eth();
    f.extend_from_slice(&ipv4_udp_header(src, dst));
    f.extend_from_slice(&udp_datagram(sport, dport, msg));
    f
}

/// An unrestricted Who-Is broadcast (Original-Broadcast-NPDU) with no
/// reply on the same UDP 4-tuple stays its own single-packet app-stream —
/// the discovery-traffic shape 11.13's module doc calls out as
/// non-session-shaped.
#[test]
fn who_is_broadcast_forms_its_own_app_stream() {
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    let who_is = bacnet_ip_message(0x0B, &[0x01, 0x00, 0x10, 0x08]);
    let frame = bacnet_udp_frame([10, 0, 0, 5], [10, 0, 0, 255], 47808, 47808, &who_is);
    agg.ingest(&engine.dissect(&frame, meta(frame.len(), 0), ParseOpts::default()));

    let bacnet_streams = agg.at_layer("bacnet_ip");
    assert_eq!(bacnet_streams.len(), 1);
    match bacnet_streams[0].rollups.get("service_choice") {
        Some(Rollup::Accumulate { values, count, .. }) => {
            assert_eq!(*count, 1);
            assert_eq!(values.as_slice(), [Value::U64(8)]); // Who-Is
        }
        other => panic!("wrong rollup: {other:?}"),
    }
}

/// A unicast ReadProperty request/ComplexACK response pair: the parent
/// UDP stream folds both directions together (its own endpoint-sort port
/// pair), and BACnet/IP's shared `app` key rides along, so this is one
/// `bacnet_ip` stream, not two — the session-shaped traffic 11.13's
/// module doc contrasts with broadcast discovery.
#[test]
fn read_property_request_and_ack_fold_into_one_app_stream() {
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    // Client -> server: Confirmed-Request, ReadProperty (service choice 12).
    let request_npdu = [0x01, 0x04, 0x00, 0x05, 0x01, 0x0C];
    let request = bacnet_ip_message(0x0A, &request_npdu);
    let request_frame = bacnet_udp_frame([10, 0, 0, 5], [10, 0, 0, 1], 47810, 47808, &request);

    // Server -> client: ComplexACK for the same service (service choice 12).
    let ack_npdu = [0x01, 0x00, 0x30, 0x01, 0x0C];
    let ack = bacnet_ip_message(0x0A, &ack_npdu);
    let ack_frame = bacnet_udp_frame([10, 0, 0, 1], [10, 0, 0, 5], 47808, 47810, &ack);

    agg.ingest(&engine.dissect(
        &request_frame,
        meta(request_frame.len(), 0),
        ParseOpts::default(),
    ));
    agg.ingest(&engine.dissect(&ack_frame, meta(ack_frame.len(), 1), ParseOpts::default()));

    let udp_stream = agg.at_layer("udp")[0];
    let bacnet_streams = agg.at_layer("bacnet_ip");
    assert_eq!(
        bacnet_streams.len(),
        1,
        "one app-stream, both directions folded via the shared app key"
    );
    assert_eq!(bacnet_streams[0].parent, Some(udp_stream.id));
    match bacnet_streams[0].rollups.get("service_choice") {
        Some(Rollup::Accumulate { values, count, .. }) => {
            assert_eq!(*count, 2);
            assert_eq!(values.as_slice(), [Value::U64(12)]);
        }
        other => panic!("wrong rollup: {other:?}"),
    }
}
