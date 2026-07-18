//! DHCPv6 (11.3, RFC 8415) end to end: real engine dispatch chain, the
//! SOLICIT->ADVERTISE->REQUEST->REPLY sequence's `msg_type` Series order,
//! and the app-stream pattern (one `dhcpv6` child stream per UDP stream) —
//! the DHCPv4 DORA precedent (06.6's `dhcp_dora_series_preserves_order`)
//! ported to DHCPv6's own message set (RFC 8415 §18).

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use pktflow_core::{LinkType, PacketMeta, ParseOpts, StopReason, Value};
use pktflow_flows::{Aggregator, AggregatorConfig, Rollup};
use pktflow_plugins::default_engine;

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
    f.extend_from_slice(&0x86DDu16.to_be_bytes());
    f
}

/// RFC 8200 fixed header; `next_header` 17 = UDP.
fn ipv6(payload_len: u16, src: [u8; 16], dst: [u8; 16]) -> Vec<u8> {
    let mut h = vec![0x60, 0, 0, 0];
    h.extend_from_slice(&payload_len.to_be_bytes());
    h.push(17);
    h.push(64);
    h.extend_from_slice(&src);
    h.extend_from_slice(&dst);
    h
}

fn udp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut h = Vec::new();
    h.extend_from_slice(&sport.to_be_bytes());
    h.extend_from_slice(&dport.to_be_bytes());
    h.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    h.extend_from_slice(&[0, 0]); // checksum: not validated (06.4 precedent)
    h.extend_from_slice(payload);
    h
}

/// msg-type(1) + transaction-id(3) + a Client Identifier option (RFC 8415
/// §21.2) — every DORA-sequence message carries one in practice.
fn dhcpv6_msg(msg_type: u8, xid: u32) -> Vec<u8> {
    let mut m = vec![msg_type];
    m.extend_from_slice(&xid.to_be_bytes()[1..]);
    m.extend_from_slice(&1u16.to_be_bytes()); // OPTION_CLIENTID
    m.extend_from_slice(&4u16.to_be_bytes());
    m.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    m
}

const CLIENT: [u8; 16] = [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const SERVER: [u8; 16] = [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
// RFC 8415 §7.1: All_DHCP_Relay_Agents_and_Servers, ff02::1:2.
const ALL_DHCP_RELAY_AGENTS_AND_SERVERS: [u8; 16] =
    [0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2];

#[test]
fn dhcpv6_dora_series_preserves_order() {
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    // RFC 8415 §18: SOLICIT/ADVERTISE/REQUEST/REPLY — client multicasts
    // from its DHCPv6 client port (546) to the well-known
    // All_DHCP_Relay_Agents_and_Servers group on the server port (547); the
    // server replies unicast from 547 to 546.
    let dora = [(1u8, true), (2, false), (3, true), (7, false)];
    for (i, (msg_type, from_client)) in dora.iter().enumerate() {
        let msg = dhcpv6_msg(*msg_type, 0x00ABCDEF);
        let (src, dst, sport, dport) = if *from_client {
            (CLIENT, ALL_DHCP_RELAY_AGENTS_AND_SERVERS, 546, 547)
        } else {
            (SERVER, CLIENT, 547, 546)
        };
        let payload = udp(sport, dport, &msg);
        let mut frame = eth();
        frame.extend_from_slice(&ipv6(payload.len() as u16, src, dst));
        frame.extend_from_slice(&payload);
        agg.ingest(&engine.dissect(&frame, meta(frame.len(), i as u64), ParseOpts::default()));
    }

    let dhcpv6_streams = agg.at_layer("dhcpv6");
    // Two transport streams (multicast solicit/request + unicast reply
    // path) — check the sequence order across their series combined by
    // time, exactly 06.6's DORA-order criterion.
    let mut observed: Vec<(SystemTime, u64)> = Vec::new();
    for s in &dhcpv6_streams {
        if let Some(Rollup::Series {
            ring, truncated, ..
        }) = s.rollups.get("msg_type")
        {
            assert!(!truncated);
            for point in ring {
                match &point.value {
                    Value::U64(v) => observed.push((point.ts(s.first_seen), *v)),
                    other => panic!("unexpected {other:?}"),
                }
            }
        }
    }
    observed.sort_by_key(|(ts, _)| *ts);
    let sequence: Vec<u64> = observed.into_iter().map(|(_, v)| v).collect();
    assert_eq!(
        sequence,
        [1, 2, 3, 7],
        "SOLICIT/ADVERTISE/REQUEST/REPLY, in order"
    );
}

#[test]
fn app_stream_pattern_one_dhcpv6_child_per_udp_stream() {
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    let msg = dhcpv6_msg(1, 0x00000042);
    let payload = udp(546, 547, &msg);
    let mut frame = eth();
    frame.extend_from_slice(&ipv6(
        payload.len() as u16,
        CLIENT,
        ALL_DHCP_RELAY_AGENTS_AND_SERVERS,
    ));
    frame.extend_from_slice(&payload);

    let packet = engine.dissect(&frame, meta(frame.len(), 0), ParseOpts::default());
    let protocols: Vec<_> = packet.layers.iter().map(|l| l.protocol).collect();
    assert_eq!(protocols, ["ethernet", "ipv6", "udp", "dhcpv6"]);
    assert_eq!(packet.stop, StopReason::Complete);
    agg.ingest(&packet);

    let udp_stream = agg.at_layer("udp")[0];
    let dhcpv6_streams = agg.at_layer("dhcpv6");
    assert_eq!(
        dhcpv6_streams.len(),
        1,
        "one app-stream per transport stream"
    );
    assert_eq!(dhcpv6_streams[0].parent, Some(udp_stream.id));
}
