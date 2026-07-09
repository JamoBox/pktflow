//! Link-layer stream behavior (06.2): MAC conversations with folded
//! directions, and QinQ stacked tags with innermost-wins lookup.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use pktflow_core::{
    Depth, LayerPlugin, LinkType, PacketMeta, ParseCtx, ParseOpts, RouteId, StopReason, Value,
};
use pktflow_flows::{dir_index, Aggregator, AggregatorConfig, Rollup};
use pktflow_plugins::default_engine;

/// One LLDP TLV: 2-byte header (7-bit type, 9-bit length) + value.
fn lldp_tlv(t: u8, value: &[u8]) -> Vec<u8> {
    let header = (u16::from(t) << 9) | (value.len() as u16);
    let mut out = header.to_be_bytes().to_vec();
    out.extend_from_slice(value);
    out
}

/// A minimal but complete LLDPDU (IEEE 802.1AB-2016): mandatory TLVs plus
/// End-of-LLDPDU.
fn lldp_pdu() -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&lldp_tlv(1, &[7, b'e', b'0'])); // chassis: locally assigned
    b.extend_from_slice(&lldp_tlv(2, &[7, b'p', b'1'])); // port: locally assigned
    b.extend_from_slice(&lldp_tlv(3, &30u16.to_be_bytes())); // ttl
    b.extend_from_slice(&lldp_tlv(0, &[])); // end
    b
}

fn meta(len: usize, ms: u64) -> PacketMeta {
    PacketMeta {
        timestamp: SystemTime::UNIX_EPOCH + Duration::from_millis(ms),
        caplen: len,
        origlen: len,
        link_type: LinkType::ETHERNET,
    }
}

const MAC_A: [u8; 6] = [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E];
const MAC_B: [u8; 6] = [0x00, 0x1B, 0x44, 0x11, 0x3A, 0xB7];

fn eth_frame(dst: [u8; 6], src: [u8; 6], ethertype: u16) -> Vec<u8> {
    let mut f = Vec::with_capacity(14);
    f.extend_from_slice(&dst);
    f.extend_from_slice(&src);
    f.extend_from_slice(&ethertype.to_be_bytes());
    f
}

#[test]
fn mac_conversation_folds_directions() {
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    // A → B, then B → A (FR-21 item 1). 0x9999 is unclaimed, so the
    // dissection stops after ethernet — the MAC conversation still forms.
    let forward = eth_frame(MAC_B, MAC_A, 0x9999);
    let reverse = eth_frame(MAC_A, MAC_B, 0x9999);
    agg.ingest(&engine.dissect(&forward, meta(forward.len(), 0), ParseOpts::default()));
    agg.ingest(&engine.dissect(&reverse, meta(reverse.len(), 1), ParseOpts::default()));

    assert_eq!(agg.len(), 1, "one folded MAC conversation");
    let stream = agg.streams().next().expect("stream");
    assert_eq!(stream.protocol, "ethernet");
    let fwd = stream.stats[dir_index(stream.initiator)];
    assert_eq!((fwd.packets, fwd.bytes), (1, 14));
    let total: u64 = stream.stats.iter().map(|s| s.packets).sum();
    assert_eq!(total, 2, "both directions in one stream");

    // The declared rollup: ethertypes seen inside this MAC pair.
    match stream.rollups.get("ethertype") {
        Some(Rollup::Accumulate { values, count, .. }) => {
            assert_eq!(*count, 2);
            assert_eq!(values.as_slice(), [Value::U64(0x9999)]);
        }
        other => panic!("wrong rollup: {other:?}"),
    }
}

#[test]
fn qinq_parses_both_tags_and_innermost_wins() {
    let engine = Arc::new(default_engine());

    // eth (0x88A8) ▸ vlan s-tag vid=10 (inner 0x8100) ▸ vlan c-tag vid=100
    // (inner 0x9999, unclaimed) — two stacked vlan LayerRecords.
    let mut pkt = eth_frame(MAC_B, MAC_A, 0x88A8);
    pkt.extend_from_slice(&[0x20, 0x0A, 0x81, 0x00]); // s-tag: vid 10
    pkt.extend_from_slice(&[0xA0, 0x64, 0x99, 0x99]); // c-tag: vid 100,
                                                      // inner 0x9999 unclaimed: must gate, not guess
    pkt.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // opaque payload

    let m = meta(pkt.len(), 0);
    let packet = engine.dissect(&pkt, m, ParseOpts::default());
    let protocols: Vec<_> = packet.layers.iter().map(|l| l.protocol).collect();
    assert_eq!(protocols, ["ethernet", "vlan", "vlan"]);
    assert_eq!(
        packet.stop,
        StopReason::UnclaimedRoute(RouteId::EtherType(0x9999))
    );
    assert_eq!(
        packet.layers[1].fields.get("vlan_id"),
        Some(&Value::U64(10)),
        "outer s-tag"
    );
    assert_eq!(
        packet.layers[2].fields.get("vlan_id"),
        Some(&Value::U64(100)),
        "inner c-tag"
    );

    // Innermost-wins (01.4) over the real stacked repeat: a cross-layer
    // reader asking for "vlan" sees the c-tag.
    let ctx = ParseCtx::new(&packet.layers, Depth::Full, &m);
    let inner = ctx.layer("vlan").expect("vlan present");
    assert_eq!(inner.fields.get("vlan_id"), Some(&Value::U64(100)));
}

#[test]
fn lldp_is_identity_less_like_arp_and_carries_no_stream_of_its_own() {
    // 802.1AB-2016 §7.1's "nearest bridge" group address — the default,
    // by far the most common destination for LLDP in the wild.
    const NEAREST_BRIDGE: [u8; 6] = [0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E];

    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    let mut pkt = eth_frame(NEAREST_BRIDGE, MAC_A, 0x88CC);
    pkt.extend_from_slice(&lldp_pdu());

    let m = meta(pkt.len(), 0);
    let packet = engine.dissect(&pkt, m, ParseOpts::default());
    let protocols: Vec<_> = packet.layers.iter().map(|l| l.protocol).collect();
    assert_eq!(protocols, ["ethernet", "lldp"]);
    // The LLDPDU consumes every remaining byte (no Ethernet padding in
    // this fixture): an empty payload stops at `Complete` regardless of
    // the plugin's own `Hint::Terminal` (03.4's "empty payload" row
    // outranks Terminal in wording only, per `Engine::resolve_next`).
    assert_eq!(packet.stop, StopReason::Complete);

    agg.ingest(&packet);
    // Same shape as ARP (06.3) and the rest of 11.1's beacon/announcement
    // protocols: one MAC-conversation stream, zero lldp streams.
    assert_eq!(agg.len(), 1, "lldp forms no stream of its own");
    let stream = agg.streams().next().expect("ethernet stream");
    assert_eq!(stream.protocol, "ethernet");
    match stream.rollups.get("ethertype") {
        Some(Rollup::Accumulate { values, .. }) => {
            assert_eq!(values.as_slice(), [Value::U64(0x88CC)]);
        }
        other => panic!("wrong rollup: {other:?}"),
    }
}

#[test]
fn lldp_route_id_is_the_registered_ethertype() {
    assert_eq!(
        pktflow_plugins::lldp::Lldp.claims(),
        &[RouteId::EtherType(0x88CC)]
    );
}
