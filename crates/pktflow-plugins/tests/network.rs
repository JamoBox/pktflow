//! Network-layer stream behavior (06.3): IP conversation folding for both
//! families, fragment safety, the ipv6 chain bound — plus 06.2's deferred
//! eth ▸ vlan ▸ ipv4 identity-less bridge fixture.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use pktflow_core::{LinkType, PacketMeta, ParseOpts, StopReason, Value};
use pktflow_flows::{Aggregator, AggregatorConfig};
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

fn eth(ethertype: u16) -> Vec<u8> {
    let mut f = vec![0xAA; 6];
    f.extend_from_slice(&[0xBB; 6]);
    f.extend_from_slice(&ethertype.to_be_bytes());
    f
}

/// RFC 791 header, valid checksum. `flags_frag` is the raw 16-bit field.
fn ipv4_header(protocol: u8, src: [u8; 4], dst: [u8; 4], flags_frag: u16) -> Vec<u8> {
    let mut h = vec![0x45, 0x00, 0x00, 0x3C, 0x1C, 0x46];
    h.extend_from_slice(&flags_frag.to_be_bytes());
    h.extend_from_slice(&[0x40, protocol, 0x00, 0x00]);
    h.extend_from_slice(&src);
    h.extend_from_slice(&dst);
    let ck = internet_checksum(&h);
    h[10..12].copy_from_slice(&ck.to_be_bytes());
    h
}

/// RFC 8200 fixed header, no extensions.
fn ipv6_header(next: u8, src: [u8; 16], dst: [u8; 16]) -> Vec<u8> {
    let mut h = vec![0x60, 0x00, 0x00, 0x00, 0x00, 0x00, next, 0x40];
    h.extend_from_slice(&src);
    h.extend_from_slice(&dst);
    h
}

fn ingest_all(frames: &[Vec<u8>]) -> Aggregator {
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());
    for (i, frame) in frames.iter().enumerate() {
        agg.ingest(&engine.dissect(frame, meta(frame.len(), i as u64), ParseOpts::default()));
    }
    agg
}

#[test]
fn ip_conversations_fold_for_both_families() {
    // v4: A -> B then B -> A under one MAC pair. Protocol 253 (RFC 3692
    // experimental) stays unclaimed so dissection ends at ip cleanly.
    let mut fwd4 = eth(0x0800);
    fwd4.extend_from_slice(&ipv4_header(253, [10, 0, 0, 1], [10, 0, 0, 2], 0x4000));
    let mut rev4 = eth(0x0800);
    rev4.extend_from_slice(&ipv4_header(253, [10, 0, 0, 2], [10, 0, 0, 1], 0x4000));

    // v6 pair, same shape.
    let (a6, b6) = ([0x20; 16], [0xFE; 16]);
    let mut fwd6 = eth(0x86DD);
    fwd6.extend_from_slice(&ipv6_header(253, a6, b6));
    let mut rev6 = eth(0x86DD);
    rev6.extend_from_slice(&ipv6_header(253, b6, a6));

    let agg = ingest_all(&[fwd4, rev4, fwd6, rev6]);

    for protocol in ["ipv4", "ipv6"] {
        let nodes = agg.at_layer(protocol);
        assert_eq!(nodes.len(), 1, "{protocol}: one folded IP conversation");
        let total: u64 = nodes[0].stats.iter().map(|s| s.packets).sum();
        assert_eq!(total, 2, "{protocol}: both directions");
        assert!(
            nodes[0].stats.iter().all(|s| s.packets == 1),
            "{protocol}: one packet per direction"
        );
    }
}

#[test]
fn eth_vlan_ipv4_bridges_to_the_eth_stream() {
    // 06.2's deferred criterion: the identity-less vlan tag must not
    // break the parent chain.
    let mut frame = eth(0x8100);
    frame.extend_from_slice(&[0xA0, 0x64, 0x08, 0x00]); // vid 100, IPv4
    frame.extend_from_slice(&ipv4_header(253, [10, 0, 0, 1], [10, 0, 0, 2], 0x4000));

    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());
    let packet = engine.dissect(&frame, meta(frame.len(), 0), ParseOpts::default());
    let protocols: Vec<_> = packet.layers.iter().map(|l| l.protocol).collect();
    assert_eq!(protocols, ["ethernet", "vlan", "ipv4"]);
    agg.ingest(&packet);

    assert_eq!(agg.len(), 2, "vlan forms no stream");
    let eth_stream = agg.at_layer("ethernet")[0];
    let ip_stream = agg.at_layer("ipv4")[0];
    assert_eq!(ip_stream.parent, Some(eth_stream.id), "bridged across vlan");
}

#[test]
fn fragments_are_terminal_and_count_into_the_ip_conversation() {
    // First fragment (offset 0, MF set) routes to the transport; a later
    // fragment (offset > 0) is terminal — its payload must produce no
    // phantom transport stream.
    let tcp_ish = [0x01u8, 0xBB, 0xC0, 0x01, 0xDE, 0xAD, 0xBE, 0xEF];
    let mut later = eth(0x0800);
    later.extend_from_slice(&ipv4_header(6, [10, 0, 0, 1], [10, 0, 0, 2], 0x20B9)); // MF, offset 185
    later.extend_from_slice(&tcp_ish);

    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());
    let packet = engine.dissect(&later, meta(later.len(), 0), ParseOpts::default());
    let protocols: Vec<_> = packet.layers.iter().map(|l| l.protocol).collect();
    assert_eq!(protocols, ["ethernet", "ipv4"], "fragment stops at ip");
    assert_eq!(packet.stop, StopReason::Terminal);
    assert_eq!(packet.opaque_len, 8, "fragment payload is opaque");
    agg.ingest(&packet);

    let ip_nodes = agg.at_layer("ipv4");
    assert_eq!(ip_nodes.len(), 1, "fragment counted into the conversation");
    assert_eq!(ip_nodes[0].opaque_bytes, 8);
}

#[test]
fn ipv6_ext_chain_walks_and_the_ninth_header_is_malformed() {
    // Hop-by-hop then fragment(offset>0): both consumed into header_len,
    // terminal because of the offset.
    let mut frame = eth(0x86DD);
    let mut h6 = ipv6_header(0, [0x20; 16], [0xFE; 16]); // next = hop-by-hop
    h6.extend_from_slice(&[44, 0, 1, 4, 0, 0, 0, 0]); // hbh: next=fragment, len 8
    h6.extend_from_slice(&[6, 0, 0x03, 0x20, 0, 0, 0, 1]); // frag: next=tcp, offset 100
    h6.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // fragment payload
    frame.extend_from_slice(&h6);

    let engine = Arc::new(default_engine());
    let packet = engine.dissect(&frame, meta(frame.len(), 0), ParseOpts::default());
    assert_eq!(packet.layers.len(), 2);
    assert_eq!(packet.layers[1].protocol, "ipv6");
    assert_eq!(packet.layers[1].header_len, 56, "40 + two 8-byte exts");
    assert_eq!(
        packet.layers[1].fields.get("next_header"),
        Some(&Value::U64(6))
    );
    assert_eq!(packet.stop, StopReason::Terminal, "fragment offset > 0");

    // Nine chained hop-by-hop headers: malformed, not a loop.
    let mut frame = eth(0x86DD);
    let mut h6 = ipv6_header(0, [0x20; 16], [0xFE; 16]);
    for _ in 0..8 {
        h6.extend_from_slice(&[0, 0, 1, 4, 0, 0, 0, 0]); // next = hbh again
    }
    h6.extend_from_slice(&[6, 0, 1, 4, 0, 0, 0, 0]); // 9th ext
    frame.extend_from_slice(&h6);
    let packet = engine.dissect(&frame, meta(frame.len(), 0), ParseOpts::default());
    assert_eq!(
        packet.layers.last().map(|l| l.protocol),
        Some("ethernet"),
        "ipv6 layer refused"
    );
    assert_eq!(packet.stop, StopReason::PluginError);
}
