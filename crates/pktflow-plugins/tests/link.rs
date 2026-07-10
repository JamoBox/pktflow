//! Link-layer stream behavior (06.2, 11.2): MAC conversations with folded
//! directions, QinQ stacked tags with innermost-wins lookup, and the
//! wireless-link sibling (802.11) entry point.

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

/// Classic STP Configuration BPDU (802.1D-2004 §9.3.1): version 0, this
/// bridge is not the root (root priority 0x8000, root mac
/// 00:1a:2b:3c:4d:5e; bridge priority 0x8000, bridge mac
/// 00:1b:44:11:3a:b7).
fn stp_config_bpdu() -> Vec<u8> {
    let mut b = vec![0x00, 0x00, 0x00, 0x00];
    b.push(0x00); // flags
    b.extend_from_slice(&[0x80, 0x00, 0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E]); // root_id
    b.extend_from_slice(&4u32.to_be_bytes()); // root_path_cost
    b.extend_from_slice(&[0x80, 0x00, 0x00, 0x1B, 0x44, 0x11, 0x3A, 0xB7]); // bridge_id
    b.extend_from_slice(&0x8001u16.to_be_bytes()); // port_id
    b.extend_from_slice(&0u16.to_be_bytes()); // message_age
    b.extend_from_slice(&0x1400u16.to_be_bytes()); // max_age
    b.extend_from_slice(&0x0200u16.to_be_bytes()); // hello_time
    b.extend_from_slice(&0x0F00u16.to_be_bytes()); // forward_delay
    b
}

#[test]
fn eth_802_3_length_field_falls_back_through_llc_to_stp_end_to_end() {
    // ethertype's low value is an 802.3 *length* (< 0x0600), so ethernet
    // (06.2) emits Hint::Unknown rather than guessing; llc (11.1) wins
    // the fallback pool and routes dsap 0x42 to stp via the llc_dsap
    // Custom space. Bridge Group Address destination (STP's fixed
    // multicast target) also exercises llc's cross-layer dst_mac probe
    // boost along the way.
    const IEEE_BRIDGE_GROUP: [u8; 6] = [0x01, 0x80, 0xC2, 0x00, 0x00, 0x00];

    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    let bpdu = stp_config_bpdu();
    let mut pkt = eth_frame(
        IEEE_BRIDGE_GROUP,
        MAC_A,
        u16::try_from(3 + bpdu.len()).expect("fixture length fits in a u16"),
    );
    pkt.extend_from_slice(&[0x42, 0x42, 0x03]); // dsap=ssap=0x42, U-format control
    pkt.extend_from_slice(&bpdu);

    let m = meta(pkt.len(), 0);
    let packet = engine.dissect(&pkt, m, ParseOpts::default());
    let protocols: Vec<_> = packet.layers.iter().map(|l| l.protocol).collect();
    assert_eq!(protocols, ["ethernet", "llc", "stp"]);
    assert_eq!(packet.layers[1].fields.get("dsap"), Some(&Value::U64(0x42)));
    assert_eq!(
        packet.layers[2].fields.get("root_path_cost"),
        Some(&Value::U64(4))
    );
    assert_eq!(packet.stop, StopReason::Complete);

    agg.ingest(&packet);
    // stp is identity-less like ARP/LLDP/CDP: one MAC-conversation
    // stream, zero stp streams — llc bridges the identity-less chain the
    // same way vlan does (06.2's deferred criterion).
    assert_eq!(agg.len(), 1, "stp forms no stream of its own");
    assert_eq!(agg.streams().next().expect("stream").protocol, "ethernet");
}

/// One CDP TLV: 2-byte type + 2-byte length (including this header) +
/// value.
fn cdp_tlv(t: u16, value: &[u8]) -> Vec<u8> {
    let mut out = t.to_be_bytes().to_vec();
    out.extend_from_slice(&u16::try_from(4 + value.len()).expect("fits").to_be_bytes());
    out.extend_from_slice(value);
    out
}

/// A minimal CDP announcement (device id last — see cdp.rs's fixture
/// doc comment for why).
fn cdp_pdu() -> Vec<u8> {
    let mut b = vec![0x02, 0x3C, 0x00, 0x00]; // version 2, ttl 60s, checksum placeholder
    b.extend_from_slice(&cdp_tlv(0x0003, b"Gi0/1")); // port id
    b.extend_from_slice(&cdp_tlv(0x0001, b"switch1")); // device id
    b
}

#[test]
fn eth_802_3_length_field_falls_back_through_llc_to_cdp_end_to_end() {
    // Cisco's multicast control-plane destination, and a SNAP frame
    // (OUI 00-00-0C Cisco, PID 0x2000 CDP) — the snap_pid Custom space
    // llc mints, now claimed by cdp.
    const CISCO_MULTICAST: [u8; 6] = [0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC];

    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    let cdp = cdp_pdu();
    let mut pkt = eth_frame(
        CISCO_MULTICAST,
        MAC_A,
        u16::try_from(4 + cdp.len()).expect("fixture length fits in a u16"),
    );
    pkt.extend_from_slice(&[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x0C, 0x20, 0x00]); // SNAP: Cisco OUI, CDP PID
    pkt.extend_from_slice(&cdp);

    let m = meta(pkt.len(), 0);
    let packet = engine.dissect(&pkt, m, ParseOpts::default());
    let protocols: Vec<_> = packet.layers.iter().map(|l| l.protocol).collect();
    assert_eq!(protocols, ["ethernet", "llc", "cdp"]);
    assert_eq!(
        packet.layers[2].fields.get("device_id"),
        Some(&Value::from("switch1"))
    );
    assert_eq!(packet.stop, StopReason::Complete);

    agg.ingest(&packet);
    // cdp is identity-less like stp/lldp/arp: one MAC-conversation
    // stream, zero cdp streams.
    assert_eq!(agg.len(), 1, "cdp forms no stream of its own");
    assert_eq!(agg.streams().next().expect("stream").protocol, "ethernet");
}

#[test]
fn pvst_plus_disambiguates_from_cdp_by_snap_pid_alone() {
    // Same OUI (Cisco) and same Cisco multicast destination as cdp's
    // fixture above — SNAP PID (0x010B vs 0x2000) is the only thing that
    // tells them apart, exactly as 11.1 specifies.
    const CISCO_MULTICAST: [u8; 6] = [0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC];

    let mut bpdu = vec![0x00, 0x00, 0x00, 0x00]; // protocol_id, version 0, type 0x00
    bpdu.push(0x00); // flags
    bpdu.extend_from_slice(&[0x80, 0x00, 0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E]); // root_id
    bpdu.extend_from_slice(&4u32.to_be_bytes()); // root_path_cost
    bpdu.extend_from_slice(&[0x80, 0x00, 0x00, 0x1B, 0x44, 0x11, 0x3A, 0xB7]); // bridge_id
    bpdu.extend_from_slice(&0x8001u16.to_be_bytes()); // port_id
    bpdu.extend_from_slice(&0u16.to_be_bytes()); // message_age
    bpdu.extend_from_slice(&0x1400u16.to_be_bytes()); // max_age
    bpdu.extend_from_slice(&0x0200u16.to_be_bytes()); // hello_time
    bpdu.extend_from_slice(&0x0F00u16.to_be_bytes()); // forward_delay
    bpdu.extend_from_slice(&0x0000u16.to_be_bytes()); // TLV type
    bpdu.extend_from_slice(&0x0002u16.to_be_bytes()); // TLV length
    bpdu.extend_from_slice(&42u16.to_be_bytes()); // TLV value: VLAN 42

    let engine = Arc::new(default_engine());
    let mut pkt = eth_frame(
        CISCO_MULTICAST,
        MAC_A,
        u16::try_from(8 + bpdu.len()).expect("fixture length fits in a u16"),
    );
    pkt.extend_from_slice(&[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x0C, 0x01, 0x0B]); // SNAP: Cisco OUI, PVST+ PID
    pkt.extend_from_slice(&bpdu);

    let m = meta(pkt.len(), 0);
    let packet = engine.dissect(&pkt, m, ParseOpts::default());
    let protocols: Vec<_> = packet.layers.iter().map(|l| l.protocol).collect();
    assert_eq!(protocols, ["ethernet", "llc", "pvst_plus"]);
    assert_eq!(
        packet.layers[2].fields.get("originating_vlan"),
        Some(&Value::U64(42))
    );
    assert_eq!(packet.stop, StopReason::Complete);
}

fn lacp_endpoint_tlv(t: u8, system: [u8; 6], key: u16, port: u16, state: u8) -> Vec<u8> {
    let mut b = vec![t, 0x14];
    b.extend_from_slice(&0x8000u16.to_be_bytes());
    b.extend_from_slice(&system);
    b.extend_from_slice(&key.to_be_bytes());
    b.extend_from_slice(&0x8000u16.to_be_bytes());
    b.extend_from_slice(&port.to_be_bytes());
    b.push(state);
    b.extend_from_slice(&[0, 0, 0]);
    b
}

/// A full LACPDU (802.3-2018 Clause 43) from `actor`'s point of view.
fn lacpdu(actor: [u8; 6], actor_state: u8, partner: [u8; 6], partner_state: u8) -> Vec<u8> {
    let mut b = vec![0x01, 0x01]; // subtype LACP, version 1
    b.extend_from_slice(&lacp_endpoint_tlv(0x01, actor, 1, 1, actor_state));
    b.extend_from_slice(&lacp_endpoint_tlv(0x02, partner, 2, 2, partner_state));
    b.push(0x03); // collector TLV
    b.push(0x10);
    b.extend_from_slice(&[0; 14]);
    b.push(0x00); // terminator TLV
    b.push(0x00);
    b.extend_from_slice(&[0; 50]); // reserved trailer
    b
}

#[test]
fn lacp_negotiation_stream_folds_both_directions_and_accumulates_actor_state() {
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    // A -> B: A hasn't seen a response yet (not yet synchronized). B ->
    // A: both sides now synchronized/collecting/distributing. Same two
    // systems, opposite actor/partner roles per direction.
    let mut a_to_b = eth_frame(MAC_B, MAC_A, 0x8809);
    a_to_b.extend_from_slice(&lacpdu(MAC_A, 0x07, MAC_B, 0x00));
    let mut b_to_a = eth_frame(MAC_A, MAC_B, 0x8809);
    b_to_a.extend_from_slice(&lacpdu(MAC_B, 0x3D, MAC_A, 0x3D));

    agg.ingest(&engine.dissect(&a_to_b, meta(a_to_b.len(), 0), ParseOpts::default()));
    agg.ingest(&engine.dissect(&b_to_a, meta(b_to_a.len(), 1), ParseOpts::default()));

    // Two streams: the ethernet MAC conversation, and one folded lacp
    // negotiation stream keyed on the unordered {A, B} system pair.
    assert_eq!(agg.len(), 2);
    let lacp_stream = agg.at_layer("lacp")[0];
    assert_eq!(lacp_stream.protocol, "lacp");
    let total: u64 = lacp_stream.stats.iter().map(|s| s.packets).sum();
    assert_eq!(
        total, 2,
        "both directions folded into one negotiation stream"
    );

    match lacp_stream.rollups.get("actor_state") {
        Some(Rollup::Accumulate { values, count, .. }) => {
            assert_eq!(*count, 2);
            let mut states: Vec<u64> = values
                .iter()
                .map(|v| match v {
                    Value::U64(n) => *n,
                    other => panic!("expected U64, got {other:?}"),
                })
                .collect();
            states.sort_unstable();
            assert_eq!(states, [0x07, 0x3D], "both PDUs' actor_state observed");
        }
        other => panic!("wrong rollup: {other:?}"),
    }
}

#[test]
fn lacp_non_lacp_slow_protocol_subtype_declines_as_plugin_error() {
    let engine = Arc::new(default_engine());
    let mut pkt = eth_frame(MAC_B, MAC_A, 0x8809);
    pkt.extend_from_slice(&lacpdu(MAC_A, 0x3D, MAC_B, 0x3D));
    pkt[14] = 0x02; // Marker protocol subtype, not LACP

    let m = meta(pkt.len(), 0);
    let packet = engine.dissect(&pkt, m, ParseOpts::default());
    assert_eq!(
        packet.layers.iter().map(|l| l.protocol).collect::<Vec<_>>(),
        ["ethernet"]
    );
    assert_eq!(
        packet.stop,
        StopReason::PluginError,
        "explicit-route decline, not an unclaimed route"
    );
}

#[test]
fn eapol_key_frame_parses_via_ethertype_and_forms_no_stream() {
    let mut body = Vec::new();
    body.push(0x02); // key_descriptor_type: RSN
    body.extend_from_slice(&0x008Au16.to_be_bytes()); // key_info
    body.extend_from_slice(&16u16.to_be_bytes()); // key_length
    body.extend_from_slice(&1u64.to_be_bytes()); // replay_counter
    body.extend_from_slice(&[0xAA; 32]); // nonce
    body.extend_from_slice(&[0; 16]); // key_iv
    body.extend_from_slice(&0u64.to_be_bytes()); // key_rsc
    body.extend_from_slice(&[0; 8]); // key id / reserved
    body.extend_from_slice(&[0; 16]); // key_mic
    body.extend_from_slice(&0u16.to_be_bytes()); // key_data_length

    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    let mut pkt = eth_frame(MAC_B, MAC_A, 0x888E);
    pkt.push(0x01); // version 1
    pkt.push(0x03); // packet_type Key
    pkt.extend_from_slice(
        &u16::try_from(body.len())
            .expect("eapol body fits")
            .to_be_bytes(),
    );
    pkt.extend_from_slice(&body);

    let m = meta(pkt.len(), 0);
    let packet = engine.dissect(&pkt, m, ParseOpts::default());
    let protocols: Vec<_> = packet.layers.iter().map(|l| l.protocol).collect();
    assert_eq!(protocols, ["ethernet", "eapol"]);
    assert_eq!(
        packet.layers[1].fields.get("key_info"),
        Some(&Value::U64(0x008A))
    );
    assert_eq!(packet.stop, StopReason::Complete);

    agg.ingest(&packet);
    // eapol is per-port link-local signaling, identity-less like the
    // rest of 11.1: one MAC-conversation stream, zero eapol streams.
    assert_eq!(agg.len(), 1, "eapol forms no stream of its own");
    assert_eq!(agg.streams().next().expect("stream").protocol, "ethernet");
}

#[test]
fn pvst_plus_forms_no_stream_of_its_own() {
    const CISCO_MULTICAST: [u8; 6] = [0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC];

    let mut bpdu = vec![0x00, 0x00, 0x00, 0x00];
    bpdu.push(0x00); // flags
    bpdu.extend_from_slice(&[0x80, 0x00, 0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E]); // root_id
    bpdu.extend_from_slice(&4u32.to_be_bytes()); // root_path_cost
    bpdu.extend_from_slice(&[0x80, 0x00, 0x00, 0x1B, 0x44, 0x11, 0x3A, 0xB7]); // bridge_id
    bpdu.extend_from_slice(&0x8001u16.to_be_bytes()); // port_id
    bpdu.extend_from_slice(&0u16.to_be_bytes()); // message_age
    bpdu.extend_from_slice(&0x1400u16.to_be_bytes()); // max_age
    bpdu.extend_from_slice(&0x0200u16.to_be_bytes()); // hello_time
    bpdu.extend_from_slice(&0x0F00u16.to_be_bytes()); // forward_delay
    bpdu.extend_from_slice(&0x0000u16.to_be_bytes()); // TLV type
    bpdu.extend_from_slice(&0x0002u16.to_be_bytes()); // TLV length
    bpdu.extend_from_slice(&7u16.to_be_bytes()); // TLV value: VLAN 7

    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());
    let mut pkt = eth_frame(
        CISCO_MULTICAST,
        MAC_A,
        u16::try_from(8 + bpdu.len()).expect("fixture length fits in a u16"),
    );
    pkt.extend_from_slice(&[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x0C, 0x01, 0x0B]);
    pkt.extend_from_slice(&bpdu);

    let packet = engine.dissect(&pkt, meta(pkt.len(), 0), ParseOpts::default());
    agg.ingest(&packet);
    // Same identity-less shape as stp/cdp/lldp: one MAC-conversation
    // stream, zero pvst_plus streams.
    assert_eq!(agg.len(), 1, "pvst_plus forms no stream of its own");
    assert_eq!(agg.streams().next().expect("stream").protocol, "ethernet");
}

#[test]
fn eth_802_3_length_field_with_unrecognized_saps_declines_rather_than_misrouting() {
    // A well-formed-looking 802.3-length frame whose LLC-shaped bytes
    // have neither a recognized SAP pair nor a reserved dst_mac: llc's
    // probe correctly scores nothing, no other fallback-pool plugin
    // claims these bytes either, so dissection honestly stops at
    // ethernet rather than fabricating a layer.
    let engine = Arc::new(default_engine());
    let mut pkt = eth_frame(MAC_B, MAC_A, 0x0004);
    pkt.extend_from_slice(&[0x01, 0x01, 0x00, 0x00]); // dsap/ssap 0x01: not in the well-known set

    let m = meta(pkt.len(), 0);
    let packet = engine.dissect(&pkt, m, ParseOpts::default());
    assert_eq!(
        packet.layers.iter().map(|l| l.protocol).collect::<Vec<_>>(),
        ["ethernet"],
        "no fallback-pool plugin mis-routes unrecognized SAPs"
    );
    assert_eq!(packet.stop, StopReason::UnknownHint);
}

// ---- 11.2: 802.11 link entry ----

const AP: [u8; 6] = [0x02, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E];
const STA: [u8; 6] = [0x00, 0x1B, 0x44, 0x11, 0x3A, 0xB7];

fn dot11_meta(len: usize, ms: u64) -> PacketMeta {
    PacketMeta {
        timestamp: SystemTime::UNIX_EPOCH + Duration::from_millis(ms),
        caplen: len,
        origlen: len,
        link_type: LinkType(105), // DLT_IEEE802_11
    }
}

/// A bodyless data frame (802.11-2020 §9.2.4.1.3's Null family, subtype
/// bit 2 set): `to_ds`/`from_ds` and `qos` chosen by the caller so the
/// same builder produces both directions of an AP<->STA exchange with
/// two distinct `frame_subtype` values (plain Null vs QoS Null).
fn dot11_null_frame(from_ds: bool, qos: bool) -> Vec<u8> {
    let subtype: u8 = if qos { 0xC } else { 0x4 };
    let fc0 = (subtype << 4) | (2 << 2); // type = Data
    let fc1: u8 = if from_ds { 0x02 } else { 0x01 };
    let (addr1, addr2) = if from_ds { (STA, AP) } else { (AP, STA) };

    let mut b = vec![fc0, fc1];
    b.extend_from_slice(&0x0000u16.to_le_bytes()); // duration
    b.extend_from_slice(&addr1);
    b.extend_from_slice(&addr2);
    b.extend_from_slice(&AP); // addr3: BSSID
    b.extend_from_slice(&0x0000u16.to_le_bytes()); // seq_ctrl
    if qos {
        b.extend_from_slice(&0x0000u16.to_le_bytes()); // qos_control
    }
    b
}

#[test]
fn dot11_ap_sta_link_folds_directions() {
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    // AP -> STA (plain Null) then STA -> AP (QoS Null): opposite
    // addr1/addr2 order, same {addr1, addr2} pair — the 802.11 sibling of
    // Ethernet's MAC-conversation fold (06.2), mirrored here for the
    // over-the-air link.
    let forward = dot11_null_frame(true, false);
    let reverse = dot11_null_frame(false, true);
    agg.ingest(&engine.dissect(&forward, dot11_meta(forward.len(), 0), ParseOpts::default()));
    agg.ingest(&engine.dissect(&reverse, dot11_meta(reverse.len(), 1), ParseOpts::default()));

    assert_eq!(agg.len(), 1, "one folded 802.11 link stream");
    let stream = agg.streams().next().expect("stream");
    assert_eq!(stream.protocol, "dot11");
    let total: u64 = stream.stats.iter().map(|s| s.packets).sum();
    assert_eq!(total, 2, "both directions in one stream");

    // The declared rollup: frame subtypes seen on this AP<->STA link.
    match stream.rollups.get("frame_subtype") {
        Some(Rollup::Accumulate { values, count, .. }) => {
            assert_eq!(*count, 2);
            let mut got = values.clone();
            got.sort_by_key(|v| match v {
                Value::U64(n) => *n,
                other => panic!("unexpected rollup value: {other:?}"),
            });
            assert_eq!(got, [Value::U64(0x4), Value::U64(0xC)]);
        }
        other => panic!("wrong rollup: {other:?}"),
    }
}

/// A structurally-real-shaped EAPOL-Key frame (802.1X-2020 §11.9), key
/// descriptor type 2 (IEEE 802.11/RSN) — the same shape as 11.1's own
/// `eapol` fixture, rebuilt here to travel over `dot11 ▸ llc` instead of
/// `ethernet`.
fn eapol_key_body() -> Vec<u8> {
    let mut body = Vec::new();
    body.push(0x02); // key_descriptor_type: RSN
    body.extend_from_slice(&0x008Au16.to_be_bytes()); // key_info
    body.extend_from_slice(&16u16.to_be_bytes()); // key_length
    body.extend_from_slice(&1u64.to_be_bytes()); // replay_counter
    body.extend_from_slice(&[0xAA; 32]); // nonce
    body.extend_from_slice(&[0; 16]); // key_iv
    body.extend_from_slice(&0u64.to_be_bytes()); // key_rsc
    body.extend_from_slice(&[0; 8]); // key id / reserved
    body.extend_from_slice(&[0; 16]); // key_mic (unset on message 1)
    body.extend_from_slice(&0u16.to_be_bytes()); // key_data_length

    let mut b = vec![0x01, 0x03]; // version 1, packet_type Key
    b.extend_from_slice(
        &u16::try_from(body.len())
            .expect("eapol body fits")
            .to_be_bytes(),
    );
    b.extend_from_slice(&body);
    b
}

#[test]
fn wpa_handshake_composes_dot11_llc_eapol_unmodified() {
    // The domain's central claim (11.2): the WPA/WPA3 4-way handshake is
    // *not* a separate plugin. EAPOL-Key message 1, unprotected (keys
    // aren't installed yet), riding LLC/SNAP EtherType 0x888E over an
    // ordinary QoS data frame — exactly 11.1's `llc` and `eapol`,
    // unmodified, reused verbatim over a second physical medium.
    let mut pkt = vec![0x88, 0x02]; // Data / QoS Data, from_ds=1 (AP -> STA)
    pkt.extend_from_slice(&0x0000u16.to_le_bytes()); // duration
    pkt.extend_from_slice(&STA); // addr1
    pkt.extend_from_slice(&AP); // addr2
    pkt.extend_from_slice(&AP); // addr3: BSSID
    pkt.extend_from_slice(&0x0000u16.to_le_bytes()); // seq_ctrl
    pkt.extend_from_slice(&0x0000u16.to_le_bytes()); // qos_control
    pkt.extend_from_slice(&[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E]); // LLC/SNAP -> EAPOL
    pkt.extend_from_slice(&eapol_key_body());

    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());
    let m = dot11_meta(pkt.len(), 0);
    let packet = engine.dissect(&pkt, m, ParseOpts::default());

    let protocols: Vec<_> = packet.layers.iter().map(|l| l.protocol).collect();
    assert_eq!(protocols, ["dot11", "llc", "eapol"]);
    assert_eq!(
        packet.layers[2].fields.get("key_info"),
        Some(&Value::U64(0x008A))
    );
    assert_eq!(
        packet.layers[2].fields.get("nonce"),
        Some(&Value::from(&[0xAA; 32][..]))
    );
    assert_eq!(packet.stop, StopReason::Complete);

    agg.ingest(&packet);
    // llc/eapol are identity-less (11.1); dot11 is the one stream, same
    // shape as the ethernet+eapol composition above.
    assert_eq!(agg.len(), 1, "llc/eapol form no stream of their own");
    assert_eq!(agg.streams().next().expect("stream").protocol, "dot11");
}

#[test]
fn dot11_protected_data_frame_never_reaches_llc() {
    let mut pkt = vec![0x88, 0x42]; // Data / QoS Data, from_ds=1, protected=1
    pkt.extend_from_slice(&0x0000u16.to_le_bytes());
    pkt.extend_from_slice(&STA);
    pkt.extend_from_slice(&AP);
    pkt.extend_from_slice(&AP);
    pkt.extend_from_slice(&0x0000u16.to_le_bytes());
    pkt.extend_from_slice(&0x0000u16.to_le_bytes());
    pkt.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // opaque ciphertext

    let engine = Arc::new(default_engine());
    let m = dot11_meta(pkt.len(), 0);
    let packet = engine.dissect(&pkt, m, ParseOpts::default());
    assert_eq!(
        packet.layers.iter().map(|l| l.protocol).collect::<Vec<_>>(),
        ["dot11"],
        "a protected frame's body is never handed to llc"
    );
    assert_eq!(packet.stop, StopReason::Terminal);
    assert_eq!(packet.opaque_len, 4);
}
