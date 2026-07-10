//! Wireless link stream behavior (11.2): the 802.11 MAC conversation
//! (mirrors 06.2's Ethernet criterion one layer up), and the domain's
//! headline claim — that `radiotap` ▸ `dot11` ▸ `llc` ▸ `eapol` composes
//! across a completely different physical medium without either the LLC
//! demux (11.1) or the EAPOL plugin (11.1) knowing 802.11 exists.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use pktflow_core::{LinkType, PacketMeta, ParseOpts, ProtocolName, RouteId, StopReason, Value};
use pktflow_flows::{dir_index, Aggregator, AggregatorConfig, Rollup};
use pktflow_plugins::default_engine;

fn meta(len: usize, ms: u64, link_type: LinkType) -> PacketMeta {
    PacketMeta {
        timestamp: SystemTime::UNIX_EPOCH + Duration::from_millis(ms),
        caplen: len,
        origlen: len,
        link_type,
    }
}

const AP: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
const STA: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
const DA: [u8; 6] = [0x0A, 0x00, 0x00, 0x00, 0x00, 0x09];

fn dot11_fc(frame_type: u8, subtype: u8) -> u8 {
    (subtype << 4) | (frame_type << 2)
}

/// Plain (non-QoS) Data frame, to-DS, carrying `body` — the shape the
/// unprotected WPA handshake and ordinary IP traffic both ride in.
fn dot11_data_frame(addr1: [u8; 6], addr2: [u8; 6], protected: bool, body: &[u8]) -> Vec<u8> {
    let flags = if protected { 0x01 | 0x40 } else { 0x01 };
    let mut b = vec![dot11_fc(2, 0b0000), flags];
    b.extend_from_slice(&0u16.to_le_bytes()); // duration
    b.extend_from_slice(&addr1);
    b.extend_from_slice(&addr2);
    b.extend_from_slice(&DA);
    b.extend_from_slice(&0u16.to_le_bytes()); // seq_ctl
    b.extend_from_slice(body);
    b
}

/// Minimal radiotap wrapper (it_present = 0) around `payload`.
fn radiotap_wrap(payload: &[u8]) -> Vec<u8> {
    let mut r = vec![0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00];
    r.extend_from_slice(payload);
    r
}

/// LLC/SNAP, RFC 1042 encapsulation reused for a real EtherType (11.1's
/// `llc`): dsap=ssap=0xAA, control=0x03, OUI 0, then `ethertype`.
fn llc_snap(ethertype: u16) -> Vec<u8> {
    let mut l = vec![0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00];
    l.extend_from_slice(&ethertype.to_be_bytes());
    l
}

/// One EAPOL-Key message (802.1X-2020 §11.9), the wire format the
/// WPA2/WPA3 4-way handshake uses — 11.1's `eapol`, unmodified.
fn eapol_key_frame(replay_counter: u64, key_info: u16) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(0x02); // key_descriptor_type: RSN
    body.extend_from_slice(&key_info.to_be_bytes());
    body.extend_from_slice(&16u16.to_be_bytes()); // key_length
    body.extend_from_slice(&replay_counter.to_be_bytes());
    body.extend_from_slice(&[0xAA; 32]); // nonce
    body.extend_from_slice(&[0; 16]); // key_iv
    body.extend_from_slice(&0u64.to_be_bytes()); // key_rsc
    body.extend_from_slice(&[0; 8]); // reserved
    body.extend_from_slice(&[0; 16]); // key_mic
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
fn dot11_link_stream_folds_directions() {
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    // AP -> STA, then STA -> AP: same shape as 06.2's mac_conversation
    // test, one layer up. Both frames are QoS Null (no body) so nothing
    // past dot11 needs to resolve for this stream-shape assertion.
    let mut forward = vec![dot11_fc(2, 0b1100), 0x02]; // from-DS
    forward.extend_from_slice(&0u16.to_le_bytes());
    forward.extend_from_slice(&STA); // addr1 (RA)
    forward.extend_from_slice(&AP); // addr2 (TA)
    forward.extend_from_slice(&DA); // addr3
    forward.extend_from_slice(&0x0010u16.to_le_bytes());
    forward.extend_from_slice(&0u16.to_le_bytes()); // qos_control

    let mut reverse = vec![dot11_fc(2, 0b1100), 0x01]; // to-DS
    reverse.extend_from_slice(&0u16.to_le_bytes());
    reverse.extend_from_slice(&AP); // addr1 (RA)
    reverse.extend_from_slice(&STA); // addr2 (TA)
    reverse.extend_from_slice(&DA);
    reverse.extend_from_slice(&0x0020u16.to_le_bytes());
    reverse.extend_from_slice(&0u16.to_le_bytes());

    let m = |len, ms| meta(len, ms, LinkType(105));
    agg.ingest(&engine.dissect(&forward, m(forward.len(), 0), ParseOpts::default()));
    agg.ingest(&engine.dissect(&reverse, m(reverse.len(), 1), ParseOpts::default()));

    assert_eq!(agg.len(), 1, "one folded 802.11 link stream");
    let stream = agg.streams().next().expect("stream");
    assert_eq!(stream.protocol, "dot11");
    let fwd = stream.stats[dir_index(stream.initiator)];
    assert_eq!((fwd.packets, fwd.bytes), (1, forward.len() as u64));
    let total: u64 = stream.stats.iter().map(|s| s.packets).sum();
    assert_eq!(total, 2, "both directions in one stream");

    // frame_subtype rollup: both frames are QoS Null (12).
    match stream.rollups.get("frame_subtype") {
        Some(Rollup::Accumulate { values, count, .. }) => {
            assert_eq!(*count, 2);
            assert_eq!(values.as_slice(), [Value::U64(0b1100)]);
        }
        other => panic!("wrong rollup: {other:?}"),
    }
}

#[test]
fn four_way_handshake_composes_radiotap_dot11_llc_eapol() {
    let engine = Arc::new(default_engine());

    // 802.1X-2020's four EAPOL-Key messages, distinguished here only by
    // replay_counter/key_info (the composition, not handshake semantics,
    // is what this test proves) — each riding radiotap > dot11 (plain,
    // unprotected, to-DS) > llc/SNAP (EtherType 0x888E) > eapol.
    let messages = [
        (1u64, 0x008Au16), // 1: ACK, pairwise
        (2u64, 0x010Au16), // 2: MIC set
        (3u64, 0x13CAu16), // 3: ACK+MIC+Install+Secure
        (4u64, 0x030Au16), // 4: MIC+Secure
    ];

    for (replay_counter, key_info) in messages {
        let eapol = eapol_key_frame(replay_counter, key_info);
        let mut llc_and_eapol = llc_snap(0x888E);
        llc_and_eapol.extend_from_slice(&eapol);
        let dot11_frame = dot11_data_frame(AP, STA, false, &llc_and_eapol);
        let frame = radiotap_wrap(&dot11_frame);

        let m = meta(frame.len(), 0, LinkType(127 /* DLT_IEEE802_11_RADIOTAP */));
        let packet = engine.dissect(&frame, m, ParseOpts::default());

        let protocols: Vec<ProtocolName> = packet.layers.iter().map(|l| l.protocol).collect();
        assert_eq!(
            protocols,
            ["radiotap", "dot11", "llc", "eapol"],
            "replay_counter {replay_counter}: full cross-medium composition"
        );
        // eapol's own hint is Terminal, but this fixture leaves no
        // trailing bytes after it — an empty payload reports Complete
        // either way (04.3's documented precedence).
        assert_eq!(packet.stop, StopReason::Complete);

        let eapol_layer = packet
            .layers
            .iter()
            .find(|l| l.protocol == "eapol")
            .expect("eapol layer");
        assert_eq!(
            eapol_layer.fields.get("packet_type"),
            Some(&Value::U64(3)),
            "EAPOL-Key"
        );
        assert_eq!(
            eapol_layer.fields.get("replay_counter"),
            Some(&Value::U64(replay_counter))
        );
        assert_eq!(
            eapol_layer.fields.get("key_info"),
            Some(&Value::U64(u64::from(key_info)))
        );
        assert_eq!(
            eapol_layer.fields.get("nonce"),
            Some(&Value::from(&[0xAAu8; 32][..]))
        );

        let llc_layer = packet
            .layers
            .iter()
            .find(|l| l.protocol == "llc")
            .expect("llc layer");
        assert_eq!(llc_layer.fields.get("pid"), Some(&Value::U64(0x888E)));
    }
}

#[test]
fn protected_data_frame_stops_at_dot11_never_reaching_llc() {
    let engine = Arc::new(default_engine());

    // Same LLC/SNAP + EAPOL-shaped bytes as the handshake test, but the
    // 802.11 Protected Frame bit is set (post-handshake traffic) — dot11
    // must never attempt llc on what is now opaque encrypted payload.
    let mut llc_and_eapol = llc_snap(0x888E);
    llc_and_eapol.extend_from_slice(&eapol_key_frame(5, 0x0000));
    let dot11_frame = dot11_data_frame(AP, STA, true, &llc_and_eapol);
    let frame = radiotap_wrap(&dot11_frame);

    let m = meta(frame.len(), 0, LinkType(127));
    let packet = engine.dissect(&frame, m, ParseOpts::default());

    let protocols: Vec<ProtocolName> = packet.layers.iter().map(|l| l.protocol).collect();
    assert_eq!(protocols, ["radiotap", "dot11"]);
    assert_eq!(packet.stop, StopReason::Terminal);
}

#[test]
fn radiotap_wrapping_a_link_type_route_is_the_only_entry_for_dlt_127() {
    let engine = Arc::new(default_engine());
    // Sanity: RouteId::LinkType(127) resolves to radiotap, distinct from
    // dot11's own LinkType(105) — a raw (non-radiotap) capture.
    let bytes = radiotap_wrap(&dot11_data_frame(AP, STA, false, &[]));
    let m = meta(bytes.len(), 0, LinkType(127));
    let packet = engine.dissect(&bytes, m, ParseOpts::default());
    assert_eq!(packet.layers[0].protocol, "radiotap");
    assert_ne!(
        RouteId::LinkType(127),
        RouteId::LinkType(105),
        "radiotap and dot11 claim distinct DLTs"
    );
}
