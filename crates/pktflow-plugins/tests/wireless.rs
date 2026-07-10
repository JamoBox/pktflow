//! `radiotap` composition (11.2): the piece `tests/link.rs`'s 802.11
//! coverage doesn't reach on its own — a radiotap-wrapped capture
//! (`DLT_IEEE802_11_RADIOTAP`) dispatching by name into `dot11`, and the
//! full `radiotap ▸ dot11 ▸ llc ▸ eapol` chain for all four WPA handshake
//! messages (`link.rs`'s `wpa_handshake_composes_dot11_llc_eapol_unmodified`
//! covers the `dot11 ▸ llc ▸ eapol` suffix directly via `LinkType(105)`;
//! this file adds the `radiotap` prefix and the remaining three messages).

use std::sync::Arc;
use std::time::SystemTime;

use pktflow_core::{LinkType, PacketMeta, ParseOpts, ProtocolName, RouteId, StopReason, Value};
use pktflow_plugins::default_engine;

fn meta(len: usize, link_type: LinkType) -> PacketMeta {
    PacketMeta {
        timestamp: SystemTime::UNIX_EPOCH,
        caplen: len,
        origlen: len,
        link_type,
    }
}

const AP: [u8; 6] = [0x02, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E];
const STA: [u8; 6] = [0x00, 0x1B, 0x44, 0x11, 0x3A, 0xB7];

/// Unprotected (unless `protected`) QoS Data, AP -> STA (from_ds),
/// carrying `body` — same fixed shape as `link.rs`'s dot11 fixtures.
fn dot11_qos_data_frame(protected: bool, body: &[u8]) -> Vec<u8> {
    let fc1 = if protected { 0x02 | 0x40 } else { 0x02 };
    let mut b = vec![0x88, fc1]; // Data / QoS Data
    b.extend_from_slice(&0x0000u16.to_le_bytes()); // duration
    b.extend_from_slice(&STA); // addr1: DA
    b.extend_from_slice(&AP); // addr2: TA/BSSID
    b.extend_from_slice(&AP); // addr3: SA
    b.extend_from_slice(&0x0000u16.to_le_bytes()); // seq_ctrl
    b.extend_from_slice(&0x0000u16.to_le_bytes()); // qos_control
    b.extend_from_slice(body);
    b
}

/// Minimal radiotap wrapper (`it_present = 0`) around `payload`.
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
fn radiotap_wrapping_a_link_type_route_is_the_only_entry_for_dlt_127() {
    let engine = Arc::new(default_engine());
    let bytes = radiotap_wrap(&dot11_qos_data_frame(false, &[]));
    let m = meta(bytes.len(), LinkType(127));
    let packet = engine.dissect(&bytes, m, ParseOpts::default());
    assert_eq!(packet.layers[0].protocol, "radiotap");
    assert_eq!(packet.layers[1].protocol, "dot11");
    assert_ne!(
        RouteId::LinkType(127),
        RouteId::LinkType(105),
        "radiotap and dot11 claim distinct DLTs"
    );
}

#[test]
fn four_way_handshake_composes_radiotap_dot11_llc_eapol() {
    let engine = Arc::new(default_engine());

    // 802.1X-2020's four EAPOL-Key messages, distinguished here only by
    // replay_counter/key_info (the composition, not handshake semantics,
    // is what this test proves) — each riding radiotap > dot11 (QoS data,
    // unprotected, from-DS) > llc/SNAP (EtherType 0x888E) > eapol.
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
        let dot11_frame = dot11_qos_data_frame(false, &llc_and_eapol);
        let frame = radiotap_wrap(&dot11_frame);

        let m = meta(frame.len(), LinkType(127 /* DLT_IEEE802_11_RADIOTAP */));
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
fn radiotap_wrapped_protected_data_frame_stops_at_dot11_never_reaching_llc() {
    // Same LLC/SNAP + EAPOL-shaped bytes as the handshake test, but the
    // 802.11 Protected Frame bit is set (post-handshake traffic) — dot11
    // must never attempt llc on what is now opaque encrypted payload,
    // whether reached raw (link.rs's `dot11_protected_data_frame_never_
    // reaches_llc`) or through the radiotap prefix, exercised here.
    let engine = Arc::new(default_engine());
    let mut llc_and_eapol = llc_snap(0x888E);
    llc_and_eapol.extend_from_slice(&eapol_key_frame(5, 0x0000));
    let dot11_frame = dot11_qos_data_frame(true, &llc_and_eapol);
    let frame = radiotap_wrap(&dot11_frame);

    let m = meta(frame.len(), LinkType(127));
    let packet = engine.dissect(&frame, m, ParseOpts::default());

    let protocols: Vec<ProtocolName> = packet.layers.iter().map(|l| l.protocol).collect();
    assert_eq!(protocols, ["radiotap", "dot11"]);
    assert_eq!(packet.stop, StopReason::Terminal);
}
