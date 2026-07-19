//! Data-center protocol behavior through the real engine: the MPLS
//! bottom-of-stack heuristic hand-off, ERSPAN unwrapping inside GRE, and
//! the shared-qualifier streams BFD/RoCEv2/PTP declare — all exercised
//! end-to-end (dissect + aggregate), zero protocol-specific aggregator
//! code, same stance as the tunnel tests.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use pktflow_core::{LinkType, PacketMeta, ParseOpts, ProtocolName, StopReason};
use pktflow_flows::{Aggregator, AggregatorConfig, StreamId};
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

const MAC_A: [u8; 6] = [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E];
const MAC_B: [u8; 6] = [0x00, 0x1B, 0x44, 0x11, 0x3A, 0xB7];
const MAC_C: [u8; 6] = [0x02, 0x42, 0xAC, 0x11, 0x00, 0x02];
const MAC_D: [u8; 6] = [0x02, 0x42, 0xAC, 0x11, 0x00, 0x03];

fn eth(dst: [u8; 6], src: [u8; 6], ethertype: u16) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&dst);
    f.extend_from_slice(&src);
    f.extend_from_slice(&ethertype.to_be_bytes());
    f
}

/// RFC 791 header whose `total_len` covers `payload_len` bytes after it —
/// the internal consistency `ipv4`'s heuristic probe verifies, which the
/// MPLS hand-off below depends on.
fn ipv4(protocol: u8, src: [u8; 4], dst: [u8; 4], payload_len: usize) -> Vec<u8> {
    let mut h = vec![0x45, 0x00];
    h.extend_from_slice(&((20 + payload_len) as u16).to_be_bytes());
    h.extend_from_slice(&[0x1C, 0x46, 0x40, 0x00, 0x40, protocol, 0x00, 0x00]);
    h.extend_from_slice(&src);
    h.extend_from_slice(&dst);
    let ck = internet_checksum(&h);
    h[10..12].copy_from_slice(&ck.to_be_bytes());
    h
}

fn udp(src_port: u16, dst_port: u16, payload_len: usize) -> Vec<u8> {
    let mut d = Vec::new();
    d.extend_from_slice(&src_port.to_be_bytes());
    d.extend_from_slice(&dst_port.to_be_bytes());
    d.extend_from_slice(&((8 + payload_len) as u16).to_be_bytes());
    d.extend_from_slice(&[0x00, 0x00]);
    d
}

/// One MPLS label-stack entry (RFC 3032).
fn mpls_entry(label: u32, s: bool, ttl: u8) -> [u8; 4] {
    ((label << 12) | (u32::from(s) << 8) | u32::from(ttl)).to_be_bytes()
}

/// RFC 5880 §4.1 control packet, version 1, state Up, detect mult 3.
fn bfd(my_disc: u32, your_disc: u32) -> Vec<u8> {
    let mut b = vec![0x20, 0xC0, 3, 24];
    b.extend_from_slice(&my_disc.to_be_bytes());
    b.extend_from_slice(&your_disc.to_be_bytes());
    b.extend_from_slice(&100_000u32.to_be_bytes());
    b.extend_from_slice(&100_000u32.to_be_bytes());
    b.extend_from_slice(&0u32.to_be_bytes());
    b
}

/// IBTA BTH: tver 0, default pkey, the caller's opcode/QP/PSN.
fn bth(opcode: u8, dest_qp: u32, psn: u32) -> Vec<u8> {
    let mut b = vec![opcode, 0x00, 0xFF, 0xFF, 0x00];
    b.extend_from_slice(&dest_qp.to_be_bytes()[1..]);
    b.push(0x00);
    b.extend_from_slice(&psn.to_be_bytes()[1..]);
    b
}

/// IEEE 1588-2008 Sync in `domain`, 10-byte originTimestamp body.
fn ptp_sync(domain: u8, sequence_id: u16) -> Vec<u8> {
    let mut b = vec![0x00, 0x02];
    b.extend_from_slice(&44u16.to_be_bytes());
    b.extend_from_slice(&[domain, 0]);
    b.extend_from_slice(&0x0200u16.to_be_bytes());
    b.extend_from_slice(&0u64.to_be_bytes());
    b.extend_from_slice(&0u32.to_be_bytes());
    b.extend_from_slice(&[0x00, 0x1B, 0x19, 0xFF, 0xFE, 0x00, 0x01, 0x02]);
    b.extend_from_slice(&1u16.to_be_bytes());
    b.extend_from_slice(&sequence_id.to_be_bytes());
    b.push(0);
    b.push(0xFF);
    b.extend_from_slice(&[0u8; 10]);
    b
}

/// GRE with the S bit (how switches ship ERSPAN Type II), protocol in the
/// EtherType space.
fn gre_seq(protocol: u16, sequence: u32) -> Vec<u8> {
    let mut g = vec![0x10, 0x00];
    g.extend_from_slice(&protocol.to_be_bytes());
    g.extend_from_slice(&sequence.to_be_bytes());
    g
}

/// ERSPAN Type II: session id, VLAN 100, index 7.
fn erspan_ii(session_id: u16) -> Vec<u8> {
    let mut e = Vec::new();
    e.extend_from_slice(&(0x1000u16 | 100).to_be_bytes());
    e.extend_from_slice(&(0x6000u16 | session_id).to_be_bytes());
    e.extend_from_slice(&7u32.to_be_bytes());
    e
}

/// RFC 826 who-has request — a small terminal payload for mirrored frames.
fn arp() -> Vec<u8> {
    let mut a = vec![0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01];
    a.extend_from_slice(&MAC_C);
    a.extend_from_slice(&[10, 0, 0, 1]);
    a.extend_from_slice(&[0x00; 6]);
    a.extend_from_slice(&[10, 0, 0, 2]);
    a
}

/// Walks the single root-to-leaf chain, returning protocols in order.
fn chain(agg: &Aggregator) -> Vec<ProtocolName> {
    let roots: Vec<StreamId> = agg.roots().map(|r| r.id).collect();
    assert_eq!(roots.len(), 1, "one root");
    let mut path = Vec::new();
    let mut cursor = roots.first().copied();
    while let Some(id) = cursor {
        let s = agg.get(id).expect("node");
        path.push(s.protocol);
        assert!(s.children.len() <= 1, "fixture chains are linear");
        cursor = s.children.first().copied();
    }
    path
}

/// MPLS names no next protocol on the wire, so the stack's payload must
/// be identified heuristically — `ipv4`'s probe verifies the structural
/// invariants and checksum and claims the frame, and dissection then
/// continues explicitly down to the BFD session the LSP was carrying.
#[test]
fn mpls_stack_hands_off_to_ipv4_heuristically() {
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    let bfd_bytes = bfd(7, 9);
    let mut frame = eth(MAC_B, MAC_A, 0x8847);
    frame.extend_from_slice(&mpls_entry(100, false, 255)); // transport label
    frame.extend_from_slice(&mpls_entry(200, true, 255)); // service label
    frame.extend_from_slice(&ipv4(17, [10, 0, 0, 1], [10, 0, 0, 2], 8 + bfd_bytes.len()));
    frame.extend_from_slice(&udp(49152, 3784, bfd_bytes.len()));
    frame.extend_from_slice(&bfd_bytes);

    let packet = engine.dissect(&frame, meta(frame.len(), 0), ParseOpts::default());
    let protocols: Vec<ProtocolName> = packet.layers.iter().map(|l| l.protocol).collect();
    assert_eq!(protocols, ["ethernet", "mpls", "ipv4", "udp", "bfd"]);
    assert_eq!(packet.stop, StopReason::Complete);

    agg.ingest(&packet);
    assert_eq!(chain(&agg), ["ethernet", "mpls", "ipv4", "udp", "bfd"]);
}

/// An IPv4 Explicit NULL bottom label (RFC 3032 §2.1) is a definitive
/// protocol indicator: dissection dispatches straight to `ipv4` with no
/// heuristic in the loop. Proven by corrupting the IPv4 checksum — the
/// heuristic probe would decline this payload, so only the explicit
/// dispatch can have reached it.
#[test]
fn mpls_explicit_null_dispatches_without_heuristics() {
    let engine = Arc::new(default_engine());

    let mut inner = ipv4(17, [10, 0, 0, 1], [10, 0, 0, 2], 8);
    inner[10..12].copy_from_slice(&[0xBA, 0xAD]); // invalid checksum
    let mut frame = eth(MAC_B, MAC_A, 0x8847);
    frame.extend_from_slice(&mpls_entry(100, false, 255));
    frame.extend_from_slice(&mpls_entry(0, true, 255)); // IPv4 Explicit NULL
    frame.extend_from_slice(&inner);
    frame.extend_from_slice(&udp(50000, 60000, 0)); // unclaimed ports

    let packet = engine.dissect(&frame, meta(frame.len(), 0), ParseOpts::default());
    let protocols: Vec<ProtocolName> = packet.layers.iter().map(|l| l.protocol).collect();
    assert_eq!(protocols, ["ethernet", "mpls", "ipv4", "udp"]);
}

/// A truncated or absent bottom-of-stack payload must stop cleanly, not
/// guess: an LSP carrying an EoMPLS pseudowire (control word first) looks
/// like nothing any probe recognizes.
#[test]
fn mpls_pseudowire_payload_stays_unknown() {
    let engine = Arc::new(default_engine());
    let mut frame = eth(MAC_B, MAC_A, 0x8847);
    frame.extend_from_slice(&mpls_entry(100, true, 255));
    frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // PW control word
    frame.extend_from_slice(&[0xAB; 14]); // opaque pseudowire payload

    let packet = engine.dissect(&frame, meta(frame.len(), 0), ParseOpts::default());
    let protocols: Vec<ProtocolName> = packet.layers.iter().map(|l| l.protocol).collect();
    assert_eq!(protocols, ["ethernet", "mpls"]);
    assert_eq!(packet.stop, StopReason::UnknownHint);
}

/// Both directions of a BFD session fold into one stream: the
/// discriminator pair swaps roles per direction, which `EndpointSort`
/// canonicalizes the same way it does TCP's port pair.
#[test]
fn bfd_session_directions_fold_into_one_stream() {
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    for (ms, src, dst, macs, my, your, sport, dport) in [
        (
            0u64,
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            (MAC_B, MAC_A),
            7u32,
            9u32,
            49152u16,
            3784u16,
        ),
        (
            1,
            [10, 0, 0, 2],
            [10, 0, 0, 1],
            (MAC_A, MAC_B),
            9,
            7,
            3784,
            49152,
        ),
    ] {
        let b = bfd(my, your);
        let mut frame = eth(macs.0, macs.1, 0x0800);
        frame.extend_from_slice(&ipv4(17, src, dst, 8 + b.len()));
        frame.extend_from_slice(&udp(sport, dport, b.len()));
        frame.extend_from_slice(&b);
        agg.ingest(&engine.dissect(&frame, meta(frame.len(), ms), ParseOpts::default()));
    }

    let sessions = agg.at_layer("bfd");
    assert_eq!(sessions.len(), 1, "one session for both directions");
}

/// ERSPAN inside GRE: the mirror header unwraps to the mirrored Ethernet
/// frame, and the session stream sits under the GRE tunnel stream.
#[test]
fn erspan_in_gre_unwraps_the_mirrored_frame() {
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    let mirrored = {
        let mut m = eth(MAC_D, MAC_C, 0x0806);
        m.extend_from_slice(&arp());
        m
    };
    let mut frame = eth(MAC_B, MAC_A, 0x0800);
    frame.extend_from_slice(&ipv4(
        47,
        [192, 168, 0, 1],
        [192, 168, 0, 2],
        8 + 8 + mirrored.len(),
    ));
    frame.extend_from_slice(&gre_seq(0x88BE, 1));
    frame.extend_from_slice(&erspan_ii(42));
    frame.extend_from_slice(&mirrored);

    let packet = engine.dissect(&frame, meta(frame.len(), 0), ParseOpts::default());
    let protocols: Vec<ProtocolName> = packet.layers.iter().map(|l| l.protocol).collect();
    assert_eq!(
        protocols,
        ["ethernet", "ipv4", "gre", "erspan", "ethernet", "arp"]
    );
    assert_eq!(packet.stop, StopReason::Complete);

    agg.ingest(&packet);
    let gre_stream = agg.at_layer("gre")[0];
    let session = agg.at_layer("erspan")[0];
    assert_eq!(session.parent, Some(gre_stream.id));
}

/// Two queue pairs inside one UDP flow are sibling RoCEv2 streams — the
/// shared-qualifier key shape VXLAN's two-VNIs test established.
#[test]
fn two_queue_pairs_over_one_udp_flow_are_sibling_streams() {
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    for (ms, qp) in [(0u64, 0xD2u32), (1, 0xD3)] {
        let b = bth(4, qp, 1); // SEND Only
        let mut frame = eth(MAC_B, MAC_A, 0x0800);
        frame.extend_from_slice(&ipv4(17, [10, 0, 0, 1], [10, 0, 0, 2], 8 + b.len()));
        frame.extend_from_slice(&udp(49152, 4791, b.len()));
        frame.extend_from_slice(&b);
        agg.ingest(&engine.dissect(&frame, meta(frame.len(), ms), ParseOpts::default()));
    }

    let outer_udp = agg.at_layer("udp")[0];
    let qps = agg.at_layer("rocev2");
    assert_eq!(qps.len(), 2, "one stream per queue pair");
    assert!(qps.iter().all(|q| q.parent == Some(outer_udp.id)));
    assert_ne!(qps[0].key, qps[1].key);
}

/// PTP reaches the same plugin over both of its encapsulations: UDP 319
/// (Annex D) and raw Ethernet 0x88F7 (Annex F).
#[test]
fn ptp_parses_over_both_udp_and_raw_ethernet() {
    let engine = Arc::new(default_engine());

    let sync = ptp_sync(0, 0x1234);
    let mut over_udp = eth(MAC_B, MAC_A, 0x0800);
    over_udp.extend_from_slice(&ipv4(17, [10, 0, 0, 1], [224, 0, 1, 129], 8 + sync.len()));
    over_udp.extend_from_slice(&udp(319, 319, sync.len()));
    over_udp.extend_from_slice(&sync);
    let packet = engine.dissect(&over_udp, meta(over_udp.len(), 0), ParseOpts::default());
    let protocols: Vec<ProtocolName> = packet.layers.iter().map(|l| l.protocol).collect();
    assert_eq!(protocols, ["ethernet", "ipv4", "udp", "ptp"]);
    assert_eq!(packet.stop, StopReason::Complete);

    let mut over_eth = eth(MAC_B, MAC_A, 0x88F7);
    over_eth.extend_from_slice(&ptp_sync(0, 0x1235));
    let packet = engine.dissect(&over_eth, meta(over_eth.len(), 1), ParseOpts::default());
    let protocols: Vec<ProtocolName> = packet.layers.iter().map(|l| l.protocol).collect();
    assert_eq!(protocols, ["ethernet", "ptp"]);
    assert_eq!(packet.stop, StopReason::Complete);
}
