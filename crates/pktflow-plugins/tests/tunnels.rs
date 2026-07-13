//! Tunnel stream behavior (06.5, FR-8): nested hierarchies falling out of
//! the 05.3 nearest-outer rule — these tests exercise zero tunnel-specific
//! aggregator code, because none exists.

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

fn eth(dst: [u8; 6], src: [u8; 6], ethertype: u16) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&dst);
    f.extend_from_slice(&src);
    f.extend_from_slice(&ethertype.to_be_bytes());
    f
}

fn ipv4(protocol: u8, src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
    let mut h = vec![
        0x45, 0x00, 0x00, 0x3C, 0x1C, 0x46, 0x40, 0x00, 0x40, protocol, 0, 0,
    ];
    h.extend_from_slice(&src);
    h.extend_from_slice(&dst);
    let ck = internet_checksum(&h);
    h[10..12].copy_from_slice(&ck.to_be_bytes());
    h
}

fn tcp(src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut s = Vec::new();
    s.extend_from_slice(&src_port.to_be_bytes());
    s.extend_from_slice(&dst_port.to_be_bytes());
    s.extend_from_slice(&[0, 0, 1, 0, 0, 0, 0, 0]);
    s.extend_from_slice(&0x5002u16.to_be_bytes()); // SYN
    s.extend_from_slice(&[0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00]);
    s
}

fn udp(src_port: u16, dst_port: u16, payload_len: u16) -> Vec<u8> {
    let mut d = Vec::new();
    d.extend_from_slice(&src_port.to_be_bytes());
    d.extend_from_slice(&dst_port.to_be_bytes());
    d.extend_from_slice(&(8 + payload_len).to_be_bytes());
    d.extend_from_slice(&[0x00, 0x00]);
    d
}

/// Keyed GRE header (K bit), protocol in the EtherType space.
fn gre_keyed(key: u32, protocol: u16) -> Vec<u8> {
    let mut g = Vec::new();
    g.extend_from_slice(&0x2000u16.to_be_bytes());
    g.extend_from_slice(&protocol.to_be_bytes());
    g.extend_from_slice(&key.to_be_bytes());
    g
}

fn vxlan(vni: u32) -> Vec<u8> {
    let mut v = vec![0x08, 0, 0, 0];
    v.extend_from_slice(&vni.to_be_bytes()[1..4]);
    v.push(0);
    v
}

/// Geneve header (RFC 8926 §3), no options, `protocol_type` in the
/// EtherType space (11.5, GRE's coincidental-reuse pattern).
fn geneve(vni: u32, protocol_type: u16) -> Vec<u8> {
    let mut g = vec![0x00, 0x00];
    g.extend_from_slice(&protocol_type.to_be_bytes());
    g.extend_from_slice(&vni.to_be_bytes()[1..4]);
    g.push(0);
    g
}

/// L2TPv3 UDP-encapsulated data message (RFC 3931 §3.2.2): T=0, Ver=3,
/// Session ID, no cookie (11.5's documented v1 default).
fn l2tpv3_udp_data(session_id: u32) -> Vec<u8> {
    let mut b = vec![0x00, 0x03, 0x00, 0x00];
    b.extend_from_slice(&session_id.to_be_bytes());
    b
}

/// L2TPv3 UDP-encapsulated control message (RFC 3931 §3.2.1): T=1, L=1,
/// S=1, Ver=3, Length, Control Connection ID, Ns, Nr, then an AVP region
/// this plugin never walks (Tier 2, 11.5's documented limitation).
fn l2tpv3_udp_control(ccid: u32, avps: &[u8]) -> Vec<u8> {
    let length = (12 + avps.len()) as u16;
    let mut b = vec![0xC8, 0x03]; // T|L|S, Ver=3
    b.extend_from_slice(&length.to_be_bytes());
    b.extend_from_slice(&ccid.to_be_bytes());
    b.extend_from_slice(&[0, 1, 0, 2]); // Ns, Nr
    b.extend_from_slice(avps);
    b
}

/// L2TPv3 direct-IP data message (RFC 3931 §4.1.1): no T/Ver word at
/// all — Session ID is the entire fixed header.
fn l2tpv3_ip_data(session_id: u32) -> Vec<u8> {
    session_id.to_be_bytes().to_vec()
}

/// ESP header (RFC 4303 §2): SPI + Sequence Number, then `ciphertext` —
/// bytes this plugin must never look inside, however plausible they look.
fn esp(spi: u32, sequence: u32, ciphertext: &[u8]) -> Vec<u8> {
    let mut e = Vec::new();
    e.extend_from_slice(&spi.to_be_bytes());
    e.extend_from_slice(&sequence.to_be_bytes());
    e.extend_from_slice(ciphertext);
    e
}

/// AH header (RFC 4302 §2): Next Header, Payload Len (word count of the
/// whole header minus 2), Reserved, SPI, Sequence Number, then an ICV of
/// whatever length `payload_len` implies (§2.2).
fn ah(next_header: u8, spi: u32, sequence: u32, icv: &[u8]) -> Vec<u8> {
    let mut a = vec![next_header, (icv.len() / 4 + 1) as u8, 0, 0];
    a.extend_from_slice(&spi.to_be_bytes());
    a.extend_from_slice(&sequence.to_be_bytes());
    a.extend_from_slice(icv);
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

const MAC_A: [u8; 6] = [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E];
const MAC_B: [u8; 6] = [0x00, 0x1B, 0x44, 0x11, 0x3A, 0xB7];
const MAC_C: [u8; 6] = [0x02, 0x42, 0xAC, 0x11, 0x00, 0x02];
const MAC_D: [u8; 6] = [0x02, 0x42, 0xAC, 0x11, 0x00, 0x03];

fn gre_frame(inner_src: [u8; 4], inner_dst: [u8; 4], sport: u16, dport: u16) -> Vec<u8> {
    let mut f = eth(MAC_B, MAC_A, 0x0800);
    f.extend_from_slice(&ipv4(47, [192, 168, 0, 1], [192, 168, 0, 2]));
    f.extend_from_slice(&gre_keyed(7, 0x0800));
    f.extend_from_slice(&ipv4(6, inner_src, inner_dst));
    f.extend_from_slice(&tcp(sport, dport));
    f
}

#[test]
fn gre_fixture_hierarchy_node_by_node() {
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());
    let frame = gre_frame([10, 0, 0, 1], [10, 0, 0, 2], 34567, 443);
    agg.ingest(&engine.dissect(&frame, meta(frame.len(), 0), ParseOpts::default()));

    assert_eq!(chain(&agg), ["ethernet", "ipv4", "gre", "ipv4", "tcp"]);

    // Node-by-node: the inner IP conversation is parented to the GRE
    // stream, not the outer IP conversation (FR-8, FR-21 item 5).
    let gre_stream = agg.at_layer("gre")[0];
    let inner_ip = agg
        .at_layer("ipv4")
        .into_iter()
        .find(|s| s.parent == Some(gre_stream.id))
        .expect("inner ip under gre");
    let session = agg.at_layer("tcp")[0];
    assert_eq!(session.parent, Some(inner_ip.id));
}

#[test]
fn vxlan_fixture_hierarchy_node_by_node() {
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    // eth ▸ ipv4 ▸ udp ▸ vxlan ▸ eth ▸ ipv4 ▸ udp (full inner stack; the
    // inner ethernet enters via ByProtocol, not a link type).
    let inner_udp = udp(50000, 60000, 0);
    let inner = {
        let mut i = eth(MAC_D, MAC_C, 0x0800);
        i.extend_from_slice(&ipv4(17, [172, 17, 0, 2], [172, 17, 0, 3]));
        i.extend_from_slice(&inner_udp);
        i
    };
    let mut frame = eth(MAC_B, MAC_A, 0x0800);
    frame.extend_from_slice(&ipv4(17, [192, 168, 0, 1], [192, 168, 0, 2]));
    frame.extend_from_slice(&udp(41000, 4789, (8 + inner.len()) as u16));
    frame.extend_from_slice(&vxlan(5001));
    frame.extend_from_slice(&inner);

    agg.ingest(&engine.dissect(&frame, meta(frame.len(), 0), ParseOpts::default()));
    assert_eq!(
        chain(&agg),
        ["ethernet", "ipv4", "udp", "vxlan", "ethernet", "ipv4", "udp"]
    );
}

#[test]
fn two_vnis_over_one_outer_udp_are_sibling_streams() {
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    for (ms, vni) in [(0u64, 100u32), (1, 200)] {
        let inner = eth(MAC_D, MAC_C, 0x9999); // unclaimed inner ethertype
        let mut frame = eth(MAC_B, MAC_A, 0x0800);
        frame.extend_from_slice(&ipv4(17, [192, 168, 0, 1], [192, 168, 0, 2]));
        frame.extend_from_slice(&udp(41000, 4789, (8 + inner.len()) as u16));
        frame.extend_from_slice(&vxlan(vni));
        frame.extend_from_slice(&inner);
        agg.ingest(&engine.dissect(&frame, meta(frame.len(), ms), ParseOpts::default()));
    }

    let outer_udp = agg.at_layer("udp")[0];
    let vxlans = agg.at_layer("vxlan");
    assert_eq!(vxlans.len(), 2, "one stream per VNI (shared-qualifier key)");
    assert!(vxlans.iter().all(|v| v.parent == Some(outer_udp.id)));
    assert_ne!(vxlans[0].key, vxlans[1].key);
}

#[test]
fn geneve_fixture_hierarchy_node_by_node() {
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    // eth ▸ ipv4 ▸ udp ▸ geneve ▸ ipv4 ▸ tcp (11.5's normative hierarchy;
    // full inner stack, same rigor as 06.5's VXLAN fixture).
    let inner = {
        let mut i = ipv4(6, [172, 17, 0, 2], [172, 17, 0, 3]);
        i.extend_from_slice(&tcp(34567, 443));
        i
    };
    let mut frame = eth(MAC_B, MAC_A, 0x0800);
    frame.extend_from_slice(&ipv4(17, [192, 168, 0, 1], [192, 168, 0, 2]));
    frame.extend_from_slice(&udp(41000, 6081, (8 + inner.len()) as u16));
    frame.extend_from_slice(&geneve(5001, 0x0800));
    frame.extend_from_slice(&inner);

    agg.ingest(&engine.dissect(&frame, meta(frame.len(), 0), ParseOpts::default()));
    assert_eq!(
        chain(&agg),
        ["ethernet", "ipv4", "udp", "geneve", "ipv4", "tcp"]
    );

    // Node-by-node: the inner IP conversation is parented to the geneve
    // stream, not the outer IP conversation (FR-8, D10 parent scoping).
    let geneve_stream = agg.at_layer("geneve")[0];
    let inner_ip = agg
        .at_layer("ipv4")
        .into_iter()
        .find(|s| s.parent == Some(geneve_stream.id))
        .expect("inner ip under geneve");
    let session = agg.at_layer("tcp")[0];
    assert_eq!(session.parent, Some(inner_ip.id));
}

#[test]
fn two_vnis_over_one_outer_udp_are_sibling_geneve_streams() {
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    // Mirrors vxlan's two-VNIs-one-outer-stream test (11.5 acceptance
    // criteria): same outer UDP stream, two VNIs -> two sibling streams.
    // `protocol_type` 0x9999 is unclaimed in the EtherType route space, so
    // the inner payload stops right at the geneve layer (the vxlan
    // fixture achieves the same "irrelevant inner content" shape via an
    // unclaimed inner Ethertype instead, since vxlan's inner is always
    // routed `ByProtocol("ethernet")` rather than by a header field).
    for (ms, vni) in [(0u64, 100u32), (1, 200)] {
        let inner = [0xFFu8; 4];
        let mut frame = eth(MAC_B, MAC_A, 0x0800);
        frame.extend_from_slice(&ipv4(17, [192, 168, 0, 1], [192, 168, 0, 2]));
        frame.extend_from_slice(&udp(41000, 6081, (8 + inner.len()) as u16));
        frame.extend_from_slice(&geneve(vni, 0x9999));
        frame.extend_from_slice(&inner);
        agg.ingest(&engine.dissect(&frame, meta(frame.len(), ms), ParseOpts::default()));
    }

    let outer_udp = agg.at_layer("udp")[0];
    let geneves = agg.at_layer("geneve");
    assert_eq!(
        geneves.len(),
        2,
        "one stream per VNI (shared-qualifier key)"
    );
    assert!(geneves.iter().all(|g| g.parent == Some(outer_udp.id)));
    assert_ne!(geneves[0].key, geneves[1].key);
}

#[test]
fn esp_fixture_stops_terminal_at_encryption_boundary_no_phantom_stream() {
    // 11.5's real-encrypted-tunnel mirror of transport.rs's
    // `encrypted_udp_no_phantom` (03.4/D12): the ciphertext trailing the
    // ESP header opens with bytes that would parse as a plausible TCP
    // SYN header (port 443, SYN flags) were anything foolish enough to
    // hand them to the tcp plugin. `Hint::Terminal` must mean that never
    // happens, no matter how header-shaped the ciphertext looks.
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    let ciphertext = [
        0x87, 0x07, 0x01, 0xBB, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0xFF,
        0xFF, 0x00, 0x00, 0x00, 0x00,
    ];
    let mut frame = eth(MAC_B, MAC_A, 0x0800);
    frame.extend_from_slice(&ipv4(50, [192, 168, 0, 1], [192, 168, 0, 2]));
    frame.extend_from_slice(&esp(0x1000_0001, 1, &ciphertext));

    let packet = engine.dissect(&frame, meta(frame.len(), 0), ParseOpts::default());
    let protocols: Vec<ProtocolName> = packet.layers.iter().map(|l| l.protocol).collect();
    assert_eq!(protocols, ["ethernet", "ipv4", "esp"], "stops at esp");
    assert_eq!(packet.stop, StopReason::Terminal);

    agg.ingest(&packet);
    assert_eq!(agg.at_layer("esp").len(), 1);
    assert_eq!(
        agg.at_layer("tcp").len(),
        0,
        "no phantom TCP stream from ciphertext"
    );
    assert_eq!(agg.at_layer("esp")[0].opaque_bytes, ciphertext.len() as u64);
}

#[test]
fn two_directions_of_one_esp_tunnel_are_sibling_streams_under_one_ip_conversation() {
    // RFC 4303 §2.1: SPI is unidirectional, each direction of a security
    // association picks its own SPI. This must fall out of keying on spi
    // alone (shared-qualifier shape, no `b` field) — no ESP-specific
    // aggregator code makes this happen (11.5's acceptance criterion).
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    let a_to_b = {
        let mut f = eth(MAC_B, MAC_A, 0x0800);
        f.extend_from_slice(&ipv4(50, [192, 168, 0, 1], [192, 168, 0, 2]));
        f.extend_from_slice(&esp(0x1000_0001, 1, &[0xAA; 4]));
        f
    };
    let b_to_a = {
        let mut f = eth(MAC_A, MAC_B, 0x0800);
        f.extend_from_slice(&ipv4(50, [192, 168, 0, 2], [192, 168, 0, 1]));
        f.extend_from_slice(&esp(0x2000_0002, 1, &[0xBB; 4]));
        f
    };
    agg.ingest(&engine.dissect(&a_to_b, meta(a_to_b.len(), 0), ParseOpts::default()));
    agg.ingest(&engine.dissect(&b_to_a, meta(b_to_a.len(), 1), ParseOpts::default()));

    let ip_conversations = agg.at_layer("ipv4");
    assert_eq!(
        ip_conversations.len(),
        1,
        "one folded IP conversation between the two hosts"
    );
    let esps = agg.at_layer("esp");
    assert_eq!(esps.len(), 2, "each direction's SPI is its own esp stream");
    assert!(esps
        .iter()
        .all(|e| e.parent == Some(ip_conversations[0].id)));
    assert_ne!(esps[0].key, esps[1].key);
}

#[test]
fn ah_fixture_hierarchy_node_by_node() {
    // eth ▸ ipv4 ▸ ah ▸ tcp (11.5's normative hierarchy): unlike ESP, AH
    // is transparent to what it protects (RFC 4302 §2 has no encryption
    // boundary), so it routes onward via its own next_header field.
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    let mut frame = eth(MAC_B, MAC_A, 0x0800);
    frame.extend_from_slice(&ipv4(51, [192, 168, 0, 1], [192, 168, 0, 2]));
    frame.extend_from_slice(&ah(6, 0x1000_0001, 1, &[0xAA; 12]));
    frame.extend_from_slice(&tcp(34567, 443));

    agg.ingest(&engine.dissect(&frame, meta(frame.len(), 0), ParseOpts::default()));
    assert_eq!(chain(&agg), ["ethernet", "ipv4", "ah", "tcp"]);

    // Node-by-node: the TCP session is parented to the ah stream, not
    // directly to the outer IP conversation (FR-8, D10 parent scoping).
    let ah_stream = agg.at_layer("ah")[0];
    let session = agg.at_layer("tcp")[0];
    assert_eq!(session.parent, Some(ah_stream.id));
}

#[test]
fn two_directions_of_one_ah_association_are_sibling_streams_under_one_ip_conversation() {
    // RFC 4302 §2.1: SPI is unidirectional, mirroring ESP's
    // `two_directions_of_one_esp_tunnel...` test above — same
    // shared-qualifier keying, same aggregator code path, different
    // plugin.
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    let mut a_to_b = eth(MAC_B, MAC_A, 0x0800);
    a_to_b.extend_from_slice(&ipv4(51, [192, 168, 0, 1], [192, 168, 0, 2]));
    a_to_b.extend_from_slice(&ah(6, 0x1000_0001, 1, &[0xAA; 12]));
    a_to_b.extend_from_slice(&tcp(34567, 443));

    let mut b_to_a = eth(MAC_A, MAC_B, 0x0800);
    b_to_a.extend_from_slice(&ipv4(51, [192, 168, 0, 2], [192, 168, 0, 1]));
    b_to_a.extend_from_slice(&ah(6, 0x2000_0002, 1, &[0xBB; 12]));
    b_to_a.extend_from_slice(&tcp(443, 34567));

    agg.ingest(&engine.dissect(&a_to_b, meta(a_to_b.len(), 0), ParseOpts::default()));
    agg.ingest(&engine.dissect(&b_to_a, meta(b_to_a.len(), 1), ParseOpts::default()));

    let ip_conversations = agg.at_layer("ipv4");
    assert_eq!(
        ip_conversations.len(),
        1,
        "one folded IP conversation between the two hosts"
    );
    let ahs = agg.at_layer("ah");
    assert_eq!(ahs.len(), 2, "each direction's SPI is its own ah stream");
    assert!(ahs.iter().all(|a| a.parent == Some(ip_conversations[0].id)));
    assert_ne!(ahs[0].key, ahs[1].key);
}

#[test]
fn ah_truncated_icv_declines_safely_no_phantom_stream() {
    // 03.4/04.3: protocol-claimed traffic one byte short of the ICV length
    // its own `payload_len` field declares stops `Truncated`, not a
    // guessed short success — a `ByteReader::take` bounds failure, so it
    // reports as `StopReason::Truncated` rather than `PluginError` (the
    // latter is reserved for a plugin that parsed successfully but lied
    // about `header_len`, router.rs's rule-3 check).
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    let full = ah(6, 0x1000_0001, 1, &[0xAA; 12]);
    let mut frame = eth(MAC_B, MAC_A, 0x0800);
    frame.extend_from_slice(&ipv4(51, [192, 168, 0, 1], [192, 168, 0, 2]));
    frame.extend_from_slice(&full[..full.len() - 1]); // one byte short of the declared ICV

    let packet = engine.dissect(&frame, meta(frame.len(), 0), ParseOpts::default());
    let protocols: Vec<ProtocolName> = packet.layers.iter().map(|l| l.protocol).collect();
    assert_eq!(protocols, ["ethernet", "ipv4"], "ah declines, no phantom");
    assert_eq!(
        packet.stop,
        StopReason::Truncated {
            needed: 12,
            have: 11
        }
    );

    agg.ingest(&packet);
    assert_eq!(agg.at_layer("ah").len(), 0);
}

#[test]
fn l2tpv3_udp_data_fixture_hierarchy_node_by_node() {
    // eth ▸ ipv4 ▸ udp ▸ l2tpv3 ▸ ethernet ▸ ipv4 ▸ tcp (11.5's normative
    // hierarchy): the pseudowire's full inner stack, same rigor as
    // 06.5's VXLAN fixture.
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    let inner = {
        let mut i = eth(MAC_D, MAC_C, 0x0800);
        i.extend_from_slice(&ipv4(6, [172, 17, 0, 2], [172, 17, 0, 3]));
        i.extend_from_slice(&tcp(34567, 443));
        i
    };
    let mut frame = eth(MAC_B, MAC_A, 0x0800);
    frame.extend_from_slice(&ipv4(17, [192, 168, 0, 1], [192, 168, 0, 2]));
    frame.extend_from_slice(&udp(41000, 1701, (8 + inner.len()) as u16));
    frame.extend_from_slice(&l2tpv3_udp_data(9001));
    frame.extend_from_slice(&inner);

    agg.ingest(&engine.dissect(&frame, meta(frame.len(), 0), ParseOpts::default()));
    // `chain()` walks strict single-child parent links, so this sequence
    // alone proves the node-by-node nesting (FR-8, D10 parent scoping):
    // the inner Ethernet ▸ ipv4 ▸ tcp stack hangs off `l2tpv3`, not
    // directly off the outer `udp` stream.
    assert_eq!(
        chain(&agg),
        ["ethernet", "ipv4", "udp", "l2tpv3", "ethernet", "ipv4", "tcp"]
    );
    assert_eq!(
        agg.at_layer("ethernet").len(),
        2,
        "outer MAC pair + inner MAC pair"
    );
}

#[test]
fn two_session_ids_over_one_outer_udp_are_sibling_l2tpv3_streams() {
    // Mirrors vxlan/geneve's two-VNIs-one-outer-stream test (11.5
    // acceptance criteria): same outer UDP stream, two session ids -> two
    // sibling streams (shared-qualifier key shape, 06.5/11.5).
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    for (ms, session_id) in [(0u64, 100u32), (1, 200)] {
        let inner = eth(MAC_D, MAC_C, 0x9999); // unclaimed inner ethertype
        let mut frame = eth(MAC_B, MAC_A, 0x0800);
        frame.extend_from_slice(&ipv4(17, [192, 168, 0, 1], [192, 168, 0, 2]));
        frame.extend_from_slice(&udp(41000, 1701, (8 + inner.len()) as u16));
        frame.extend_from_slice(&l2tpv3_udp_data(session_id));
        frame.extend_from_slice(&inner);
        agg.ingest(&engine.dissect(&frame, meta(frame.len(), ms), ParseOpts::default()));
    }

    let outer_udp = agg.at_layer("udp")[0];
    let streams = agg.at_layer("l2tpv3");
    assert_eq!(
        streams.len(),
        2,
        "one stream per session id (shared-qualifier key)"
    );
    assert!(streams.iter().all(|s| s.parent == Some(outer_udp.id)));
    assert_ne!(streams[0].key, streams[1].key);
}

#[test]
fn l2tpv3_control_path_stops_terminal_without_misinterpreting_avps_as_data() {
    // 11.5's acceptance criterion: a control message's AVP region (Tier
    // 2, not decoded) must never be misread as pseudowire data, and a
    // control message (no `session_id`) forms no l2tpv3 stream.
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    // An AVP-shaped tail this plugin must never walk or route through.
    let avps = [0x00, 0x08, 0x00, 0x01, 0x00, 0x00];
    let control = l2tpv3_udp_control(7, &avps);
    let mut frame = eth(MAC_B, MAC_A, 0x0800);
    frame.extend_from_slice(&ipv4(17, [192, 168, 0, 1], [192, 168, 0, 2]));
    frame.extend_from_slice(&udp(41000, 1701, control.len() as u16));
    frame.extend_from_slice(&control);

    let packet = engine.dissect(&frame, meta(frame.len(), 0), ParseOpts::default());
    let protocols: Vec<ProtocolName> = packet.layers.iter().map(|l| l.protocol).collect();
    assert_eq!(
        protocols,
        ["ethernet", "ipv4", "udp", "l2tpv3"],
        "stops at l2tpv3, no phantom ethernet layer from the AVP bytes"
    );
    assert_eq!(packet.stop, StopReason::Terminal);

    agg.ingest(&packet);
    assert_eq!(
        agg.at_layer("l2tpv3").len(),
        0,
        "a control message carries no session_id: no stream can key on it"
    );
    assert_eq!(
        agg.at_layer("ethernet").len(),
        1,
        "only the outer MAC pair forms; no phantom inner ethernet from the AVP bytes"
    );
    assert_eq!(
        agg.at_layer("udp")[0].opaque_bytes,
        avps.len() as u64,
        "the AVP tail lands as opaque payload on udp, the innermost real stream"
    );
}

#[test]
fn l2tpv3_direct_ip_data_fixture_hierarchy_node_by_node() {
    // RFC 3931 §4.1.1: the direct-IP claim (IpProtocol 115, no UDP
    // header) carries data messages only — eth ▸ ipv4 ▸ l2tpv3 ▸ ethernet
    // ▸ ipv4 ▸ tcp, same full-inner-stack shape as the UDP path.
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    let inner = {
        let mut i = eth(MAC_D, MAC_C, 0x0800);
        i.extend_from_slice(&ipv4(6, [172, 17, 0, 2], [172, 17, 0, 3]));
        i.extend_from_slice(&tcp(34567, 443));
        i
    };
    let mut frame = eth(MAC_B, MAC_A, 0x0800);
    frame.extend_from_slice(&ipv4(115, [192, 168, 0, 1], [192, 168, 0, 2]));
    frame.extend_from_slice(&l2tpv3_ip_data(4242));
    frame.extend_from_slice(&inner);

    agg.ingest(&engine.dissect(&frame, meta(frame.len(), 0), ParseOpts::default()));
    assert_eq!(
        chain(&agg),
        ["ethernet", "ipv4", "l2tpv3", "ethernet", "ipv4", "tcp"]
    );
}

#[test]
fn inner_direction_stays_canonical_when_outer_disagrees() {
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    // Asymmetric tunnel: both packets ride the SAME outer direction
    // (192.168.0.1 -> .2), but the inner five-tuple flips. The inner
    // session must still fold both directions on its own canonical key.
    let fwd = gre_frame([10, 0, 0, 1], [10, 0, 0, 2], 34567, 443);
    let ret = gre_frame([10, 0, 0, 2], [10, 0, 0, 1], 443, 34567);
    agg.ingest(&engine.dissect(&fwd, meta(fwd.len(), 0), ParseOpts::default()));
    agg.ingest(&engine.dissect(&ret, meta(ret.len(), 1), ParseOpts::default()));

    // Outer IP conversation: both packets went one way.
    let outer_ip = agg
        .at_layer("ipv4")
        .into_iter()
        .find(|s| {
            s.parent
                .is_some_and(|p| agg.get(p).is_some_and(|q| q.protocol == "ethernet"))
        })
        .expect("outer ip");
    let outer_dirs: Vec<u64> = outer_ip.stats.iter().map(|s| s.packets).collect();
    assert!(
        outer_dirs.contains(&2) && outer_dirs.contains(&0),
        "outer traffic is one-directional: {outer_dirs:?}"
    );

    // Inner IP conversation and TCP session: one packet each direction,
    // canonicalized by their own keys.
    let inner_ip = agg
        .at_layer("ipv4")
        .into_iter()
        .find(|s| {
            s.parent
                .is_some_and(|p| agg.get(p).is_some_and(|q| q.protocol == "gre"))
        })
        .expect("inner ip");
    assert!(inner_ip.stats.iter().all(|s| s.packets == 1));
    let session = agg.at_layer("tcp")[0];
    assert!(session.stats.iter().all(|s| s.packets == 1));
}
