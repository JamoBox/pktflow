//! `pktflow-testkit` — the 09.2 synthetic fixture builder: real
//! wire-format bytes (checksums computed), layer by layer, deterministic
//! across runs. Test-only; never a dependency of shipping crates.
//!
//! Depends on `pktflow-core` alone: pcap files are written by hand (the
//! classic container is 24 + 16·n bytes of framing), keeping libpcap
//! behind the D1 boundary even for test tooling.

use std::path::Path;
use std::time::{Duration, SystemTime};

use pktflow_core::{LinkType, PacketMeta};

/// TCP flag bits for [`PacketBuilder::tcp`].
pub mod flags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
}

#[derive(Clone, Debug)]
enum Layer {
    Eth {
        src: [u8; 6],
        dst: [u8; 6],
    },
    Vlan {
        vid: u16,
        /// TPID the *enclosing* header uses to announce this tag: 0x8100
        /// for an ordinary 802.1Q tag, 0x88A8 for an 802.1ad S-tag (the
        /// outer tag of a QinQ stack).
        tpid: u16,
    },
    Ipv4 {
        src: [u8; 4],
        dst: [u8; 4],
    },
    /// RFC 7348 VXLAN: 8-byte header (I-flag + VNI), always wrapping an
    /// inner Ethernet frame.
    Vxlan {
        vni: u32,
    },
    Tcp {
        sport: u16,
        dport: u16,
        flags: u8,
        seq: u32,
        ack: u32,
    },
    Udp {
        sport: u16,
        dport: u16,
    },
    Gre,
    Payload(Vec<u8>),
    /// Payload bytes, but the enclosing header claims `protocol` as its
    /// next-protocol number regardless of what these bytes actually
    /// contain — fixtures needing a header that announces more than the
    /// bytes back up (a truncated TCP header, say).
    RawNext {
        protocol: u8,
        bytes: Vec<u8>,
    },
}

/// Fluent single-packet builder (outermost layer first). `build` yields
/// real wire bytes: lengths, next-protocol fields, and checksums are
/// computed, so fixtures exercise the actual parse path.
pub struct PacketBuilder {
    ts: SystemTime,
    layers: Vec<Layer>,
}

/// `"aa:bb:cc:dd:ee:ff"` → bytes. Panics on malformed input: fixtures
/// are compile-time constants and should fail loudly.
fn mac(s: &str) -> [u8; 6] {
    let mut out = [0u8; 6];
    let mut parts = s.split(':');
    for slot in &mut out {
        let part = parts.next().expect("6 MAC octets");
        *slot = u8::from_str_radix(part, 16).expect("hex MAC octet");
    }
    assert!(parts.next().is_none(), "6 MAC octets exactly");
    out
}

/// `"10.0.0.5"` → bytes; panics on malformed input (see [`mac`]).
fn ipv4(s: &str) -> [u8; 4] {
    let mut out = [0u8; 4];
    let mut parts = s.split('.');
    for slot in &mut out {
        let part = parts.next().expect("4 IPv4 octets");
        *slot = part.parse().expect("decimal IPv4 octet");
    }
    assert!(parts.next().is_none(), "4 IPv4 octets exactly");
    out
}

impl PacketBuilder {
    pub fn new(ts: SystemTime) -> Self {
        Self {
            ts,
            layers: Vec::new(),
        }
    }

    /// Timestamp helper: `at_secs(n)` = epoch + n seconds.
    pub fn at_secs(secs: u64) -> Self {
        Self::new(SystemTime::UNIX_EPOCH + Duration::from_secs(secs))
    }

    pub fn eth(mut self, src: &str, dst: &str) -> Self {
        self.layers.push(Layer::Eth {
            src: mac(src),
            dst: mac(dst),
        });
        self
    }

    /// An ordinary 802.1Q tag (TPID 0x8100).
    pub fn vlan(mut self, vid: u16) -> Self {
        self.layers.push(Layer::Vlan { vid, tpid: 0x8100 });
        self
    }

    /// An 802.1ad S-tag (TPID 0x88A8) — the outer tag of a QinQ stack
    /// (09.2 `qinq_stack`); follow with `.vlan(inner_vid)` for the C-tag.
    pub fn vlan_stag(mut self, vid: u16) -> Self {
        self.layers.push(Layer::Vlan { vid, tpid: 0x88A8 });
        self
    }

    pub fn ipv4(mut self, src: &str, dst: &str) -> Self {
        self.layers.push(Layer::Ipv4 {
            src: ipv4(src),
            dst: ipv4(dst),
        });
        self
    }

    pub fn tcp(mut self, sport: u16, dport: u16, flags: u8, seq: u32) -> Self {
        self.layers.push(Layer::Tcp {
            sport,
            dport,
            flags,
            seq,
            ack: 0,
        });
        self
    }

    pub fn tcp_ack(mut self, sport: u16, dport: u16, flags: u8, seq: u32, ack: u32) -> Self {
        self.layers.push(Layer::Tcp {
            sport,
            dport,
            flags,
            seq,
            ack,
        });
        self
    }

    pub fn udp(mut self, sport: u16, dport: u16) -> Self {
        self.layers.push(Layer::Udp { sport, dport });
        self
    }

    /// Base RFC 2784 GRE (no checksum/key/sequence; keyless = key 0).
    pub fn gre(mut self) -> Self {
        self.layers.push(Layer::Gre);
        self
    }

    /// RFC 7348 VXLAN over UDP (dst port 4789 conventionally set via
    /// `.udp(sport, 4789)`); always wraps an inner Ethernet frame.
    pub fn vxlan(mut self, vni: u32) -> Self {
        self.layers.push(Layer::Vxlan { vni });
        self
    }

    /// `n` bytes of `0xCC` filler beyond the last parsed layer.
    pub fn payload(self, n: usize) -> Self {
        self.bytes(vec![0xCC; n])
    }

    /// Raw application bytes (DNS messages, etc.).
    pub fn bytes(mut self, b: Vec<u8>) -> Self {
        self.layers.push(Layer::Payload(b));
        self
    }

    /// Raw bytes under an explicit IP next-protocol claim — for
    /// malformed fixtures (09.2 `malformed_zoo`): a header can announce
    /// TCP/UDP/etc. while the bytes behind it are too short to parse.
    pub fn bytes_claiming(mut self, protocol: u8, b: Vec<u8>) -> Self {
        self.layers.push(Layer::RawNext { protocol, bytes: b });
        self
    }

    /// A minimal DNS query message (one question, A/IN).
    pub fn dns_query(self, txid: u16, qname: &str) -> Self {
        let mut b = Vec::new();
        b.extend_from_slice(&txid.to_be_bytes());
        b.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
        b.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // 1 question
        push_qname(&mut b, qname);
        b.extend_from_slice(&[0, 1, 0, 1]); // A, IN
        self.bytes(b)
    }

    /// A DHCP/BOOTP message (RFC 2131): fixed 236-byte header + magic
    /// cookie + TLV options, always terminated by `END` (09.2 `dhcp_dora`:
    /// vary `op`/`msg_type`/`options` to build DISCOVER/OFFER/REQUEST/ACK).
    /// `op` is 1 (BOOTREQUEST, client→server) or 2 (BOOTREPLY, server→client);
    /// `msg_type` is the DHCP option-53 code (1=DISCOVER 2=OFFER 3=REQUEST
    /// 5=ACK). `options` are extra TLVs (code, data) appended after msg_type.
    pub fn dhcp(
        self,
        op: u8,
        msg_type: u8,
        xid: u32,
        client_mac: &str,
        options: &[(u8, &[u8])],
    ) -> Self {
        const MAGIC_COOKIE: u32 = 0x6382_5363;
        let mut b = Vec::with_capacity(240);
        b.push(op);
        b.push(1); // htype = Ethernet
        b.push(6); // hlen = 6
        b.push(0); // hops
        b.extend_from_slice(&xid.to_be_bytes());
        b.extend_from_slice(&[0; 8]); // secs+flags, ciaddr
        b.extend_from_slice(&[0; 8]); // yiaddr, siaddr
        b.extend_from_slice(&[0; 4]); // giaddr
        b.extend_from_slice(&mac(client_mac));
        b.extend_from_slice(&[0; 10]); // pad chaddr to 16 bytes
        b.extend_from_slice(&[0; 64]); // sname
        b.extend_from_slice(&[0; 128]); // file
        b.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        b.extend_from_slice(&[53, 1, msg_type]);
        for (code, data) in options {
            b.push(*code);
            b.push(u8::try_from(data.len()).expect("dhcp option fits in a byte"));
            b.extend_from_slice(data);
        }
        b.push(255); // END
        self.bytes(b)
    }

    /// A minimal DNS response (echoes the question, one A answer).
    pub fn dns_response(self, txid: u16, qname: &str, addr: &str) -> Self {
        let mut b = Vec::new();
        b.extend_from_slice(&txid.to_be_bytes());
        b.extend_from_slice(&0x8180u16.to_be_bytes()); // QR, RD, RA
        b.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 0]); // 1 q, 1 answer
        push_qname(&mut b, qname);
        b.extend_from_slice(&[0, 1, 0, 1]); // A, IN
        b.extend_from_slice(&[0xC0, 0x0C]); // pointer to the question name
        b.extend_from_slice(&[0, 1, 0, 1]); // A, IN
        b.extend_from_slice(&60u32.to_be_bytes()); // TTL
        b.extend_from_slice(&4u16.to_be_bytes());
        b.extend_from_slice(&ipv4(addr));
        self.bytes(b)
    }

    /// Real wire bytes + matching `PacketMeta` (ETHERNET link type).
    pub fn build(self) -> (PacketMeta, Vec<u8>) {
        let bytes = assemble(&self.layers);
        (
            PacketMeta {
                timestamp: self.ts,
                caplen: bytes.len(),
                origlen: bytes.len(),
                link_type: LinkType::ETHERNET,
            },
            bytes,
        )
    }
}

fn push_qname(out: &mut Vec<u8>, qname: &str) {
    for label in qname.split('.') {
        out.push(u8::try_from(label.len()).expect("label ≤ 63"));
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
}

/// EtherType announcing `layer` (what an Ethernet/VLAN/GRE header puts in
/// its next-protocol field).
fn ether_type_of(layer: &Layer) -> u16 {
    match layer {
        Layer::Vlan { tpid, .. } => *tpid,
        Layer::Ipv4 { .. } => 0x0800,
        // Payload directly under eth/gre: an ethertype nothing claims.
        _ => 0x9999,
    }
}

/// IPv4 protocol number announcing `layer`.
fn ip_proto_of(layer: Option<&Layer>) -> u8 {
    match layer {
        Some(Layer::Tcp { .. }) => 6,
        Some(Layer::Udp { .. }) => 17,
        Some(Layer::Gre) => 47,
        Some(Layer::Ipv4 { .. }) => 4, // IP-in-IP
        Some(Layer::RawNext { protocol, .. }) => *protocol,
        // Nothing (or a raw payload) next: a number nothing claims.
        _ => 253,
    }
}

/// RFC 1071 internet checksum.
fn internet_checksum(chunks: &[&[u8]]) -> u16 {
    let mut sum = 0u32;
    let mut carry_byte: Option<u8> = None;
    for chunk in chunks {
        for &b in *chunk {
            match carry_byte.take() {
                None => carry_byte = Some(b),
                Some(hi) => sum += u32::from(u16::from_be_bytes([hi, b])),
            }
        }
    }
    if let Some(hi) = carry_byte {
        sum += u32::from(u16::from_be_bytes([hi, 0]));
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Materializes innermost-first so every header knows its body; scans
/// outward for the enclosing IPv4 when a transport checksum needs the
/// pseudo-header.
fn assemble(layers: &[Layer]) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::new();
    for (i, layer) in layers.iter().enumerate().rev() {
        let next = layers.get(i + 1);
        body = match layer {
            Layer::Payload(b) => {
                let mut out = b.clone();
                out.extend_from_slice(&body);
                out
            }
            Layer::RawNext { bytes, .. } => {
                let mut out = bytes.clone();
                out.extend_from_slice(&body);
                out
            }
            Layer::Eth { src, dst } => {
                let mut out = Vec::with_capacity(14 + body.len());
                out.extend_from_slice(dst);
                out.extend_from_slice(src);
                out.extend_from_slice(&next.map_or(0x9999, ether_type_of).to_be_bytes());
                out.extend_from_slice(&body);
                out
            }
            Layer::Vlan { vid, .. } => {
                let mut out = Vec::with_capacity(4 + body.len());
                out.extend_from_slice(&(vid & 0x0FFF).to_be_bytes());
                out.extend_from_slice(&next.map_or(0x9999, ether_type_of).to_be_bytes());
                out.extend_from_slice(&body);
                out
            }
            Layer::Gre => {
                let mut out = Vec::with_capacity(4 + body.len());
                out.extend_from_slice(&0u16.to_be_bytes()); // no C/K/S, version 0
                out.extend_from_slice(&next.map_or(0x9999, ether_type_of).to_be_bytes());
                out.extend_from_slice(&body);
                out
            }
            Layer::Vxlan { vni } => {
                let mut out = Vec::with_capacity(8 + body.len());
                out.push(0x08); // flags: I-bit set, nothing else
                out.extend_from_slice(&[0, 0, 0]); // reserved
                out.extend_from_slice(&vni.to_be_bytes()[1..]); // 24-bit VNI
                out.push(0); // reserved
                out.extend_from_slice(&body);
                out
            }
            Layer::Ipv4 { src, dst } => {
                let total = u16::try_from(20 + body.len()).expect("IPv4 total_len fits");
                let mut hdr = Vec::with_capacity(20);
                hdr.extend_from_slice(&[0x45, 0]);
                hdr.extend_from_slice(&total.to_be_bytes());
                hdr.extend_from_slice(&[0x00, 0x00, 0x40, 0x00, 64, ip_proto_of(next)]);
                hdr.extend_from_slice(&[0, 0]); // checksum placeholder
                hdr.extend_from_slice(src);
                hdr.extend_from_slice(dst);
                let ck = internet_checksum(&[&hdr]);
                hdr[10..12].copy_from_slice(&ck.to_be_bytes());
                hdr.extend_from_slice(&body);
                hdr
            }
            Layer::Udp { sport, dport } => {
                let len = u16::try_from(8 + body.len()).expect("UDP length fits");
                let mut hdr = Vec::with_capacity(8);
                hdr.extend_from_slice(&sport.to_be_bytes());
                hdr.extend_from_slice(&dport.to_be_bytes());
                hdr.extend_from_slice(&len.to_be_bytes());
                hdr.extend_from_slice(&[0, 0]);
                let ck = transport_checksum(layers, i, 17, &hdr, &body);
                // UDP: an all-zero checksum means "none"; RFC 768 maps a
                // computed zero to 0xFFFF.
                let ck = if ck == 0 { 0xFFFF } else { ck };
                hdr[6..8].copy_from_slice(&ck.to_be_bytes());
                hdr.extend_from_slice(&body);
                hdr
            }
            Layer::Tcp {
                sport,
                dport,
                flags,
                seq,
                ack,
            } => {
                let mut hdr = Vec::with_capacity(20);
                hdr.extend_from_slice(&sport.to_be_bytes());
                hdr.extend_from_slice(&dport.to_be_bytes());
                hdr.extend_from_slice(&seq.to_be_bytes());
                hdr.extend_from_slice(&ack.to_be_bytes());
                hdr.extend_from_slice(&[5 << 4, *flags]);
                hdr.extend_from_slice(&8192u16.to_be_bytes());
                hdr.extend_from_slice(&[0, 0, 0, 0]); // checksum, urgent
                let ck = transport_checksum(layers, i, 6, &hdr, &body);
                hdr[16..18].copy_from_slice(&ck.to_be_bytes());
                hdr.extend_from_slice(&body);
                hdr
            }
        };
    }
    body
}

/// Pseudo-header checksum over the nearest enclosing IPv4 (scan outward).
fn transport_checksum(
    layers: &[Layer],
    index: usize,
    proto: u8,
    header: &[u8],
    body: &[u8],
) -> u16 {
    let enclosing = layers[..index].iter().rev().find_map(|l| match l {
        Layer::Ipv4 { src, dst } => Some((src, dst)),
        _ => None,
    });
    let Some((src, dst)) = enclosing else {
        return 0; // no IP parent (synthetic edge case): leave unchecksummed
    };
    let seg_len = u16::try_from(header.len() + body.len()).expect("transport segment length fits");
    let mut pseudo = Vec::with_capacity(12);
    pseudo.extend_from_slice(src);
    pseudo.extend_from_slice(dst);
    pseudo.extend_from_slice(&[0, proto]);
    pseudo.extend_from_slice(&seg_len.to_be_bytes());
    internet_checksum(&[&pseudo, header, body])
}

/// Multi-packet capture: pcap files for CLI-level tests, raw packet
/// vectors for in-process ones (`MockSource::new(kit.packets(), …)`).
#[derive(Clone, Default)]
pub struct CaptureBuilder {
    packets: Vec<(SystemTime, Vec<u8>)>,
}

impl CaptureBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn packet(mut self, builder: PacketBuilder) -> Self {
        let (meta, bytes) = builder.build();
        self.packets.push((meta.timestamp, bytes));
        self
    }

    /// A packet from already-assembled wire bytes, bypassing
    /// `PacketBuilder` — for fixtures that need post-build byte patching
    /// (09.2 `malformed_zoo`: bad IHL, fragment offsets) that the fluent
    /// layer-by-layer builder can't express.
    pub fn raw_packet(mut self, ts: SystemTime, bytes: Vec<u8>) -> Self {
        self.packets.push((ts, bytes));
        self
    }

    /// `(timestamp, wire bytes)` in insertion order — feed to
    /// `MockSource::new(…, LinkType::ETHERNET)`.
    pub fn packets(self) -> Vec<(SystemTime, Vec<u8>)> {
        self.packets
    }

    /// Classic little-endian µs pcap (DLT_EN10MB), written by hand:
    /// byte-identical across runs.
    pub fn write_pcap(&self, path: &Path) {
        let mut out = Vec::new();
        out.extend_from_slice(&0xA1B2_C3D4u32.to_le_bytes());
        out.extend_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(&4u16.to_le_bytes());
        out.extend_from_slice(&0i32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&65535u32.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        for (ts, frame) in &self.packets {
            let since = ts
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("fixture timestamps are ≥ epoch");
            let len = u32::try_from(frame.len()).expect("frame length fits");
            out.extend_from_slice(
                &u32::try_from(since.as_secs())
                    .expect("secs fit")
                    .to_le_bytes(),
            );
            out.extend_from_slice(&since.subsec_micros().to_le_bytes());
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(frame);
        }
        std::fs::write(path, out).expect("write pcap fixture");
    }
}

/// Deterministic address derived from a pool index: `prefix.b2.b1.b0` —
/// used by [`mixed_capture`] (and available to benches needing their own
/// bulk-distinct-flow corpora) so traffic is reproducible without a
/// `rand` dependency.
pub fn pool_ipv4(prefix: u8, index: u32) -> String {
    let [_, b2, b1, b0] = index.to_be_bytes();
    format!("{prefix}.{b2}.{b1}.{b0}")
}

/// Deterministic MAC derived from a pool index, paired with [`pool_ipv4`].
pub fn pool_mac(tag: u8, index: u32) -> String {
    let [_, b2, b1, b0] = index.to_be_bytes();
    format!("aa:bb:{tag:02x}:{b2:02x}:{b1:02x}:{b0:02x}")
}

/// The 09.4 bench corpus: a deterministic `n`-packet mix — 70% TCP, 20%
/// UDP+DNS, 5% tunnels (GRE), 5% noise (unclaimed-port UDP) — cycling
/// through bounded pools of distinct conversations (so aggregation sees
/// realistic, interleaved cardinality rather than one giant flow or a
/// million singleton ones). Reproducible byte-for-byte across runs: no
/// randomness, just index arithmetic.
pub fn mixed_capture(n: usize) -> Vec<(SystemTime, Vec<u8>)> {
    const TCP_POOL: u32 = 2_000;
    const DNS_POOL: u32 = 500;
    const TUNNEL_POOL: u32 = 100;
    const NOISE_POOL: u32 = 200;

    let mut packets = Vec::with_capacity(n);
    for i in 0..n {
        let ts = SystemTime::UNIX_EPOCH + Duration::from_secs(i as u64);
        let bucket = i % 20;
        let (meta, bytes) = if bucket < 14 {
            // 70%: TCP, a short handshake-through-data-through-teardown
            // cycle (14 phases) per flow, `TCP_POOL` flows interleaved.
            let flow = (i as u32 / 14) % TCP_POOL;
            let client = pool_ipv4(10, flow);
            let server = pool_ipv4(172, flow);
            let cport = 40000 + (flow % 20_000) as u16;
            let phase = i % 14;
            let (a, b, flags, seq) = match phase {
                0 => (&client, &server, flags::SYN, 1u32),
                1 => (&server, &client, flags::SYN | flags::ACK, 1),
                13 => (&client, &server, flags::FIN | flags::ACK, 100),
                p if p % 2 == 0 => (&client, &server, flags::PSH | flags::ACK, p as u32),
                p => (&server, &client, flags::PSH | flags::ACK, p as u32),
            };
            let (sport, dport) = if a == &client {
                (cport, 443)
            } else {
                (443, cport)
            };
            PacketBuilder::new(ts)
                .eth(&pool_mac(1, flow), &pool_mac(2, flow))
                .ipv4(a, b)
                .tcp(sport, dport, flags, seq)
                .payload(64)
                .build()
        } else if bucket < 18 {
            // 20%: DNS over UDP, query then response per flow.
            let flow = (i as u32 / 4) % DNS_POOL;
            let client = pool_ipv4(10, flow);
            let resolver = pool_ipv4(192, flow % 4); // a handful of resolvers
            let qname = format!("host-{flow}.example.net");
            let txid = (flow as u16).wrapping_add(i as u16);
            if i % 2 == 0 {
                PacketBuilder::new(ts)
                    .eth(&pool_mac(3, flow), &pool_mac(4, flow))
                    .ipv4(&client, &resolver)
                    .udp(34567, 53)
                    .dns_query(txid, &qname)
                    .build()
            } else {
                PacketBuilder::new(ts)
                    .eth(&pool_mac(4, flow), &pool_mac(3, flow))
                    .ipv4(&resolver, &client)
                    .udp(53, 34567)
                    .dns_response(txid, &qname, "93.184.216.34")
                    .build()
            }
        } else if bucket < 19 {
            // 5%: GRE-tunneled TCP.
            let flow = (i as u32) % TUNNEL_POOL;
            let outer_a = pool_ipv4(198, flow);
            let outer_b = pool_ipv4(203, flow);
            let inner_a = pool_ipv4(10, flow.wrapping_add(1_000_000));
            let inner_b = pool_ipv4(10, flow.wrapping_add(2_000_000));
            PacketBuilder::new(ts)
                .eth(&pool_mac(5, flow), &pool_mac(6, flow))
                .ipv4(&outer_a, &outer_b)
                .gre()
                .ipv4(&inner_a, &inner_b)
                .tcp(50000, 443, flags::PSH | flags::ACK, i as u32)
                .payload(32)
                .build()
        } else {
            // 5%: noise — an unclaimed UDP port, proving the gate holds
            // under load (03.4).
            let flow = (i as u32) % NOISE_POOL;
            let a = pool_ipv4(10, flow.wrapping_add(3_000_000));
            let b = pool_ipv4(10, flow.wrapping_add(4_000_000));
            PacketBuilder::new(ts)
                .eth(&pool_mac(7, flow), &pool_mac(8, flow))
                .ipv4(&a, &b)
                .udp(51820, 51820)
                .payload(96)
                .build()
        };
        packets.push((meta.timestamp, bytes));
    }
    packets
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_matches_a_known_vector() {
        // RFC 1071 example words: 0x0001 0xf203 0xf4f5 0xf6f7 → sum
        // 0x2ddf0 → fold 0xddf2 → complement 0x220d.
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(internet_checksum(&[&data]), 0x220d);
    }

    #[test]
    fn builds_are_byte_identical_across_runs() {
        let build = || {
            PacketBuilder::at_secs(100)
                .eth("aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02")
                .ipv4("10.0.0.5", "93.184.216.34")
                .tcp(52341, 443, flags::SYN, 1)
                .payload(3)
                .build()
        };
        let (meta_a, bytes_a) = build();
        let (meta_b, bytes_b) = build();
        assert_eq!(bytes_a, bytes_b);
        assert_eq!(meta_a, meta_b);
        assert_eq!(meta_a.caplen, 14 + 20 + 20 + 3);
    }

    #[test]
    fn ipv4_header_checksum_verifies() {
        let (_, bytes) = PacketBuilder::at_secs(0)
            .eth("aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02")
            .ipv4("10.0.0.5", "10.0.0.1")
            .udp(1000, 2000)
            .payload(4)
            .build();
        // Re-checksumming a valid header (checksum field included) gives 0.
        assert_eq!(internet_checksum(&[&bytes[14..34]]), 0);
    }

    #[test]
    fn tcp_checksum_verifies_against_the_pseudo_header() {
        let (_, bytes) = PacketBuilder::at_secs(0)
            .eth("aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02")
            .ipv4("10.0.0.5", "10.0.0.1")
            .tcp(1000, 2000, flags::SYN, 7)
            .build();
        let seg = &bytes[34..];
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&[10, 0, 0, 5, 10, 0, 0, 1, 0, 6]);
        pseudo.extend_from_slice(&u16::try_from(seg.len()).expect("fits").to_be_bytes());
        assert_eq!(internet_checksum(&[&pseudo, seg]), 0);
    }

    #[test]
    fn gre_nesting_announces_inner_ipv4() {
        let (_, bytes) = PacketBuilder::at_secs(0)
            .eth("aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02")
            .ipv4("192.168.1.1", "192.168.1.2")
            .gre()
            .ipv4("10.0.0.5", "10.0.0.9")
            .udp(1000, 2000)
            .build();
        assert_eq!(bytes[23], 47, "outer IP proto is GRE");
        assert_eq!(&bytes[34..38], &[0, 0, 0x08, 0x00], "GRE announces IPv4");
    }

    #[test]
    fn mixed_capture_is_deterministic_and_well_formed() {
        let a = mixed_capture(2000);
        let b = mixed_capture(2000);
        assert_eq!(a, b, "reproducible across runs");
        assert_eq!(a.len(), 2000);
        assert!(
            a.iter().all(|(_, bytes)| bytes.len() >= 14),
            "every packet has at least an eth header"
        );
    }
}
