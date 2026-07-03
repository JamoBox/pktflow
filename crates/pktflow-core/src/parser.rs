//! The lazy layer-at-a-time iterator (04.1) and entry resolution (04.2).
//!
//! One parsed layer per `next()`, borrowing the capture buffer, consuming
//! only as deep as the caller pulls — laziness is a real performance lever
//! when depth or an early consumer stops the walk (PRD §7).

use crate::context::ParseCtx;
use crate::depth::ParseOpts;
use crate::engine::Engine;
use crate::error::StopReason;
use crate::packet::{DissectedPacket, LayerRecord, LinkType, PacketMeta};
use crate::plugin::Hint;
use crate::route::RouteId;
use crate::router::{dispatch_explicit, StepOutcome};

/// One step of the walk: the parsed layer plus the payload after it.
pub struct LayerStep<'a> {
    /// Owned (fields extracted); the canonical copy stays in the iterator
    /// for cross-layer context — this is a cheap clone (see 04.1).
    pub record: LayerRecord,
    /// Remaining bytes after this header — borrowed, zero-copy.
    pub payload: &'a [u8],
    /// 03.3 diagnostic: this layer came from the fallback pool.
    pub via_heuristic: bool,
}

/// Lazy per-packet iterator; build with [`Engine::layers`].
pub struct LayerIter<'a> {
    engine: &'a Engine,
    bytes: &'a [u8],
    meta: PacketMeta,
    opts: ParseOpts,
    /// Canonical layer stack so `ParseCtx` can present prior layers.
    records: Vec<LayerRecord>,
    /// Offset of the remaining payload within `bytes`.
    cursor: usize,
    /// The last layer's hint, consumed by the next step.
    pending: Option<Hint>,
    started: bool,
    stop: Option<StopReason>,
}

impl Engine {
    /// Walks `bytes` one layer per `next()` call.
    ///
    /// # Panics
    ///
    /// A forced entry (`opts.entry`) naming an unregistered plugin is a
    /// caller bug, surfaced loudly at call time (build-style, 04.2) —
    /// never a quiet `StopReason`.
    pub fn layers<'a>(
        &'a self,
        bytes: &'a [u8],
        meta: &PacketMeta,
        opts: ParseOpts,
    ) -> LayerIter<'a> {
        if let Some(name) = opts.entry {
            assert!(
                self.plugin_by_name(name).is_some(),
                "forced entry {name:?} is not a registered plugin"
            );
        }
        LayerIter {
            engine: self,
            bytes,
            meta: *meta,
            opts,
            records: Vec::new(),
            cursor: 0,
            pending: None,
            started: false,
            stop: None,
        }
    }

    /// Entry precedence (04.2): forced entry, then the link-type route,
    /// then — strictly opt-in — heuristic first-layer identification.
    /// The entry is the one place heuristics may run without a preceding
    /// `Hint::Unknown`.
    fn resolve_entry(
        &self,
        bytes: &[u8],
        ctx: &ParseCtx,
        opts: &ParseOpts,
        link_type: LinkType,
    ) -> StepOutcome {
        if bytes.is_empty() {
            return StepOutcome::Stop(StopReason::Complete);
        }

        // Tier 1: forced entry (existence validated in `layers()`).
        if let Some(name) = opts.entry {
            return match self.plugin_by_name(name) {
                Some(p) => dispatch_explicit(p, bytes, ctx),
                None => StepOutcome::Stop(StopReason::PluginError),
            };
        }

        // Tier 2: the capture's link type, looked up like any explicit route.
        let id = RouteId::LinkType(link_type.0);
        if let Some(p) = self.plugin_for_route(id) {
            return dispatch_explicit(p, bytes, ctx);
        }

        // Tier 3: heuristics, only when explicitly allowed. With an empty
        // layer stack there is no predecessor, so no prior applies.
        if opts.allow_entry_heuristics {
            return match self.heuristic_fallback(bytes, ctx) {
                Some((protocol, parsed)) => StepOutcome::Layer {
                    protocol,
                    parsed,
                    via_heuristic: true,
                },
                None => StepOutcome::Stop(StopReason::UnknownHint),
            };
        }

        // Default-off keeps the gate philosophy: an unclaimed link type is
        // a configuration gap the user should see.
        StepOutcome::Stop(StopReason::UnclaimedRoute(id))
    }
}

impl<'a> LayerIter<'a> {
    /// `Some(reason)` once iteration has ended.
    pub fn stop_reason(&self) -> Option<StopReason> {
        self.stop
    }

    /// Finish eagerly (04.3): drain the walk and package the owned result.
    pub fn into_packet(mut self, meta: PacketMeta) -> DissectedPacket {
        while self.next().is_some() {}
        DissectedPacket {
            meta,
            opaque_len: self.bytes.len().saturating_sub(self.cursor),
            stop: self.stop.unwrap_or(StopReason::Complete),
            layers: self.records,
        }
    }
}

impl<'a> Iterator for LayerIter<'a> {
    type Item = LayerStep<'a>;

    fn next(&mut self) -> Option<LayerStep<'a>> {
        if self.stop.is_some() {
            return None;
        }
        let remaining = self.bytes.get(self.cursor..).unwrap_or(&[]);

        // Runaway guard: more payload at the cap is DepthCap; a cleanly
        // exhausted payload is still Complete.
        if self.records.len() >= self.opts.max_layers {
            self.stop = Some(if remaining.is_empty() {
                StopReason::Complete
            } else {
                StopReason::DepthCap
            });
            return None;
        }

        let depth = self.opts.effective_depth();
        let ctx = ParseCtx::new(&self.records, depth, &self.meta);
        let outcome = if self.started {
            let Some(hint) = self.pending.take() else {
                self.stop = Some(StopReason::PluginError);
                return None;
            };
            self.engine.resolve_next(&hint, remaining, &ctx)
        } else {
            self.started = true;
            self.engine
                .resolve_entry(remaining, &ctx, &self.opts, self.meta.link_type)
        };

        match outcome {
            StepOutcome::Layer {
                protocol,
                parsed,
                via_heuristic,
            } => {
                let record = LayerRecord {
                    protocol,
                    offset: self.cursor,
                    header_len: parsed.header_len,
                    fields: parsed.fields,
                };
                // header_len_ok was verified before the layer was emitted.
                self.cursor += parsed.header_len;
                self.pending = Some(parsed.hint);
                self.records.push(record.clone());
                Some(LayerStep {
                    record,
                    payload: self.bytes.get(self.cursor..).unwrap_or(&[]),
                    via_heuristic,
                })
            }
            StepOutcome::Stop(reason) => {
                self.stop = Some(reason);
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::SystemTime;

    use smallvec::SmallVec;

    use super::*;
    use crate::bytes::ByteReader;
    use crate::depth::Depth;
    use crate::error::ParseError;
    use crate::packet::ProtocolName;
    use crate::plugin::{Confidence, LayerPlugin, ParsedLayer};
    use crate::value::{FieldMap, Value};

    // ---- synthetic protocol set (real ones land in task 06) ----

    /// Ethernet II: 14-byte header, routes on the EtherType.
    struct Eth;

    impl LayerPlugin for Eth {
        fn name(&self) -> ProtocolName {
            "eth"
        }

        fn parse(&self, bytes: &[u8], _ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
            let mut r = ByteReader::new(bytes);
            let dst = r.take(6)?;
            let _src = r.take(6)?;
            let ethertype = r.u16_be()?;
            let mut fields = FieldMap::new();
            fields.insert("dst_mac", Value::from(dst));
            Ok(ParsedLayer {
                header_len: 14,
                fields,
                hint: Hint::Route(RouteId::EtherType(ethertype)),
            })
        }

        fn claims(&self) -> &'static [RouteId] {
            &[RouteId::LinkType(1)]
        }
    }

    /// IPv4-ish: version nibble + IHL, routes on the protocol byte.
    /// Records the depth it observed and counts parse calls.
    struct Ipv4 {
        parse_calls: Arc<AtomicUsize>,
        seen_depth: Arc<AtomicU8>,
        probing: bool,
    }

    impl Ipv4 {
        fn new() -> Self {
            Self {
                parse_calls: Arc::new(AtomicUsize::new(0)),
                seen_depth: Arc::new(AtomicU8::new(u8::MAX)),
                probing: false,
            }
        }
    }

    fn ipv4_checksum(header: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut i = 0;
        while i + 1 < header.len() {
            sum += u32::from(u16::from_be_bytes([header[i], header[i + 1]]));
            i += 2;
        }
        while sum > 0xFFFF {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }

    impl LayerPlugin for Ipv4 {
        fn name(&self) -> ProtocolName {
            "ipv4"
        }

        fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
            self.parse_calls.fetch_add(1, Ordering::SeqCst);
            self.seen_depth.store(ctx.depth() as u8, Ordering::SeqCst);
            let mut r = ByteReader::new(bytes);
            let ver_ihl = r.u8()?;
            if ver_ihl >> 4 != 4 {
                return Err(ParseError::Malformed("not ipv4"));
            }
            let header_len = usize::from(ver_ihl & 0x0F) * 4;
            if header_len < 20 {
                return Err(ParseError::Malformed("bad ihl"));
            }
            let _rest_to_proto = r.take(8)?; // tos..ttl
            let proto = r.u8()?;
            let _checksum = r.u16_be()?;
            let _addrs = r.take(header_len - 14)?;
            Ok(ParsedLayer {
                header_len,
                fields: FieldMap::new(),
                hint: Hint::Route(RouteId::IpProtocol(proto)),
            })
        }

        fn claims(&self) -> &'static [RouteId] {
            &[RouteId::EtherType(0x0800)]
        }

        fn has_probe(&self) -> bool {
            self.probing
        }

        /// The 04.2 raw-IP probe: version nibble + header checksum.
        fn probe(&self, bytes: &[u8], _ctx: &ParseCtx) -> Option<Confidence> {
            if !self.probing {
                return None;
            }
            let first = *bytes.first()?;
            if first >> 4 != 4 {
                return None;
            }
            let header_len = usize::from(first & 0x0F) * 4;
            let header = bytes.get(..header_len)?;
            (ipv4_checksum(header) == 0).then(|| Confidence::new(95))
        }
    }

    /// TCP-ish: fixed 20-byte header, terminal; counts parse calls.
    struct Tcp {
        parse_calls: Arc<AtomicUsize>,
    }

    impl LayerPlugin for Tcp {
        fn name(&self) -> ProtocolName {
            "tcp"
        }

        fn parse(&self, bytes: &[u8], _ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
            self.parse_calls.fetch_add(1, Ordering::SeqCst);
            let mut r = ByteReader::new(bytes);
            let src_port = r.u16_be()?;
            let dst_port = r.u16_be()?;
            let _rest = r.take(16)?;
            let mut fields = FieldMap::new();
            fields.insert("src_port", Value::U64(u64::from(src_port)));
            fields.insert("dst_port", Value::U64(u64::from(dst_port)));
            Ok(ParsedLayer {
                header_len: 20,
                fields,
                hint: Hint::Terminal,
            })
        }

        fn claims(&self) -> &'static [RouteId] {
            &[RouteId::IpProtocol(6)]
        }
    }

    /// UDP-ish: 8-byte header, offers dst/src port candidates.
    struct Udp;

    impl LayerPlugin for Udp {
        fn name(&self) -> ProtocolName {
            "udp"
        }

        fn parse(&self, bytes: &[u8], _ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
            let mut r = ByteReader::new(bytes);
            let src_port = r.u16_be()?;
            let dst_port = r.u16_be()?;
            let _len_ck = r.take(4)?;
            let mut fields = FieldMap::new();
            fields.insert("src_port", Value::U64(u64::from(src_port)));
            fields.insert("dst_port", Value::U64(u64::from(dst_port)));
            Ok(ParsedLayer {
                header_len: 8,
                fields,
                hint: Hint::Candidates(SmallVec::from_slice(&[
                    RouteId::UdpPort(dst_port),
                    RouteId::UdpPort(src_port),
                ])),
            })
        }

        fn claims(&self) -> &'static [RouteId] {
            &[RouteId::IpProtocol(17)]
        }
    }

    /// Self-encapsulating: 1 byte per layer, forever.
    struct Recurse;

    impl LayerPlugin for Recurse {
        fn name(&self) -> ProtocolName {
            "recurse"
        }

        fn parse(&self, bytes: &[u8], _ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
            let mut r = ByteReader::new(bytes);
            let _b = r.u8()?;
            Ok(ParsedLayer {
                header_len: 1,
                fields: FieldMap::new(),
                hint: Hint::ByProtocol("recurse"),
            })
        }

        fn claims(&self) -> &'static [RouteId] {
            &[RouteId::LinkType(147)]
        }
    }

    // ---- fixtures ----

    fn ipv4_header(proto: u8) -> Vec<u8> {
        let mut h = vec![
            0x45, 0x00, // ver/ihl, tos
            0x00, 0x28, // total length (irrelevant here)
            0x00, 0x01, 0x00, 0x00, // id, flags/frag
            0x40, proto, // ttl, protocol
            0x00, 0x00, // checksum placeholder
            10, 0, 0, 1, // src
            10, 0, 0, 2, // dst
        ];
        let ck = ipv4_checksum(&h);
        h[10] = (ck >> 8) as u8;
        h[11] = (ck & 0xFF) as u8;
        h
    }

    /// eth/ipv4/tcp with no payload after the TCP header.
    fn eth_ipv4_tcp() -> Vec<u8> {
        let mut pkt = vec![0xAA; 6];
        pkt.extend_from_slice(&[0xBB; 6]);
        pkt.extend_from_slice(&[0x08, 0x00]);
        pkt.extend_from_slice(&ipv4_header(6));
        pkt.extend_from_slice(&[
            0x01, 0xBB, 0xC0, 0x01, // ports 443 -> 49153
            0, 0, 0, 1, 0, 0, 0, 0, // seq, ack
            0x50, 0x02, 0x20, 0x00, // offset/flags/window
            0x00, 0x00, 0x00, 0x00, // checksum/urgent
        ]);
        pkt
    }

    fn meta(link_type: LinkType, len: usize) -> PacketMeta {
        PacketMeta {
            timestamp: SystemTime::UNIX_EPOCH,
            caplen: len,
            origlen: len,
            link_type,
        }
    }

    fn full_engine() -> (Engine, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let ipv4 = Ipv4::new();
        let ipv4_calls = Arc::clone(&ipv4.parse_calls);
        let tcp = Tcp {
            parse_calls: Arc::new(AtomicUsize::new(0)),
        };
        let tcp_calls = Arc::clone(&tcp.parse_calls);
        let engine = Engine::builder()
            .plugin(Eth)
            .plugin(ipv4)
            .plugin(tcp)
            .plugin(Udp)
            .build()
            .expect("valid registry");
        (engine, ipv4_calls, tcp_calls)
    }

    // ---- 04.1 ----

    #[test]
    fn eth_ipv4_tcp_yields_three_steps_then_complete() {
        let (engine, _, _) = full_engine();
        let pkt = eth_ipv4_tcp();
        let m = meta(LinkType::ETHERNET, pkt.len());
        let mut iter = engine.layers(&pkt, &m, ParseOpts::default());

        let steps: Vec<_> = iter.by_ref().collect();
        let summary: Vec<_> = steps
            .iter()
            .map(|s| {
                (
                    s.record.protocol,
                    s.record.offset,
                    s.record.header_len,
                    s.payload.len(),
                )
            })
            .collect();
        assert_eq!(
            summary,
            [("eth", 0, 14, 40), ("ipv4", 14, 20, 20), ("tcp", 34, 20, 0)]
        );
        assert!(steps.iter().all(|s| !s.via_heuristic));
        assert_eq!(iter.stop_reason(), Some(StopReason::Complete));
    }

    #[test]
    fn pulling_one_step_skips_inner_parsing() {
        let (engine, ipv4_calls, tcp_calls) = full_engine();
        let pkt = eth_ipv4_tcp();
        let m = meta(LinkType::ETHERNET, pkt.len());
        let mut iter = engine.layers(&pkt, &m, ParseOpts::default());

        let first = iter.next().expect("eth parses");
        assert_eq!(first.record.protocol, "eth");
        // Laziness verified, not assumed: nothing inner has run.
        assert_eq!(ipv4_calls.load(Ordering::SeqCst), 0);
        assert_eq!(tcp_calls.load(Ordering::SeqCst), 0);

        drop(iter);
        assert_eq!(ipv4_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn max_layers_cap_stops_with_depth_cap_no_hang() {
        let engine = Engine::builder().plugin(Recurse).build().expect("valid");
        let bytes = vec![0u8; 64];
        let m = meta(LinkType(147), bytes.len());
        let opts = ParseOpts {
            max_layers: 5,
            ..ParseOpts::default()
        };
        let mut iter = engine.layers(&bytes, &m, opts);
        assert_eq!(iter.by_ref().count(), 5);
        assert_eq!(iter.stop_reason(), Some(StopReason::DepthCap));
    }

    #[test]
    fn depth_clamp_plugins_observe_keys() {
        let ipv4 = Ipv4::new();
        let seen = Arc::clone(&ipv4.seen_depth);
        let engine = Engine::builder()
            .plugin(Eth)
            .plugin(ipv4)
            .build()
            .expect("valid");
        let pkt = eth_ipv4_tcp();
        let m = meta(LinkType::ETHERNET, pkt.len());
        let opts = ParseOpts {
            depth: Depth::None,
            aggregation: true,
            ..ParseOpts::default()
        };
        // Drain: ipv4 parses (tcp is unclaimed here — no tcp plugin).
        let iter = engine.layers(&pkt, &m, opts);
        assert!(iter.count() >= 2);
        assert_eq!(seen.load(Ordering::SeqCst), Depth::Keys as u8);
    }

    #[test]
    fn into_packet_packages_records_stop_and_opaque_len() {
        let (engine, _, _) = full_engine();
        // Unclaimed EtherType after eth: 2 opaque payload bytes remain.
        let mut pkt = vec![0xAA; 6];
        pkt.extend_from_slice(&[0xBB; 6]);
        pkt.extend_from_slice(&[0x86, 0xDD]); // ipv6, unregistered
        pkt.extend_from_slice(&[0x01, 0x02]);
        let m = meta(LinkType::ETHERNET, pkt.len());
        let packet = engine.layers(&pkt, &m, ParseOpts::default()).into_packet(m);
        assert_eq!(packet.layers.len(), 1);
        assert_eq!(packet.layers[0].protocol, "eth");
        assert_eq!(
            packet.stop,
            StopReason::UnclaimedRoute(RouteId::EtherType(0x86DD))
        );
        assert_eq!(packet.opaque_len, 2);
    }

    // ---- 04.2 ----

    #[test]
    fn forced_entry_beats_the_link_type_route() {
        let (engine, _, _) = full_engine();
        // An ipv4 packet on an Ethernet-typed capture, forced to ipv4.
        let mut pkt = ipv4_header(6);
        pkt.extend_from_slice(&eth_ipv4_tcp()[34..]); // the tcp bytes
        let m = meta(LinkType::ETHERNET, pkt.len());
        let opts = ParseOpts {
            entry: Some("ipv4"),
            ..ParseOpts::default()
        };
        let mut iter = engine.layers(&pkt, &m, opts);
        let first = iter.next().expect("ipv4 parses");
        assert_eq!(first.record.protocol, "ipv4");
        assert_eq!(iter.next().map(|s| s.record.protocol), Some("tcp"));
    }

    #[test]
    #[should_panic(expected = "not a registered plugin")]
    fn forced_entry_with_unknown_name_is_a_call_time_error() {
        let (engine, _, _) = full_engine();
        let pkt = eth_ipv4_tcp();
        let m = meta(LinkType::ETHERNET, pkt.len());
        let opts = ParseOpts {
            entry: Some("ghost"),
            ..ParseOpts::default()
        };
        let _ = engine.layers(&pkt, &m, opts);
    }

    #[test]
    fn unclaimed_link_type_with_heuristics_off_stops_with_zero_layers() {
        let (engine, _, _) = full_engine();
        let pkt = eth_ipv4_tcp();
        let m = meta(LinkType(147), pkt.len());
        let mut iter = engine.layers(&pkt, &m, ParseOpts::default());
        assert_eq!(iter.by_ref().count(), 0);
        assert_eq!(
            iter.stop_reason(),
            Some(StopReason::UnclaimedRoute(RouteId::LinkType(147)))
        );
    }

    #[test]
    fn raw_ip_parses_via_entry_heuristics_when_enabled() {
        let mut ipv4 = Ipv4::new();
        ipv4.probing = true;
        let tcp = Tcp {
            parse_calls: Arc::new(AtomicUsize::new(0)),
        };
        let engine = Engine::builder()
            .plugin(ipv4)
            .plugin(tcp)
            .build()
            .expect("valid");

        // DLT_RAW capture: bytes start straight at the IP header.
        let mut pkt = ipv4_header(6);
        pkt.extend_from_slice(&eth_ipv4_tcp()[34..]);
        let m = meta(LinkType::RAW, pkt.len());

        // Off by default: configuration gap, not a guess.
        let mut iter = engine.layers(&pkt, &m, ParseOpts::default());
        assert_eq!(iter.by_ref().count(), 0);
        assert_eq!(
            iter.stop_reason(),
            Some(StopReason::UnclaimedRoute(RouteId::LinkType(101)))
        );

        // Opted in: the version-nibble + checksum probe wins.
        let opts = ParseOpts {
            allow_entry_heuristics: true,
            ..ParseOpts::default()
        };
        let mut iter = engine.layers(&pkt, &m, opts);
        let first = iter.next().expect("ipv4 probe wins and parses");
        assert_eq!(first.record.protocol, "ipv4");
        assert!(first.via_heuristic);
        assert_eq!(iter.next().map(|s| s.record.protocol), Some("tcp"));
        assert_eq!(iter.stop_reason(), None); // not ended yet
    }

    // ---- toward 03.4: the motivating failure, at dissection level ----
    // (the stream-level assertions land with task 05)

    #[test]
    fn encrypted_udp_no_phantom() {
        let (engine, _, _) = full_engine();
        // eth/ipv4/udp with both ports unclaimed and an "encrypted"
        // payload that would historically cascade into TCP->IPv6->TCP.
        let mut pkt = vec![0xAA; 6];
        pkt.extend_from_slice(&[0xBB; 6]);
        pkt.extend_from_slice(&[0x08, 0x00]);
        pkt.extend_from_slice(&ipv4_header(17));
        pkt.extend_from_slice(&[
            0x11, 0x51, 0x11, 0x51, // ports 4433 -> 4433, unclaimed
            0x00, 0x28, 0x00, 0x00, // len, checksum
        ]);
        pkt.extend_from_slice(&[0x45, 0x00, 0x60, 0x02, 0xDE, 0xAD, 0xBE, 0xEF]);

        let m = meta(LinkType::ETHERNET, pkt.len());
        let packet = engine.layers(&pkt, &m, ParseOpts::default()).into_packet(m);

        let protocols: Vec<_> = packet.layers.iter().map(|l| l.protocol).collect();
        assert_eq!(protocols, ["eth", "ipv4", "udp"], "dissection ends at UDP");
        assert_eq!(
            packet.stop,
            StopReason::UnclaimedRoute(RouteId::UdpPort(4433))
        );
        assert_eq!(packet.opaque_len, 8, "payload attributed, not parsed");
    }
}
