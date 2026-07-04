//! The source abstraction (07.1): one interface the CLI pumps regardless
//! of file vs. device, delivering zero-copy buffers + capture metadata.

use std::sync::mpsc::SyncSender;
use std::time::SystemTime;

use pktflow_core::{DissectedPacket, Engine, LinkType, PacketMeta, ParseOpts};

use crate::error::CaptureError;

/// One captured packet, borrowed from the source's internal buffer —
/// valid until the next `next_packet` call (lending-iterator shape). The
/// pipeline dissects immediately into an owned `DissectedPacket`, so the
/// borrow never outlives one loop turn: bytes are copied only into
/// `Value::Bytes` fields, never wholesale.
pub struct RawPacket<'a> {
    pub bytes: &'a [u8],
    pub meta: PacketMeta,
}

/// Received/dropped counters (FR-27). Nonzero drops must reach the user:
/// silent drops corrupt trust in stream stats.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct CaptureStats {
    pub received: u64,
    pub dropped_kernel: u64,
    pub dropped_iface: u64,
}

pub trait PacketSource {
    /// Blocking next packet. `Ok(None)` = clean end (file EOF / capture
    /// stopped) — never a mere timeout.
    fn next_packet(&mut self) -> Result<Option<RawPacket<'_>>, CaptureError>;
    /// Core's u16 DLT space, mapped from pcap here (core stays pcap-free).
    fn link_type(&self) -> LinkType;
    fn stats(&self) -> CaptureStats;
}

/// Totals for the final summary.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct PumpReport {
    pub packets: u64,
    pub bytes: u64,
    /// Out-of-order capture timestamps seen (real files have them; the
    /// aggregator's monotonic-max clock still ingests every packet).
    pub timestamps_regressed: u64,
    pub stats: CaptureStats,
}

/// The D5 pipeline's producer side, shared by offline and live: dissect
/// each packet and push it over the bounded channel (backpressure), up to
/// `limit` packets (FR-27's cap).
pub fn pump(
    src: &mut dyn PacketSource,
    engine: &Engine,
    opts: ParseOpts,
    tx: &SyncSender<DissectedPacket>,
    limit: Option<u64>,
) -> Result<PumpReport, CaptureError> {
    let mut report = PumpReport::default();
    let mut last_ts: Option<SystemTime> = None;

    while limit.is_none_or(|l| report.packets < l) {
        let Some(raw) = src.next_packet()? else {
            break;
        };
        if last_ts.is_some_and(|t| raw.meta.timestamp < t) {
            report.timestamps_regressed += 1;
        }
        last_ts = Some(last_ts.map_or(raw.meta.timestamp, |t| t.max(raw.meta.timestamp)));

        let packet = engine.dissect(raw.bytes, raw.meta, opts);
        report.packets += 1;
        report.bytes += raw.meta.origlen as u64;
        tx.send(packet)
            .map_err(|_| CaptureError::Backend("aggregation channel closed".into()))?;
    }
    report.stats = src.stats();
    Ok(report)
}

/// In-memory source for tests (07/08/09 all reuse it).
pub struct MockSource {
    packets: Vec<(SystemTime, Vec<u8>)>,
    link_type: LinkType,
    cursor: usize,
}

impl MockSource {
    pub fn new(packets: Vec<(SystemTime, Vec<u8>)>, link_type: LinkType) -> Self {
        Self {
            packets,
            link_type,
            cursor: 0,
        }
    }
}

impl PacketSource for MockSource {
    fn next_packet(&mut self) -> Result<Option<RawPacket<'_>>, CaptureError> {
        let Some((ts, bytes)) = self.packets.get(self.cursor) else {
            return Ok(None);
        };
        self.cursor += 1;
        Ok(Some(RawPacket {
            bytes,
            meta: PacketMeta {
                timestamp: *ts,
                caplen: bytes.len(),
                origlen: bytes.len(),
                link_type: self.link_type,
            },
        }))
    }

    fn link_type(&self) -> LinkType {
        self.link_type
    }

    fn stats(&self) -> CaptureStats {
        CaptureStats {
            received: self.cursor as u64,
            dropped_kernel: 0,
            dropped_iface: 0,
        }
    }
}
