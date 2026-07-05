//! Live capture & interface listing (07.3): named devices with
//! kernel-drop visibility, on Linux (libpcap) and Windows (Npcap).

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use pcap::{Active, Capture};
use pktflow_core::LinkType;

use crate::error::{map_pcap_error, CaptureError};
use crate::offline::header_meta;
use crate::source::{CaptureStats, PacketSource, RawPacket};

pub struct LiveConfig {
    pub promiscuous: bool,
    pub snaplen: i32,
    /// Kernel buffer size in bytes.
    pub buffer_size: usize,
    /// Bounds shutdown latency: the read loop re-checks the stop flag at
    /// least this often on a quiet interface. Reads are nonblocking under
    /// the hood — kernel read timeouts are not honored on every platform
    /// when no packets arrive at all, so the loop polls instead.
    pub read_timeout: Duration,
    /// Pre-kernel BPF filter string, compiled via libpcap.
    pub bpf: Option<String>,
}

impl Default for LiveConfig {
    fn default() -> Self {
        Self {
            promiscuous: true,
            snaplen: 65535,
            buffer_size: 4 * 1024 * 1024,
            read_timeout: Duration::from_millis(250),
            bpf: None,
        }
    }
}

pub struct LiveSource {
    capture: Capture<Active>,
    link_type: LinkType,
    stop: Arc<AtomicBool>,
    /// Sleep between empty nonblocking reads; derived from `read_timeout`.
    poll_interval: Duration,
    delivered: u64,
    kernel_stats: CaptureStats,
    /// Owns the most recent packet's bytes; libpcap's own buffer is only
    /// valid until the next read, so each packet is copied out once.
    buf: Vec<u8>,
}

/// Compiles and applies a BPF string; errors carry the filter text.
fn apply_bpf<T: pcap::Activated + ?Sized>(
    capture: &mut Capture<T>,
    bpf: &str,
) -> Result<(), CaptureError> {
    capture
        .filter(bpf, true)
        .map_err(|e| CaptureError::Backend(format!("BPF filter {bpf:?}: {e}")))
}

impl LiveSource {
    pub fn open(device: &str, cfg: LiveConfig) -> Result<LiveSource, CaptureError> {
        let inactive = Capture::from_device(device).map_err(|e| map_pcap_error(device, &e))?;
        let mut capture = inactive
            .promisc(cfg.promiscuous)
            .snaplen(cfg.snaplen)
            .buffer_size(i32::try_from(cfg.buffer_size).unwrap_or(i32::MAX))
            .timeout(i32::try_from(cfg.read_timeout.as_millis()).unwrap_or(250))
            .open()
            .map_err(|e| map_pcap_error(device, &e))?
            .setnonblock()
            .map_err(|e| map_pcap_error(device, &e))?;
        if let Some(bpf) = &cfg.bpf {
            apply_bpf(&mut capture, bpf)?;
        }
        let dlt = capture.get_datalink().0;
        Ok(LiveSource {
            capture,
            link_type: LinkType(u16::try_from(dlt).unwrap_or(u16::MAX)),
            stop: Arc::new(AtomicBool::new(false)),
            poll_interval: (cfg.read_timeout / 4)
                .clamp(Duration::from_millis(1), Duration::from_millis(50)),
            delivered: 0,
            kernel_stats: CaptureStats::default(),
            buf: Vec::new(),
        })
    }

    /// Shared stop flag: set it (e.g. from a Ctrl-C handler) and
    /// `next_packet` returns `Ok(None)` within one read timeout.
    pub fn stop_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.stop)
    }

    fn refresh_stats(&mut self) {
        if let Ok(s) = self.capture.stats() {
            self.kernel_stats = CaptureStats {
                received: self.delivered,
                dropped_kernel: u64::from(s.dropped),
                dropped_iface: u64::from(s.if_dropped),
            };
        } else {
            self.kernel_stats.received = self.delivered;
        }
    }
}

impl PacketSource for LiveSource {
    fn next_packet(&mut self) -> Result<Option<RawPacket<'_>>, CaptureError> {
        let meta = loop {
            if self.stop.load(Ordering::SeqCst) {
                self.refresh_stats();
                return Ok(None); // capture stopped: the clean end
            }
            match self.capture.next_packet() {
                Ok(packet) => {
                    self.buf.clear();
                    self.buf.extend_from_slice(packet.data);
                    break header_meta(packet.header, self.link_type);
                }
                // An empty nonblocking read is an internal retry, not
                // Ok(None) — that strictly means "source ended".
                Err(pcap::Error::TimeoutExpired) => {
                    self.refresh_stats();
                    std::thread::sleep(self.poll_interval);
                    continue;
                }
                Err(e) => return Err(map_pcap_error("live capture", &e)),
            }
        };
        self.delivered += 1;
        Ok(Some(RawPacket {
            bytes: &self.buf,
            meta,
        }))
    }

    fn link_type(&self) -> LinkType {
        self.link_type
    }

    fn stats(&self) -> CaptureStats {
        let mut s = self.kernel_stats;
        s.received = self.delivered;
        s
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct InterfaceInfo {
    pub name: String,
    pub description: Option<String>,
    pub addrs: Vec<IpAddr>,
    pub up: bool,
    pub loopback: bool,
}

/// FR-23: what can be captured on. On Windows this is how users discover
/// `\Device\NPF_{GUID}` names.
pub fn list_interfaces() -> Result<Vec<InterfaceInfo>, CaptureError> {
    let devices = pcap::Device::list().map_err(|e| map_pcap_error("device list", &e))?;
    Ok(devices
        .into_iter()
        .map(|d| InterfaceInfo {
            up: d.flags.is_up(),
            loopback: d.flags.is_loopback(),
            name: d.name,
            description: d.desc,
            addrs: d.addresses.iter().map(|a| a.addr).collect(),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(
        windows,
        ignore = "requires the Npcap runtime, which CI installs only as an SDK"
    )]
    fn invalid_bpf_is_a_clean_backend_error_naming_the_filter() {
        // A dead capture compiles filters without any capture privileges.
        let mut cap = Capture::dead(pcap::Linktype::ETHERNET).expect("dead captures always open");
        let err = apply_bpf(&mut cap, "this is not bpf").expect_err("invalid filter");
        let text = err.to_string();
        assert!(text.contains("this is not bpf"), "names the filter: {text}");
        assert!(matches!(err, CaptureError::Backend(_)));
    }
}
