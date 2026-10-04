//! Live capture & interface listing (07.3): named devices with
//! kernel-drop visibility.

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use pktflow_core::{LinkType, PacketMeta};

use crate::error::{map_pkttap_error, CaptureError};
use crate::offline::to_core_link_type;
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
    /// Pre-kernel BPF filter string, compiled via pkttap / pktbaffle.
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
    capture: pkttap::Capture,
    link_type: LinkType,
    stop: Arc<AtomicBool>,
    /// Sleep between empty nonblocking reads; derived from `read_timeout`.
    poll_interval: Duration,
    delivered: u64,
    kernel_stats: CaptureStats,
    /// Owns the most recent packet's bytes; pkttap's own buffer is only
    /// valid until the next read, so each packet is copied out once.
    buf: Vec<u8>,
}

impl LiveSource {
    pub fn open(device: &str, cfg: LiveConfig) -> Result<LiveSource, CaptureError> {
        let mut builder = pkttap::Capture::live(device)
            .promiscuous(cfg.promiscuous)
            .snaplen(u32::try_from(cfg.snaplen).unwrap_or(65535))
            .buffer_timeout(cfg.read_timeout)
            .nonblocking(true);
        if let Some(bpf) = &cfg.bpf {
            builder = builder.filter(bpf.as_str());
        }
        let capture = builder.open().map_err(|e| {
            if let Some(bpf) = &cfg.bpf {
                if matches!(e, pkttap::Error::Filter(_)) {
                    return map_pkttap_error(&format!("{device} ({bpf})"), &e);
                }
            }
            map_pkttap_error(device, &e)
        })?;
        let link_type = to_core_link_type(capture.link_type());
        Ok(LiveSource {
            capture,
            link_type,
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
                dropped_kernel: s.dropped,
                dropped_iface: s.if_dropped,
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
            match self.capture.next() {
                Ok(Some(packet)) => {
                    self.buf.clear();
                    self.buf.extend_from_slice(packet.data());
                    break PacketMeta {
                        timestamp: packet.timestamp(),
                        caplen: packet.data().len(),
                        origlen: packet.orig_len() as usize,
                        link_type: self.link_type,
                    };
                }
                // An empty nonblocking read is an internal retry, not
                // Ok(None) — that strictly means "source ended".
                Ok(None) | Err(pkttap::Error::WouldBlock) => {
                    self.refresh_stats();
                    std::thread::sleep(self.poll_interval);
                }
                Err(e) => return Err(map_pkttap_error("live capture", &e)),
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

/// FR-23: what can be captured on.
pub fn list_interfaces() -> Result<Vec<InterfaceInfo>, CaptureError> {
    let names = pkttap::interfaces().map_err(|e| map_pkttap_error("device list", &e))?;
    Ok(names
        .into_iter()
        .map(|name| {
            let lower = name.to_lowercase();
            let loopback = lower == "lo" || lower == "lo0" || lower.contains("loopback");
            InterfaceInfo {
                name,
                description: None,
                addrs: Vec::new(),
                up: true,
                loopback,
            }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_bpf_is_a_clean_backend_error_naming_the_filter() {
        let filter = "this is not bpf";
        let res = pktbaffle::compile(
            filter,
            pktbaffle::codegen::LinkType::Ethernet,
            pktbaffle::Target::Classic,
        );
        let err = match res {
            Ok(_) => panic!("invalid filter must fail"),
            Err(e) => CaptureError::Backend(format!("BPF filter error on test: {filter}: {e}")),
        };
        let text = err.to_string();
        assert!(text.contains("this is not bpf"), "names the filter: {text}");
        assert!(matches!(err, CaptureError::Backend(_)));
    }
}
