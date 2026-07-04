//! Offline replay (07.2): `.pcap` and `.pcapng` through the same
//! `PacketSource` — libpcap handles both containers transparently (D1),
//! no hand-rolled file parsing.
//!
//! Multi-linktype pcapng note: libpcap presents one link type per read
//! handle; a file whose interfaces genuinely mix DLTs surfaces as a
//! libpcap read error (mapped to `Backend`), not a misparse.

use std::path::Path;
use std::time::{Duration, SystemTime};

use pcap::{Capture, Offline};
use pktflow_core::{LinkType, PacketMeta};

use crate::error::CaptureError;
use crate::source::{CaptureStats, PacketSource, RawPacket};

pub struct FileSource {
    capture: Capture<Offline>,
    link_type: LinkType,
    delivered: u64,
}

/// libpcap timeval → `SystemTime`. File timestamps predate the epoch in
/// some synthetic captures; clamp rather than panic.
pub(crate) fn timeval_to_system_time(tv_sec: i64, tv_usec: i64) -> SystemTime {
    let secs = u64::try_from(tv_sec).unwrap_or(0);
    let micros = u64::try_from(tv_usec).unwrap_or(0);
    SystemTime::UNIX_EPOCH + Duration::from_secs(secs) + Duration::from_micros(micros)
}

/// timeval field widths differ across platforms, hence the cast allows.
#[allow(clippy::unnecessary_cast, clippy::useless_conversion)]
pub(crate) fn header_meta(header: &pcap::PacketHeader, link_type: LinkType) -> PacketMeta {
    PacketMeta {
        timestamp: timeval_to_system_time(header.ts.tv_sec as i64, header.ts.tv_usec as i64),
        caplen: header.caplen as usize,
        origlen: header.len as usize,
        link_type,
    }
}

impl FileSource {
    pub fn open(path: &Path) -> Result<FileSource, CaptureError> {
        let capture = Capture::from_file(path)
            .map_err(|e| CaptureError::FileFormat(format!("{}: {e}", path.display())))?;
        let dlt = capture.get_datalink().0;
        let link_type = LinkType(u16::try_from(dlt).unwrap_or(u16::MAX));
        Ok(FileSource {
            capture,
            link_type,
            delivered: 0,
        })
    }
}

impl PacketSource for FileSource {
    fn next_packet(&mut self) -> Result<Option<RawPacket<'_>>, CaptureError> {
        match self.capture.next_packet() {
            Ok(packet) => {
                self.delivered += 1;
                let meta = header_meta(packet.header, self.link_type);
                Ok(Some(RawPacket {
                    bytes: packet.data,
                    meta,
                }))
            }
            Err(pcap::Error::NoMorePackets) => Ok(None),
            Err(e) => Err(CaptureError::FileFormat(e.to_string())),
        }
    }

    fn link_type(&self) -> LinkType {
        self.link_type
    }

    fn stats(&self) -> CaptureStats {
        // libpcap has no kernel stats for files; received is ours.
        CaptureStats {
            received: self.delivered,
            dropped_kernel: 0,
            dropped_iface: 0,
        }
    }
}
