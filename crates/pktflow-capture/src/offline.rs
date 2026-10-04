//! Offline replay (07.2): `.pcap` and `.pcapng` through the same
//! `PacketSource` — pkttap handles both containers transparently,
//! no hand-rolled file parsing.

use std::path::Path;

use pktflow_core::{LinkType, PacketMeta};

use crate::error::{map_pkttap_error, CaptureError};
use crate::source::{CaptureStats, PacketSource, RawPacket};

pub struct FileSource {
    capture: pkttap::Capture,
    link_type: LinkType,
    delivered: u64,
}

pub(crate) fn to_core_link_type(lt: pkttap::LinkType) -> LinkType {
    match lt {
        pkttap::LinkType::Ethernet => LinkType::ETHERNET,
        pkttap::LinkType::RawIp => LinkType::RAW,
        pkttap::LinkType::LinuxSll => LinkType(113),
    }
}

impl FileSource {
    pub fn open(path: &Path) -> Result<FileSource, CaptureError> {
        Self::open_with_filter(path, None)
    }

    pub fn open_with_filter(path: &Path, filter: Option<&str>) -> Result<FileSource, CaptureError> {
        let mut builder = pkttap::Capture::from_file(path);
        if let Some(f) = filter {
            builder = builder.filter(f);
        }
        let capture = builder.open().map_err(|e| match e {
            pkttap::Error::Io(ref io_err) => {
                CaptureError::FileFormat(format!("{}: {io_err}", path.display()))
            }
            _ => map_pkttap_error(&path.display().to_string(), &e),
        })?;
        let link_type = to_core_link_type(capture.link_type());
        Ok(FileSource {
            capture,
            link_type,
            delivered: 0,
        })
    }
}

impl PacketSource for FileSource {
    fn next_packet(&mut self) -> Result<Option<RawPacket<'_>>, CaptureError> {
        match self.capture.next() {
            Ok(Some(pkt)) => {
                self.delivered += 1;
                Ok(Some(RawPacket {
                    bytes: pkt.data(),
                    meta: PacketMeta {
                        timestamp: pkt.timestamp(),
                        caplen: pkt.data().len(),
                        origlen: pkt.orig_len() as usize,
                        link_type: self.link_type,
                    },
                }))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(map_pkttap_error("file capture", &e)),
        }
    }

    fn link_type(&self) -> LinkType {
        self.link_type
    }

    fn stats(&self) -> CaptureStats {
        CaptureStats {
            received: self.delivered,
            dropped_kernel: 0,
            dropped_iface: 0,
        }
    }
}
