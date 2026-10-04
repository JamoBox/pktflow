//! Capture-side failures (07.1): devices, files, permissions.

/// Per-OS remediation guidance for capture permissions; both variants are
/// always present so docs and tests don't depend on the build target.
pub const PERMISSION_REMEDIATION: &str = "on Linux: grant the binary capture rights \
(sudo setcap cap_net_raw,cap_net_admin=eip <path>) or run under sudo; \
on Windows: install Npcap (https://npcap.com) and run as Administrator \
or enable WinPcap-compatible mode for non-admin capture";

/// A capture source could not be opened or read. Unlike core's
/// `ParseError`, these are real program errors that surface to the user.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CaptureError {
    #[error("capture device not found: {0}")]
    DeviceNotFound(String),
    #[error("permission denied opening {device:?} — {PERMISSION_REMEDIATION}")]
    PermissionDenied { device: String },
    /// Not a capture file / corrupt container; carries libpcap's message.
    #[error("cannot read capture file: {0}")]
    FileFormat(String),
    #[error("capture I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Everything else libpcap reports (BPF compile errors, etc).
    #[error("capture backend error: {0}")]
    Backend(String),
}

/// Maps a pkttap error for an open/read on `subject` (device or path).
pub fn map_pkttap_error(subject: &str, err: &pkttap::Error) -> CaptureError {
    match err {
        pkttap::Error::PermissionDenied => CaptureError::PermissionDenied {
            device: subject.to_string(),
        },
        pkttap::Error::Filter(e) => {
            CaptureError::Backend(format!("BPF filter error on {subject}: {e}"))
        }
        pkttap::Error::Pcap(e) => CaptureError::FileFormat(format!("{subject}: {e}")),
        pkttap::Error::Io(e) => CaptureError::Io(std::io::Error::new(e.kind(), e.to_string())),
        pkttap::Error::Platform(msg) => {
            let lower = msg.to_lowercase();
            if lower.contains("no such device")
                || lower.contains("doesn't exist")
                || lower.contains("not found")
            {
                CaptureError::DeviceNotFound(subject.to_string())
            } else {
                CaptureError::Backend(format!("{subject}: {msg}"))
            }
        }
        pkttap::Error::WouldBlock => CaptureError::Backend(format!("{subject}: would block")),
    }
}
