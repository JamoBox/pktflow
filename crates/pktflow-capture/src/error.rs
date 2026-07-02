//! Capture-side failures: devices, files, permissions (00.2).

/// A capture source could not be opened or read.
///
/// Unlike core's `ParseError`, these are real program errors that surface
/// to the user.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CaptureError {
    /// Interface enumeration or open failed.
    #[error("capture device error: {0}")]
    Device(#[from] pcap::Error),
    /// A `.pcap`/`.pcapng` file could not be opened or read.
    #[error("capture file {path:?}: {source}")]
    File {
        path: std::path::PathBuf,
        source: std::io::Error,
    },
    /// Live capture requires privileges the process does not have.
    #[error("insufficient permissions for live capture on {interface:?}")]
    Permission { interface: String },
}
