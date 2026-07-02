//! User-facing error wrapper with process exit codes (00.2).

use pktflow_capture::CaptureError;

/// Anything the `pktflow` binary can fail with, mapped to an exit code.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CliError {
    /// Bad arguments or usage.
    #[error("{0}")]
    Usage(String),
    /// A capture source failed.
    #[error(transparent)]
    Capture(#[from] CaptureError),
    /// Output or filesystem failure outside capture.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl CliError {
    /// Process exit code for this error (sysexits-style).
    pub fn exit_code(&self) -> i32 {
        match self {
            CliError::Usage(_) => 64,   // EX_USAGE
            CliError::Capture(_) => 74, // EX_IOERR
            CliError::Io(_) => 74,      // EX_IOERR
        }
    }
}
