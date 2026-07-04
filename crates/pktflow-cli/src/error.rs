//! User-facing error wrapper with process exit codes (08.1): `0` ok,
//! `1` runtime error, `2` usage error (clap's own convention). Parse
//! failures of individual packets are data, not process errors (D9).

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
    /// A pipeline invariant broke (a bug, not a usage problem).
    #[error("internal error: {0}")]
    Internal(String),
}

impl CliError {
    /// Process exit code for this error (08.1).
    pub fn exit_code(&self) -> i32 {
        match self {
            CliError::Usage(_) => 2,
            _ => 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_follow_the_spec() {
        assert_eq!(CliError::Usage("bad".into()).exit_code(), 2);
        assert_eq!(
            CliError::Capture(CaptureError::Backend("x".into())).exit_code(),
            1
        );
        assert_eq!(CliError::Internal("bug".into()).exit_code(), 1);
    }
}
