//! Error types for sntrup operations.

/// Errors returned by sntrup operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Byte slice has the wrong length for conversion.
    #[error("invalid size: expected {expected} bytes, got {actual}")]
    InvalidSize {
        /// Expected size.
        expected: usize,
        /// Provided size.
        actual: usize,
    },
    /// A fixed-size key does not use the canonical Streamlined NTRU Prime
    /// encoding or contains inconsistent embedded metadata.
    #[error("invalid {kind} encoding")]
    InvalidEncoding {
        /// Kind of key whose encoded representation failed validation.
        kind: &'static str,
    },
}
