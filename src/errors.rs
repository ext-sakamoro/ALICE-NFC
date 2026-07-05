//! errors.

use core::fmt;

// Errors
// ---------------------------------------------------------------------------

/// Crate-wide error type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NfcError {
    /// Payload too large or otherwise invalid.
    InvalidPayload(&'static str),
    /// Malformed NDEF message bytes.
    InvalidNdef(&'static str),
    /// TLV parse error.
    InvalidTlv(&'static str),
    /// APDU parse / build error.
    InvalidApdu(&'static str),
    /// Tag operation error.
    TagError(&'static str),
    /// Anti-collision error.
    CollisionError(&'static str),
    /// Buffer too small.
    BufferTooSmall,
}

impl fmt::Display for NfcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPayload(m)
            | Self::InvalidNdef(m)
            | Self::InvalidTlv(m)
            | Self::InvalidApdu(m)
            | Self::TagError(m)
            | Self::CollisionError(m) => f.write_str(m),
            Self::BufferTooSmall => f.write_str("buffer too small"),
        }
    }
}
