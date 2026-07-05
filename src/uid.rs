//! uid.

use crate::errors::NfcError;
use core::fmt;

// ---------------------------------------------------------------------------
// UID
// ---------------------------------------------------------------------------

/// NFC UID (4, 7, or 10 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Uid {
    bytes: Vec<u8>,
}

impl Uid {
    /// Create a UID from raw bytes. Length must be 4, 7 or 10.
    ///
    /// # Errors
    /// Returns `NfcError` if the length is not 4, 7, or 10.
    pub fn new(bytes: &[u8]) -> Result<Self, NfcError> {
        match bytes.len() {
            4 | 7 | 10 => Ok(Self {
                bytes: bytes.to_vec(),
            }),
            _ => Err(NfcError::InvalidPayload("UID must be 4, 7 or 10 bytes")),
        }
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Compute BCC (XOR of all bytes).
    #[must_use]
    pub fn bcc(&self) -> u8 {
        self.bytes.iter().fold(0u8, |acc, &b| acc ^ b)
    }
}

impl fmt::Display for Uid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, b) in self.bytes.iter().enumerate() {
            if i > 0 {
                f.write_str(":")?;
            }
            write!(f, "{b:02X}")?;
        }
        Ok(())
    }
}
