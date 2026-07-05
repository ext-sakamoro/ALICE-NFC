//! tlv.

use crate::errors::NfcError;

// ---------------------------------------------------------------------------
// TLV
// ---------------------------------------------------------------------------

/// TLV (Tag-Length-Value) block used in NFC Forum tags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tlv {
    pub tag: u8,
    pub value: Vec<u8>,
}

/// Well-known TLV tag constants.
pub const TLV_NULL: u8 = 0x00;
pub const TLV_NDEF_MESSAGE: u8 = 0x03;
pub const TLV_PROPRIETARY: u8 = 0xFD;
pub const TLV_TERMINATOR: u8 = 0xFE;

impl Tlv {
    #[must_use]
    pub const fn new(tag: u8, value: Vec<u8>) -> Self {
        Self { tag, value }
    }

    /// Encode this TLV to bytes (1-byte or 3-byte length format).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![self.tag];
        let len = self.value.len();
        if len < 0xFF {
            #[allow(clippy::cast_possible_truncation)]
            out.push(len as u8);
        } else {
            out.push(0xFF);
            #[allow(clippy::cast_possible_truncation)]
            {
                out.push((len >> 8) as u8);
                out.push(len as u8);
            }
        }
        out.extend_from_slice(&self.value);
        out
    }

    /// Parse a sequence of TLV blocks from raw bytes.
    ///
    /// # Errors
    /// Returns `NfcError` on malformed data.
    pub fn parse_all(data: &[u8]) -> Result<Vec<Self>, NfcError> {
        let mut result = Vec::new();
        let mut i = 0;
        while i < data.len() {
            let tag = data[i];
            i += 1;
            if tag == TLV_NULL {
                result.push(Self {
                    tag,
                    value: Vec::new(),
                });
                continue;
            }
            if tag == TLV_TERMINATOR {
                result.push(Self {
                    tag,
                    value: Vec::new(),
                });
                break;
            }
            if i >= data.len() {
                return Err(NfcError::InvalidTlv("unexpected end after tag"));
            }
            let length: usize;
            if data[i] == 0xFF {
                i += 1;
                if i + 1 >= data.len() {
                    return Err(NfcError::InvalidTlv("truncated 3-byte length"));
                }
                length = usize::from(data[i]) << 8 | usize::from(data[i + 1]);
                i += 2;
            } else {
                length = usize::from(data[i]);
                i += 1;
            }
            if i + length > data.len() {
                return Err(NfcError::InvalidTlv("value extends past end"));
            }
            result.push(Self {
                tag,
                value: data[i..i + length].to_vec(),
            });
            i += length;
        }
        Ok(result)
    }
}
