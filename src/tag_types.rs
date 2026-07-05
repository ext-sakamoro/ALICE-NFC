//! tag types.

use crate::errors::NfcError;
use crate::ndef::NdefMessage;
use crate::tlv::{Tlv, TLV_NDEF_MESSAGE};
use crate::uid::Uid;

// ---------------------------------------------------------------------------
// Tag Types (1-4)
// ---------------------------------------------------------------------------

/// NFC tag type classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagType {
    Type1,
    Type2,
    Type3,
    Type4,
}

/// Simulated NFC tag with internal memory.
#[derive(Debug, Clone)]
pub struct Tag {
    pub tag_type: TagType,
    pub uid: Uid,
    memory: Vec<u8>,
    read_only: bool,
}

impl Tag {
    /// Create a new tag with given capacity (bytes).
    ///
    /// # Errors
    /// Returns `NfcError` if uid is invalid.
    #[must_use]
    pub fn new(tag_type: TagType, uid: Uid, capacity: usize) -> Self {
        Self {
            tag_type,
            uid,
            memory: vec![0u8; capacity],
            read_only: false,
        }
    }

    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.memory.len()
    }

    #[must_use]
    pub const fn is_read_only(&self) -> bool {
        self.read_only
    }

    pub const fn set_read_only(&mut self) {
        self.read_only = true;
    }

    /// Read bytes from tag memory.
    ///
    /// # Errors
    /// Returns `NfcError` if out of range.
    pub fn read(&self, offset: usize, length: usize) -> Result<&[u8], NfcError> {
        if offset + length > self.memory.len() {
            return Err(NfcError::TagError("read out of range"));
        }
        Ok(&self.memory[offset..offset + length])
    }

    /// Write bytes to tag memory.
    ///
    /// # Errors
    /// Returns `NfcError` if read-only or out of range.
    pub fn write(&mut self, offset: usize, data: &[u8]) -> Result<(), NfcError> {
        if self.read_only {
            return Err(NfcError::TagError("tag is read-only"));
        }
        if offset + data.len() > self.memory.len() {
            return Err(NfcError::TagError("write out of range"));
        }
        self.memory[offset..offset + data.len()].copy_from_slice(data);
        Ok(())
    }

    /// Write an NDEF message (as TLV) to the tag.
    ///
    /// # Errors
    /// Returns `NfcError` if data won't fit or tag is read-only.
    pub fn write_ndef(&mut self, msg: &NdefMessage) -> Result<(), NfcError> {
        let tlv_data = msg.to_tlv();
        let header_offset = match self.tag_type {
            TagType::Type1 => 12, // skip header area
            TagType::Type2 => 16, // skip first 4 pages (16 bytes)
            TagType::Type3 | TagType::Type4 => 0,
        };
        if header_offset + tlv_data.len() > self.memory.len() {
            return Err(NfcError::TagError("NDEF message too large for tag"));
        }
        self.write(header_offset, &tlv_data)
    }

    /// Read an NDEF message from the tag (scan for TLV type 0x03).
    ///
    /// # Errors
    /// Returns `NfcError` if no NDEF TLV found or parse fails.
    pub fn read_ndef(&self) -> Result<NdefMessage, NfcError> {
        let header_offset = match self.tag_type {
            TagType::Type1 => 12,
            TagType::Type2 => 16,
            TagType::Type3 | TagType::Type4 => 0,
        };
        if header_offset >= self.memory.len() {
            return Err(NfcError::TagError("tag too small"));
        }
        let tlvs = Tlv::parse_all(&self.memory[header_offset..])?;
        for tlv in &tlvs {
            if tlv.tag == TLV_NDEF_MESSAGE {
                return NdefMessage::parse(&tlv.value);
            }
        }
        Err(NfcError::TagError("no NDEF TLV found"))
    }
}
