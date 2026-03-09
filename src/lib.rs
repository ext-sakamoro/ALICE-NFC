#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

//! ALICE-NFC: Pure Rust NFC library.
//!
//! Covers NDEF (Text, URI, MIME, Smart Poster), Tag Type 1-4 read/write,
//! APDU commands (SELECT, READ BINARY, UPDATE BINARY), card emulation,
//! anti-collision, UID handling, and TLV encoding.

use core::fmt;

// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
// NDEF
// ---------------------------------------------------------------------------

/// NDEF Type Name Format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Tnf {
    Empty = 0x00,
    WellKnown = 0x01,
    MimeMedia = 0x02,
    AbsoluteUri = 0x03,
    External = 0x04,
    Unknown = 0x05,
    Unchanged = 0x06,
    Reserved = 0x07,
}

impl Tnf {
    const fn from_byte(b: u8) -> Self {
        match b & 0x07 {
            0x00 => Self::Empty,
            0x01 => Self::WellKnown,
            0x02 => Self::MimeMedia,
            0x03 => Self::AbsoluteUri,
            0x04 => Self::External,
            0x05 => Self::Unknown,
            0x06 => Self::Unchanged,
            _ => Self::Reserved,
        }
    }
}

/// NDEF record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NdefRecord {
    pub tnf: Tnf,
    pub record_type: Vec<u8>,
    pub id: Vec<u8>,
    pub payload: Vec<u8>,
}

// NDEF record header flag bits.
const FLAG_MB: u8 = 0x80;
const FLAG_ME: u8 = 0x40;
const FLAG_SR: u8 = 0x10;
const FLAG_IL: u8 = 0x08;

impl NdefRecord {
    /// Create a new NDEF record.
    #[must_use]
    pub const fn new(tnf: Tnf, record_type: Vec<u8>, id: Vec<u8>, payload: Vec<u8>) -> Self {
        Self {
            tnf,
            record_type,
            id,
            payload,
        }
    }

    // -- Convenience constructors ------------------------------------------

    /// Create an NDEF Text record (NFC Forum RTD Text, language code = "en").
    #[must_use]
    pub fn text(content: &str) -> Self {
        let lang = b"en";
        let mut payload = Vec::with_capacity(1 + lang.len() + content.len());
        #[allow(clippy::cast_possible_truncation)]
        payload.push(lang.len() as u8); // status byte: UTF-8, lang len
        payload.extend_from_slice(lang);
        payload.extend_from_slice(content.as_bytes());
        Self::new(Tnf::WellKnown, vec![b'T'], Vec::new(), payload)
    }

    /// Create an NDEF URI record with a URI identifier code.
    #[must_use]
    pub fn uri(identifier_code: u8, uri_field: &str) -> Self {
        let mut payload = Vec::with_capacity(1 + uri_field.len());
        payload.push(identifier_code);
        payload.extend_from_slice(uri_field.as_bytes());
        Self::new(Tnf::WellKnown, vec![b'U'], Vec::new(), payload)
    }

    /// Create an NDEF MIME record.
    #[must_use]
    pub fn mime(mime_type: &str, data: &[u8]) -> Self {
        Self::new(
            Tnf::MimeMedia,
            mime_type.as_bytes().to_vec(),
            Vec::new(),
            data.to_vec(),
        )
    }

    /// Create an NDEF Smart Poster record wrapping inner records.
    #[must_use]
    pub fn smart_poster(inner: &[Self]) -> Self {
        let payload = NdefMessage::new(inner.to_vec()).encode();
        Self::new(Tnf::WellKnown, vec![b'S', b'p'], Vec::new(), payload)
    }

    /// Encode a single record to bytes.
    /// `mb` / `me` indicate message-begin / message-end flags.
    #[must_use]
    pub fn encode(&self, mb: bool, me: bool) -> Vec<u8> {
        let sr = self.payload.len() < 256;
        let il = !self.id.is_empty();
        let mut flags: u8 = self.tnf as u8;
        if mb {
            flags |= FLAG_MB;
        }
        if me {
            flags |= FLAG_ME;
        }
        if sr {
            flags |= FLAG_SR;
        }
        if il {
            flags |= FLAG_IL;
        }

        let mut out = Vec::new();
        out.push(flags);
        #[allow(clippy::cast_possible_truncation)]
        out.push(self.record_type.len() as u8);

        if sr {
            #[allow(clippy::cast_possible_truncation)]
            out.push(self.payload.len() as u8);
        } else {
            #[allow(clippy::cast_possible_truncation)]
            let plen = self.payload.len() as u32;
            out.extend_from_slice(&plen.to_be_bytes());
        }

        if il {
            #[allow(clippy::cast_possible_truncation)]
            out.push(self.id.len() as u8);
        }

        out.extend_from_slice(&self.record_type);
        if il {
            out.extend_from_slice(&self.id);
        }
        out.extend_from_slice(&self.payload);
        out
    }

    /// Parse a single NDEF record from bytes, returning (record, `bytes_consumed`).
    ///
    /// # Errors
    /// Returns `NfcError` on malformed data.
    pub fn parse(data: &[u8]) -> Result<(Self, usize), NfcError> {
        if data.is_empty() {
            return Err(NfcError::InvalidNdef("empty record"));
        }
        let flags = data[0];
        let tnf = Tnf::from_byte(flags);
        let sr = flags & FLAG_SR != 0;
        let il = flags & FLAG_IL != 0;

        let mut pos: usize = 1;
        if pos >= data.len() {
            return Err(NfcError::InvalidNdef("truncated type length"));
        }
        let type_len = usize::from(data[pos]);
        pos += 1;

        let payload_len: usize;
        if sr {
            if pos >= data.len() {
                return Err(NfcError::InvalidNdef("truncated SR payload length"));
            }
            payload_len = usize::from(data[pos]);
            pos += 1;
        } else {
            if pos + 4 > data.len() {
                return Err(NfcError::InvalidNdef("truncated payload length"));
            }
            payload_len =
                u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]])
                    as usize;
            pos += 4;
        }

        let id_len: usize;
        if il {
            if pos >= data.len() {
                return Err(NfcError::InvalidNdef("truncated id length"));
            }
            id_len = usize::from(data[pos]);
            pos += 1;
        } else {
            id_len = 0;
        }

        if pos + type_len + id_len + payload_len > data.len() {
            return Err(NfcError::InvalidNdef("record extends past end"));
        }
        let record_type = data[pos..pos + type_len].to_vec();
        pos += type_len;
        let id = data[pos..pos + id_len].to_vec();
        pos += id_len;
        let payload = data[pos..pos + payload_len].to_vec();
        pos += payload_len;

        Ok((
            Self {
                tnf,
                record_type,
                id,
                payload,
            },
            pos,
        ))
    }

    /// Extract text content from an NDEF Text record.
    ///
    /// # Errors
    /// Returns `NfcError` if not a valid text record.
    pub fn text_content(&self) -> Result<String, NfcError> {
        if self.tnf != Tnf::WellKnown || self.record_type != [b'T'] {
            return Err(NfcError::InvalidNdef("not a text record"));
        }
        if self.payload.is_empty() {
            return Err(NfcError::InvalidNdef("empty text payload"));
        }
        let lang_len = usize::from(self.payload[0] & 0x3F);
        if 1 + lang_len > self.payload.len() {
            return Err(NfcError::InvalidNdef("bad lang length"));
        }
        String::from_utf8(self.payload[1 + lang_len..].to_vec())
            .map_err(|_| NfcError::InvalidNdef("invalid UTF-8 in text"))
    }

    /// Extract URI string from an NDEF URI record.
    ///
    /// # Errors
    /// Returns `NfcError` if not a valid URI record.
    pub fn uri_content(&self) -> Result<String, NfcError> {
        if self.tnf != Tnf::WellKnown || self.record_type != [b'U'] {
            return Err(NfcError::InvalidNdef("not a URI record"));
        }
        if self.payload.is_empty() {
            return Err(NfcError::InvalidNdef("empty URI payload"));
        }
        let prefix = uri_prefix(self.payload[0]);
        let rest = core::str::from_utf8(&self.payload[1..])
            .map_err(|_| NfcError::InvalidNdef("invalid UTF-8 in URI"))?;
        Ok(format!("{prefix}{rest}"))
    }
}

/// Map a URI identifier code to its string prefix (NFC Forum RTD URI).
#[must_use]
pub const fn uri_prefix(code: u8) -> &'static str {
    match code {
        0x01 => "http://www.",
        0x02 => "https://www.",
        0x03 => "http://",
        0x04 => "https://",
        0x05 => "tel:",
        0x06 => "mailto:",
        0x07 => "ftp://anonymous:anonymous@",
        0x08 => "ftp://ftp.",
        0x09 => "ftps://",
        0x0A => "sftp://",
        0x0B => "smb://",
        0x0C => "nfs://",
        0x0D => "ftp://",
        0x0E => "dav://",
        0x0F => "news:",
        0x10 => "telnet://",
        0x11 => "imap:",
        0x12 => "rtsp://",
        0x13 => "urn:",
        0x14 => "pop:",
        0x15 => "sip:",
        0x16 => "sips:",
        0x17 => "tftp:",
        0x18 => "btspp://",
        0x19 => "btl2cap://",
        0x1A => "btgoep://",
        0x1B => "tcpobex://",
        0x1C => "irdaobex://",
        0x1D => "file://",
        0x1E => "urn:epc:id:",
        0x1F => "urn:epc:tag:",
        0x20 => "urn:epc:pat:",
        0x21 => "urn:epc:raw:",
        0x22 => "urn:epc:",
        0x23 => "urn:nfc:",
        _ => "",
    }
}

/// NDEF message (ordered list of records).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NdefMessage {
    pub records: Vec<NdefRecord>,
}

impl NdefMessage {
    #[must_use]
    pub const fn new(records: Vec<NdefRecord>) -> Self {
        Self { records }
    }

    /// Encode the entire NDEF message to bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let len = self.records.len();
        let mut out = Vec::new();
        for (i, rec) in self.records.iter().enumerate() {
            out.extend_from_slice(&rec.encode(i == 0, i + 1 == len));
        }
        out
    }

    /// Parse an NDEF message from bytes.
    ///
    /// # Errors
    /// Returns `NfcError` on malformed data.
    pub fn parse(data: &[u8]) -> Result<Self, NfcError> {
        let mut records = Vec::new();
        let mut pos = 0;
        while pos < data.len() {
            let (rec, consumed) = NdefRecord::parse(&data[pos..])?;
            let flags = data[pos];
            pos += consumed;
            records.push(rec);
            if flags & FLAG_ME != 0 {
                break;
            }
        }
        if records.is_empty() {
            return Err(NfcError::InvalidNdef("no records"));
        }
        Ok(Self { records })
    }

    /// Wrap this NDEF message in TLV (type 0x03) + terminator.
    #[must_use]
    pub fn to_tlv(&self) -> Vec<u8> {
        let ndef_bytes = self.encode();
        let mut tlv = Tlv::new(TLV_NDEF_MESSAGE, ndef_bytes).encode();
        tlv.push(TLV_TERMINATOR);
        tlv
    }
}

// ---------------------------------------------------------------------------
// APDU
// ---------------------------------------------------------------------------

/// ISO 7816-4 APDU command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApduCommand {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub data: Vec<u8>,
    pub le: Option<u16>,
}

/// Well-known INS bytes.
pub const INS_SELECT: u8 = 0xA4;
pub const INS_READ_BINARY: u8 = 0xB0;
pub const INS_UPDATE_BINARY: u8 = 0xD6;

impl ApduCommand {
    #[must_use]
    pub const fn new(cla: u8, ins: u8, p1: u8, p2: u8) -> Self {
        Self {
            cla,
            ins,
            p1,
            p2,
            data: Vec::new(),
            le: None,
        }
    }

    #[must_use]
    pub fn with_data(mut self, data: Vec<u8>) -> Self {
        self.data = data;
        self
    }

    #[must_use]
    pub const fn with_le(mut self, le: u16) -> Self {
        self.le = Some(le);
        self
    }

    /// Build a SELECT command by name (P1=0x04, P2=0x00).
    #[must_use]
    pub fn select(aid: &[u8]) -> Self {
        Self::new(0x00, INS_SELECT, 0x04, 0x00).with_data(aid.to_vec())
    }

    /// Build a `READ BINARY` command.
    #[must_use]
    pub fn read_binary(offset: u16, length: u8) -> Self {
        #[allow(clippy::cast_possible_truncation)]
        Self::new(0x00, INS_READ_BINARY, (offset >> 8) as u8, offset as u8)
            .with_le(u16::from(length))
    }

    /// Build an `UPDATE BINARY` command.
    #[must_use]
    pub fn update_binary(offset: u16, data: &[u8]) -> Self {
        #[allow(clippy::cast_possible_truncation)]
        Self::new(0x00, INS_UPDATE_BINARY, (offset >> 8) as u8, offset as u8)
            .with_data(data.to_vec())
    }

    /// Encode the APDU command to bytes (short APDU format).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![self.cla, self.ins, self.p1, self.p2];
        if !self.data.is_empty() {
            #[allow(clippy::cast_possible_truncation)]
            out.push(self.data.len() as u8);
            out.extend_from_slice(&self.data);
        }
        if let Some(le) = self.le {
            #[allow(clippy::cast_possible_truncation)]
            out.push(le as u8);
        }
        out
    }

    /// Parse an APDU command from bytes.
    ///
    /// # Errors
    /// Returns `NfcError` on malformed data.
    pub fn parse(data: &[u8]) -> Result<Self, NfcError> {
        if data.len() < 4 {
            return Err(NfcError::InvalidApdu("APDU must be >= 4 bytes"));
        }
        let mut cmd = Self::new(data[0], data[1], data[2], data[3]);
        if data.len() == 4 {
            return Ok(cmd);
        }
        if data.len() == 5 {
            cmd.le = Some(u16::from(data[4]));
            return Ok(cmd);
        }
        let lc = usize::from(data[4]);
        if 5 + lc > data.len() {
            return Err(NfcError::InvalidApdu("Lc extends past end"));
        }
        cmd.data = data[5..5 + lc].to_vec();
        if 5 + lc < data.len() {
            cmd.le = Some(u16::from(data[5 + lc]));
        }
        Ok(cmd)
    }
}

/// ISO 7816-4 APDU response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApduResponse {
    pub data: Vec<u8>,
    pub sw1: u8,
    pub sw2: u8,
}

impl ApduResponse {
    #[must_use]
    pub const fn success(data: Vec<u8>) -> Self {
        Self {
            data,
            sw1: 0x90,
            sw2: 0x00,
        }
    }

    #[must_use]
    pub const fn error(sw1: u8, sw2: u8) -> Self {
        Self {
            data: Vec::new(),
            sw1,
            sw2,
        }
    }

    #[must_use]
    pub const fn is_ok(&self) -> bool {
        self.sw1 == 0x90 && self.sw2 == 0x00
    }

    #[must_use]
    pub fn status_word(&self) -> u16 {
        u16::from(self.sw1) << 8 | u16::from(self.sw2)
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.data.clone();
        out.push(self.sw1);
        out.push(self.sw2);
        out
    }

    /// Parse an APDU response from bytes.
    ///
    /// # Errors
    /// Returns `NfcError` if data is shorter than 2 bytes.
    pub fn parse(data: &[u8]) -> Result<Self, NfcError> {
        if data.len() < 2 {
            return Err(NfcError::InvalidApdu("response must be >= 2 bytes"));
        }
        let sw_start = data.len() - 2;
        Ok(Self {
            data: data[..sw_start].to_vec(),
            sw1: data[sw_start],
            sw2: data[sw_start + 1],
        })
    }
}

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

// ---------------------------------------------------------------------------
// Anti-Collision
// ---------------------------------------------------------------------------

/// NFC-A (ISO 14443-3A) anti-collision cascade level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CascadeLevel {
    Level1,
    Level2,
    Level3,
}

impl CascadeLevel {
    #[must_use]
    pub const fn sel_byte(self) -> u8 {
        match self {
            Self::Level1 => 0x93,
            Self::Level2 => 0x95,
            Self::Level3 => 0x97,
        }
    }
}

/// Cascade tag byte (0x88) used in multi-level UIDs.
pub const CASCADE_TAG: u8 = 0x88;

/// Anti-collision state machine.
#[derive(Debug, Clone)]
pub struct AntiCollision {
    known_bits: u8,
    uid_partial: Vec<u8>,
    cascade_level: CascadeLevel,
}

impl Default for AntiCollision {
    fn default() -> Self {
        Self::new()
    }
}

impl AntiCollision {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            known_bits: 0,
            uid_partial: Vec::new(),
            cascade_level: CascadeLevel::Level1,
        }
    }

    /// Build a SELECT command for the current cascade level.
    /// NVB indicates known bits: 0x20 = 2 bytes header + 0 UID bytes known.
    #[must_use]
    pub fn build_anticollision_cmd(&self) -> Vec<u8> {
        let mut cmd = vec![self.cascade_level.sel_byte(), 0x20 + self.known_bits];
        cmd.extend_from_slice(&self.uid_partial);
        cmd
    }

    /// Build a SELECT command (full UID known at current level).
    #[must_use]
    pub fn build_select_cmd(&self, uid_clx: &[u8; 4], bcc: u8) -> Vec<u8> {
        vec![
            self.cascade_level.sel_byte(),
            0x70, // NVB = 7 bytes
            uid_clx[0],
            uid_clx[1],
            uid_clx[2],
            uid_clx[3],
            bcc,
        ]
    }

    /// Advance to next cascade level.
    pub fn advance(&mut self) {
        self.cascade_level = match self.cascade_level {
            CascadeLevel::Level1 => CascadeLevel::Level2,
            CascadeLevel::Level2 | CascadeLevel::Level3 => CascadeLevel::Level3,
        };
        self.known_bits = 0;
        self.uid_partial.clear();
    }

    /// Set partial UID bits discovered during anti-collision.
    pub fn set_partial(&mut self, bits: u8, data: &[u8]) {
        self.known_bits = bits;
        self.uid_partial = data.to_vec();
    }

    #[must_use]
    pub const fn cascade_level(&self) -> CascadeLevel {
        self.cascade_level
    }

    /// Resolve a complete UID from cascade level responses.
    /// For a 4-byte UID, only level 1 response (4 bytes) is needed.
    /// For a 7-byte UID, level 1 has `[CT, u0, u1, u2]` and level 2 has `[u3, u4, u5, u6]`.
    ///
    /// # Errors
    /// Returns `NfcError` if slice lengths are wrong.
    pub fn resolve_uid(
        cl1: &[u8],
        cl2: Option<&[u8]>,
        cl3: Option<&[u8]>,
    ) -> Result<Uid, NfcError> {
        if cl1.len() != 4 {
            return Err(NfcError::CollisionError("CL1 must be 4 bytes"));
        }
        match (cl2, cl3) {
            (None, None) => Uid::new(cl1),
            (Some(l2), None) => {
                if l2.len() != 4 {
                    return Err(NfcError::CollisionError("CL2 must be 4 bytes"));
                }
                // cl1[0] should be CASCADE_TAG
                let mut uid = Vec::with_capacity(7);
                uid.extend_from_slice(&cl1[1..4]);
                uid.extend_from_slice(l2);
                Uid::new(&uid)
            }
            (Some(l2), Some(l3)) => {
                if l2.len() != 4 || l3.len() != 4 {
                    return Err(NfcError::CollisionError("CL2/CL3 must be 4 bytes"));
                }
                let mut uid = Vec::with_capacity(10);
                uid.extend_from_slice(&cl1[1..4]);
                uid.extend_from_slice(&l2[1..4]);
                uid.extend_from_slice(l3);
                Uid::new(&uid)
            }
            (None, Some(_)) => Err(NfcError::CollisionError("CL3 without CL2")),
        }
    }
}

// ---------------------------------------------------------------------------
// Card Emulation
// ---------------------------------------------------------------------------

/// NDEF Tag Application AID (NFC Forum Type 4 Tag).
pub const NDEF_TAG_APPLICATION_AID: &[u8] = &[0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01];

/// Capability Container file ID.
pub const CC_FILE_ID: u16 = 0xE103;

/// NDEF file default ID.
pub const NDEF_FILE_ID: u16 = 0xE104;

/// Emulated NFC Type 4 tag (card emulation mode).
#[derive(Debug, Clone)]
pub struct CardEmulator {
    /// Capability container.
    cc: Vec<u8>,
    /// NDEF file content (2-byte length prefix + NDEF message).
    ndef_file: Vec<u8>,
    /// Currently selected file.
    selected_file: Option<u16>,
    /// Application selected flag.
    app_selected: bool,
}

impl CardEmulator {
    /// Create a new card emulator with an NDEF message.
    #[must_use]
    pub fn new(msg: &NdefMessage) -> Self {
        let ndef_bytes = msg.encode();

        // Build CC file (15 bytes as per NFC Forum Type 4 spec).
        let mut cc = vec![0u8; 15];
        cc[0] = 0x00; // CC length high
        cc[1] = 0x0F; // CC length low = 15
        cc[2] = 0x20; // mapping version 2.0
        cc[3] = 0x00; // MLe high
        cc[4] = 0xFF; // MLe low = 255
        cc[5] = 0x00; // MLc high
        cc[6] = 0xFF; // MLc low = 255
                      // NDEF File Control TLV
        cc[7] = 0x04; // T
        cc[8] = 0x06; // L
        cc[9] = 0xE1; // NDEF File ID high
        cc[10] = 0x04; // NDEF File ID low
        #[allow(clippy::cast_possible_truncation)]
        {
            let max_size: u16 = 0x0800;
            cc[11] = (max_size >> 8) as u8;
            cc[12] = max_size as u8;
        }
        cc[13] = 0x00; // read access: no security
        cc[14] = 0x00; // write access: no security

        // NDEF file: 2-byte length + NDEF bytes.
        let mut ndef_file = Vec::with_capacity(2 + ndef_bytes.len());
        #[allow(clippy::cast_possible_truncation)]
        {
            let nlen = ndef_bytes.len() as u16;
            ndef_file.push((nlen >> 8) as u8);
            ndef_file.push(nlen as u8);
        }
        ndef_file.extend_from_slice(&ndef_bytes);

        Self {
            cc,
            ndef_file,
            selected_file: None,
            app_selected: false,
        }
    }

    /// Process an incoming APDU command and return a response.
    #[must_use]
    pub fn process(&mut self, cmd: &ApduCommand) -> ApduResponse {
        match cmd.ins {
            INS_SELECT => self.handle_select(cmd),
            INS_READ_BINARY => self.handle_read(cmd),
            INS_UPDATE_BINARY => self.handle_update(cmd),
            _ => ApduResponse::error(0x6D, 0x00), // INS not supported
        }
    }

    fn handle_select(&mut self, cmd: &ApduCommand) -> ApduResponse {
        // Select by name (AID)
        if cmd.p1 == 0x04 {
            if cmd.data == NDEF_TAG_APPLICATION_AID {
                self.app_selected = true;
                self.selected_file = None;
                return ApduResponse::success(Vec::new());
            }
            return ApduResponse::error(0x6A, 0x82); // file not found
        }
        // Select by file ID
        if cmd.p1 == 0x00 && cmd.data.len() == 2 {
            if !self.app_selected {
                return ApduResponse::error(0x69, 0x86); // command not allowed
            }
            let fid = u16::from(cmd.data[0]) << 8 | u16::from(cmd.data[1]);
            if fid == CC_FILE_ID || fid == NDEF_FILE_ID {
                self.selected_file = Some(fid);
                return ApduResponse::success(Vec::new());
            }
            return ApduResponse::error(0x6A, 0x82);
        }
        ApduResponse::error(0x6A, 0x86) // incorrect P1-P2
    }

    fn handle_read(&self, cmd: &ApduCommand) -> ApduResponse {
        let Some(fid) = self.selected_file else {
            return ApduResponse::error(0x69, 0x86);
        };
        let file = if fid == CC_FILE_ID {
            &self.cc
        } else if fid == NDEF_FILE_ID {
            &self.ndef_file
        } else {
            return ApduResponse::error(0x6A, 0x82);
        };
        let offset = usize::from(cmd.p1) << 8 | usize::from(cmd.p2);
        let le = cmd.le.map_or(0, usize::from);
        if offset >= file.len() {
            return ApduResponse::error(0x6A, 0x82);
        }
        let end = file.len().min(offset + le);
        ApduResponse::success(file[offset..end].to_vec())
    }

    fn handle_update(&mut self, cmd: &ApduCommand) -> ApduResponse {
        let Some(fid) = self.selected_file else {
            return ApduResponse::error(0x69, 0x86);
        };
        if fid != NDEF_FILE_ID {
            return ApduResponse::error(0x69, 0x86);
        }
        let offset = usize::from(cmd.p1) << 8 | usize::from(cmd.p2);
        if offset + cmd.data.len() > self.ndef_file.len() {
            // Extend if needed
            self.ndef_file.resize(offset + cmd.data.len(), 0);
        }
        self.ndef_file[offset..offset + cmd.data.len()].copy_from_slice(&cmd.data);
        ApduResponse::success(Vec::new())
    }

    /// Get the currently stored NDEF message.
    ///
    /// # Errors
    /// Returns `NfcError` if stored data is invalid.
    pub fn ndef_message(&self) -> Result<NdefMessage, NfcError> {
        if self.ndef_file.len() < 2 {
            return Err(NfcError::InvalidNdef("NDEF file too short"));
        }
        let nlen = usize::from(self.ndef_file[0]) << 8 | usize::from(self.ndef_file[1]);
        if 2 + nlen > self.ndef_file.len() {
            return Err(NfcError::InvalidNdef("NDEF length exceeds file"));
        }
        NdefMessage::parse(&self.ndef_file[2..2 + nlen])
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // === UID tests ===

    #[test]
    fn uid_4byte() {
        let uid = Uid::new(&[0x01, 0x02, 0x03, 0x04]).unwrap();
        assert_eq!(uid.len(), 4);
        assert!(!uid.is_empty());
    }

    #[test]
    fn uid_7byte() {
        let uid = Uid::new(&[1, 2, 3, 4, 5, 6, 7]).unwrap();
        assert_eq!(uid.len(), 7);
    }

    #[test]
    fn uid_10byte() {
        let uid = Uid::new(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]).unwrap();
        assert_eq!(uid.len(), 10);
    }

    #[test]
    fn uid_invalid_length() {
        assert!(Uid::new(&[1, 2, 3]).is_err());
        assert!(Uid::new(&[1, 2, 3, 4, 5]).is_err());
        assert!(Uid::new(&[]).is_err());
    }

    #[test]
    fn uid_bcc() {
        let uid = Uid::new(&[0x01, 0x02, 0x03, 0x04]).unwrap();
        assert_eq!(uid.bcc(), 0x01 ^ 0x02 ^ 0x03 ^ 0x04);
    }

    #[test]
    fn uid_display() {
        let uid = Uid::new(&[0xAB, 0xCD, 0xEF, 0x01]).unwrap();
        assert_eq!(format!("{uid}"), "AB:CD:EF:01");
    }

    #[test]
    fn uid_as_bytes() {
        let uid = Uid::new(&[0x10, 0x20, 0x30, 0x40]).unwrap();
        assert_eq!(uid.as_bytes(), &[0x10, 0x20, 0x30, 0x40]);
    }

    // === TLV tests ===

    #[test]
    fn tlv_null() {
        let tlv = Tlv::new(TLV_NULL, Vec::new());
        let encoded = tlv.encode();
        assert_eq!(encoded, &[0x00, 0x00]);
    }

    #[test]
    fn tlv_short_value() {
        let tlv = Tlv::new(0x03, vec![0xAA, 0xBB]);
        let encoded = tlv.encode();
        assert_eq!(encoded, &[0x03, 0x02, 0xAA, 0xBB]);
    }

    #[test]
    fn tlv_3byte_length() {
        let data = vec![0x42; 300];
        let tlv = Tlv::new(0x03, data.clone());
        let encoded = tlv.encode();
        assert_eq!(encoded[0], 0x03);
        assert_eq!(encoded[1], 0xFF);
        assert_eq!(encoded[2], 0x01); // 300 >> 8
        assert_eq!(encoded[3], 0x2C); // 300 & 0xFF
        assert_eq!(&encoded[4..], &data[..]);
    }

    #[test]
    fn tlv_parse_empty() {
        let data = [TLV_TERMINATOR];
        let tlvs = Tlv::parse_all(&data).unwrap();
        assert_eq!(tlvs.len(), 1);
        assert_eq!(tlvs[0].tag, TLV_TERMINATOR);
    }

    #[test]
    fn tlv_parse_null_and_terminator() {
        let data = [TLV_NULL, TLV_TERMINATOR];
        let tlvs = Tlv::parse_all(&data).unwrap();
        assert_eq!(tlvs.len(), 2);
    }

    #[test]
    fn tlv_parse_ndef() {
        let inner = vec![0xD1, 0x01, 0x00];
        let mut data = vec![0x03, 0x03]; // tag=NDEF, len=3
        data.extend_from_slice(&inner);
        data.push(TLV_TERMINATOR);
        let tlvs = Tlv::parse_all(&data).unwrap();
        assert_eq!(tlvs.len(), 2);
        assert_eq!(tlvs[0].tag, TLV_NDEF_MESSAGE);
        assert_eq!(tlvs[0].value, inner);
    }

    #[test]
    fn tlv_roundtrip() {
        let original = Tlv::new(0xFD, vec![1, 2, 3, 4, 5]);
        let encoded = original.encode();
        let parsed = Tlv::parse_all(&encoded).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0], original);
    }

    #[test]
    fn tlv_parse_truncated() {
        assert!(Tlv::parse_all(&[0x03]).is_err());
    }

    #[test]
    fn tlv_parse_3byte_len_truncated() {
        assert!(Tlv::parse_all(&[0x03, 0xFF, 0x00]).is_err());
    }

    #[test]
    fn tlv_parse_value_too_short() {
        assert!(Tlv::parse_all(&[0x03, 0x05, 0x01]).is_err());
    }

    // === NDEF Record tests ===

    #[test]
    fn ndef_text_record() {
        let rec = NdefRecord::text("Hello");
        assert_eq!(rec.tnf, Tnf::WellKnown);
        assert_eq!(rec.record_type, vec![b'T']);
        let content = rec.text_content().unwrap();
        assert_eq!(content, "Hello");
    }

    #[test]
    fn ndef_uri_record() {
        let rec = NdefRecord::uri(0x04, "example.com");
        let content = rec.uri_content().unwrap();
        assert_eq!(content, "https://example.com");
    }

    #[test]
    fn ndef_uri_prefix_http() {
        assert_eq!(uri_prefix(0x03), "http://");
    }

    #[test]
    fn ndef_uri_prefix_unknown() {
        assert_eq!(uri_prefix(0xFF), "");
    }

    #[test]
    fn ndef_uri_prefix_tel() {
        assert_eq!(uri_prefix(0x05), "tel:");
    }

    #[test]
    fn ndef_uri_prefix_mailto() {
        assert_eq!(uri_prefix(0x06), "mailto:");
    }

    #[test]
    fn ndef_mime_record() {
        let rec = NdefRecord::mime("text/plain", b"test data");
        assert_eq!(rec.tnf, Tnf::MimeMedia);
        assert_eq!(rec.record_type, b"text/plain");
        assert_eq!(rec.payload, b"test data");
    }

    #[test]
    fn ndef_smart_poster() {
        let uri = NdefRecord::uri(0x04, "example.com");
        let title = NdefRecord::text("Example");
        let sp = NdefRecord::smart_poster(&[uri, title]);
        assert_eq!(sp.tnf, Tnf::WellKnown);
        assert_eq!(sp.record_type, b"Sp");
    }

    #[test]
    fn ndef_record_encode_single() {
        let rec = NdefRecord::text("Hi");
        let bytes = rec.encode(true, true);
        // flags: MB|ME|SR|TNF=1 => 0x80|0x40|0x10|0x01 = 0xD1
        assert_eq!(bytes[0], 0xD1);
        assert_eq!(bytes[1], 1); // type length
    }

    #[test]
    fn ndef_record_parse_roundtrip() {
        let rec = NdefRecord::text("Roundtrip");
        let bytes = rec.encode(true, true);
        let (parsed, consumed) = NdefRecord::parse(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed.payload, rec.payload);
    }

    #[test]
    fn ndef_record_with_id() {
        let rec = NdefRecord::new(
            Tnf::WellKnown,
            vec![b'T'],
            vec![0x01],
            vec![0x02, b'e', b'n', b'X'],
        );
        let bytes = rec.encode(true, true);
        assert!(bytes[0] & FLAG_IL != 0);
        let (parsed, _) = NdefRecord::parse(&bytes).unwrap();
        assert_eq!(parsed.id, vec![0x01]);
    }

    #[test]
    fn ndef_record_long_payload() {
        let payload = vec![0x42; 300];
        let rec = NdefRecord::new(Tnf::Unknown, Vec::new(), Vec::new(), payload.clone());
        let bytes = rec.encode(true, true);
        assert!(bytes[0] & FLAG_SR == 0); // not short record
        let (parsed, _) = NdefRecord::parse(&bytes).unwrap();
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn ndef_text_content_invalid() {
        let rec = NdefRecord::uri(0x00, "test");
        assert!(rec.text_content().is_err());
    }

    #[test]
    fn ndef_uri_content_invalid() {
        let rec = NdefRecord::text("test");
        assert!(rec.uri_content().is_err());
    }

    #[test]
    fn ndef_text_empty_payload() {
        let rec = NdefRecord::new(Tnf::WellKnown, vec![b'T'], Vec::new(), Vec::new());
        assert!(rec.text_content().is_err());
    }

    #[test]
    fn ndef_parse_empty_data() {
        assert!(NdefRecord::parse(&[]).is_err());
    }

    #[test]
    fn ndef_parse_truncated_type_len() {
        assert!(NdefRecord::parse(&[0xD1]).is_err());
    }

    // === NDEF Message tests ===

    #[test]
    fn ndef_message_single_record() {
        let msg = NdefMessage::new(vec![NdefRecord::text("Test")]);
        let bytes = msg.encode();
        let parsed = NdefMessage::parse(&bytes).unwrap();
        assert_eq!(parsed.records.len(), 1);
    }

    #[test]
    fn ndef_message_multiple_records() {
        let msg = NdefMessage::new(vec![
            NdefRecord::text("One"),
            NdefRecord::uri(0x04, "example.com"),
            NdefRecord::text("Three"),
        ]);
        let bytes = msg.encode();
        let parsed = NdefMessage::parse(&bytes).unwrap();
        assert_eq!(parsed.records.len(), 3);
    }

    #[test]
    fn ndef_message_to_tlv() {
        let msg = NdefMessage::new(vec![NdefRecord::text("TLV")]);
        let tlv_bytes = msg.to_tlv();
        assert_eq!(tlv_bytes[0], TLV_NDEF_MESSAGE);
        assert_eq!(*tlv_bytes.last().unwrap(), TLV_TERMINATOR);
    }

    #[test]
    fn ndef_message_parse_empty() {
        assert!(NdefMessage::parse(&[]).is_err());
    }

    #[test]
    fn ndef_message_roundtrip() {
        let original = NdefMessage::new(vec![
            NdefRecord::text("Hello"),
            NdefRecord::uri(0x01, "example.com"),
        ]);
        let bytes = original.encode();
        let parsed = NdefMessage::parse(&bytes).unwrap();
        assert_eq!(parsed.records.len(), 2);
        assert_eq!(parsed.records[0].text_content().unwrap(), "Hello");
        assert_eq!(
            parsed.records[1].uri_content().unwrap(),
            "http://www.example.com"
        );
    }

    #[test]
    fn ndef_smart_poster_roundtrip() {
        let inner_uri = NdefRecord::uri(0x04, "rust-lang.org");
        let inner_text = NdefRecord::text("Rust");
        let sp = NdefRecord::smart_poster(&[inner_uri, inner_text]);
        let msg = NdefMessage::new(vec![sp]);
        let bytes = msg.encode();
        let parsed = NdefMessage::parse(&bytes).unwrap();
        assert_eq!(parsed.records.len(), 1);
        assert_eq!(parsed.records[0].record_type, b"Sp");
        // Parse inner message
        let inner = NdefMessage::parse(&parsed.records[0].payload).unwrap();
        assert_eq!(inner.records.len(), 2);
    }

    // === TNF tests ===

    #[test]
    fn tnf_from_byte_all() {
        assert_eq!(Tnf::from_byte(0x00), Tnf::Empty);
        assert_eq!(Tnf::from_byte(0x01), Tnf::WellKnown);
        assert_eq!(Tnf::from_byte(0x02), Tnf::MimeMedia);
        assert_eq!(Tnf::from_byte(0x03), Tnf::AbsoluteUri);
        assert_eq!(Tnf::from_byte(0x04), Tnf::External);
        assert_eq!(Tnf::from_byte(0x05), Tnf::Unknown);
        assert_eq!(Tnf::from_byte(0x06), Tnf::Unchanged);
        assert_eq!(Tnf::from_byte(0x07), Tnf::Reserved);
    }

    #[test]
    fn tnf_from_byte_masked() {
        // Only bottom 3 bits matter
        assert_eq!(Tnf::from_byte(0xF1), Tnf::WellKnown);
        assert_eq!(Tnf::from_byte(0x88), Tnf::Empty);
    }

    // === APDU tests ===

    #[test]
    fn apdu_select() {
        let cmd = ApduCommand::select(NDEF_TAG_APPLICATION_AID);
        assert_eq!(cmd.ins, INS_SELECT);
        assert_eq!(cmd.p1, 0x04);
        assert_eq!(cmd.data, NDEF_TAG_APPLICATION_AID);
    }

    #[test]
    fn apdu_read_binary() {
        let cmd = ApduCommand::read_binary(0x0000, 0x0F);
        assert_eq!(cmd.ins, INS_READ_BINARY);
        assert_eq!(cmd.p1, 0x00);
        assert_eq!(cmd.p2, 0x00);
        assert_eq!(cmd.le, Some(0x0F));
    }

    #[test]
    fn apdu_update_binary() {
        let cmd = ApduCommand::update_binary(0x0004, &[0xAA, 0xBB]);
        assert_eq!(cmd.ins, INS_UPDATE_BINARY);
        assert_eq!(cmd.p1, 0x00);
        assert_eq!(cmd.p2, 0x04);
        assert_eq!(cmd.data, vec![0xAA, 0xBB]);
    }

    #[test]
    fn apdu_read_binary_offset() {
        let cmd = ApduCommand::read_binary(0x0102, 16);
        assert_eq!(cmd.p1, 0x01);
        assert_eq!(cmd.p2, 0x02);
    }

    #[test]
    fn apdu_encode_header_only() {
        let cmd = ApduCommand::new(0x00, 0xA4, 0x04, 0x00);
        let bytes = cmd.encode();
        assert_eq!(bytes, &[0x00, 0xA4, 0x04, 0x00]);
    }

    #[test]
    fn apdu_encode_with_data() {
        let cmd = ApduCommand::new(0x00, 0xA4, 0x04, 0x00).with_data(vec![0x01, 0x02]);
        let bytes = cmd.encode();
        assert_eq!(bytes, &[0x00, 0xA4, 0x04, 0x00, 0x02, 0x01, 0x02]);
    }

    #[test]
    fn apdu_encode_with_le() {
        let cmd = ApduCommand::new(0x00, 0xB0, 0x00, 0x00).with_le(0x10);
        let bytes = cmd.encode();
        assert_eq!(bytes, &[0x00, 0xB0, 0x00, 0x00, 0x10]);
    }

    #[test]
    fn apdu_encode_with_data_and_le() {
        let cmd = ApduCommand::new(0x00, 0xA4, 0x04, 0x00)
            .with_data(vec![0xAA])
            .with_le(0x00);
        let bytes = cmd.encode();
        assert_eq!(bytes, &[0x00, 0xA4, 0x04, 0x00, 0x01, 0xAA, 0x00]);
    }

    #[test]
    fn apdu_parse_header_only() {
        let cmd = ApduCommand::parse(&[0x00, 0xA4, 0x04, 0x00]).unwrap();
        assert_eq!(cmd.cla, 0x00);
        assert_eq!(cmd.ins, 0xA4);
        assert!(cmd.data.is_empty());
        assert!(cmd.le.is_none());
    }

    #[test]
    fn apdu_parse_le_only() {
        let cmd = ApduCommand::parse(&[0x00, 0xB0, 0x00, 0x00, 0x10]).unwrap();
        assert_eq!(cmd.le, Some(0x10));
        assert!(cmd.data.is_empty());
    }

    #[test]
    fn apdu_parse_with_data() {
        let cmd = ApduCommand::parse(&[0x00, 0xA4, 0x04, 0x00, 0x02, 0xAA, 0xBB]).unwrap();
        assert_eq!(cmd.data, vec![0xAA, 0xBB]);
    }

    #[test]
    fn apdu_parse_data_and_le() {
        let cmd = ApduCommand::parse(&[0x00, 0xA4, 0x04, 0x00, 0x01, 0xAA, 0x10]).unwrap();
        assert_eq!(cmd.data, vec![0xAA]);
        assert_eq!(cmd.le, Some(0x10));
    }

    #[test]
    fn apdu_parse_too_short() {
        assert!(ApduCommand::parse(&[0x00, 0xA4]).is_err());
    }

    #[test]
    fn apdu_parse_lc_overflow() {
        assert!(ApduCommand::parse(&[0x00, 0xA4, 0x00, 0x00, 0x05, 0x01]).is_err());
    }

    #[test]
    fn apdu_roundtrip() {
        let original = ApduCommand::select(&[0xD2, 0x76]);
        let bytes = original.encode();
        let parsed = ApduCommand::parse(&bytes).unwrap();
        assert_eq!(parsed.ins, original.ins);
        assert_eq!(parsed.data, original.data);
    }

    // === APDU Response tests ===

    #[test]
    fn apdu_response_success() {
        let resp = ApduResponse::success(vec![0x01, 0x02]);
        assert!(resp.is_ok());
        assert_eq!(resp.status_word(), 0x9000);
    }

    #[test]
    fn apdu_response_error() {
        let resp = ApduResponse::error(0x6A, 0x82);
        assert!(!resp.is_ok());
        assert_eq!(resp.status_word(), 0x6A82);
    }

    #[test]
    fn apdu_response_encode() {
        let resp = ApduResponse::success(vec![0xAA]);
        let bytes = resp.encode();
        assert_eq!(bytes, &[0xAA, 0x90, 0x00]);
    }

    #[test]
    fn apdu_response_parse() {
        let resp = ApduResponse::parse(&[0xAA, 0xBB, 0x90, 0x00]).unwrap();
        assert_eq!(resp.data, vec![0xAA, 0xBB]);
        assert!(resp.is_ok());
    }

    #[test]
    fn apdu_response_parse_sw_only() {
        let resp = ApduResponse::parse(&[0x90, 0x00]).unwrap();
        assert!(resp.data.is_empty());
        assert!(resp.is_ok());
    }

    #[test]
    fn apdu_response_parse_too_short() {
        assert!(ApduResponse::parse(&[0x90]).is_err());
    }

    // === Tag tests ===

    #[test]
    fn tag_type1_create() {
        let uid = Uid::new(&[1, 2, 3, 4]).unwrap();
        let tag = Tag::new(TagType::Type1, uid, 120);
        assert_eq!(tag.tag_type, TagType::Type1);
        assert_eq!(tag.capacity(), 120);
        assert!(!tag.is_read_only());
    }

    #[test]
    fn tag_read_write() {
        let uid = Uid::new(&[1, 2, 3, 4]).unwrap();
        let mut tag = Tag::new(TagType::Type2, uid, 64);
        tag.write(0, &[0xAA, 0xBB]).unwrap();
        assert_eq!(tag.read(0, 2).unwrap(), &[0xAA, 0xBB]);
    }

    #[test]
    fn tag_read_out_of_range() {
        let uid = Uid::new(&[1, 2, 3, 4]).unwrap();
        let tag = Tag::new(TagType::Type1, uid, 16);
        assert!(tag.read(15, 4).is_err());
    }

    #[test]
    fn tag_write_out_of_range() {
        let uid = Uid::new(&[1, 2, 3, 4]).unwrap();
        let mut tag = Tag::new(TagType::Type1, uid, 16);
        assert!(tag.write(15, &[1, 2, 3]).is_err());
    }

    #[test]
    fn tag_read_only() {
        let uid = Uid::new(&[1, 2, 3, 4]).unwrap();
        let mut tag = Tag::new(TagType::Type2, uid, 64);
        tag.set_read_only();
        assert!(tag.is_read_only());
        assert!(tag.write(0, &[0xFF]).is_err());
    }

    #[test]
    fn tag_write_read_ndef_type1() {
        let uid = Uid::new(&[1, 2, 3, 4]).unwrap();
        let mut tag = Tag::new(TagType::Type1, uid, 256);
        let msg = NdefMessage::new(vec![NdefRecord::text("Tag1")]);
        tag.write_ndef(&msg).unwrap();
        let read = tag.read_ndef().unwrap();
        assert_eq!(read.records[0].text_content().unwrap(), "Tag1");
    }

    #[test]
    fn tag_write_read_ndef_type2() {
        let uid = Uid::new(&[1, 2, 3, 4]).unwrap();
        let mut tag = Tag::new(TagType::Type2, uid, 256);
        let msg = NdefMessage::new(vec![NdefRecord::uri(0x04, "rust-lang.org")]);
        tag.write_ndef(&msg).unwrap();
        let read = tag.read_ndef().unwrap();
        assert_eq!(
            read.records[0].uri_content().unwrap(),
            "https://rust-lang.org"
        );
    }

    #[test]
    fn tag_write_read_ndef_type3() {
        let uid = Uid::new(&[1, 2, 3, 4]).unwrap();
        let mut tag = Tag::new(TagType::Type3, uid, 256);
        let msg = NdefMessage::new(vec![NdefRecord::text("Tag3")]);
        tag.write_ndef(&msg).unwrap();
        let read = tag.read_ndef().unwrap();
        assert_eq!(read.records[0].text_content().unwrap(), "Tag3");
    }

    #[test]
    fn tag_write_read_ndef_type4() {
        let uid = Uid::new(&[1, 2, 3, 4]).unwrap();
        let mut tag = Tag::new(TagType::Type4, uid, 256);
        let msg = NdefMessage::new(vec![NdefRecord::text("Tag4")]);
        tag.write_ndef(&msg).unwrap();
        let read = tag.read_ndef().unwrap();
        assert_eq!(read.records[0].text_content().unwrap(), "Tag4");
    }

    #[test]
    fn tag_ndef_too_large() {
        let uid = Uid::new(&[1, 2, 3, 4]).unwrap();
        let mut tag = Tag::new(TagType::Type2, uid, 20);
        let msg = NdefMessage::new(vec![NdefRecord::text(
            "This is way too long for a tiny tag",
        )]);
        assert!(tag.write_ndef(&msg).is_err());
    }

    #[test]
    fn tag_no_ndef() {
        let uid = Uid::new(&[1, 2, 3, 4]).unwrap();
        let tag = Tag::new(TagType::Type2, uid, 256);
        assert!(tag.read_ndef().is_err());
    }

    // === Anti-collision tests ===

    #[test]
    fn anticollision_default() {
        let ac = AntiCollision::new();
        assert_eq!(ac.cascade_level(), CascadeLevel::Level1);
    }

    #[test]
    fn anticollision_cmd_level1() {
        let ac = AntiCollision::new();
        let cmd = ac.build_anticollision_cmd();
        assert_eq!(cmd[0], 0x93);
        assert_eq!(cmd[1], 0x20);
    }

    #[test]
    fn anticollision_advance() {
        let mut ac = AntiCollision::new();
        ac.advance();
        assert_eq!(ac.cascade_level(), CascadeLevel::Level2);
        let cmd = ac.build_anticollision_cmd();
        assert_eq!(cmd[0], 0x95);
    }

    #[test]
    fn anticollision_advance_to_level3() {
        let mut ac = AntiCollision::new();
        ac.advance();
        ac.advance();
        assert_eq!(ac.cascade_level(), CascadeLevel::Level3);
        assert_eq!(ac.cascade_level().sel_byte(), 0x97);
    }

    #[test]
    fn anticollision_advance_beyond_level3() {
        let mut ac = AntiCollision::new();
        ac.advance();
        ac.advance();
        ac.advance();
        assert_eq!(ac.cascade_level(), CascadeLevel::Level3);
    }

    #[test]
    fn anticollision_set_partial() {
        let mut ac = AntiCollision::new();
        ac.set_partial(2, &[0xAA, 0xBB]);
        let cmd = ac.build_anticollision_cmd();
        assert_eq!(cmd[1], 0x22); // 0x20 + 2
        assert_eq!(&cmd[2..], &[0xAA, 0xBB]);
    }

    #[test]
    fn anticollision_select_cmd() {
        let ac = AntiCollision::new();
        let cmd = ac.build_select_cmd(&[0x01, 0x02, 0x03, 0x04], 0x04);
        assert_eq!(cmd[0], 0x93);
        assert_eq!(cmd[1], 0x70);
        assert_eq!(&cmd[2..6], &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(cmd[6], 0x04);
    }

    #[test]
    fn resolve_uid_4byte() {
        let uid = AntiCollision::resolve_uid(&[0x01, 0x02, 0x03, 0x04], None, None).unwrap();
        assert_eq!(uid.len(), 4);
        assert_eq!(uid.as_bytes(), &[0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn resolve_uid_7byte() {
        let uid = AntiCollision::resolve_uid(
            &[CASCADE_TAG, 0x01, 0x02, 0x03],
            Some(&[0x04, 0x05, 0x06, 0x07]),
            None,
        )
        .unwrap();
        assert_eq!(uid.len(), 7);
        assert_eq!(uid.as_bytes(), &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
    }

    #[test]
    fn resolve_uid_10byte() {
        let uid = AntiCollision::resolve_uid(
            &[CASCADE_TAG, 0x01, 0x02, 0x03],
            Some(&[CASCADE_TAG, 0x04, 0x05, 0x06]),
            Some(&[0x07, 0x08, 0x09, 0x0A]),
        )
        .unwrap();
        assert_eq!(uid.len(), 10);
    }

    #[test]
    fn resolve_uid_bad_cl1() {
        assert!(AntiCollision::resolve_uid(&[0x01, 0x02], None, None).is_err());
    }

    #[test]
    fn resolve_uid_cl3_without_cl2() {
        assert!(
            AntiCollision::resolve_uid(&[0x01, 0x02, 0x03, 0x04], None, Some(&[1, 2, 3, 4]))
                .is_err()
        );
    }

    #[test]
    fn resolve_uid_bad_cl2_len() {
        assert!(AntiCollision::resolve_uid(&[CASCADE_TAG, 1, 2, 3], Some(&[1, 2]), None).is_err());
    }

    #[test]
    fn cascade_tag_value() {
        assert_eq!(CASCADE_TAG, 0x88);
    }

    // === Card Emulation tests ===

    #[test]
    fn card_emu_select_aid() {
        let msg = NdefMessage::new(vec![NdefRecord::text("Card")]);
        let mut emu = CardEmulator::new(&msg);
        let cmd = ApduCommand::select(NDEF_TAG_APPLICATION_AID);
        let resp = emu.process(&cmd);
        assert!(resp.is_ok());
    }

    #[test]
    fn card_emu_select_wrong_aid() {
        let msg = NdefMessage::new(vec![NdefRecord::text("Card")]);
        let mut emu = CardEmulator::new(&msg);
        let cmd = ApduCommand::select(&[0x00, 0x01]);
        let resp = emu.process(&cmd);
        assert!(!resp.is_ok());
        assert_eq!(resp.status_word(), 0x6A82);
    }

    #[test]
    fn card_emu_select_cc_file() {
        let msg = NdefMessage::new(vec![NdefRecord::text("CC")]);
        let mut emu = CardEmulator::new(&msg);
        // Select app first
        let _ = emu.process(&ApduCommand::select(NDEF_TAG_APPLICATION_AID));
        // Select CC file
        let cmd = ApduCommand::new(0x00, INS_SELECT, 0x00, 0x00).with_data(vec![0xE1, 0x03]);
        let resp = emu.process(&cmd);
        assert!(resp.is_ok());
    }

    #[test]
    fn card_emu_select_ndef_file() {
        let msg = NdefMessage::new(vec![NdefRecord::text("NDEF")]);
        let mut emu = CardEmulator::new(&msg);
        let _ = emu.process(&ApduCommand::select(NDEF_TAG_APPLICATION_AID));
        let cmd = ApduCommand::new(0x00, INS_SELECT, 0x00, 0x00).with_data(vec![0xE1, 0x04]);
        let resp = emu.process(&cmd);
        assert!(resp.is_ok());
    }

    #[test]
    fn card_emu_select_file_without_app() {
        let msg = NdefMessage::new(vec![NdefRecord::text("X")]);
        let mut emu = CardEmulator::new(&msg);
        let cmd = ApduCommand::new(0x00, INS_SELECT, 0x00, 0x00).with_data(vec![0xE1, 0x03]);
        let resp = emu.process(&cmd);
        assert!(!resp.is_ok());
    }

    #[test]
    fn card_emu_read_cc() {
        let msg = NdefMessage::new(vec![NdefRecord::text("R")]);
        let mut emu = CardEmulator::new(&msg);
        let _ = emu.process(&ApduCommand::select(NDEF_TAG_APPLICATION_AID));
        let _ = emu
            .process(&ApduCommand::new(0x00, INS_SELECT, 0x00, 0x00).with_data(vec![0xE1, 0x03]));
        let read_cmd = ApduCommand::read_binary(0, 15);
        let resp = emu.process(&read_cmd);
        assert!(resp.is_ok());
        assert_eq!(resp.data.len(), 15);
        assert_eq!(resp.data[2], 0x20); // mapping version
    }

    #[test]
    fn card_emu_read_ndef() {
        let msg = NdefMessage::new(vec![NdefRecord::text("ReadMe")]);
        let mut emu = CardEmulator::new(&msg);
        let _ = emu.process(&ApduCommand::select(NDEF_TAG_APPLICATION_AID));
        let _ = emu
            .process(&ApduCommand::new(0x00, INS_SELECT, 0x00, 0x00).with_data(vec![0xE1, 0x04]));
        // Read the first 2 bytes (NDEF length)
        let read_cmd = ApduCommand::read_binary(0, 2);
        let resp = emu.process(&read_cmd);
        assert!(resp.is_ok());
        assert_eq!(resp.data.len(), 2);
    }

    #[test]
    fn card_emu_read_no_file_selected() {
        let msg = NdefMessage::new(vec![NdefRecord::text("X")]);
        let mut emu = CardEmulator::new(&msg);
        let _ = emu.process(&ApduCommand::select(NDEF_TAG_APPLICATION_AID));
        let resp = emu.process(&ApduCommand::read_binary(0, 4));
        assert!(!resp.is_ok());
    }

    #[test]
    fn card_emu_update_ndef() {
        let msg = NdefMessage::new(vec![NdefRecord::text("Old")]);
        let mut emu = CardEmulator::new(&msg);
        let _ = emu.process(&ApduCommand::select(NDEF_TAG_APPLICATION_AID));
        let _ = emu
            .process(&ApduCommand::new(0x00, INS_SELECT, 0x00, 0x00).with_data(vec![0xE1, 0x04]));
        let new_msg = NdefMessage::new(vec![NdefRecord::text("New")]);
        let new_bytes = new_msg.encode();
        #[allow(clippy::cast_possible_truncation)]
        let len_prefix = vec![(new_bytes.len() >> 8) as u8, new_bytes.len() as u8];
        let update_len = ApduCommand::update_binary(0, &len_prefix);
        let resp = emu.process(&update_len);
        assert!(resp.is_ok());
        let update_data = ApduCommand::update_binary(2, &new_bytes);
        let resp = emu.process(&update_data);
        assert!(resp.is_ok());
        let read_msg = emu.ndef_message().unwrap();
        assert_eq!(read_msg.records[0].text_content().unwrap(), "New");
    }

    #[test]
    fn card_emu_update_cc_denied() {
        let msg = NdefMessage::new(vec![NdefRecord::text("X")]);
        let mut emu = CardEmulator::new(&msg);
        let _ = emu.process(&ApduCommand::select(NDEF_TAG_APPLICATION_AID));
        let _ = emu
            .process(&ApduCommand::new(0x00, INS_SELECT, 0x00, 0x00).with_data(vec![0xE1, 0x03]));
        let resp = emu.process(&ApduCommand::update_binary(0, &[0xFF]));
        assert!(!resp.is_ok());
    }

    #[test]
    fn card_emu_unsupported_ins() {
        let msg = NdefMessage::new(vec![NdefRecord::text("X")]);
        let mut emu = CardEmulator::new(&msg);
        let cmd = ApduCommand::new(0x00, 0xFF, 0x00, 0x00);
        let resp = emu.process(&cmd);
        assert_eq!(resp.status_word(), 0x6D00);
    }

    #[test]
    fn card_emu_ndef_message_getter() {
        let msg = NdefMessage::new(vec![NdefRecord::uri(0x04, "nfc.example.com")]);
        let emu = CardEmulator::new(&msg);
        let retrieved = emu.ndef_message().unwrap();
        assert_eq!(
            retrieved.records[0].uri_content().unwrap(),
            "https://nfc.example.com"
        );
    }

    #[test]
    fn card_emu_bad_select_p1() {
        let msg = NdefMessage::new(vec![NdefRecord::text("X")]);
        let mut emu = CardEmulator::new(&msg);
        let cmd = ApduCommand::new(0x00, INS_SELECT, 0x08, 0x00);
        let resp = emu.process(&cmd);
        assert!(!resp.is_ok());
    }

    #[test]
    fn card_emu_select_invalid_file_id() {
        let msg = NdefMessage::new(vec![NdefRecord::text("X")]);
        let mut emu = CardEmulator::new(&msg);
        let _ = emu.process(&ApduCommand::select(NDEF_TAG_APPLICATION_AID));
        let cmd = ApduCommand::new(0x00, INS_SELECT, 0x00, 0x00).with_data(vec![0xFF, 0xFF]);
        let resp = emu.process(&cmd);
        assert_eq!(resp.status_word(), 0x6A82);
    }

    #[test]
    fn card_emu_read_past_end() {
        let msg = NdefMessage::new(vec![NdefRecord::text("X")]);
        let mut emu = CardEmulator::new(&msg);
        let _ = emu.process(&ApduCommand::select(NDEF_TAG_APPLICATION_AID));
        let _ = emu
            .process(&ApduCommand::new(0x00, INS_SELECT, 0x00, 0x00).with_data(vec![0xE1, 0x03]));
        let read_cmd = ApduCommand::read_binary(0xFF00, 1);
        let resp = emu.process(&read_cmd);
        assert!(!resp.is_ok());
    }

    // === Error Display tests ===

    #[test]
    fn error_display() {
        let e = NfcError::InvalidPayload("bad");
        assert_eq!(format!("{e}"), "bad");
        let e2 = NfcError::BufferTooSmall;
        assert_eq!(format!("{e2}"), "buffer too small");
    }

    #[test]
    fn error_display_all_variants() {
        assert!(!format!("{}", NfcError::InvalidNdef("x")).is_empty());
        assert!(!format!("{}", NfcError::InvalidTlv("x")).is_empty());
        assert!(!format!("{}", NfcError::InvalidApdu("x")).is_empty());
        assert!(!format!("{}", NfcError::TagError("x")).is_empty());
        assert!(!format!("{}", NfcError::CollisionError("x")).is_empty());
    }

    // === URI prefix coverage ===

    #[test]
    fn uri_prefixes_selected() {
        assert_eq!(uri_prefix(0x01), "http://www.");
        assert_eq!(uri_prefix(0x02), "https://www.");
        assert_eq!(uri_prefix(0x09), "ftps://");
        assert_eq!(uri_prefix(0x0A), "sftp://");
        assert_eq!(uri_prefix(0x0D), "ftp://");
        assert_eq!(uri_prefix(0x13), "urn:");
        assert_eq!(uri_prefix(0x1D), "file://");
        assert_eq!(uri_prefix(0x23), "urn:nfc:");
    }

    // === Additional edge-case tests ===

    #[test]
    fn ndef_message_encode_decode_five_records() {
        let records: Vec<NdefRecord> = (0..5)
            .map(|i| NdefRecord::text(&format!("Rec{i}")))
            .collect();
        let msg = NdefMessage::new(records);
        let bytes = msg.encode();
        let parsed = NdefMessage::parse(&bytes).unwrap();
        assert_eq!(parsed.records.len(), 5);
        for (i, rec) in parsed.records.iter().enumerate() {
            assert_eq!(rec.text_content().unwrap(), format!("Rec{i}"));
        }
    }

    #[test]
    fn tag_type2_multiple_writes() {
        let uid = Uid::new(&[0xAA, 0xBB, 0xCC, 0xDD]).unwrap();
        let mut tag = Tag::new(TagType::Type2, uid, 512);
        let msg1 = NdefMessage::new(vec![NdefRecord::text("First")]);
        tag.write_ndef(&msg1).unwrap();
        let msg2 = NdefMessage::new(vec![NdefRecord::text("Second")]);
        tag.write_ndef(&msg2).unwrap();
        let read = tag.read_ndef().unwrap();
        assert_eq!(read.records[0].text_content().unwrap(), "Second");
    }

    #[test]
    fn uid_clone_eq() {
        let uid1 = Uid::new(&[1, 2, 3, 4]).unwrap();
        let uid2 = uid1.clone();
        assert_eq!(uid1, uid2);
    }

    #[test]
    fn anticollision_default_trait() {
        let ac = AntiCollision::default();
        assert_eq!(ac.cascade_level(), CascadeLevel::Level1);
    }
}
