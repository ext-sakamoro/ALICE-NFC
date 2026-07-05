//! ndef.

use crate::errors::NfcError;
use crate::tlv::{Tlv, TLV_NDEF_MESSAGE, TLV_TERMINATOR};

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
    pub(crate) const fn from_byte(b: u8) -> Self {
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
pub const FLAG_SR: u8 = 0x10;
pub const FLAG_IL: u8 = 0x08;

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
