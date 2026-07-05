//! apdu.

use crate::errors::NfcError;

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
