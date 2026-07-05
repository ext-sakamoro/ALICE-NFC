//! card emulation.

use crate::apdu::{ApduCommand, ApduResponse};
use crate::errors::NfcError;
use crate::ndef::NdefMessage;

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
            crate::apdu::INS_SELECT => self.handle_select(cmd),
            crate::apdu::INS_READ_BINARY => self.handle_read(cmd),
            crate::apdu::INS_UPDATE_BINARY => self.handle_update(cmd),
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
