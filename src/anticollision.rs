//! anticollision.

use crate::errors::NfcError;
use crate::uid::Uid;

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
