//! ALICE-NFC: NFC protocol stack (NDEF/APDU/Anti-collision/Card Emulation).

#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(
    clippy::module_name_repetitions,
    clippy::doc_markdown,
    clippy::wildcard_imports,
    clippy::too_many_lines,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::similar_names,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::return_self_not_must_use,
    clippy::unreadable_literal
)]

pub mod anticollision;
pub mod apdu;
pub mod card_emulation;
pub mod errors;
pub mod ndef;
pub mod prelude;
pub mod tag_types;
pub mod tlv;
pub mod uid;

#[cfg(test)]
mod integration_tests;

// Backward-compat re-exports.
pub use crate::anticollision::*;
pub use crate::apdu::*;
pub use crate::card_emulation::*;
pub use crate::errors::*;
pub use crate::ndef::*;
pub use crate::tag_types::*;
pub use crate::tlv::*;
pub use crate::uid::*;
