//! TROPIC01 secure element driver for patina_key.
//!
//! A `no_std`, no-heap, panic-free Rust driver for the TROPIC01 secure
//! element over SPI. The crate is internally layered (L1 transport, L2 framing,
//! L3 encrypted commands, the Noise session). Transport and crypto detail stay
//! `pub(crate)`. The public surface is the device handle, the type-state
//! markers, the `SeWait`/`SeCommands` ports, the command value types, and the
//! error enums.
//!
//! The crate opens a Noise KK1 secure channel (verified against a libtropic
//! golden KAT) and runs encrypted L3 commands over it: crypto adapters, the
//! L1 poll/read, chunked L2 transport, L3 AES-GCM seal/open, and the session
//! teardown gate that wipes keys on any crypto fault.

#![cfg_attr(not(test), no_std)]

mod buf;
mod crc;
mod crypto;
mod device;
mod error;
mod handshake;
mod ids;
mod l1;
mod l2;
mod l3;
mod nonce;
mod parse;
mod port;
mod session;
mod wait;

#[cfg(test)]
mod test_support;

// Curated public surface. Nothing else is exported.
pub use crate::device::ActiveSession;
pub use crate::device::Bootloader;
pub use crate::device::NoSession;
pub use crate::device::SessionConfig;
pub use crate::device::Tropic01;
pub use crate::error::HandshakeError;
pub use crate::error::L1Error;
pub use crate::error::L2Error;
pub use crate::error::L3Error;
pub use crate::error::ParseError;
pub use crate::error::SeError;
pub use crate::ids::L2Status;
pub use crate::ids::L3Status;
pub use crate::ids::UnknownId;
pub use crate::port::EccCurve;
pub use crate::port::EccSlot;
pub use crate::port::MCounterIdx;
pub use crate::port::MacAndDestroyOutput;
pub use crate::port::MacDestroySlot;
pub use crate::port::RMemSlot;
pub use crate::port::SeCommands;
pub use crate::port::Signature;
pub use crate::wait::SeWait;

/// Fuzzing seam. Exposes the attacker-facing parsers to libFuzzer harnesses.
///
/// Gated behind the `_fuzz` feature so the normal public API stays minimal. The
/// entry points must never panic on any input. Not part of the supported API.
#[cfg(feature = "_fuzz")]
pub mod fuzz
{
    /// Drives the L2 response parser over arbitrary bytes. Must never panic.
    pub fn parse_l2_response(data: &[u8])
    {
        let _ = crate::l2::frame::parse_response(data);
    }

    /// Drives the L3 result opener over arbitrary bytes. Must never panic.
    ///
    /// Builds a `SessionKeys` from fixed fuzz keys, copies `data` into an
    /// L3-sized buffer, and tries to open it as a sealed result. The fixed
    /// keys make the tag check fail on almost every input, so the target is the
    /// length/bounds handling in front of the decrypt.
    pub fn decrypt_l3_result(data: &[u8])
    {
        let mut keys = crate::session::SessionKeys::new([0xA5u8; 32], [0x5Au8; 32]);
        let mut l3 = [0u8; crate::buf::L3_FRAME_MAX];
        let n = data.len().min(crate::buf::L3_FRAME_MAX);
        l3[..n].copy_from_slice(&data[..n]);
        let _ = keys.open_result(&mut l3, n);
    }

    /// Drives the Handshake_Resp body parser over arbitrary bytes. Must never
    /// panic.
    pub fn parse_handshake_resp(data: &[u8])
    {
        let _ = crate::device::parse_handshake_resp(data);
    }
}
