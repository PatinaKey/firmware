//! TROPIC01 secure element driver for patina_key.
//!
//! A `no_std`, no-heap, panic-free Rust driver for the TROPIC01 secure
//! element over SPI. The crate is internally layered (L1 transport, L2 framing,
//! L3 encrypted commands, the Noise session); transport and crypto detail stay
//! `pub(crate)`. The public surface is the device handle, the type-state
//! markers, the `SeWait`/`SeCommands` ports, the command value types, and the
//! error enums.
//!
//! Increment 1 implements the foundation: error model, protocol ids, the
//! bounds-checked parser, the L2 CRC16, the no-heap buffers, the L2 frame
//! build/parse, the non-wrapping nonce counter, and the trait/type-state
//! definitions. Crypto, the handshake, and the L3 command bodies arrive later.

#![cfg_attr(not(test), no_std)]
// Increment 1 is the foundation: the L1/L3/handshake/command layers that
// consume these `pub(crate)` building blocks land in later increments, so the
// non-test build cannot yet reach all of them. Each item here is unit-tested,
// and a caller wires it in as the higher layers arrive. TIGHTEN THIS: remove
// the allow once L1/L3/commands exist, and let dead-code analysis catch any
// unused scaffolding.
#![cfg_attr(not(test), allow(dead_code))]

mod buf;
mod crc;
mod device;
mod error;
mod ids;
mod l2;
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
    /// Drive the L2 response parser over arbitrary bytes. Must never panic.
    pub fn parse_l2_response(data: &[u8])
    {
        let _ = crate::l2::frame::parse_response(data);
    }
}
