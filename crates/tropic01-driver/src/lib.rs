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
//!
//! # Crate features
//!
//! There is no user-facing feature. Both Cargo features are development-only and
//! a consumer leaves them off. `_fuzz` exposes the attacker-facing parsers to
//! the libFuzzer harnesses. `model-itest` compiles the live integration tests
//! that run against the official TROPIC01 emulator.

#![cfg_attr(not(test), no_std)]

mod buf;
mod cert;
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
pub use crate::cert::parse_stpub;
pub use crate::cert::parse_verified_stpub;
pub use crate::cert::verify_cert_chain;
pub use crate::cert::RootAnchor;
pub use crate::device::ActiveSession;
pub use crate::device::Bootloader;
pub use crate::device::ChipMode;
pub use crate::device::FwBankId;
pub use crate::device::NoSession;
pub use crate::device::SessionConfig;
pub use crate::device::StartupId;
pub use crate::device::Tropic01;
pub use crate::error::CertError;
pub use crate::error::ChainError;
pub use crate::error::HandshakeError;
pub use crate::error::L1Error;
pub use crate::error::L2Error;
pub use crate::error::L3Error;
pub use crate::error::ParseError;
pub use crate::error::SeError;
pub use crate::ids::L2Status;
pub use crate::ids::L3Status;
pub use crate::ids::UnknownId;
pub use crate::port::ConfigBitIndex;
pub use crate::port::ConfigObjectAddr;
pub use crate::port::EccCurve;
pub use crate::port::EccSlot;
pub use crate::port::MCounterIdx;
pub use crate::port::MacAndDestroyOutput;
pub use crate::port::MacDestroySlot;
pub use crate::port::PairingKeySlot;
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

    /// Drives the certificate-store STPUB parser over arbitrary bytes. Must
    /// never panic.
    pub fn parse_stpub(data: &[u8])
    {
        let _ = crate::cert::parse_stpub(data);
    }

    /// Drives the certificate-chain verifier over arbitrary bytes with a fixed
    /// pinned anchor. Must never panic. The anchor's exact value is irrelevant:
    /// fuzzing targets the bounded DER parsing in front of the crypto, which
    /// fails closed on essentially every mutated input.
    pub fn verify_cert_chain(data: &[u8])
    {
        // A fixed, REAL P-521 SEC1 point (0x04 || X(66) || Y(66)). The anchor now
        // validates the point at construction, so a real on-curve point is used.
        // Its exact value is irrelevant to the fuzz target, which exercises the
        // bounded DER parsing in front of the crypto. This is the model TEST root.
        const FUZZ_ANCHOR_POINT: [u8; 133] = [
            0x04, 0x01, 0x35, 0xc7, 0xa2, 0x4d, 0x16, 0xb3, 0x74, 0xb2, 0x07, 0xad,
            0xe8, 0xfe, 0x50, 0xf5, 0x03, 0xad, 0x34, 0xe0, 0xe5, 0x96, 0xc8, 0x3f,
            0xc9, 0x8a, 0xdb, 0x4c, 0x43, 0x88, 0xca, 0x0a, 0xd9, 0xb2, 0x4e, 0x77,
            0xe9, 0x84, 0xb8, 0x97, 0x82, 0x53, 0xa8, 0xe0, 0xd6, 0xfd, 0x68, 0xea,
            0xa8, 0xd9, 0xc9, 0xa9, 0xa6, 0xc8, 0x83, 0x5a, 0x13, 0x8c, 0xcc, 0xff,
            0x51, 0x13, 0x0d, 0xa1, 0x09, 0x86, 0x80, 0x00, 0xcd, 0xf7, 0xfa, 0xd5,
            0xa0, 0x2b, 0xbd, 0x84, 0x45, 0x3c, 0x56, 0x36, 0xf2, 0x5f, 0x1c, 0x39,
            0x5b, 0xdc, 0x22, 0xee, 0x7b, 0x44, 0x1a, 0x81, 0xb5, 0x9f, 0x20, 0x40,
            0x53, 0x89, 0xf4, 0x7d, 0x65, 0xf0, 0x74, 0xa6, 0x02, 0xf9, 0x33, 0x2d,
            0xf1, 0x33, 0x79, 0xf2, 0x7d, 0x65, 0x4f, 0x4e, 0x1b, 0x0f, 0xd4, 0x56,
            0xc1, 0xa9, 0x9f, 0x54, 0x36, 0x64, 0x0f, 0x7e, 0xe0, 0x4e, 0x1b, 0x48,
            0x81,
        ];
        if let Ok(anchor) = crate::cert::RootAnchor::from_sec1_p521(&FUZZ_ANCHOR_POINT)
        {
            let _ = crate::cert::verify_cert_chain(data, &anchor);
        }
    }
}
