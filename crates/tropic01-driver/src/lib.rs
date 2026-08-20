//! TROPIC01 secure element driver.
//!
//! Unofficial `no_std`, no-heap, panic-free Rust driver for the TROPIC01 secure
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
//! The user-facing feature is `attestation` (ON by default): it enables X.509
//! chain verification and pulls the ECDSA curve crates (`ecdsa`, `p384`,
//! `p521`). Disable the feature via `default-features = false` to drop them when
//! only STPUB extraction is needed. The other two features are development-only
//! and a consumer leaves them off. `_fuzz` exposes the attacker-facing parsers to
//! the libFuzzer harnesses. `model-itest` compiles the live integration tests
//! that run against the official TROPIC01 emulator.
//!
//! # Error-path latency
//!
//! Every L2 exchange runs through a CRC-retry seam. A CRC fault buys up to 3
//! extra round-trips, and each round-trip owns a full chip-response poll budget
//! of 50 polls spaced 25 ms apart. One exchange is therefore bounded by
//! `(1 + 3) * 50 * 25 = 5000 ms`, against 1250 ms for a single budget. That
//! 4-budget shape is the chip answering just before each budget expires. A chip
//! that goes silent after one corrupt frame is cheaper, 2 budgets and 2500 ms,
//! because the first unanswered budget ends the retry loop. Both shapes are
//! reachable, so 5000 ms is the number to size against. The success path is
//! untouched: one request, one read.
//!
//! That bound is PER EXCHANGE, not per call. A call built from N L2 exchanges
//! multiplies it. Reading the X.509 store is 30 `Get_Info` blocks. A firmware
//! image is relayed as one `Mutable_FW_Update` plus one `Mutable_FW_Update_Data`
//! per chunk, so its worst case grows linearly with the image size. An
//! integrator sizing a transport deadline, a USB stack for instance, sizes it on
//! the number of exchanges the call makes, not on the call.
//!
//! # Example
//!
//! Open a secure channel and run one L3 command. The chip wiring (the SPI bus
//! and the ready/timeout provider) is supplied by the integrator, here it is
//! stubbed. All keys come from the caller via [`SessionConfig`].
//!
//! ```no_run
//! # use embedded_hal::spi::{ErrorType, Operation, SpiDevice};
//! # use core::convert::Infallible;
//! # struct Spi;
//! # impl ErrorType for Spi { type Error = Infallible; }
//! # impl SpiDevice for Spi {
//! #     fn transaction(&mut self, _ops: &mut [Operation<'_, u8>]) -> Result<(), Infallible> { Ok(()) }
//! # }
//! # struct Wait;
//! # impl tropic01_driver::SeWait for Wait {
//! #     type Error = Infallible;
//! #     fn wait_ready(&mut self, _ms: u32) -> Result<(), Infallible> { Ok(()) }
//! #     fn delay_ms(&mut self, _ms: u32) -> Result<(), Infallible> { Ok(()) }
//! # }
//! use tropic01_driver::{SeCommands, SessionConfig, StartupId, Tropic01};
//! use zeroize::Zeroizing;
//!
//! fn run() -> Result<(), tropic01_driver::SeError>
//! {
//!     let mut dev = Tropic01::new(Spi, Wait);
//!     // Load the Application firmware: the secure channel lives there.
//!     dev.reboot(StartupId::Reboot)?;
//!
//!     // All key material is caller-provided. The driver hardcodes no secrets.
//!     // These zeros are PLACEHOLDERS: real ephemerals come from a TRNG, the
//!     // pairing keys from provisioning, and `stpub` from the chip certificate.
//!     // For a genuine-chip trust decision, obtain `stpub` via
//!     // `read_verified_chip_stpub` against a `RootAnchor` pinned out-of-band,
//!     // not the unverified `read_chip_stpub`.
//!     let ehpriv = Zeroizing::new([0u8; 32]);
//!     let shipriv = Zeroizing::new([0u8; 32]);
//!     let shipub = [0u8; 32];
//!     let stpub = [0u8; 32];
//!     let cfg = SessionConfig
//!     {
//!         ehpriv: &ehpriv,
//!         shipriv: &shipriv,
//!         shipub: &shipub,
//!         stpub: &stpub,
//!         pkey_index: 0,
//!     };
//!     // open_session consumes the handle and reports the error as a tuple, so
//!     // recover the SeError with map_err before using `?`.
//!     let mut session = dev.open_session(cfg).map_err(|(_dev, e)| e)?;
//!
//!     // Run one encrypted L3 command, then tear the channel down.
//!     let mut random = [0u8; 32];
//!     session.random_into(&mut random)?;
//!     let _dev = session.close_session();
//!     Ok(())
//! }
//! ```

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
#[cfg(feature = "attestation")]
pub use crate::cert::parse_verified_stpub;
#[cfg(feature = "attestation")]
pub use crate::cert::verify_cert_chain;
#[cfg(feature = "attestation")]
pub use crate::cert::RootAnchor;
pub use crate::device::ActiveSession;
pub use crate::device::Bootloader;
pub use crate::device::ChipMode;
pub use crate::device::FwBankId;
pub use crate::device::FwImageChunks;
pub use crate::device::NoSession;
pub use crate::device::SessionConfig;
pub use crate::device::StartupId;
pub use crate::device::Tropic01;
pub use crate::error::CertError;
#[cfg(feature = "attestation")]
pub use crate::error::ChainError;
pub use crate::error::FwImageError;
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

    /// Drives the firmware-image blob decoder over arbitrary bytes. Must never
    /// panic.
    ///
    /// The update blob is attacker-influenced. `FwImageChunks::new` then a full
    /// drain of the iterator exercises every length-prefix bound: a constructor
    /// reject, a clean chunk walk, and the fuse-on-truncation path. It then
    /// drives `image_version` on the same bytes, exercising the chunk-0 version
    /// extraction (the const-offset `take` + `take_le_u32` reads). Both share the
    /// blob as their attacker surface. Any panic is a finding.
    pub fn fw_image_chunks(data: &[u8])
    {
        if let Ok(chunks) = crate::device::FwImageChunks::new(data)
        {
            for chunk in chunks
            {
                let _ = chunk;
            }
        }
        let _ = crate::device::image_version(data);
    }

    /// Drives the certificate-chain verifier over arbitrary bytes with a fixed
    /// pinned anchor. Must never panic. The anchor's exact value is irrelevant:
    /// fuzzing targets the bounded DER parsing in front of the crypto, which
    /// fails closed on essentially every mutated input.
    #[cfg(feature = "attestation")]
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
