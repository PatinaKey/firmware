//! The `SeCommands` driving port and its value types.
//!
//! This is the only SE surface that CTAP2 / OpenPGP / PKCS#11 layers consume.
//! No SPI, no session handle, and no transport error leak through it. A method
//! returns a known-size output by value (`Copy`). A variable-size output uses
//! the `_into(out: &mut [u8]) -> Result<usize, SeError>` convention.
//!
//! `Tropic01<SPI, W, ActiveSession>` implements this trait.

use crate::error::SeError;

/// An ECC key slot index (0..=31).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EccSlot(pub u8);

/// The curve selected for an ECC slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EccCurve
{
    /// NIST P-256 (secp256r1), ECDSA.
    P256,
    /// Ed25519, EdDSA.
    Ed25519,
}

/// An R-Memory user-data slot index (0..=511).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RMemSlot(pub u16);

/// A monotonic counter index (0..=15).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MCounterIdx(pub u8);

/// A MAC-and-Destroy PIN-attempt slot index (0..=127).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacDestroySlot(pub u8);

/// A 64-byte ECC signature (R = 32 B, S = 32 B).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature(pub [u8; 64]);

/// The high-level secure-element command port.
///
/// Implemented by an active session handle. Every method returns `SeError` on
/// failure, keeping transport and crypto detail out of the upper layers.
pub trait SeCommands
{
    /// Generates an ECC key pair on the chip in `slot` for `curve`.
    ///
    /// The private key never leaves the chip. Errors on a busy/locked slot or
    /// a session fault.
    fn ecc_key_generate
    (
        &mut self,
        slot: EccSlot,
        curve: EccCurve,
    )
    -> Result<(), SeError>;

    /// Reads the public key for `slot` into `out`.
    ///
    /// Returns the number of bytes written. Errors with `BufferTooSmall` when
    /// `out` is too short, or `SeError` on a session fault.
    fn ecc_public_key_into
    (
        &mut self,
        slot: EccSlot,
        out: &mut [u8],
    )
    -> Result<usize, SeError>;

    /// Signs a 32-byte digest with the P-256 key in `slot` (ECDSA).
    ///
    /// Returns the 64-byte signature. The host must pre-hash with SHA-256.
    fn ecdsa_sign
    (
        &mut self,
        slot: EccSlot,
        digest: &[u8; 32],
    )
    -> Result<Signature, SeError>;

    /// Signs `message` with the Ed25519 key in `slot` (EdDSA).
    ///
    /// The chip hashes the message internally (RFC 8032). Returns the 64-byte
    /// signature.
    fn eddsa_sign
    (
        &mut self,
        slot: EccSlot,
        message: &[u8],
    )
    -> Result<Signature, SeError>;

    /// Fills `out` with TRNG bytes.
    ///
    /// Returns the number of bytes written. Errors on a session fault.
    fn random_into
    (
        &mut self,
        out: &mut [u8],
    )
    -> Result<usize, SeError>;

    /// Reads R-Memory `slot` into `out`.
    ///
    /// Returns the number of bytes written. Errors with `BufferTooSmall` when
    /// `out` is too short.
    fn rmem_read_into
    (
        &mut self,
        slot: RMemSlot,
        out: &mut [u8],
    )
    -> Result<usize, SeError>;

    /// Writes `data` to R-Memory `slot`.
    ///
    /// The slot must be erased first. Errors with `InvalidArgument` on an
    /// oversize payload.
    fn rmem_write
    (
        &mut self,
        slot: RMemSlot,
        data: &[u8],
    )
    -> Result<(), SeError>;

    /// Reads monotonic counter `idx`.
    ///
    /// Returns the current 32-bit value. Errors on a disabled counter.
    fn mcounter_get
    (
        &mut self,
        idx: MCounterIdx,
    )
    -> Result<u32, SeError>;

    /// Runs MAC-and-Destroy on `slot` with `input`.
    ///
    /// Returns the 32-byte output derived from the pre-overwrite slot value.
    fn mac_and_destroy
    (
        &mut self,
        slot: MacDestroySlot,
        input: &[u8; 32],
    )
    -> Result<[u8; 32], SeError>;
}
