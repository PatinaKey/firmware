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
///
/// The private field encodes the valid range. `new` rejects an out-of-range
/// value with `InvalidArgument`, so no command can send a bad slot to the chip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EccSlot(u8);

impl EccSlot
{
    /// Builds a slot index, rejecting any value above 31.
    ///
    /// Errors with `InvalidArgument` outside 0..=31.
    pub const fn new(value: u8) -> Result<Self, SeError>
    {
        if value > 31
        {
            return Err(SeError::InvalidArgument);
        }
        Ok(EccSlot(value))
    }

    /// Returns the wire index.
    // The ECC commands that send this index are not wired yet, so the accessor
    // is dead in the non-test build. The newtype tests use it, which fulfils an
    // `#[expect]` in the test build and would fire `unfulfilled_lint_expectations`
    // there, so `#[allow]` is required (same pattern as `ids::ObjectId`).
    #[allow(dead_code)]
    pub(crate) const fn get(self) -> u8
    {
        self.0
    }
}

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
///
/// The private field encodes the valid range. `new` rejects an out-of-range
/// value with `InvalidArgument`, so no command can send a bad slot to the chip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RMemSlot(u16);

impl RMemSlot
{
    /// Builds a slot index, rejecting any value above 511.
    ///
    /// Errors with `InvalidArgument` outside 0..=511.
    pub const fn new(value: u16) -> Result<Self, SeError>
    {
        if value > 511
        {
            return Err(SeError::InvalidArgument);
        }
        Ok(RMemSlot(value))
    }

    /// Returns the wire index.
    // The R-Memory commands that send this index are not wired yet (dead in the
    // non-test build). The newtype tests use it, so `#[allow]` is required (same
    // pattern as `ids::ObjectId`).
    #[allow(dead_code)]
    pub(crate) const fn get(self) -> u16
    {
        self.0
    }
}

/// A monotonic counter index (0..=15).
///
/// The private field encodes the valid range. `new` rejects an out-of-range
/// value with `InvalidArgument`, so no command can send a bad index to the chip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MCounterIdx(u8);

impl MCounterIdx
{
    /// Builds a counter index, rejecting any value above 15.
    ///
    /// Errors with `InvalidArgument` outside 0..=15.
    pub const fn new(value: u8) -> Result<Self, SeError>
    {
        if value > 15
        {
            return Err(SeError::InvalidArgument);
        }
        Ok(MCounterIdx(value))
    }

    /// Returns the wire index.
    // `mcounter_get`'s only caller is the not-yet-wired `SeCommands` impl, so
    // this accessor is dead in the non-test build. The tests use it, so
    // `#[allow]` is required (same pattern as `ids::ObjectId`).
    #[allow(dead_code)]
    pub(crate) const fn get(self) -> u8
    {
        self.0
    }
}

/// A MAC-and-Destroy PIN-attempt slot index (0..=127).
///
/// The private field encodes the valid range. `new` rejects an out-of-range
/// value with `InvalidArgument`, so no command can send a bad slot to the chip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacDestroySlot(u8);

impl MacDestroySlot
{
    /// Builds a slot index, rejecting any value above 127.
    ///
    /// Errors with `InvalidArgument` outside 0..=127.
    pub const fn new(value: u8) -> Result<Self, SeError>
    {
        if value > 127
        {
            return Err(SeError::InvalidArgument);
        }
        Ok(MacDestroySlot(value))
    }

    /// Returns the wire index.
    // The MAC-and-Destroy command that sends this index is not wired yet (dead
    // in the non-test build). The newtype tests use it, so `#[allow]` is
    // required (same pattern as `ids::ObjectId`).
    #[allow(dead_code)]
    pub(crate) const fn get(self) -> u8
    {
        self.0
    }
}

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
    /// Returns the number of bytes written, which equals `out.len()`. An empty
    /// `out` returns `Ok(0)` with no chip traffic. Rejects `out.len() > 255`
    /// with `InvalidArgument` (chunking is a caller concern). Errors on a
    /// session fault.
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
    /// Returns the current 32-bit value. A disabled counter surfaces as a
    /// recoverable `L3Error::Result(CounterInvalid)` that keeps the session
    /// live. The index range (0..=15) is enforced by `MCounterIdx::new`.
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

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn ecc_slot_accepts_max_and_rejects_one_past()
    {
        assert_eq!(EccSlot::new(31).map(|s| s.get()), Ok(31));
        assert_eq!(EccSlot::new(32), Err(SeError::InvalidArgument));
    }

    #[test]
    fn rmem_slot_accepts_max_and_rejects_one_past()
    {
        assert_eq!(RMemSlot::new(511).map(|s| s.get()), Ok(511));
        assert_eq!(RMemSlot::new(512), Err(SeError::InvalidArgument));
    }

    #[test]
    fn mcounter_idx_accepts_max_and_rejects_one_past()
    {
        assert_eq!(MCounterIdx::new(15).map(|s| s.get()), Ok(15));
        assert_eq!(MCounterIdx::new(16), Err(SeError::InvalidArgument));
    }

    #[test]
    fn mac_destroy_slot_accepts_max_and_rejects_one_past()
    {
        assert_eq!(MacDestroySlot::new(127).map(|s| s.get()), Ok(127));
        assert_eq!(MacDestroySlot::new(128), Err(SeError::InvalidArgument));
    }
}
