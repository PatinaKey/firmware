//! The `SeCommands` driving port and its value types.
//!
//! This is the only SE surface that CTAP2 / OpenPGP / PKCS#11 layers consume.
//! No SPI, no session handle, and no transport error leak through it. A method
//! returns a known-size output by value (`Copy`). A variable-size output uses
//! the `_into(out: &mut [u8]) -> Result<usize, SeError>` convention.
//!
//! `Tropic01<SPI, W, ActiveSession>` implements this trait.

use zeroize::ZeroizeOnDrop;
use zeroize::Zeroizing;

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

impl EccCurve
{
    /// Returns the chip CURVE wire byte (P-256 = 0x01, Ed25519 = 0x02).
    ///
    /// Source: libtropic `lt_ecc_curve_type_t` (`L3_ECC_KEY_GENERATE`).
    pub(crate) const fn wire_byte(self) -> u8
    {
        match self
        {
            EccCurve::P256 => 0x01,
            EccCurve::Ed25519 => 0x02,
        }
    }

    /// Returns the raw public-key length in bytes for this curve.
    ///
    /// P-256 returns 64 (raw X || Y, no 0x04 prefix). Ed25519 returns 32.
    pub(crate) const fn pubkey_len(self) -> usize
    {
        match self
        {
            EccCurve::P256 => 64,
            EccCurve::Ed25519 => 32,
        }
    }

    /// Maps a chip CURVE wire byte back to a curve.
    ///
    /// Returns `None` for any byte other than 0x01 (P-256) or 0x02 (Ed25519).
    pub(crate) const fn from_wire_byte(byte: u8) -> Option<Self>
    {
        match byte
        {
            0x01 => Some(EccCurve::P256),
            0x02 => Some(EccCurve::Ed25519),
            _ => None,
        }
    }
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
    pub(crate) const fn get(self) -> u8
    {
        self.0
    }
}

/// A pairing key slot index (0..=3).
///
/// The private field encodes the valid range. `new` rejects an out-of-range
/// value with `InvalidArgument`, so no command can send a bad slot to the chip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairingKeySlot(u8);

impl PairingKeySlot
{
    /// Builds a slot index, rejecting any value above 3.
    ///
    /// Errors with `InvalidArgument` outside 0..=3.
    pub const fn new(value: u8) -> Result<Self, SeError>
    {
        if value > 3
        {
            return Err(SeError::InvalidArgument);
        }
        Ok(PairingKeySlot(value))
    }

    /// Returns the wire index.
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
    pub(crate) const fn get(self) -> u8
    {
        self.0
    }
}

/// A named TROPIC01 configuration object (CO) register.
///
/// Each variant is one CO address the R-Config / I-Config commands target. The
/// type is the whitelist: an out-of-range or unnamed address cannot be
/// constructed, so it can never reach the wire (the role libtropic's runtime
/// `conf_addr_valid` plays, enforced here BY THE TYPE). `wire_addr` yields the
/// u16 address sent in the command. Addresses match libtropic
/// `tropic01_bootloader_co.h` / `tropic01_application_co.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigObjectAddr
{
    // Bootloader / Application configuration.
    /// Start-up behaviour.
    CfgStartUp,
    /// Tamper sensor configuration.
    CfgSensors,
    /// Debug-interface configuration.
    CfgDebug,
    /// General-purpose output configuration.
    CfgGpo,
    /// Sleep-mode configuration.
    CfgSleepMode,

    // UAP (user access privileges): which pairing keys may run each command.
    /// UAP for PairingKeyWrite.
    CfgUapPairingKeyWrite,
    /// UAP for PairingKeyRead.
    CfgUapPairingKeyRead,
    /// UAP for PairingKeyInvalidate.
    CfgUapPairingKeyInvalidate,
    /// UAP for both R-Config write AND erase (one register gates both).
    CfgUapRConfigWriteErase,
    /// UAP for R-Config read.
    CfgUapRConfigRead,
    /// UAP for I-Config write (the irreversible bit-burn command).
    CfgUapIConfigWrite,
    /// UAP for I-Config read.
    CfgUapIConfigRead,

    // UAP for the functional L3 commands.
    /// UAP for Ping.
    CfgUapPing,
    /// UAP for R-Memory data write.
    CfgUapRMemDataWrite,
    /// UAP for R-Memory data read.
    CfgUapRMemDataRead,
    /// UAP for R-Memory data erase.
    CfgUapRMemDataErase,
    /// UAP for RandomValueGet.
    CfgUapRandomValueGet,
    /// UAP for EccKeyGenerate.
    CfgUapEccKeyGenerate,
    /// UAP for EccKeyStore.
    CfgUapEccKeyStore,
    /// UAP for EccKeyRead.
    CfgUapEccKeyRead,
    /// UAP for EccKeyErase.
    CfgUapEccKeyErase,
    /// UAP for EcdsaSign.
    CfgUapEcdsaSign,
    /// UAP for EddsaSign.
    CfgUapEddsaSign,
    /// UAP for McounterInit.
    CfgUapMcounterInit,
    /// UAP for McounterGet.
    CfgUapMcounterGet,
    /// UAP for McounterUpdate.
    CfgUapMcounterUpdate,
    /// UAP for MacAndDestroy (the PIN primitive).
    CfgUapMacAndDestroy,
}

impl ConfigObjectAddr
{
    /// Returns the u16 CO address sent on the wire.
    ///
    /// Source: libtropic `tropic01_bootloader_co.h` /
    /// `tropic01_application_co.h`.
    pub(crate) const fn wire_addr(self) -> u16
    {
        match self
        {
            ConfigObjectAddr::CfgStartUp => 0x0000,
            ConfigObjectAddr::CfgSensors => 0x0008,
            ConfigObjectAddr::CfgDebug => 0x0010,
            ConfigObjectAddr::CfgGpo => 0x0014,
            ConfigObjectAddr::CfgSleepMode => 0x0018,
            ConfigObjectAddr::CfgUapPairingKeyWrite => 0x0020,
            ConfigObjectAddr::CfgUapPairingKeyRead => 0x0024,
            ConfigObjectAddr::CfgUapPairingKeyInvalidate => 0x0028,
            ConfigObjectAddr::CfgUapRConfigWriteErase => 0x0030,
            ConfigObjectAddr::CfgUapRConfigRead => 0x0034,
            ConfigObjectAddr::CfgUapIConfigWrite => 0x0040,
            ConfigObjectAddr::CfgUapIConfigRead => 0x0044,
            ConfigObjectAddr::CfgUapPing => 0x0100,
            ConfigObjectAddr::CfgUapRMemDataWrite => 0x0110,
            ConfigObjectAddr::CfgUapRMemDataRead => 0x0114,
            ConfigObjectAddr::CfgUapRMemDataErase => 0x0118,
            ConfigObjectAddr::CfgUapRandomValueGet => 0x0120,
            ConfigObjectAddr::CfgUapEccKeyGenerate => 0x0130,
            ConfigObjectAddr::CfgUapEccKeyStore => 0x0134,
            ConfigObjectAddr::CfgUapEccKeyRead => 0x0138,
            ConfigObjectAddr::CfgUapEccKeyErase => 0x013C,
            ConfigObjectAddr::CfgUapEcdsaSign => 0x0140,
            ConfigObjectAddr::CfgUapEddsaSign => 0x0144,
            ConfigObjectAddr::CfgUapMcounterInit => 0x0150,
            ConfigObjectAddr::CfgUapMcounterGet => 0x0154,
            ConfigObjectAddr::CfgUapMcounterUpdate => 0x0158,
            ConfigObjectAddr::CfgUapMacAndDestroy => 0x0160,
        }
    }
}

/// An I-Config bit index (0..=31).
///
/// The private field encodes the valid range. `new` rejects an out-of-range
/// value with `InvalidArgument`, so no command can send a bad bit index to the
/// chip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigBitIndex(u8);

impl ConfigBitIndex
{
    /// Builds a bit index, rejecting any value above 31.
    ///
    /// Errors with `InvalidArgument` outside 0..=31.
    pub const fn new(value: u8) -> Result<Self, SeError>
    {
        if value > 31
        {
            return Err(SeError::InvalidArgument);
        }
        Ok(ConfigBitIndex(value))
    }

    /// Returns the wire bit index.
    pub(crate) const fn get(self) -> u8
    {
        self.0
    }
}

/// A 64-byte ECC signature (R = 32 B, S = 32 B).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature(pub [u8; 64]);

/// An ECC public key returned by the chip, carrying its curve.
///
/// The private fields tie the byte count to the curve: a key holds 64 raw
/// bytes, of which the curve picks the meaningful prefix (32 for Ed25519, 64
/// for P-256). Only the driver builds one, so the curve/length invariant holds
/// by construction. A public key is not secret, so `Copy` is fine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EccPublicKey
{
    curve: EccCurve,
    bytes: [u8; 64],
}

impl EccPublicKey
{
    /// Builds a public key from a curve and its raw 64-byte backing store.
    ///
    /// `pub(crate)`: only the driver, having validated the curve and length,
    /// constructs one. The caller copies the key bytes into `bytes` and leaves
    /// the tail zero for a 32-byte curve.
    pub(crate) const fn new(curve: EccCurve, bytes: [u8; 64]) -> Self
    {
        EccPublicKey
        {
            curve,
            bytes,
        }
    }

    /// Returns the curve this key belongs to.
    pub const fn curve(&self) -> EccCurve
    {
        self.curve
    }

    /// Returns the raw key bytes, trimmed to the curve length.
    ///
    /// A P-256 key exposes 64 bytes (raw X || Y), an Ed25519 key 32 bytes. The
    /// zero tail stays hidden.
    pub fn bytes(&self) -> &[u8]
    {
        &self.bytes[..self.curve.pubkey_len()]
    }
}

/// The 32-byte MAC-and-Destroy output, a secret.
///
/// The chip derives this from the pre-overwrite slot value, and it feeds the
/// PIN key-derivation step. The byte field stays private and the type carries
/// no `Debug`/`Clone`/`Copy`, so it cannot leak or duplicate. `ZeroizeOnDrop`
/// wipes the bytes when the value falls out of scope. The caller reads them
/// once via `expose`, derives, then drops.
#[derive(ZeroizeOnDrop)]
pub struct MacAndDestroyOutput
{
    bytes: [u8; 32],
}

impl MacAndDestroyOutput
{
    /// Wraps the 32 output bytes.
    ///
    /// `pub(crate)`: only the driver, having parsed the result, builds one.
    pub(crate) const fn new(bytes: [u8; 32]) -> Self
    {
        MacAndDestroyOutput
        {
            bytes,
        }
    }

    /// Borrows the secret output bytes.
    ///
    /// The caller must consume them immediately into a derivation step. The
    /// borrow keeps the secret tied to the owning value's lifetime, so it is
    /// wiped on drop. Zeroization covers only this value: any copy the caller
    /// makes of the exposed bytes is the caller's own to wipe.
    pub fn expose(&self) -> &[u8; 32]
    {
        &self.bytes
    }
}

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

    /// Reads the public key for `slot`.
    ///
    /// Returns the key by value, carrying its curve. Errors with `SeError` on a
    /// session fault.
    fn ecc_public_key
    (
        &mut self,
        slot: EccSlot,
    )
    -> Result<EccPublicKey, SeError>;

    /// Imports an external private key into ECC `slot` for `curve`.
    ///
    /// `private_key` is the raw 32-byte scalar (P-256 private integer or Ed25519
    /// seed). It is sent inside the AES-GCM-encrypted channel and the L3
    /// plaintext is zeroized after use. The slot range (0..=31) is enforced by
    /// `EccSlot::new`. A non-OK RESULT (SlotNotEmpty, InvalidKey, Unauthorized,
    /// Fail, HardwareFail) keeps the session live and surfaces as a recoverable
    /// `SeError`.
    ///
    /// SECURITY: an imported key is non-attestable (indistinguishable on-chip
    /// from a chip-generated one). FIDO2 credentials must use chip-generated
    /// keys. Confine import to the OpenPGP / PKCS#11 / imported-SSH path.
    fn ecc_key_store
    (
        &mut self,
        slot: EccSlot,
        curve: EccCurve,
        private_key: &Zeroizing<[u8; 32]>,
    )
    -> Result<(), SeError>;

    /// Erases ECC `slot`, removing any stored key.
    ///
    /// The slot range (0..=31) is enforced by `EccSlot::new`. Erasing an empty
    /// slot surfaces a recoverable non-OK RESULT (SlotEmpty) and keeps the
    /// session live.
    fn ecc_key_erase
    (
        &mut self,
        slot: EccSlot,
    )
    -> Result<(), SeError>;

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
    /// Returns the number of bytes written. 0 means empty: a stored slot is
    /// never zero-length (write enforces a 1-byte minimum). Errors with
    /// `BufferTooSmall` when `out` is too short.
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
    /// Returns the secret 32-byte output derived from the pre-overwrite slot
    /// value, wrapped so it zeroizes on drop. A non-OK RESULT keeps the session
    /// live and surfaces as a recoverable `SeError`.
    fn mac_and_destroy
    (
        &mut self,
        slot: MacDestroySlot,
        input: &[u8; 32],
    )
    -> Result<MacAndDestroyOutput, SeError>;

    /// Erases R-Memory `slot`, clearing it for a fresh write.
    ///
    /// A write requires an empty slot, so a rewrite is erase-then-write. The
    /// slot range (0..=511) is enforced by `RMemSlot::new`. A non-OK RESULT
    /// keeps the session live and surfaces as a recoverable `SeError`.
    fn rmem_erase
    (
        &mut self,
        slot: RMemSlot,
    )
    -> Result<(), SeError>;

    /// Initializes monotonic counter `idx` to `value`.
    ///
    /// The anti-clone counters must be initialized before a decrement. The index
    /// range (0..=15) is enforced by `MCounterIdx::new`, any 32-bit `value` is
    /// accepted. A non-OK RESULT keeps the session live.
    ///
    /// PROVISIONING ONLY. Init can re-set a counter to a higher value and defeat
    /// the anti-rollback guarantee, so the caller must invoke it only during
    /// provisioning, never in normal operation. The driver enforces no policy.
    fn mcounter_init
    (
        &mut self,
        idx: MCounterIdx,
        value: u32,
    )
    -> Result<(), SeError>;

    /// Decrements monotonic counter `idx` by one.
    ///
    /// The decrement is fixed at one. A counter already at zero surfaces as a
    /// recoverable `L3Error::Result(UpdateErr)`, and an uninitialized or locked
    /// counter as `L3Error::Result(CounterInvalid)`, both keep the session live.
    /// The index range (0..=15) is enforced by `MCounterIdx::new`.
    fn mcounter_update
    (
        &mut self,
        idx: MCounterIdx,
    )
    -> Result<(), SeError>;

    /// Writes the host pairing public key `public_key` into pairing `slot`.
    ///
    /// Provisions one of the four pairing slots the handshake authenticates
    /// against (`SessionConfig.shipub` / `pkey_index` select the slot chip-side).
    /// `public_key` is the 32-byte host static pairing PUBLIC key (`S_HiPub`),
    /// not a secret. The slot range (0..=3) is enforced by `PairingKeySlot::new`.
    /// A non-OK RESULT (HardwareFail on an OTP write error that permanently
    /// invalidates the slot, plus Unauthorized / Fail) keeps the session live and
    /// surfaces as a recoverable `SeError`.
    ///
    /// PROVISIONING ONLY. Overwriting the slot named by the session `pkey_index`
    /// (the active handshake key) can permanently prevent re-establishing a secure
    /// channel.
    fn pairing_key_write
    (
        &mut self,
        slot: PairingKeySlot,
        public_key: &[u8; 32],
    )
    -> Result<(), SeError>;

    /// Reads the host pairing public key stored in pairing `slot`.
    ///
    /// Returns the slot's 32-byte public pairing key (`S_HiPub`) by value. The
    /// slot range (0..=3) is enforced by `PairingKeySlot::new`. A non-OK RESULT
    /// (SlotEmpty on an unprovisioned slot, SlotInvalid on an invalidated one,
    /// plus Unauthorized / Fail) keeps the session live and surfaces as a
    /// recoverable `SeError`.
    fn pairing_key_read
    (
        &mut self,
        slot: PairingKeySlot,
    )
    -> Result<[u8; 32], SeError>;

    /// Invalidates pairing `slot`, blocking future handshakes against it.
    ///
    /// The slot range (0..=3) is enforced by `PairingKeySlot::new`. A non-OK
    /// RESULT (HardwareFail on an OTP write error, plus Unauthorized / Fail)
    /// keeps the session live and surfaces as a recoverable `SeError`.
    ///
    /// PROVISIONING ONLY. Invalidating the slot named by the session `pkey_index`
    /// (the active handshake key) can permanently prevent re-establishing a secure
    /// channel.
    fn pairing_key_invalidate
    (
        &mut self,
        slot: PairingKeySlot,
    )
    -> Result<(), SeError>;

    /// Writes the 32-bit `value` to R-Config object `addr`.
    ///
    /// R-Config is the reversible working copy of the chip configuration. A
    /// write here can be undone by an erase, unlike I-Config. A non-OK RESULT
    /// (Unauthorized, Fail, ...) keeps the session live and surfaces as a
    /// recoverable `SeError`.
    ///
    /// The final configuration the chip enforces is the bitwise AND of I-Config
    /// and R-Config, applied AFTER the next boot. `CfgUapRConfigWriteErase` gates
    /// both this write and `r_config_erase` (one UAP register for both).
    fn r_config_write
    (
        &mut self,
        addr: ConfigObjectAddr,
        value: u32,
    )
    -> Result<(), SeError>;

    /// Reads the 32-bit value of R-Config object `addr`.
    ///
    /// Returns the reversible working-copy value. A non-OK RESULT keeps the
    /// session live and surfaces as a recoverable `SeError`.
    fn r_config_read
    (
        &mut self,
        addr: ConfigObjectAddr,
    )
    -> Result<u32, SeError>;

    /// Erases the ENTIRE R-Config, setting every object back to all-ones.
    ///
    /// This is NOT a per-object erase: it wipes the WHOLE R-Config (all
    /// configuration objects to all-1s) in one command. A caller expecting to
    /// clear a single object will instead reset the entire reversible config.
    /// `CfgUapRConfigWriteErase` gates both this erase and `r_config_write`.
    fn r_config_erase
    (
        &mut self,
    )
    -> Result<(), SeError>;

    /// Burns a single bit of I-Config object `addr` from 1 to 0.
    ///
    /// SECURITY: I-Config is OTP / IRREVERSIBLE. A bit only flips 1 -> 0 and can
    /// NEVER be restored. There is NO I-Config erase. The chip enforces the
    /// bitwise AND of I-Config and R-Config AFTER the next boot. Burning all
    /// access bits of a `CfgUap*` object to 0 PERMANENTLY disables that command
    /// for every pairing key. The chip's response to re-writing an
    /// already-cleared bit is unspecified by the TROPIC01 documentation, so the
    /// caller must not rely on a particular status.
    ///
    /// PROVISIONING ONLY. The bit range (0..=31) is enforced by
    /// `ConfigBitIndex::new`. A non-OK RESULT keeps the session live and surfaces
    /// as a recoverable `SeError`, EXCEPT that a HardwareFail on an I-Config write
    /// is fatal on real silicon (the chip enters ALARM). The driver enforces no
    /// policy on when this runs.
    fn i_config_write
    (
        &mut self,
        addr: ConfigObjectAddr,
        bit: ConfigBitIndex,
    )
    -> Result<(), SeError>;

    /// Reads the 32-bit value of I-Config object `addr`.
    ///
    /// Returns the irreversible-config value. A non-OK RESULT keeps the session
    /// live and surfaces as a recoverable `SeError`.
    fn i_config_read
    (
        &mut self,
        addr: ConfigObjectAddr,
    )
    -> Result<u32, SeError>;
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

    #[test]
    fn pairing_key_slot_accepts_max_and_rejects_one_past()
    {
        assert_eq!(PairingKeySlot::new(3).map(|s| s.get()), Ok(3));
        assert_eq!(PairingKeySlot::new(4), Err(SeError::InvalidArgument));
    }

    #[test]
    fn ecc_curve_wire_bytes_match_libtropic()
    {
        assert_eq!(EccCurve::P256.wire_byte(), 0x01);
        assert_eq!(EccCurve::Ed25519.wire_byte(), 0x02);
    }

    #[test]
    fn ecc_curve_pubkey_lengths()
    {
        assert_eq!(EccCurve::P256.pubkey_len(), 64);
        assert_eq!(EccCurve::Ed25519.pubkey_len(), 32);
    }

    #[test]
    fn ecc_curve_wire_byte_round_trips_every_variant()
    {
        // Drift guard: every variant survives a wire_byte -> from_wire_byte trip.
        for c in [EccCurve::P256, EccCurve::Ed25519]
        {
            assert_eq!(EccCurve::from_wire_byte(c.wire_byte()), Some(c));
        }
    }

    #[test]
    fn ecc_curve_from_wire_byte_round_trips_and_rejects()
    {
        assert_eq!(EccCurve::from_wire_byte(0x01), Some(EccCurve::P256));
        assert_eq!(EccCurve::from_wire_byte(0x02), Some(EccCurve::Ed25519));
        assert_eq!(EccCurve::from_wire_byte(0x00), None);
        assert_eq!(EccCurve::from_wire_byte(0x03), None);
        assert_eq!(EccCurve::from_wire_byte(0xFF), None);
    }

    #[test]
    fn config_bit_index_accepts_max_and_rejects_one_past()
    {
        assert_eq!(ConfigBitIndex::new(31).map(|b| b.get()), Ok(31));
        assert_eq!(ConfigBitIndex::new(32), Err(SeError::InvalidArgument));
    }

    #[test]
    fn config_object_addr_wire_addrs_match_libtropic()
    {
        // Source: libtropic tropic01_bootloader_co.h / tropic01_application_co.h.
        assert_eq!(ConfigObjectAddr::CfgStartUp.wire_addr(), 0x0000);
        assert_eq!(ConfigObjectAddr::CfgSensors.wire_addr(), 0x0008);
        assert_eq!(ConfigObjectAddr::CfgDebug.wire_addr(), 0x0010);
        assert_eq!(ConfigObjectAddr::CfgGpo.wire_addr(), 0x0014);
        assert_eq!(ConfigObjectAddr::CfgSleepMode.wire_addr(), 0x0018);
        assert_eq!(ConfigObjectAddr::CfgUapPairingKeyWrite.wire_addr(), 0x0020);
        assert_eq!(ConfigObjectAddr::CfgUapRConfigWriteErase.wire_addr(), 0x0030);
        assert_eq!(ConfigObjectAddr::CfgUapIConfigWrite.wire_addr(), 0x0040);
        assert_eq!(ConfigObjectAddr::CfgUapIConfigRead.wire_addr(), 0x0044);
        assert_eq!(ConfigObjectAddr::CfgUapPing.wire_addr(), 0x0100);
        assert_eq!(ConfigObjectAddr::CfgUapEccKeyErase.wire_addr(), 0x013C);
        assert_eq!(ConfigObjectAddr::CfgUapMacAndDestroy.wire_addr(), 0x0160);
    }
}
