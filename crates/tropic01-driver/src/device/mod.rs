//! The device handle and its type-state markers.
//!
//! `Tropic01<SPI, W, State>` owns the SPI port, the wait provider, and the
//! fixed L2/L3 buffers. The `State` type parameter encodes the session
//! lifecycle at compile time: L3 commands are reachable only on
//! `ActiveSession`, firmware update only on `Bootloader`.
//!
//! The handle is ~4.4 KiB and MUST live as a `static` singleton in the secure
//! binary, accessed by `&mut`. It must never sit on a call stack. A
//! size-regression test pins its footprint.
//!
//! This module holds the shared type definitions (the handle, its type-states,
//! and the command-layout constants). The behaviour is split across child
//! modules:
//!
//! - `nosession`: pre-session L2 ops (`reboot`, `Get_Info`, `sleep`,
//!   `chip_mode`, `get_log_into`) and `open_session`.
//! - `commands`: the `ActiveSession` lifecycle (`close_session`,
//!   `abort_session`), the `run` gate, and every L3 command.
//! - `se_commands`: the `SeCommands` trait impl that delegates to those commands.
//!
//! Child modules import the shared definitions here by name from `super`.

use crate::buf::L2Buf;
use crate::buf::L3Buf;
use crate::crypto;
use crate::error::L2Error;
use crate::parse::take_array;
use crate::session::SessionKeys;
use zeroize::Zeroizing;

mod commands;
mod nosession;
mod se_commands;

#[cfg(test)]
mod tests;

/// State marker: no secure channel is open. Plain-L2 ops are available.
#[derive(Debug, Clone, Copy)]
pub struct NoSession;

/// State marker: a secure channel is open. L3 commands are available.
///
/// Holds the session keys (zeroized on drop) and a `poisoned` flag. On a
/// session-fatal error the command path zeroizes the keys and sets `poisoned`,
/// so every subsequent L3 call fast-fails with `SessionLost` without touching
/// the chip. Carries no `Debug`/`Clone`/`Copy` because it holds secrets.
pub struct ActiveSession
{
    keys: SessionKeys,
    poisoned: bool,
}

impl ActiveSession
{
    /// Wraps derived session keys into the active state.
    ///
    /// `pub(crate)`: only the handshake builds this. Starts un-poisoned.
    pub(crate) fn new(keys: SessionKeys) -> Self
    {
        ActiveSession
        {
            keys,
            poisoned: false,
        }
    }

    /// Reports whether this session has been torn down.
    pub(crate) fn is_poisoned(&self) -> bool
    {
        self.poisoned
    }

    /// Marks the session fatal and zeroizes the keys.
    ///
    /// Idempotent. After this, the session can only be closed and replaced.
    pub(crate) fn poison(&mut self)
    {
        self.keys.wipe();
        self.poisoned = true;
    }
}

/// State marker: the chip is in bootloader (start-up) mode for firmware update.
#[derive(Debug, Clone, Copy)]
pub struct Bootloader;

/// Which mode the chip reboots into for a `Startup_Req`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupId
{
    /// Restart and initialize as after a power cycle (loads Application FW).
    Reboot,
    /// Restart but stay in Start-up (Maintenance) Mode. Do not load Application FW.
    MaintenanceReboot,
}

impl StartupId
{
    /// Returns the `Startup_Req` `startup_id` wire byte (0x01 / 0x03).
    ///
    /// Source: libtropic `lt_startup_id_t` (`TR01_REBOOT`,
    /// `TR01_MAINTENANCE_REBOOT`).
    const fn wire_byte(self) -> u8
    {
        match self
        {
            StartupId::Reboot => 0x01,
            StartupId::MaintenanceReboot => 0x03,
        }
    }
}

/// Which firmware bank a `Get_Info` FW_BANK read targets.
///
/// The `Get_Info_Req` BLOCK_INDEX selects the bank for object FW_BANK. The chip
/// holds two mutable application banks (FW1/FW2) and two SPECT banks
/// (SPECT1/SPECT2). FW_BANK is readable only in Start-up (Maintenance) Mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FwBankId
{
    /// First application firmware bank.
    Fw1,
    /// Second application firmware bank.
    Fw2,
    /// First SPECT firmware bank.
    Spect1,
    /// Second SPECT firmware bank.
    Spect2,
}

impl FwBankId
{
    /// Returns the `Get_Info_Req` BLOCK_INDEX wire byte for this bank.
    ///
    /// Source: libtropic `lt_bank_id_t` (`FW_BANK_FW1` 0x01, `FW_BANK_FW2` 0x02,
    /// `FW_BANK_SPECT1` 0x11, `FW_BANK_SPECT2` 0x12).
    const fn wire_byte(self) -> u8
    {
        match self
        {
            FwBankId::Fw1 => 0x01,
            FwBankId::Fw2 => 0x02,
            FwBankId::Spect1 => 0x11,
            FwBankId::Spect2 => 0x12,
        }
    }
}

/// The operating mode the chip reports through CHIP_STATUS.
///
/// Decoded from the raw CHIP_STATUS byte (the raw byte is never exposed). The
/// driver maps it like libtropic `lt_get_tr01_mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChipMode
{
    /// Application FW is running. L2 requests and L3 commands are available.
    Application,
    /// Start-up (Maintenance) Mode. Only Bootloader L2 requests are available.
    Startup,
    /// Alarm Mode. The chip rejects normal traffic until a power cycle or reset.
    /// This is a terminal state: do not retry, reset the chip.
    Alarm,
}

/// The TROPIC01 device handle.
///
/// Generic over the SPI device port and the wait provider, with a type-state
/// parameter for the session lifecycle. Owns the no-heap L2 and L3 buffers.
pub struct Tropic01<SPI, W, State = NoSession>
{
    spi: SPI,
    wait: W,
    l2: L2Buf,
    l3: L3Buf,
    state: State,
}

/// Parameters for opening a Noise KK1 secure channel.
///
/// All key material is borrowed. The config owns no secrets. `ehpriv` is the
/// host ephemeral private (fresh per session, from the platform TRNG). The
/// driver derives the matching public key and sends it in the handshake.
pub struct SessionConfig<'a>
{
    /// Host ephemeral X25519 private key (fresh per session).
    pub ehpriv: &'a Zeroizing<[u8; 32]>,
    /// Host static pairing private key.
    pub shipriv: &'a Zeroizing<[u8; 32]>,
    /// Host static pairing public key.
    pub shipub: &'a [u8; 32],
    /// Chip static public key (from the device certificate).
    pub stpub: &'a [u8; 32],
    /// Pairing key slot index (0..=3).
    pub pkey_index: u8,
}

/// Splits a Handshake_Resp body into `(ETPUB, T_TAUTH)`.
///
/// The body must be exactly 48 bytes: ETPUB(32) || T_TAUTH(16). libtropic
/// enforces the same exact length (`TR01_L2_HANDSHAKE_RSP_LEN`). Errors with
/// `ShortFrame` on a truncated body and `BadFrame` on trailing bytes.
pub(crate) fn parse_handshake_resp(data: &[u8]) -> Result<([u8; 32], [u8; 16]), L2Error>
{
    let (rest, etpub) = take_array::<32>(data).map_err(|_| L2Error::ShortFrame)?;
    let (tail, t_tauth) = take_array::<16>(rest).map_err(|_| L2Error::ShortFrame)?;
    if !tail.is_empty()
    {
        return Err(L2Error::BadFrame);
    }
    Ok((etpub, t_tauth))
}

/// `Get_Info` block size in bytes (the chip serves every object in 128-byte
/// blocks). Used for the cert-store loop and the CHIP_ID length check.
///
/// Source: libtropic `GET_INFO_BLOCK_LEN`.
const GET_INFO_BLOCK_LEN: usize = 128;

/// Number of 128-byte blocks in the X.509 certificate store.
///
/// Source: libtropic `LT_CERT_STORE_BLOCKS` (the cert store is 30 blocks).
const GET_INFO_CERT_STORE_BLOCKS: usize = 30;

/// Total X.509 certificate store length in bytes (30 * 128 = 3840).
///
/// Used for the up-front buffer check and the read-loop end bound. Derived from
/// the block count and block size, so the two can never drift apart.
const GET_INFO_CERT_STORE_LEN: usize = GET_INFO_CERT_STORE_BLOCKS * GET_INFO_BLOCK_LEN;

/// Maximum R-Memory user-data DATA length in bytes (target firmware >= 2.0.0).
///
/// Source: libtropic `R_MEM_DATA_SIZE_MAX`.
const R_MEM_DATA_MAX: usize = 475;

/// Maximum ECC public-key length in bytes (P-256, raw X || Y).
///
/// Ed25519 returns 32 bytes. `EccPublicKey` backs every key with this many
/// bytes and trims to the curve length on read.
const ECC_PUBKEY_MAX: usize = 64;

/// Padding bytes between the ORIGIN field and the PUBKEY in an EccKeyRead
/// result (CURVE(1) || ORIGIN(1) || PADDING(13) || PUBKEY).
///
/// Source: libtropic `struct lt_l3_ecc_key_read_res_t` (`padding[13]`).
const ECC_READ_PADDING: usize = 13;

/// Byte offset of the imported key within the EccKeyStore command plaintext.
///
/// Layout: CMD_ID(1) || SLOT(2) || CURVE(1) || PADDING(12) || K(32). Source:
/// libtropic `struct lt_l3_ecc_key_store_cmd_t` (`padding[12]` before `k[32]`).
const ECC_STORE_KEY_OFFSET: usize = 16;

/// EccKeyStore command plaintext length: header+padding(16) || K(32) = 48.
///
/// The imported scalar is 32 bytes for both curves (libtropic
/// `TR01_CURVE_PRIVKEY_LEN`). Total matches `TR01_L3_ECC_KEY_STORE_CMD_SIZE`.
const ECC_STORE_CMD_LEN: usize = ECC_STORE_KEY_OFFSET + 32;

/// Padding bytes between the SLOT field and the message in a sign command
/// (CMD_ID(1) || SLOT(2) || PADDING(13) || MSG...).
///
/// Source: libtropic `struct lt_l3_ecdsa_sign_cmd_t` / `lt_l3_eddsa_sign_cmd_t`
/// (`padding[13]`).
const SIGN_CMD_PADDING: usize = 13;

/// Sign-command header length in bytes: CMD_ID(1) || SLOT(2) || PADDING(13).
///
/// The message (ECDSA digest or EdDSA payload) follows this header.
const SIGN_CMD_HEADER: usize = 3 + SIGN_CMD_PADDING;

/// ECDSA sign command plaintext length: header(16) || MSG_HASH(32).
const ECDSA_CMD_LEN: usize = SIGN_CMD_HEADER + 32;

/// Padding bytes before R in a sign result (PADDING(15) || R(32) || S(32)).
///
/// Source: libtropic `struct lt_l3_ecdsa_sign_res_t` and
/// `struct lt_l3_eddsa_sign_res_t` (`padding[15]`). The two result structs are
/// byte-identical, which is what justifies the shared `parse_signature`.
const SIGN_RES_PADDING: usize = 15;

/// Sign-result RES_DATA length in bytes: PADDING(15) || R(32) || S(32).
const SIGN_RES_DATA_LEN: usize = SIGN_RES_PADDING + 64;

/// Maximum EdDSA message length in bytes.
///
/// Source: libtropic `TR01_L3_EDDSA_SIGN_CMD_MSG_LEN_MAX`. A 4096-byte message
/// yields a 4112-byte plaintext, which fills the L3 buffer to capacity.
const EDDSA_MSG_MAX: usize = 4096;

/// MAC-and-Destroy command header length: CMD_ID(1) || SLOT(2) || PADDING(1).
///
/// Source: libtropic `struct lt_l3_mac_and_destroy_cmd_t` (`slot` u16, then
/// `padding` before `data_in`). DATA_IN(32) follows this header.
const MAC_DESTROY_CMD_HEADER: usize = 4;

/// MAC-and-Destroy command plaintext length: header(4) || DATA_IN(32).
const MAC_DESTROY_CMD_LEN: usize = MAC_DESTROY_CMD_HEADER + 32;

/// Padding bytes before DATA_OUT in a MAC-and-Destroy result.
///
/// Source: libtropic `struct lt_l3_mac_and_destroy_res_t` (`padding[3]`).
const MAC_DESTROY_RES_PADDING: usize = 3;

/// MAC-and-Destroy result RES_DATA length: PADDING(3) || DATA_OUT(32).
const MAC_DESTROY_RES_DATA_LEN: usize = MAC_DESTROY_RES_PADDING + 32;

/// McounterInit command header length: CMD_ID(1) || MCOUNTER_INDEX(2) ||
/// PADDING(1). The u32 init value follows this header.
///
/// Source: libtropic `struct lt_l3_mcounter_init_cmd_t` (index u16, then a
/// padding byte before `mcounter_val`).
const MCOUNTER_INIT_HEADER: usize = 4;

/// McounterInit command plaintext length: header(4) || MCOUNTER_VAL(u32 LE).
///
/// Source: libtropic `TR01_L3_MCOUNTER_INIT_CMD_SIZE` (CMD_ID + index + padding
/// + 4-byte value = 8).
const MCOUNTER_INIT_CMD_LEN: usize = MCOUNTER_INIT_HEADER + 4;

/// Byte offset of the host pairing public key within the PairingKeyWrite
/// command plaintext.
///
/// Layout: CMD_ID(1) || SLOT(2) || PADDING(1) || S_HIPUB(32). Source: libtropic
/// `struct lt_l3_pairing_key_write_cmd_t` (`slot` u16, a padding byte, then
/// `s_hipub[32]`).
const PAIRING_KEY_WRITE_KEY_OFFSET: usize = 4;

/// PairingKeyWrite command plaintext length: header+padding(4) || S_HIPUB(32).
///
/// Total matches libtropic `TR01_L3_PAIRING_KEY_WRITE_CMD_SIZE`.
const PAIRING_KEY_WRITE_CMD_LEN: usize = PAIRING_KEY_WRITE_KEY_OFFSET + 32;

/// Byte offset of VALUE within the RConfigWrite command plaintext.
///
/// Layout: CMD_ID(1) || ADDRESS(2) || PADDING(1) || VALUE(4). The value sits
/// after a padding byte the address does not imply, so the offset is non-obvious
/// and earns a name. Source: libtropic `struct lt_l3_r_config_write_cmd_t`
/// (`address` u16, a `padding` byte, then `value`).
const R_CONFIG_WRITE_VALUE_OFFSET: usize = 4;

/// RConfigWrite command plaintext length: header+padding(4) || VALUE(u32) = 8.
///
/// Total matches libtropic `TR01_L3_R_CONFIG_WRITE_CMD_SIZE`.
const R_CONFIG_WRITE_CMD_LEN: usize = R_CONFIG_WRITE_VALUE_OFFSET + 4;

/// Padding bytes before VALUE in a config-read result
/// (PADDING(3) || VALUE(u32 LE)).
///
/// Source: libtropic `struct lt_l3_r_config_read_res_t` /
/// `lt_l3_i_config_read_res_t` (`padding[3]`). The two result structs are
/// byte-identical, which is what justifies the shared `parse_config_value`.
const CONFIG_READ_PADDING: usize = 3;

// Compile-time invariant: the maximum EdDSA wire packet fills the L3 buffer
// exactly. The packet is 2 (L3 CMD_SIZE prefix) || SIGN_CMD_HEADER ||
// EDDSA_MSG_MAX || GCM_TAG_LEN. If any term drifts, the build fails here
// instead of silently overflowing the eddsa_sign cmd[16..] copy. The runtime
// bound in eddsa_sign mirrors this for the local copy.
const _: () =
{
    assert!(
        2 + SIGN_CMD_HEADER + EDDSA_MSG_MAX + crypto::GCM_TAG_LEN
            == crate::buf::L3_FRAME_MAX
    );
};

/// Test-only accessor to the SPI port, for inspecting the chip mock.
#[cfg(test)]
impl<SPI, W, State> Tropic01<SPI, W, State>
{
    pub(crate) fn spi_ref(&self) -> &SPI
    {
        &self.spi
    }

    pub(crate) fn spi_mut(&mut self) -> &mut SPI
    {
        &mut self.spi
    }
}

/// Test-only seam to drive the nonce counters toward exhaustion.
#[cfg(test)]
impl<SPI, W> Tropic01<SPI, W, ActiveSession>
{
    pub(crate) fn seed_nonces(&mut self, cmd: u32, res: u32)
    {
        self.state.keys.set_nonces_for_test(cmd, res);
    }
}
