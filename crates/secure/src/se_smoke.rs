//! Secure-world TROPIC01 bring-up smoke routines, exported to the NSC veneer.
//!
//! These `extern "C"` entries are the secure side of the non-secure-callable
//! bring-up veneers. The non-secure world calls a value-out veneer, the veneer
//! forwards here, and this code talks to the TROPIC01 over the real SPI1. Each
//! entry builds the device on the call (stateless, simplest for a smoke test),
//! runs a no-session L2 probe, packs the result into a `u32`, and returns.
//!
//! FAIL-CLOSED: a [`SeError`] never panics out of here. It maps to an error
//! status word the non-secure world logs, so a SPI or chip fault surfaces as data
//! rather than a secure-world fault.
//!
//! These run ON-DEMAND when the veneer is called. After the boot hand-off the
//! secure world only runs on a veneer call, so this is not in secure `main`.
//!
//! QUARANTINE: the bin denies `unsafe_code` (overriding the workspace forbid).
//! The three entries below each need `#[unsafe(no_mangle)]` so the C veneers in
//! csrc/secure_nsc.c can resolve them by their C ABI names. The names are unique
//! to this crate (the `patinakey_se_*` prefix), so there is no duplicate-symbol
//! hazard. Each export carries its own per-item `#[allow(unsafe_code)]`, matching
//! the per-item pattern in main.rs / the veneer declarations.

use mcu_spi::MmioSpiBus;
use mcu_spi::Spi1Device;
use mcu_spi::SysTickWait;
use platform::MmioBus;
use platform::SysTick;
use tropic01_driver::ChipMode;
use tropic01_driver::L1Error;
use tropic01_driver::L2Error;
use tropic01_driver::NoSession;
use tropic01_driver::SeError;
use tropic01_driver::Tropic01;

// Status-word encoding (value-out, no pointer crosses the boundary).
//
// CROSS-CRATE COUPLING: SMOKE_OK / SMOKE_ERR MUST match the encoding decoded on
// the non-secure side (crates/nonsecure/src/main.rs). The two crates do not share
// a type, so the bit layout is duplicated by hand and the two copies must stay in
// sync.

/// Status bit: the operation succeeded (`chip_mode` smoke word).
const SMOKE_OK: u32 = 1 << 8;
/// Status bit: the operation failed (`chip_mode` smoke word). The low byte then
/// carries the [`SeError`] code.
const SMOKE_ERR: u32 = 1 << 31;

/// `ChipMode` code in the smoke word low byte: Application FW running.
const MODE_APPLICATION: u32 = 1;
/// `ChipMode` code: Start-up (Maintenance) Mode.
const MODE_STARTUP: u32 = 2;
/// `ChipMode` code: Alarm Mode (terminal).
const MODE_ALARM: u32 = 3;

/// Sentinel base returned by the version veneers on any [`SeError`].
///
/// A firmware version is four raw bytes. The Start-up-Mode sentinel
/// `0x8000_0000` is a VALID version round-trip, so it cannot double as the error
/// marker. The error word is `0xEEEE_EExx`, where the low byte `xx` carries the
/// error code. By convention the chip is not expected to emit `0xEE EE EE xx` for
/// a version object, so the non-secure logger reads the `0xEEEE_EE` prefix as the
/// error case. This is a convention, not a hardware guarantee.
const VERSION_ERR_BASE: u32 = 0xEEEE_EE00;

/// Maps a [`SeError`] to a stable one-byte status code for the value-out words.
///
/// The non-secure side logs the code. The exact numbering is a local convention,
/// not a chip value. It groups by layer so a fault is legible in the log. Shared
/// with the fw-update path (se_fw_update.rs) so both veneers encode errors the
/// same way.
pub(crate) fn se_error_code(err: SeError) -> u32
{
    let code: u8 = match err
    {
        SeError::L1(l1) => l1_diag_code(l1),
        SeError::L2(L2Error::Crc) => 0xE1,
        SeError::L2(L2Error::BadFrame) => 0xE2,
        SeError::L2(L2Error::ShortFrame) => 0xE3,
        SeError::L2(L2Error::Status(s)) => s as u8,
        SeError::L2(L2Error::L1(l1)) => l1_diag_code(l1),
        SeError::L3(_) => 0x13,
        SeError::Handshake(_) => 0x20,
        SeError::Cert(_) => 0x30,
        // The chain-verify error variant is compiled into the driver whenever the
        // driver attestation feature is on (the crypto path verifies the chain to
        // the pinned root).
        #[cfg(feature = "se-session")]
        SeError::Chain(_) => 0x31,
        SeError::SessionLost => 0x40,
        SeError::NonceExhausted => 0x41,
        SeError::InvalidArgument => 0x50,
        SeError::BufferTooSmall => 0x51,
        SeError::Image(_) => 0x60,
        SeError::FwUpdateIncomplete => 0x61,
        SeError::FwVersionMismatch => 0x62,
        SeError::RebootUnsuccessful => 0x63,
        // Catch-all arm to handle Cargo feature unification.
        // If another crate in the workspace enables the driver's attestation feature,
        // the `SeError::Chain` variant is globally compiled into the enum. 
        // Since we cannot `#[cfg]` check other crates' features, this match would 
        // fail to compile (E0004) if our own `se-session` feature is off.
        //
        // This wildcard ensures the match remains exhaustive across all workspace builds.
        // We use `allow(unreachable_patterns)` to silence the warning when it's not needed.
        #[allow(unreachable_patterns)]
        _ => 0x7F,
    };
    code as u32
}

/// Diagnostic: maps an L1 error to a distinct low-byte code (bring-up only).
fn l1_diag_code(l1: L1Error) -> u8
{
    match l1
    {
        L1Error::Bus => 0xE4,
        L1Error::ChipBusy => 0xE5,
        L1Error::Alarm => 0xE6,
        L1Error::BadChipStatus => 0xE7,
    }
}

/// Builds a fresh no-session TROPIC01 handle over the real SPI1.
///
/// The handle (~4.4 KiB) lives in this call's secure stack frame. The secure RAM
/// is 128 KiB and no other deep frame is live during a smoke veneer, so the
/// headroom is ample for a one-shot probe. A persistent session would instead hold
/// the handle in a secure `static`, added when the application logic is wired.
///
/// Shared with the fw-update path (se_fw_update.rs) so both build the handle the
/// same way over the real SPI1.
pub(crate) fn build_device()
    -> Tropic01<Spi1Device<MmioSpiBus>, SysTickWait<MmioBus>, NoSession>
{
    let spi = Spi1Device::new(MmioSpiBus::new());
    let wait = SysTickWait::new(SysTick::new(MmioBus::new(), platform::HCLK_HZ));
    Tropic01::new(spi, wait)
}

/// Packs a `ChipMode` into the smoke word low byte with the OK marker.
fn smoke_ok_word(mode: ChipMode) -> u32
{
    let mode_code = match mode
    {
        ChipMode::Application => MODE_APPLICATION,
        ChipMode::Startup => MODE_STARTUP,
        ChipMode::Alarm => MODE_ALARM,
    };
    SMOKE_OK | mode_code
}

/// Packs four firmware-version bytes big-endian into a `u32`.
fn version_word(bytes: [u8; 4]) -> u32
{
    u32::from_be_bytes(bytes)
}

/// Probes the chip mode over SPI and returns a packed status word.
///
/// Builds the device, polls `CHIP_STATUS` (a pure L1 probe, valid in any mode),
/// and packs `ChipMode` plus an OK flag into a `u32`. On any [`SeError`] returns
/// the error word (bit 31 set, the error code in the low byte).
///
/// This is the non-secure-callable entry the version-out veneer forwards to.
// QUARANTINE: the stable C export name needs `#[unsafe(no_mangle)]`. The bin
// otherwise denies `unsafe_code`.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn patinakey_se_smoke() -> u32
{
    let mut dev = build_device();
    match dev.chip_mode()
    {
        Ok(mode) => smoke_ok_word(mode),
        Err(e) => SMOKE_ERR | se_error_code(e),
    }
}

/// Reads the 4-byte RISC-V (application) firmware version over SPI.
///
/// Builds the device and runs `Get_Info` for the RISC-V FW version (no session
/// needed). Returns the four bytes packed big-endian. In Start-up Mode the chip
/// returns the `0x8000_0000` sentinel, a valid round trip the non-secure side
/// interprets. On any [`SeError`] returns [`VERSION_ERR_BASE`] with the error
/// code in the low byte.
// QUARANTINE: the stable C export name needs `#[unsafe(no_mangle)]`. The bin
// otherwise denies `unsafe_code`.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn patinakey_se_riscv_fw_version() -> u32
{
    let mut dev = build_device();
    match dev.riscv_fw_version()
    {
        Ok(bytes) => version_word(bytes),
        Err(e) => VERSION_ERR_BASE | se_error_code(e),
    }
}

/// Reads the 4-byte SPECT firmware version over SPI.
///
/// Builds the device and runs `Get_Info` for the SPECT FW version (no session
/// needed). Returns the four bytes packed big-endian. In Start-up Mode the chip
/// returns the `0x8000_0000` sentinel. On any [`SeError`] returns
/// [`VERSION_ERR_BASE`] with the error code in the low byte.
// QUARANTINE: the stable C export name needs `#[unsafe(no_mangle)]`. The bin
// otherwise denies `unsafe_code`.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn patinakey_se_spect_fw_version() -> u32
{
    let mut dev = build_device();
    match dev.spect_fw_version()
    {
        Ok(bytes) => version_word(bytes),
        Err(e) => VERSION_ERR_BASE | se_error_code(e),
    }
}
