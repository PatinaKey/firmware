//! Secure-world TROPIC01 firmware-update routine, exported to the NSC veneer.
//!
//! One-shot update of the secure element from factory FW to CPU 2.0.0 / SPECT
//! 1.0.0, driven from the secure world over SPI1. It is the secure side of the
//! `patinakey_nsc_se_fw_update` non-secure-callable veneer: the non-secure world
//! calls the veneer, the veneer forwards here, this code drives the update, packs
//! the outcome into a `u32`, and returns.
//!
//! FEATURE-GATED: the whole module and its blobs compile ONLY under the
//! `se-fw-update` cargo feature. With the feature off the product firmware is
//! byte-unchanged and never references this path.
//!
//! FAITHFUL TRANSPORT: the two vendor blobs are fed to the driver verbatim. This
//! module never parses, reorders, or reframes them. The driver relays them and
//! the chip's own signature check validates the payload.
//!
//! BRICK CLASS, NO R-CONFIG: this path issues ZERO R_Config writes and never
//! enables or disables Maintenance. The chip is dual-bank, so an interrupted
//! update leaves the chip in Start-up (Maintenance) Mode and a re-run re-flashes
//! and recovers (part errata). The status word carries the failing step so the
//! non-secure log tells whether a re-run is expected to recover.
//!
//! QUARANTINE: the `extern "C"` entry needs `#[unsafe(no_mangle)]` 
//! so the C veneer in csrc/secure_nsc.c can resolve it by its C ABI name. 
//! The name is unique to this crate (the `patinakey_se_` prefix),
//! so there is no duplicate-symbol hazard.

use tropic01_driver::SeError;

use crate::se_smoke::build_device;
use crate::se_smoke::se_error_code;

/// The signed CPU (RISC-V) firmware image, version 2.0.0.
///
/// A gitignored vendor blob (crates/secure/fw_blobs/). `include_bytes!` fails the
/// build if it is absent, which is acceptable: a feature-on build requires the
/// blob present. The bytes are the exact `cpu_image` stream `update_firmware`
/// expects, relayed verbatim.
const CPU_FW_2_0_0: &[u8] = include_bytes!("../fw_blobs/cpu_fw_2_0_0.bin");

/// The signed SPECT firmware image, version 1.0.0.
///
/// A gitignored vendor blob (crates/secure/fw_blobs/). `include_bytes!` fails the
/// build if absent. The bytes are the exact `spect_image` stream verbatim.
const SPECT_FW_1_0_0: &[u8] = include_bytes!("../fw_blobs/spect_fw_1_0_0.bin");

// Status-word encoding (value-out, no pointer crosses the boundary).
//
// CROSS-CRATE COUPLING: FWU_OK / FWU_ERR / the STEP codes / FWU_UPDATED_MARKER
// MUST match the encoding decoded on the non-secure side
// (crates/nonsecure/src/main.rs). The two crates do not share a type, so the bit
// layout is duplicated by hand and the two copies must stay in sync.
//
// Layout:
//   bit 31    FWU_ERR : the update failed.
//   bit 8     FWU_OK  : the update succeeded.
//   bits 15..8 (on ERR) STEP code: which step failed.
//   bits 7..0  (on ERR) the SeError code (se_error_code, shared with se_smoke).
//   bits 7..0  (on OK)  FWU_UPDATED_MARKER: a fixed pattern the NS logs as
//                       "updated to 2.0.0".
// An error word can also set bit 8 incidentally (an odd STEP shifts a 1 into
// bit 8 via STEP << 8). FWU_ERR (bit 31) is the discriminator: the NS tests
// FWU_ERR FIRST, so an error word with bit 8 set is read as an error.

/// Status bit: the update succeeded.
const FWU_OK: u32 = 1 << 8;
/// Status bit: the update failed. Bits 15..8 then carry the STEP, bits 7..0 the
/// [`SeError`] code.
const FWU_ERR: u32 = 1 << 31;

/// Low-byte marker returned on success. The non-secure side logs it as "updated
/// to 2.0.0". The running versions are read back via the existing version
/// veneers.
const FWU_UPDATED_MARKER: u32 = 0x20;

/// STEP code: entering the bootloader (`MaintenanceReboot`) failed. The chip is
/// still in Application Mode, a re-run is safe.
const STEP_ENTER_BOOTLOADER: u32 = 0x01;
/// STEP code: writing a firmware bank pair failed (a 0xB0/0xB1 primitive, the
/// inter-pair reboot, or a bad signature). The chip is in Maintenance Mode, a
/// re-run re-flashes and recovers.
const STEP_BANK_WRITE: u32 = 0x02;
/// STEP code: the exit reboot back to Application Mode failed. Both bank pairs
/// were written, a re-run recovers.
const STEP_EXIT_REBOOT: u32 = 0x03;
/// STEP code: the post-reboot running-version verify failed (a version read
/// fault or a mismatch). The banks were written, a re-run recovers.
const STEP_VERIFY: u32 = 0x04;

/// Packs a failing STEP and an [`SeError`] into the error status word.
///
/// `FWU_ERR | (step << 8) | error_code`. The step lives in bits 15..8, the error
/// code in the low byte, so the non-secure log names both the failing step and
/// the fault.
fn err_word(step: u32, err: SeError) -> u32
{
    FWU_ERR | (step << 8) | se_error_code(err)
}

/// Runs the one-shot SE firmware update and returns a packed status word.
///
/// Drives the driver's own bootloader primitives step by step so the returned
/// word names WHICH step failed:
///   1. `enter_bootloader` (a `MaintenanceReboot`),
///   2. `Bootloader::update_firmware` (both bank pairs, CPU before SPECT, the
///      inter-pair reboot), fed the two blobs verbatim,
///   3. `exit_to_application` (a plain `Reboot`),
///   4. a post-reboot running-version verify: the RISC-V and SPECT versions must
///      equal the image versions returned by step 2.
///
/// FAITHFUL TRANSPORT: the blobs are passed to the driver byte-for-byte. This
/// function does not parse or reorder them.
///
/// NO R-CONFIG, NO MAINTENANCE TOGGLE: every step is a driver primitive that
/// issues only 0xB0/0xB1 update or Start-up reboot frames. None writes R-Config
/// or toggles Maintenance. The exit is a plain `Reboot` with nothing after it.
///
/// On any [`SeError`] returns [`err_word`] (bit 31 set, the step in bits 15..8,
/// the error code in the low byte). On success returns `FWU_OK |
/// FWU_UPDATED_MARKER`.
///
/// This is the non-secure-callable entry the update veneer forwards to.
// QUARANTINE: the stable C export name needs `#[unsafe(no_mangle)]`.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn patinakey_se_fw_update() -> u32
{
    let dev = build_device();

    // Step 1: enter the bootloader. On failure the handle is returned unmoved
    // and the chip is still in Application Mode, so a re-run is safe.
    let mut bl = match dev.enter_bootloader()
    {
        Ok(bl) => bl,
        Err((_dev, e)) => return err_word(STEP_ENTER_BOOTLOADER, e),
    };

    // Step 2: write both bank pairs from the two blobs verbatim. On success the
    // driver returns the two decoded image versions, reused by the verify below.
    let (cpu_version, spect_version) = match bl.update_firmware(CPU_FW_2_0_0, SPECT_FW_1_0_0)
    {
        Ok(versions) => versions,
        Err(e) => return err_word(STEP_BANK_WRITE, e),
    };

    // Step 3: exit to Application Mode (a plain Reboot, nothing after it).
    let mut ns = match bl.exit_to_application()
    {
        Ok(ns) => ns,
        Err((_bl, e)) => return err_word(STEP_EXIT_REBOOT, e),
    };

    // Step 4: confirm the running firmware equals the image versions, mirroring
    // the driver's own post-reboot check (libtropic validate). The running
    // versions (LE u32) must equal the expected image versions decoded during
    // the bank write. A read fault or a mismatch means the update did not take
    // effect.
    let verify = match (ns.riscv_fw_version(), ns.spect_fw_version())
    {
        (Ok(riscv), Ok(spect)) =>
        {
            if u32::from_le_bytes(riscv) != cpu_version
                || u32::from_le_bytes(spect) != spect_version
            {
                Err(SeError::FwVersionMismatch)
            }
            else
            {
                Ok(())
            }
        }
        (Err(e), _) | (_, Err(e)) => Err(e),
    };
    match verify
    {
        Ok(()) => FWU_OK | FWU_UPDATED_MARKER,
        Err(e) => err_word(STEP_VERIFY, e),
    }
}
