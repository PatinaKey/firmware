//! The target reset entry and the secure-to-secure hand-off jump.
//!
//! Compiled only for the embedded target. This is the untestable silicon glue:
//! the reset vector wires the real flash driver, runs the boot flow, then either
//! hands off to the secure app, wedges, or (on an auto-revert) has already reset.
//!
//! # The hand-off is a plain secure-to-secure branch
//!
//! The boot stage and the secure app both run in the Secure state (TZEN=1 boots
//! secure). Handing off to the app is an ordinary branch, not a BXNS: BXNS is
//! defined only for a secure-to-non-secure transition (PM0264 sec 2.5, Table 27),
//! and the app performs the NS transition later. The Thumb bit of the reset vector
//! is kept, never cleared.
//!
//! Sequence, grounded on RM0456 sec 4 / PM0264 sec 2.1.3 / 2.4:
//!   1. Read the app initial MSP (vector word 0) and reset entry (word 1) from the
//!      app vector table at 0x0C014000.
//!   2. Point `SCB->VTOR` (the secure VTOR, 0xE000ED08) at the app vector table,
//!      then `DSB` + `ISB` so the write completes before the branch.
//!   3. Clear `MSPLIM_S` (a software hand-off does not reset it, PM0264 sec
//!      2.1.3.3), set `MSP_S` to the app SP, then branch to the app reset handler.
//!
//! The boot stage does not reprogram the SAU, the secure MPU, or the SECWM: they
//! are provisioned once and persist across this internal jump.

use cortex_m_rt::entry;
// The halting panic handler. A boot stage must never unwind: every fault is a
// deliberate typed wedge, this only backstops an unreachable panic.
use panic_halt as _;

use crate::glue::BootOutcome;
use crate::glue::run;
use crate::key;
use crate::real::real_flash;

/// The secure app vector table base (pages 10-19 link origin, 0x0C014000).
const APP_VECTOR_TABLE: u32 = 0x0C01_4000;

/// The secure SCB VTOR register address (`SCB->VTOR`, resolves to VTOR_S).
const SCB_VTOR: u32 = 0xE000_ED08;

/// The immutable boot-stage reset entry.
#[entry]
fn boot() -> !
{
    let mut flash = real_flash();
    let root = match key::product_root_key()
    {
        Ok(key) => key,
        // A corrupt pinned key must never fall back to trusting an image.
        Err(_) => wedge(),
    };

    match run(&mut flash, &root)
    {
        BootOutcome::HandOff(_) => jump_to_secure_app(),
        // On silicon the auto-revert already armed the option load and reset the
        // part, so this arm is unreachable there. If control ever returns, wedge.
        BootOutcome::Reverted => wedge(),
        BootOutcome::Wedge(_) => wedge(),
    }
}

/// Halts fail-closed. No image is booted and no security state is left.
fn wedge() -> !
{
    loop
    {
        mcu_arch::wfi();
    }
}

/// Hands off to the secure app: sets the secure VTOR, MSP, then branches.
///
/// Diverges: the app reset handler runs next and never returns here.
#[expect
(
    unsafe_code,
    reason = "secure-to-secure hand-off needs the VTOR write plus the MSP/MSPLIM/bx sequence"
)]
fn jump_to_secure_app() -> !
{
    // SAFETY: a one-time boot hand-off. The two reads take aligned u32 words from
    // the app vector table at its architectural secure-flash base (volatile, so
    // they are neither reordered nor elided). SCB->VTOR is written at its
    // architectural address. MSPLIM_S is cleared and MSP_S is set to the app's own
    // initial SP before an ordinary branch to the app reset handler (Thumb bit
    // kept). No value crosses as a pointer into this stage's memory, and the
    // branch does not return. The SAU / MPU / SECWM are untouched (provisioned and
    // persistent). This is a secure-to-secure branch, never a BXNS.
    unsafe
    {
        let table = APP_VECTOR_TABLE as *const u32;
        let app_msp = core::ptr::read_volatile(table);
        let app_reset = core::ptr::read_volatile(table.add(1));
        core::ptr::write_volatile(SCB_VTOR as *mut u32, APP_VECTOR_TABLE);
        core::arch::asm!
        (
            "dsb",
            "isb",
            "msr msplim, {zero}",
            "msr msp, {msp}",
            "bx {reset}",
            zero = in(reg) 0u32,
            msp = in(reg) app_msp,
            reset = in(reg) app_reset,
            options(noreturn),
        );
    }
}
