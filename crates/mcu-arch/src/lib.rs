//! Armv8-M core instruction wrappers for the Cortex-M33.
//!
//! Wraps `WFI`, `DSB`, `ISB`, and the PRIMASK interrupt mask behind Rust
//! functions.
//!
//! # The one block outside this crate
//!
//! `crates/secure/src/main.rs` keeps a raw `asm!` for the secure-to-non-secure
//! hand-off (`msr MSP_NS` then `bxns`). It writes a banked special register, it
//! never returns, and it leaves the security state, so it has no reusable
//! register-bus form.
//!
//! # Two builds
//!
//! The `arm` module holds the real `asm!` and compiles only for
//! `target_os = "none"`. The `host` module holds stubs, so the workspace stays
//! checkable and testable on x86_64 without a bare-metal harness.
//!
//! # Barrier contract
//!
//! [`dsb`] and [`isb`] bracket the instruction with a `SeqCst` compiler fence.
//!
//! # Reference
//!
//! Each `asm!` block mirrors the operand and option set that the `cortex-m` crate
//! 0.7.7 (`asm/inline.rs`, `src/interrupt.rs`, `src/register/primask.rs`) uses for
//! the same instruction.

#![cfg_attr(not(test), no_std)]

#[cfg(target_os = "none")]
mod arm;
#[cfg(not(target_os = "none"))]
mod host;

#[cfg(target_os = "none")]
use crate::arm as imp;
#[cfg(not(target_os = "none"))]
use crate::host as imp;

/// Suspends the core until an interrupt or an event wakes it.
///
/// Host build: does nothing, so a host `loop { wfi() }` would spin.
#[inline]
pub fn wfi()
{
    imp::wfi();
}

/// Data synchronisation barrier (`DSB`), fenced on both sides.
///
/// Completes every pending explicit memory access before the next instruction
/// executes.
/// Host build: the compiler fence alone.
#[inline]
pub fn dsb()
{
    imp::dsb();
}

/// Instruction synchronisation barrier (`ISB`), fenced on both sides.
///
/// Flushes the pipeline so instructions fetched after it observe the new context.
/// Host build: the compiler fence alone.
#[inline]
pub fn isb()
{
    imp::isb();
}

/// Reads PRIMASK and reports whether configurable-priority exceptions are enabled.
///
/// Returns `true` when PRIMASK bit 0 is clear. Under TrustZone the read resolves
/// to the banked PRIMASK of the security state the caller runs in. NMI and
/// HardFault are outside PRIMASK's reach either way.
///
/// Bare-metal target only: a hosted OS exposes no such register.
#[cfg(target_os = "none")]
#[inline]
pub fn interrupts_enabled() -> bool
{
    imp::interrupts_enabled()
}

/// Masks all maskable interrupts (`CPSID i`), then fences.
///
/// Safe to call: masking interrupts cannot introduce a data race. Pair it with
/// [`enable_interrupts`] only when the mask was clear beforehand.
///
/// Bare-metal target only.
#[cfg(target_os = "none")]
#[inline]
pub fn disable_interrupts()
{
    imp::disable_interrupts();
}

/// Fences, then unmasks all maskable interrupts (`CPSIE i`).
///
/// Bare-metal target only.
///
/// # Safety
///
/// The caller must not be inside a critical section entered by
/// [`disable_interrupts`], other than the outermost one it is unwinding. Calling
/// it inside a nested section would expose the section's state to an interrupt
/// handler.
#[cfg(target_os = "none")]
#[inline]
#[allow(unsafe_code)]
pub unsafe fn enable_interrupts()
{
    // SAFETY: the caller carries the obligation stated above.
    unsafe
    {
        imp::enable_interrupts();
    }
}

/// Maps a PRIMASK word to whether configurable-priority exceptions are enabled.
///
/// PRIMASK bit 0 set means masked. The other 31 bits are reserved and ignored.
#[cfg(any(target_os = "none", test))]
pub(crate) const fn interrupts_enabled_from_primask(primask: u32) -> bool
{
    primask & 1 == 0
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn primask_bit0_clear_reports_interrupts_enabled()
    {
        assert!(interrupts_enabled_from_primask(0));
    }

    #[test]
    fn primask_bit0_set_reports_interrupts_masked()
    {
        assert!(!interrupts_enabled_from_primask(1));
    }

    #[test]
    fn primask_polarity_ignores_the_reserved_bits()
    {
        assert!(interrupts_enabled_from_primask(0xFFFF_FFFE));
        assert!(!interrupts_enabled_from_primask(u32::MAX));
    }
}
