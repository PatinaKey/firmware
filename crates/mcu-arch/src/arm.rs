//! The Armv8-M instructions (`target_os = "none"` only).
//!
//! Every reusable `asm!` block in the firmware lives here.
use core::arch::asm;
use core::sync::atomic::compiler_fence;
use core::sync::atomic::Ordering;

use crate::interrupts_enabled_from_primask;

/// Suspends the core until an interrupt or an event wakes it.
#[inline]
#[allow(unsafe_code)]
pub(crate) fn wfi()
{
    // SAFETY: `wfi` takes no operand, reads and writes no memory, touches no stack
    // slot, and preserves the condition flags. Waking is an architectural event
    // with no Rust-level effect.
    unsafe
    {
        asm!("wfi", options(nomem, nostack, preserves_flags));
    }
}

/// Data synchronisation barrier, bracketed by compiler fences.
#[inline]
#[allow(unsafe_code)]
pub(crate) fn dsb()
{
    compiler_fence(Ordering::SeqCst);

    // SAFETY: `dsb` takes no operand and has no Rust-level memory, stack, or flag
    // effect. The two fences, are what stop the compiler moving accesses across the barrier.
    unsafe
    {
        asm!("dsb", options(nomem, nostack, preserves_flags));
    }

    compiler_fence(Ordering::SeqCst);
}

/// Instruction synchronisation barrier, bracketed by compiler fences.
#[inline]
#[allow(unsafe_code)]
pub(crate) fn isb()
{
    compiler_fence(Ordering::SeqCst);

    // SAFETY: `isb` takes no operand and has no Rust-level memory, stack, or flag
    // effect. The two fences are what stop the compiler moving accesses across the barrier.
    unsafe
    {
        asm!("isb", options(nomem, nostack, preserves_flags));
    }

    compiler_fence(Ordering::SeqCst);
}

/// Reads PRIMASK and reports whether maskable interrupts are enabled.
#[inline]
#[allow(unsafe_code)]
pub(crate) fn interrupts_enabled() -> bool
{
    let primask: u32;

    // SAFETY: `mrs` copies the PRIMASK special register into a scratch register.
    // It reads no memory, touches no stack slot, and preserves the condition
    // flags. Under TrustZone the instruction resolves to the banked PRIMASK of the
    // current security state.
    unsafe
    {
        asm!
        (
            "mrs {}, PRIMASK",
            out(reg) primask,
            options(nomem, nostack, preserves_flags),
        );
    }

    interrupts_enabled_from_primask(primask)
}

/// Masks all maskable interrupts, then fences.
#[inline]
#[allow(unsafe_code)]
pub(crate) fn disable_interrupts()
{
    // SAFETY: `cpsid i` sets PRIMASK. It takes no operand, reads and writes no
    // memory, touches no stack slot, and preserves the condition flags.
    unsafe
    {
        asm!("cpsid i", options(nomem, nostack, preserves_flags));
    }

    compiler_fence(Ordering::SeqCst);
}

/// Fences, then unmasks all maskable interrupts.
///
/// # Safety
///
/// The caller must not re-enable interrupts while still inside a nested critical
/// section entered by [`disable_interrupts`].
#[inline]
#[allow(unsafe_code)]
pub(crate) unsafe fn enable_interrupts()
{
    compiler_fence(Ordering::SeqCst);

    // SAFETY: `cpsie i` clears PRIMASK. It takes no operand, reads and writes no
    // memory, touches no stack slot, and preserves the condition flags. The caller
    // carries the obligation that no enclosing critical section is still open.
    unsafe
    {
        asm!("cpsie i", options(nomem, nostack, preserves_flags));
    }
}
