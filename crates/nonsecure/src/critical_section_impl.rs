//! The critical-section implementation of the non-secure world.
//!
//! `defmt-rtt` guards its RTT ring buffer with a critical section, so the link
//! needs one registered implementation. Only a top-level binary may
//! register one: a library that did would collide with every other library in the
//! link. That is why the registration sits in this bin and not in `mcu-arch`.
//!
//! The implementation masks interrupts through PRIMASK and restores the previous
//! mask on release. `RawRestoreState` is `bool` (the `restore-state-bool` cargo
//! feature), because the only state to save is whether interrupts were enabled.
//!
//! # What PRIMASK masks
//!
//! `CPSID i` boosts the execution priority, which masks every exception of
//! CONFIGURABLE priority. NMI (priority -2) and HardFault (priority -1) are not
//! configurable and keep preempting. A section here excludes ordinary interrupt
//! handlers, and nothing more. Neither fault handler exists in this image today.
//!
//! # TrustZone reach
//!
//! The register is banked, the masking scope is not. PM0264, PRIMASK: setting
//! PRIMASK_NS to one boosts the current execution priority to 0 when `AIRCR.PRIS`
//! is 0, and to 0x80 when it is 1. Every exception of lower or equal priority is
//! then masked. `AIRCR.PRIS` resets to 0 and this firmware never writes AIRCR, so
//! a `CPSID i` executed by this non-secure image masks the SECURE
//! configurable-priority exceptions too, not just the non-secure ones.
//!
//! No interrupt source is enabled in either image, so nothing is masked today.
//! The reach still matters. `defmt-rtt` calls the raw `critical_section::acquire`
//! in `_defmt_acquire` and releases only once the whole log record is encoded and
//! copied into the RTT buffer, so a non-secure `defmt::info!` holds the mask for a
//! long window whose length the non-secure world chooses.
//!
//! OBLIGATION: the SECURE world must set `AIRCR.PRIS` to 1 before the first secure
//! interrupt is enabled. It moves the non-secure boost to 0x80 and leaves the
//! secure priority range (0x00 to 0x7F) unmaskable from here. Until that write
//! lands, a non-secure log line can stall a secure handler.
//!
//! The write CANNOT come from this crate. PM0264 Table 67 gives PRIS (AIRCR bit
//! 14) as "RW from Secure state and RAZ/WI from nonsecure state", so a non-secure
//! write is discarded with no fault, leaving the mitigation only apparent. Once
//! the secure boot has set PRIS, it can freeze it: RM0456 sec 15.3.5 defines
//! `SYSCFG_CSLCKR` bit 0 `LOCKSVTAIRCR`, which disables writes to `VTOR_S` and to
//! the AIRCR PRIS and BFHFNMINS bits. Software sets it, only a system reset clears
//! it, and it too is writable from the secure state alone.
//!
//! The PRIMASK access itself lives in `mcu-arch` alongside every other `asm!`
//! block, which keeps this binary's unsafe surface down to the secure-gateway
//! veneer declarations plus the trait registration below.

// QUARANTINE: 
// The`critical_section::Impl` trait is unsafe to implement, and `set_impl!` expands
// to the unsafe `extern "Rust"` acquire/release shims the crate links against.
// This module-wide allow opts both in. Every unsafe block below carries its own
// `// SAFETY:` note.
#![allow(unsafe_code)]

use critical_section::Impl;
use critical_section::RawRestoreState;

/// The registered implementation. Zero-sized, it holds no state.
struct SingleCoreCriticalSection;

critical_section::set_impl!(SingleCoreCriticalSection);

// SAFETY: `acquire` sets PRIMASK before it returns, masking every
// configurable-priority exception on this single-core part, so no interrupt
// handler runs inside the section. PRIMASK does not mask NMI or HardFault, so the
// invariant this rests on is that no code running at NMI or HardFault priority
// takes a critical section. `release` restores the exact mask `acquire` observed,
// so a section nested inside another leaves interrupts masked until the outermost
// release runs. Those are the two obligations `critical_section::Impl` states.
unsafe impl Impl for SingleCoreCriticalSection
{
    unsafe fn acquire() -> RawRestoreState
    {
        let was_enabled = mcu_arch::interrupts_enabled();
        mcu_arch::disable_interrupts();
        was_enabled
    }

    unsafe fn release(was_enabled: RawRestoreState)
    {
        if was_enabled
        {
            // SAFETY: this unwinds the matching `acquire`, which observed
            // interrupts enabled. No enclosing critical section is open, otherwise
            // `acquire` would have observed them masked and returned false.
            unsafe
            {
                mcu_arch::enable_interrupts();
            }
        }
    }
}
