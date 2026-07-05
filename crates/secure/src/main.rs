//! Secure-world (TZ-S) firmware entry.
//!
//! The first code the CPU runs after reset (with TZEN=1 it boots Secure). Its job
//! is to run the TrustZone partition bring-up over the REAL MMIO bus, then idle.
//! This is the untestable glue. The partition LOGIC lives in `platform` and is
//! host-tested there. This binary only wires the real [`platform::MmioBus`] into it.
//!
//! The crate compiles two ways:
//!   - For the embedded target (`target_os = "none"`): a `no_std`/`no_main`
//!     cortex-m-rt binary with a halting panic handler (the `firmware` module).
//!   - For the host: an empty `main`, so the whole workspace stays host-checkable
//!     (`cargo check`) without a bare-metal test harness.
//!
//! Deferred: the SE driver instantiation.
//!
//! FAIL-CLOSED CONTRACT: PartitionError => never hand off to NS. A partition or
//! secure-MPU fault leaves the secure world's isolation incomplete, so on error
//! the secure world wedges in a tight secure loop and the non-secure world is
//! never started. Only the path where both `apply_partition` and
//! `apply_secure_mpu` succeed reaches the NS hand-off below.

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

// The non-secure-callable smoke routines (the secure side of the SE bring-up
// veneers). Target-only: they build the device on the real SPI1 MMIO bus. The C
// veneers in csrc/secure_nsc.c forward to these `extern "C"` entries.
#[cfg(target_os = "none")]
mod se_smoke;

// The one-shot SE firmware-update path (secure side of the fw-update veneer).
// Feature-gated: OFF by default, so the product firmware is byte-unchanged and
// never references it.
#[cfg(all(target_os = "none", feature = "se-fw-update"))]
mod se_fw_update;

// The L3 secure-channel bring-up path (secure side of the session veneer).
// Feature-gated: OFF by default, so the product firmware is byte-unchanged and
// never references it.
#[cfg(all(target_os = "none", feature = "se-session"))]
mod se_session;

// The crypto + attestation bring-up path (secure side of the crypto veneer).
// Feature-gated under the se-session feature: OFF by default, so the
// product firmware is byte-unchanged and never references it.
#[cfg(all(target_os = "none", feature = "se-session"))]
mod se_crypto;

// The persistent-but-reversible state bring-up path. 
// Feature-gated under the se-session feature: OFF by default, so the
// product firmware is byte-unchanged and never references it.
#[cfg(all(target_os = "none", feature = "se-session"))]
mod se_persist;

// The read-only sweep plus P-256 export path.
// Feature-gated under the se-session feature: OFF by default, so the
// product firmware is byte-unchanged and never references it.
#[cfg(all(target_os = "none", feature = "se-session"))]
mod se_readonly;

#[cfg(target_os = "none")]
mod firmware
{
    use core::ptr;
    use cortex_m_rt::entry;
    use panic_halt as _;
    use platform::apply_partition;
    use platform::apply_secure_mpu;
    use platform::MmioBus;

    /// Non-secure vector table base: NS flash Bank 2 (NS alias). RM0456 memory
    /// map. word[0] = NS initial MSP, word[1] = NS reset entry.
    const NS_VECTOR_TABLE: u32 = 0x0804_0000;

    /// `SCB_NS->VTOR`: the non-secure alias of the SCB VTOR register. The NS SCB
    /// is the standard SCB block at the non-secure-alias base, VTOR at +0xD08
    /// (0xE002_ED08). PM0264 (Cortex-M33) VTOR banking. Armv8-M SCB_NS alias.
    const SCB_NS_VTOR: u32 = 0xE002_ED08;

    /// Secure reset entry: partition the device, then hand off to NS (or wedge).
    #[entry]
    fn main() -> !
    {
        let mut bus = MmioBus::new();

        // Apply the SAU/GTZC runtime partition. A PartitionError is a programming
        // fault in the (host-tested) region table, surfaced before any hardware
        // write, so the device is still in its all-secure reset state. Silicon
        // recovery is impossible, and the secure world MUST NOT hand off to NS with
        // crypto/SPI1 left non-secure. The Ok and Err paths are structurally
        // distinct: only Ok may ever reach the NS hand-off.
        match apply_partition(&mut bus)
        {
            Ok(()) =>
            {
                // Partition applied: enable the secure MPU then hand off to the
                // non-secure world. This never returns on success. The MPU is
                // enabled inside start_nonsecure as the LAST isolation step, and on
                // an MPU fault that function wedges instead of handing off.
                start_nonsecure(&mut bus);
            }
            Err(_) =>
            {
                // FAIL-CLOSED: never reach the NS hand-off. Wedge the secure world
                // in a tight loop that no NS transition can follow.
                loop
                {
                    cortex_m::asm::wfi();
                }
            }
        }
    }

    /// Enables the secure MPU then hands control to the non-secure world.
    /// Diverges (the NS reset runs next, or the secure world wedges on a fault).
    ///
    /// Hand-off order (no standing NS window in the secure MPU): read and stage
    /// the NS vectors while the MPU is OFF, enable the MPU as the LAST isolation
    /// step, then branch.
    ///   1. read the NS MSP (vector word 0) and NS reset entry (word 1) from the NS
    ///      vector table, and point `SCB_NS->VTOR` at it, all while the MPU is OFF,
    ///   2. apply the secure MPU (the last isolation step). On error, FAIL-CLOSED:
    ///      wedge and never hand off,
    ///   3. `DSB` then `ISB` so the new MPU config takes effect before any
    ///      dependent access,
    ///   4. set MSP_NS, then `BXNS` to the NS reset (the low bit cleared selects
    ///      the non-secure state).
    ///
    /// Between the MPU enable and the `BXNS` there is NO secure data-memory access:
    /// only secure-flash instruction fetch and register ops run, so the secure SRAM
    /// region already covers everything needed and no extra MPU region is required.
    ///
    /// Only the partition's Ok path calls this, preserving the fail-closed
    /// contract. It is reached once at boot, it does not return.
    //
    // QUARANTINE: the bin denies `unsafe_code` (overriding the workspace forbid).
    // This targeted allow opts in just the volatile NS-vector reads, the SCB_NS
    // write, and the MSR/BXNS hand-off below, each carrying its own `// SAFETY:`.
    #[allow(unsafe_code)]
    fn start_nonsecure(bus: &mut MmioBus) -> !
    {
        // Stage the NS hand-off inputs while the MPU is still OFF. These reads and
        // the SCB_NS->VTOR write must happen before the MPU is enabled, because the
        // secure MPU has no standing NS window.
        //
        // SAFETY: a one-time boot hand-off after the partition succeeded. The NS
        // vector table sits at the cited NS-flash base. word[0]/word[1] are read as
        // aligned u32 (volatile, so the reads are not reordered or elided), and
        // SCB_NS->VTOR is written at its architectural NS-alias address. No value
        // crosses as a pointer to secure memory.
        let (ns_msp, ns_reset) = unsafe
        {
            let ns_vectors = NS_VECTOR_TABLE as *const u32;
            let ns_msp = ptr::read_volatile(ns_vectors);
            let ns_reset = ptr::read_volatile(ns_vectors.add(1));

            // Point the non-secure VTOR at the NS vector table (MPU still off).
            ptr::write_volatile(SCB_NS_VTOR as *mut u32, NS_VECTOR_TABLE);
            (ns_msp, ns_reset)
        };

        // Enable the secure MPU as the LAST isolation step. On error FAIL-CLOSED:
        // wedge and never hand off, so the NS world cannot start with the secure
        // world unprotected.
        if apply_secure_mpu(bus).is_err()
        {
            loop
            {
                cortex_m::asm::wfi();
            }
        }

        // Architectural barriers so the freshly enabled MPU config is in effect
        // before any subsequent access or the branch.
        cortex_m::asm::dsb();
        cortex_m::asm::isb();

        // SAFETY: the architectural S->NS entry. MSP_NS is set then BXNS branches
        // to the NS reset, clearing the low bit to enter the non-secure state. The
        // NS reset value already carries the Thumb bit, masked here for the state
        // select. The staged ns_msp/ns_reset were read above while the MPU was off.
        // This leaves the secure state by definition and never returns.
        unsafe
        {
            core::arch::asm!(
                "msr MSP_NS, {msp}",
                "bxns {reset}",
                msp = in(reg) ns_msp,
                reset = in(reg) ns_reset & !1,
                options(noreturn),
            );
        }
    }
}

// Host stub: keeps `cargo check`/`clippy` green on x86_64 without a bare-metal
// runtime. Carries no firmware behaviour.
#[cfg(not(target_os = "none"))]
fn main()
{
}
