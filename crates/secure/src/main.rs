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
//! Deferred: the secure MPU and the SE driver instantiation.
//!
//! FAIL-CLOSED CONTRACT: PartitionError => never hand off to NS. A partition fault
//! leaves SPI1/crypto in their NS reset state, so on error the secure world wedges
//! in a tight secure loop and the non-secure world is never started. Only the Ok
//! path reaches the NS hand-off below.

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(target_os = "none")]
mod firmware
{
    use core::ptr;
    use cortex_m_rt::entry;
    use panic_halt as _;
    use platform::apply_partition;
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
                // Partition applied: hand off to the non-secure world. This never
                // returns.
                start_nonsecure();
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

    /// Hands control to the non-secure world. Diverges (the NS reset runs next).
    ///
    /// Steps (Armv8-M secure->non-secure transition):
    ///   1. point `SCB_NS->VTOR` at the NS vector table,
    ///   2. load the NS main stack pointer from NS vector word[0],
    ///   3. read the NS reset entry from NS vector word[1] and branch to it with
    ///      `BXNS` (the low bit cleared selects the non-secure state).
    ///
    /// Only the partition's Ok path calls this, preserving the fail-closed
    /// contract. It is reached once at boot, it does not return.
    //
    // QUARANTINE: the bin denies `unsafe_code` (overriding the workspace forbid).
    // This targeted allow opts in just the volatile NS-vector reads, the SCB_NS
    // write, and the MSR/BXNS hand-off below, each carrying its own `// SAFETY:`.
    #[allow(unsafe_code)]
    fn start_nonsecure() -> !
    {
        // SAFETY: a one-time boot hand-off after the partition succeeded. The NS
        // vector table sits at the cited NS-flash base. word[0]/word[1] are read as
        // aligned u32 (volatile, so the reads are not reordered or elided), and
        // SCB_NS->VTOR is written at its architectural NS-alias address. MSP_NS is
        // set then BXNS branches to the NS reset, clearing the low bit to enter the
        // non-secure state. No value crosses as a pointer to secure memory. This is
        // the architectural S->NS entry, which by definition leaves the secure
        // state and never returns.
        unsafe
        {
            let ns_vectors = NS_VECTOR_TABLE as *const u32;
            let ns_msp = ptr::read_volatile(ns_vectors);
            let ns_reset = ptr::read_volatile(ns_vectors.add(1));

            // 1. Point the non-secure VTOR at the NS vector table.
            ptr::write_volatile(SCB_NS_VTOR as *mut u32, NS_VECTOR_TABLE);

            // 2/3. Set MSP_NS, then BXNS to the NS reset entry. BXNS with the low
            // bit of the target cleared selects the non-secure state. The NS reset
            // value already carries the Thumb bit. Mask it for the state select.
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
