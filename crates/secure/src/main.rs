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
//! Deferred: the secure MPU, the NS hand-off (`SCB_NS->VTOR` + `BXNS`), the SE
//! driver instantiation, and the C `-mcmse` NSC veneer shim.
//!
//! FAIL-CLOSED CONTRACT: PartitionError => never hand off to NS. A partition fault
//! leaves SPI1/crypto in their NS reset state, so on error the secure world wedges
//! in a tight secure loop and the non-secure world is never started.

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(target_os = "none")]
mod firmware
{
    use cortex_m_rt::entry;
    use panic_halt as _;
    use platform::apply_partition;
    use platform::MmioBus;

    /// Secure reset entry: partition the device, then idle (or wedge on fault).
    #[entry]
    fn main() -> !
    {
        let mut bus = MmioBus::new();

        // Apply the SAU/GTZC runtime partition. A PartitionError is a programming
        // fault in the (host-tested) region table, surfaced before any hardware
        // write, so the device is still in its all-secure reset state. Silicon
        // recovery is impossible, and the secure world MUST NOT hand off to NS with
        // crypto/SPI1 left non-secure. The Ok and Err paths are structurally
        // distinct: only Ok may ever reach the (future) NS hand-off.
        match apply_partition(&mut bus)
        {
            Ok(()) =>
            {
                // Partition applied. The NS hand-off and the secure service loop
                // attach here. Until then, hold the secure world.
                loop
                {
                    cortex_m::asm::wfi();
                }
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
}

// Host stub: keeps `cargo check`/`clippy` green on x86_64 without a bare-metal
// runtime. Carries no firmware behaviour.
#[cfg(not(target_os = "none"))]
fn main()
{
}
