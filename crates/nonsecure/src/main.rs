//! Non-secure (TZ-NS) firmware entry.
//!
//! Minimal skeleton. The secure world hands control here after it programs the
//! partition (via `SCB_NS->VTOR` + `BXNS`, deferred). This will become the embassy
//! application (USB / CTAPHID / CCID / CTAP2 / OpenPGP). For now it is a bare
//! cortex-m-rt entry that idles, present so the S+NS dual-image build links.
//!
//! Compiles two ways, like the secure bin: a `no_std`/`no_main` cortex-m-rt
//! binary for the embedded target, an empty `main` on the host so the whole
//! workspace stays host-checkable.

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(target_os = "none")]
mod firmware
{
    use cortex_m_rt::entry;
    use panic_halt as _;

    /// Non-secure entry: idle skeleton (to become the embassy app).
    #[entry]
    fn main() -> !
    {
        loop
        {
            cortex_m::asm::wfi();
        }
    }
}

// Host stub: keeps `cargo check`/`clippy` green on x86_64.
#[cfg(not(target_os = "none"))]
fn main()
{
}
