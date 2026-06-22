//! Non-secure (TZ-NS) firmware entry.
//!
//! Minimal skeleton. The secure world hands control here via `SCB_NS->VTOR` +
//! `BXNS` after it programs the partition. This will become the embassy
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
    use core::hint::black_box;
    use cortex_m_rt::entry;
    use panic_halt as _;

    // The secure-gateway veneer exported by the secure world's NSC shim. The NS
    // link resolves this symbol against the CMSE import object emitted by the
    // secure build (see build.rs). That resolution is the proof the S/NS bridge
    // links. Value-out only, no pointer/secret/handle crosses the boundary.
    //
    // QUARANTINE: the bin denies `unsafe_code` (overriding the workspace forbid).
    // This targeted allow opts in just the extern declaration of the veneer.
    #[allow(unsafe_code)]
    unsafe extern "C"
    {
        fn patinakey_nsc_version() -> u32;
    }

    /// Non-secure entry: read the NSC version once, then idle skeleton (to become
    /// the embassy app).
    //
    // QUARANTINE: targeted allow for the single veneer call below. See its
    // `// SAFETY:` note. The bin otherwise denies `unsafe_code`.
    #[allow(unsafe_code)]
    #[entry]
    fn main() -> !
    {
        // SAFETY: patinakey_nsc_version is a CMSE secure-gateway entry that takes
        // no argument and returns a scalar. Calling it crosses into the secure
        // world through the SG veneer. No pointer or caller memory is shared, so
        // there is nothing to validate on either side. black_box keeps the call
        // live so the linker must resolve the veneer (the bridge proof).
        let version = unsafe
        {
            patinakey_nsc_version()
        };
        black_box(version);

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
