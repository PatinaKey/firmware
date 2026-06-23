//! Non-secure (TZ-NS) firmware entry.
//!
//! The secure world hands control here via `SCB_NS->VTOR` + `BXNS` after it
//! programs the partition. This entry runs the SE bring-up chain over the NSC
//! veneers, logs the result over defmt-RTT, then idles in a `wfi` loop. It is the
//! non-secure half of the S+NS dual-image build.
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
    use defmt_rtt as _;
    use panic_halt as _;

    // The secure-gateway veneers exported by the secure world's NSC shim. The NS
    // link resolves these symbols against the CMSE import object emitted by the
    // secure build (see build.rs). That resolution is the proof the S/NS bridge
    // links. Each is value-out only, no pointer/secret/handle crosses the
    // boundary.
    //
    // QUARANTINE: the bin denies `unsafe_code` (overriding the workspace forbid).
    // This targeted allow opts in just the extern declarations of the veneers.
    #[allow(unsafe_code)]
    unsafe extern "C"
    {
        fn patinakey_nsc_version() -> u32;
        fn patinakey_nsc_se_smoke() -> u32;
        fn patinakey_nsc_se_riscv_fw_version() -> u32;
        fn patinakey_nsc_se_spect_fw_version() -> u32;
    }

    // CROSS-CRATE COUPLING: SMOKE_ERR / SMOKE_OK MUST match the encoding produced
    // on the secure side (crates/secure/src/se_smoke.rs). The two crates do not
    // share a type, so the bit layout is duplicated by hand and the two copies must
    // stay in sync.

    /// Smoke-word bit set when the secure side reports an SE fault.
    const SMOKE_ERR: u32 = 1 << 31;
    /// Smoke-word bit set when the chip-mode probe succeeded.
    const SMOKE_OK: u32 = 1 << 8;

    /// Decodes a smoke `ChipMode` low-byte code into a static label.
    fn mode_label(low_byte: u32) -> &'static str
    {
        match low_byte
        {
            1 => "Application",
            2 => "Startup",
            3 => "Alarm",
            _ => "Unknown",
        }
    }

    /// Non-secure entry: run the SE bring-up chain over the veneers and report.
    ///
    /// Calls the version veneer, then the three SE veneers, logging the NSC
    /// version, the chip mode, and both firmware versions over defmt-RTT. The full
    /// non-secure -> secure -> TROPIC01 chain runs here at boot, then the entry
    /// idles in a `wfi` loop.
    //
    // QUARANTINE: targeted allow for the veneer calls below. Each is a CMSE
    // secure-gateway entry taking no argument and returning a scalar, so nothing
    // is shared to validate. The bin otherwise denies `unsafe_code`.
    #[allow(unsafe_code)]
    #[entry]
    fn main() -> !
    {
        // SAFETY: each veneer is a CMSE secure-gateway entry that takes no
        // argument and returns a scalar. Calling one crosses into the secure world
        // through the SG veneer. No pointer or caller memory is shared, so there is
        // nothing to validate on either side.
        let (version, smoke, riscv, spect) = unsafe
        {
            (
                patinakey_nsc_version(),
                patinakey_nsc_se_smoke(),
                patinakey_nsc_se_riscv_fw_version(),
                patinakey_nsc_se_spect_fw_version(),
            )
        };

        defmt::info!("NSC interface version {=u32:#010x}", version);

        if smoke & SMOKE_ERR != 0
        {
            defmt::warn!("SE chip-mode probe failed, error code {=u8:#04x}", smoke as u8);
        }
        else if smoke & SMOKE_OK != 0
        {
            defmt::info!("SE chip mode: {=str}", mode_label(smoke & 0xFF));
        }
        else
        {
            defmt::warn!("SE chip-mode word unrecognized {=u32:#010x}", smoke);
        }

        defmt::info!("SE RISC-V FW version word {=u32:#010x}", riscv);
        defmt::info!("SE SPECT FW version word {=u32:#010x}", spect);

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
