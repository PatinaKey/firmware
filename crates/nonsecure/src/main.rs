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

    // The fw-update veneer is feature-gated: it is only emitted secure-side under
    // the matching feature.
    #[cfg(feature = "se-fw-update")]
    #[allow(unsafe_code)]
    unsafe extern "C"
    {
        fn patinakey_nsc_se_fw_update() -> u32;
    }

    // The L3 session veneer is feature-gated: it is only emitted secure-side
    // under the matching feature.
    #[cfg(feature = "se-session")]
    #[allow(unsafe_code)]
    unsafe extern "C"
    {
        fn patinakey_nsc_se_session_ping() -> u32;
    }

    // The crypto + attestation veneer rides the SAME se-session feature: it is
    // only emitted secure-side under that feature.
    #[cfg(feature = "se-session")]
    #[allow(unsafe_code)]
    unsafe extern "C"
    {
        fn patinakey_nsc_se_crypto() -> u32;
    }

    // CROSS-CRATE COUPLING: SMOKE_ERR / SMOKE_OK MUST match the encoding produced
    // on the secure side (crates/secure/src/se_smoke.rs). The two crates do not
    // share a type, so the bit layout is duplicated by hand and the two copies must
    // stay in sync.

    /// Smoke-word bit set when the secure side reports an SE fault.
    const SMOKE_ERR: u32 = 1 << 31;
    /// Smoke-word bit set when the chip-mode probe succeeded.
    const SMOKE_OK: u32 = 1 << 8;

    // CROSS-CRATE COUPLING: the fw-update status-word bit layout below MUST match
    // the encoding produced on the secure side (crates/secure/src/se_fw_update.rs).
    // The two crates do not share a type, so it is duplicated by hand and the two
    // copies must stay in sync.

    /// Fw-update word bit set when the secure side reports the update failed.
    /// Bits 15..8 then carry the step, bits 7..0 the error code.
    #[cfg(feature = "se-fw-update")]
    const FWU_ERR: u32 = 1 << 31;
    /// Fw-update word bit set when the update succeeded. The low byte carries the
    /// updated-to-2.0.0 marker.
    #[cfg(feature = "se-fw-update")]
    const FWU_OK: u32 = 1 << 8;

    /// Decodes a fw-update failing-step code into a static label plus whether a
    /// re-run is expected to recover. Steps mirror se_fw_update.rs: 1 enter
    /// bootloader, 2 bank write, 3 exit reboot, 4 verify.
    #[cfg(feature = "se-fw-update")]
    fn fwu_step(step: u32) -> (&'static str, bool)
    {
        match step
        {
            // Enter-bootloader failed: chip still in Application, a re-run is safe.
            1 => ("enter-bootloader", true),
            // Bank write failed: chip in Maintenance, a re-run re-flashes.
            2 => ("bank-write", true),
            // Exit reboot failed: banks written, a re-run recovers.
            3 => ("exit-reboot", true),
            // Verify failed: banks written, a re-run recovers.
            4 => ("verify", true),
            _ => ("unknown", false),
        }
    }

    // CROSS-CRATE COUPLING: the L3-session status-word bit layout below MUST
    // match the encoding produced on the secure side
    // (crates/secure/src/se_session.rs). The two crates do not share a type, so
    // it is duplicated by hand and the two copies must stay in sync.

    /// Session word bit set when the secure side reports the L3 bring-up failed.
    /// Bits 15..8 then carry the step, bits 7..0 the error code (or 0xF0, an echo
    /// mismatch, which is not an SeError).
    #[cfg(feature = "se-session")]
    const SES_ERR: u32 = 1 << 31;
    /// Session word bit set when the L3 bring-up succeeded. The low byte carries
    /// the OK marker.
    #[cfg(feature = "se-session")]
    const SES_OK: u32 = 1 << 8;

    /// Decodes an L3-session failing-step code into a static label. Steps mirror
    /// se_session.rs: 1 read-stpub, 2 open-session, 3 ping, 4 session-abort.
    #[cfg(feature = "se-session")]
    fn ses_step(step: u32) -> &'static str
    {
        match step
        {
            1 => "read-stpub",
            2 => "open-session",
            3 => "ping",
            4 => "session-abort",
            _ => "unknown",
        }
    }

    // CROSS-CRATE COUPLING: the crypto status-word bit layout below MUST match
    // the encoding produced on the secure side (crates/secure/src/se_crypto.rs).
    // The two crates do not share a type, so it is duplicated by hand and the two
    // copies must stay in sync.

    /// Crypto word bit set when the secure side reports the bring-up failed. Bits
    /// 15..8 then carry the step, bits 7..0 the error code. RESERVED non-SeError
    /// low-byte codes: 0xF1 EdDSA verify reject, 0xF2 random sanity, 0xF3 ECDSA
    /// shape, 0xF4 pubkey length.
    #[cfg(feature = "se-session")]
    const SCR_ERR: u32 = 1 << 31;
    /// Crypto word bit set when the bring-up succeeded. The low byte carries the
    /// OK marker.
    #[cfg(feature = "se-session")]
    const SCR_OK: u32 = 1 << 8;

    /// Decodes a crypto failing-step code into a static label. Steps mirror
    /// se_crypto.rs: 1 attestation, 2 open-session, 3 random, 4 pre-clean, 5
    /// ed25519-generate, 6 ed25519-pubkey, 7 eddsa-sign, 8 eddsa-verify, 9
    /// ed25519-erase, 10 ecdsa-p256, 11 session-abort.
    #[cfg(feature = "se-session")]
    fn crypto_step(step: u32) -> &'static str
    {
        match step
        {
            1 => "attestation",
            2 => "open-session",
            3 => "random",
            4 => "pre-clean",
            5 => "ed25519-generate",
            6 => "ed25519-pubkey",
            7 => "eddsa-sign",
            8 => "eddsa-verify",
            9 => "ed25519-erase",
            10 => "ecdsa-p256",
            11 => "session-abort",
            _ => "unknown",
        }
    }

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

        // Feature-gated: run the one-shot SE firmware update and log the decoded
        // outcome (which step, success plus the versions read back, or the failure
        // plus whether a re-run recovers). Compiled out entirely when the feature
        // is off, so the default NS entry is unchanged.
        #[cfg(feature = "se-fw-update")]
        {
            // SAFETY: the fw-update veneer is a CMSE secure-gateway entry taking
            // no argument and returning a scalar. Calling it crosses into the
            // secure world through the SG veneer. No pointer or caller memory is
            // shared, so there is nothing to validate on either side.
            let fwu = unsafe { patinakey_nsc_se_fw_update() };

            if fwu & FWU_ERR != 0
            {
                let (label, recovers) = fwu_step((fwu >> 8) & 0xFF);
                defmt::error!
                (
                    "SE fw-update FAILED at step {=str}, error code {=u8:#04x} \
                     (re-run recovers: {=bool})",
                    label,
                    fwu as u8,
                    recovers
                );
            }
            else if fwu & FWU_OK != 0
            {
                // Read the running versions back over the existing veneers so the
                // log shows the new firmware, not just the ok marker.
                // SAFETY: value-out CMSE entries, same contract as above.
                let (new_riscv, new_spect) = unsafe
                {
                    (
                        patinakey_nsc_se_riscv_fw_version(),
                        patinakey_nsc_se_spect_fw_version(),
                    )
                };
                defmt::info!
                (
                    "SE fw-update OK (updated to 2.0.0), marker {=u8:#04x}, \
                     RISC-V now {=u32:#010x}, SPECT now {=u32:#010x}",
                    fwu as u8,
                    new_riscv,
                    new_spect
                );
            }
            else
            {
                defmt::warn!("SE fw-update word unrecognized {=u32:#010x}", fwu);
            }
        }

        // Feature-gated: run the L3 secure-channel bring-up and log the decoded
        // outcome (which step, success plus the OK marker, or the failure plus
        // its error code).
        #[cfg(feature = "se-session")]
        {
            // SAFETY: the session veneer is a CMSE secure-gateway entry taking
            // no argument and returning a scalar. Calling it crosses into the
            // secure world through the SG veneer. No pointer or caller memory is
            // shared, so there is nothing to validate on either side.
            let ses = unsafe { patinakey_nsc_se_session_ping() };

            if ses & SES_ERR != 0
            {
                // The low byte is the SeError code, or 0xF0 = echo mismatch (a
                // good L3 reply that did not echo the Ping payload).
                defmt::error!
                (
                    "SE L3 session FAILED at step {=str}, error code {=u8:#04x}",
                    ses_step((ses >> 8) & 0xFF),
                    ses as u8
                );
            }
            else if ses & SES_OK != 0
            {
                defmt::info!("SE L3 session + Ping OK, marker {=u8:#04x}", ses as u8);
            }
            else
            {
                defmt::warn!("SE L3 session word unrecognized {=u32:#010x}", ses);
            }

            // Crypto + attestation bring-up, run AFTER the session ping. It
            // verifies the chain to the pinned root, opens a session on the
            // verified STPUB, and runs the TRNG / Ed25519 / P-256 sequence.
            //
            // SAFETY: the crypto veneer is a CMSE secure-gateway entry taking no
            // argument and returning a scalar. Calling it crosses into the secure
            // world through the SG veneer. No pointer or caller memory is shared,
            // so there is nothing to validate on either side.
            let scr = unsafe { patinakey_nsc_se_crypto() };

            if scr & SCR_ERR != 0
            {
                // The low byte is the SeError code, or a RESERVED code: 0xF1
                // EdDSA verify reject, 0xF2 random sanity, 0xF3 ECDSA shape, 0xF4
                // pubkey length.
                defmt::error!
                (
                    "SE crypto FAILED at step {=str}, error code {=u8:#04x}",
                    crypto_step((scr >> 8) & 0xFF),
                    scr as u8
                );
            }
            else if scr & SCR_OK != 0
            {
                defmt::info!("SE crypto + attestation OK, marker {=u8:#04x}", scr as u8);
            }
            else
            {
                defmt::warn!("SE crypto word unrecognized {=u32:#010x}", scr);
            }

            // defmt-rtt is non-blocking and the core reaching wfi immediately
            // after the final line can drop it before the host drains RTT. Busy
            // spin a bounded count (about 4 s at 4 MHz MSI) so the host has time
            // to read the buffer. Bring-up only, gated with the feature.
            for _ in 0..16_000_000u32
            {
                cortex_m::asm::nop();
            }
        }

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
