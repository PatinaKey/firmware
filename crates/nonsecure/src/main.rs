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

    // The persistent-but-reversible state veneer rides the SAME se-session
    // feature: it is only emitted secure-side under that feature.
    #[cfg(feature = "se-session")]
    #[allow(unsafe_code)]
    unsafe extern "C"
    {
        fn patinakey_nsc_se_persist() -> u32;
    }

    // The read-only sweep plus P-256 export veneer rides the SAME se-session
    // feature. The exported record is too
    // big for a u32, so the secure side writes it to the pinned shared non-secure
    // output window (SHARED_OUT below) at a fixed compile-time address. 
    // This side reads that window after the veneer returns.
    #[cfg(feature = "se-session")]
    #[allow(unsafe_code)]
    unsafe extern "C"
    {
        fn patinakey_nsc_se_readonly() -> u32;
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

    // CROSS-CRATE COUPLING: the persist status-word bit layout below MUST match
    // the encoding produced on the secure side (crates/secure/src/se_persist.rs).
    // The two crates do not share a type, so it is duplicated by hand and the two
    // copies must stay in sync.

    /// Persist word bit set when the secure side reports the bring-up failed. Bits
    /// 15..8 then carry the step, bits 7..0 the error code. RESERVED non-SeError
    /// low-byte codes: 0xF5 mcounter value mismatch, 0xF6 mcounter zero-boundary
    /// surprise, 0xF7 MAC-and-Destroy determinism mismatch, 0xF8 pubkey KAT
    /// mismatch, 0xF9 EdDSA verify reject, 0xFA post-erase sign unexpectedly Ok.
    #[cfg(feature = "se-session")]
    const SPR_ERR: u32 = 1 << 31;
    /// Persist word bit set when the bring-up succeeded. The low byte carries the
    /// OK marker.
    #[cfg(feature = "se-session")]
    const SPR_OK: u32 = 1 << 8;

    /// Decodes a persist failing-step code into a static label. Steps mirror
    /// se_persist.rs: 1 open-session, 2 mcounter-init, 3 mcounter-get, 4
    /// mcounter-update, 5 mcounter-reinit, 6 mcounter-zero, 7 mac-and-destroy, 8
    /// pre-clean, 9 ecc-store, 10 ecc-pubkey, 11 ecc-sign, 12 ecc-erase, 13
    /// post-erase, 14 session-abort.
    #[cfg(feature = "se-session")]
    fn persist_step(step: u32) -> &'static str
    {
        match step
        {
            1 => "open-session",
            2 => "mcounter-init",
            3 => "mcounter-get",
            4 => "mcounter-update",
            5 => "mcounter-reinit",
            6 => "mcounter-zero",
            7 => "mac-and-destroy",
            8 => "pre-clean",
            9 => "ecc-store",
            10 => "ecc-pubkey",
            11 => "ecc-sign",
            12 => "ecc-erase",
            13 => "post-erase",
            14 => "session-abort",
            _ => "unknown",
        }
    }

    // CROSS-CRATE COUPLING: the read-only status-word bit layout and record byte
    // layout below MUST match the encoding produced on the secure side
    // (crates/secure/src/se_readonly.rs). The two crates do not share a type, so
    // it is duplicated by hand and the two copies must stay in sync.

    /// Read-only word bit set when the secure side reports the sweep failed. Bits
    /// 15..8 then carry the step, bits 7..0 the error code. RESERVED non-SeError
    /// low-byte codes: 0xFB prod0 pubkey mismatch, 0xFD slot not empty, 0xFE
    /// length surprise.
    #[cfg(feature = "se-session")]
    const RDO_ERR: u32 = 1 << 31;
    /// Read-only word bit set when the sweep succeeded. The low byte carries the
    /// OK marker.
    #[cfg(feature = "se-session")]
    const RDO_OK: u32 = 1 << 8;

    /// Total exported-record length. Matches `RECORD_LEN` in se_readonly.rs.
    #[cfg(feature = "se-session")]
    const RDO_RECORD_LEN: usize = 540;

    /// Pinned shared non-secure OUTPUT window: the fixed RAM block the secure
    /// read-only veneer writes the exported record into. It is placed in the
    /// dedicated `.shared_out` linker section (crates/nonsecure/memory.x), which
    /// pins it at 0x2002_FC00, the top 1 KiB of the NS SRAM half. The main RAM
    /// region is shrunk so no stack, static, or embassy allocation overlaps it.
    ///
    /// HAND-SYNCED PIN: the section address MUST match SHARED_OUT_ADDR in
    /// se_readonly.rs and MPU_NS_SHARED_BASE in platform map.rs (the 4th secure
    /// MPU region). The buffer is 1 KiB, larger than RDO_RECORD_LEN, and sits at
    /// the region base, so the secure write lands at its start.
    //
    // QUARANTINE: This allow opts in the pinned `link_section` placement of the shared output buffer.
    #[cfg(feature = "se-session")]
    #[allow(unsafe_code)]
    #[unsafe(link_section = ".shared_out")]
    static mut SHARED_OUT: [u8; 1024] = [0u8; 1024];

    /// The four-byte record magic ("PK54"). Matches `RECORD_MAGIC` in
    /// se_readonly.rs. The secure side writes it at offset 0, and this side checks
    /// it before trusting the rest of the record.
    #[cfg(feature = "se-session")]
    const RDO_MAGIC: [u8; 4] = [0x50, 0x4B, 0x35, 0x34];

    /// Record field offsets, matching the layout in se_readonly.rs. The operator
    /// pipes the P-256 public key, signature, and digest to the host verifier.
    #[cfg(feature = "se-session")]
    const RDO_OFF_CHIP_ID: usize = 4;
    #[cfg(feature = "se-session")]
    const RDO_OFF_PAIRING0: usize = 132;
    #[cfg(feature = "se-session")]
    const RDO_OFF_P256_PUB: usize = 164;
    #[cfg(feature = "se-session")]
    const RDO_OFF_P256_SIG: usize = 228;
    #[cfg(feature = "se-session")]
    const RDO_OFF_DIGEST: usize = 292;
    #[cfg(feature = "se-session")]
    const RDO_OFF_R_CONFIG: usize = 324;
    #[cfg(feature = "se-session")]
    const RDO_OFF_I_CONFIG: usize = 432;

    /// Decodes a read-only failing-step code into a static label. Steps mirror
    /// se_readonly.rs: 1 chip-id, 2 open-session, 3 pairing, 4 r-config, 5
    /// i-config, 6 rmem-read, 7 rmem-erase, 8 p256, 9 session-abort.
    #[cfg(feature = "se-session")]
    fn rdo_step(step: u32) -> &'static str
    {
        match step
        {
            1 => "chip-id",
            2 => "open-session",
            3 => "pairing",
            4 => "r-config",
            5 => "i-config",
            6 => "rmem-read",
            7 => "rmem-erase",
            8 => "p256",
            9 => "session-abort",
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

    /// Logs the decoded SE chip-mode smoke word over RTT.
    fn report_smoke(smoke: u32)
    {
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
    }

    /// Logs the decoded fw-update outcome over RTT.
    ///
    /// On success reads the running versions back over the existing veneers so the
    /// log shows the new firmware, not just the ok marker.
    #[cfg(feature = "se-fw-update")]
    #[allow(unsafe_code)]
    fn report_fw_update(fwu: u32)
    {
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
            // SAFETY: value-out CMSE entries, same contract as the other veneers.
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

    /// Logs the decoded L3-session outcome over RTT.
    #[cfg(feature = "se-session")]
    fn report_session(ses: u32)
    {
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
    }

    /// Logs the decoded crypto + attestation outcome over RTT.
    #[cfg(feature = "se-session")]
    fn report_crypto(scr: u32)
    {
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
    }

    /// Logs the decoded persistent-state outcome over RTT.
    #[cfg(feature = "se-session")]
    fn report_persist(spr: u32)
    {
        if spr & SPR_ERR != 0
        {
            // The low byte is the SeError code, or a RESERVED code: 0xF5
            // mcounter value mismatch, 0xF6 mcounter zero-boundary surprise,
            // 0xF7 MAC-and-Destroy determinism mismatch, 0xF8 pubkey KAT
            // mismatch, 0xF9 EdDSA verify reject, 0xFA post-erase sign Ok.
            defmt::error!
            (
                "SE persistent state FAILED at step {=str}, error code {=u8:#04x}",
                persist_step((spr >> 8) & 0xFF),
                spr as u8
            );
        }
        else if spr & SPR_OK != 0
        {
            defmt::info!("SE persistent state OK, marker {=u8:#04x}", spr as u8);
        }
        else
        {
            defmt::warn!("SE persistent state word unrecognized {=u32:#010x}", spr);
        }
    }

    /// Logs the decoded read-only sweep outcome over RTT.
    ///
    /// On success logs each record field as hex so the operator copies the P-256
    /// fields to the host verifier. All bytes are public.
    #[cfg(feature = "se-session")]
    fn report_readonly(rdo: u32, record: &[u8; 1024])
    {
        if rdo & RDO_ERR != 0
        {
            // The low byte is the SeError code, or a RESERVED code: 0xFB prod0
            // pubkey mismatch, 0xFD slot not empty, 0xFE length surprise.
            defmt::error!
            (
                "SE read-only sweep FAILED at step {=str}, error code {=u8:#04x}",
                rdo_step((rdo >> 8) & 0xFF),
                rdo as u8
            );
        }
        else if rdo & RDO_OK != 0 && record[0..RDO_MAGIC.len()] != RDO_MAGIC
        {
            // The status word says OK, but the record does not carry the magic
            // tag: a corrupt or stale buffer. Do NOT log the fields as valid.
            defmt::error!
            (
                "SE read-only sweep OK but record magic mismatch, first bytes {=[u8]:02x}",
                record[0..RDO_MAGIC.len()]
            );
        }
        else if rdo & RDO_OK != 0
        {
            defmt::info!("SE read-only sweep OK, marker {=u8:#04x}", rdo as u8);
            // Log each record field over RTT as hex so the operator copies the
            // P-256 fields to the host verifier. All bytes are public.
            defmt::info!("chip id: {=[u8]:02x}", record[RDO_OFF_CHIP_ID..RDO_OFF_PAIRING0]);
            defmt::info!("pairing0 pubkey: {=[u8]:02x}", record[RDO_OFF_PAIRING0..RDO_OFF_P256_PUB]);
            defmt::info!("p256 pubkey X||Y: {=[u8]:02x}", record[RDO_OFF_P256_PUB..RDO_OFF_P256_SIG]);
            defmt::info!("p256 signature r||s: {=[u8]:02x}", record[RDO_OFF_P256_SIG..RDO_OFF_DIGEST]);
            defmt::info!("p256 digest: {=[u8]:02x}", record[RDO_OFF_DIGEST..RDO_OFF_R_CONFIG]);
            defmt::info!("r-config dump: {=[u8]:02x}", record[RDO_OFF_R_CONFIG..RDO_OFF_I_CONFIG]);
            defmt::info!("i-config dump: {=[u8]:02x}", record[RDO_OFF_I_CONFIG..RDO_RECORD_LEN]);
        }
        else
        {
            defmt::warn!("SE read-only sweep word unrecognized {=u32:#010x}", rdo);
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

        report_smoke(smoke);

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

            report_fw_update(fwu);
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

            report_session(ses);

            // Crypto + attestation bring-up, run AFTER the session ping. It
            // verifies the chain to the pinned root, opens a session on the
            // verified STPUB, and runs the TRNG / Ed25519 / P-256 sequence.
            //
            // SAFETY: the crypto veneer is a CMSE secure-gateway entry taking no
            // argument and returning a scalar. Calling it crosses into the secure
            // world through the SG veneer. No pointer or caller memory is shared,
            // so there is nothing to validate on either side.
            let scr = unsafe { patinakey_nsc_se_crypto() };

            report_crypto(scr);

            // Persistent-but-reversible state bring-up, run after the crypto
            // veneer. It opens a session and exercises the monotonic counters,
            // MAC-and-Destroy, and ECC_Key_Store, all reversible (no OTP, config,
            // or pairing write).
            //
            // SAFETY: No pointer or caller memory is shared,
            // so there is nothing to validate on either side.
            let spr = unsafe { patinakey_nsc_se_persist() };

            report_persist(spr);

            // Read-only sweep plus P-256 export, run after the persist veneer. It
            // takes no argument: the secure side writes the exported record to the
            // pinned shared output window (SHARED_OUT) at a fixed compile-time
            // address, so nothing is shared to validate.
            //
            // SAFETY: No pointer or caller memory is shared,
            // so there is nothing to validate on either side.
            let rdo = unsafe { patinakey_nsc_se_readonly() };

            // Read the pinned shared window the secure world just wrote. Only the
            // first RDO_RECORD_LEN bytes are meaningful. read_volatile forces the
            // read (the compiler cannot see the cross-world write) and copies out
            // of the static.
            //
            // SAFETY: SHARED_OUT is a valid, correctly-aligned NS static of 1024
            // bytes at the pinned address. The secure veneer wrote the record there
            // before returning. Only public bytes are read.
            let record: [u8; 1024] = unsafe { core::ptr::read_volatile(&raw const SHARED_OUT) };

            report_readonly(rdo, &record);

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
