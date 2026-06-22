//! The ordered TrustZone runtime partition bring-up.
//!
//! [`apply_partition`] runs the EXACT register sequence the first secure code must
//! execute to partition the device, driven entirely through the [`RegisterBus`]
//! seam so the host tests can record and assert every write in order. The ordering
//! is load-bearing (each ordering hazard is documented at its step), and the module
//! tests encode those hazards as regression checks.
//!
//! SCOPE: RUNTIME isolation only: SAU / GTZC / GPIO / GPDMA / TZIC plus the sticky
//! in-RAM config locks. It issues NO irreversible option-byte write (no TZEN / RDP
//! / BOOT_LOCK / WRP / FLASH_OPTR). Those are silicon-lifecycle steps deferred
//! pending the hardware power-fault validation (RM0456 sec 7 option bytes).
//!
//! The secure-bank MPU is programmed separately by [`crate::apply_secure_mpu`] in
//! the `mpu` module, applied by the secure binary as the LAST isolation step right
//! before the non-secure hand-off (so it does not appear in this sequence).

use crate::bus::RegisterBus;
use crate::error::PartitionError;
use crate::map;
use crate::regs;

/// Programs the full SAU/GTZC partition in the one safe order. The caller performs
/// the non-secure hand-off (`SCB_NS->VTOR` + NS MSP + `BXNS`) with CPU intrinsics
/// that have no register-bus form.
///
/// The steps run in the one safe order:
/// 1. enable GTZC clocks (HARD prerequisite: later GTZC writes are lost without
///    it),
/// 2. program + enable the SAU regions,
/// 3. TZSC peripheral security (SE SPI + crypto secure),
/// 4. MPCBB SRAM block security (SRAM1 split, SRAM2/4 stay secure at reset),
/// 5. GPIO security (SE pins secure, USB/TSC pins NS),
/// 6. GPDMA secure channels for the SE link,
/// 7. enable TZIC illegal-access events, AFTER all TZSC/MPCBB writes,
/// 8. apply the sticky locks LAST.
///
/// The secure-bank MPU is NOT programmed here. The caller applies
/// [`crate::apply_secure_mpu`] as the last isolation step just before the hand-off.
///
/// # Errors
///
/// `PartitionError` only from building the SAU region table (a misaligned or
/// inverted region constant), surfaced BEFORE any hardware write. Every other step
/// is an infallible register write.
pub fn apply_partition<B>(bus: &mut B) -> Result<(), PartitionError>
where
    B: RegisterBus,
{
    // FAIL-CLOSED: build and validate the SAU region table BEFORE touching any
    // hardware. A misaligned or inverted region constant aborts here, so a faulty
    // table can never leave clocks, SAU, or TZSC half-applied. No bus write has
    // run at this point.
    let sau = map::sau_table()?;

    enable_gtzc_clocks(bus);
    program_sau(bus, &sau);
    program_tzsc(bus);
    program_mpcbb(bus);
    program_gpio(bus);
    program_gpdma(bus);
    enable_tzic(bus);
    apply_locks(bus);
    Ok(())
}

/// Step 1: enable the GTZC1/GTZC2 (and GPDMA1) clocks.
///
/// HARD PREREQUISITE: any TZSC/MPCBB/TZIC write before this is silently lost.
/// GPDMA1EN is enabled here too so the GPDMA SECCFGR step can take effect.
/// RM0456 sec 11.8 (AHB1ENR/AHB3ENR).
fn enable_gtzc_clocks<B>(bus: &mut B)
where
    B: RegisterBus,
{
    bus.modify32(
        regs::RCC_AHB1ENR,
        0,
        regs::RCC_AHB1ENR_GTZC1EN | regs::RCC_AHB1ENR_GPDMA1EN,
    );
    bus.modify32(regs::RCC_AHB3ENR, 0, regs::RCC_AHB3ENR_GTZC2EN);
}

/// Step 2: program the SAU regions and enable the SAU.
///
/// Disable while programming (`CTRL = 0`), write each region (RNR, RBAR, RLAR),
/// then enable with `ENABLE=1, ALLNS=0`. ALLNS is NEVER set. It would make the
/// whole map NS and bypass CPU isolation.
///
/// The `table` is the already-validated region set built at the top of
/// `apply_partition`, so this step is an infallible sequence of register writes.
fn program_sau<B>(bus: &mut B, table: &[map::SauRegion])
where
    B: RegisterBus,
{
    // Disable the SAU while reprogramming.
    bus.write32(regs::SAU_CTRL, 0);

    for (region, entry) in (0u32..).zip(table.iter())
    {
        bus.write32(regs::SAU_RNR, region);
        bus.write32(regs::SAU_RBAR, entry.rbar());
        bus.write32(regs::SAU_RLAR, entry.rlar());
    }

    // Enable, ALLNS cleared. The default-no-region attribution is SECURE.
    bus.write32(regs::SAU_CTRL, regs::SAU_CTRL_ENABLE);
}

/// Step 3: GTZC1 TZSC peripheral security.
///
/// SE SPI1 link secure (SECCFGR2.SPI1SEC), the crypto block secure
/// (SECCFGR3.AES/HASH/RNG/PKA/SAES). TSC and LTDC/USB stay NS (reset value).
fn program_tzsc<B>(bus: &mut B)
where
    B: RegisterBus,
{
    bus.modify32(
        regs::GTZC1_TZSC_BASE + regs::TZSC_SECCFGR2_OFF,
        0,
        regs::TZSC1_SECCFGR2_SPI1SEC,
    );

    let crypto = regs::TZSC1_SECCFGR3_AESSEC
        | regs::TZSC1_SECCFGR3_HASHSEC
        | regs::TZSC1_SECCFGR3_RNGSEC
        | regs::TZSC1_SECCFGR3_PKASEC
        | regs::TZSC1_SECCFGR3_SAESSEC;
    bus.modify32(regs::GTZC1_TZSC_BASE + regs::TZSC_SECCFGR3_OFF, 0, crypto);
}

/// Step 4: MPCBB per-block SRAM security.
///
/// Reset = all blocks secure (0xFFFF_FFFF). SRAM2 and SRAM4 stay fully secure
/// (no write). For SRAM1 this step CLEARS the upper NS super-blocks (8..=11 for the
/// provisional 128 KB-secure split), leaving 0..=7 secure. RM0456 sec 5.8.
fn program_mpcbb<B>(bus: &mut B)
where
    B: RegisterBus,
{
    // SRAM1: clear the NS super-blocks' SECCFGR entries (whole-word NS = 0).
    let mut sb = map::SRAM1_FIRST_NS_SUPERBLOCK;
    while sb < map::SRAM1_SUPERBLOCKS
    {
        bus.write32(regs::mpcbb_seccfgr(regs::MPCBB1_BASE, sb), 0);
        sb += 1;
    }
    // SRAM2 (MPCBB2) and SRAM4 (MPCBB4) are intentionally left at reset (secure).
}

/// Step 5: GPIO per-pin security (the silent-death pitfall).
///
/// A secure peripheral on an NS pin drives zero, killing the SE SPI with no error.
/// This step KEEPS the SE pins secure (PA4-7, PB1, the reset value) and CLEARS the USB (PA11/
/// 12) and TSC (PB4/6) pins to NS. SECCFGR bit set = secure, clear = NS.
fn program_gpio<B>(bus: &mut B)
where
    B: RegisterBus,
{
    // GPIOA: ensure SE pins secure (no-op vs reset), clear USB pins to NS.
    bus.modify32(
        regs::gpio_seccfgr(regs::GPIOA_BASE),
        map::GPIOA_NS_PINS,
        map::GPIOA_SECURE_PINS,
    );
    // GPIOB: ensure SE GPO secure, clear TSC pins to NS.
    bus.modify32(
        regs::gpio_seccfgr(regs::GPIOB_BASE),
        map::GPIOB_NS_PINS,
        map::GPIOB_SECURE_PINS,
    );
}

/// Step 6: GPDMA secure channels for the SE link.
///
/// The SE SPI1 DMA channels MUST be secure or an NS->S transfer silently drops.
/// SECCFGR writes need the channel disabled (reset state here), so this runs at
/// bring-up before any channel is enabled. RM0456 sec 17.8.
fn program_gpdma<B>(bus: &mut B)
where
    B: RegisterBus,
{
    bus.modify32(regs::GPDMA_SECCFGR, 0, map::GPDMA_SECURE_CHANNELS);
}

/// Step 7: enable TZIC illegal-access events.
///
/// Run AFTER all TZSC/MPCBB programming, or in-flux accesses raise spurious secure
/// faults (ordering hazard). This step unmasks all four IER words so the controller catches
/// any illegal access during bring-up. A narrower mask can replace this once the
/// set of expected illegal-access sources is fixed. RM0456 sec 5.7.
fn enable_tzic<B>(bus: &mut B)
where
    B: RegisterBus,
{
    bus.write32(regs::GTZC1_TZIC_BASE + regs::TZIC_IER1_OFF, 0xFFFF_FFFF);
    bus.write32(regs::GTZC1_TZIC_BASE + regs::TZIC_IER2_OFF, 0xFFFF_FFFF);
    bus.write32(regs::GTZC1_TZIC_BASE + regs::TZIC_IER3_OFF, 0xFFFF_FFFF);
    bus.write32(regs::GTZC1_TZIC_BASE + regs::TZIC_IER4_OFF, 0xFFFF_FFFF);
}

/// Step 8: apply the sticky config locks LAST, after the config is set.
///
/// Order: MPCBB super-block locks (CFGLOCKR1) -> MPCBB CR.GLOCK -> TZSC_CR.LCK
/// (GTZC1 and GTZC2) -> GPDMA RCFGLOCKR for the SE channels. These freeze the
/// GTZC/GPDMA configuration until reset. They are the ONLY "lock" step here, NOT
/// silicon lifecycle (no option byte is touched). RM0456 sec 5.6/5.8/17.8.
fn apply_locks<B>(bus: &mut B)
where
    B: RegisterBus,
{
    // MPCBB super-block locks: lock every IMPLEMENTED super-block of each owned
    // MPCBB, writing the exact valid SPLCKx mask per controller. Setting reserved
    // CFGLOCKR1 bits (above the implemented super-block count) is an illegal write.
    // MPCBB1 (SRAM1) has 12 super-blocks -> SPLCK0..11, MPCBB2 (SRAM2) has 4 ->
    // SPLCK0..3, MPCBB4 (SRAM4) has 1 -> SPLCK0. RM0456 sec 5.8.2.
    bus.write32(regs::mpcbb_cfglockr1(regs::MPCBB1_BASE), map::MPCBB1_CFGLOCK_MASK);
    bus.write32(regs::mpcbb_cfglockr1(regs::MPCBB2_BASE), map::MPCBB2_CFGLOCK_MASK);
    bus.write32(regs::mpcbb_cfglockr1(regs::MPCBB4_BASE), map::MPCBB4_CFGLOCK_MASK);

    // MPCBB global config lock.
    bus.modify32(regs::MPCBB1_BASE + regs::MPCBB_CR_OFF, 0, regs::MPCBB_CR_GLOCK);
    bus.modify32(regs::MPCBB2_BASE + regs::MPCBB_CR_OFF, 0, regs::MPCBB_CR_GLOCK);
    bus.modify32(regs::MPCBB4_BASE + regs::MPCBB_CR_OFF, 0, regs::MPCBB_CR_GLOCK);

    // TZSC config lock, both GTZC instances.
    bus.modify32(regs::GTZC1_TZSC_BASE + regs::TZSC_CR_OFF, 0, regs::TZSC_CR_LCK);
    bus.modify32(regs::GTZC2_TZSC_BASE + regs::TZSC_CR_OFF, 0, regs::TZSC_CR_LCK);

    // GPDMA channel-config lock for the secure SE channels.
    bus.modify32(regs::GPDMA_RCFGLOCKR, 0, map::GPDMA_SECURE_CHANNELS);
}

#[cfg(test)]
mod tests;
