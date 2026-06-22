//! The partition MAP: every address, region, pin and channel assignment as a
//! named, cited constant. This is the single place the device's security layout
//! is declared, and the sequence in `partition` only consumes these.
//!
//! Source anchors are RM0456 (memory map and per-peripheral register sections),
//! AN5347 (TrustZone bring-up application note), the Armv8-M Architecture Reference
//! Manual (SAU region encoding), and the board pin map (SE SPI1 on PA4-7 + PB1,
//! USB on PA11/PA12, TSC on PB4/PB6). Where a value is PROVISIONAL (open decision),
//! it is marked so and kept easy to retune.

use crate::error::PartitionError;
use crate::regs::SAU_ALIGN_MASK;
use crate::regs::SAU_RLAR_ENABLE;
use crate::regs::SAU_RLAR_NSC;

// ===========================================================================
// SRAM1 secure / non-secure split (PROVISIONAL).
//
// SRAM1 is 192 KB at 0x2000_0000 (MPCBB1, 384 blocks of 512 B, 12 super-blocks).
// The LOWER 128 KB is provisionally secure, the UPPER 64 KB non-secure.
// This is a TUNABLE skeleton value, not a final security decision. It drives both
// SAU region 2 (CPU view) and MPCBB1 SECCFGR8..11 (DMA/bus view), which MUST stay
// consistent. Retune both together when the real secure-RAM budget is known.
// ===========================================================================

/// SRAM1 base address. RM0456 memory map.
pub(crate) const SRAM1_BASE: u32 = 0x2000_0000;
/// SRAM1 total size: 192 KB. RM0456 memory map.
pub(crate) const SRAM1_SIZE: u32 = 192 * 1024;
/// PROVISIONAL secure portion of SRAM1: lower 128 KB. Tunable.
pub(crate) const SRAM1_SECURE_SIZE: u32 = 128 * 1024;
/// First non-secure address in SRAM1 (start of the upper 64 KB). PROVISIONAL.
pub(crate) const SRAM1_NS_BASE: u32 = SRAM1_BASE + SRAM1_SECURE_SIZE;
/// Last byte of SRAM1 (inclusive top).
pub(crate) const SRAM1_TOP: u32 = SRAM1_BASE + SRAM1_SIZE - 1;

/// MPCBB1 super-block index of the first NON-SECURE super-block.
///
/// One super-block = 32 blocks * 512 B = 16 KB. 128 KB secure / 16 KB = 8, so
/// super-blocks 0..=7 stay secure (reset value) and 8..=11 are cleared to NS.
/// Derived from `SRAM1_SECURE_SIZE`, kept in lock-step with it.
pub(crate) const SRAM1_FIRST_NS_SUPERBLOCK: u32 = SRAM1_SECURE_SIZE / (32 * 512);
/// Number of MPCBB1 (SRAM1) super-blocks: SECCFGR0..11. RM0456 sec 5.8.
pub(crate) const SRAM1_SUPERBLOCKS: u32 = 12;

// ===========================================================================
// MPCBB CFGLOCKR1 super-block lock masks (one valid SPLCKx bit per implemented
// super-block). Writing bits above the implemented count sets reserved bits and
// is an illegal write, so each controller gets its exact mask. RM0456 sec 5.8.2.
//   MPCBB1 (SRAM1, 192 KB): 12 super-blocks -> SPLCK0..11
//   MPCBB2 (SRAM2, 64 KB):   4 super-blocks -> SPLCK0..3
//   MPCBB4 (SRAM4, 16 KB):   1 super-block  -> SPLCK0
// ===========================================================================

/// MPCBB1 CFGLOCKR1 lock mask: SPLCK0..11 (12 super-blocks). RM0456 sec 5.8.2.
pub(crate) const MPCBB1_CFGLOCK_MASK: u32 = (1 << 12) - 1;
/// MPCBB2 CFGLOCKR1 lock mask: SPLCK0..3 (4 super-blocks). RM0456 sec 5.8.2.
pub(crate) const MPCBB2_CFGLOCK_MASK: u32 = (1 << 4) - 1;
/// MPCBB4 CFGLOCKR1 lock mask: SPLCK0 (1 super-block). RM0456 sec 5.8.2.
pub(crate) const MPCBB4_CFGLOCK_MASK: u32 = 1;

// ===========================================================================
// Flash and address-space regions. RM0456 memory map. The NSC veneer window is
// the top 8 KB of secure Bank 1, where the toolchain places `.gnu.sgstubs`.
// ===========================================================================

/// NSC veneer window base: top 8 KB of secure Bank 1 (.gnu.sgstubs lands here).
pub(crate) const NSC_VENEER_BASE: u32 = 0x0C03_E000;
/// NSC veneer window inclusive limit (8 KB).
pub(crate) const NSC_VENEER_LIMIT: u32 = 0x0C03_FFFF;

/// Non-secure flash (Bank 2) base. RM0456 memory map.
pub(crate) const FLASH_NS_BASE: u32 = 0x0804_0000;
/// Non-secure flash inclusive limit (256 KB). RM0456 memory map.
pub(crate) const FLASH_NS_LIMIT: u32 = 0x0807_FFFF;

/// Non-secure peripheral APB/AHB alias base. RM0456 memory map.
pub(crate) const PERIPH_NS_BASE: u32 = 0x4000_0000;
/// Non-secure peripheral alias inclusive limit. RM0456 memory map.
pub(crate) const PERIPH_NS_LIMIT: u32 = 0x4FFF_FFFF;

/// External-memory range base (unused, mapped NS to avoid bus faults).
/// RM0456 memory map.
pub(crate) const EXTMEM_NS_BASE: u32 = 0x6000_0000;
/// External-memory range inclusive limit. RM0456 memory map.
pub(crate) const EXTMEM_NS_LIMIT: u32 = 0x9FFF_FFFF;

/// RSSLIB non-secure function-pointer table base.
///
/// The non-secure world reads this table to dispatch RSSLIB calls after the
/// hand-off, so it must be attributed NS (NOT NSC). RM0456 sec 3.6.2 (RSSLIB)
/// defers the exact bounds to the device RSSLIB_SYS_FLASH_NS_PFUNC_START /
/// RSSLIB_SYS_FLASH_NS_PFUNC_END constants, which give this 192-byte range.
///
/// The region is deliberately the minimal PFUNC table (least privilege): it does
/// NOT cover the bootloader code, the OTP area, the reserved gap, or the flash
/// ECC test words, so the NS world cannot read any of them. OTP NS access is a
/// separate concern and is not on the RSSLIB call path.
pub(crate) const RSSLIB_NS_BASE: u32 = 0x0BF9_9E40;
/// RSSLIB non-secure function-pointer table inclusive limit. RM0456 sec 3.6.2,
/// device RSSLIB_SYS_FLASH_NS_PFUNC_END.
pub(crate) const RSSLIB_NS_LIMIT: u32 = 0x0BF9_9EFF;

// ===========================================================================
// SAU region table: a validated description of the 8 architectural SAU regions.
//
// Secure is the DEFAULT (uncovered = secure once SAU is enabled), so only NS and
// NSC regions need an entry.
// ===========================================================================

/// A single SAU region: an inclusive `[base, limit]` range with an NSC flag.
///
/// Built only through [`SauRegion::new`], which enforces the 32-byte alignment
/// and ascending-range invariants, so a malformed region can never reach the
/// register-write step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SauRegion
{
    base: u32,
    limit: u32,
    nsc: bool,
}

impl SauRegion
{
    /// Builds a validated SAU region covering the inclusive range `[base, limit]`.
    ///
    /// `nsc` marks the region Non-Secure-Callable (set ONLY on the veneer window).
    ///
    /// # Errors
    ///
    /// - `PartitionError::SauRegionMisaligned` if `base` or `limit` is not 32-byte
    ///   aligned (the architecture fixes the low 5 bits of BADDR/LADDR).
    /// - `PartitionError::SauRegionInverted` if `limit < base`.
    pub const fn new(base: u32, limit: u32, nsc: bool) -> Result<Self, PartitionError>
    {
        // RLAR holds an inclusive limit whose low 5 bits read as 1. The caller's
        // `limit` is the true top byte, so it must be 32-byte aligned at the top
        // (i.e. its low 5 bits all set) OR expressed as a region top. The constructor
        // accepts a `limit` whose low 5 bits are all 1 (inclusive top of a 32-byte
        // unit) and a `base` whose low 5 bits are all 0.
        if base & SAU_ALIGN_MASK != 0
        {
            return Err(PartitionError::SauRegionMisaligned);
        }
        if limit & SAU_ALIGN_MASK != SAU_ALIGN_MASK
        {
            return Err(PartitionError::SauRegionMisaligned);
        }
        if limit < base
        {
            return Err(PartitionError::SauRegionInverted);
        }
        Ok(SauRegion
        {
            base,
            limit,
            nsc,
        })
    }

    /// The value to write to `SAU_RBAR` (BADDR in [31:5], low bits zero).
    pub(crate) const fn rbar(self) -> u32
    {
        // `base` is already 32-byte aligned, so it is the RBAR value directly.
        self.base
    }

    /// The value to write to `SAU_RLAR` (LADDR[31:5] | NSC | ENABLE).
    ///
    /// LADDR is `limit` with its low 5 bits cleared. The region is always enabled,
    /// and NSC is set per the region's flag.
    pub(crate) const fn rlar(self) -> u32
    {
        let laddr = self.limit & !SAU_ALIGN_MASK;
        let nsc_bit = if self.nsc { SAU_RLAR_NSC } else { 0 };
        laddr | nsc_bit | SAU_RLAR_ENABLE
    }
}

/// The number of SAU regions the partition programs (of the 8 available).
pub const SAU_PROGRAMMED_REGIONS: usize = 6;

/// Builds the validated SAU region table.
///
/// Returns the regions in RNR order (index = region number): the NSC veneer window
/// plus the NS ranges (flash, SRAM, peripherals, external memory, the RSSLIB NS
/// function-pointer table). Secure is the default attribution, so secure ranges
/// need no entry. The remaining architectural regions are not emitted.
///
/// # Errors
///
/// `PartitionError` if any constant in the table violates the SAU alignment or
/// ordering invariants. The fault surfaces before any hardware write, so a bad
/// edit fails the host tests rather than mis-partitioning silicon.
pub(crate) fn sau_table() -> Result<[SauRegion; SAU_PROGRAMMED_REGIONS], PartitionError>
{
    Ok([
        // Region 0: NSC veneer window (the only NSC region).
        SauRegion::new(NSC_VENEER_BASE, NSC_VENEER_LIMIT, true)?,
        // Region 1: Flash Bank 2 NS.
        SauRegion::new(FLASH_NS_BASE, FLASH_NS_LIMIT, false)?,
        // Region 2: SRAM1 NS half (PROVISIONAL split).
        SauRegion::new(SRAM1_NS_BASE, SRAM1_TOP, false)?,
        // Region 3: NS peripheral alias.
        SauRegion::new(PERIPH_NS_BASE, PERIPH_NS_LIMIT, false)?,
        // Region 4: external-memory range NS.
        SauRegion::new(EXTMEM_NS_BASE, EXTMEM_NS_LIMIT, false)?,
        // Region 5: RSSLIB NS function-pointer table (so NS RSSLIB calls do not
        // fault).
        SauRegion::new(RSSLIB_NS_BASE, RSSLIB_NS_LIMIT, false)?,
    ])
}

// ===========================================================================
// GPIO pin assignments (board pin map).
// GPIOx_SECCFGR: bit per pin, reset all-secure. The partition KEEPS the SE-SPI pins
// secure (reset value) and CLEARS the USB + TSC pins to non-secure.
// ===========================================================================

/// GPIOA pins kept SECURE (SE SPI1): PA4 NSS, PA5 SCK, PA6 MISO, PA7 MOSI.
/// Board pin map.
pub(crate) const GPIOA_SECURE_PINS: u32 = (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7);
/// GPIOA pins cleared to NON-SECURE: PA11 USB_DM, PA12 USB_DP. Board pin map.
pub(crate) const GPIOA_NS_PINS: u32 = (1 << 11) | (1 << 12);

/// GPIOB pin kept SECURE (SE GPO / IRQ): PB1. Board pin map.
pub(crate) const GPIOB_SECURE_PINS: u32 = 1 << 1;
/// GPIOB pins cleared to NON-SECURE: PB4 TSC sampling, PB6 TSC channel.
/// Board pin map.
pub(crate) const GPIOB_NS_PINS: u32 = (1 << 4) | (1 << 6);

// ===========================================================================
// GPDMA channel assignments.
//
// The SE SPI1 DMA channels MUST be secure or an NS->S transfer silently vanishes.
// The exact channel numbers are a driver-wiring decision not yet frozen, so this
// map PROVISIONALLY reserves channels 0 and 1 as the secure SPI1 TX/RX pair. Retune
// when the SPI1 DMA channel allocation is fixed. SECx bit per channel in SECCFGR.
// ===========================================================================

/// PROVISIONAL secure GPDMA channels (SPI1 TX/RX): channels 0 and 1.
pub(crate) const GPDMA_SECURE_CHANNELS: u32 = (1 << 0) | (1 << 1);

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn sram1_split_is_consistent()
    {
        // 128 KB secure -> super-block 8 is the first NS one, and the NS base sits
        // exactly on that boundary. This guards the SAU/MPCBB lock-step invariant.
        assert_eq!(SRAM1_FIRST_NS_SUPERBLOCK, 8);
        assert_eq!(SRAM1_NS_BASE, 0x2002_0000);
        assert_eq!(SRAM1_TOP, 0x2002_FFFF);
    }

    #[test]
    fn sau_table_builds_and_validates()
    {
        let t = sau_table().expect("table must validate");
        assert_eq!(t.len(), SAU_PROGRAMMED_REGIONS);
        // Region 0 is the NSC veneer, the rest are plain NS.
        assert_eq!(t[0].rlar() & SAU_RLAR_NSC, SAU_RLAR_NSC);
        for region in &t[1..]
        {
            assert_eq!(region.rlar() & SAU_RLAR_NSC, 0);
        }
    }

    #[test]
    fn sau_region_rejects_misaligned_base()
    {
        assert_eq!(
            SauRegion::new(0x0804_0001, 0x0807_FFFF, false),
            Err(PartitionError::SauRegionMisaligned)
        );
    }

    #[test]
    fn sau_region_rejects_misaligned_limit()
    {
        // A limit must be the inclusive top of a 32-byte unit (low 5 bits set).
        assert_eq!(
            SauRegion::new(0x0804_0000, 0x0807_FFF0, false),
            Err(PartitionError::SauRegionMisaligned)
        );
    }

    #[test]
    fn sau_region_rejects_inverted_range()
    {
        assert_eq!(
            SauRegion::new(0x0808_0000, 0x0804_001F, false),
            Err(PartitionError::SauRegionInverted)
        );
    }

    #[test]
    fn sau_region_rlar_encodes_limit_and_enable()
    {
        let r = SauRegion::new(0x0804_0000, 0x0807_FFFF, false).expect("valid");
        // LADDR = limit with low 5 bits cleared, ENABLE set, NSC clear.
        assert_eq!(r.rlar(), 0x0807_FFE0 | SAU_RLAR_ENABLE);
        assert_eq!(r.rbar(), 0x0804_0000);
    }

    #[test]
    fn rsslib_ns_region_base_limit_and_ns_encoding()
    {
        // Pin the RSSLIB NS function-pointer table to its cited address and prove
        // it encodes NS (not NSC). RM0456 sec 3.6.2, device
        // RSSLIB_SYS_FLASH_NS_PFUNC_START/END. The minimal 192-byte table excludes
        // the bootloader, OTP, and the flash ECC test words. 32-byte alignment
        // holds (base low 5 bits clear, limit set).
        assert_eq!(RSSLIB_NS_BASE, 0x0BF9_9E40);
        assert_eq!(RSSLIB_NS_LIMIT, 0x0BF9_9EFF);
        assert_eq!(RSSLIB_NS_BASE & SAU_ALIGN_MASK, 0);
        assert_eq!(RSSLIB_NS_LIMIT & SAU_ALIGN_MASK, SAU_ALIGN_MASK);

        let r = SauRegion::new(RSSLIB_NS_BASE, RSSLIB_NS_LIMIT, false)
            .expect("RSSLIB region must validate");
        assert_eq!(r.rbar(), 0x0BF9_9E40);
        // Full RLAR word: LADDR = limit with low 5 bits cleared, ENABLE set, NSC clear.
        assert_eq!(r.rlar(), 0x0BF9_9EE0 | SAU_RLAR_ENABLE);
        assert_eq!(r.rlar() & SAU_RLAR_NSC, 0);

        // It is the last region in the programmed table.
        let t = sau_table().expect("table must validate");
        assert_eq!(t.len(), SAU_PROGRAMMED_REGIONS);
        assert_eq!(t[SAU_PROGRAMMED_REGIONS - 1], r);
    }

    #[test]
    fn gpio_secure_and_ns_pins_are_disjoint()
    {
        assert_eq!(GPIOA_SECURE_PINS & GPIOA_NS_PINS, 0);
        assert_eq!(GPIOB_SECURE_PINS & GPIOB_NS_PINS, 0);
    }
}
