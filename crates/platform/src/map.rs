//! The partition MAP: every address, region, pin and channel assignment as a
//! named, cited constant. This is the place the device's security layout
//! is declared, and the sequence in `partition` consumes these.
//!
//! Source anchors are RM0456 (memory map and per-peripheral register sections),
//! AN5347 (TrustZone bring-up application note), the Armv8-M Architecture Reference
//! Manual (SAU region encoding), and the board pin map (SE SPI1 on PA4-7 + PB1,
//! USB on PA11/PA12, TSC on PB4/PB6).

use mcu_layout::NSC_VENEER_BASE;
use mcu_layout::NSC_VENEER_LIMIT;

use crate::error::PartitionError;
use crate::regs::SAU_ALIGN_MASK;
use crate::regs::SAU_RLAR_ENABLE;
use crate::regs::SAU_RLAR_NSC;

// ===========================================================================
// SRAM1 secure / non-secure split (PROVISIONAL).
//
// SRAM1 is 192 KB at 0x2000_0000 (MPCBB1, 384 blocks of 512 B, 12 super-blocks).
// The LOWER 128 KB is provisionally secure, the UPPER 64 KB non-secure.
// This is a tunable skeleton value, not a final security decision. It drives both
// SAU region 2 (CPU view) and MPCBB1 SECCFGR8..11 (DMA/bus view). 
// Retune both together when the real secure-RAM budget is known.
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
// Flash and address-space regions. RM0456 memory map.
//
// The NSC veneer window (`NSC_VENEER_BASE` / `NSC_VENEER_LIMIT`, imported from
// mcu-layout above) is the top 512 bytes of the secure app band, where the
// toolchain places `.gnu.sgstubs`.
// ===========================================================================

/// Non-secure flash alias base: the whole non-secure flash alias, not just the
/// high bank.
///
/// (RM0456 sec 2.2 Table 8 + sec 3.5.3): a memory space not covered by an
/// SAU region is fixed SECURE, so an uncovered 0x08.. address is promoted to
/// secure. Under the A/B layout the ACTIVE bank's non-secure pages sit at the LOW
/// non-secure alias (0x0802_8000..), which a region starting at 0x0804_0000 would
/// leave uncovered, so a secure-tagged write to a SECWM-nonsecure page is
/// Write-Ignored plus WRPERR (RM0456 Table 68). Covering the whole 0x0800_0000..
/// 0x0807_FFFF alias tags both banks' non-secure pages NS under either SWAP_BANK
/// value. SECWM still makes a non-secure read of a secure page RAZ plus an
/// illegal event, so this does not weaken isolation. RM0456 memory map.
pub(crate) const FLASH_NS_BASE: u32 = 0x0800_0000;
/// Non-secure flash alias inclusive limit (whole 512 KB alias). RM0456 memory
/// map.
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
// Secure MPU region table (PMSAv8, banked secure bank). Layout L1 (b2): SEVEN
// regions over the addresses the CPU ACTUALLY emits in the secure state, one
// spare of the eight implemented. RM0456 memory map, RM0456 sec 7.5.8
// (identical-per-bank layout, the inactive bank ALWAYS at the high alias).
//
//   R0 0x0C004000..0x0C027FFF  RX     active secure code, pages 2-19
//   R1 metadata SWAP-DERIVED   RW+XN  physical Bank 1 pages 0-1 (see below)
//   R2 secure SRAM             RW+XN
//   R3 NS shared-out window    RW+XN
//   R4 secure peripherals      RW+XN  (Device)
//   R5 0x0C052000..0x0C067FFF  RW+XN  inactive bank secure image pages 9-19
//   R6 0x08068000..0x0807FFFF  RW+XN  inactive bank NS image pages 20-31
//
// Least privilege: R5/R6 start at page 9, so the MPU PHYSICALLY blocks an updater
// bug from storing into the inactive bank's metadata (pages 0-1) or its immutable
// boot stage (pages 2-8, which no region maps at the high alias). R0 excludes the
// metadata pages (0-1) so a metadata WRITE cannot land in the RX code region: the
// metadata is a separate RW region. W^X / DEP: R0 is the ONLY executable region
// (XN = 0), every writable region is execute-never (XN = 1). With PRIVDEFENA = 0
// there is no background map, so any secure access outside these regions faults.
// R5/R6 are FIXED (the inactive bank is always at the high alias). Only R1 is
// swap-derived, re-read from OPTR.SWAP_BANK on every boot's MPU apply.
// ===========================================================================

/// Secure LOW alias base: the ACTIVE bank at 0x0C00_0000. RM0456 sec 7.5.8.
const FLASH_SECURE_LOW_BASE: u32 = 0x0C00_0000;
/// Secure HIGH alias base: the INACTIVE bank at 0x0C04_0000 (512 KB U545, two
/// contiguous 256 KB banks). RM0456 sec 7.5.8, AN5347 Table 2.
const FLASH_SECURE_HIGH_BASE: u32 = 0x0C04_0000;
/// The non-secure alias sits this far below the secure alias. AN5347 Table 2.
const FLASH_SECURE_ALIAS_OFFSET: u32 = 0x0400_0000;
/// One 8 KB flash page. RM0456 sec 7.3.1 Table 51 (DUALBANK=1).
const FLASH_PAGE: u32 = 0x2000;

/// Secure code region base: page 2 of the active bank (the immutable boot
/// stage), the first page after the metadata band. Layout L1.
pub(crate) const MPU_CODE_BASE: u32 = FLASH_SECURE_LOW_BASE + 2 * FLASH_PAGE;
/// Secure code region inclusive limit: through page 19 (the NSC veneer), pages
/// 2-19 of the active bank. Layout L1.
pub(crate) const MPU_CODE_LIMIT: u32 = FLASH_SECURE_LOW_BASE + 20 * FLASH_PAGE - 1;

/// Boot-metadata region size: pages 0-1 (16 KB). Layout L1.
const MPU_META_SIZE: u32 = 2 * FLASH_PAGE;
/// Metadata region base when SWAP_BANK is CLEAR: physical Bank 1 at the low
/// alias. RM0456 sec 7.5.8 (the metadata is pinned to physical Bank 1).
pub(crate) const MPU_META_LOW_BASE: u32 = FLASH_SECURE_LOW_BASE;
/// Metadata region base when SWAP_BANK is SET: physical Bank 1 at the high alias.
pub(crate) const MPU_META_HIGH_BASE: u32 = FLASH_SECURE_HIGH_BASE;
/// Metadata region inclusive limit when SWAP_BANK is CLEAR (16 KB).
pub(crate) const MPU_META_LOW_LIMIT: u32 = MPU_META_LOW_BASE + MPU_META_SIZE - 1;
/// Metadata region inclusive limit when SWAP_BANK is SET (16 KB).
pub(crate) const MPU_META_HIGH_LIMIT: u32 = MPU_META_HIGH_BASE + MPU_META_SIZE - 1;

/// Inactive-bank SECURE image region base: pages 9-19 at the secure HIGH alias.
/// The inactive bank is ALWAYS at the high alias (RM0456 sec 7.5.8), so this is
/// FIXED across swaps. Grants the updater store / read-back into the secure
/// image sub-band, never into the inactive metadata (pages 0-1) or boot stage
/// (pages 2-8), which no high-alias region maps.
pub(crate) const MPU_INACTIVE_SECURE_BASE: u32 =
    FLASH_SECURE_HIGH_BASE + 9 * FLASH_PAGE;
/// Inactive-bank secure image region inclusive limit: through page 19 (88 KB).
pub(crate) const MPU_INACTIVE_SECURE_LIMIT: u32 =
    FLASH_SECURE_HIGH_BASE + 20 * FLASH_PAGE - 1;

/// Inactive-bank NON-SECURE image region base: pages 20-31 at the NS HIGH alias.
/// FIXED across swaps. The non-secure image sub-band MUST be driven through the
/// non-secure alias (0x08..), or a secure-alias access is RAZ / WRPERR (RM0456
/// Table 68), so the updater's store / read-back of this band uses this region.
pub(crate) const MPU_INACTIVE_NS_BASE: u32 =
    FLASH_SECURE_HIGH_BASE - FLASH_SECURE_ALIAS_OFFSET + 20 * FLASH_PAGE;
/// Inactive-bank NS image region inclusive limit: through page 31 (96 KB).
pub(crate) const MPU_INACTIVE_NS_LIMIT: u32 =
    FLASH_SECURE_HIGH_BASE - FLASH_SECURE_ALIAS_OFFSET + 32 * FLASH_PAGE - 1;

/// Secure SRAM region base: SRAM1 secure half. Reuses `SRAM1_BASE`.
///
/// SCOPE (intentional, least privilege): the secure MPU SRAM region covers ONLY
/// the secure half of SRAM1, the RAM the secure binary actually uses per its
/// linker layout (crates/secure/memory.x). SRAM2 and SRAM4 are kept secure by the
/// GTZC / MPCBB partition (the DMA and bus view), but they are deliberately NOT
/// mapped into the secure MPU. With `MPU_CTRL.PRIVDEFENA = 0` there is no
/// background map, so the secure CPU cannot touch SRAM2 or SRAM4 at all. That is
/// the W^X / least-privilege intent, not an oversight. Any future secure use of
/// SRAM2 or SRAM4 MUST add a matching MPU region together with the linker-script
/// change. Armv8-M PMSAv8 region model, RM0456 memory map.
pub(crate) const MPU_SRAM_BASE: u32 = SRAM1_BASE;
/// Secure SRAM region inclusive limit: last byte of the secure half
/// (`SRAM1_NS_BASE - 1`), kept in lock-step with the SAU / MPCBB split.
pub(crate) const MPU_SRAM_LIMIT: u32 = SRAM1_NS_BASE - 1;

/// Secure peripheral region base: secure peripheral alias. RM0456 memory map.
pub(crate) const MPU_PERIPH_BASE: u32 = 0x5000_0000;
/// Secure peripheral region inclusive limit: covers RCC / GTZC / GPIO / SPI1 /
/// crypto secure aliases. RM0456 memory map.
pub(crate) const MPU_PERIPH_LIMIT: u32 = 0x5FFF_FFFF;

// ===========================================================================
// Pinned non-secure shared OUTPUT window. A fixed 1 KiB block at the very top of
// the non-secure SRAM half, the ONLY non-secure RAM the secure core is granted
// permission to write. A secure veneer that must return more than a u32 (an SE
// data record) writes it here at a COMPILE-TIME address.
//
// HAND-SYNCED PIN: 
// this base and limit MUST match the `SHARED_OUT` MEMORY region + `.shared_out` 
// section in crates/nonsecure/memory.x AND the `SHARED_OUT_ADDR` / `SHARED_OUT_LEN`
// constants in crates/secure/src/se_readonly.rs. The three copies are kept in
// lock-step by hand because the crates share no type. Base 0x2002_FC00, length
// 0x400, inclusive limit 0x2002_FFFF, all 32-byte aligned.
//
// SAU / GTZC: NO change is needed. The whole NS half [0x2002_0000, 0x2002_FFFF]
// is already SAU-attributed non-secure (SAU region 2 above) and GTZC MPCBB NS,
// so this window is already non-secure memory. The 4th MPU region below only
// grants the SECURE CORE permission to write into that NS range.
//
// LEAST PRIVILEGE: the region covers ONLY the 1 KiB window, never the whole NS
// half, so the secure core can write nowhere else in non-secure RAM.
// ===========================================================================

/// Non-secure shared output window base: top 1 KiB of the NS SRAM half.
pub(crate) const MPU_NS_SHARED_BASE: u32 = 0x2002_FC00;
/// Non-secure shared output window inclusive limit (1 KiB, ending at the NS top).
pub(crate) const MPU_NS_SHARED_LIMIT: u32 = 0x2002_FFFF;

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
    fn mpu_region_constants_are_consistent()
    {
        // The secure SRAM MPU region ends exactly one byte below the NS half, so
        // it cannot overlap the non-secure SRAM. This guards the lock-step with
        // the SAU / MPCBB split.
        assert_eq!(MPU_SRAM_BASE, 0x2000_0000);
        assert_eq!(MPU_SRAM_LIMIT, SRAM1_NS_BASE - 1);
        assert_eq!(MPU_SRAM_LIMIT, 0x2001_FFFF);
        // Layout L1: the code region is pages 2-19 of the active bank, excluding
        // the metadata band (pages 0-1) so a metadata WRITE never lands in the RX
        // region. It includes the NSC veneer window at its top.
        assert_eq!(MPU_CODE_BASE, 0x0C00_4000);
        assert_eq!(MPU_CODE_LIMIT, 0x0C02_7FFF);
        let veneer_in_code = NSC_VENEER_BASE >= MPU_CODE_BASE
            && NSC_VENEER_LIMIT <= MPU_CODE_LIMIT;
        assert!(veneer_in_code, "NSC veneer must lie inside the code region");
        // DRIFT GUARD.
        assert_eq!
        (
            NSC_VENEER_LIMIT, MPU_CODE_LIMIT,
            "the NSC veneer window must end at the top of the secure code region"
        );
        // SAU granule: RBAR fixes a base's low 5 bits to zero, RLAR reads a
        // limit's low 5 bits as one.
        assert_eq!(NSC_VENEER_BASE & SAU_ALIGN_MASK, 0);
        assert_eq!(NSC_VENEER_LIMIT & SAU_ALIGN_MASK, SAU_ALIGN_MASK);
        // The swap-derived metadata region is pages 0-1 (16 KB) of physical Bank
        // 1, at the low alias when SWAP_BANK is clear and the high alias when set.
        assert_eq!(MPU_META_LOW_BASE, 0x0C00_0000);
        assert_eq!(MPU_META_LOW_LIMIT, 0x0C00_3FFF);
        assert_eq!(MPU_META_HIGH_BASE, 0x0C04_0000);
        assert_eq!(MPU_META_HIGH_LIMIT, 0x0C04_3FFF);
        // The low-alias metadata region ends one byte below the code region base,
        // so R1 (SWAP clear) and R0 are adjacent, never overlapping.
        assert_eq!(MPU_META_LOW_LIMIT + 1, MPU_CODE_BASE);
        // The inactive-bank secure image region is pages 9-19 (88 KB) at the
        // secure high alias, fixed across swaps.
        assert_eq!(MPU_INACTIVE_SECURE_BASE, 0x0C05_2000);
        assert_eq!(MPU_INACTIVE_SECURE_LIMIT, 0x0C06_7FFF);
        // The inactive-bank NS image region is pages 20-31 (96 KB) at the NS high
        // alias, fixed across swaps.
        assert_eq!(MPU_INACTIVE_NS_BASE, 0x0806_8000);
        assert_eq!(MPU_INACTIVE_NS_LIMIT, 0x0807_FFFF);
        // Every region base is 32-byte aligned and every limit is an inclusive
        // 32-byte top (low 5 bits set), the ARMv8-M MPU granule.
        for base in [
            MPU_CODE_BASE,
            MPU_META_LOW_BASE,
            MPU_META_HIGH_BASE,
            MPU_INACTIVE_SECURE_BASE,
            MPU_INACTIVE_NS_BASE,
        ]
        {
            assert_eq!(base & 0x1F, 0, "MPU base must be 32-byte aligned");
        }
        for limit in [
            MPU_CODE_LIMIT,
            MPU_META_LOW_LIMIT,
            MPU_META_HIGH_LIMIT,
            MPU_INACTIVE_SECURE_LIMIT,
            MPU_INACTIVE_NS_LIMIT,
        ]
        {
            assert_eq!(limit & 0x1F, 0x1F, "MPU limit must be an inclusive top");
        }
        // Peripheral region covers the secure peripheral aliases.
        assert_eq!(MPU_PERIPH_BASE, 0x5000_0000);
        assert_eq!(MPU_PERIPH_LIMIT, 0x5FFF_FFFF);
    }

    #[test]
    fn ns_shared_window_is_pinned_aligned_and_disjoint()
    {
        // Pinned base/limit, hand-synced with crates/nonsecure/memory.x and
        // crates/secure/src/se_readonly.rs.
        assert_eq!(MPU_NS_SHARED_BASE, 0x2002_FC00);
        assert_eq!(MPU_NS_SHARED_LIMIT, 0x2002_FFFF);
        // 32-byte granule: base low 5 bits clear, limit low 5 bits set.
        assert_eq!(MPU_NS_SHARED_BASE & SAU_ALIGN_MASK, 0);
        assert_eq!(MPU_NS_SHARED_LIMIT & SAU_ALIGN_MASK, SAU_ALIGN_MASK);
        // 1 KiB window.
        assert_eq!(MPU_NS_SHARED_LIMIT - MPU_NS_SHARED_BASE + 1, 1024);
        // Entirely inside the non-secure half of SRAM1, ending at the NS top.
        let in_ns_half = MPU_NS_SHARED_BASE >= SRAM1_NS_BASE;
        assert!(in_ns_half, "shared window must start in the NS half");
        assert_eq!(MPU_NS_SHARED_LIMIT, SRAM1_TOP);
        // Strictly above the secure SRAM region, so the two never overlap.
        let above_secure_sram = MPU_NS_SHARED_BASE > MPU_SRAM_LIMIT;
        assert!(above_secure_sram, "shared window must not overlap secure SRAM");
    }

    #[test]
    fn gpio_secure_and_ns_pins_are_disjoint()
    {
        assert_eq!(GPIOA_SECURE_PINS & GPIOA_NS_PINS, 0);
        assert_eq!(GPIOB_SECURE_PINS & GPIOB_NS_PINS, 0);
    }
}
