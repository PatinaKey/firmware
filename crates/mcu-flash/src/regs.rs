//! Hand-rolled, cited register and geometry definitions for the embedded flash.
//!
//! ONLY the FLASH controller registers, key values, and bank geometry the
//! dual-bank update path touches are defined here, each with an RM0456 ch.7
//! citation.
//!
//! Addresses use the SECURE alias because this driver runs in the secure state
//! and writes the secure bank: a secure-world driver uses the SEC register bank
//! exclusively (RM0456 sec 7.7 Table 72). Every ADDRESS, BIT POSITION, KEY
//! VALUE, and GEOMETRY constant here is pinned to a hard-coded primary-source
//! literal in `regs_pin_tests`.
//!
//! # The physical-bank-versus-mapped-address contract (RM0456 sec 7.5.8)
//!
//! SWAP_BANK remaps the ADDRESS of each bank. It does NOT move the BKER erase
//! selector, the SECWM, or the WRP, which all follow the PHYSICAL bank (RM0456
//! sec 7.5.8 Fig 23/24). A driver that wants to act on physical bank X must
//! therefore use TWO different facts that diverge under SWAP_BANK=1: the erase
//! BKER bit is SWAP_BANK-independent, while the program / read address is
//! SWAP_BANK-derived. [`PhysBank`] folds both into one place so erase and
//! program always agree on the same physical bank.

// ===========================================================================
// FLASH controller register block. Secure alias base 0x5002_2000, non-secure
// 0x4002_2000 (RM0456 sec 2.3 memory map, sec 7.9.35 Table 79). This driver
// lives in the secure world and writes the secure bank, so it uses the SECURE
// alias and the SEC register bank (FLASH_SECKEYR / FLASH_SECSR / FLASH_SECCR,
// RM0456 sec 7.7 Table 72).
// ===========================================================================

/// FLASH secure-alias base. RM0456 sec 2.3 memory map, sec 7.9.35 Table 79.
pub(crate) const FLASH_BASE: u32 = 0x5002_2000;

/// `FLASH_NSKEYR` offset 0x08 (non-secure CR unlock keys). RM0456 sec 7.9.35.
pub(crate) const FLASH_NSKEYR_OFF: u32 = 0x08;
/// `FLASH_SECKEYR` offset 0x0C (secure CR unlock keys). RM0456 sec 7.9.35.
pub(crate) const FLASH_SECKEYR_OFF: u32 = 0x0C;
/// `FLASH_OPTKEYR` offset 0x10 (option-byte unlock keys). RM0456 sec 7.9.35.
pub(crate) const FLASH_OPTKEYR_OFF: u32 = 0x10;
/// `FLASH_NSSR` offset 0x20 (non-secure status, holds OPTWERR). RM0456 sec
/// 7.9.35.
pub(crate) const FLASH_NSSR_OFF: u32 = 0x20;
/// `FLASH_SECSR` offset 0x24 (secure status). RM0456 sec 7.9.35.
pub(crate) const FLASH_SECSR_OFF: u32 = 0x24;
/// `FLASH_NSCR` offset 0x28 (non-secure control, holds the option-byte bits).
/// RM0456 sec 7.9.35.
pub(crate) const FLASH_NSCR_OFF: u32 = 0x28;
/// `FLASH_SECCR` offset 0x2C (secure control). RM0456 sec 7.9.35.
pub(crate) const FLASH_SECCR_OFF: u32 = 0x2C;
/// `FLASH_OPTR` offset 0x40 (option register, holds SWAP_BANK). RM0456 sec
/// 7.9.35.
pub(crate) const FLASH_OPTR_OFF: u32 = 0x40;

/// `FLASH_NSKEYR` absolute address.
pub(crate) const FLASH_NSKEYR: u32 = FLASH_BASE + FLASH_NSKEYR_OFF;
/// `FLASH_SECKEYR` absolute address.
pub(crate) const FLASH_SECKEYR: u32 = FLASH_BASE + FLASH_SECKEYR_OFF;
/// `FLASH_OPTKEYR` absolute address.
pub(crate) const FLASH_OPTKEYR: u32 = FLASH_BASE + FLASH_OPTKEYR_OFF;
/// `FLASH_NSSR` absolute address.
pub(crate) const FLASH_NSSR: u32 = FLASH_BASE + FLASH_NSSR_OFF;
/// `FLASH_SECSR` absolute address.
pub(crate) const FLASH_SECSR: u32 = FLASH_BASE + FLASH_SECSR_OFF;
/// `FLASH_NSCR` absolute address.
pub(crate) const FLASH_NSCR: u32 = FLASH_BASE + FLASH_NSCR_OFF;
/// `FLASH_SECCR` absolute address.
pub(crate) const FLASH_SECCR: u32 = FLASH_BASE + FLASH_SECCR_OFF;
/// `FLASH_OPTR` absolute address.
pub(crate) const FLASH_OPTR: u32 = FLASH_BASE + FLASH_OPTR_OFF;

// ===========================================================================
// CR / OPT unlock keys. A wrong value or order locks the CR until reset.
// ===========================================================================

/// CR unlock KEY1 (write first to SECKEYR / NSKEYR). RM0456 sec 7.3.5.
pub(crate) const FLASH_KEY1: u32 = 0x4567_0123;
/// CR unlock KEY2 (write second). RM0456 sec 7.3.5.
pub(crate) const FLASH_KEY2: u32 = 0xCDEF_89AB;
/// Option-byte unlock OPTKEY1 (write first to OPTKEYR). RM0456 sec 7.4.2.
pub(crate) const FLASH_OPTKEY1: u32 = 0x0819_2A3B;
/// Option-byte unlock OPTKEY2 (write second). RM0456 sec 7.4.2.
pub(crate) const FLASH_OPTKEY2: u32 = 0x4C5D_6E7F;

// ===========================================================================
// FLASH_SECCR control bits. RM0456 sec 7.9.10. FLASH_NSCR (sec 7.9.9) shares
// the program / erase bits and additionally carries the option-byte bits
// OPTLOCK / OPTSTRT / OBL_LAUNCH.
// ===========================================================================

/// `SECCR.PG` bit 0: programming enable. RM0456 sec 7.9.10.
pub(crate) const SECCR_PG: u32 = 1 << 0;
/// `SECCR.PER` bit 1: page-erase enable. RM0456 sec 7.9.10.
pub(crate) const SECCR_PER: u32 = 1 << 1;
/// `SECCR.MER1` bit 2: bank-1 mass-erase. Defined to keep it referenced and so
/// the pin-test fixes its position. The driver never sets it. RM0456 sec
/// 7.9.10.
pub(crate) const SECCR_MER1: u32 = 1 << 2;
/// `SECCR.PNB` field shift (bits [10:3]): page number to erase. RM0456 sec
/// 7.9.10.
pub(crate) const SECCR_PNB_SHIFT: u32 = 3;
/// `SECCR.PNB` field mask (bits [10:3]). RM0456 sec 7.9.10.
pub(crate) const SECCR_PNB_MASK: u32 = 0xFF << SECCR_PNB_SHIFT;
/// `SECCR.BKER` bit 11: erase bank select (0 Bank1, 1 Bank2). RM0456 sec
/// 7.9.10. BKER selects the PHYSICAL bank, SWAP_BANK does not move it (RM0456
/// sec 7.5.8).
pub(crate) const SECCR_BKER: u32 = 1 << 11;
/// `SECCR.BWR` bit 14: burst-write request. Defined to fix its position. The
/// driver never sets it. RM0456 sec 7.9.10.
pub(crate) const SECCR_BWR: u32 = 1 << 14;
/// `SECCR.MER2` bit 15: bank-2 mass-erase. Defined to fix its position. The
/// driver never sets it. RM0456 sec 7.9.10.
pub(crate) const SECCR_MER2: u32 = 1 << 15;
/// `SECCR.STRT` bit 16: start the erase. RM0456 sec 7.9.10.
pub(crate) const SECCR_STRT: u32 = 1 << 16;
/// `SECCR.EOPIE` bit 24: end-of-operation interrupt enable. Defined to fix its
/// position. The driver polls and never enables it. RM0456 sec 7.9.10.
pub(crate) const SECCR_EOPIE: u32 = 1 << 24;
/// `SECCR.ERRIE` bit 25: error interrupt enable. Defined to fix its position.
/// RM0456 sec 7.9.10.
pub(crate) const SECCR_ERRIE: u32 = 1 << 25;
/// `SECCR.LOCK` bit 31: control-register lock. RM0456 sec 7.9.10.
pub(crate) const SECCR_LOCK: u32 = 1 << 31;

/// `NSCR.OPTSTRT` bit 17: start the option-byte program. RM0456 sec 7.9.9.
pub(crate) const NSCR_OPTSTRT: u32 = 1 << 17;
/// `NSCR.OBL_LAUNCH` bit 27: trigger the option-byte reload (resets the part).
/// RM0456 sec 7.9.9. This bit drives the inert brick-class reset.
pub(crate) const NSCR_OBL_LAUNCH: u32 = 1 << 27;
/// `NSCR.OPTLOCK` bit 30: option-byte lock. RM0456 sec 7.9.9.
pub(crate) const NSCR_OPTLOCK: u32 = 1 << 30;
/// `NSCR.LOCK` bit 31: non-secure control-register lock. RM0456 sec 7.9.9.
pub(crate) const NSCR_LOCK: u32 = 1 << 31;

// ===========================================================================
// FLASH_SECSR / FLASH_NSSR status flags. RM0456 sec 7.9.7 (NSSR) / sec 7.9.8
// (SECSR). BSY is mirrored in both (RM0456 sec 7.3.5). Each error flag is
// rc_w1 (write 1 to clear).
// ===========================================================================

/// `SR.EOP` bit 0: end of operation. RM0456 sec 7.9.7 / 7.9.8.
pub(crate) const SR_EOP: u32 = 1 << 0;
/// `SR.OPERR` bit 1: operation error. RM0456 sec 7.9.7 / 7.9.8.
pub(crate) const SR_OPERR: u32 = 1 << 1;
/// `SR.PROGERR` bit 3: programming error (reprogram of a non-erased word).
/// RM0456 sec 7.9.7 / 7.9.8.
pub(crate) const SR_PROGERR: u32 = 1 << 3;
/// `SR.WRPERR` bit 4: write-protection error. RM0456 sec 7.9.7 / 7.9.8.
pub(crate) const SR_WRPERR: u32 = 1 << 4;
/// `SR.PGAERR` bit 5: programming-alignment error. RM0456 sec 7.9.7 / 7.9.8.
pub(crate) const SR_PGAERR: u32 = 1 << 5;
/// `SR.SIZERR` bit 6: size error (a sub-quad-word write). RM0456 sec 7.9.7 /
/// 7.9.8.
pub(crate) const SR_SIZERR: u32 = 1 << 6;
/// `SR.PGSERR` bit 7: programming-sequence error. RM0456 sec 7.9.7 / 7.9.8.
pub(crate) const SR_PGSERR: u32 = 1 << 7;
/// `SR.OPTWERR` bit 13 (NSSR only): option write error. RM0456 sec 7.9.7.
pub(crate) const SR_OPTWERR: u32 = 1 << 13;
/// `SR.BSY` bit 16: a flash operation is in progress. RM0456 sec 7.9.7 /
/// 7.9.8.
pub(crate) const SR_BSY: u32 = 1 << 16;
/// `SR.WDW` bit 17: wait-data-write (a write to a busy data buffer must wait).
/// RM0456 sec 7.9.7 / 7.9.8.
pub(crate) const SR_WDW: u32 = 1 << 17;

/// Every program / erase error flag, OR-folded for one rc_w1 clear and one
/// fault test. OPTWERR is NSSR-only and is folded into the option-byte clear
/// path separately.
pub(crate) const SR_ALL_ERRORS: u32 = SR_OPERR
    | SR_PROGERR
    | SR_WRPERR
    | SR_PGAERR
    | SR_SIZERR
    | SR_PGSERR;

// ===========================================================================
// FLASH_OPTR option register. RM0456 sec 7.9.13. SWAP_BANK cannot be modified
// when BOOT_LOCK and TZEN are both set, EXCEPT at RDP2 (RM0456 sec 7.4.2 /
// 7.6.2), which is the production posture this update path targets.
// ===========================================================================

/// `OPTR.SWAP_BANK` bit 20: the bank-swap option byte. RM0456 sec 7.9.13.
/// When clear, physical Bank 1 sits at the low alias. When set, physical Bank 2
/// sits at the low alias (RM0456 sec 7.5.8).
pub(crate) const OPTR_SWAP_BANK: u32 = 1 << 20;
/// `OPTR.DUALBANK` bit 21: dual-bank mode. RM0456 sec 7.9.13. This driver pins
/// the DUALBANK=1 geometry below.
pub(crate) const OPTR_DUALBANK: u32 = 1 << 21;
/// `OPTR.TZEN` bit 31: TrustZone enable. RM0456 sec 7.9.13.
pub(crate) const OPTR_TZEN: u32 = 1 << 31;

// ===========================================================================
// Bank geometry, DUALBANK=1 real A/B layout (512 KB STM32U545). RM0456 sec
// 7.3.1 Table 51, AN5347 Table 2 (the +0x0400_0000 secure-alias offset).
// ===========================================================================

/// A flash erase page is 8 KB. RM0456 sec 7.3.1 Table 51 (DUALBANK=1).
pub(crate) const PAGE_SIZE: u32 = 0x2000;
/// Pages per bank under DUALBANK=1. RM0456 sec 7.3.1 Table 51.
pub(crate) const PAGES_PER_BANK: u32 = 32;
/// Bytes per bank under DUALBANK=1 (256 KB). RM0456 sec 7.3.1 Table 51.
pub(crate) const BANK_SIZE: u32 = PAGE_SIZE * PAGES_PER_BANK;

/// The LOW secure alias base (the boot / active range). RM0456 sec 7.3.1 Table
/// 51, AN5347 Table 2. SECBOOTADD0 points here, so whichever physical bank
/// SWAP_BANK maps low is the bank that boots (RM0456 sec 7.5.8).
pub(crate) const LOW_ALIAS_BASE: u32 = 0x0C00_0000;
/// The HIGH secure alias base (the staging / inactive range). RM0456 sec 7.3.1
/// Table 51 (Bank 2 page 0 at 0x0C04_0000 secure for the 512 KB STM32U545),
/// AN5347 Table 2. The two 256 KB ranges are contiguous (the 512 KB part keeps
/// DUALBANK=1 contiguous, not the 0x0802_0000 split of the smaller variants in
/// the Table 51 footnote).
pub(crate) const HIGH_ALIAS_BASE: u32 = LOW_ALIAS_BASE + BANK_SIZE;

/// The flash program granularity in bytes: a quad-word is 4 x 32-bit words.
/// RM0456 sec 7.3.7. A program writes one whole quad-word, a sub-quad-word
/// write raises SIZERR.
pub(crate) const QUAD_WORD_LEN: u32 = 16;
/// The number of 32-bit words in a quad-word. RM0456 sec 7.3.7.
pub(crate) const QUAD_WORD_WORDS: u32 = 4;
/// The erased value of a flash byte. An erase sets every bit, a program only
/// clears bits. RM0456 sec 7.3.1, sec 7.3.6.
pub(crate) const ERASED_BYTE: u8 = 0xFF;
/// The erased value of a 32-bit flash word (all bits set). RM0456 sec 7.3.1.
pub(crate) const ERASED_WORD: u32 = 0xFFFF_FFFF;

// ===========================================================================
// Physical bank selector: the single B1 helper.
//
// RM0456 sec 7.5.8 Fig 23/24: SWAP_BANK remaps the bank ADDRESS but NOT the
// BKER erase selector, which always names the physical bank. Folding both into
// one type forces erase (BKER) and program / read (address) to agree on the
// same physical bank.
// ===========================================================================

/// One of the two physical flash banks.
///
/// A PHYSICAL bank is a fixed silicon region. Its erase selector (BKER) never
/// moves, while its mapped address depends on SWAP_BANK (RM0456 sec 7.5.8). The
/// driver names the physical bank with this type, then asks for the BKER bit and
/// the mapped base together so the two can never diverge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PhysBank
{
    /// Physical Bank 1: BKER = 0, governed by SECWM1 / WRP1 / HDP1.
    One,
    /// Physical Bank 2: BKER = 1, governed by SECWM2 / WRP2 / HDP2.
    Two,
}

impl PhysBank
{
    /// The BKER erase-selector bit for this physical bank.
    ///
    /// RM0456 sec 7.9.10: BKER = 0 selects Bank 1, BKER = 1 selects Bank 2.
    /// SWAP_BANK does not move this (RM0456 sec 7.5.8), so it is a pure function
    /// of the physical bank.
    pub(crate) const fn bker(self) -> u32
    {
        match self
        {
            PhysBank::One => 0,
            PhysBank::Two => SECCR_BKER,
        }
    }

    /// The mapped secure-alias base of this physical bank for the given
    /// SWAP_BANK state.
    ///
    /// RM0456 sec 7.5.8: when SWAP_BANK is clear, Bank 1 sits at the low alias
    /// and Bank 2 at the high alias. When SWAP_BANK is set, the two exchange.
    /// `swap` is the live `OPTR.SWAP_BANK` bit state.
    pub(crate) const fn mapped_base(self, swap: bool) -> u32
    {
        match (self, swap)
        {
            (PhysBank::One, false) | (PhysBank::Two, true) => LOW_ALIAS_BASE,
            (PhysBank::One, true) | (PhysBank::Two, false) => HIGH_ALIAS_BASE,
        }
    }
}

/// Decodes `OPTR.SWAP_BANK` into a plain bool (true = SWAP_BANK set).
pub(crate) const fn swap_bank_set(optr: u32) -> bool
{
    optr & OPTR_SWAP_BANK != 0
}

/// The physical bank that currently boots (sits at the low alias).
///
/// RM0456 sec 7.5.8: SWAP_BANK clear boots Bank 1, SWAP_BANK set boots Bank 2.
pub(crate) const fn running_phys_bank(swap: bool) -> PhysBank
{
    if swap
    {
        PhysBank::Two
    }
    else
    {
        PhysBank::One
    }
}

/// The inactive (staging) physical bank, the opposite of the running one.
pub(crate) const fn inactive_phys_bank(swap: bool) -> PhysBank
{
    if swap
    {
        PhysBank::One
    }
    else
    {
        PhysBank::Two
    }
}

// ===========================================================================
// Per-bank layout (the M2 reconciliation). docs grounding: each 256 KB bank is
// split [boot metadata | boot-stage + key | secure app | NSC veneer | NS app].
// This driver only addresses the boot-metadata band and the A/B image band. The
// boot-stage, key, and application bands are placed by the linker of a future
// crate, not here.
//
// The NVCNT, the pending record, the boot-count, and the update-outcome record
// live in pages 0-1 of PHYSICAL Bank 1, the FIXED metadata band (RM0456 sec
// 7.5.8: protections follow the physical bank, so SECWM1 / WRP1 / HDP1 cover it
// permanently). The driver re-derives the MAPPED address of physical Bank 1 from
// SWAP_BANK on every metadata access, so the record survives a swap. There is a
// SINGLE copy, no per-bank duplicate.
// ===========================================================================

/// The first metadata page index inside physical Bank 1 (pages 0-1).
pub(crate) const META_PAGE_FIRST: u32 = 0;
/// The number of metadata pages reserved at the bottom of physical Bank 1.
///
/// Two 8 KB pages (16 KB) carry the NVCNT log, the pending record, the
/// boot-count log, and the update-outcome record. The image band starts after
/// them.
pub(crate) const META_PAGE_COUNT: u32 = 2;

/// The image band start page inside each bank (just past the metadata band).
///
/// The A/B image occupies pages [`IMAGE_PAGE_FIRST`]..[`PAGES_PER_BANK`] of the
/// inactive bank. The metadata band (pages 0-1 of physical Bank 1) is never an
/// image page, so the image write / erase loop never touches NVCNT.
pub(crate) const IMAGE_PAGE_FIRST: u32 = META_PAGE_FIRST + META_PAGE_COUNT;
/// The number of image pages per bank (the pages after the metadata band).
pub(crate) const IMAGE_PAGE_COUNT: u32 = PAGES_PER_BANK - IMAGE_PAGE_FIRST;
/// The image band size per bank in bytes.
///
/// This is the span the A/B update writes. It is the bank minus the 16 KB
/// metadata band, so the image region no longer silently shrinks under a
/// top-of-bank carve-out, it is the explicit lower-pages span the layout
/// reserves.
pub(crate) const IMAGE_REGION_SIZE: u32 = IMAGE_PAGE_COUNT * PAGE_SIZE;
/// The byte offset of the image band from a bank base.
pub(crate) const IMAGE_REGION_OFFSET: u32 = IMAGE_PAGE_FIRST * PAGE_SIZE;

// Metadata record offsets inside physical Bank 1.
//
// Page 0 holds the append-only logs (NVCNT, boot-count). Page 1 holds the
// mutable records (pending, update-outcome), each in its own half so a rewrite
// of one never disturbs the other. All offsets are relative to physical Bank 1's
// MAPPED base, so a swap-aware add yields the live address.

/// The NVCNT append-only log offset (page 0, low half).
pub(crate) const META_NVCNT_OFFSET: u32 = 0;
/// The boot-count append-only log offset (page 0, high half).
pub(crate) const META_BOOT_OFFSET: u32 = PAGE_SIZE / 2;
/// The pending-record offset (page 1, low half, erase-then-program).
pub(crate) const META_PENDING_OFFSET: u32 = PAGE_SIZE;
/// The update-outcome-record offset (page 1, high half, erase-then-program).
pub(crate) const META_OUTCOME_OFFSET: u32 = PAGE_SIZE + PAGE_SIZE / 2;

/// The metadata page index that carries the pending and outcome records.
///
/// Both mutable records live in page 1 of physical Bank 1. A rewrite of either
/// erases this one page and reprograms both records, so they share an erase
/// granularity (RM0456 sec 7.3.6: erase is per 8 KB page).
pub(crate) const META_MUTABLE_PAGE: u32 = META_PAGE_FIRST + 1;

/// Quad-word slots in a half-page log (4 KB / 16 bytes).
///
/// The append-only NVCNT and boot-count logs each own one half of page 0, so
/// each holds this many ticks before the half is exhausted (the finite burn
/// budget per log).
pub(crate) const META_LOG_SLOTS: u32 = (PAGE_SIZE / 2) / QUAD_WORD_LEN;

/// Pending-record encoding: no swap awaiting confirmation. This is the erased
/// value (RM0456 sec 7.3.1), so an erased record reads as `None`.
pub(crate) const PENDING_NONE: u32 = 0xFFFF_FFFF;
/// Pending-record encoding: a swap is armed toward Bank 1.
pub(crate) const PENDING_ARMED_BANK1: u32 = 0xA5A5_0001;
/// Pending-record encoding: a swap is armed toward Bank 2.
pub(crate) const PENDING_ARMED_BANK2: u32 = 0xA5A5_0002;
/// The boot-count tick value programmed into each slot (any non-erased value).
pub(crate) const BOOT_TICK: u32 = 0xA5A5_5A5A;

/// Update-outcome encoding: no outcome recorded (the erased value).
///
/// This is what a cleared outcome reads as: a fresh update begins or a new image
/// confirms by clearing the outcome back to this erased state.
pub(crate) const OUTCOME_NONE: u32 = 0xFFFF_FFFF;
/// Update-outcome encoding: an auto-revert happened.
///
/// A future boot-stage SETS this on an auto-revert so the event is NOT silent: a
/// later host tool reads it back and surfaces it. This driver only reserves the
/// region and provides the read / write / clear seam. The LED and host-CLI
/// surfacing is future work.
pub(crate) const OUTCOME_AUTO_REVERTED: u32 = 0x5A5A_0001;

#[cfg(test)]
#[path = "regs_pin_tests.rs"]
mod regs_pin_tests;
