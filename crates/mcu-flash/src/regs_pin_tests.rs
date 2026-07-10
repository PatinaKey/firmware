//! Ground-truth pinning tests for `regs`.
//!
//! Every assertion compares a symbolic constant against a HARD-CODED
//! primary-source LITERAL, never against another symbol or an expression built
//! from other symbols. 
//! The source is RM0456 ch.7 (registers, sequences, geometry) 
//! plus AN5347 Table 2 (the secure-alias offset).

use super::*;

#[test]
fn flash_register_addresses_are_canonical()
{
    // Secure alias base 0x5002_2000 (RM0456 sec 2.3, sec 7.9.35 Table 79).
    assert_eq!(FLASH_BASE, 0x5002_2000, "FLASH secure base");
    assert_eq!(FLASH_NSKEYR, 0x5002_2008, "FLASH_NSKEYR (offset 0x08)");
    assert_eq!(FLASH_SECKEYR, 0x5002_200C, "FLASH_SECKEYR (offset 0x0C)");
    assert_eq!(FLASH_OPTKEYR, 0x5002_2010, "FLASH_OPTKEYR (offset 0x10)");
    assert_eq!(FLASH_NSSR, 0x5002_2020, "FLASH_NSSR (offset 0x20)");
    assert_eq!(FLASH_SECSR, 0x5002_2024, "FLASH_SECSR (offset 0x24)");
    assert_eq!(FLASH_NSCR, 0x5002_2028, "FLASH_NSCR (offset 0x28)");
    assert_eq!(FLASH_SECCR, 0x5002_202C, "FLASH_SECCR (offset 0x2C)");
    assert_eq!(FLASH_OPTR, 0x5002_2040, "FLASH_OPTR (offset 0x40)");
}

#[test]
fn unlock_keys_are_canonical()
{
    // CR keys (RM0456 sec 7.3.5), OPT keys (RM0456 sec 7.4.2).
    assert_eq!(FLASH_KEY1, 0x4567_0123, "CR KEY1");
    assert_eq!(FLASH_KEY2, 0xCDEF_89AB, "CR KEY2");
    assert_eq!(FLASH_OPTKEY1, 0x0819_2A3B, "OPTKEY1");
    assert_eq!(FLASH_OPTKEY2, 0x4C5D_6E7F, "OPTKEY2");
}

#[test]
fn seccr_bits_are_canonical()
{
    // RM0456 sec 7.9.10.
    assert_eq!(SECCR_PG, 0x0000_0001, "SECCR.PG bit0");
    assert_eq!(SECCR_PER, 0x0000_0002, "SECCR.PER bit1");
    assert_eq!(SECCR_MER1, 0x0000_0004, "SECCR.MER1 bit2");
    assert_eq!(SECCR_PNB_SHIFT, 3, "SECCR.PNB shift");
    assert_eq!(SECCR_PNB_MASK, 0x0000_07F8, "SECCR.PNB [10:3]");
    assert_eq!(SECCR_BKER, 0x0000_0800, "SECCR.BKER bit11");
    assert_eq!(SECCR_BWR, 0x0000_4000, "SECCR.BWR bit14");
    assert_eq!(SECCR_MER2, 0x0000_8000, "SECCR.MER2 bit15");
    assert_eq!(SECCR_STRT, 0x0001_0000, "SECCR.STRT bit16");
    assert_eq!(SECCR_EOPIE, 0x0100_0000, "SECCR.EOPIE bit24");
    assert_eq!(SECCR_ERRIE, 0x0200_0000, "SECCR.ERRIE bit25");
    assert_eq!(SECCR_LOCK, 0x8000_0000, "SECCR.LOCK bit31");
}

#[test]
fn nscr_option_bits_are_canonical()
{
    // RM0456 sec 7.9.9.
    assert_eq!(NSCR_OPTSTRT, 0x0002_0000, "NSCR.OPTSTRT bit17");
    assert_eq!(NSCR_OBL_LAUNCH, 0x0800_0000, "NSCR.OBL_LAUNCH bit27");
    assert_eq!(NSCR_OPTLOCK, 0x4000_0000, "NSCR.OPTLOCK bit30");
    assert_eq!(NSCR_LOCK, 0x8000_0000, "NSCR.LOCK bit31");
}

#[test]
fn status_flags_are_canonical()
{
    // RM0456 sec 7.9.7 / 7.9.8.
    assert_eq!(SR_EOP, 0x0000_0001, "SR.EOP bit0");
    assert_eq!(SR_OPERR, 0x0000_0002, "SR.OPERR bit1");
    assert_eq!(SR_PROGERR, 0x0000_0008, "SR.PROGERR bit3");
    assert_eq!(SR_WRPERR, 0x0000_0010, "SR.WRPERR bit4");
    assert_eq!(SR_PGAERR, 0x0000_0020, "SR.PGAERR bit5");
    assert_eq!(SR_SIZERR, 0x0000_0040, "SR.SIZERR bit6");
    assert_eq!(SR_PGSERR, 0x0000_0080, "SR.PGSERR bit7");
    assert_eq!(SR_OPTWERR, 0x0000_2000, "SR.OPTWERR bit13 (NSSR)");
    assert_eq!(SR_BSY, 0x0001_0000, "SR.BSY bit16");
    assert_eq!(SR_WDW, 0x0002_0000, "SR.WDW bit17");
}

#[test]
fn error_fold_covers_every_program_erase_error()
{
    // The fold is the OR of OPERR, PROGERR, WRPERR, PGAERR, SIZERR, PGSERR,
    // pinned to the resulting literal mask.
    assert_eq!(SR_ALL_ERRORS, 0x0000_00FA, "SR error fold");
}

#[test]
fn optr_bits_are_canonical()
{
    // RM0456 sec 7.9.13.
    assert_eq!(OPTR_SWAP_BANK, 0x0010_0000, "OPTR.SWAP_BANK bit20");
    assert_eq!(OPTR_DUALBANK, 0x0020_0000, "OPTR.DUALBANK bit21");
    assert_eq!(OPTR_TZEN, 0x8000_0000, "OPTR.TZEN bit31");
}

#[test]
fn geometry_is_canonical()
{
    // RM0456 sec 7.3.1 Table 51 (DUALBANK=1), AN5347 Table 2.
    assert_eq!(PAGE_SIZE, 0x0000_2000, "page 8 KB");
    assert_eq!(PAGES_PER_BANK, 32, "32 pages per bank");
    assert_eq!(BANK_SIZE, 0x0004_0000, "256 KB per bank");
    assert_eq!(LOW_ALIAS_BASE, 0x0C00_0000, "low secure alias base");
    assert_eq!(HIGH_ALIAS_BASE, 0x0C04_0000, "high secure alias base");
    // The two alias ranges are exactly one bank apart (contiguous, no overlap).
    assert_eq!(HIGH_ALIAS_BASE - LOW_ALIAS_BASE, 0x0004_0000, "alias stride");
}

#[test]
fn program_granularity_is_canonical()
{
    // RM0456 sec 7.3.7.
    assert_eq!(QUAD_WORD_LEN, 16, "quad-word 16 bytes");
    assert_eq!(QUAD_WORD_WORDS, 4, "quad-word 4 words");
    assert_eq!(ERASED_BYTE, 0xFF, "erased byte");
    assert_eq!(ERASED_WORD, 0xFFFF_FFFF, "erased word");
}

#[test]
fn physical_bank_mapping_flips_on_swap()
{
    // RM0456 sec 7.5.8: BKER names the physical bank (SWAP_BANK-independent),
    // the mapped base follows SWAP_BANK.
    assert_eq!(PhysBank::One.bker(), 0x0000_0000, "Bank 1 BKER = 0");
    assert_eq!(PhysBank::Two.bker(), 0x0000_0800, "Bank 2 BKER = bit11");

    // SWAP_BANK clear: Bank 1 low, Bank 2 high.
    assert_eq!(
        PhysBank::One.mapped_base(false),
        0x0C00_0000,
        "Bank 1 at low alias when SWAP_BANK clear"
    );
    assert_eq!(
        PhysBank::Two.mapped_base(false),
        0x0C04_0000,
        "Bank 2 at high alias when SWAP_BANK clear"
    );
    // SWAP_BANK set: the two exchange.
    assert_eq!(
        PhysBank::One.mapped_base(true),
        0x0C04_0000,
        "Bank 1 at high alias when SWAP_BANK set"
    );
    assert_eq!(
        PhysBank::Two.mapped_base(true),
        0x0C00_0000,
        "Bank 2 at low alias when SWAP_BANK set"
    );
}

#[test]
fn running_and_inactive_bank_track_swap()
{
    assert_eq!(running_phys_bank(false), PhysBank::One, "boots Bank 1");
    assert_eq!(running_phys_bank(true), PhysBank::Two, "boots Bank 2");
    assert_eq!(inactive_phys_bank(false), PhysBank::Two, "inactive Bank 2");
    assert_eq!(inactive_phys_bank(true), PhysBank::One, "inactive Bank 1");
}

#[test]
fn image_band_layout_is_canonical()
{
    // The metadata band is pages 0-1, the image band is pages 2-31, all HARD
    // literals so a layout change must be re-pinned deliberately.
    assert_eq!(META_PAGE_FIRST, 0, "metadata band first page");
    assert_eq!(META_PAGE_COUNT, 2, "metadata band 2 pages (16 KB)");
    assert_eq!(IMAGE_PAGE_FIRST, 2, "image band first page");
    assert_eq!(IMAGE_PAGE_COUNT, 30, "image band 30 pages");
    assert_eq!(IMAGE_REGION_OFFSET, 0x0000_4000, "image band offset 16 KB");
    // 30 pages of 8 KB. The literal atom, not a 30 * 0x2000 expression.
    assert_eq!(IMAGE_REGION_SIZE, 0x0003_C000, "image band 240 KB");
}

#[test]
fn metadata_layout_is_canonical()
{
    // The metadata records live at fixed offsets inside PHYSICAL Bank 1, pinned
    // to HARD literal byte offsets (the driver re-derives the live alias address
    // from SWAP_BANK on every access).
    assert_eq!(META_NVCNT_OFFSET, 0x0000_0000, "NVCNT log offset");
    assert_eq!(META_BOOT_OFFSET, 0x0000_1000, "boot-count log offset");
    assert_eq!(META_PENDING_OFFSET, 0x0000_2000, "pending record offset");
    assert_eq!(META_OUTCOME_OFFSET, 0x0000_3000, "outcome record offset");
    assert_eq!(META_MUTABLE_PAGE, 1, "mutable records page index");
    assert_eq!(META_LOG_SLOTS, 256, "quad-word slots per half-page log");
}

#[test]
fn pending_and_outcome_encodings_are_distinct_and_canonical()
{
    assert_eq!(PENDING_NONE, 0xFFFF_FFFF, "pending None = erased");
    assert_eq!(PENDING_ARMED_BANK1, 0xA5A5_0001, "pending Armed Bank1");
    assert_eq!(PENDING_ARMED_BANK2, 0xA5A5_0002, "pending Armed Bank2");
    assert_eq!(BOOT_TICK, 0xA5A5_5A5A, "boot tick value");
    assert_eq!(OUTCOME_NONE, 0xFFFF_FFFF, "outcome None = erased");
    assert_eq!(OUTCOME_AUTO_REVERTED, 0x5A5A_0001, "outcome auto-reverted");
    // The pending encodings must be mutually distinct.
    assert_ne!(PENDING_NONE, PENDING_ARMED_BANK1);
    assert_ne!(PENDING_NONE, PENDING_ARMED_BANK2);
    assert_ne!(PENDING_ARMED_BANK1, PENDING_ARMED_BANK2);
    // The outcome non-erased encoding must differ from the pending ones, since
    // both records share page 1 and a stray read must not be misdecoded.
    assert_ne!(OUTCOME_AUTO_REVERTED, PENDING_ARMED_BANK1);
    assert_ne!(OUTCOME_AUTO_REVERTED, PENDING_ARMED_BANK2);
}
