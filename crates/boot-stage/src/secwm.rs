//! The SECWM readback wedge.
//!
//! Before the boot stage trusts the SAU / MPU / SECWM isolation, it reads the two
//! flash secure-watermark registers back and refuses to run a mis-provisioned
//! part. Under the widened SAU (the secure image is protected only by SECWM), a
//! part whose watermarks do not cover pages 0..=19 secure must not boot: a
//! non-secure fetch could reach secure code, or a secure page could sit
//! unprotected.
//!
//! # Registers
//!
//! `FLASH_SECWM1R1` (physical Bank 1, secure address 0x5002_2050) and
//! `FLASH_SECWM2R1` (Bank 2, 0x5002_2060). In each word `PSTRT` is bits [7:0] and
//! `PEND` is bits [23:16], but on the STM32U535/545 only the low 5 bits of each
//! field are page-index bits (32 pages per bank), so the decode masks to 5 bits.
//! Both registers are secure-read-only: a non-secure read is RAZ, so a TZEN=0
//! part reads all zeros here, which fails this check as well. RM0456 sec 7.9.17 /
//! 7.9.21, Table 59 (inclusive page bounds).

/// The expected first secure page (inclusive). Pages 0..=`EXPECTED_PEND` secure.
pub(crate) const EXPECTED_PSTRT: u8 = 0;

/// The expected last secure page (inclusive). Matches `mcu_flash` SECWM_PEND: the
/// image band splits at page 19 (pages 0..=19 secure, 20..=31 non-secure).
pub(crate) const EXPECTED_PEND: u8 = 19;

/// The 5-bit page-index mask for the STM32U535/545 SECWM PSTRT/PEND fields
/// (32 pages per bank). Part-specific: RM0456 sec 7.9.17 limits SECWM1_PSTRT/PEND
/// to 5 bits on the STM32U535/545. On the STM32U575/585 the same fields are
/// 7 bits, where masking to 0x1F would drop the upper page bits and turn this
/// wedge fail-open (a page index above 31 would decode as an in-range page). A
/// 7-bit part needs 0x7F here plus a re-review of this wedge against the wider
/// watermark window.
const PAGE_FIELD_MASK: u32 = 0x1F;

/// The PEND field shift inside a `FLASH_SECWMxR1` word (bits [23:16]).
const PEND_SHIFT: u32 = 16;

/// One bank's read-back secure watermark, as inclusive page bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SecwmWindow
{
    /// The first secure page (inclusive).
    pub(crate) start: u8,
    /// The last secure page (inclusive).
    pub(crate) end: u8,
}

/// Both banks' read-back watermarks. The boot stage requires both to match the
/// provisioned layout, so a swap can never expose an unprotected bank.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SecwmReadback
{
    /// Physical Bank 1 watermark (`FLASH_SECWM1R1`).
    pub(crate) bank1: SecwmWindow,
    /// Physical Bank 2 watermark (`FLASH_SECWM2R1`).
    pub(crate) bank2: SecwmWindow,
}

/// Decodes a raw `FLASH_SECWMxR1` word into inclusive page bounds.
///
/// `PSTRT` is bits [4:0], `PEND` is bits [20:16] on the U535/545 (masked to the
/// 5 usable page-index bits, RM0456 sec 7.9.17 / 7.9.21).
pub(crate) fn decode_window(word: u32) -> SecwmWindow
{
    let start = (word & PAGE_FIELD_MASK) as u8;
    let end = ((word >> PEND_SHIFT) & PAGE_FIELD_MASK) as u8;
    SecwmWindow { start, end }
}

/// Reports whether both watermarks exactly match the provisioned layout.
///
/// Fails closed: any deviation (a factory-default part, a swap mix-up, a TZEN=0
/// RAZ read) yields a mismatch and the boot stage wedges.
pub(crate) fn secwm_ok(readback: &SecwmReadback) -> bool
{
    window_ok(&readback.bank1) && window_ok(&readback.bank2)
}

/// Reports whether one watermark matches the expected inclusive bounds.
fn window_ok(window: &SecwmWindow) -> bool
{
    window.start == EXPECTED_PSTRT && window.end == EXPECTED_PEND
}
