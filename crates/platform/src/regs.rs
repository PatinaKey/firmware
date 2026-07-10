//! Hand-rolled, minimal register definitions for the partition bring-up.
//!
//! ONLY the registers the partition sequence touches are defined here, each with
//! an RM0456 / AN5347 / Armv8-M citation. This module does NOT pull the full
//! `stm32u5` PAC. The audit surface of a security product should be the handful of
//! registers it programs, every one traceable to a manual line, not a
//! machine-generated crate of thousands of fields.
//!
//! Addresses use the SECURE peripheral alias (0x5xxx_xxxx / 0x52xx_xxxx /
//! 0x56xx_xxxx) because the partition code runs in the secure state and these
//! registers are secure-privileged-write-only. Citations are to RM0456 register
//! map line numbers, AN5347 section numbers, or the Armv8-M Architecture Reference
//! Manual (and CMSIS `core_cm33.h`) where RM0456 only names the register.
//!
//! Every register ADDRESS and key BIT POSITION here is pinned to a hard-coded
//! primary-source literal in `regs_pin_tests`. That ground-truth anchor guards
//! against an off-by-one slot, not the symbolic constants.

// ===========================================================================
// RCC: reset and clock control (SRD / AHB3 bus, secure alias 0x5602_0C00).
// RM0456 sec 2.3 Table 5 (base, L6267). RCC itself is on the SRD bus. AHB1ENR /
// AHB3ENR gate the GTZC / GPDMA clocks.
// ===========================================================================

/// RCC secure-alias base. RM0456 Table 5 L6267.
pub(crate) const RCC_BASE: u32 = 0x5602_0C00;

/// `RCC_AHB1ENR` (clock enable). RM0456 register map L32648.
pub(crate) const RCC_AHB1ENR: u32 = RCC_BASE + 0x088;
/// `RCC_AHB3ENR` (clock enable). RM0456 register map L32654.
pub(crate) const RCC_AHB3ENR: u32 = RCC_BASE + 0x094;

/// `AHB1ENR.GTZC1EN` bit 24 -> GTZC1 clock. RM0456 sec 11.8.29 L28863.
pub(crate) const RCC_AHB1ENR_GTZC1EN: u32 = 1 << 24;
/// `AHB1ENR.GPDMA1EN` bit 0 -> GPDMA1 clock. RM0456 L28995.
pub(crate) const RCC_AHB1ENR_GPDMA1EN: u32 = 1 << 0;
/// `AHB3ENR.GTZC2EN` bit 12 -> GTZC2 clock. RM0456 sec 11.8.32 L29421.
pub(crate) const RCC_AHB3ENR_GTZC2EN: u32 = 1 << 12;

// ===========================================================================
// GTZC1 / GTZC2 sub-blocks. RM0456 Table 29/30 (L8696-8712) lay out the
// per-block offsets from the GTZC base.
// GTZC1 base 0x5003_2400 (S), RM0456 L6367. GTZC2 base 0x5602_3000 (S), L6260.
// ===========================================================================

/// GTZC1 secure-alias base. RM0456 L6367.
pub(crate) const GTZC1_BASE: u32 = 0x5003_2400;
/// GTZC2 secure-alias base. RM0456 L6260.
pub(crate) const GTZC2_BASE: u32 = 0x5602_3000;

// --- TZSC (peripheral security), at offset 0x0 from the GTZC base. RM0456
//     Table 29 L8696. ---

/// GTZC1 TZSC base (= GTZC1 base). RM0456 Table 29 L8696.
pub(crate) const GTZC1_TZSC_BASE: u32 = GTZC1_BASE;
/// GTZC2 TZSC base (= GTZC2 base). RM0456 Table 30 L8710.
pub(crate) const GTZC2_TZSC_BASE: u32 = GTZC2_BASE;

/// `TZSC_CR` offset (holds LCK bit 0). RM0456 sec 5.6.1 L9007.
pub(crate) const TZSC_CR_OFF: u32 = 0x000;
/// `TZSC_SECCFGR2` offset (GTZC1 only). RM0456 sec 5.6.3 L9235.
pub(crate) const TZSC_SECCFGR2_OFF: u32 = 0x014;
/// `TZSC_SECCFGR3` offset (GTZC1 only). RM0456 sec 5.6.4 L9335.
pub(crate) const TZSC_SECCFGR3_OFF: u32 = 0x018;

/// `TZSC_CR.LCK` bit 0: lock the TZSC configuration until reset. RM0456 L9033.
pub(crate) const TZSC_CR_LCK: u32 = 1 << 0;

/// `SECCFGR2.SPI1SEC` bit 1 -> SE SPI link secure. RM0456 L9315.
pub(crate) const TZSC1_SECCFGR2_SPI1SEC: u32 = 1 << 1;

/// `SECCFGR3.AESSEC` bit 11. RM0456 L9499.
pub(crate) const TZSC1_SECCFGR3_AESSEC: u32 = 1 << 11;
/// `SECCFGR3.HASHSEC` bit 12. RM0456 L9493.
pub(crate) const TZSC1_SECCFGR3_HASHSEC: u32 = 1 << 12;
/// `SECCFGR3.RNGSEC` bit 13. RM0456 L9487.
pub(crate) const TZSC1_SECCFGR3_RNGSEC: u32 = 1 << 13;
/// `SECCFGR3.PKASEC` bit 14. RM0456 L9479.
pub(crate) const TZSC1_SECCFGR3_PKASEC: u32 = 1 << 14;
/// `SECCFGR3.SAESSEC` bit 15. RM0456 L9471.
pub(crate) const TZSC1_SECCFGR3_SAESSEC: u32 = 1 << 15;

// --- MPCBB (per-512-byte SRAM block security). Offsets from the GTZC base:
//     MPCBB1 +0x800, MPCBB2 +0xC00 (RM0456 Table 29 L8698/8699),
//     MPCBB4 +0x800 from GTZC2 (Table 30 L8712). ---

/// GTZC1 MPCBB1 (SRAM1) base. RM0456 Table 29 L8698.
pub(crate) const MPCBB1_BASE: u32 = GTZC1_BASE + 0x800;
/// GTZC1 MPCBB2 (SRAM2) base. RM0456 Table 29 L8699.
pub(crate) const MPCBB2_BASE: u32 = GTZC1_BASE + 0xC00;
/// GTZC2 MPCBB4 (SRAM4) base. RM0456 Table 30 L8712.
pub(crate) const MPCBB4_BASE: u32 = GTZC2_BASE + 0x800;

/// `MPCBBx_CR` offset. RM0456 sec 5.8.1 L12615.
pub(crate) const MPCBB_CR_OFF: u32 = 0x000;
/// `MPCBBx_CFGLOCKR1` offset (super-block locks 0..31). RM0456 sec 5.8.2 L12810.
pub(crate) const MPCBB_CFGLOCKR1_OFF: u32 = 0x010;
/// `MPCBBx_SECCFGR0` offset, entry x at `+0x100 + 4*x`. RM0456 sec 5.8.4 L12815.
pub(crate) const MPCBB_SECCFGR0_OFF: u32 = 0x100;

/// `MPCBBx_CR.GLOCK` bit 0: freeze the whole MPCBB config. RM0456 L12659.
pub(crate) const MPCBB_CR_GLOCK: u32 = 1 << 0;

/// Returns the absolute address of MPCBB super-block lock register CFGLOCKR1.
pub(crate) const fn mpcbb_cfglockr1(base: u32) -> u32
{
    base + MPCBB_CFGLOCKR1_OFF
}

/// Returns the absolute address of MPCBB `SECCFGR[index]` (super-block `index`).
pub(crate) const fn mpcbb_seccfgr(base: u32, index: u32) -> u32
{
    base + MPCBB_SECCFGR0_OFF + 4 * index
}

// --- TZIC (illegal-access interrupt controller), at offset 0x400 from GTZC1.
//     RM0456 Table 29 L8697, base 0x5003_2800, L6366. ---

/// GTZC1 TZIC base. RM0456 Table 29 L8697.
pub(crate) const GTZC1_TZIC_BASE: u32 = GTZC1_BASE + 0x400;
/// `TZIC_IER1` offset. RM0456 sec 5.7.1 L10339.
pub(crate) const TZIC_IER1_OFF: u32 = 0x000;
/// `TZIC_IER2` offset. RM0456 register map L12551.
pub(crate) const TZIC_IER2_OFF: u32 = 0x004;
/// `TZIC_IER3` offset. RM0456 register map L12553.
pub(crate) const TZIC_IER3_OFF: u32 = 0x008;
/// `TZIC_IER4` offset. RM0456 register map L12570.
pub(crate) const TZIC_IER4_OFF: u32 = 0x00C;

// ===========================================================================
// GPIO (per-pin security). GPIOx_SECCFGR offset 0x30, bit per pin, reset
// all-secure, secure-write-only. RM0456 sec 13.4.13 L34330, offset L34420.
// GPIOA base 0x5202_0000, GPIOB base 0x5202_0400 (S alias). RM0456 L6356/6357.
// ===========================================================================

/// GPIOA secure-alias base. RM0456 L6356.
pub(crate) const GPIOA_BASE: u32 = 0x5202_0000;
/// GPIOB secure-alias base. RM0456 L6357.
pub(crate) const GPIOB_BASE: u32 = 0x5202_0400;
/// `GPIOx_SECCFGR` offset (bit per pin). RM0456 L34420.
pub(crate) const GPIO_SECCFGR_OFF: u32 = 0x30;

/// Returns the absolute `GPIOx_SECCFGR` address for a GPIO base.
pub(crate) const fn gpio_seccfgr(base: u32) -> u32
{
    base + GPIO_SECCFGR_OFF
}

// ===========================================================================
// GPDMA1 (DMA channel security + lock). Base 0x5002_0000 (S). RM0456 L6391.
// SECCFGR at 0x00, RCFGLOCKR at 0x08. RM0456 sec 17.8.1 L38591 / 17.8.3 L38669.
// ===========================================================================

/// GPDMA1 secure-alias base. RM0456 L6391.
pub(crate) const GPDMA1_BASE: u32 = 0x5002_0000;
/// `GPDMA_SECCFGR` (SECx bit per channel), offset 0x00. RM0456 sec 17.8.1 L38591.
pub(crate) const GPDMA_SECCFGR: u32 = GPDMA1_BASE;
/// `GPDMA_RCFGLOCKR` (LOCKx bit per channel). RM0456 sec 17.8.3 L38669.
pub(crate) const GPDMA_RCFGLOCKR: u32 = GPDMA1_BASE + 0x08;

// ===========================================================================
// SAU: Armv8-M architectural, in the secure System Control Space.
// The SAU block starts at 0xE000_EDD0. RM0456 names these only. The addresses
// and field layout come from the Armv8-M Architecture Reference Manual (SAU
// register block, offsets from 0xE000_EDD0) and CMSIS core_cm33.h `SAU_Type`.
//
// CANONICAL layout (do NOT collapse the SAU_TYPE gap: it is a real read-only
// register at 0xE000_EDD4 and skipping it shifts every following register by one
// slot):
//   SAU_CTRL = 0xE000_EDD0
//   SAU_TYPE = 0xE000_EDD4  (read-only, named here so the gap is explicit)
//   SAU_RNR  = 0xE000_EDD8
//   SAU_RBAR = 0xE000_EDDC
//   SAU_RLAR = 0xE000_EDE0
// ===========================================================================

/// `SAU_CTRL` (ENABLE bit0, ALLNS bit1). Armv8-M ARM SAU block, CMSIS `SAU_Type`.
pub(crate) const SAU_CTRL: u32 = 0xE000_EDD0;
/// `SAU_TYPE` (read-only, SREGION field = number of implemented regions).
///
/// Named so the address gap between `SAU_CTRL` and `SAU_RNR` is explicit and the
/// following registers cannot silently shift up by one slot. The sequence never writes it.
/// Armv8-M ARM SAU block, CMSIS `SAU_Type`.
#[allow(dead_code)]
pub(crate) const SAU_TYPE: u32 = 0xE000_EDD4;
/// `SAU_RNR` (region number select). Armv8-M ARM SAU block, CMSIS `SAU_Type`.
pub(crate) const SAU_RNR: u32 = 0xE000_EDD8;
/// `SAU_RBAR` (region base, BADDR[31:5]). Armv8-M ARM SAU block, CMSIS `SAU_Type`.
pub(crate) const SAU_RBAR: u32 = 0xE000_EDDC;
/// `SAU_RLAR` (region limit LADDR[31:5], NSC bit1, ENABLE bit0). Armv8-M ARM SAU
/// block, CMSIS `SAU_Type`.
pub(crate) const SAU_RLAR: u32 = 0xE000_EDE0;

/// `SAU_CTRL.ENABLE` bit 0. AN5347 sec 3.3.2, Armv8-M ARM SAU block.
pub(crate) const SAU_CTRL_ENABLE: u32 = 1 << 0;
/// `SAU_CTRL.ALLNS` bit 1: mark ALL memory NS. NEVER set in production.
///
/// Used by the test that asserts this bit is never present in any value written
/// to `SAU_CTRL` (it must stay 0). The sequence deliberately never writes it.
/// Armv8-M ARM SAU block.
#[allow(dead_code)]
pub(crate) const SAU_CTRL_ALLNS: u32 = 1 << 1;
/// `SAU_RLAR.ENABLE` bit 0: region enabled. Armv8-M.
pub(crate) const SAU_RLAR_ENABLE: u32 = 1 << 0;
/// `SAU_RLAR.NSC` bit 1: region is Non-Secure-Callable. Armv8-M.
pub(crate) const SAU_RLAR_NSC: u32 = 1 << 1;

/// The 32-byte alignment mask SAU bases/limits must satisfy (BADDR/LADDR[31:5]).
/// AN5347 Table 1 alignment note, Armv8-M ARM SAU region encoding.
pub(crate) const SAU_ALIGN_MASK: u32 = 0x1F;

// ===========================================================================
// Secure MPU (Armv8-M PMSAv8, banked secure bank), in the secure System
// Control Space. The MPU register block base is 0xE000_ED90. PM0264 sec 4.5.9
// Table 97, CMSIS core_cm33.h `MPU_Type`. RM0456 names these only.
//
// The SCS region 0xE000_E000-0xE000_EFFF is ALWAYS Device + XN accessible
// regardless of the MPU, so NO MPU region is needed to reach the SAU / MPU / SCB
// registers (PM0264 line 13199). With PRIVDEFENA = 0 there is no background map,
// so every other secure access must hit an enabled region or fault.
// ===========================================================================

/// `MPU_TYPE` (read-only, DREGION field). PM0264 sec 4.5.9 Table 97.
///
/// Named so the address gap before `MPU_CTRL` is explicit. The sequence never
/// writes it. The secure bank implements 8 regions (DREGION = 8).
#[allow(dead_code)]
pub(crate) const MPU_TYPE: u32 = 0xE000_ED90;
/// `MPU_CTRL` (ENABLE bit0, HFNMIENA bit1, PRIVDEFENA bit2). PM0264 sec 4.5.11.
pub(crate) const MPU_CTRL: u32 = 0xE000_ED94;
/// `MPU_RNR` (region number select). PM0264 sec 4.5.9 Table 97.
pub(crate) const MPU_RNR: u32 = 0xE000_ED98;
/// `MPU_RBAR` (BASE[31:5], SH[4:3], AP[2:1], XN bit0). PM0264 sec 4.5.13.
pub(crate) const MPU_RBAR: u32 = 0xE000_ED9C;
/// `MPU_RLAR` (LIMIT[31:5], AttrIndx[3:1], EN bit0). PM0264 sec 4.5.15.
pub(crate) const MPU_RLAR: u32 = 0xE000_EDA0;
/// `MPU_MAIR0` (Attr0..3, one byte each). PM0264 sec 4.5.17.
pub(crate) const MPU_MAIR0: u32 = 0xE000_EDC0;
/// `MPU_MAIR1` (Attr4..7, one byte each). PM0264 sec 4.5.17.
///
/// Left at its reset value (0): only Attr0/Attr1 in MAIR0 are used. Named so the
/// block layout is explicit. The sequence never writes it.
#[allow(dead_code)]
pub(crate) const MPU_MAIR1: u32 = 0xE000_EDC4;

/// `MPU_CTRL.ENABLE` bit 0: enable the MPU. PM0264 sec 4.5.11 Table 99.
pub(crate) const MPU_CTRL_ENABLE: u32 = 1 << 0;
/// `MPU_CTRL.HFNMIENA` bit 1: keep the MPU on in HardFault / NMI. PM0264 Table 99.
pub(crate) const MPU_CTRL_HFNMIENA: u32 = 1 << 1;
/// `MPU_CTRL.PRIVDEFENA` bit 2: privileged background map. NEVER set here.
///
/// Left 0 so there is no background region: every secure access must match an
/// enabled MPU region or fault (strict least privilege). Used by the test that
/// asserts this bit is never present in any `MPU_CTRL` write. PM0264 Table 99.
#[allow(dead_code)]
pub(crate) const MPU_CTRL_PRIVDEFENA: u32 = 1 << 2;

/// `MPU_RLAR.EN` bit 0: region enabled. PM0264 sec 4.5.15 Table 102.
pub(crate) const MPU_RLAR_EN: u32 = 1 << 0;
/// `MPU_RLAR.AttrIndx` field position (bits [3:1]). PM0264 sec 4.5.15 Table 102.
pub(crate) const MPU_RLAR_ATTRINDX_SHIFT: u32 = 1;
/// `MPU_RBAR.XN` bit 0: execute-never. PM0264 sec 4.5.13 Table 101.
pub(crate) const MPU_RBAR_XN: u32 = 1 << 0;
/// `MPU_RBAR.AP` field position (bits [2:1]). PM0264 sec 4.5.13 Table 101.
pub(crate) const MPU_RBAR_AP_SHIFT: u32 = 1;
/// `MPU_RBAR.SH` field position (bits [4:3]). PM0264 sec 4.5.13 Table 101.
pub(crate) const MPU_RBAR_SH_SHIFT: u32 = 3;

/// `MPU_RBAR.AP` = 0b00: read-write, privileged only. PM0264 sec 4.5.13 Table 101.
pub(crate) const MPU_AP_RW_PRIV: u32 = 0b00;
/// `MPU_RBAR.AP` = 0b10: read-only, privileged only. PM0264 sec 4.5.13 Table 101.
pub(crate) const MPU_AP_RO_PRIV: u32 = 0b10;
/// `MPU_RBAR.SH` = 0b00: non-shareable. PM0264 sec 4.5.13 Table 101.
pub(crate) const MPU_SH_NON_SHAREABLE: u32 = 0b00;

/// MAIR AttrIndx 0 = Normal memory (write-through non-transient, `0xAA`).
pub(crate) const MPU_ATTRINDX_NORMAL: u32 = 0;
/// MAIR AttrIndx 1 = Device-nGnRnE (`0x00`).
pub(crate) const MPU_ATTRINDX_DEVICE: u32 = 1;

/// `MAIR0` Attr0 byte: Normal memory, write-through non-transient. PM0264 sec
/// 4.5.17, Armv8-M memory attribute encoding (`0xAA`).
pub(crate) const MPU_MAIR_ATTR_NORMAL: u32 = 0xAA;
/// `MAIR0` Attr1 byte: Device-nGnRnE. PM0264 sec 4.5.17 (`0x00`).
pub(crate) const MPU_MAIR_ATTR_DEVICE: u32 = 0x00;

/// `MPU_MAIR0` value: Attr0 = Normal (`0xAA`) in byte 0, Attr1 = Device (`0x00`)
/// in byte 1, Attr2/Attr3 unused (0). PM0264 sec 4.5.17.
pub(crate) const MPU_MAIR0_VALUE: u32 =
    MPU_MAIR_ATTR_NORMAL | (MPU_MAIR_ATTR_DEVICE << 8);

/// The 32-byte alignment mask MPU bases/limits must satisfy (BASE/LIMIT[31:5]).
///
/// Same architectural 32-byte granule as the SAU, so this reuses `SAU_ALIGN_MASK`
/// (`0x1F`). PM0264 sec 4.5.13/4.5.15, Armv8-M PMSAv8 region encoding.
pub(crate) const MPU_ALIGN_MASK: u32 = SAU_ALIGN_MASK;

#[cfg(test)]
#[path = "regs_pin_tests.rs"]
mod regs_pin_tests;
