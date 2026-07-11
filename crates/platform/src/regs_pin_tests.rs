//! Ground-truth pinning tests for `regs`.
//!
//! Every assertion here compares a symbolic constant from `regs` against a
//! HARD-CODED primary-source LITERAL, never against another symbol. A test that
//! asserts a constant equals itself (or equals a value derived from the same
//! symbol) is vacuous and cannot catch an off-by-one slot or a transposed bit.
//! These literals are the crate's anchor to the silicon.
//!
//! Each line carries its primary source: the Armv8-M Architecture Reference
//! Manual (SAU register block, offsets from 0xE000_EDD0, CMSIS `SAU_Type`), or
//! the RM0456 / AN5347 register map for the STM32U545 peripherals.

use super::*;

// ===========================================================================
// SAU: the off-by-one slot defect lives here. Pin all five addresses to the
// canonical Armv8-M literals so a shifted block fails immediately.
// Armv8-M ARM SAU register block, CMSIS core_cm33.h `SAU_Type`.
// ===========================================================================

#[test]
fn sau_register_addresses_are_canonical()
{
    assert_eq!(SAU_CTRL, 0xE000_EDD0, "SAU_CTRL");
    assert_eq!(SAU_TYPE, 0xE000_EDD4, "SAU_TYPE (read-only gap)");
    assert_eq!(SAU_RNR, 0xE000_EDD8, "SAU_RNR");
    assert_eq!(SAU_RBAR, 0xE000_EDDC, "SAU_RBAR");
    assert_eq!(SAU_RLAR, 0xE000_EDE0, "SAU_RLAR");
}

#[test]
fn sau_bit_positions_are_canonical()
{
    // SAU_CTRL: ENABLE bit0, ALLNS bit1.
    assert_eq!(SAU_CTRL_ENABLE, 0x0000_0001, "SAU_CTRL.ENABLE bit0");
    assert_eq!(SAU_CTRL_ALLNS, 0x0000_0002, "SAU_CTRL.ALLNS bit1");
    // SAU_RLAR: ENABLE bit0, NSC bit1.
    assert_eq!(SAU_RLAR_ENABLE, 0x0000_0001, "SAU_RLAR.ENABLE bit0");
    assert_eq!(SAU_RLAR_NSC, 0x0000_0002, "SAU_RLAR.NSC bit1");
    // Region base/limit 32-byte alignment mask (low 5 bits).
    assert_eq!(SAU_ALIGN_MASK, 0x0000_001F, "SAU 32-byte align mask");
}

// ===========================================================================
// Secure MPU (Armv8-M PMSAv8). The off-by-one slot defect lives here too: pin
// every address to the canonical PM0264 / CMSIS core_cm33.h literal.
// PM0264 sec 4.5.9 Table 97, CMSIS `MPU_Type`.
// ===========================================================================

#[test]
fn mpu_register_addresses_are_canonical()
{
    assert_eq!(MPU_TYPE, 0xE000_ED90, "MPU_TYPE");
    assert_eq!(MPU_CTRL, 0xE000_ED94, "MPU_CTRL");
    assert_eq!(MPU_RNR, 0xE000_ED98, "MPU_RNR");
    assert_eq!(MPU_RBAR, 0xE000_ED9C, "MPU_RBAR");
    assert_eq!(MPU_RLAR, 0xE000_EDA0, "MPU_RLAR");
    assert_eq!(MPU_MAIR0, 0xE000_EDC0, "MPU_MAIR0");
    assert_eq!(MPU_MAIR1, 0xE000_EDC4, "MPU_MAIR1");
}

#[test]
fn mpu_bit_positions_are_canonical()
{
    // MPU_CTRL: ENABLE bit0, HFNMIENA bit1, PRIVDEFENA bit2.
    assert_eq!(MPU_CTRL_ENABLE, 0x0000_0001, "MPU_CTRL.ENABLE bit0");
    assert_eq!(MPU_CTRL_HFNMIENA, 0x0000_0002, "MPU_CTRL.HFNMIENA bit1");
    assert_eq!(MPU_CTRL_PRIVDEFENA, 0x0000_0004, "MPU_CTRL.PRIVDEFENA bit2");
    // MPU_RLAR: EN bit0, AttrIndx[3:1].
    assert_eq!(MPU_RLAR_EN, 0x0000_0001, "MPU_RLAR.EN bit0");
    assert_eq!(MPU_RLAR_ATTRINDX_SHIFT, 1, "MPU_RLAR.AttrIndx shift");
    // MPU_RBAR: XN bit0, AP[2:1], SH[4:3].
    assert_eq!(MPU_RBAR_XN, 0x0000_0001, "MPU_RBAR.XN bit0");
    assert_eq!(MPU_RBAR_AP_SHIFT, 1, "MPU_RBAR.AP shift");
    assert_eq!(MPU_RBAR_SH_SHIFT, 3, "MPU_RBAR.SH shift");
    // AP / SH encodings.
    assert_eq!(MPU_AP_RW_PRIV, 0b00, "AP RW priv-only");
    assert_eq!(MPU_AP_RO_PRIV, 0b10, "AP RO priv-only");
    assert_eq!(MPU_SH_NON_SHAREABLE, 0b00, "SH non-shareable");
    // 32-byte region granule mask (low 5 bits).
    assert_eq!(MPU_ALIGN_MASK, 0x0000_001F, "MPU 32-byte align mask");
}

#[test]
fn mpu_mair_attributes_are_canonical()
{
    // Attr bytes: Normal write-through non-transient = 0xAA, Device-nGnRnE = 0x00.
    assert_eq!(MPU_MAIR_ATTR_NORMAL, 0xAA, "Attr Normal byte");
    assert_eq!(MPU_MAIR_ATTR_DEVICE, 0x00, "Attr Device byte");
    // AttrIndx 0 = Normal, AttrIndx 1 = Device.
    assert_eq!(MPU_ATTRINDX_NORMAL, 0, "AttrIndx Normal");
    assert_eq!(MPU_ATTRINDX_DEVICE, 1, "AttrIndx Device");
    // MAIR0 packs Attr0 in byte0, Attr1 in byte1, the rest 0.
    assert_eq!(MPU_MAIR0_VALUE, 0x0000_00AA, "MPU_MAIR0 packed value");
}

// ===========================================================================
// RCC clock enables. RM0456 register map (AHB1ENR L32648, AHB3ENR L32654).
// ===========================================================================

#[test]
fn rcc_clock_enable_addresses_and_bits()
{
    // RCC secure-alias base 0x5602_0C00. AHB1ENR at +0x088, AHB3ENR at +0x094.
    assert_eq!(RCC_AHB1ENR, 0x5602_0C88, "RCC_AHB1ENR absolute");
    assert_eq!(RCC_AHB3ENR, 0x5602_0C94, "RCC_AHB3ENR absolute");
    assert_eq!(RCC_AHB1ENR_GTZC1EN, 1u32 << 24, "AHB1ENR.GTZC1EN bit24");
    assert_eq!(RCC_AHB1ENR_GPDMA1EN, 1u32 << 0, "AHB1ENR.GPDMA1EN bit0");
    assert_eq!(RCC_AHB3ENR_GTZC2EN, 1u32 << 12, "AHB3ENR.GTZC2EN bit12");
}

// ===========================================================================
// GTZC1 / GTZC2 bases and TZSC. RM0456 memory map + sec 5.6.
// ===========================================================================

#[test]
fn gtzc_bases_are_canonical()
{
    assert_eq!(GTZC1_BASE, 0x5003_2400, "GTZC1 secure base");
    assert_eq!(GTZC2_BASE, 0x5602_3000, "GTZC2 secure base");
    assert_eq!(GTZC1_TZIC_BASE, 0x5003_2800, "GTZC1 TZIC base (GTZC1 + 0x400)");
}

#[test]
fn tzsc_offsets_and_bits()
{
    assert_eq!(TZSC_CR_OFF, 0x000, "TZSC_CR offset");
    assert_eq!(TZSC_SECCFGR2_OFF, 0x014, "TZSC_SECCFGR2 offset");
    assert_eq!(TZSC_SECCFGR3_OFF, 0x018, "TZSC_SECCFGR3 offset");
    assert_eq!(TZSC_CR_LCK, 1u32 << 0, "TZSC_CR.LCK bit0");
    assert_eq!(TZSC1_SECCFGR2_SPI1SEC, 1u32 << 1, "SECCFGR2.SPI1SEC bit1");
    assert_eq!(TZSC1_SECCFGR3_AESSEC, 1u32 << 11, "SECCFGR3.AESSEC bit11");
    assert_eq!(TZSC1_SECCFGR3_HASHSEC, 1u32 << 12, "SECCFGR3.HASHSEC bit12");
    assert_eq!(TZSC1_SECCFGR3_RNGSEC, 1u32 << 13, "SECCFGR3.RNGSEC bit13");
    assert_eq!(TZSC1_SECCFGR3_PKASEC, 1u32 << 14, "SECCFGR3.PKASEC bit14");
    assert_eq!(TZSC1_SECCFGR3_SAESSEC, 1u32 << 15, "SECCFGR3.SAESSEC bit15");
}

// ===========================================================================
// MPCBB. RM0456 sec 5.8: SECCFGR formula and CFGLOCKR1 offset / GLOCK bit.
// ===========================================================================

#[test]
fn mpcbb_bases_offsets_and_formula()
{
    // MPCBB1 = GTZC1 + 0x800, MPCBB2 = GTZC1 + 0xC00, MPCBB4 = GTZC2 + 0x800.
    assert_eq!(MPCBB1_BASE, 0x5003_2C00, "MPCBB1 base");
    assert_eq!(MPCBB2_BASE, 0x5003_3000, "MPCBB2 base");
    assert_eq!(MPCBB4_BASE, 0x5602_3800, "MPCBB4 base");
    assert_eq!(MPCBB_CFGLOCKR1_OFF, 0x010, "MPCBB_CFGLOCKR1 offset");
    assert_eq!(MPCBB_CR_GLOCK, 1u32 << 0, "MPCBB_CR.GLOCK bit0");
    // SECCFGR formula: base + 0x100 + 4*index. Pin against the raw arithmetic.
    assert_eq!(mpcbb_seccfgr(MPCBB1_BASE, 0), 0x5003_2C00 + 0x100, "SECCFGR0");
    assert_eq!(mpcbb_seccfgr(MPCBB1_BASE, 8), 0x5003_2C00 + 0x100 + 4 * 8, "SECCFGR8");
    assert_eq!(mpcbb_cfglockr1(MPCBB1_BASE), 0x5003_2C00 + 0x010, "CFGLOCKR1");
}

// ===========================================================================
// GPIO. RM0456 sec 13.4.13: SECCFGR at offset 0x30, bit per pin.
// ===========================================================================

#[test]
fn gpio_bases_and_seccfgr_offset()
{
    assert_eq!(GPIOA_BASE, 0x5202_0000, "GPIOA secure base");
    assert_eq!(GPIOB_BASE, 0x5202_0400, "GPIOB secure base");
    assert_eq!(GPIO_SECCFGR_OFF, 0x30, "GPIOx_SECCFGR offset");
    assert_eq!(gpio_seccfgr(GPIOA_BASE), 0x5202_0030, "GPIOA SECCFGR absolute");
}

// ===========================================================================
// GPDMA1. RM0456 sec 17.8: SECCFGR at offset 0, RCFGLOCKR at offset 0x08.
// ===========================================================================

#[test]
fn gpdma_offsets()
{
    assert_eq!(GPDMA1_BASE, 0x5002_0000, "GPDMA1 secure base");
    assert_eq!(GPDMA_SECCFGR, 0x5002_0000, "GPDMA_SECCFGR offset0");
    assert_eq!(GPDMA_RCFGLOCKR, 0x5002_0008, "GPDMA_RCFGLOCKR offset0x08");
}

// ===========================================================================
// TZIC IER words. RM0456 sec 5.7.1 + register map: IER1..4 at 0x00/04/08/0C.
// ===========================================================================

#[test]
fn tzic_ier_offsets()
{
    assert_eq!(TZIC_IER1_OFF, 0x000, "TZIC_IER1 offset");
    assert_eq!(TZIC_IER2_OFF, 0x004, "TZIC_IER2 offset");
    assert_eq!(TZIC_IER3_OFF, 0x008, "TZIC_IER3 offset");
    assert_eq!(TZIC_IER4_OFF, 0x00C, "TZIC_IER4 offset");
}

// ===========================================================================
// SysTick (Armv8-M, secure view). Pin every address and bit to the canonical
// PM0264 Table 83 / 84 literal so a shifted block or transposed bit fails here.
// ===========================================================================

#[test]
fn systick_register_addresses_are_canonical()
{
    assert_eq!(SYST_CSR, 0xE000_E010, "SYST_CSR");
    assert_eq!(SYST_RVR, 0xE000_E014, "SYST_RVR");
    assert_eq!(SYST_CVR, 0xE000_E018, "SYST_CVR");
    assert_eq!(SYST_CALIB, 0xE000_E01C, "SYST_CALIB");
}

#[test]
fn systick_bit_positions_are_canonical()
{
    // SYST_CSR: ENABLE bit0, TICKINT bit1, CLKSOURCE bit2, COUNTFLAG bit16.
    assert_eq!(SYST_CSR_ENABLE, 0x0000_0001, "SYST_CSR.ENABLE bit0");
    assert_eq!(SYST_CSR_TICKINT, 0x0000_0002, "SYST_CSR.TICKINT bit1");
    assert_eq!(SYST_CSR_CLKSOURCE, 0x0000_0004, "SYST_CSR.CLKSOURCE bit2");
    assert_eq!(SYST_CSR_COUNTFLAG, 0x0001_0000, "SYST_CSR.COUNTFLAG bit16");
    // RVR / CVR count fields are the low 24 bits.
    assert_eq!(SYST_RVR_RELOAD_MASK, 0x00FF_FFFF, "SYST_RVR.RELOAD [23:0]");
    assert_eq!(SYST_CVR_CURRENT_MASK, 0x00FF_FFFF, "SYST_CVR.CURRENT [23:0]");
}
