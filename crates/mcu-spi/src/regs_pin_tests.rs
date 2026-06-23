//! Ground-truth pinning tests for `regs`.
//!
//! Every assertion compares a symbolic constant against a HARD-CODED
//! primary-source LITERAL, never against another symbol. A test that asserts a
//! constant equals itself is vacuous and cannot catch an off-by-one slot or a
//! transposed bit. These literals are the crate's anchor to the silicon. Each
//! carries its RM0456 (or STM32U545CEU6Q datasheet) source.

use super::*;

#[test]
fn rcc_addresses_and_bits_are_canonical()
{
    // RCC secure-alias base 0x5602_0C00. AHB2ENR1 at +0x08C, APB2ENR at +0x0A4.
    assert_eq!(RCC_BASE, 0x5602_0C00, "RCC secure base");
    assert_eq!(RCC_AHB2ENR1, 0x5602_0C8C, "RCC_AHB2ENR1 absolute");
    assert_eq!(RCC_APB2ENR, 0x5602_0CA4, "RCC_APB2ENR absolute");
    assert_eq!(RCC_AHB2ENR1_GPIOAEN, 1u32 << 0, "AHB2ENR1.GPIOAEN bit0");
    assert_eq!(RCC_APB2ENR_SPI1EN, 1u32 << 12, "APB2ENR.SPI1EN bit12");
}

#[test]
fn gpioa_addresses_are_canonical()
{
    assert_eq!(GPIOA_BASE, 0x5202_0000, "GPIOA secure base");
    assert_eq!(GPIOA_MODER, 0x5202_0000, "GPIOA_MODER (offset 0x00)");
    assert_eq!(GPIOA_OTYPER, 0x5202_0004, "GPIOA_OTYPER (offset 0x04)");
    assert_eq!(GPIOA_OSPEEDR, 0x5202_0008, "GPIOA_OSPEEDR (offset 0x08)");
    assert_eq!(GPIOA_PUPDR, 0x5202_000C, "GPIOA_PUPDR (offset 0x0C)");
    assert_eq!(GPIOA_BSRR, 0x5202_0018, "GPIOA_BSRR (offset 0x18)");
    assert_eq!(GPIOA_AFRL, 0x5202_0020, "GPIOA_AFRL (offset 0x20)");
}

#[test]
fn gpio_field_encodings_are_canonical()
{
    assert_eq!(GPIO_MODER_ALTERNATE, 0b10, "MODER alternate function");
    assert_eq!(GPIO_MODER_OUTPUT, 0b01, "MODER output");
    assert_eq!(GPIO_OSPEEDR_VERY_HIGH, 0b11, "OSPEEDR very-high");
    assert_eq!(GPIO_PUPDR_PULLUP, 0b01, "PUPDR pull-up");
    assert_eq!(GPIO_PUPDR_NONE, 0b00, "PUPDR no-pull");
    assert_eq!(GPIO_AF5, 0b0101, "AF5 selector for SPI1");
}

#[test]
fn gpio_pin_numbers_match_board()
{
    // PatinaKey schematic v1: CS=PA4, SCK=PA5, MISO=PA6, MOSI=PA7.
    assert_eq!(CS_PIN, 4, "CS pin PA4");
    assert_eq!(SCK_PIN, 5, "SCK pin PA5");
    assert_eq!(MISO_PIN, 6, "MISO pin PA6");
    assert_eq!(MOSI_PIN, 7, "MOSI pin PA7");
}

#[test]
fn gpio_field_helpers_compute_canonical_shifts()
{
    // 2-bit fields: pin 4 -> bit 8, pin 7 -> bit 14.
    assert_eq!(field2_shift(4), 8, "MODER/OSPEEDR/PUPDR shift for pin 4");
    assert_eq!(field2_shift(7), 14, "2-bit field shift for pin 7");
    // 4-bit AFRL fields (pins 0..7): pin 5 -> bit 20, pin 7 -> bit 28.
    assert_eq!(afrl_shift(5), 20, "AFRL shift for pin 5");
    assert_eq!(afrl_shift(7), 28, "AFRL shift for pin 7");
    // BSRR: set half [15:0], reset half [31:16].
    assert_eq!(bsrr_set(4), 1u32 << 4, "BSRR set bit for pin 4");
    assert_eq!(bsrr_reset(4), 1u32 << 20, "BSRR reset bit for pin 4");
}

#[test]
fn spi1_addresses_are_canonical()
{
    // SPI1 secure-alias base 0x5001_3000 (APB2). Offsets from RM0456 Table 703.
    assert_eq!(SPI1_BASE, 0x5001_3000, "SPI1 secure base");
    assert_eq!(SPI1_CR1, 0x5001_3000, "SPI_CR1 (offset 0x000)");
    assert_eq!(SPI1_CR2, 0x5001_3004, "SPI_CR2 (offset 0x004)");
    assert_eq!(SPI1_CFG1, 0x5001_3008, "SPI_CFG1 (offset 0x008)");
    assert_eq!(SPI1_CFG2, 0x5001_300C, "SPI_CFG2 (offset 0x00C)");
    assert_eq!(SPI1_SR, 0x5001_3014, "SPI_SR (offset 0x014)");
    assert_eq!(SPI1_IFCR, 0x5001_3018, "SPI_IFCR (offset 0x018)");
    assert_eq!(SPI1_TXDR, 0x5001_3020, "SPI_TXDR (offset 0x020)");
    // RXDR sits at 0x030, NOT 0x024: reserved words separate it from TXDR.
    assert_eq!(SPI1_RXDR, 0x5001_3030, "SPI_RXDR (offset 0x030)");
}

#[test]
fn spi_cr1_bits_are_canonical()
{
    assert_eq!(SPI_CR1_SPE, 1u32 << 0, "CR1.SPE bit0");
    assert_eq!(SPI_CR1_MASRX, 1u32 << 8, "CR1.MASRX bit8");
    assert_eq!(SPI_CR1_CSTART, 1u32 << 9, "CR1.CSTART bit9");
    assert_eq!(SPI_CR1_SSI, 1u32 << 12, "CR1.SSI bit12");
}

#[test]
fn spi_cr2_tsize_mask_is_canonical()
{
    assert_eq!(SPI_CR2_TSIZE_MASK, 0x0000_FFFF, "CR2.TSIZE [15:0]");
}

#[test]
fn spi_cfg1_fields_are_canonical()
{
    // DSIZE [4:0], 8-bit = N-1 = 7.
    assert_eq!(SPI_CFG1_DSIZE_MASK, 0x0000_001F, "CFG1.DSIZE [4:0]");
    assert_eq!(SPI_CFG1_DSIZE_8BIT, 7, "CFG1.DSIZE 8-bit (N-1=7)");
    // FTHLV [8:5], 1-data threshold = 0.
    assert_eq!(SPI_CFG1_FTHLV_MASK, 0x0000_01E0, "CFG1.FTHLV [8:5]");
    assert_eq!(SPI_CFG1_FTHLV_1DATA, 0, "CFG1.FTHLV 1-data");
    // MBR [30:28], /128 = 0b110.
    assert_eq!(SPI_CFG1_MBR_SHIFT, 28, "CFG1.MBR shift");
    assert_eq!(SPI_CFG1_MBR_MASK, 0x7000_0000, "CFG1.MBR [30:28]");
    assert_eq!(SPI_CFG1_MBR_DIV128, 0b110 << 28, "CFG1.MBR /128");
}

#[test]
fn spi_cfg2_bits_are_canonical()
{
    // COMM [18:17], full-duplex = 0b00.
    assert_eq!(SPI_CFG2_COMM_MASK, 0x0006_0000, "CFG2.COMM [18:17]");
    assert_eq!(SPI_CFG2_COMM_FULL_DUPLEX, 0, "CFG2.COMM full-duplex");
    assert_eq!(SPI_CFG2_MASTER, 1u32 << 22, "CFG2.MASTER bit22");
    assert_eq!(SPI_CFG2_LSBFRST, 1u32 << 23, "CFG2.LSBFRST bit23");
    assert_eq!(SPI_CFG2_CPHA, 1u32 << 24, "CFG2.CPHA bit24");
    assert_eq!(SPI_CFG2_CPOL, 1u32 << 25, "CFG2.CPOL bit25");
    assert_eq!(SPI_CFG2_SSM, 1u32 << 26, "CFG2.SSM bit26");
    assert_eq!(SPI_CFG2_SSOE, 1u32 << 29, "CFG2.SSOE bit29");
    assert_eq!(SPI_CFG2_AFCNTR, 1u32 << 31, "CFG2.AFCNTR bit31");
}

#[test]
fn spi_sr_bits_are_canonical()
{
    assert_eq!(SPI_SR_RXP, 1u32 << 0, "SR.RXP bit0");
    assert_eq!(SPI_SR_TXP, 1u32 << 1, "SR.TXP bit1");
    assert_eq!(SPI_SR_OVR, 1u32 << 6, "SR.OVR bit6");
}

#[test]
fn spi_ifcr_bits_are_canonical()
{
    assert_eq!(SPI_IFCR_EOTC, 1u32 << 3, "IFCR.EOTC bit3");
    assert_eq!(SPI_IFCR_TXTFC, 1u32 << 4, "IFCR.TXTFC bit4");
    assert_eq!(SPI_IFCR_OVRC, 1u32 << 6, "IFCR.OVRC bit6");
}
