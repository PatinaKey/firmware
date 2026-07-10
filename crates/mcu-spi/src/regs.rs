//! Hand-rolled, cited register definitions for the SPI1 bring-up.
//!
//! ONLY the registers the SPI1 init and PIO transfer touch are defined here, each
//! with an RM0456 (or STM32U545CEU6Q datasheet, for the alternate-function map)
//! citation. This module does NOT pull the full `stm32u5` PAC. A security
//! product's audit surface should be the handful of registers it programs, every
//! one traceable to a manual line.
//!
//! Addresses use the SECURE peripheral alias (0x5xxx_xxxx) because this code runs
//! in the secure state and SPI1, GPIOA, and the RCC are kept secure by the
//! partition. Every ADDRESS and key BIT POSITION here is pinned to a hard-coded
//! primary-source literal in `regs_pin_tests`.

// ===========================================================================
// RCC clock enables (secure alias). RCC base 0x5602_0C00. RM0456 Table 6.
// SPI1 is on APB2 (RCC_APB2ENR, SPI1EN). GPIOA is on AHB2 (RCC_AHB2ENR1,
// GPIOAEN).
// ===========================================================================

/// RCC secure-alias base. RM0456 Table 6 (memory map).
pub(crate) const RCC_BASE: u32 = 0x5602_0C00;

/// `RCC_AHB2ENR1` (clock enable), offset 0x08C. RM0456 sec 11.8.30.
pub(crate) const RCC_AHB2ENR1: u32 = RCC_BASE + 0x08C;
/// `RCC_APB2ENR` (clock enable), offset 0x0A4. RM0456 sec 11.8.35.
pub(crate) const RCC_APB2ENR: u32 = RCC_BASE + 0x0A4;

/// `AHB2ENR1.GPIOAEN` bit 0 -> GPIOA clock. RM0456 sec 11.8.30.
pub(crate) const RCC_AHB2ENR1_GPIOAEN: u32 = 1 << 0;
/// `APB2ENR.SPI1EN` bit 12 -> SPI1 clock. RM0456 sec 11.8.35.
pub(crate) const RCC_APB2ENR_SPI1EN: u32 = 1 << 12;

// ===========================================================================
// GPIOA (secure alias 0x5202_0000). RM0456 Table 6 + sec 13.4 (register map and
// field encodings). PA4 = software CS (GPIO output), PA5/PA6/PA7 = SPI1 SCK /
// MISO / MOSI on AF5.
// ===========================================================================

/// GPIOA secure-alias base. RM0456 Table 6 (memory map).
pub(crate) const GPIOA_BASE: u32 = 0x5202_0000;

/// `GPIOx_MODER` offset (2 bits per pin). RM0456 sec 13.4.1.
pub(crate) const GPIO_MODER_OFF: u32 = 0x00;
/// `GPIOx_OTYPER` offset (1 bit per pin). RM0456 sec 13.4.2.
pub(crate) const GPIO_OTYPER_OFF: u32 = 0x04;
/// `GPIOx_OSPEEDR` offset (2 bits per pin). RM0456 sec 13.4.3.
pub(crate) const GPIO_OSPEEDR_OFF: u32 = 0x08;
/// `GPIOx_PUPDR` offset (2 bits per pin). RM0456 sec 13.4.4.
pub(crate) const GPIO_PUPDR_OFF: u32 = 0x0C;
/// `GPIOx_BSRR` offset (set [15:0] / reset [31:16]). RM0456 sec 13.4.7.
pub(crate) const GPIO_BSRR_OFF: u32 = 0x18;
/// `GPIOx_AFRL` offset (4 bits per pin, pins 0..7). RM0456 sec 13.4.9.
pub(crate) const GPIO_AFRL_OFF: u32 = 0x20;

/// `GPIOA_MODER` absolute address.
pub(crate) const GPIOA_MODER: u32 = GPIOA_BASE + GPIO_MODER_OFF;
/// `GPIOA_OTYPER` absolute address.
pub(crate) const GPIOA_OTYPER: u32 = GPIOA_BASE + GPIO_OTYPER_OFF;
/// `GPIOA_OSPEEDR` absolute address.
pub(crate) const GPIOA_OSPEEDR: u32 = GPIOA_BASE + GPIO_OSPEEDR_OFF;
/// `GPIOA_PUPDR` absolute address.
pub(crate) const GPIOA_PUPDR: u32 = GPIOA_BASE + GPIO_PUPDR_OFF;
/// `GPIOA_BSRR` absolute address.
pub(crate) const GPIOA_BSRR: u32 = GPIOA_BASE + GPIO_BSRR_OFF;
/// `GPIOA_AFRL` absolute address.
pub(crate) const GPIOA_AFRL: u32 = GPIOA_BASE + GPIO_AFRL_OFF;

/// `MODER` field value: alternate function (`0b10`). RM0456 sec 13.4.1.
pub(crate) const GPIO_MODER_ALTERNATE: u32 = 0b10;
/// `MODER` field value: general-purpose output (`0b01`). RM0456 sec 13.4.1.
pub(crate) const GPIO_MODER_OUTPUT: u32 = 0b01;
/// `OSPEEDR` field value: very-high speed (`0b11`). RM0456 sec 13.4.3.
pub(crate) const GPIO_OSPEEDR_VERY_HIGH: u32 = 0b11;
/// `PUPDR` field value: pull-up (`0b01`). RM0456 sec 13.4.4.
pub(crate) const GPIO_PUPDR_PULLUP: u32 = 0b01;
/// `PUPDR` field value: no pull (`0b00`). RM0456 sec 13.4.4.
pub(crate) const GPIO_PUPDR_NONE: u32 = 0b00;
/// Alternate-function selector value for SPI1 on PA5/PA6/PA7: AF5 (`0b0101`).
/// STM32U545CEU6Q datasheet (DS14216) alternate-function table, AF5 column.
pub(crate) const GPIO_AF5: u32 = 0b0101;

/// CS pin number on GPIOA (PA4, software-managed active-low chip select).
/// Board pin map (PatinaKey hardware schematic v1).
pub(crate) const CS_PIN: u32 = 4;
/// SCK pin number on GPIOA (PA5, SPI1_SCK AF5). Board pin map.
pub(crate) const SCK_PIN: u32 = 5;
/// MISO pin number on GPIOA (PA6, SPI1_MISO AF5). Board pin map.
pub(crate) const MISO_PIN: u32 = 6;
/// MOSI pin number on GPIOA (PA7, SPI1_MOSI AF5). Board pin map.
pub(crate) const MOSI_PIN: u32 = 7;

// ===========================================================================
// SPI1 (secure alias 0x5001_3000, APB2). RM0456 Table 6 + sec 68.8 (register
// map and field encodings). This is the newer SPI/I2S peripheral with
// TSIZE / PACKET, NOT the F1/F4 SPI.
// ===========================================================================

/// SPI1 secure-alias base. RM0456 Table 6 (memory map).
pub(crate) const SPI1_BASE: u32 = 0x5001_3000;

/// `SPI_CR1` offset. RM0456 sec 68.8.1.
pub(crate) const SPI_CR1_OFF: u32 = 0x000;
/// `SPI_CR2` offset (holds TSIZE). RM0456 sec 68.8.2.
pub(crate) const SPI_CR2_OFF: u32 = 0x004;
/// `SPI_CFG1` offset. RM0456 sec 68.8.3.
pub(crate) const SPI_CFG1_OFF: u32 = 0x008;
/// `SPI_CFG2` offset. RM0456 sec 68.8.4.
pub(crate) const SPI_CFG2_OFF: u32 = 0x00C;
/// `SPI_SR` (status) offset. RM0456 sec 68.8.6.
pub(crate) const SPI_SR_OFF: u32 = 0x014;
/// `SPI_IFCR` (interrupt/flag clear) offset. RM0456 sec 68.8.7.
pub(crate) const SPI_IFCR_OFF: u32 = 0x018;
/// `SPI_TXDR` (transmit data) offset. RM0456 sec 68.8.9.
pub(crate) const SPI_TXDR_OFF: u32 = 0x020;
/// `SPI_RXDR` (receive data) offset. RM0456 sec 68.8.10.
pub(crate) const SPI_RXDR_OFF: u32 = 0x030;

/// `SPI1_CR1` absolute address.
pub(crate) const SPI1_CR1: u32 = SPI1_BASE + SPI_CR1_OFF;
/// `SPI1_CR2` absolute address.
pub(crate) const SPI1_CR2: u32 = SPI1_BASE + SPI_CR2_OFF;
/// `SPI1_CFG1` absolute address.
pub(crate) const SPI1_CFG1: u32 = SPI1_BASE + SPI_CFG1_OFF;
/// `SPI1_CFG2` absolute address.
pub(crate) const SPI1_CFG2: u32 = SPI1_BASE + SPI_CFG2_OFF;
/// `SPI1_SR` absolute address.
pub(crate) const SPI1_SR: u32 = SPI1_BASE + SPI_SR_OFF;
/// `SPI1_IFCR` absolute address.
pub(crate) const SPI1_IFCR: u32 = SPI1_BASE + SPI_IFCR_OFF;
/// `SPI1_TXDR` absolute address (byte access only at DSIZE = 8).
pub(crate) const SPI1_TXDR: u32 = SPI1_BASE + SPI_TXDR_OFF;
/// `SPI1_RXDR` absolute address (byte access only at DSIZE = 8).
pub(crate) const SPI1_RXDR: u32 = SPI1_BASE + SPI_RXDR_OFF;

// --- SPI_CR1 bits. RM0456 sec 68.8.1. ---

/// `SPI_CR1.SPE` bit 0: serial peripheral enable. RM0456 sec 68.8.1.
pub(crate) const SPI_CR1_SPE: u32 = 1 << 0;
/// `SPI_CR1.MASRX` bit 8: master automatic suspension in receive mode. Set so the
/// master suspends SCK on an RxFIFO-full condition before it can overrun, closing
/// the OVR window when an IRQ preempts the byte loop. RM0456 sec 68.8.1.
pub(crate) const SPI_CR1_MASRX: u32 = 1 << 8;
/// `SPI_CR1.CSTART` bit 9: master transfer start. RM0456 sec 68.8.1.
pub(crate) const SPI_CR1_CSTART: u32 = 1 << 9;
/// `SPI_CR1.SSI` bit 12: internal slave-select level (active when SSM = 1). Held
/// high to keep the internal select inactive, which prevents a master MODF.
/// RM0456 sec 68.8.1.
pub(crate) const SPI_CR1_SSI: u32 = 1 << 12;

// --- SPI_CR2 fields. RM0456 sec 68.8.2. ---

/// `SPI_CR2.TSIZE` field mask (bits [15:0]): number of data frames. TSIZE = 0
/// with CSTART selects an endless transfer (the software-CS PIO model). RM0456
/// sec 68.8.2.
pub(crate) const SPI_CR2_TSIZE_MASK: u32 = 0x0000_FFFF;

// --- SPI_CFG1 fields. RM0456 sec 68.8.3. ---

/// `SPI_CFG1.DSIZE` field shift (bits [4:0]). RM0456 sec 68.8.3.
pub(crate) const SPI_CFG1_DSIZE_SHIFT: u32 = 0;
/// `SPI_CFG1.DSIZE` field mask (bits [4:0]). RM0456 sec 68.8.3.
pub(crate) const SPI_CFG1_DSIZE_MASK: u32 = 0x1F << SPI_CFG1_DSIZE_SHIFT;
/// `DSIZE` value for an 8-bit frame: encoded as N-1 = 7. RM0456 sec 68.8.3.
pub(crate) const SPI_CFG1_DSIZE_8BIT: u32 = 7 << SPI_CFG1_DSIZE_SHIFT;
/// `SPI_CFG1.FTHLV` field shift (bits [8:5]). RM0456 sec 68.8.3.
pub(crate) const SPI_CFG1_FTHLV_SHIFT: u32 = 5;
/// `SPI_CFG1.FTHLV` field mask (bits [8:5]). RM0456 sec 68.8.3.
pub(crate) const SPI_CFG1_FTHLV_MASK: u32 = 0xF << SPI_CFG1_FTHLV_SHIFT;
/// `FTHLV` value for a 1-data threshold (`0b0000`). RM0456 sec 68.8.3.
pub(crate) const SPI_CFG1_FTHLV_1DATA: u32 = 0 << SPI_CFG1_FTHLV_SHIFT;
/// `SPI_CFG1.MBR` field shift (bits [30:28]): master baud-rate prescaler. RM0456
/// sec 68.8.3.
pub(crate) const SPI_CFG1_MBR_SHIFT: u32 = 28;
/// `SPI_CFG1.MBR` field mask (bits [30:28]). RM0456 sec 68.8.3.
pub(crate) const SPI_CFG1_MBR_MASK: u32 = 0x7 << SPI_CFG1_MBR_SHIFT;
/// `MBR` value for a /128 prescaler (`0b110`): a slow SCK well under the
/// TROPIC01 maximum from an MSI-derived kernel clock. RM0456 sec 68.8.3.
pub(crate) const SPI_CFG1_MBR_DIV128: u32 = 0b110 << SPI_CFG1_MBR_SHIFT;

// --- SPI_CFG2 bits. RM0456 sec 68.8.4. ---

/// `SPI_CFG2.COMM` field shift (bits [18:17]): communication mode. RM0456 sec
/// 68.8.4.
pub(crate) const SPI_CFG2_COMM_SHIFT: u32 = 17;
/// `SPI_CFG2.COMM` field mask (bits [18:17]). RM0456 sec 68.8.4.
pub(crate) const SPI_CFG2_COMM_MASK: u32 = 0x3 << SPI_CFG2_COMM_SHIFT;
/// `COMM` value for full-duplex (`0b00`). RM0456 sec 68.8.4.
pub(crate) const SPI_CFG2_COMM_FULL_DUPLEX: u32 = 0b00 << SPI_CFG2_COMM_SHIFT;
/// `SPI_CFG2.MASTER` bit 22: master mode. RM0456 sec 68.8.4.
pub(crate) const SPI_CFG2_MASTER: u32 = 1 << 22;
/// `SPI_CFG2.LSBFRST` bit 23: 0 = MSB first. Defined so the MSB-first invariant
/// is checked (the init leaves it clear). RM0456 sec 68.8.4.
pub(crate) const SPI_CFG2_LSBFRST: u32 = 1 << 23;
/// `SPI_CFG2.CPHA` bit 24: clock phase. 0 = first edge captures (SPI mode 0).
/// RM0456 sec 68.8.4.
pub(crate) const SPI_CFG2_CPHA: u32 = 1 << 24;
/// `SPI_CFG2.CPOL` bit 25: clock polarity. 0 = SCK idles low (SPI mode 0).
/// RM0456 sec 68.8.4.
pub(crate) const SPI_CFG2_CPOL: u32 = 1 << 25;
/// `SPI_CFG2.SSM` bit 26: software slave management. 1 frees the NSS pin for the
/// software GPIO CS. RM0456 sec 68.8.4.
pub(crate) const SPI_CFG2_SSM: u32 = 1 << 26;
/// `SPI_CFG2.SSOE` bit 29: NSS output enable. Left 0 so the peripheral never
/// drives the NSS pin (the CS is the software GPIO PA4). RM0456 sec 68.8.4.
pub(crate) const SPI_CFG2_SSOE: u32 = 1 << 29;
/// `SPI_CFG2.AFCNTR` bit 31: AF GPIO control kept by the peripheral even when
/// SPE = 0, avoiding line glitches across CS toggles. In the endless model SPE
/// stays set between transactions, so AFCNTR keeps the AF pins driven while the
/// engine idles between GPIO-CS windows. RM0456 sec 68.8.4.
pub(crate) const SPI_CFG2_AFCNTR: u32 = 1 << 31;

// --- SPI_SR bits. RM0456 sec 68.8.6. ---

/// `SPI_SR.RXP` bit 0: an Rx packet is available to read from RXDR. RM0456 sec
/// 68.8.6.
pub(crate) const SPI_SR_RXP: u32 = 1 << 0;
/// `SPI_SR.TXP` bit 1: TxFIFO has space for a packet to write to TXDR. RM0456
/// sec 68.8.6.
pub(crate) const SPI_SR_TXP: u32 = 1 << 1;
/// `SPI_SR.OVR` bit 6: receive overrun. RM0456 sec 68.8.6.
pub(crate) const SPI_SR_OVR: u32 = 1 << 6;
/// `SPI_SR.MODF` bit 9: mode fault. Set when MASTER and SSM are both set while
/// SSI is 0 (the internal slave-select is asserted low). A latched MODF
/// hardware-clears MASTER and SPE and is
/// cleared only by writing `IFCR.MODFC`. Defined so the host model can observe the
/// fault the silicon would raise (production code prevents MODF by ordering, so it
/// never reads this flag). RM0456 sec 68.8.6.
#[cfg(test)]
pub(crate) const SPI_SR_MODF: u32 = 1 << 9;

// --- SPI_IFCR bits. RM0456 sec 68.8.7. ---

/// `SPI_IFCR.EOTC` bit 3: clear EOT. RM0456 sec 68.8.7.
pub(crate) const SPI_IFCR_EOTC: u32 = 1 << 3;
/// `SPI_IFCR.TXTFC` bit 4: clear TXTF. RM0456 sec 68.8.7.
pub(crate) const SPI_IFCR_TXTFC: u32 = 1 << 4;
/// `SPI_IFCR.OVRC` bit 6: clear OVR. RM0456 sec 68.8.7.
pub(crate) const SPI_IFCR_OVRC: u32 = 1 << 6;
/// `SPI_IFCR.MODFC` bit 9: clear MODF (mode fault). This SPI clears a latched
/// mode fault by WRITING 1 here, NOT by the legacy read-SR-then-write-CR1
/// sequence of the older SPI. A latched MODF hardware-clears MASTER and SPE, so
/// until MODFC is written the master cannot re-enable. RM0456 sec 68.8.7.
pub(crate) const SPI_IFCR_MODFC: u32 = 1 << 9;

/// Returns the 2-bit-field shift for `pin` in a MODER/OSPEEDR/PUPDR register.
pub(crate) const fn field2_shift(pin: u32) -> u32
{
    pin * 2
}

/// Returns the 4-bit-field shift for `pin` (0..7) in the AFRL register.
pub(crate) const fn afrl_shift(pin: u32) -> u32
{
    pin * 4
}

/// Returns the BSRR bit that DRIVES `pin` low (reset half, bits [31:16]).
pub(crate) const fn bsrr_reset(pin: u32) -> u32
{
    1 << (pin + 16)
}

/// Returns the BSRR bit that DRIVES `pin` high (set half, bits [15:0]).
pub(crate) const fn bsrr_set(pin: u32) -> u32
{
    1 << pin
}

#[cfg(test)]
#[path = "regs_pin_tests.rs"]
mod regs_pin_tests;
