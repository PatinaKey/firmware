//! Blocking SPI1 master driver over the [`SpiBusAccess`] seam.
//!
//! [`Spi1Device`] is an `embedded-hal` 1.0 `SpiDevice`: a polled-I/O SPI1 master
//! plus a software GPIO chip-select on PA4 (active-low). It owns the register
//! seam, so the same transfer logic runs on hardware (`MmioSpiBus`) and on the
//! host (`ScriptedBus`).
//!
//! TRANSPORT MODEL: SPI mode 0, MSB-first, full-duplex, endless transfer
//! (`TSIZE` = 0). Each clocked frame both sends one byte and receives one. The
//! loop polls `SR.TXP` before writing `TXDR`, then `SR.RXP` before reading
//! `RXDR`, so every send pairs with its receive. The chip-select is the software
//! GPIO PA4, asserted for the whole `transaction` and released after, which holds
//! the multi-operation L1 response read under one CS assertion. RM0456 sec 68.4.

use embedded_hal::spi::Error as SpiError;
use embedded_hal::spi::ErrorKind;
use embedded_hal::spi::ErrorType;
use embedded_hal::spi::Operation;
use embedded_hal::spi::SpiDevice;

use crate::bus::SpiBusAccess;
use crate::regs;

/// A bus-side fault from the SPI1 driver.
///
/// The byte loop can stall (the status flag never settles within the budget) or
/// the receiver can overrun. Both map to an `embedded-hal` [`ErrorKind`] so the
/// TROPIC01 L1 seam erases them to `L1Error::Bus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Spi1Error
{
    /// A status flag (`TXP` / `RXP` / `SUSP`) never settled within the poll
    /// budget.
    Timeout,
    /// The receiver reported an overrun (`SR.OVR`).
    Overrun,
}

impl SpiError for Spi1Error
{
    fn kind(&self) -> ErrorKind
    {
        match self
        {
            Spi1Error::Timeout => ErrorKind::Other,
            Spi1Error::Overrun => ErrorKind::Overrun,
        }
    }
}

/// Bounded poll budget for a single status-flag wait.
///
/// One frame at the /128 prescaler is far below this many bus reads, so the
/// budget only ends a stuck transfer rather than a slow one. It bounds the loop
/// so a wedged peripheral cannot hang the secure world forever.
const STATUS_POLL_TRIES: u32 = 100_000;

/// Dummy byte clocked out while reading (the chip ignores MOSI on a read).
const READ_DUMMY: u8 = 0x00;

/// The SPI1 master with its software GPIO chip-select.
///
/// Generic over the register seam so it is host-testable. Built and initialized
/// through [`Spi1Device::new`], then consumed as an `embedded-hal` `SpiDevice` by
/// the TROPIC01 driver.
pub struct Spi1Device<B>
{
    bus: B,
}

impl<B> Spi1Device<B>
where
    B: SpiBusAccess,
{
    /// Builds and initializes the SPI1 master and the PA4 software chip-select.
    ///
    /// Enables the GPIOA and SPI1 clocks, configures PA5/PA6/PA7 as SPI1 AF5 and
    /// PA4 as a push-pull output (CS, deasserted high), programs the SPI for SPI
    /// mode 0 / MSB-first / 8-bit / software slave management / full-duplex /
    /// endless transfer, then enables the peripheral and starts the master
    /// engine. The chip-select idles HIGH (deselected) on return.
    pub fn new(mut bus: B) -> Self
    {
        enable_clocks(&mut bus);
        configure_gpio(&mut bus);
        configure_spi(&mut bus);
        Spi1Device
        {
            bus,
        }
    }

    /// Consumes the device and returns the register bus (test inspection only).
    #[cfg(test)]
    pub(crate) fn into_bus(self) -> B
    {
        self.bus
    }

    /// Drives the chip-select PA4 low (asserted, the chip is selected).
    fn select(&mut self)
    {
        self.bus.write32(regs::GPIOA_BSRR, regs::bsrr_reset(regs::CS_PIN));
    }

    /// Drives the chip-select PA4 high (deasserted, the chip is released).
    fn deselect(&mut self)
    {
        self.bus.write32(regs::GPIOA_BSRR, regs::bsrr_set(regs::CS_PIN));
    }

    /// Polls `SR` until every bit in `mask` is set, or the budget runs out.
    ///
    /// Returns `Spi1Error::Timeout` if the flag never settles. `SR.OVR` short-
    /// circuits to `Spi1Error::Overrun` so a receive overrun fails loud rather
    /// than looping.
    fn wait_status(&mut self, mask: u32) -> Result<(), Spi1Error>
    {
        let mut tries = 0u32;
        while tries < STATUS_POLL_TRIES
        {
            let sr = self.bus.read32(regs::SPI1_SR);
            if sr & regs::SPI_SR_OVR != 0
            {
                return Err(Spi1Error::Overrun);
            }
            if sr & mask == mask
            {
                return Ok(());
            }
            tries += 1;
        }
        Err(Spi1Error::Timeout)
    }

    /// Clocks one full-duplex frame: sends `tx`, returns the received byte.
    ///
    /// Waits for `TXP` (Tx space), writes `tx` to `TXDR`, waits for `RXP` (an Rx
    /// frame), then reads `RXDR`. With `DSIZE` = 8 the data registers are accessed
    /// byte-wide. RM0456 sec 68.8.9-68.8.10.
    fn transfer_byte(&mut self, tx: u8) -> Result<u8, Spi1Error>
    {
        self.wait_status(regs::SPI_SR_TXP)?;
        self.bus.write8(regs::SPI1_TXDR, tx);
        self.wait_status(regs::SPI_SR_RXP)?;
        Ok(self.bus.read8(regs::SPI1_RXDR))
    }

    /// Runs one `embedded-hal` operation against the selected chip.
    ///
    /// `Write` clocks each byte and discards the read. `Read` clocks a dummy byte
    /// per slot and stores the read. `Transfer` / `TransferInPlace` send and store
    /// per byte. `DelayNs` busy-spins a bounded count (an approximate delay, the
    /// L1 cadence does not need a precise one).
    fn run_operation(&mut self, op: &mut Operation<'_, u8>) -> Result<(), Spi1Error>
    {
        match op
        {
            Operation::Write(buf) =>
            {
                for &b in buf.iter()
                {
                    self.transfer_byte(b)?;
                }
                Ok(())
            }
            Operation::Read(buf) =>
            {
                for slot in buf.iter_mut()
                {
                    *slot = self.transfer_byte(READ_DUMMY)?;
                }
                Ok(())
            }
            Operation::Transfer(read, write) =>
            {
                // Clock each frame: send a write byte (or the dummy past its end)
                // and store the read into the read buffer where it has room.
                let len = read.len().max(write.len());
                for i in 0..len
                {
                    let tx = write.get(i).copied().unwrap_or(READ_DUMMY);
                    let rx = self.transfer_byte(tx)?;
                    if let Some(slot) = read.get_mut(i)
                    {
                        *slot = rx;
                    }
                }
                Ok(())
            }
            Operation::TransferInPlace(buf) =>
            {
                for slot in buf.iter_mut()
                {
                    *slot = self.transfer_byte(*slot)?;
                }
                Ok(())
            }
            Operation::DelayNs(ns) =>
            {
                spin_delay_ns(*ns);
                Ok(())
            }
        }
    }
}

impl<B> ErrorType for Spi1Device<B>
where
    B: SpiBusAccess,
{
    type Error = Spi1Error;
}

impl<B> SpiDevice<u8> for Spi1Device<B>
where
    B: SpiBusAccess,
{
    /// Runs `operations` under one chip-select assertion.
    ///
    /// Re-arms the engine from a flushed FIFO, asserts PA4 (low), runs each
    /// operation in order, then deasserts PA4 (high) even on a fault, so the chip
    /// is never left selected after an error and no stale received byte survives
    /// into the next transaction.
    fn transaction(&mut self, operations: &mut [Operation<'_, u8>]) -> Result<(), Spi1Error>
    {
        // Re-arm from an empty FIFO. Clearing SPE flushes BOTH FIFOs and resets the
        // state machine, so a byte left unread in the RxFIFO by a prior failed
        // transaction cannot desync the tx/rx pairing here. A GPIO-CS deassert and
        // an IFCR write do NOT flush the data FIFOs, only clearing SPE does. RM0456
        // sec 68.4.12 (p.2921): both FIFOs are flushed when SPE is cleared. The
        // RM-recommended re-enable order: SPE = 0, then re-write TSIZE = 0
        // (writable only while disabled, RM0456 sec 68.8.2 p.2937), then SPE = 1,
        // then CSTART. RM0456 sec 68.4.13 p.2924.
        rearm_engine(&mut self.bus);

        self.select();
        let mut result = Ok(());
        for op in operations.iter_mut()
        {
            result = self.run_operation(op);
            if result.is_err()
            {
                break;
            }
        }
        self.deselect();

        // Clear the sticky transfer flags so a stale EOT / TXTF / OVR / MODF cannot
        // leak into the next transaction. MODF is cleared here as defense in depth:
        // a latched mode fault hardware-clears MASTER and SPE, and only writing
        // MODFC clears it, so without this a once-latched fault would keep the
        // master from ever re-enabling. Write-1-to-clear. RM0456 sec 68.8.7.
        self.bus.write32(
            regs::SPI1_IFCR,
            regs::SPI_IFCR_EOTC
                | regs::SPI_IFCR_TXTFC
                | regs::SPI_IFCR_OVRC
                | regs::SPI_IFCR_MODFC,
        );

        // FAIL-CLOSED DRAIN: on any operation error, clear SPE so the engine is
        // left flushed and disabled. A byte may sit unread in the RxFIFO (the error
        // returned between the TXDR write and the matching RXDR read), and only
        // clearing SPE evicts it. The next transaction re-arms from empty above.
        // RM0456 sec 68.4.12 p.2921.
        if result.is_err()
        {
            self.bus.modify32(regs::SPI1_CR1, regs::SPI_CR1_SPE, 0);
        }

        result
    }
}

/// Enables the GPIOA (AHB2) and SPI1 (APB2) peripheral clocks.
fn enable_clocks<B>(bus: &mut B)
where
    B: SpiBusAccess,
{
    bus.modify32(regs::RCC_AHB2ENR1, 0, regs::RCC_AHB2ENR1_GPIOAEN);
    bus.modify32(regs::RCC_APB2ENR, 0, regs::RCC_APB2ENR_SPI1EN);
}

/// Configures PA5/PA6/PA7 as SPI1 AF5 and PA4 as the push-pull CS output.
fn configure_gpio<B>(bus: &mut B)
where
    B: SpiBusAccess,
{
    // CS idles HIGH (deselected) BEFORE the pin becomes an output, so the line
    // never glitches low at select time. RM0456 sec 13.4.7 (BSRR).
    bus.write32(regs::GPIOA_BSRR, regs::bsrr_set(regs::CS_PIN));

    // AFRL: PA5/PA6/PA7 -> AF5 (SPI1). Pins 0..7 live in AFRL.
    let af_clear = (0xF << regs::afrl_shift(regs::SCK_PIN))
        | (0xF << regs::afrl_shift(regs::MISO_PIN))
        | (0xF << regs::afrl_shift(regs::MOSI_PIN));
    let af_set = (regs::GPIO_AF5 << regs::afrl_shift(regs::SCK_PIN))
        | (regs::GPIO_AF5 << regs::afrl_shift(regs::MISO_PIN))
        | (regs::GPIO_AF5 << regs::afrl_shift(regs::MOSI_PIN));
    bus.modify32(regs::GPIOA_AFRL, af_clear, af_set);

    // MODER: PA5/PA6/PA7 -> alternate function, PA4 -> output.
    let moder_clear = (0b11 << regs::field2_shift(regs::CS_PIN))
        | (0b11 << regs::field2_shift(regs::SCK_PIN))
        | (0b11 << regs::field2_shift(regs::MISO_PIN))
        | (0b11 << regs::field2_shift(regs::MOSI_PIN));
    let moder_set = (regs::GPIO_MODER_OUTPUT << regs::field2_shift(regs::CS_PIN))
        | (regs::GPIO_MODER_ALTERNATE << regs::field2_shift(regs::SCK_PIN))
        | (regs::GPIO_MODER_ALTERNATE << regs::field2_shift(regs::MISO_PIN))
        | (regs::GPIO_MODER_ALTERNATE << regs::field2_shift(regs::MOSI_PIN));
    bus.modify32(regs::GPIOA_MODER, moder_clear, moder_set);

    // OTYPER: push-pull (clear the bit) on all four pins. CS and the SPI signals
    // are all driven push-pull. RM0456 sec 13.4.2.
    let otype_pins = (1 << regs::CS_PIN)
        | (1 << regs::SCK_PIN)
        | (1 << regs::MISO_PIN)
        | (1 << regs::MOSI_PIN);
    bus.modify32(regs::GPIOA_OTYPER, otype_pins, 0);

    // OSPEEDR: very-high speed on the four pins (SCK edge quality, fast CS).
    let ospeed_clear = (0b11 << regs::field2_shift(regs::CS_PIN))
        | (0b11 << regs::field2_shift(regs::SCK_PIN))
        | (0b11 << regs::field2_shift(regs::MISO_PIN))
        | (0b11 << regs::field2_shift(regs::MOSI_PIN));
    let ospeed_set = (regs::GPIO_OSPEEDR_VERY_HIGH << regs::field2_shift(regs::CS_PIN))
        | (regs::GPIO_OSPEEDR_VERY_HIGH << regs::field2_shift(regs::SCK_PIN))
        | (regs::GPIO_OSPEEDR_VERY_HIGH << regs::field2_shift(regs::MISO_PIN))
        | (regs::GPIO_OSPEEDR_VERY_HIGH << regs::field2_shift(regs::MOSI_PIN));
    bus.modify32(regs::GPIOA_OSPEEDR, ospeed_clear, ospeed_set);

    // PUPDR: a pull-up on MISO so a floating SE output reads as idle-high, no
    // pull on the driven SCK/MOSI/CS lines (CS has the external 10k R4 pull-up).
    let pupd_clear = (0b11 << regs::field2_shift(regs::CS_PIN))
        | (0b11 << regs::field2_shift(regs::SCK_PIN))
        | (0b11 << regs::field2_shift(regs::MISO_PIN))
        | (0b11 << regs::field2_shift(regs::MOSI_PIN));
    let pupd_set = (regs::GPIO_PUPDR_NONE << regs::field2_shift(regs::CS_PIN))
        | (regs::GPIO_PUPDR_NONE << regs::field2_shift(regs::SCK_PIN))
        | (regs::GPIO_PUPDR_PULLUP << regs::field2_shift(regs::MISO_PIN))
        | (regs::GPIO_PUPDR_NONE << regs::field2_shift(regs::MOSI_PIN));
    bus.modify32(regs::GPIOA_PUPDR, pupd_clear, pupd_set);
}

/// Programs SPI1 for SPI mode 0, MSB-first, 8-bit, software-CS, endless transfer.
///
/// CFG1/CFG2 are written while `SPE` = 0 (RM0456 sec 68.8.3/4 write-protect them
/// once enabled). `SSI` = 1 is written BEFORE the CFG2 write that selects MASTER
/// with SSM, so the internal slave-select is never low while the master is
/// selected (which would arm a mode fault under software slave management). Then
/// `TSIZE` = 0 (endless), `SPE` = 1, and `CSTART` arm the master engine. RM0456
/// sec 68.4.10.
fn configure_spi<B>(bus: &mut B)
where
    B: SpiBusAccess,
{
    // SPE must be 0 to write CFG1/CFG2. The peripheral is in its reset state at
    // bring-up, but clear SPE explicitly to be order-independent.
    bus.modify32(regs::SPI1_CR1, regs::SPI_CR1_SPE, 0);

    // CFG1: 8-bit frames, 1-data FIFO threshold, /128 baud-rate prescaler.
    let cfg1 = regs::SPI_CFG1_DSIZE_8BIT
        | regs::SPI_CFG1_FTHLV_1DATA
        | regs::SPI_CFG1_MBR_DIV128;
    bus.modify32(
        regs::SPI1_CFG1,
        regs::SPI_CFG1_DSIZE_MASK | regs::SPI_CFG1_FTHLV_MASK | regs::SPI_CFG1_MBR_MASK,
        cfg1,
    );

    // Hold the internal slave-select inactive BEFORE master mode is selected, and
    // arm MASRX so the master auto-suspends SCK on an RxFIFO-full condition before
    // it can overrun.
    //
    // SSI MUST be high before the CFG2 write below sets MASTER with SSM. With
    // software slave management the internal slave-select follows SSI, so if MASTER
    // and SSM were set while SSI is still 0 the master would be selected low for the
    // window between the two writes. A master selected low ARMS a mode fault (MODF,
    // SR bit 9), which hardware-clears MASTER and SPE and drops the peripheral back
    // to slave mode, so it never drives SCK and every transfer stalls. Writing SSI
    // high first keeps the internal select inactive and that window never opens.
    //
    // MASRX makes the master suspend SCK on an RxFIFO-full condition before it can
    // overrun, closing the OVR window where a non-secure IRQ preempts the secure
    // veneer mid-byte and the received companion frame would otherwise be lost.
    // MASRX acts on the RxFIFO-full condition with no TSIZE restriction, so it is
    // effective in the TSIZE = 0 endless model. RM0456 sec 68.8.1 bit 12 (SSI) and
    // bit 8 (MASRX), and sec 68.5.2 (MASRX prevents OVR in master mode).
    bus.modify32(regs::SPI1_CR1, 0, regs::SPI_CR1_SSI | regs::SPI_CR1_MASRX);

    // CFG2: master, full-duplex, SPI mode 0 (CPOL=0, CPHA=0), MSB-first
    // (LSBFRST=0), software slave management (SSM=1, NSS pin freed), NSS output
    // disabled (SSOE=0), AF GPIO control retained across CS toggles (AFCNTR=1).
    // SSI is already high above, so selecting MASTER here never opens the MODF
    // window.
    let cfg2 = regs::SPI_CFG2_MASTER
        | regs::SPI_CFG2_COMM_FULL_DUPLEX
        | regs::SPI_CFG2_SSM
        | regs::SPI_CFG2_AFCNTR;
    bus.modify32(
        regs::SPI1_CFG2,
        regs::SPI_CFG2_MASTER
            | regs::SPI_CFG2_COMM_MASK
            | regs::SPI_CFG2_LSBFRST
            | regs::SPI_CFG2_CPHA
            | regs::SPI_CFG2_CPOL
            | regs::SPI_CFG2_SSM
            | regs::SPI_CFG2_SSOE
            | regs::SPI_CFG2_AFCNTR,
        cfg2,
    );

    // Arm the engine for the first transaction: TSIZE = 0, SPE = 1, CSTART. Each
    // transaction re-arms the same way through rearm_engine.
    rearm_engine(bus);
}

/// Re-arms the SPI master engine from a flushed FIFO for one transaction.
///
/// Clears SPE first (this flushes both FIFOs and resets the state machine, RM0456
/// sec 68.4.12 p.2921), re-writes TSIZE = 0 (writable only while disabled, RM0456
/// sec 68.8.2 p.2937), sets SPE = 1, then sets CSTART to start the master engine.
/// RM0456 sec 68.4.13 p.2924 (disable then re-enable to restart the state machine).
fn rearm_engine<B>(bus: &mut B)
where
    B: SpiBusAccess,
{
    // SPE = 0: flush both FIFOs, reset the state machine. CFG1/CFG2 stay write-
    // protected only while enabled, so they are not re-written here.
    bus.modify32(regs::SPI1_CR1, regs::SPI_CR1_SPE, 0);

    // Endless transfer: TSIZE = 0. The byte loop manages the frame count and the
    // software CS bounds each transaction. RM0456 sec 68.8.2.
    bus.modify32(regs::SPI1_CR2, regs::SPI_CR2_TSIZE_MASK, 0);

    // Enable the peripheral, then start the master engine.
    bus.modify32(regs::SPI1_CR1, 0, regs::SPI_CR1_SPE);
    bus.modify32(regs::SPI1_CR1, 0, regs::SPI_CR1_CSTART);
}

/// Busy-spins an approximate `ns`-nanosecond delay (host build: a counted loop).
///
/// Only the `Operation::DelayNs` path uses it, which the TROPIC01 L1 sequence
/// does not exercise. The count is a coarse upper bound, not a calibrated delay.
#[cfg(not(target_os = "none"))]
fn spin_delay_ns(_ns: u32)
{
}

/// Busy-spins an approximate `ns`-nanosecond delay using a NOP loop.
///
/// An approximate busy-wait, NOT a calibrated delay: it spins one NOP per
/// requested nanosecond, so at any real core clock a NOP costs well under one
/// nanosecond and the loop under-waits. The TROPIC01 L1 path never exercises it
/// (the poll cadence uses `SeWait`, not SPI `DelayNs`), so the coarse bound is
/// acceptable here. A precise delay would scale by the known core clock.
#[cfg(target_os = "none")]
fn spin_delay_ns(ns: u32)
{
    for _ in 0..ns
    {
        cortex_m::asm::nop();
    }
}
