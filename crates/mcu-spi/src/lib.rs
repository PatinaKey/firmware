//! STM32U545 blocking SPI1 master driver for the TROPIC01 secure element.
//!
//! Provides an `embedded-hal` 1.0 `SpiDevice` ([`Spi1Device`]) and a blocking
//! `SeWait` ([`CycleWait`]) the TROPIC01 driver consumes, all behind a
//! host-testable register seam ([`SpiBusAccess`]). The driver is a polled-I/O
//! SPI1 master plus a software GPIO chip-select on PA4 (active-low), in SPI mode
//! 0, MSB-first, 8-bit frames. It does the FUNCTIONAL bring-up the TrustZone
//! partition leaves out: the RCC SPI1 / GPIOA clock enable, the GPIO mode / AF /
//! speed / pull setup for PA4-7, and the SPI control-register init plus the PIO
//! transfer. It does NOT touch GTZC / TZSC security: the partition already marks
//! SPI1 and PA4-7 secure.
//!
//! # Design for testability
//!
//! The init sequence and the byte transfer loop run against [`SpiBusAccess`], so
//! they are hardware-independent and host-testable. [`MmioSpiBus`] is the real
//! volatile-MMIO implementation (the crate's ONLY `unsafe`, gated to the embedded
//! target), with 32-bit accesses for the control / config / STATUS / RCC / GPIO
//! registers and 8-bit accesses for `TXDR` / `RXDR` (the data registers are
//! accessed at the configured data width: a 32-bit access at `DSIZE` = 8 packs
//! four frames into one access, RM0456 sec 68.4.12). Host tests drive the loop
//! through a SCRIPTED bus that returns a
//! programmed sequence of STATUS and data reads, which a config-register
//! recording bus cannot model.
//!
//! # Register definitions
//!
//! The registers are HAND-ROLLED and cited (`regs`), not pulled from the full
//! `stm32u5` PAC. Every address and key bit is pinned to a primary-source literal
//! in the `regs` pinning tests. Sources are RM0456 (registers) and the
//! STM32U545CEU6Q datasheet (the AF5 alternate-function map).

#![cfg_attr(not(test), no_std)]

mod bus;
mod regs;
mod spi;
mod wait;

#[cfg(target_os = "none")]
pub use crate::bus::MmioSpiBus;
pub use crate::bus::SpiBusAccess;
pub use crate::spi::Spi1Device;
pub use crate::spi::Spi1Error;
pub use crate::wait::CycleWait;

#[cfg(test)]
mod tests;
