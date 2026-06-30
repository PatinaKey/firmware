//! `ScriptedBus`: a host test double that returns a programmed read sequence.
//!
//! The SPI transfer loop polls STATUS flags (`SR.TXP` / `SR.RXP` / `SR.EOT`)
//! whose value changes on its own, and reads `RXDR` data bytes that depend on
//! what the chip would clock back. The `platform` `RecordingBus` cannot model
//! either: it returns the last value WRITTEN to an address, which is correct for a
//! config register but wrong for a status or data register.
//!
//! `ScriptedBus` separates the two kinds of register:
//!   - CONFIG registers (and any unscripted 32-bit address) read back the last
//!     value written, exactly like a recording bus, so the init writes are
//!     observable and a read-modify-write is faithful.
//!   - SCRIPTED addresses return the next value from a per-address QUEUE that the
//!     test programs ahead of time. A 32-bit queue feeds `read32` (the `SR`
//!     polls), an 8-bit queue feeds `read8` (the `RXDR` reads). When a scripted
//!     queue runs dry the read panics, which is a TEST failure surfacing an
//!     unscripted poll, never production behaviour.
//!
//! Writes are recorded in order as typed `(addr, value)` entries, so a test
//! asserts both the values and the ordering of the init sequence and the data
//! writes.

use std::collections::HashMap;
use std::collections::VecDeque;

use super::SpiBusAccess;
use crate::regs;

/// A single recorded write, tagged 32-bit (`Word`) or 8-bit (`Byte`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Write
{
    /// A 32-bit write of `value` to `addr`.
    Word
    {
        /// Target address.
        addr: u32,
        /// Written value.
        value: u32,
    },
    /// An 8-bit write of `value` to `addr`.
    Byte
    {
        /// Target address.
        addr: u32,
        /// Written value.
        value: u8,
    },
}

/// A scriptable register bus for host tests.
///
/// Programs a queue of `read32` results per status address and a queue of `read8`
/// results per data address, models every other 32-bit address as read == last
/// write, and records all writes in order.
pub(crate) struct ScriptedBus
{
    /// Last value written to each 32-bit address (config-register model).
    config: HashMap<u32, u32>,
    /// Programmed `read32` results per address (consumed front-to-back).
    word_reads: HashMap<u32, VecDeque<u32>>,
    /// Programmed `read8` results per address (consumed front-to-back).
    byte_reads: HashMap<u32, VecDeque<u8>>,
    /// Ordered log of every write.
    writes: Vec<Write>,
}

impl ScriptedBus
{
    /// Builds an empty scripted bus (every unscripted 32-bit address reads 0).
    pub(crate) fn new() -> Self
    {
        ScriptedBus
        {
            config: HashMap::new(),
            word_reads: HashMap::new(),
            byte_reads: HashMap::new(),
            writes: Vec::new(),
        }
    }

    /// Programs the next `read32(addr)` results, appended in order.
    pub(crate) fn script_word_reads(&mut self, addr: u32, values: &[u32])
    {
        self.word_reads
            .entry(addr)
            .or_default()
            .extend(values.iter().copied());
    }

    /// Programs the next `read8(addr)` results, appended in order.
    pub(crate) fn script_byte_reads(&mut self, addr: u32, values: &[u8])
    {
        self.byte_reads
            .entry(addr)
            .or_default()
            .extend(values.iter().copied());
    }

    /// Borrows the ordered write log.
    pub(crate) fn writes(&self) -> &[Write]
    {
        &self.writes
    }

    /// Returns the index of the first WORD write to `addr`, or `None`.
    pub(crate) fn first_word_write_index(&self, addr: u32) -> Option<usize>
    {
        self.writes.iter().position(|w| {
            matches!(w, Write::Word { addr: a, .. } if *a == addr)
        })
    }

    /// Returns the value of the last WORD write to `addr`, or `None`.
    pub(crate) fn last_word_value(&self, addr: u32) -> Option<u32>
    {
        self.writes.iter().rev().find_map(|w| match w
        {
            Write::Word { addr: a, value } if *a == addr => Some(*value),
            _ => None,
        })
    }

    /// Models the silicon mode-fault (MODF) the host recording bus cannot show.
    ///
    /// The recording bus reads back the last value written, so it never raises a
    /// status the firmware did not write. On real silicon, selecting MASTER under
    /// software slave management while the internal slave-select is low (CR1.SSI =
    /// 0) ARMS a mode fault: SR.MODF latches and the hardware clears MASTER and SPE.
    /// This models exactly that one transition, plus the IFCR.MODFC clear, so a test
    /// can observe the fault the wrong write order would cause.
    ///
    /// The latch lands in the config-readback map, and `read32` serves a scripted
    /// queue first, so a latched MODF is observable only when SR is read without a
    /// scripted value (the init tests, which never script SR). The transfer tests
    /// script SR for the polling loop and do not exercise this fault.
    fn model_mode_fault(&mut self, addr: u32, value: u32)
    {
        if addr == regs::SPI1_CFG2
        {
            let sets_master_with_ssm = value & regs::SPI_CFG2_MASTER != 0
                && value & regs::SPI_CFG2_SSM != 0;
            let ssi_high =
                self.config.get(&regs::SPI1_CR1).copied().unwrap_or(0) & regs::SPI_CR1_SSI != 0;
            if sets_master_with_ssm && !ssi_high
            {
                // Latch MODF and drop MASTER + SPE, as the hardware does.
                let sr = self.config.entry(regs::SPI1_SR).or_default();
                *sr |= regs::SPI_SR_MODF;
                let cfg2 = self.config.entry(regs::SPI1_CFG2).or_default();
                *cfg2 &= !regs::SPI_CFG2_MASTER;
                let cr1 = self.config.entry(regs::SPI1_CR1).or_default();
                *cr1 &= !regs::SPI_CR1_SPE;
            }
        }
        else if addr == regs::SPI1_IFCR
            && value & regs::SPI_IFCR_MODFC != 0
            && let Some(sr) = self.config.get_mut(&regs::SPI1_SR)
        {
            *sr &= !regs::SPI_SR_MODF;
        }
    }

    /// Returns the ordered byte values written to `addr`.
    pub(crate) fn byte_writes(&self, addr: u32) -> Vec<u8>
    {
        self.writes
            .iter()
            .filter_map(|w| match w
            {
                Write::Byte { addr: a, value } if *a == addr => Some(*value),
                _ => None,
            })
            .collect()
    }
}

impl SpiBusAccess for ScriptedBus
{
    fn read32(&mut self, addr: u32) -> u32
    {
        if let Some(queue) = self.word_reads.get_mut(&addr)
        {
            return queue
                .pop_front()
                .expect("scripted word-read queue underflowed: an unscripted SR poll");
        }
        self.config.get(&addr).copied().unwrap_or(0)
    }

    fn write32(&mut self, addr: u32, value: u32)
    {
        self.config.insert(addr, value);
        self.writes.push(Write::Word { addr, value });
        self.model_mode_fault(addr, value);
    }

    fn read8(&mut self, addr: u32) -> u8
    {
        let queue = self
            .byte_reads
            .get_mut(&addr)
            .expect("read8 of an unscripted address: program a byte-read queue first");
        queue
            .pop_front()
            .expect("scripted byte-read queue underflowed: an unscripted RXDR read")
    }

    fn write8(&mut self, addr: u32, value: u8)
    {
        self.writes.push(Write::Byte { addr, value });
    }
}
