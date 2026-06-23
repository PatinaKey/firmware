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
