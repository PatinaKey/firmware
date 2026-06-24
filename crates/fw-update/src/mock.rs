//! Host mock of the update seams.
//!
//! [`MockFlash`] models the inactive bank as an in-RAM byte array plus the
//! persistent counters, records, and the bank-select state. [`MockSeCounter`]
//! models the secure-element down-counter. Both expose fault-injection switches
//! so a test can prove every seam error collapses to a state that keeps the OLD
//! bank bootable.
//!
//! Compiled only for host tests and the fuzz harness. Production never links
//! this: the real flash MMIO lives in a separate hardware-gated crate.

#![cfg(any(test, feature = "_fuzz"))]

use crate::seam::BankId;
use crate::seam::FlashError;
use crate::seam::FlashSeam;
use crate::seam::PageIndex;
use crate::seam::PendingFlag;
use crate::seam::SeCounterError;
use crate::seam::SeCounterSeam;

/// The modelled page size in bytes.
pub const PAGE_LEN: usize = 256;

/// The modelled inactive-bank size in bytes.
///
/// Sized to hold a representative update image in host tests. The real bank
/// geometry comes from the hardware-gated flash driver, not this mock.
pub const BANK_LEN: usize = 4096;

/// Where a seam call should be forced to fail, for fail-closed tests.
///
/// `None` means the mock behaves normally. Any other variant makes the matching
/// seam method return its typed error on the next call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FaultPoint
{
    /// No injected fault.
    #[default]
    None,
    /// [`FlashSeam::erase_inactive`] fails.
    Erase,
    /// [`FlashSeam::write_inactive_page`] fails.
    WritePage,
    /// [`FlashSeam::commit_swap`] fails.
    Commit,
    /// [`FlashSeam::revert_swap`] fails.
    Revert,
    /// [`FlashSeam::nvcnt_bump`] fails.
    NvcntBump,
    /// [`FlashSeam::pending_write`] fails.
    PendingWrite,
    /// [`FlashSeam::boot_count_advance`] fails.
    BootCount,
}

/// A host model of the inactive bank and the persistent update records.
///
/// `committed` and `reverted` record whether the matching seam call was issued,
/// so a test can assert the OLD bank stays bootable on any failure path. The
/// mock writes NO real flash and arms NO real SWAP_BANK.
pub struct MockFlash
{
    bank: [u8; BANK_LEN],
    nvcnt: u32,
    pending: PendingFlag,
    boot_count: u32,
    running: BankId,
    target: BankId,
    fault: FaultPoint,
    committed: bool,
    reverted: bool,
}

impl MockFlash
{
    /// Builds an erased bank with the given starting flash counter.
    ///
    /// Models the OLD bank as [`BankId::Bank1`] running and [`BankId::Bank2`] as
    /// the inactive target the swap would make bootable.
    pub fn new(nvcnt: u32) -> MockFlash
    {
        MockFlash
        {
            bank: [0xFF; BANK_LEN],
            nvcnt,
            pending: PendingFlag::None,
            boot_count: 0,
            running: BankId::Bank1,
            target: BankId::Bank2,
            fault: FaultPoint::None,
            committed: false,
            reverted: false,
        }
    }

    /// Arms a single injected fault for the next matching seam call.
    pub fn set_fault(&mut self, fault: FaultPoint)
    {
        self.fault = fault;
    }

    /// Forces the persistent pending record, modelling a state after a reset.
    pub fn force_pending(&mut self, flag: PendingFlag)
    {
        self.pending = flag;
    }

    /// Forces the running bank, modelling which bank a reset booted.
    pub fn force_running(&mut self, bank: BankId)
    {
        self.running = bank;
    }

    /// True once [`FlashSeam::commit_swap`] was issued.
    pub fn committed(&self) -> bool
    {
        self.committed
    }

    /// True once [`FlashSeam::revert_swap`] was issued.
    pub fn reverted(&self) -> bool
    {
        self.reverted
    }

    /// Reads back the modelled bank contents (test inspection only).
    pub fn bank(&self) -> &[u8]
    {
        &self.bank
    }

    /// The stored flash anti-rollback counter (test inspection only).
    pub fn nvcnt(&self) -> u32
    {
        self.nvcnt
    }

    /// Takes the injected fault if it matches `point`, else returns false.
    fn take_fault(&mut self, point: FaultPoint) -> bool
    {
        if self.fault == point
        {
            self.fault = FaultPoint::None;
            return true;
        }
        false
    }
}

impl FlashSeam for MockFlash
{
    fn inactive_bank(&self) -> &[u8]
    {
        &self.bank
    }

    fn erase_inactive(&mut self) -> Result<(), FlashError>
    {
        if self.take_fault(FaultPoint::Erase)
        {
            return Err(FlashError::Hardware);
        }
        self.bank = [0xFF; BANK_LEN];
        Ok(())
    }

    fn write_inactive_page
    (
        &mut self,
        page: PageIndex,
        data: &[u8],
    )
        -> Result<(), FlashError>
    {
        if self.take_fault(FaultPoint::WritePage)
        {
            return Err(FlashError::WriteFailed);
        }
        if data.len() > PAGE_LEN
        {
            return Err(FlashError::WriteFailed);
        }
        let start = (page as usize)
            .checked_mul(PAGE_LEN)
            .ok_or(FlashError::OutOfRange)?;
        let end = start
            .checked_add(data.len())
            .ok_or(FlashError::OutOfRange)?;
        let slot = self
            .bank
            .get_mut(start..end)
            .ok_or(FlashError::OutOfRange)?;
        slot.copy_from_slice(data);
        Ok(())
    }

    fn running_bank(&mut self) -> Result<BankId, FlashError>
    {
        Ok(self.running)
    }

    fn target_bank(&mut self) -> Result<BankId, FlashError>
    {
        Ok(self.target)
    }

    fn commit_swap(&mut self) -> Result<(), FlashError>
    {
        if self.take_fault(FaultPoint::Commit)
        {
            return Err(FlashError::Hardware);
        }
        self.committed = true;
        // Model the swap reset: the next boot runs from the target bank.
        self.running = self.target;
        Ok(())
    }

    fn revert_swap(&mut self) -> Result<(), FlashError>
    {
        if self.take_fault(FaultPoint::Revert)
        {
            return Err(FlashError::Hardware);
        }
        self.reverted = true;
        Ok(())
    }

    fn nvcnt_read(&mut self) -> Result<u32, FlashError>
    {
        Ok(self.nvcnt)
    }

    fn nvcnt_bump(&mut self, value: u32) -> Result<(), FlashError>
    {
        if self.take_fault(FaultPoint::NvcntBump)
        {
            return Err(FlashError::CounterExhausted);
        }
        if value < self.nvcnt
        {
            return Err(FlashError::WriteFailed);
        }
        self.nvcnt = value;
        Ok(())
    }

    fn pending_read(&mut self) -> Result<PendingFlag, FlashError>
    {
        Ok(self.pending)
    }

    fn pending_write(&mut self, flag: PendingFlag) -> Result<(), FlashError>
    {
        if self.take_fault(FaultPoint::PendingWrite)
        {
            return Err(FlashError::WriteFailed);
        }
        self.pending = flag;
        Ok(())
    }

    fn boot_count_read(&mut self) -> Result<u32, FlashError>
    {
        Ok(self.boot_count)
    }

    fn boot_count_advance(&mut self) -> Result<(), FlashError>
    {
        if self.take_fault(FaultPoint::BootCount)
        {
            return Err(FlashError::WriteFailed);
        }
        self.boot_count = self
            .boot_count
            .checked_add(1)
            .ok_or(FlashError::WriteFailed)?;
        Ok(())
    }
}

/// A host model of the secure-element down-counter (Gate 2).
pub struct MockSeCounter
{
    value: u32,
    available: bool,
    updated: bool,
}

impl MockSeCounter
{
    /// Builds a counter at `value`, channel up.
    pub fn new(value: u32) -> MockSeCounter
    {
        MockSeCounter
        {
            value,
            available: true,
            updated: false,
        }
    }

    /// Forces the channel down, modelling a secure-element not yet ready.
    pub fn set_unavailable(&mut self)
    {
        self.available = false;
    }

    /// True once [`SeCounterSeam::update`] decremented the counter.
    pub fn updated(&self) -> bool
    {
        self.updated
    }

    /// The current modelled value (test inspection only).
    pub fn value(&self) -> u32
    {
        self.value
    }
}

impl SeCounterSeam for MockSeCounter
{
    fn read(&mut self) -> Result<u32, SeCounterError>
    {
        if !self.available
        {
            return Err(SeCounterError::Unavailable);
        }
        Ok(self.value)
    }

    fn update(&mut self) -> Result<(), SeCounterError>
    {
        if !self.available
        {
            return Err(SeCounterError::Unavailable);
        }
        let next = self
            .value
            .checked_sub(1)
            .ok_or(SeCounterError::Exhausted)?;
        self.value = next;
        self.updated = true;
        Ok(())
    }
}
