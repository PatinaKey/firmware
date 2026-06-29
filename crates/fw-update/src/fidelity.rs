//! A fidelity host model of STM32U5 flash, for machine-checked power-fault tests.
//!
//! [`MockFlash`](crate::mock::MockFlash) is enough for the happy-path and
//! single-fault tests, but two silicon-only failure modes are structurally
//! invisible behind it. It writes pages with `copy_from_slice`, which can raise a
//! bit from 0 to 1 (real flash program only clears bits, RM0456 sec 7.3.1), and
//! its `commit_swap` flips the running bank INSTANTLY in the same call, whereas
//! real silicon stages SWAP_BANK and applies it only at the next reset (RM0456
//! sec 7.5.8). [`FidelityFlash`] models both, so the fault harness can inject a
//! torn write that survives as detectable corruption and a power loss between
//! arming the swap and the reset.
//!
//! # Two physically separate banks
//!
//! Real dual-bank silicon holds two distinct physical bank stores (RM0456 sec
//! 7.5.8). [`PersistentState`] models both as `bank_a` and `bank_b`. `running`
//! selects the bank the firmware boots from (the OLD bank), and `target` selects
//! the inactive bank the update writes. The update flow only ever touches the
//! inactive store, so the OLD store is provably untouched until a swap is
//! confirmed. A staged swap flips which store is `running` at the next reset, the
//! same way the option load does on real silicon.
//!
//! # Persistent versus volatile state
//!
//! Real flash, the NVCNT area, the pending record, the boot counter, and the
//! bank-select option survive a power cut. RAM does not. [`PersistentState`]
//! holds exactly the bytes that survive. A modelled power cut keeps a
//! [`PersistentState`] and drops everything else. A modelled reboot rebuilds a
//! fresh [`FidelityFlash`] from that [`PersistentState`], which is how the
//! harness models the loss of the volatile [`crate::Updater`].
//!
//! # The cut countdown survives the reset
//!
//! A single global cut index walks EVERY persistent mutation of the whole flow,
//! across the reset boundary. The remaining countdown rides inside
//! [`PersistentState`] so the post-reset [`FidelityFlash`] re-arms it. That lets
//! a cut fire AFTER the reboot, inside on_boot, confirm, or revert, which is
//! where the most safety-critical ordering lives (NVCNT bumped LAST, the SE
//! spend).
//!
//! # The grounded flash semantics this models
//!
//! - Program clears bits only (`new = old AND data`), so a write never raises a
//!   bit without an erase (RM0456 sec 7.3.1).
//! - A quad-word is 16 bytes. A torn quad-word write leaves contents not
//!   guaranteed (RM0456 sec 7.3.11), and on readback a real double-bit ECC error
//!   raises ECCD plus NMI (RM0456 sec 7.3.2). The [`crate::FlashSeam`] returns
//!   the bank as `&[u8]` with no fault path, so the host-observable consequence
//!   of a torn quad-word is modelled as a poison byte pattern that makes the bank
//!   fail image-verify. The verifier rejects the corrupted bank, and the OLD bank
//!   boots.
//! - SWAP_BANK plus an option load is atomic at the next reset. The CPU never
//!   sees a half-applied option map. A power loss before the option load commits
//!   keeps the OLD option values, so the OLD bank boots (RM0456 sec 7.4.2, sec
//!   7.5.8).
//! - The NVCNT area is never erased (WRP plus HDP). A torn bump reads back the
//!   old value or the new value, never below the old, because the prior
//!   fully-programmed words are untouched and WRP blocks the erase (UM2851 Table
//!   7, Table 8). HONESTY: the bit-level monotone encoding is an INFERENCE
//!   consistent with stock MCUboot, NOT a direct RM quote. The property the model
//!   relies on is the floor, a torn bump reads back at least the old value.

#![cfg(test)]

use crate::seam::BankId;
use crate::seam::FlashError;
use crate::seam::FlashSeam;
use crate::seam::PageIndex;
use crate::seam::PendingFlag;
use crate::seam::SeCounterError;
use crate::seam::SeCounterSeam;
use crate::seam::UpdateOutcome;

/// The modelled bank size in bytes (each of the two physical banks).
///
/// Sized to hold a representative update image in host tests. The real bank
/// geometry comes from the hardware-gated flash driver, not this model.
pub const BANK_LEN: usize = 4096;

/// The flash program granularity in bytes (a quad-word, RM0456 sec 7.3.1).
///
/// Program acts on a whole quad-word at a time. A torn write corrupts the
/// quad-word it was landing on, which is the granularity the model poisons.
pub const QUAD_WORD_LEN: usize = 16;

/// The poison byte a torn quad-word reads back as.
///
/// A torn quad-word write leaves contents not guaranteed (RM0456 sec 7.3.11) and
/// a real readback raises a double-bit ECC fault (RM0456 sec 7.3.2). The seam has
/// no fault path on the byte slice, so the model writes a poison value into the
/// torn quad-word. The host-observable consequence is the same, the verifier
/// rejects the corrupted bank, so the OLD bank boots.
pub const POISON_BYTE: u8 = 0xA5;

/// The state that survives a power cut.
///
/// Both physical bank stores, the NVCNT area, the pending record, the boot
/// counter, the bank-select option, and the in-flight cut countdown all live in
/// non-volatile storage from the model's point of view. A modelled power cut
/// keeps this and drops the rest. A modelled reboot rebuilds a [`FidelityFlash`]
/// from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PersistentState
{
    /// The first physical bank store (program clears bits, erase sets 0xFF).
    pub bank_a: [u8; BANK_LEN],
    /// The second physical bank store (program clears bits, erase sets 0xFF).
    pub bank_b: [u8; BANK_LEN],
    /// The monotone NVCNT anti-rollback counter (Gate 1, UM2851 NVCNT).
    pub nvcnt: u32,
    /// The persistent pending-confirm record.
    pub pending: PendingFlag,
    /// The persistent update-outcome record (reserved for the boot-stage).
    pub outcome: UpdateOutcome,
    /// The boot-count confirmation countdown.
    pub boot_count: u32,
    /// The bank the firmware currently runs from (the OLD bank).
    pub running: BankId,
    /// The bank the swap would make bootable (the inactive bank).
    pub target: BankId,
    /// The staged SWAP_BANK target, applied only at the next modelled reset.
    ///
    /// [`None`] means no swap is staged. [`Some`] holds the bank the option load
    /// will select at the next reset. A power cut before the reset keeps the OLD
    /// `running`, modelling the atomic-at-reset option load (RM0456 sec 7.5.8).
    pub staged_swap: Option<BankId>,
    /// The remaining global cut countdown, carried across the reset boundary.
    ///
    /// [`None`] means no cut is armed (a clean reboot after a settled run). When
    /// a script arms a cut whose index lands after the reset, the surviving
    /// countdown rides here so the post-reset model re-arms it and the cut can
    /// fire in on_boot, confirm, or revert.
    pub cut_countdown: Option<u32>,
    /// The cut mode that pairs with `cut_countdown`.
    pub cut_mode: CutMode,
}

impl PersistentState
{
    /// Builds a baseline: a valid OLD bank, an erased inactive bank, no swap.
    ///
    /// The caller fills the inactive bank at begin time. The OLD bank runs from
    /// [`BankId::Bank1`] (stored in `bank_a`), the inactive target is
    /// [`BankId::Bank2`] (stored in `bank_b`), and no swap is staged.
    pub fn baseline(nvcnt: u32) -> PersistentState
    {
        PersistentState
        {
            bank_a: [0xFF; BANK_LEN],
            bank_b: [0xFF; BANK_LEN],
            nvcnt,
            pending: PendingFlag::None,
            outcome: UpdateOutcome::None,
            boot_count: 0,
            running: BankId::Bank1,
            target: BankId::Bank2,
            staged_swap: None,
            cut_countdown: None,
            cut_mode: CutMode::BeforeMutation,
        }
    }

    /// Borrows the store backing the given bank id.
    pub fn store(&self, bank: BankId) -> &[u8; BANK_LEN]
    {
        match bank
        {
            BankId::Bank1 => &self.bank_a,
            BankId::Bank2 => &self.bank_b,
        }
    }

    /// Mutably borrows the store backing the given bank id.
    fn store_mut(&mut self, bank: BankId) -> &mut [u8; BANK_LEN]
    {
        match bank
        {
            BankId::Bank1 => &mut self.bank_a,
            BankId::Bank2 => &mut self.bank_b,
        }
    }

    /// Applies the staged option load atomically, modelling the swap reset.
    ///
    /// On a real reset the option load selects the staged bank atomically, then
    /// clears the stage. A power cut BEFORE this point keeps the OLD `running`, so
    /// the harness only calls this to model a clean reset boundary. After it,
    /// `running` is the staged bank and `target` is the other bank.
    pub fn apply_reset(&mut self)
    {
        if let Some(next) = self.staged_swap.take()
        {
            self.running = next;
            self.target = other_bank(next);
        }
    }
}

/// The other bank of the two-bank map.
fn other_bank(bank: BankId) -> BankId
{
    match bank
    {
        BankId::Bank1 => BankId::Bank2,
        BankId::Bank2 => BankId::Bank1,
    }
}

/// Where a single power cut lands relative to a persistent mutation.
///
/// The harness arms a countdown over the persistent mutations the script issues.
/// When the countdown reaches the armed op, the mode decides what the cut does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CutMode
{
    /// The power dies BEFORE the mutation lands. The op returns an error and the
    /// persistent state is unchanged.
    BeforeMutation,
    /// The power dies AFTER the mutation lands. The op succeeds, then the next
    /// call faults, modelling the machine never running past the cut.
    AfterMutation,
    /// A write tears mid quad-word. For a page write the targeted quad-word is
    /// poisoned so the bank fails verify on readback, then the call faults. For a
    /// non-write mutation there is no quad-word to poison, so this degrades to
    /// [`CutMode::BeforeMutation`] at the mutation site (see each non-write arm).
    TornWrite,
}

/// The outcome of running a script under an armed cut.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CutOutcome
{
    /// The cut never fired (the script issued fewer mutations than the index).
    NotReached,
    /// The cut fired at the armed mutation.
    Fired,
}

/// A fidelity host model of STM32U5 flash and the staged-swap option state.
///
/// Implements [`FlashSeam`] modelling the real hardware state, not a per-address
/// queue. It carries an optional armed power cut. When the cut fires it records
/// the outcome and faults the rest of the script. A modelled reboot reads the
/// surviving [`PersistentState`] out, optionally applies the staged swap, then
/// rebuilds a fresh model that re-arms any surviving cut countdown.
pub struct FidelityFlash
{
    persistent: PersistentState,
    /// Counts persistent mutations down to the armed cut. [`None`] means no cut
    /// is armed, so the model behaves like clean silicon.
    countdown: Option<u32>,
    cut_mode: CutMode,
    outcome: CutOutcome,
    /// Set once the cut has fired, so every later seam call faults (the machine
    /// stopped at the cut on real hardware).
    tripped: bool,
}

impl FidelityFlash
{
    /// Builds a model over the given persistent state, re-arming any surviving
    /// cut countdown carried in the state.
    ///
    /// A fresh script arms its cut with [`FidelityFlash::arm_cut`] after this. A
    /// post-reset reboot instead inherits the countdown the previous segment left
    /// in [`PersistentState::cut_countdown`], so a single global cut index can
    /// fire after the reset.
    pub fn new(mut persistent: PersistentState) -> FidelityFlash
    {
        let countdown = persistent.cut_countdown.take();
        let cut_mode = persistent.cut_mode;
        FidelityFlash
        {
            persistent,
            countdown,
            cut_mode,
            outcome: CutOutcome::NotReached,
            tripped: false,
        }
    }

    /// Arms a single power cut at the `index`-th persistent mutation.
    ///
    /// `index` counts mutating seam calls from zero, over the WHOLE flow. `mode`
    /// decides whether the cut lands before the mutation, after it, or tears a
    /// write. The cut fires at most once across the whole flow, even across the
    /// reset, because the surviving countdown rides in the persistent state.
    pub fn arm_cut(&mut self, index: u32, mode: CutMode)
    {
        self.countdown = Some(index);
        self.cut_mode = mode;
    }

    /// The recorded cut outcome.
    pub fn outcome(&self) -> CutOutcome
    {
        self.outcome
    }

    /// Borrows the persistent state (test inspection only).
    ///
    /// The harness reads the surviving state out through this to model a reboot.
    /// The returned state carries any unspent cut countdown, so the next
    /// [`FidelityFlash::new`] re-arms the cut after the reset.
    pub fn persistent(&self) -> &PersistentState
    {
        &self.persistent
    }

    /// Reads the surviving persistent state out, modelling a power cut.
    ///
    /// A cut does NOT apply a staged swap. The surviving state carries the
    /// remaining cut countdown so a post-reset model re-arms it.
    pub fn into_surviving(self) -> PersistentState
    {
        let mut surviving = self.persistent;
        // Carry the remaining countdown across the reset only if the cut has not
        // already fired in this segment. Once fired, the cut is spent.
        if self.tripped
        {
            surviving.cut_countdown = None;
        }
        else
        {
            surviving.cut_countdown = self.countdown;
            surviving.cut_mode = self.cut_mode;
        }
        surviving
    }

    /// Steps the cut countdown for one persistent mutation.
    ///
    /// Returns the action the caller must take. On a clean step the caller
    /// performs the mutation. On a fired cut the caller honours the mode.
    fn step_cut(&mut self) -> CutAction
    {
        if self.tripped
        {
            // A cut already fired, so the machine never reached this op on real
            // hardware. Every later mutation faults.
            return CutAction::Fault;
        }
        match self.countdown
        {
            None => CutAction::Proceed,
            Some(0) =>
            {
                self.outcome = CutOutcome::Fired;
                self.tripped = true;
                self.countdown = None;
                match self.cut_mode
                {
                    CutMode::BeforeMutation => CutAction::Fault,
                    CutMode::AfterMutation => CutAction::MutateThenStop,
                    CutMode::TornWrite => CutAction::Tear,
                }
            }
            Some(n) =>
            {
                self.countdown = Some(n - 1);
                CutAction::Proceed
            }
        }
    }

    /// Poisons the quad-word a torn write was landing on.
    ///
    /// A torn quad-word write corrupts that quad-word (RM0456 sec 7.3.11), so the
    /// bank fails verify on readback. The model writes [`POISON_BYTE`] across the
    /// quad-word aligned to `start`, clamped to the inactive bank store.
    fn poison_quad_word(&mut self, start: usize)
    {
        let aligned = start - (start % QUAD_WORD_LEN);
        let end = core::cmp::min(aligned + QUAD_WORD_LEN, BANK_LEN);
        let target = self.persistent.target;
        let store = self.persistent.store_mut(target);
        if let Some(slot) = store.get_mut(aligned..end)
        {
            for byte in slot.iter_mut()
            {
                *byte = POISON_BYTE;
            }
        }
    }
}

/// What a cut step tells a mutating seam method to do.
enum CutAction
{
    /// No cut here. Perform the mutation normally.
    Proceed,
    /// The cut landed before the mutation. Fault, leave state unchanged.
    Fault,
    /// The cut landed after the mutation. Perform it, then the model is tripped
    /// so later calls fault.
    MutateThenStop,
    /// A write tears. Poison the targeted quad-word, then fault.
    Tear,
}

impl FlashSeam for FidelityFlash
{
    fn inactive_bank(&self) -> &[u8]
    {
        self.persistent.store(self.persistent.target)
    }

    fn erase_inactive(&mut self) -> Result<(), FlashError>
    {
        match self.step_cut()
        {
            CutAction::Proceed | CutAction::MutateThenStop =>
            {
                let target = self.persistent.target;
                *self.persistent.store_mut(target) = [0xFF; BANK_LEN];
                Ok(())
            }
            // For an erase there is no targeted quad-word, so a TornWrite cut
            // degrades to BeforeMutation here: the erase faults, state unchanged.
            CutAction::Fault | CutAction::Tear =>
            {
                Err(FlashError::Hardware)
            }
        }
    }

    fn write_inactive_page
    (
        &mut self,
        page: PageIndex,
        data: &[u8],
    )
        -> Result<(), FlashError>
    {
        let start = (page as usize)
            .checked_mul(crate::machine::PAGE_LEN)
            .ok_or(FlashError::OutOfRange)?;
        let end = start
            .checked_add(data.len())
            .ok_or(FlashError::OutOfRange)?;
        if end > BANK_LEN
        {
            return Err(FlashError::OutOfRange);
        }
        match self.step_cut()
        {
            CutAction::Proceed | CutAction::MutateThenStop =>
            {
                let target = self.persistent.target;
                program_clears_bits(
                    self.persistent.store_mut(target),
                    start,
                    data,
                )?;
                Ok(())
            }
            CutAction::Fault =>
            {
                Err(FlashError::WriteFailed)
            }
            CutAction::Tear =>
            {
                // Program a torn quad-word: the contents are not guaranteed
                // (RM0456 sec 7.3.11), modelled as a poisoned quad-word that
                // fails verify on readback (RM0456 sec 7.3.2).
                self.poison_quad_word(start);
                Err(FlashError::WriteFailed)
            }
        }
    }

    fn running_bank(&mut self) -> Result<BankId, FlashError>
    {
        Ok(self.persistent.running)
    }

    fn target_bank(&mut self) -> Result<BankId, FlashError>
    {
        Ok(self.persistent.target)
    }

    fn commit_swap(&mut self) -> Result<(), FlashError>
    {
        match self.step_cut()
        {
            CutAction::Proceed | CutAction::MutateThenStop =>
            {
                // Stage the swap. It applies only at the next modelled reset
                // (RM0456 sec 7.5.8), so running_bank does NOT change here.
                self.persistent.staged_swap = Some(self.persistent.target);
                Ok(())
            }
            // commit_swap is an option-program arm, not a quad-word write, so a
            // TornWrite cut degrades to BeforeMutation here: it faults, no swap.
            CutAction::Fault | CutAction::Tear =>
            {
                Err(FlashError::Hardware)
            }
        }
    }

    fn revert_swap(&mut self) -> Result<(), FlashError>
    {
        match self.step_cut()
        {
            CutAction::Proceed | CutAction::MutateThenStop =>
            {
                // Stage a reverse swap back to the previously running bank. It
                // too applies only at the next modelled reset.
                let back = other_bank(self.persistent.running);
                self.persistent.staged_swap = Some(back);
                Ok(())
            }
            // revert_swap is an option-program arm, not a quad-word write, so a
            // TornWrite cut degrades to BeforeMutation here: it faults, no swap.
            CutAction::Fault | CutAction::Tear =>
            {
                Err(FlashError::Hardware)
            }
        }
    }

    fn nvcnt_read(&mut self) -> Result<u32, FlashError>
    {
        Ok(self.persistent.nvcnt)
    }

    fn nvcnt_bump(&mut self, value: u32) -> Result<(), FlashError>
    {
        if value < self.persistent.nvcnt
        {
            return Err(FlashError::WriteFailed);
        }
        match self.step_cut()
        {
            CutAction::Proceed | CutAction::MutateThenStop =>
            {
                self.persistent.nvcnt = value;
                Ok(())
            }
            CutAction::Fault =>
            {
                // A cut before the bump lands keeps the OLD counter. The NVCNT
                // area is never erased, so it reads back the prior value.
                Err(FlashError::WriteFailed)
            }
            CutAction::Tear =>
            {
                // A torn bump reads back the old value OR the new value, never
                // below the old (UM2851 NVCNT, the monotone floor). The model
                // keeps the old value, so the torn result equals the
                // BeforeMutation outcome and still satisfies the floor, then it
                // faults.
                Err(FlashError::WriteFailed)
            }
        }
    }

    fn pending_read(&mut self) -> Result<PendingFlag, FlashError>
    {
        Ok(self.persistent.pending)
    }

    fn pending_write(&mut self, flag: PendingFlag) -> Result<(), FlashError>
    {
        match self.step_cut()
        {
            CutAction::Proceed | CutAction::MutateThenStop =>
            {
                self.persistent.pending = flag;
                Ok(())
            }
            // The pending record is a word write, not a quad-word image write, so
            // a TornWrite cut degrades to BeforeMutation here: it faults, the
            // record keeps its prior value.
            CutAction::Fault | CutAction::Tear =>
            {
                Err(FlashError::WriteFailed)
            }
        }
    }

    fn boot_count_read(&mut self) -> Result<u32, FlashError>
    {
        Ok(self.persistent.boot_count)
    }

    fn boot_count_advance(&mut self) -> Result<(), FlashError>
    {
        match self.step_cut()
        {
            CutAction::Proceed | CutAction::MutateThenStop =>
            {
                self.persistent.boot_count = self
                    .persistent
                    .boot_count
                    .checked_add(1)
                    .ok_or(FlashError::WriteFailed)?;
                Ok(())
            }
            // The boot count is a word write, so a TornWrite cut degrades to
            // BeforeMutation here: it faults, the count keeps its prior value.
            CutAction::Fault | CutAction::Tear =>
            {
                Err(FlashError::WriteFailed)
            }
        }
    }

    fn update_outcome_read(&mut self) -> Result<UpdateOutcome, FlashError>
    {
        Ok(self.persistent.outcome)
    }

    fn update_outcome_write
    (
        &mut self,
        outcome: UpdateOutcome,
    )
        -> Result<(), FlashError>
    {
        match self.step_cut()
        {
            CutAction::Proceed | CutAction::MutateThenStop =>
            {
                self.persistent.outcome = outcome;
                Ok(())
            }
            // The outcome record is a word write, not a quad-word image write, so
            // a TornWrite cut degrades to BeforeMutation here: it faults, the
            // record keeps its prior value.
            CutAction::Fault | CutAction::Tear =>
            {
                Err(FlashError::WriteFailed)
            }
        }
    }

    fn update_outcome_clear(&mut self) -> Result<(), FlashError>
    {
        match self.step_cut()
        {
            CutAction::Proceed | CutAction::MutateThenStop =>
            {
                self.persistent.outcome = UpdateOutcome::None;
                Ok(())
            }
            CutAction::Fault | CutAction::Tear =>
            {
                Err(FlashError::WriteFailed)
            }
        }
    }
}

/// A fidelity host model of the secure-element down-counter (Gate 2).
///
/// [`crate::mock::MockSeCounter`] is enough for the simple tests, but it has no
/// switch to drop the channel mid-spend. This model adds one, so the harness can
/// inject a channel drop on the [`SeCounterSeam::update`] call itself, the spend
/// window between the SE decrement and the NVCNT bump in confirm (machine.rs
/// confirm). The model proves the recovery on the next boot does not double-spend
/// the counter and does not strand a half-confirmed state.
pub struct FidelitySeCounter
{
    value: u32,
    updated: bool,
    /// When `true`, the next [`SeCounterSeam::update`] drops the channel and the
    /// counter does NOT decrement, modelling a power loss or channel drop during
    /// the spend.
    drop_on_update: bool,
}

impl FidelitySeCounter
{
    /// Builds a counter at `value`, channel up, no drop armed.
    pub fn new(value: u32) -> FidelitySeCounter
    {
        FidelitySeCounter
        {
            value,
            updated: false,
            drop_on_update: false,
        }
    }

    /// Arms a channel drop on the next [`SeCounterSeam::update`].
    pub fn arm_drop_on_update(&mut self)
    {
        self.drop_on_update = true;
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

impl SeCounterSeam for FidelitySeCounter
{
    fn read(&mut self) -> Result<u32, SeCounterError>
    {
        Ok(self.value)
    }

    fn update(&mut self) -> Result<(), SeCounterError>
    {
        if self.drop_on_update
        {
            // The channel dropped during the spend. The counter does not
            // decrement, so the next boot reads the same value and the recovery
            // retries the spend without a double decrement.
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

/// Programs `data` into `bank` at `start`, clearing bits only (RM0456 sec 7.3.1).
///
/// `new = old AND data`, so a write never raises a bit from 0 to 1. A real
/// reprogram of a non-zero word raises PROGERR, but for the host-observable bank
/// readback the AND-mask captures the property the verifier depends on, a write
/// can only clear bits an erase set.
fn program_clears_bits
(
    bank: &mut [u8; BANK_LEN],
    start: usize,
    data: &[u8],
)
    -> Result<(), FlashError>
{
    let end = start
        .checked_add(data.len())
        .ok_or(FlashError::OutOfRange)?;
    let slot = bank
        .get_mut(start..end)
        .ok_or(FlashError::OutOfRange)?;
    for (cell, byte) in slot.iter_mut().zip(data.iter())
    {
        *cell &= *byte;
    }
    Ok(())
}
