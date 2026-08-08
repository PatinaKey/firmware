//! The mockable seams the update machine drives.
//!
//! Every irreversible or brick-risk operation on the MCU's own firmware (a
//! flash write, an erase, a SWAP_BANK flip, an option load) is reachable only
//! through an explicit method on [`FlashSeam`]. This crate ships no real MMIO
//! impl of either seam: the real volatile-flash driver is a separate
//! hardware-gated crate. The only impl here is the host mock in
//! [`crate::mock`]. A caller cannot emit an irreversible op except by calling a
//! named seam method, so the dangerous surface stays auditable in one place.
//!
//! [`SeCounterSeam`] is the second anti-rollback gate (UM2851). This crate
//! splits it from [`FlashSeam`] because it lives on the secure element, the
//! machine reaches it over a different bus, and it gates the key-ops accept
//! rather than the boot decision.

/// A single page index inside the inactive bank.
///
/// The machine addresses the inactive bank page-relative, so it never holds an
/// absolute flash address. The seam maps a page to the real bank base.
pub type PageIndex = u16;

/// An error the [`FlashSeam`] returns.
///
/// Every variant collapses the machine to a state that keeps the old bank
/// bootable (fail-closed). The machine never retries an irreversible step on
/// error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlashError
{
    /// A page index fell outside the inactive bank.
    OutOfRange,
    /// A write or erase did not take effect (verify-after-write mismatch).
    WriteFailed,
    /// The monotone flash counter cannot be bumped (burn budget reached).
    CounterExhausted,
    /// The underlying flash controller reported a fault.
    Hardware,
}

/// An error the [`SeCounterSeam`] returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeCounterError
{
    /// The secure-element channel was not up or dropped mid-call.
    Unavailable,
    /// The monotonic counter reached its floor and cannot decrement further.
    Exhausted,
}

/// The persistent record that a swap is awaiting confirmation.
///
/// This record survives the reset that the swap commits on (RM0456 sec 7.5.8:
/// the SWAP_BANK plus option load takes effect at the next reset). It carries
/// which bank the running firmware must be, so a boot can prove the swap took
/// effect before it owes a confirm. The machine writes [`PendingFlag::Armed`]
/// before [`FlashSeam::commit_swap`], because that call triggers the reset on
/// real hardware, so the confirm-owed marker must already be persisted when the
/// new bank first runs.
///
/// # Why the bank id is load-bearing
///
/// A power loss after the machine writes [`PendingFlag::Armed`] but before the
/// option load commits leaves the old bank booting (RM0456 sec 7.5.8: the CPU
/// never sees a half-swapped map). On that next boot [`FlashSeam::running_bank`]
/// still reports the old bank, which does not match the armed target, so the
/// machine knows the swap never took effect. It clears the record and keeps the
/// old bank, instead of arming a reverse swap into the unverified bank.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingFlag
{
    /// No swap is awaiting confirmation. The running bank is confirmed.
    None,
    /// A swap was armed toward the given bank. A boot must compare the
    /// running bank against this target before it owes a confirm.
    Armed(BankId),
}

/// Which physical bank the firmware runs from.
///
/// The dual-bank map (RM0456 sec 7.5.8) names the two banks. The machine pairs
/// the armed target with the running bank to tell "swap took effect, confirm
/// owed" apart from "swap never took effect, old bank still boots".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BankId
{
    /// Bank 1.
    Bank1,
    /// Bank 2.
    Bank2,
}

/// The persistent outcome of the last update attempt.
///
/// An auto-revert (the boot-stage re-arms SWAP_BANK back to the old bank when a
/// new image does not confirm in time) must not be silent. The boot-stage sets
/// this record on an auto-revert, and it is cleared when a fresh update begins or
/// a new image confirms. It survives the reset the revert commits on, so a later
/// boot and a host tool can read it back and surface the event.
///
/// This crate ships the type and the seam. The boot-stage that sets it on an
/// auto-revert, and the LED plus host-CLI surfacing that consumes it, are future
/// work. The machine in this crate does not set it: it lives in the metadata area
/// alongside the pending record, reserved for the boot-stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateOutcome
{
    /// No outcome recorded. The last update path ran clean, or none has run.
    None,
    /// The boot-stage auto-reverted the last update (the new image never
    /// confirmed within the boot budget).
    AutoReverted,
}

/// The only path from the machine to flash and the SWAP_BANK commit.
///
/// Each method returns a typed [`Result`] so a fault fails closed. The machine
/// holds the seam by mutable reference and the host mock implements it directly.
///
/// # Safety of the commit
///
/// [`Self::commit_swap`] models RM0456 sec 7.5.8: writing SWAP_BANK plus an
/// option load takes effect at the next reset, atomically. The CPU never sees a
/// half-swapped map. A power loss before the option load commits leaves the old
/// bank booting. This crate models the commit as a seam call and emits no real
/// SWAP_BANK or option-byte write.
pub trait FlashSeam
{
    /// Borrows the image descriptor of the inactive bank, read through the secure
    /// alias.
    ///
    /// The signed image file stays contiguous `header || payload || signature`,
    /// but the device de-interleaves it: the header lands at the front of the
    /// descriptor and the signature just after it, while the payload lands
    /// page-aligned at its link origin. So the descriptor holds the header at
    /// byte offset [0:`image_verify::HEADER_LEN`] and the signature at
    /// [`image_verify::HEADER_LEN`:`image_verify::HEADER_LEN`+`image_verify::SIG_LEN`].
    /// The descriptor is a secure page, read through the secure alias, the store
    /// the commit boots.
    ///
    /// # Returns
    ///
    /// The inactive-bank descriptor bytes, at least a header plus a signature.
    fn inactive_descriptor(&self) -> &[u8];

    /// Borrows the secure payload sub-band of the inactive bank, read through the
    /// secure alias.
    ///
    /// The payload spans a SECWM boundary: the low payload pages are secure, the
    /// high pages non-secure (RM0456 sec 7.9.17). The two sub-bands carry
    /// different security attributes and must be read through different address
    /// aliases: a secure page read through the non-secure alias returns RAZ, and
    /// vice versa (RM0456 Table 68). So the seam hands the verifier the descriptor
    /// plus two payload bands whose logical concatenation, in order header,
    /// secure payload, non-secure payload, signature, is the image, each read
    /// through its own alias.
    ///
    /// On real hardware the inactive bank is memory-mapped, so this returns a
    /// view of the exact secure payload bytes [`Self::commit_swap`] makes
    /// bootable. The machine verifies these bytes, so the verified image and the
    /// committed image are the same bytes by construction.
    ///
    /// # Returns
    ///
    /// The inactive-bank secure payload sub-band, erased bytes included.
    fn inactive_secure_band(&self) -> &[u8];

    /// Borrows the non-secure payload sub-band of the inactive bank, read through
    /// the non-secure alias.
    ///
    /// In logical order the payload is [`Self::inactive_secure_band`] followed by
    /// this band. Reading this band through the secure alias would return RAZ (all
    /// zeros, RM0456 Table 68), so the seam reads it through the non-secure alias.
    /// The verify / commit same-store property holds: these are still the bytes
    /// the commit boots, read through the correct alias.
    ///
    /// # Returns
    ///
    /// The inactive-bank non-secure payload sub-band, erased bytes included.
    fn inactive_ns_band(&self) -> &[u8];

    /// Erases the whole inactive bank to the flash erased state.
    ///
    /// # Errors
    ///
    /// [`FlashError::Hardware`] or [`FlashError::WriteFailed`] on a controller
    /// fault.
    fn erase_inactive(&mut self) -> Result<(), FlashError>;

    /// Writes one page of the inactive bank from `data`.
    ///
    /// # Arguments
    ///
    /// - `page`: page index inside the inactive bank.
    /// - `data`: the page contents.
    ///
    /// # Errors
    ///
    /// [`FlashError::OutOfRange`] if `page` is past the bank end,
    /// [`FlashError::WriteFailed`] if the write did not verify.
    fn write_inactive_page
    (
        &mut self,
        page: PageIndex,
        data: &[u8],
    )
        -> Result<(), FlashError>;

    /// Writes the image descriptor of the inactive bank from `descriptor`.
    ///
    /// `descriptor` is the header followed by the signature, so its length is
    /// `image_verify::HEADER_LEN` + `image_verify::SIG_LEN`. The machine writes it
    /// once, at accept time, after the descriptor page has been erased, so the
    /// single programming pass raises no reprogram fault. [`Self::inactive_descriptor`]
    /// reads these exact bytes back for the verify.
    ///
    /// # Errors
    ///
    /// [`FlashError::OutOfRange`] if `descriptor` is larger than the descriptor
    /// page, [`FlashError::WriteFailed`] if the write did not verify.
    fn write_descriptor(&mut self, descriptor: &[u8]) -> Result<(), FlashError>;

    /// Reports the bank the firmware currently runs from.
    ///
    /// The machine compares this against the armed target in [`PendingFlag`] so
    /// it can tell a committed swap apart from a swap that never took effect.
    ///
    /// # Errors
    ///
    /// [`FlashError::Hardware`] if the bank-select state is unreadable.
    fn running_bank(&mut self) -> Result<BankId, FlashError>;

    /// Reports the bank the swap will make bootable (the inactive bank).
    ///
    /// # Errors
    ///
    /// [`FlashError::Hardware`] if the bank-select state is unreadable.
    fn target_bank(&mut self) -> Result<BankId, FlashError>;

    /// Commits the swap: arms SWAP_BANK plus an option load (RM0456 sec 7.5.8).
    ///
    /// The flip takes effect at the next reset, atomically. This crate models
    /// it. It emits no real SWAP_BANK or option-byte write.
    ///
    /// # Errors
    ///
    /// [`FlashError::Hardware`] if the option program reported a fault.
    fn commit_swap(&mut self) -> Result<(), FlashError>;

    /// Reverts the swap: arms SWAP_BANK back to the previous bank.
    ///
    /// The machine calls this when the new bank fails to self-confirm. It takes
    /// effect at the next reset, same atomicity as [`Self::commit_swap`].
    ///
    /// # Errors
    ///
    /// [`FlashError::Hardware`] on a controller fault.
    fn revert_swap(&mut self) -> Result<(), FlashError>;

    /// Reads the monotone flash anti-rollback counter (Gate 1, UM2851 NVCNT).
    ///
    /// # Errors
    ///
    /// [`FlashError::Hardware`] if the counter store is unreadable.
    fn nvcnt_read(&mut self) -> Result<u32, FlashError>;

    /// Bumps the monotone flash counter to `value` (Gate 1, UM2851 NVCNT).
    ///
    /// `value` must be at least the current counter. The store is monotone and
    /// has a finite burn budget (UM2851 cites ~500 updates).
    ///
    /// # Errors
    ///
    /// [`FlashError::CounterExhausted`] if the burn budget is spent,
    /// [`FlashError::WriteFailed`] if `value` is below the stored counter.
    fn nvcnt_bump(&mut self, value: u32) -> Result<(), FlashError>;

    /// Reads the persistent pending-confirm record.
    ///
    /// # Errors
    ///
    /// [`FlashError::Hardware`] if the record store is unreadable.
    fn pending_read(&mut self) -> Result<PendingFlag, FlashError>;

    /// Writes the persistent pending-confirm record.
    ///
    /// # Errors
    ///
    /// [`FlashError::WriteFailed`] on a write fault.
    fn pending_write(&mut self, flag: PendingFlag) -> Result<(), FlashError>;

    /// Reads the boot-count confirmation countdown.
    ///
    /// # Errors
    ///
    /// [`FlashError::Hardware`] if the store is unreadable.
    fn boot_count_read(&mut self) -> Result<u32, FlashError>;

    /// Raises the boot-count confirmation countdown by one.
    ///
    /// # Errors
    ///
    /// [`FlashError::WriteFailed`] on a write fault.
    fn boot_count_advance(&mut self) -> Result<(), FlashError>;

    /// Reads the persistent update-outcome record.
    ///
    /// Reserved for a future boot-stage. It reads back what the boot-stage last
    /// wrote, so an auto-revert is never silent. The metadata area survives a
    /// swap (RM0456 sec 7.5.8).
    ///
    /// # Errors
    ///
    /// [`FlashError::Hardware`] if the record store is unreadable.
    fn update_outcome_read(&mut self) -> Result<UpdateOutcome, FlashError>;

    /// Writes the persistent update-outcome record.
    ///
    /// The boot-stage sets [`UpdateOutcome::AutoReverted`] on an auto-revert.
    ///
    /// # Errors
    ///
    /// [`FlashError::WriteFailed`] on a write fault.
    fn update_outcome_write
    (
        &mut self,
        outcome: UpdateOutcome,
    )
        -> Result<(), FlashError>;

    /// Clears the update-outcome record back to [`UpdateOutcome::None`].
    ///
    /// A fresh update begins or a new image confirms by clearing the record.
    ///
    /// # Errors
    ///
    /// [`FlashError::WriteFailed`] on a write fault.
    fn update_outcome_clear(&mut self) -> Result<(), FlashError>;
}

/// The secure-element monotonic counter (Gate 2, anti-rollback after channel up).
///
/// This counter gates the key-ops accept, not the boot decision. The TROPIC01
/// MCounter counts down: [`Self::update`] decrements it (a successful accepted
/// update spends one tick). The machine reads it to enforce an anti-rollback
/// floor on accept, and decrements it on a confirmed update. This crate models
/// the counter abstractly and talks to no real secure element.
pub trait SeCounterSeam
{
    /// Reads the current secure-element counter value.
    ///
    /// # Errors
    ///
    /// [`SeCounterError::Unavailable`] if the channel is down.
    fn read(&mut self) -> Result<u32, SeCounterError>;

    /// Decrements the secure-element counter by one (MCounter_Update).
    ///
    /// # Errors
    ///
    /// [`SeCounterError::Unavailable`] if the channel is down,
    /// [`SeCounterError::Exhausted`] if the counter is already at its floor.
    fn update(&mut self) -> Result<(), SeCounterError>;
}
