//! The hardware seam the boot stage drives.
//!
//! Every register read, image read, persistent write, and swap arm the boot stage
//! needs is a method on [`BootFlash`]. The [`crate::decision`] never touches
//! it. On silicon the real driver (`mcu_flash::Stm32FlashSeam`) backs it (see the
//! target-only `real` module). On the host a faithful state mock backs it, so the
//! whole boot flow is proven without hardware.
//!
//! The metadata and swap-control methods mirror `fw_update::FlashSeam` (the
//! updater's view) and reuse its `BankId` / `PendingFlag` / `UpdateOutcome` /
//! `FlashError` vocabulary, so both sides agree on the persistent encoding. The
//! image reads are the boot stage's own: they read the running (active) bank
//! through the low alias, whereas the updater reads the inactive bank through the
//! high alias.

use fw_update::BankId;
use fw_update::FlashError;
use fw_update::PendingFlag;
use fw_update::UpdateOutcome;

use crate::secwm::SecwmReadback;

/// The only path from the boot stage to flash, the persistent records, and the
/// swap arm.
///
/// Each method returns a typed [`Result`] so a fault fails closed. The image-read
/// methods borrow the memory-mapped running bank, so the bytes verified are the
/// bytes the hand-off boots.
pub(crate) trait BootFlash
{
    /// Asserts the partition is sane (DUALBANK and TZEN set).
    ///
    /// # Errors
    ///
    /// [`FlashError::Hardware`] if the part is not in the dual-bank secure
    /// posture the layout requires.
    fn require_partition(&mut self) -> Result<(), FlashError>;

    /// Reads the two flash secure-watermark registers back.
    ///
    /// # Errors
    ///
    /// [`FlashError::Hardware`] if the registers are unreadable.
    fn read_secwm(&mut self) -> Result<SecwmReadback, FlashError>;

    /// Reports the bank the firmware currently runs from (the low-alias bank).
    ///
    /// # Errors
    ///
    /// [`FlashError::Hardware`] if the bank-select state is unreadable.
    fn running_bank(&mut self) -> Result<BankId, FlashError>;

    /// Reads the persistent pending-confirm record.
    ///
    /// # Errors
    ///
    /// [`FlashError::Hardware`] if the record store is unreadable.
    fn pending_read(&mut self) -> Result<PendingFlag, FlashError>;

    /// Reads the monotone flash anti-rollback counter (NVCNT).
    ///
    /// # Errors
    ///
    /// [`FlashError::Hardware`] if the counter store is unreadable.
    fn nvcnt_read(&mut self) -> Result<u32, FlashError>;

    /// Borrows the running bank's image descriptor (page 9, secure alias): the
    /// header at [0:24] and the signature at [24:88].
    fn active_descriptor(&self) -> &[u8];

    /// Borrows the running bank's secure payload sub-band (pages 10-19, secure
    /// alias).
    fn active_secure_band(&self) -> &[u8];

    /// Borrows the running bank's non-secure payload sub-band (pages 20-31,
    /// non-secure alias).
    fn active_ns_band(&self) -> &[u8];

    /// Clears the update-outcome record back to [`UpdateOutcome::None`].
    ///
    /// # Errors
    ///
    /// [`FlashError::WriteFailed`] on a write fault.
    fn update_outcome_clear(&mut self) -> Result<(), FlashError>;

    /// Writes the update-outcome record.
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

    /// Writes the persistent pending-confirm record.
    ///
    /// # Errors
    ///
    /// [`FlashError::WriteFailed`] on a write fault.
    fn pending_write(&mut self, flag: PendingFlag) -> Result<(), FlashError>;

    /// Bumps the monotone NVCNT to `value` (an equal value is a no-op).
    ///
    /// # Errors
    ///
    /// [`FlashError::CounterExhausted`] if the burn budget is spent,
    /// [`FlashError::WriteFailed`] if `value` is below the stored counter.
    fn nvcnt_bump(&mut self, value: u32) -> Result<(), FlashError>;

    /// Arms SWAP_BANK back toward the inactive (old) bank, the auto-revert.
    ///
    /// On real silicon this triggers the option load and resets the part, which
    /// applies the swap.
    ///
    /// # Errors
    ///
    /// [`FlashError::Hardware`] on a controller fault.
    fn revert_swap(&mut self) -> Result<(), FlashError>;
}
