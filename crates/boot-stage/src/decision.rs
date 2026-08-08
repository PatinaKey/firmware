//! The boot decision state machine.
//!
//! [`decide`] maps the persistent boot state (running bank, pending-confirm
//! record, NVCNT, and running image health) to a [`BootDecision`].
//!
//! # The three situations
//!
//! - No pending update (`PendingFlag::None`): the running bank is confirmed. 
//!   Boot it if healthy, else wedge.
//! - A swap took effect (`Armed(target)`, running == target): the running bank is
//!   the freshly swapped-to new bank and a confirm is owed. Healthy and not
//!   rolled back means confirm then boot, otherwise revert.
//! - A swap never took effect (`Armed(target)`, running != target): a power loss
//!   before the option load committed left the old bank booting (RM0456 sec
//!   7.5.8: the CPU never sees a half-swapped map), or an auto-revert already
//!   landed back on it. The stale record is cleared and the old bank boots.
//!
//! # Anti-brick ordering
//!
//! A confirm clears the outcome, clears the pending record, then bumps the NVCNT
//! last (see [`BootPlan`]). A revert never bumps the NVCNT, and each [`decide`]
//! returns exactly one decision, so a bank can never gain an NVCNT floor and then
//! be reverted away. A cut between clearing pending and the bump leaves
//! `PendingFlag::None` with a lagging NVCNT, which the no-pending arm heals by
//! advancing the NVCNT to the running image's counter.

use fw_update::BankId;
use fw_update::PendingFlag;

use crate::health::ImageHealth;

/// Why the boot stage refuses to hand off. A wedge halts fail-closed: no image is
/// booted and no swap is armed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WedgeReason
{
    /// No bootable image: the running bank did not verify and there is no other
    /// bank to fall back to.
    NoBootableImage,
    /// The running bank verified but its security counter is below the NVCNT
    /// anti-rollback floor.
    RolledBack,
    /// The provisioned watermarks did not match the expected secure layout.
    SecwmMismatch,
    /// A persistent record or a register was unreadable, or the partition
    /// (DUALBANK / TZEN) was not sane.
    Unreadable,
}

/// The persistent bookkeeping a Boot decision applies before hand-off.
///
/// Applied in field order: clear the outcome, clear the pending record, then bump
/// the NVCNT last.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct BootPlan
{
    /// Clear the update-outcome record: a fresh confirm supersedes any prior
    /// auto-revert note.
    pub(crate) clear_outcome: bool,
    /// Clear the pending-confirm record to `None`. This is the commit point that
    /// ends "confirm owed".
    pub(crate) clear_pending: bool,
    /// Bump the NVCNT to this value, done last. `None` means no bump is owed.
    pub(crate) advance_nvcnt: Option<u32>,
}

/// What the boot stage does after reading its inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BootDecision
{
    /// Hand off to the running bank's app after applying the [`BootPlan`].
    Boot(BootPlan),
    /// Re-arm SWAP_BANK toward the inactive (old) bank and record the auto-revert.
    /// Never bumps the NVCNT.
    Revert,
    /// Halt fail-closed.
    Wedge(WedgeReason),
}

/// The NVCNT advance owed when booting a verified, non-rolled-back image.
///
/// Returns the image counter when it is strictly above the stored NVCNT, else
/// `None`. A higher counter on a confirmed bank means a prior confirm was cut
/// after clearing pending but before the bump, so advancing closes that rollback
/// window.
fn advance_owed(security_counter: u32, nvcnt: u32) -> Option<u32>
{
    if security_counter > nvcnt
    {
        Some(security_counter)
    }
    else
    {
        None
    }
}

/// The pure boot decision.
///
/// # Arguments
///
/// - `running`: the physical bank the firmware currently runs from.
/// - `pending`: the persistent pending-confirm record.
/// - `nvcnt`: the stored anti-rollback counter.
/// - `health`: the running bank image's verified health.
///
/// # Returns
///
/// Exactly one of [`BootDecision::Boot`], [`BootDecision::Revert`], or
/// [`BootDecision::Wedge`].
pub(crate) fn decide
(
    running: BankId,
    pending: PendingFlag,
    nvcnt: u32,
    health: ImageHealth,
)
    -> BootDecision
{
    match pending
    {
        PendingFlag::None => decide_no_pending(nvcnt, health),
        PendingFlag::Armed(target) if running == target =>
        {
            decide_swap_applied(nvcnt, health)
        }
        PendingFlag::Armed(_) => decide_swap_never_applied(nvcnt, health),
    }
}

/// No pending update: the running bank is the confirmed bank.
fn decide_no_pending(nvcnt: u32, health: ImageHealth) -> BootDecision
{
    match health
    {
        ImageHealth::Rejected => BootDecision::Wedge(WedgeReason::NoBootableImage),
        ImageHealth::Verified { security_counter } =>
        {
            if security_counter < nvcnt
            {
                BootDecision::Wedge(WedgeReason::RolledBack)
            }
            else
            {
                BootDecision::Boot(BootPlan
                {
                    clear_outcome: false,
                    clear_pending: false,
                    advance_nvcnt: advance_owed(security_counter, nvcnt),
                })
            }
        }
    }
}

/// The swap took effect (running == armed target): a confirm is owed on the new
/// bank.
fn decide_swap_applied(nvcnt: u32, health: ImageHealth) -> BootDecision
{
    match health
    {
        // A new bank that fails to verify or is a rollback is reverted. The revert
        // never bumps the NVCNT, so the reverted-to old image is not read as a
        // downgrade.
        ImageHealth::Rejected => BootDecision::Revert,
        ImageHealth::Verified { security_counter } =>
        {
            if security_counter < nvcnt
            {
                BootDecision::Revert
            }
            else
            {
                // Confirm: clear the outcome and the pending record, then bump the
                // NVCNT to this image's counter last. An equal bump is a no-op
                // against the monotone store, so re-confirming the same image
                // spends no burn budget.
                BootDecision::Boot(BootPlan
                {
                    clear_outcome: true,
                    clear_pending: true,
                    advance_nvcnt: Some(security_counter),
                })
            }
        }
    }
}

/// The swap never took effect (running != armed target): the old bank booted, or
/// an auto-revert already landed back on it. Clear the stale record and boot the
/// old bank.
fn decide_swap_never_applied(nvcnt: u32, health: ImageHealth) -> BootDecision
{
    match health
    {
        // The old bank should be the previously confirmed image, so a rejection
        // here means both banks are unbootable. Wedge, do not arm any swap.
        ImageHealth::Rejected => BootDecision::Wedge(WedgeReason::NoBootableImage),
        ImageHealth::Verified { security_counter } =>
        {
            if security_counter < nvcnt
            {
                BootDecision::Wedge(WedgeReason::RolledBack)
            }
            else
            {
                // Boot the old bank and clear the stale Armed record. Preserve the
                // outcome so a prior auto-revert stays visible. Heal the NVCNT if
                // it lags the confirmed image.
                BootDecision::Boot(BootPlan
                {
                    clear_outcome: false,
                    clear_pending: true,
                    advance_nvcnt: advance_owed(security_counter, nvcnt),
                })
            }
        }
    }
}
