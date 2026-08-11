//! The boot flow: read the seam, decide, apply, then report the hand-off.
//!
//! [`run`] is generic over [`BootFlash`], so the same orchestration the silicon
//! runs is driven on the host over a state mock. It reads the persistent inputs,
//! assesses the running bank, calls the [`decide`], applies the ordered
//! bookkeeping, and returns a [`BootOutcome`] the target entry acts on (jump,
//! reset, or wedge). It performs no jump itself.

use image_verify::RootKey;

use fw_update::BankId;
use fw_update::FlashError;
use fw_update::PendingFlag;
use fw_update::UpdateOutcome;

use crate::decision::BootDecision;
use crate::decision::BootPlan;
use crate::decision::WedgeReason;
use crate::decision::decide;
use crate::health;
use crate::health::ImageHealth;
use crate::secwm::secwm_ok;
use crate::seam::BootFlash;

/// What the boot stage decided to do, for the target entry to carry out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BootOutcome
{
    /// Hand off to the running bank's secure app.
    HandOff(BankId),
    /// The auto-revert was armed. On silicon the option load has reset the part,
    /// so this is reached only on the host model or if the reset did not fire.
    Reverted,
    /// Halt fail-closed.
    Wedge(WedgeReason),
}

/// Runs the boot decision over the seam and applies its bookkeeping.
///
/// # Arguments
///
/// - `flash`: the hardware seam (real driver on silicon, state mock on host).
/// - `root_key`: the pinned product root public key.
///
/// # Returns
///
/// A [`BootOutcome`] the caller acts on. Any unreadable input or mis-provisioned
/// watermark wedges before an image is trusted.
pub(crate) fn run<F>(flash: &mut F, root_key: &RootKey) -> BootOutcome
where
    F: BootFlash,
{
    // 0. Partition sanity, then the SECWM readback wedge, before trusting any
    //    isolation. A mis-provisioned part must not run.
    if flash.require_partition().is_err()
    {
        return BootOutcome::Wedge(WedgeReason::Unreadable);
    }
    match flash.read_secwm()
    {
        Ok(readback) =>
        {
            if !secwm_ok(&readback)
            {
                return BootOutcome::Wedge(WedgeReason::SecwmMismatch);
            }
        }
        Err(_) => return BootOutcome::Wedge(WedgeReason::Unreadable),
    }

    // 1. Read the persistent boot state. Any read fault fails closed.
    let running = match flash.running_bank()
    {
        Ok(bank) => bank,
        Err(_) => return BootOutcome::Wedge(WedgeReason::Unreadable),
    };
    let pending = match flash.pending_read()
    {
        Ok(flag) => flag,
        Err(_) => return BootOutcome::Wedge(WedgeReason::Unreadable),
    };
    let nvcnt = match flash.nvcnt_read()
    {
        Ok(value) => value,
        Err(_) => return BootOutcome::Wedge(WedgeReason::Unreadable),
    };

    // 2. Assess the running bank's image from its four segments. The immutable
    //    borrows are scoped so they drop before the mutable apply below.
    let health = assess_running(flash, root_key);

    // 3. Decide, then act.
    match decide(running, pending, nvcnt, health)
    {
        BootDecision::Boot(plan) =>
        {
            // A verified image boots even if a bookkeeping write faults: the
            // image is authentic, and the confirm or self-heal retries on the
            // next boot. This mirrors the updater, which keeps the new bank
            // booting on a confirm-write fault rather than bricking it.
            let _ = apply_plan(flash, &plan);
            BootOutcome::HandOff(running)
        }
        BootDecision::Revert =>
        {
            let _ = apply_revert(flash);
            BootOutcome::Reverted
        }
        BootDecision::Wedge(reason) => BootOutcome::Wedge(reason),
    }
}

/// Reads the running bank's four segments and assesses their health.
fn assess_running<F>(flash: &F, root_key: &RootKey) -> ImageHealth
where
    F: BootFlash,
{
    let descriptor = flash.active_descriptor();
    let secure_band = flash.active_secure_band();
    let ns_band = flash.active_ns_band();
    health::assess(descriptor, secure_band, ns_band, root_key)
}

/// Applies a boot plan's bookkeeping in the safety-critical order: clear the
/// outcome, clear the pending record, then bump the NVCNT last.
///
/// # Errors
///
/// The first [`FlashError`] a step returns. A caller on the Boot path proceeds to
/// hand off regardless, so a fault only defers the confirm to the next boot.
fn apply_plan<F>(flash: &mut F, plan: &BootPlan) -> Result<(), FlashError>
where
    F: BootFlash,
{
    if plan.clear_outcome
    {
        flash.update_outcome_clear()?;
    }
    if plan.clear_pending
    {
        flash.pending_write(PendingFlag::None)?;
    }
    // The NVCNT bump is last, past every revert decision.
    if let Some(value) = plan.advance_nvcnt
    {
        flash.nvcnt_bump(value)?;
    }
    Ok(())
}

/// Records the auto-revert outcome, then arms SWAP_BANK back toward the old bank.
///
/// The NVCNT is never touched here, so a reverted-to old image is never a
/// downgrade. Recording the outcome before arming the swap keeps the event
/// visible even if the reset fires immediately after the arm.
///
/// # Errors
///
/// The first [`FlashError`] a step returns.
fn apply_revert<F>(flash: &mut F) -> Result<(), FlashError>
where
    F: BootFlash,
{
    flash.update_outcome_write(UpdateOutcome::AutoReverted)?;
    flash.revert_swap()?;
    Ok(())
}
