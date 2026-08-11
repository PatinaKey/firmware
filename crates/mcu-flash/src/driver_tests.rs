//! Driver-level sequencing tests over the faithful FLASH-controller model.
//!
//! These drive [`Stm32FlashSeam`] directly against [`FlashModel`] and assert the
//! driver emits the right register sequence (unlock to PG to write to poll to
//! lock), decodes the error flags, maps logical pages to addresses, and fails
//! closed. The model enforces real controller semantics: a write to a flash
//! address with PG clear is ignored, a wrong unlock key leaves the CR locked, a
//! reprogram of a non-erased word raises PROGERR, a sub-quad-word program is
//! padded so a short page never raises SIZERR. So a wrong sequence shows up as a
//! failed or no-op operation.

#![cfg(test)]

use fw_update::BankId;
use fw_update::FlashError;
use fw_update::FlashSeam;
use fw_update::PendingFlag;
use fw_update::UpdateOutcome;

use crate::driver::Stm32FlashSeam;
use crate::model::FlashModel;
use crate::regs;

// Builds a driver over a freshly erased model that boots Bank 1, so the inactive
// (target) bank is Bank 2.
fn fresh() -> Stm32FlashSeam<FlashModel>
{
    Stm32FlashSeam::new(FlashModel::new())
}

#[test]
fn inactive_bank_is_bank2_when_booting_bank1()
{
    let mut up = fresh();
    assert_eq!(up.running_bank().expect("running"), BankId::Bank1);
    assert_eq!(up.target_bank().expect("target"), BankId::Bank2);
}

#[test]
fn erase_inactive_leaves_image_region_erased_and_relocks()
{
    let mut up = fresh();
    up.erase_inactive().expect("erase");
    // Both sub-bands of the inactive (Bank 2) image region read erased, each
    // through its own alias (secure via 0x0C.., non-secure via 0x08..).
    let secure = up.inactive_secure_band();
    assert!(secure.iter().all(|byte| *byte == regs::ERASED_BYTE));
    let ns = up.inactive_ns_band();
    assert!(ns.iter().all(|byte| *byte == regs::ERASED_BYTE));
    // The driver re-locked the CR from a known state after the op.
    assert!(up.access().model_locked());
}

#[test]
fn write_then_read_back_round_trips_through_the_seam()
{
    let mut up = fresh();
    up.erase_inactive().expect("erase");
    // A page that is not a multiple of the 16-byte quad-word, to exercise the
    // short-tail pad path (a sub-quad-word write would otherwise raise SIZERR).
    let mut data = [0u8; 70];
    for (i, byte) in data.iter_mut().enumerate()
    {
        *byte = (i as u8) | 0x80;
    }
    up.write_inactive_page(0, &data).expect("write page 0");
    // Logical payload page 0 lands at the start of the secure payload sub-band
    // (physical page 10), so read it back through the secure alias.
    let bank = up.inactive_secure_band();
    assert_eq!(&bank[..data.len()], &data[..], "round-trip");
    // The bytes past the written page stay erased.
    assert!(bank[data.len()..fw_update::PAGE_LEN].iter().all(|b| *b == 0xFF));
}

#[test]
fn descriptor_writes_page_9_and_reads_back_through_the_secure_alias()
{
    // The descriptor lands on page 9 (the image band start), one page below the
    // secure payload band. Writing it must not touch the payload band, and it
    // reads back through the secure alias.
    let mut up = fresh();
    up.erase_inactive().expect("erase");
    let mut descriptor = [0u8; 88];
    for (i, byte) in descriptor.iter_mut().enumerate()
    {
        *byte = (i as u8) | 0x80;
    }
    up.write_descriptor(&descriptor).expect("write descriptor");

    let read = up.inactive_descriptor();
    assert_eq!(&read[..descriptor.len()], &descriptor[..], "descriptor round-trip");
    // The secure PAYLOAD band (page 10 onward) is a different page, still erased.
    let payload = up.inactive_secure_band();
    assert!(
        payload.iter().all(|byte| *byte == regs::ERASED_BYTE),
        "the descriptor write did not touch the payload band"
    );
    // The driver re-locked the CR from a known state after the op.
    assert!(up.access().model_locked());
}

#[test]
fn active_descriptor_reads_the_running_bank_through_the_low_alias()
{
    // The boot stage verifies the running bank. Write a descriptor into the
    // inactive bank (Bank 2 while running Bank 1), then commit and reset so that
    // bank becomes active. The active read must then return those exact bytes
    // through the low alias, proving the bytes verified are the bytes booted.
    let mut up = fresh();
    up.erase_inactive().expect("erase");
    let mut descriptor = [0u8; 88];
    for (i, byte) in descriptor.iter_mut().enumerate()
    {
        *byte = (i as u8) | 0x80;
    }
    up.write_descriptor(&descriptor).expect("write descriptor");

    // Before the swap the running bank (Bank 1) is still erased, so the active
    // read does not see the new descriptor. This makes the post-swap check
    // non-vacuous.
    assert!(
        up.active_descriptor()
            .iter()
            .all(|byte| *byte == regs::ERASED_BYTE),
        "the running bank is erased before the swap"
    );

    up.commit_swap().expect("commit");
    up.access_mut().apply_reset();
    assert_eq!(up.running_bank().expect("running"), BankId::Bank2);

    let read = up.active_descriptor();
    assert_eq!(
        &read[..descriptor.len()],
        &descriptor[..],
        "the active read returns the running bank's descriptor after the swap"
    );
}

#[test]
fn read_secwm_raw_reads_both_watermark_registers()
{
    // The default model shadows no watermark, so both read back zero. The read
    // must not fault, and the boot stage treats an unprovisioned zero readback as
    // a mismatch (a fail-closed discriminator).
    let mut up = fresh();
    assert_eq!(up.read_secwm_raw().expect("read secwm"), (0, 0));
}

#[test]
fn write_without_a_prior_erase_fails_closed_on_progerr()
{
    let mut up = fresh();
    up.erase_inactive().expect("erase");
    up.write_inactive_page(0, &[0x00; 16]).expect("first write");
    // Reprogramming the same quad-word with new zero bits the erase did not set
    // raises PROGERR in the model, which the driver decodes to WriteFailed.
    let again = up.write_inactive_page(0, &[0x11; 16]);
    assert_eq!(again, Err(FlashError::WriteFailed), "fail closed on PROGERR");
    // The driver still re-locked the CR despite the fault.
    assert!(up.access().model_locked());
}

#[test]
fn write_protected_page_fails_closed_on_wrperr()
{
    let mut model = FlashModel::new();
    // The driver writes the inactive bank (physical Bank 2 here). The payload band
    // starts at physical page IMAGE_PAYLOAD_PAGE_FIRST, so logical payload page 0
    // lands on that physical page. Protect it to drive a WRPERR on the first
    // payload write.
    model.protect_bank2_page(regs::IMAGE_PAYLOAD_PAGE_FIRST);
    let mut up = Stm32FlashSeam::new(model);
    up.erase_inactive().ok();
    let result = up.write_inactive_page(0, &[0x00; 16]);
    assert_eq!(result, Err(FlashError::WriteFailed), "fail closed on WRPERR");
}

#[test]
fn logical_page_past_the_image_region_is_out_of_range()
{
    let mut up = fresh();
    up.erase_inactive().expect("erase");
    // The payload band is 22 pages of 8 KB. PAGE_LEN is 256 bytes, so the last
    // valid logical payload page is just under IMAGE_PAYLOAD_SIZE / PAGE_LEN.
    let last_valid = (regs::IMAGE_PAYLOAD_SIZE / fw_update::PAGE_LEN as u32) - 1;
    up.write_inactive_page(last_valid as u16, &[0xAA; 16])
        .expect("last valid page");
    let one_past = last_valid + 1;
    let result = up.write_inactive_page(one_past as u16, &[0xAA; 16]);
    assert_eq!(result, Err(FlashError::OutOfRange), "out of range page");
}

#[test]
fn nvcnt_starts_zero_and_bumps_monotone()
{
    let mut up = fresh();
    assert_eq!(up.nvcnt_read().expect("read"), 0);
    up.nvcnt_bump(5).expect("bump 5");
    assert_eq!(up.nvcnt_read().expect("read"), 5);
    // A bump to the same value is a no-op and spends no slot.
    up.nvcnt_bump(5).expect("bump same");
    assert_eq!(up.nvcnt_read().expect("read"), 5);
    // A regression below the floor fails closed.
    assert_eq!(up.nvcnt_bump(4), Err(FlashError::WriteFailed), "regression");
    // A higher value programs the next slot.
    up.nvcnt_bump(9).expect("bump 9");
    assert_eq!(up.nvcnt_read().expect("read"), 9);
}

#[test]
fn pending_record_round_trips_and_clears()
{
    let mut up = fresh();
    assert_eq!(up.pending_read().expect("read"), PendingFlag::None);
    up.pending_write(PendingFlag::Armed(BankId::Bank2))
        .expect("arm bank2");
    assert_eq!(
        up.pending_read().expect("read"),
        PendingFlag::Armed(BankId::Bank2)
    );
    up.pending_write(PendingFlag::None).expect("clear");
    assert_eq!(up.pending_read().expect("read"), PendingFlag::None);
}

#[test]
fn boot_count_advances_and_reads_back()
{
    let mut up = fresh();
    assert_eq!(up.boot_count_read().expect("read"), 0);
    up.boot_count_advance().expect("advance");
    assert_eq!(up.boot_count_read().expect("read"), 1);
    up.boot_count_advance().expect("advance");
    assert_eq!(up.boot_count_read().expect("read"), 2);
}

#[test]
fn update_outcome_round_trips_and_clears()
{
    let mut up = fresh();
    assert_eq!(up.update_outcome_read().expect("read"), UpdateOutcome::None);
    up.update_outcome_write(UpdateOutcome::AutoReverted)
        .expect("set auto-reverted");
    assert_eq!(
        up.update_outcome_read().expect("read"),
        UpdateOutcome::AutoReverted
    );
    up.update_outcome_clear().expect("clear");
    assert_eq!(up.update_outcome_read().expect("read"), UpdateOutcome::None);
}

#[test]
fn pending_and_outcome_records_are_independent()
{
    // Both records share page 1 of physical Bank 1, so a rewrite of one must
    // preserve the other across the shared erase.
    let mut up = fresh();
    up.update_outcome_write(UpdateOutcome::AutoReverted)
        .expect("set outcome");
    up.pending_write(PendingFlag::Armed(BankId::Bank2))
        .expect("arm pending");
    // The outcome survived the pending rewrite.
    assert_eq!(
        up.update_outcome_read().expect("read"),
        UpdateOutcome::AutoReverted
    );
    assert_eq!(
        up.pending_read().expect("read"),
        PendingFlag::Armed(BankId::Bank2)
    );
    // Clearing the outcome leaves the pending record intact.
    up.update_outcome_clear().expect("clear outcome");
    assert_eq!(up.update_outcome_read().expect("read"), UpdateOutcome::None);
    assert_eq!(
        up.pending_read().expect("read"),
        PendingFlag::Armed(BankId::Bank2)
    );
}

#[test]
fn metadata_reads_from_physical_bank1_after_a_swap()
{
    // The B1 proof at the driver level: NVCNT, the pending record, and the outcome
    // record are pinned to physical Bank 1, addressed through the SWAP_BANK-aware
    // helper. After a swap, physical Bank 1 sits at the high alias, so a driver that
    // used a fixed low-alias address would read the wrong physical bank. This asserts
    // the records read back unchanged after the swap.
    let mut up = fresh();
    up.nvcnt_bump(11).expect("bump nvcnt");
    up.pending_write(PendingFlag::Armed(BankId::Bank2))
        .expect("arm pending");
    up.update_outcome_write(UpdateOutcome::AutoReverted)
        .expect("set outcome");
    up.boot_count_advance().expect("advance boot count");

    // Stage and apply a swap, so physical Bank 1 moves to the high alias.
    up.commit_swap().expect("commit");
    up.access_mut().apply_reset();

    // After the swap the same physical Bank 1 metadata reads back unchanged.
    assert_eq!(up.nvcnt_read().expect("read"), 11, "NVCNT survives the swap");
    assert_eq!(
        up.pending_read().expect("read"),
        PendingFlag::Armed(BankId::Bank2),
        "pending survives the swap"
    );
    assert_eq!(
        up.update_outcome_read().expect("read"),
        UpdateOutcome::AutoReverted,
        "outcome survives the swap"
    );
    assert_eq!(
        up.boot_count_read().expect("read"),
        1,
        "boot count survives the swap"
    );
    assert!(up.access().boots_bank2(), "the part now boots Bank 2");
}

#[test]
fn commit_swap_stages_the_swap_and_records_obl_launch_inert()
{
    let mut up = fresh();
    // commit_swap carries the full real option-byte sequence. On the model it
    // stages the swap and records the OBL_LAUNCH without resetting, so the inert
    // brick-class path is exercised without a real option load.
    up.commit_swap().expect("commit swap");
    let model = up.access();
    assert!(model.obl_launched(), "OBL_LAUNCH write observed");
    // The swap is staged, not yet applied: OPTR still boots Bank 1 until reset.
    assert_eq!(model.staged_swap(), Some(true), "staged toward Bank 2");
    assert!(!model.boots_bank2(), "not applied before reset");
}

#[test]
fn revert_after_commit_arms_the_swap_back_to_the_original_bank()
{
    // The revert-direction proof at the model level, across two modelled resets. A
    // forward commit boots physical Bank 2, then a revert must point the boot map
    // back at physical Bank 1 (the previously-running, now inactive bank, RM0456 sec
    // 7.5.8), not re-arm toward the bank already running. The check also asserts the
    // original bank's image bytes are still intact and bootable after the round trip,
    // read physically so it does not depend on the alias.
    let mut model = FlashModel::new();
    // Seed physical Bank 1 (bank2 false) image band with a recognisable pattern, so
    // the "original bank stays intact" claim is asserted against real backing bytes,
    // not a rebuilt copy.
    let pattern: [u8; 32] = core::array::from_fn(|i| (i as u8) | 0x80);
    for (i, byte) in pattern.iter().enumerate()
    {
        let offset = regs::IMAGE_REGION_OFFSET as usize + i;
        model.poke_phys(false, offset, *byte);
    }
    let mut up = Stm32FlashSeam::new(model);

    // Start booting Bank 1, so the inactive (target) bank is Bank 2.
    assert_eq!(up.running_bank().expect("running"), BankId::Bank1);

    // Forward commit, then the modelled reset: the part now boots physical Bank
    // 2 (SWAP_BANK set). This mirrors the existing commit test.
    up.commit_swap().expect("commit");
    up.access_mut().apply_reset();
    assert!(up.access().boots_bank2(), "commit boots Bank 2");
    assert_eq!(up.running_bank().expect("running"), BankId::Bank2);

    // Revert, then the modelled reset: the boot map must flip back to physical
    // Bank 1 (SWAP_BANK clear). A revert that re-armed toward the running bank
    // would leave SWAP_BANK set and keep the device on Bank 2.
    up.revert_swap().expect("revert");
    up.access_mut().apply_reset();
    assert!(!up.access().boots_bank2(), "revert boots Bank 1 again");
    assert_eq!(up.running_bank().expect("running"), BankId::Bank1);

    // The original physical Bank 1 image bytes survived the round trip intact,
    // read physically so the check is alias-independent.
    for (i, byte) in pattern.iter().enumerate()
    {
        let offset = regs::IMAGE_REGION_OFFSET as usize + i;
        assert_eq!(
            up.access().phys_byte(false, offset),
            Some(*byte),
            "original Bank 1 image byte intact after revert"
        );
    }
}

#[test]
fn commit_swap_refused_without_dualbank_or_tzen()
{
    let mut model = FlashModel::new();
    model.clear_dualbank();
    let mut up = Stm32FlashSeam::new(model);
    assert_eq!(up.commit_swap(), Err(FlashError::Hardware), "no DUALBANK");
}
