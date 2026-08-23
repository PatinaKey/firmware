//! Host tests for the dual-bank update machine, driven through the mocks.
//!
//! Every irreversible seam op (commit, revert) is asserted to fire only on the
//! intended path. Every fault path is asserted to keep the old bank bootable
//! (no commit), which is the fail-closed contract. The image streams through the
//! seam into the mock inactive bank, and verify reads that same bank back, so a
//! test proves verify and commit act on the same bytes.

use super::*;

use image_verify::HEADER_LEN;
use image_verify::SIG_LEN;
use image_verify::VerifyError;
use p256::ecdsa::SigningKey;

use crate::test_fixtures::DEV_SCALAR;
use crate::test_fixtures::build_image;
use crate::test_fixtures::dev_root;

// Asserts the machine de-interleaved the signed file onto the two stores exactly:
// the header at the front of the descriptor, the signature just after it, and the
// payload page-aligned from offset 0 in the payload store. Also proves the four
// logical segments the verifier reads back concatenate to the original file, and
// that the payload store starts with the firmware bytes, not the header magic.
fn assert_deinterleaved(flash: &MockFlash, image: &[u8])
{
    let payload_len = image.len() - HEADER_LEN - SIG_LEN;
    let header = &image[..HEADER_LEN];
    let payload = &image[HEADER_LEN..HEADER_LEN + payload_len];
    let sig = &image[image.len() - SIG_LEN..];

    assert_eq!(&flash.descriptor()[..HEADER_LEN], header, "header in descriptor");
    assert_eq!(
        &flash.descriptor()[HEADER_LEN..HEADER_LEN + SIG_LEN],
        sig,
        "signature in descriptor"
    );
    assert_eq!(&flash.bank()[..payload_len], payload, "payload in payload store");

    // The four-segment concatenation the verifier reads is the original file.
    let mut rebuilt = std::vec::Vec::new();
    rebuilt.extend_from_slice(&flash.descriptor()[..HEADER_LEN]);
    rebuilt.extend_from_slice(&flash.bank()[..payload_len]);
    rebuilt.extend_from_slice(&flash.descriptor()[HEADER_LEN..HEADER_LEN + SIG_LEN]);
    assert_eq!(rebuilt, image, "reassembled four segments equal the file");
}

// A scalar that does not match DEV_ROOT_KEY_TEST_ONLY, used to mint an image the
// pinned key must reject.
const WRONG_SCALAR: [u8; 32] = [2u8; 32];

// An SE counter value whose derived anti-rollback floor is zero, so Gate 2 does
// not interfere with a test that only exercises Gate 1 or the signature.
const SE_FLOOR_ZERO: u32 = SE_COUNTER_ORIGIN;

// Feeds a whole image into the updater in one chunk at offset 0, declaring the
// exact length so the completeness gate is satisfied.
fn feed
(
    up: &mut Updater<'_, MockFlash, MockSeCounter>,
    image: &[u8],
)
    -> Result<(), UpdateError>
{
    up.begin(image.len())?;
    up.receive_chunk(0, image)
}

#[test]
fn dev_scalar_public_key_matches_dev_root_key()
{
    let sk = SigningKey::from_slice(&DEV_SCALAR).expect("dev scalar in [1, n-1]");
    let point = sk.verifying_key().to_sec1_point(false);
    assert_eq!(point.as_ref(), &DEV_ROOT_KEY_TEST_ONLY[..]);
}

#[test]
fn happy_path_receive_verify_commit_boot_confirm()
{
    let root = dev_root();
    let flash = MockFlash::new(0);
    let se = MockSeCounter::new(SE_FLOOR_ZERO);
    let mut up = Updater::new(&root, flash, se);

    let image = build_image(DEV_SCALAR, 5, b"new firmware payload");
    feed(&mut up, &image).expect("feed");
    assert_eq!(up.state(), UpdateState::ReceivingChunks);

    up.verify_and_accept().expect("verify");
    assert_eq!(up.state(), UpdateState::PendingCommit);
    // After accept the whole image has de-interleaved onto the descriptor and the
    // payload store through the seam.
    assert_deinterleaved(up.flash(), &image);

    up.commit().expect("commit");
    assert_eq!(up.state(), UpdateState::Committed);
    assert!(up.flash().committed());

    // Model the reset into the new bank: the running bank now matches the armed
    // target, so on_boot owes a confirm.
    assert_eq!(up.on_boot().expect("boot"), UpdateState::AwaitingConfirm);

    up.confirm(5).expect("confirm");
    assert_eq!(up.state(), UpdateState::Confirmed);
    // Gate 1 bumped to the image counter, Gate 2 spent, no revert.
    assert_eq!(up.flash().nvcnt(), 5);
    assert!(up.se_counter().updated());
    assert!(!up.flash().reverted());
}

#[test]
fn verify_reads_the_bank_the_commit_will_boot()
{
    // Prove verify and commit act on the same bytes: the bank holds the image,
    // and verify reads it straight back from the seam.
    let root = dev_root();
    let flash = MockFlash::new(0);
    let se = MockSeCounter::new(SE_FLOOR_ZERO);
    let mut up = Updater::new(&root, flash, se);

    let image = build_image(DEV_SCALAR, 1, b"payload across one page boundary plus");
    feed(&mut up, &image).expect("feed");
    up.verify_and_accept().expect("verify reads the bank");
    assert_eq!(up.state(), UpdateState::PendingCommit);
    // Verify ran off the stores, which now hold the de-interleaved image bytes.
    assert_deinterleaved(up.flash(), &image);
}

#[test]
fn multi_page_image_streams_through_seam()
{
    // An image larger than one page must flush full pages through the seam and
    // still verify off the bank.
    let root = dev_root();
    let flash = MockFlash::new(0);
    let se = MockSeCounter::new(SE_FLOOR_ZERO);
    let mut up = Updater::new(&root, flash, se);

    let big = vec![0xABu8; 600];
    let image = build_image(DEV_SCALAR, 2, &big);
    assert!(image.len() > PAGE_LEN);
    feed(&mut up, &image).expect("feed multi-page");
    // Full payload pages flushed during receive. The trailing partial payload
    // page and the descriptor flush at accept, after which the stores hold the
    // de-interleaved image.
    up.verify_and_accept().expect("verify multi-page");
    assert_eq!(up.state(), UpdateState::PendingCommit);
    assert_deinterleaved(up.flash(), &image);
}

#[test]
fn incomplete_transfer_is_rejected_no_commit()
{
    // Declare the full length but feed only a prefix: the completeness gate must
    // reject before verify even runs the signature.
    let root = dev_root();
    let flash = MockFlash::new(0);
    let se = MockSeCounter::new(SE_FLOOR_ZERO);
    let mut up = Updater::new(&root, flash, se);

    let image = build_image(DEV_SCALAR, 1, b"a complete enough payload here ok");
    up.begin(image.len()).expect("begin");
    let half = image.len() / 2;
    up.receive_chunk(0, &image[..half]).expect("prefix");

    let err = up.verify_and_accept().expect_err("must reject prefix");
    assert_eq!(err, UpdateError::Incomplete);
    assert_eq!(up.state(), UpdateState::Idle);
    assert!(!up.flash().committed());
}

#[test]
fn tampered_image_is_rejected_as_bad_signature_no_commit()
{
    let root = dev_root();
    let flash = MockFlash::new(0);
    let se = MockSeCounter::new(SE_FLOOR_ZERO);
    let mut up = Updater::new(&root, flash, se);

    // Signed by the wrong key, so the signature fails under DEV_ROOT_KEY.
    let image = build_image(WRONG_SCALAR, 5, b"evil payload");
    feed(&mut up, &image).expect("feed");

    let err = up.verify_and_accept().expect_err("must reject");
    assert_eq!(err, UpdateError::VerifyFailed(VerifyError::BadSignature));
    assert_eq!(up.state(), UpdateState::Idle);
    assert!(!up.flash().committed());
    assert!(!up.flash().reverted());
}

#[test]
fn a_chunk_that_lands_wrong_fails_closed_no_commit()
{
    // A second chunk at the wrong offset (a gap) is rejected, the bank is
    // cleared, and no commit can follow.
    let root = dev_root();
    let flash = MockFlash::new(0);
    let se = MockSeCounter::new(SE_FLOOR_ZERO);
    let mut up = Updater::new(&root, flash, se);

    let image = build_image(DEV_SCALAR, 1, b"payload");
    up.begin(image.len()).expect("begin");
    up.receive_chunk(0, &image[..10]).expect("chunk 0");
    // Skip ahead, leaving a gap: rejected fail-closed.
    let err = up
        .receive_chunk(20, &image[20..])
        .expect_err("out-of-order chunk");
    assert_eq!(err, UpdateError::ChunkOutOfRange);
    assert_eq!(up.state(), UpdateState::Rejected);
    assert!(!up.flash().committed());
    // verify cannot run from Rejected.
    assert_eq!(up.verify_and_accept(), Err(UpdateError::BadState));
}

#[test]
fn downgrade_below_nvcnt_is_rejected_no_commit()
{
    let root = dev_root();
    // Stored NVCNT is 10, the image carries 5, a downgrade.
    let flash = MockFlash::new(10);
    let se = MockSeCounter::new(SE_FLOOR_ZERO);
    let mut up = Updater::new(&root, flash, se);

    let image = build_image(DEV_SCALAR, 5, b"old firmware payload");
    feed(&mut up, &image).expect("feed");

    let err = up.verify_and_accept().expect_err("must reject downgrade");
    assert_eq!(err, UpdateError::Rollback);
    assert_eq!(up.state(), UpdateState::Idle);
    assert!(!up.flash().committed());
}

#[test]
fn se_counter_regression_is_rejected_no_commit()
{
    // Gate 2: the secure-element floor is 8, the image carries 5, below it.
    let root = dev_root();
    let flash = MockFlash::new(0);
    let se = MockSeCounter::new(SE_COUNTER_ORIGIN - 8);
    let mut up = Updater::new(&root, flash, se);

    let image = build_image(DEV_SCALAR, 5, b"rolled-back payload");
    feed(&mut up, &image).expect("feed");

    let err = up.verify_and_accept().expect_err("se floor rejects");
    assert_eq!(err, UpdateError::Rollback);
    assert_eq!(up.state(), UpdateState::Idle);
    assert!(!up.flash().committed());
}

#[test]
fn se_at_floor_accepts_equal_counter()
{
    // Gate 2: floor 5, image counter 5: equal is accepted.
    let root = dev_root();
    let flash = MockFlash::new(0);
    let se = MockSeCounter::new(SE_COUNTER_ORIGIN - 5);
    let mut up = Updater::new(&root, flash, se);

    let image = build_image(DEV_SCALAR, 5, b"at-the-floor payload");
    feed(&mut up, &image).expect("feed");
    up.verify_and_accept().expect("equal to floor accepted");
    assert_eq!(up.state(), UpdateState::PendingCommit);
}

#[test]
fn se_unavailable_on_accept_fails_closed()
{
    // Gate 2 cannot read the secure-element counter: the accept must fail closed.
    let root = dev_root();
    let flash = MockFlash::new(0);
    let mut se = MockSeCounter::new(SE_FLOOR_ZERO);
    se.set_unavailable();
    let mut up = Updater::new(&root, flash, se);

    let image = build_image(DEV_SCALAR, 5, b"payload");
    feed(&mut up, &image).expect("feed");

    let err = up.verify_and_accept().expect_err("se unavailable");
    assert_eq!(err, UpdateError::SeCounter(SeCounterError::Unavailable));
    assert_eq!(up.state(), UpdateState::Idle);
    assert!(!up.flash().committed());
}

#[test]
fn equal_counter_is_accepted()
{
    let root = dev_root();
    // NVCNT == image counter is allowed (a re-install of the same version).
    let flash = MockFlash::new(7);
    let se = MockSeCounter::new(SE_FLOOR_ZERO);
    let mut up = Updater::new(&root, flash, se);

    let image = build_image(DEV_SCALAR, 7, b"same version payload");
    feed(&mut up, &image).expect("feed");
    up.verify_and_accept().expect("equal counter accepted");
    assert_eq!(up.state(), UpdateState::PendingCommit);
}

#[test]
fn reconfirm_same_counter_does_not_waste_burn_budget()
{
    // Confirming an image whose counter equals the stored NVCNT must not change
    // the monotone store, so the finite burn budget is not spent.
    let root = dev_root();
    let flash = MockFlash::new(9);
    let se = MockSeCounter::new(SE_FLOOR_ZERO);
    let mut up = Updater::new(&root, flash, se);

    let image = build_image(DEV_SCALAR, 9, b"same counter payload");
    feed(&mut up, &image).expect("feed");
    up.verify_and_accept().expect("verify");
    up.commit().expect("commit");
    up.on_boot().expect("boot");
    up.confirm(9).expect("confirm");
    assert_eq!(up.flash().nvcnt(), 9);
}

#[test]
fn confirmation_timeout_reverts_to_old_bank()
{
    let root = dev_root();
    let flash = MockFlash::new(0);
    let se = MockSeCounter::new(SE_FLOOR_ZERO);
    let mut up = Updater::new(&root, flash, se);

    let image = build_image(DEV_SCALAR, 1, b"payload");
    feed(&mut up, &image).expect("feed");
    up.verify_and_accept().expect("verify");
    up.commit().expect("commit");
    up.on_boot().expect("boot");
    assert_eq!(up.state(), UpdateState::AwaitingConfirm);

    // The new bank failed its health checks: revert instead of confirm.
    up.revert().expect("revert");
    assert_eq!(up.state(), UpdateState::Reverted);
    assert!(up.flash().reverted());
    // The forward swap bumped no NVCNT, so the old bank is not poisoned.
    assert_eq!(up.flash().nvcnt(), 0);
}

#[test]
fn erase_fault_keeps_old_bank_bootable()
{
    let root = dev_root();
    let mut flash = MockFlash::new(0);
    flash.set_fault(FaultPoint::Erase);
    let se = MockSeCounter::new(SE_FLOOR_ZERO);
    let mut up = Updater::new(&root, flash, se);

    let err = up.begin(64).expect_err("erase fault");
    assert_eq!(err, UpdateError::Flash(FlashError::Hardware));
    assert_eq!(up.state(), UpdateState::Idle);
    assert!(!up.flash().committed());
}

#[test]
fn commit_swap_fault_clears_pending_no_old_bank_loss()
{
    let root = dev_root();
    let mut flash = MockFlash::new(0);
    flash.set_fault(FaultPoint::Commit);
    let se = MockSeCounter::new(SE_FLOOR_ZERO);
    let mut up = Updater::new(&root, flash, se);

    let image = build_image(DEV_SCALAR, 1, b"payload");
    feed(&mut up, &image).expect("feed");
    up.verify_and_accept().expect("verify");

    let err = up.commit().expect_err("commit fault");
    assert_eq!(err, UpdateError::Flash(FlashError::Hardware));
    // Swap was not armed, machine stays at PendingCommit, old bank bootable. The
    // commit path undid the pending record, so a later boot owes no confirm.
    assert!(!up.flash().committed());
    assert_eq!(up.state(), UpdateState::PendingCommit);
}

#[test]
fn swap_not_effective_on_boot_does_not_revert_into_unverified_bank()
{
    // Model a power loss after the pending record was armed but before the swap
    // committed: the running bank still matches the old bank, not the armed
    // target. on_boot must clear the record and stay on the old bank, not enter
    // AwaitingConfirm where a revert could flip into the unverified bank.
    let root = dev_root();
    let mut flash = MockFlash::new(0);
    flash.force_pending(PendingFlag::Armed(BankId::Bank2));
    flash.force_running(BankId::Bank1);
    let se = MockSeCounter::new(SE_FLOOR_ZERO);
    let mut up = Updater::new(&root, flash, se);

    assert_eq!(up.on_boot().expect("boot"), UpdateState::Idle);
    assert!(!up.flash().committed());
    assert!(!up.flash().reverted());
    // The record was cleared, so a revert is unreachable.
    assert_eq!(up.revert(), Err(UpdateError::BadState));
}

#[test]
fn nvcnt_bump_fault_on_confirm_leaves_swap_committed()
{
    let root = dev_root();
    let mut flash = MockFlash::new(0);
    flash.set_fault(FaultPoint::NvcntBump);
    let se = MockSeCounter::new(SE_FLOOR_ZERO);
    let mut up = Updater::new(&root, flash, se);

    let image = build_image(DEV_SCALAR, 2, b"payload");
    feed(&mut up, &image).expect("feed");
    up.verify_and_accept().expect("verify");
    up.commit().expect("commit");
    up.on_boot().expect("boot");

    let err = up.confirm(2).expect_err("nvcnt fault");
    assert_eq!(err, UpdateError::Flash(FlashError::CounterExhausted));
    // The swap is committed, the new bank keeps booting, the confirm is retried.
    assert!(up.flash().committed());
    // The SE counter was already spent before the NVCNT bump failed.
    assert!(up.se_counter().updated());
    assert_eq!(up.state(), UpdateState::Confirming);
}

#[test]
fn pending_write_fault_on_confirm_leaves_nvcnt_at_the_old_floor()
{
    // Order oracle, first cut point. confirm spends the SE counter, clears the
    // pending record, then bumps NVCNT last. Faulting the record clear freezes
    // the flow there and exposes that the bump has not run. Bumping first bricks
    // the part: a cut between a raised NVCNT and a record still Armed lets the
    // immutable boot stage auto-revert to the old bank on the boot budget, and
    // the old image's counter then sits below the raised NVCNT floor, so it
    // fails anti-rollback and no image boots.
    let root = dev_root();
    let mut flash = MockFlash::new(0);
    // The state after the swap reset: the record survived and the running bank
    // matches the armed target, so the boot owes a confirm.
    flash.force_pending(PendingFlag::Armed(BankId::Bank2));
    flash.force_running(BankId::Bank2);
    flash.set_fault(FaultPoint::PendingWrite);
    let se = MockSeCounter::new(SE_FLOOR_ZERO);
    let mut up = Updater::new(&root, flash, se);

    assert_eq!(up.on_boot().expect("boot"), UpdateState::AwaitingConfirm);

    let err = up.confirm(4).expect_err("the record clear faults");
    assert_eq!(err, UpdateError::Flash(FlashError::WriteFailed));
    // NVCNT still holds the old floor, never raised while the record is armed.
    assert_eq!(up.flash().nvcnt(), 0);
    // The SE counter was spent before the record clear was attempted.
    assert!(up.se_counter().updated());
    // The record still reads Armed toward the target bank, and on_boot answers
    // AwaitingConfirm, an answer with that single preimage whose branch writes no
    // record. This oracle mutates machine state: it returns the machine from
    // Confirming to AwaitingConfirm, so it stays the last statement and nothing
    // observing machine state may be appended after it.
    assert_eq!(up.on_boot().expect("re-boot"), UpdateState::AwaitingConfirm);
}

#[test]
fn nvcnt_bump_fault_on_confirm_proves_the_record_was_cleared_first()
{
    // Order oracle, second cut point. Faulting the NVCNT bump freezes the flow
    // there and exposes that the pending clear already ran. The reverse order
    // raises NVCNT while the record is still Armed, and a cut in that window
    // lets the immutable boot stage auto-revert to the old bank, whose counter
    // now sits below the raised NVCNT floor, leaving no bootable image.
    let root = dev_root();
    let mut flash = MockFlash::new(0);
    flash.force_pending(PendingFlag::Armed(BankId::Bank2));
    flash.force_running(BankId::Bank2);
    flash.set_fault(FaultPoint::NvcntBump);
    let se = MockSeCounter::new(SE_FLOOR_ZERO);
    let mut up = Updater::new(&root, flash, se);

    assert_eq!(up.on_boot().expect("boot"), UpdateState::AwaitingConfirm);

    let err = up.confirm(4).expect_err("the nvcnt bump faults");
    assert_eq!(err, UpdateError::Flash(FlashError::CounterExhausted));
    // Idle means the record no longer owes a confirm, so the clear ran before the
    // bump. on_boot collapses PendingFlag::None and Armed(a bank other than the
    // running one) onto the same Idle answer, and it rewrites the record to None
    // itself on that second preimage. So this assertion pins the ORDER, never the
    // record value.
    assert_eq!(up.on_boot().expect("re-boot"), UpdateState::Idle);
}

#[test]
fn revert_after_confirm_step_is_rejected()
{
    // Once a confirm step has begun (the state left AwaitingConfirm), revert must
    // be refused, so the machine cannot both bump NVCNT and later revert.
    let root = dev_root();
    let mut flash = MockFlash::new(0);
    // Fail the NVCNT bump so confirm stops mid-way at Confirming.
    flash.set_fault(FaultPoint::NvcntBump);
    let se = MockSeCounter::new(SE_FLOOR_ZERO);
    let mut up = Updater::new(&root, flash, se);

    let image = build_image(DEV_SCALAR, 2, b"payload");
    feed(&mut up, &image).expect("feed");
    up.verify_and_accept().expect("verify");
    up.commit().expect("commit");
    up.on_boot().expect("boot");
    let _ = up.confirm(2).expect_err("nvcnt fault stops at Confirming");

    assert_eq!(up.state(), UpdateState::Confirming);
    assert_eq!(up.revert(), Err(UpdateError::BadState));
    assert!(!up.flash().reverted());
}

#[test]
fn se_counter_unavailable_on_confirm_fails_closed()
{
    let root = dev_root();
    let flash = MockFlash::new(0);
    // The SE channel is up at accept time, then the test drops it before confirm
    // through the mutable seam accessor.
    let se = MockSeCounter::new(SE_FLOOR_ZERO);
    let mut up = Updater::new(&root, flash, se);

    let image = build_image(DEV_SCALAR, 2, b"payload");
    feed(&mut up, &image).expect("feed");
    up.verify_and_accept().expect("verify");
    up.commit().expect("commit");
    up.on_boot().expect("boot");

    // Drop the channel between accept and confirm.
    up.se_counter_mut().set_unavailable();

    let err = up.confirm(2).expect_err("se unavailable");
    assert_eq!(err, UpdateError::SeCounter(SeCounterError::Unavailable));
    // The confirm left AwaitingConfirm to forbid a later revert.
    assert_eq!(up.state(), UpdateState::Confirming);
}

#[test]
fn no_pending_flag_boots_old_bank_idle()
{
    let root = dev_root();
    let flash = MockFlash::new(0);
    let se = MockSeCounter::new(SE_FLOOR_ZERO);
    let mut up = Updater::new(&root, flash, se);

    // A normal boot with no swap pending.
    assert_eq!(up.on_boot().expect("boot"), UpdateState::Idle);
    assert!(!up.flash().committed());
}

#[test]
fn boot_after_swap_reset_re_enters_confirm_countdown()
{
    let root = dev_root();
    let mut flash = MockFlash::new(0);
    // Model the state after the swap reset: the record survived AND the running
    // bank now matches the armed target.
    flash.force_pending(PendingFlag::Armed(BankId::Bank2));
    flash.force_running(BankId::Bank2);
    let se = MockSeCounter::new(SE_FLOOR_ZERO);
    let mut up = Updater::new(&root, flash, se);

    assert_eq!(up.on_boot().expect("boot"), UpdateState::AwaitingConfirm);
}

#[test]
fn out_of_range_chunk_is_rejected_fail_closed()
{
    let root = dev_root();
    let flash = MockFlash::new(0);
    let se = MockSeCounter::new(SE_FLOOR_ZERO);
    let mut up = Updater::new(&root, flash, se);

    up.begin(16).expect("begin");
    // An offset past the declared length must be rejected without a panic.
    let err = up
        .receive_chunk(usize::MAX, b"x")
        .expect_err("overflow chunk");
    assert_eq!(err, UpdateError::ChunkOutOfRange);
    assert_eq!(up.state(), UpdateState::Rejected);
    assert!(!up.flash().committed());
}

#[test]
fn chunk_past_declared_length_is_rejected()
{
    let root = dev_root();
    let flash = MockFlash::new(0);
    let se = MockSeCounter::new(SE_FLOOR_ZERO);
    let mut up = Updater::new(&root, flash, se);

    up.begin(4).expect("begin");
    let err = up
        .receive_chunk(0, b"abcdefgh")
        .expect_err("past declared length");
    assert_eq!(err, UpdateError::ChunkOutOfRange);
    assert_eq!(up.state(), UpdateState::Rejected);
}

#[test]
fn begin_with_payload_over_bank_is_rejected()
{
    let root = dev_root();
    let flash = MockFlash::new(0);
    let se = MockSeCounter::new(SE_FLOOR_ZERO);
    let mut up = Updater::new(&root, flash, se);

    // The payload band is BANK_LEN bytes. A file whose payload exceeds it by one
    // byte (header + signature + payload band + 1) is rejected at begin.
    let over = HEADER_LEN + SIG_LEN + BANK_LEN + 1;
    let err = up.begin(over).expect_err("over bank");
    assert_eq!(err, UpdateError::ChunkOutOfRange);
    assert_eq!(up.state(), UpdateState::Idle);
    // The payload band's exact capacity (header + signature + BANK_LEN) is
    // accepted, proving the boundary is the payload size, not the file size.
    up.begin(HEADER_LEN + SIG_LEN + BANK_LEN).expect("at capacity");
    assert_eq!(up.state(), UpdateState::ReceivingChunks);
}

#[test]
fn committed_bank_is_bootable_shaped_and_round_trips()
{
    let root = dev_root();
    let flash = MockFlash::new(0);
    let se = MockSeCounter::new(SE_FLOOR_ZERO);
    let mut up = Updater::new(&root, flash, se);

    // A payload whose first 8 bytes are a plausible Cortex-M vector table (an
    // initial stack pointer then a reset vector), distinct from the "PKIM" magic.
    let mut payload = std::vec::Vec::new();
    payload.extend_from_slice(&0x2003_0000u32.to_le_bytes());
    payload.extend_from_slice(&0x0C01_4101u32.to_le_bytes());
    payload.extend_from_slice(b"the rest of the firmware image body");
    let image = build_image(DEV_SCALAR, 3, &payload);

    feed(&mut up, &image).expect("feed");
    up.verify_and_accept().expect("verify accepts the de-interleaved image");
    assert_eq!(up.state(), UpdateState::PendingCommit);

    // The payload store at offset 0 is the firmware vector table, not the magic.
    assert_eq!(&up.flash().bank()[..4], &0x2003_0000u32.to_le_bytes());
    assert_ne!(&up.flash().bank()[..4], b"PKIM");
    // The magic lives at the front of the descriptor.
    assert_eq!(&up.flash().descriptor()[..4], b"PKIM");
    // Full de-interleave round-trip: the four segments reassemble the file.
    assert_deinterleaved(up.flash(), &image);
}

#[test]
fn commit_in_wrong_state_is_bad_state()
{
    let root = dev_root();
    let flash = MockFlash::new(0);
    let se = MockSeCounter::new(SE_FLOOR_ZERO);
    let mut up = Updater::new(&root, flash, se);

    // Commit before any verify: must refuse.
    assert_eq!(up.commit(), Err(UpdateError::BadState));
    assert!(!up.flash().committed());
}

#[test]
fn confirm_before_boot_floor_is_bad_state()
{
    let root = dev_root();
    let flash = MockFlash::new(0);
    let se = MockSeCounter::new(SE_FLOOR_ZERO);
    let mut up = Updater::new(&root, flash, se);

    let image = build_image(DEV_SCALAR, 1, b"payload");
    feed(&mut up, &image).expect("feed");
    up.verify_and_accept().expect("verify");
    up.commit().expect("commit");

    // confirm before on_boot (boot count still 0): refused.
    assert_eq!(up.confirm(1), Err(UpdateError::BadState));
}

#[test]
fn multi_chunk_accumulation_tracks_written_len()
{
    let root = dev_root();
    let flash = MockFlash::new(0);
    let se = MockSeCounter::new(SE_FLOOR_ZERO);
    let mut up = Updater::new(&root, flash, se);

    let image = build_image(DEV_SCALAR, 3, b"chunked firmware payload here");
    up.begin(image.len()).expect("begin");
    // Split the image into two in-order chunks.
    let mid = image.len() / 2;
    up.receive_chunk(0, &image[..mid]).expect("chunk 0");
    up.receive_chunk(mid, &image[mid..]).expect("chunk 1");
    assert_eq!(up.written(), image.len());

    up.verify_and_accept().expect("verify reassembled image");
    assert_eq!(up.state(), UpdateState::PendingCommit);
}

#[test]
fn page_constants_are_consistent()
{
    assert_eq!(PAGE_LEN, 256);
    assert_eq!(CONFIRM_BOOTS, 1);
}

#[cfg(feature = "_fuzz")]
fn frame_for_fuzz_seam(image: &[u8]) -> std::vec::Vec<u8>
{
    let mut framed = std::vec::Vec::new();
    let declared = image.len() as u16;
    framed.extend_from_slice(&declared.to_le_bytes());
    for chunk in image.chunks(255)
    {
        framed.push(chunk.len() as u8);
        framed.extend_from_slice(chunk);
    }
    framed
}

#[cfg(feature = "_fuzz")]
#[test]
fn the_fuzz_seam_reaches_a_commit_for_a_signed_image()
{
    let image = build_image(DEV_SCALAR, 3, b"the fuzz seam must reach a commit");
    let framed = frame_for_fuzz_seam(&image);

    assert!(
        crate::fuzz::drive_machine(&framed),
        "the fuzz seam must ARM A COMMIT for an image signed with the dev scalar"
    );
}

#[cfg(feature = "_fuzz")]
#[test]
fn the_fuzz_seam_rejects_an_image_signed_by_the_wrong_key()
{
    let image = build_image(WRONG_SCALAR, 3, b"the fuzz seam must reject this");
    let framed = frame_for_fuzz_seam(&image);

    assert!(
        !crate::fuzz::drive_machine(&framed),
        "an image signed by the wrong key must never arm a commit"
    );
}

#[cfg(feature = "_fuzz")]
#[test]
fn the_fuzz_entry_point_survives_degenerate_inputs()
{
    assert!(!crate::fuzz::drive_machine(&[]));
    assert!(!crate::fuzz::drive_machine(&[0x00]));
    assert!(!crate::fuzz::drive_machine(&[0xFF, 0xFF]));
    assert!(!crate::fuzz::drive_machine(&[0x00, 0x00, 0xFF, 0x01, 0x02]));
    assert!(!crate::fuzz::drive_machine(&[0x10, 0x00, 0x02, 0xAA, 0xBB]));
}
