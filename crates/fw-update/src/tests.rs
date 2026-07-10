//! Host tests for the dual-bank update machine, driven through the mocks.
//!
//! Every irreversible seam op (commit, revert) is asserted to fire ONLY on the
//! intended path. Every fault path is asserted to keep the OLD bank bootable
//! (no commit), which is the fail-closed contract. The image streams through the
//! seam into the mock inactive bank, and verify reads that same bank back, so a
//! test proves verify and commit act on the same bytes.

use super::*;

use ed25519_dalek::Signer;
use ed25519_dalek::SigningKey;
use image_verify::RootKey;
use image_verify::VerifyError;
use std::vec::Vec;

// The signing seed whose public key equals DEV_ROOT_KEY (the all-0x01 scalar).
const DEV_SEED: [u8; 32] = [1u8; 32];

// A seed that does NOT match DEV_ROOT_KEY, used to mint a tampered image.
const WRONG_SEED: [u8; 32] = [2u8; 32];

// Pinned header layout (image-verify format, HEADER_LEN = 24, SIG_LEN = 64).
const HEADER_LEN: usize = 24;
const OFF_MAGIC: usize = 0;
const OFF_FORMAT_VERSION: usize = 4;
const OFF_ALGORITHM: usize = 5;
const OFF_VERSION_MAJOR: usize = 6;
const OFF_VERSION_MINOR: usize = 7;
const OFF_VERSION_REVISION: usize = 8;
const OFF_VERSION_BUILD: usize = 10;
const OFF_SECURITY_COUNTER: usize = 14;
const OFF_PAYLOAD_LEN: usize = 18;
const MAGIC: [u8; 4] = *b"PKIM";
const FORMAT_VERSION: u8 = 1;
const ALG_ED25519: u8 = 0x01;

// An SE counter value whose derived anti-rollback floor is zero, so Gate 2 does
// not interfere with a test that only exercises Gate 1 or the signature.
const SE_FLOOR_ZERO: u32 = SE_COUNTER_ORIGIN;

// Builds a HEADER || payload || signature image signed with `seed`, carrying the
// given security counter and payload.
fn build_image
(
    seed: [u8; 32],
    security_counter: u32,
    payload: &[u8],
)
    -> Vec<u8>
{
    let mut header = [0u8; HEADER_LEN];
    header[OFF_MAGIC..OFF_MAGIC + 4].copy_from_slice(&MAGIC);
    header[OFF_FORMAT_VERSION] = FORMAT_VERSION;
    header[OFF_ALGORITHM] = ALG_ED25519;
    header[OFF_VERSION_MAJOR] = 1;
    header[OFF_VERSION_MINOR] = 0;
    header[OFF_VERSION_REVISION..OFF_VERSION_REVISION + 2]
        .copy_from_slice(&0u16.to_le_bytes());
    header[OFF_VERSION_BUILD..OFF_VERSION_BUILD + 4]
        .copy_from_slice(&0u32.to_le_bytes());
    header[OFF_SECURITY_COUNTER..OFF_SECURITY_COUNTER + 4]
        .copy_from_slice(&security_counter.to_le_bytes());
    header[OFF_PAYLOAD_LEN..OFF_PAYLOAD_LEN + 4]
        .copy_from_slice(&(payload.len() as u32).to_le_bytes());

    let mut signed = Vec::new();
    signed.extend_from_slice(&header);
    signed.extend_from_slice(payload);

    let sk = SigningKey::from_bytes(&seed);
    let sig = sk.sign(&signed);

    let mut image = signed;
    image.extend_from_slice(&sig.to_bytes());
    image
}

fn dev_root() -> RootKey
{
    RootKey::from_bytes(DEV_ROOT_KEY).expect("dev root key is on-curve")
}

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
fn dev_seed_public_key_matches_dev_root_key()
{
    let sk = SigningKey::from_bytes(&DEV_SEED);
    assert_eq!(sk.verifying_key().to_bytes(), DEV_ROOT_KEY);
}

#[test]
fn happy_path_receive_verify_commit_boot_confirm()
{
    let root = dev_root();
    let flash = MockFlash::new(0);
    let se = MockSeCounter::new(SE_FLOOR_ZERO);
    let mut up = Updater::new(&root, flash, se);

    let image = build_image(DEV_SEED, 5, b"new firmware payload");
    feed(&mut up, &image).expect("feed");
    assert_eq!(up.state(), UpdateState::ReceivingChunks);

    up.verify_and_accept().expect("verify");
    assert_eq!(up.state(), UpdateState::PendingCommit);
    // After accept the whole image, including the trailing partial page, has
    // landed in the mock inactive bank through the seam.
    assert_eq!(&up.flash().bank()[..image.len()], &image[..]);

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
    // Prove verify and commit act on the SAME bytes: the bank holds the image,
    // and verify reads it straight back from the seam.
    let root = dev_root();
    let flash = MockFlash::new(0);
    let se = MockSeCounter::new(SE_FLOOR_ZERO);
    let mut up = Updater::new(&root, flash, se);

    let image = build_image(DEV_SEED, 1, b"payload across one page boundary plus");
    feed(&mut up, &image).expect("feed");
    up.verify_and_accept().expect("verify reads the bank");
    assert_eq!(up.state(), UpdateState::PendingCommit);
    // Verify ran off the bank, which now holds the exact image bytes.
    assert_eq!(&up.flash().bank()[..image.len()], &image[..]);
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
    let image = build_image(DEV_SEED, 2, &big);
    assert!(image.len() > PAGE_LEN);
    feed(&mut up, &image).expect("feed multi-page");
    // Full pages flushed during receive. The trailing partial page flushes at
    // accept, after which the bank holds the exact image bytes.
    up.verify_and_accept().expect("verify multi-page");
    assert_eq!(up.state(), UpdateState::PendingCommit);
    assert_eq!(&up.flash().bank()[..image.len()], &image[..]);
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

    let image = build_image(DEV_SEED, 1, b"a complete enough payload here ok");
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

    // Signed by the WRONG key, so the signature fails under DEV_ROOT_KEY.
    let image = build_image(WRONG_SEED, 5, b"evil payload");
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

    let image = build_image(DEV_SEED, 1, b"payload");
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

    let image = build_image(DEV_SEED, 5, b"old firmware payload");
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

    let image = build_image(DEV_SEED, 5, b"rolled-back payload");
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

    let image = build_image(DEV_SEED, 5, b"at-the-floor payload");
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

    let image = build_image(DEV_SEED, 5, b"payload");
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

    let image = build_image(DEV_SEED, 7, b"same version payload");
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

    let image = build_image(DEV_SEED, 9, b"same counter payload");
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

    let image = build_image(DEV_SEED, 1, b"payload");
    feed(&mut up, &image).expect("feed");
    up.verify_and_accept().expect("verify");
    up.commit().expect("commit");
    up.on_boot().expect("boot");
    assert_eq!(up.state(), UpdateState::AwaitingConfirm);

    // The new bank failed its health checks: revert instead of confirm.
    up.revert().expect("revert");
    assert_eq!(up.state(), UpdateState::Reverted);
    assert!(up.flash().reverted());
    // The forward swap bumped no NVCNT, so the OLD bank is not poisoned.
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

    let image = build_image(DEV_SEED, 1, b"payload");
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
    // committed: the running bank still matches the OLD bank, not the armed
    // target. on_boot must clear the record and stay on the OLD bank, NOT enter
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

    let image = build_image(DEV_SEED, 2, b"payload");
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

    let image = build_image(DEV_SEED, 2, b"payload");
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

    let image = build_image(DEV_SEED, 2, b"payload");
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
fn begin_with_total_len_over_bank_is_rejected()
{
    let root = dev_root();
    let flash = MockFlash::new(0);
    let se = MockSeCounter::new(SE_FLOOR_ZERO);
    let mut up = Updater::new(&root, flash, se);

    let err = up.begin(BANK_LEN + 1).expect_err("over bank");
    assert_eq!(err, UpdateError::ChunkOutOfRange);
    assert_eq!(up.state(), UpdateState::Idle);
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

    let image = build_image(DEV_SEED, 1, b"payload");
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

    let image = build_image(DEV_SEED, 3, b"chunked firmware payload here");
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
