//! Machine-checked power-fault harness over the dual-bank update machine.
//!
//! The earlier tests trace the power-loss windows by hand. This harness turns
//! that tracing into a machine-checked property. It drives the full machine begin
//! -> receive -> verify_and_accept -> commit -> [modelled reset] -> on_boot ->
//! confirm or revert, and injects a power loss at EVERY persistent-mutation
//! boundary of the WHOLE flow, before and after the mutation, plus a torn-write
//! variant. A SINGLE GLOBAL cut index walks every persistent mutation across the
//! reset boundary, so a cut can fire in confirm or revert AFTER the reboot, not
//! only before it. After each injected cut the harness rebuilds the [`Updater`]
//! from the surviving persistent state (a modelled reboot), runs on_boot
//! recovery, retries reboots until the state settles, then asserts the safety
//! invariant on that settled state.
//!
//! # The cut spans the reset
//!
//! The remaining cut countdown rides inside [`PersistentState`] (see
//! [`crate::fidelity`]), so the post-reset model re-arms it. That places the
//! confirm mutations (the SE spend, the pending clear, the NVCNT bump done LAST)
//! and the revert mutations (the reverse-swap arm, the pending clear) inside the
//! fault-injection span.
//!
//! # The fidelity model closes the gap
//!
//! The cuts run against [`FidelityFlash`], which models program-clears-bits-only,
//! two physically separate bank stores, a staged SWAP_BANK applied only at the
//! next reset, and a torn quad-word that reads back as detectable corruption.
//! Those are invisible behind the simple [`crate::mock::MockFlash`], so this
//! harness is the only place the silicon-only faults are representable.
//!
//! # No new attacker-facing decoder
//!
//! This harness adds no parser of attacker bytes. The image bytes still go
//! through `image-verify`, which has its own fuzz target, and the chunk-offset
//! path is already exercised by the `drive_machine` fuzz target.

use ed25519_dalek::Signer;
use ed25519_dalek::SigningKey;
use image_verify::RootKey;
use image_verify::verify_image;

use crate::DEV_ROOT_KEY;
use crate::SE_COUNTER_ORIGIN;
use crate::UpdateState;
use crate::Updater;
use crate::fidelity::CutMode;
use crate::fidelity::CutOutcome;
use crate::fidelity::FidelityFlash;
use crate::fidelity::FidelitySeCounter;
use crate::fidelity::PersistentState;
use crate::seam::BankId;
use crate::seam::PendingFlag;

// The signing seed whose public key equals DEV_ROOT_KEY (the all-0x01 scalar).
const DEV_SEED: [u8; 32] = [1u8; 32];

// Pinned header layout (image-verify format, HEADER_LEN = 24, SIG_LEN = 64).
const HEADER_LEN: usize = 24;
const OFF_MAGIC: usize = 0;
const OFF_FORMAT_VERSION: usize = 4;
const OFF_ALGORITHM: usize = 5;
const OFF_VERSION_MAJOR: usize = 6;
const OFF_SECURITY_COUNTER: usize = 14;
const OFF_PAYLOAD_LEN: usize = 18;
const MAGIC: [u8; 4] = *b"PKIM";
const FORMAT_VERSION: u8 = 1;
const ALG_ED25519: u8 = 0x01;

// The image security counter the baseline OLD bank and the new image carry. The
// stored NVCNT starts below it so the update is a forward step, not a downgrade.
const OLD_BANK_COUNTER: u32 = 4;
const NEW_IMAGE_COUNTER: u32 = 5;
const BASELINE_NVCNT: u32 = 4;

// An SE counter value whose derived anti-rollback floor is at or below the image
// counter, so Gate 2 accepts the forward step.
const SE_AT_FLOOR: u32 = SE_COUNTER_ORIGIN - NEW_IMAGE_COUNTER;

// Builds a HEADER || payload || signature image signed with the dev seed.
fn build_image(security_counter: u32, payload: &[u8]) -> std::vec::Vec<u8>
{
    let mut header = [0u8; HEADER_LEN];
    header[OFF_MAGIC..OFF_MAGIC + 4].copy_from_slice(&MAGIC);
    header[OFF_FORMAT_VERSION] = FORMAT_VERSION;
    header[OFF_ALGORITHM] = ALG_ED25519;
    header[OFF_VERSION_MAJOR] = 1;
    header[OFF_SECURITY_COUNTER..OFF_SECURITY_COUNTER + 4]
        .copy_from_slice(&security_counter.to_le_bytes());
    header[OFF_PAYLOAD_LEN..OFF_PAYLOAD_LEN + 4]
        .copy_from_slice(&(payload.len() as u32).to_le_bytes());

    let mut signed = std::vec::Vec::new();
    signed.extend_from_slice(&header);
    signed.extend_from_slice(payload);

    let sk = SigningKey::from_bytes(&DEV_SEED);
    let sig = sk.sign(&signed);

    let mut image = signed;
    image.extend_from_slice(&sig.to_bytes());
    image
}

// Builds an image whose signature is corrupted, so verify_image rejects it.
fn build_rejected_image(payload: &[u8]) -> std::vec::Vec<u8>
{
    let mut image = build_image(NEW_IMAGE_COUNTER, payload);
    // Flip a byte inside the trailing signature so the Ed25519 check fails. The
    // header still parses, so the image reaches the signature check and is
    // rejected there, never accepted.
    if let Some(last) = image.last_mut()
    {
        *last ^= 0xFF;
    }
    image
}

fn dev_root() -> RootKey
{
    match RootKey::from_bytes(DEV_ROOT_KEY)
    {
        Ok(key) => key,
        Err(_) => panic!("dev root key is on-curve"),
    }
}

// A baseline persistent state: the OLD bank store (bank_a, BankId::Bank1) holds a
// valid signed image, the inactive store (bank_b, BankId::Bank2) is erased. The
// update flow writes only the inactive store, so the OLD store is provably
// untouched until a swap is confirmed. The returned image is the exact bytes the
// OLD bank store holds, so the OLD-bank-bootable invariant verifies the MODEL's
// own OLD-bank bytes, not a freshly rebuilt copy.
fn baseline() -> (PersistentState, std::vec::Vec<u8>)
{
    let old_image = build_image(OLD_BANK_COUNTER, b"old firmware payload here");
    let mut state = PersistentState::baseline(BASELINE_NVCNT);
    // Place the OLD image into the running (OLD) store. The harness reads it back
    // out of the model to verify the OLD bank, never from a rebuilt copy.
    let store = &mut state.bank_a;
    let len = core::cmp::min(old_image.len(), store.len());
    store[..len].copy_from_slice(&old_image[..len]);
    (state, old_image)
}

// Which recovery branch the post-reset boot drives once the swap took effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Health
{
    // The new bank is healthy, so on_boot reaches AwaitingConfirm and confirm is
    // driven (machine.rs confirm: SE spend, pending clear, NVCNT bump LAST).
    Confirm,
    // The new bank failed its health check, so confirm is skipped and revert is
    // driven instead (machine.rs revert: reverse-swap arm, pending clear).
    Revert,
}

// The settled result of driving a flow under one armed cut.
struct FlowResult
{
    surviving: PersistentState,
    outcome: CutOutcome,
    // The global mutation index the cut fired at, if it fired anywhere in the
    // whole flow (across the reset).
    fired_index: Option<u32>,
    // The end-to-end disposition of the swap once the state settled.
    settled: Settled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Settled
{
    // The OLD bank still boots (the swap was never confirmed).
    OldBank,
    // The NEW bank booted and the swap was confirmed end to end.
    Confirmed,
}

// Drives the WHOLE flow under a single global cut at `cut_index` in `mode`.
//
// Segment 1 runs begin -> receive -> accept -> commit with the cut armed. The cut
// countdown that survives rides in the persistent state. `reset_applied` models
// the option-load-at-reset window: `true` applies the staged swap atomically
// (RM0456 sec 7.5.8), `false` models a cut before the option load committed, which
// keeps the OLD bank running. After the reset the harness reboots repeatedly,
// running on_boot recovery and driving confirm or revert by `health`, until the
// state settles (no cut left to fire and no further mutation owed).
fn run_flow
(
    root: &RootKey,
    image: &[u8],
    cut_index: u32,
    mode: CutMode,
    reset_applied: bool,
    health: Health,
)
    -> FlowResult
{
    let (state, _old) = baseline();
    let mut flash = FidelityFlash::new(state);
    flash.arm_cut(cut_index, mode);
    let se = FidelitySeCounter::new(SE_AT_FLOOR);
    let mut up = Updater::new(root, flash, se);

    // Stream and accept. Any error here is the cut firing during erase, a page
    // write, or a read, which collapses the machine fail-closed.
    let accepted = up.begin(image.len()).is_ok()
        && up.receive_chunk(0, image).is_ok()
        && up.verify_and_accept().is_ok();

    // Commit the swap if accepted. A cut here leaves the staged swap either set
    // or not, which the modelled reset resolves.
    let _committed = accepted && up.commit().is_ok();

    // The global index the cut fires at IS the armed `cut_index`, because the cut
    // fires exactly when the countdown reaches the armed op (in either segment).
    // The harness records whether it fired anywhere across the whole flow.
    let mut fired_anywhere = up.flash().outcome() == CutOutcome::Fired;

    // Model the reboot. Read the surviving state out (carrying any unspent cut
    // countdown). The option-load-at-reset window has two outcomes (RM0456 sec
    // 7.5.8). When `reset_applied` is true the option program landed, so the
    // staged swap applies atomically and the NEW bank boots. When it is false the
    // cut killed the option program before it landed, so the arm is LOST and the
    // OLD option bytes (the OLD bank) survive: the staged swap never takes effect
    // and is dropped. Both outcomes must hold the invariant.
    let mut surviving = up.into_flash().into_surviving();
    if reset_applied
    {
        surviving.apply_reset();
    }
    else
    {
        // The option program did not complete: the arm is lost, OLD bank boots.
        surviving.staged_swap = None;
    }

    // Drive recovery to a settled state. Each loop iteration models one boot
    // cycle: a reset (which applies any staged swap), then on_boot, then confirm
    // or revert by health. A cut that survived into the post-reset segment fires
    // inside one of these boots and faults the recovery mid-way. The next boot
    // runs on clean silicon (the cut is spent) and retries, so the loop runs
    // until the state reaches a fixed point with no staged swap and no record.
    let mut guard = 0u32;
    loop
    {
        guard += 1;
        assert!(guard < 16, "recovery must settle in a bounded number of boots");

        // Each boot after the first applies the staged option load atomically:
        // a reboot IS a reset. The first iteration already had `reset_applied`
        // resolved above.
        if guard > 1
        {
            surviving.apply_reset();
        }

        let before = surviving;
        let flash2 = FidelityFlash::new(surviving);
        let se2 = FidelitySeCounter::new(SE_AT_FLOOR);
        let mut up2 = Updater::new(root, flash2, se2);

        let boot_state = up2.on_boot();

        if let Ok(UpdateState::AwaitingConfirm) = boot_state
        {
            match health
            {
                Health::Confirm =>
                {
                    let _ = up2.confirm(NEW_IMAGE_COUNTER);
                }
                Health::Revert =>
                {
                    let _ = up2.revert();
                }
            }
        }
        if up2.flash().outcome() == CutOutcome::Fired
        {
            fired_anywhere = true;
        }

        surviving = up2.into_flash().into_surviving();

        // The state has settled once no swap is staged, no record dangles, and a
        // full clean boot cycle changed nothing (a functional fixed point). A
        // cut countdown may still ride if its armed index is past the LAST
        // mutation the settled flow ever issues: that cut is genuinely
        // unreachable for this configuration (recorded as NotReached), so the
        // fixed point still settles. The leftover countdown is cleared below.
        let quiescent = surviving.staged_swap.is_none()
            && surviving.pending == PendingFlag::None;
        if quiescent && surviving == before
        {
            break;
        }
    }

    // Clear any unreachable leftover cut so the settled state is clean. The
    // outcome already records NotReached for a cut that never hit a mutation.
    surviving.cut_countdown = None;

    let settled = settled_disposition(&surviving, health);
    let (outcome, fired_index) = if fired_anywhere
    {
        (CutOutcome::Fired, Some(cut_index))
    }
    else
    {
        (CutOutcome::NotReached, None)
    };
    FlowResult
    {
        surviving,
        outcome,
        fired_index,
        settled,
    }
}

// Decides the settled disposition from the final state and the health branch.
fn settled_disposition(state: &PersistentState, health: Health) -> Settled
{
    // A confirmed swap leaves the NEW bank (Bank2) running with the record clear.
    // Any other settled state keeps the OLD bank (Bank1) running.
    if health == Health::Confirm
        && state.running == BankId::Bank2
        && state.pending == PendingFlag::None
    {
        Settled::Confirmed
    }
    else
    {
        Settled::OldBank
    }
}

// Asserts the safety invariant on a settled state, given the OLD bank image and
// the end-to-end disposition.
//
// (a) the OLD bank stays bootable at every cut until a swap is confirmed,
// (b) the booting bank always verifies and an unverified image never boots,
// (c) the NVCNT never rises above the security counter of the bank that boots,
// (d) no settled state leaves a staged swap pointing at the unverified bank.
fn assert_invariants
(
    result: &FlowResult,
    old_image: &[u8],
    new_image: &[u8],
    root: &RootKey,
)
{
    let surviving = &result.surviving;

    // (d) After recovery no swap may be left staged and no pending record may
    // dangle toward the unverified bank.
    assert_eq!(
        surviving.staged_swap,
        None,
        "no staged swap may survive a settled recovery"
    );
    assert_eq!(
        surviving.pending,
        PendingFlag::None,
        "no pending record may survive a settled recovery"
    );

    match result.settled
    {
        Settled::Confirmed =>
        {
            // The swap is confirmed: the NEW bank (Bank2) is the bank that boots.
            assert_eq!(
                surviving.running,
                BankId::Bank2,
                "a confirmed swap boots the NEW bank"
            );
            // (b) The booting bank must verify. Read the EXACT bytes that ended
            // up bootable out of the model and prove they verify.
            let booted = surviving.store(BankId::Bank2);
            let len = core::cmp::min(new_image.len(), booted.len());
            assert!(
                verify_image(&booted[..len], root).is_ok(),
                "the confirmed NEW bank bytes must verify"
            );
            // (c) NVCNT never above the booting bank counter.
            assert!(
                surviving.nvcnt <= NEW_IMAGE_COUNTER,
                "NVCNT must not exceed the booting bank counter"
            );
        }
        Settled::OldBank =>
        {
            // (a) The swap is not confirmed, so the OLD bank (Bank1) must boot.
            assert_eq!(
                surviving.running,
                BankId::Bank1,
                "an unconfirmed swap must keep the OLD bank running"
            );
            // (b) The OLD bank bytes in the MODEL must still verify (non-vacuous:
            // these are the actual stored bytes, never a rebuilt copy).
            let booted = surviving.store(BankId::Bank1);
            let len = core::cmp::min(old_image.len(), booted.len());
            assert!(
                verify_image(&booted[..len], root).is_ok(),
                "the OLD bank bytes must still verify"
            );
            // (c) No Gate-1 poisoning: an unconfirmed update must not raise NVCNT
            // above the OLD bank counter.
            assert!(
                surviving.nvcnt <= OLD_BANK_COUNTER,
                "NVCNT must not rise above the OLD bank on an unconfirmed update"
            );
        }
    }
}

// The number of global mutation indices the valid-image confirm flow walks.
//
// Derived from the 600-byte payload image (688 bytes, two full pages plus a
// partial). The sequence is: erase (0), page write (1), page write (2), partial
// page write (3), pending arm (4), swap arm (5), [reset], boot_count_advance (6),
// confirm pending clear (7), confirm NVCNT bump (8). The revert flow walks the
// same count: ..., boot_count_advance (6), reverse-swap arm (7), pending clear
// (8). The harness enumerates 0..MUTATION_COUNT and asserts every index that is
// reachable for a configuration fires at least once.
const MUTATION_COUNT: u32 = 9;

#[test]
fn exhaustive_power_fault_interleavings_hold_the_invariant()
{
    let root = dev_root();
    // A small multi-page image so the script issues several page writes, each a
    // distinct cut boundary. The trailing partial page adds one more write.
    let image = build_image(NEW_IMAGE_COUNTER, &[0xCD; 600]);
    let (_state, old_image) = baseline();

    let modes = [
        CutMode::BeforeMutation,
        CutMode::AfterMutation,
        CutMode::TornWrite,
    ];
    // The option-load-at-reset window: when a swap is staged, model both the
    // reset committing it and a cut before it committed. Both must hold.
    let reset_outcomes = [true, false];
    // Drive both the confirm branch and the revert branch (BLOCKER 2).
    let healths = [Health::Confirm, Health::Revert];

    let mut total = 0u32;
    let mut fired = 0u32;
    // Census of which global indices fired, to prove every reachable mutation
    // point was actually injected (this is the check that would have caught the
    // earlier gap where no cut ever fired after the reset).
    let mut fired_seen = [false; MUTATION_COUNT as usize];

    for mode in modes
    {
        for reset_applied in reset_outcomes
        {
            for health in healths
            {
                for k in 0..MUTATION_COUNT
                {
                    let result =
                        run_flow(&root, &image, k, mode, reset_applied, health);
                    assert_invariants(&result, &old_image, &image, &root);

                    total += 1;
                    if result.outcome == CutOutcome::Fired
                    {
                        fired += 1;
                    }
                    if let Some(idx) = result.fired_index
                        && let Some(slot) = fired_seen.get_mut(idx as usize)
                    {
                        *slot = true;
                    }
                }
            }
        }
    }

    // Every global mutation index must have fired at least once across the
    // census. This is the assertion that proves the cut spans the WHOLE flow,
    // including the post-reset confirm and revert mutations.
    for (idx, seen) in fired_seen.iter().enumerate()
    {
        assert!(
            *seen,
            "global mutation index {idx} never fired, the cut span has a gap"
        );
    }

    // Report the interleaving count honestly. `total` is the full cross product
    // of modes, reset outcomes, health branches, and cut indices. `fired` counts
    // configurations where the armed cut actually hit a reachable mutation. Some
    // configurations do not reach a given index (for example a pre-reset cut
    // makes the post-reset branch shorter), so `fired` is below `total` by
    // design, and the per-index census above is the real coverage proof.
    let configs = (modes.len() * reset_outcomes.len() * healths.len()) as u32;
    std::eprintln!(
        "power-fault harness: {total} interleavings exercised, \
         {fired} cuts fired, every one of {MUTATION_COUNT} global mutation \
         indices fired at least once"
    );
    assert_eq!(total, configs * MUTATION_COUNT);
    assert!(fired > 0, "at least one cut must have fired");
}

#[test]
fn rejected_image_never_commits_at_any_cut()
{
    // BLOCKER 3 part 2: stream an image with a bad signature, drive the full flow
    // with a cut at every index in every mode, and assert it NEVER reaches a
    // confirmed swap and the OLD bank always boots. A rejected image must never
    // arm a swap nor flip the running bank.
    let root = dev_root();
    let bad_image = build_rejected_image(&[0xCD; 600]);
    let (_state, old_image) = baseline();

    let modes = [
        CutMode::BeforeMutation,
        CutMode::AfterMutation,
        CutMode::TornWrite,
    ];
    let reset_outcomes = [true, false];

    for mode in modes
    {
        for reset_applied in reset_outcomes
        {
            for k in 0..MUTATION_COUNT
            {
                let result = run_flow(
                    &root,
                    &bad_image,
                    k,
                    mode,
                    reset_applied,
                    Health::Confirm,
                );
                // The image never verifies, so the swap is never confirmed.
                assert_eq!(
                    result.settled,
                    Settled::OldBank,
                    "a rejected image must never reach a confirmed swap"
                );
                // The OLD bank still boots and still verifies.
                assert_eq!(
                    result.surviving.running,
                    BankId::Bank1,
                    "a rejected image must keep the OLD bank running"
                );
                let booted = result.surviving.store(BankId::Bank1);
                let len = core::cmp::min(old_image.len(), booted.len());
                assert!(
                    verify_image(&booted[..len], &root).is_ok(),
                    "the OLD bank bytes must still verify after a rejection"
                );
                // No swap may be staged and no record may dangle.
                assert_eq!(result.surviving.staged_swap, None);
                assert_eq!(result.surviving.pending, PendingFlag::None);
                // NVCNT must not have risen on a rejected image.
                assert!(
                    result.surviving.nvcnt <= OLD_BANK_COUNTER,
                    "a rejected image must not bump NVCNT"
                );
            }
        }
    }
}

#[test]
fn se_spend_interrupted_does_not_double_spend_or_strand()
{
    // MAJOR 2: interrupt confirm right at the SE spend (the channel drops on
    // se.update()), then prove the recovery on the next boot does not
    // double-spend the SE counter and does not strand a half-confirmed state. The
    // machine spends the SE counter FIRST in confirm (machine.rs confirm), so a
    // drop there leaves the swap committed, the record still Armed, and the NVCNT
    // not yet bumped. The next boot must re-enter AwaitingConfirm and complete.
    let root = dev_root();
    let image = build_image(NEW_IMAGE_COUNTER, b"se spend window payload one");

    // Run to a clean post-reset AwaitingConfirm state.
    let (state, _old) = baseline();
    let flash = FidelityFlash::new(state);
    let se = FidelitySeCounter::new(SE_AT_FLOOR);
    let mut up = Updater::new(&root, flash, se);
    up.begin(image.len()).expect("begin");
    up.receive_chunk(0, &image).expect("receive");
    up.verify_and_accept().expect("accept");
    up.commit().expect("commit");
    let mut surviving = up.into_flash().into_surviving();
    surviving.apply_reset();

    // First confirm boot: arm a channel drop on the SE update. The spend faults.
    let flash2 = FidelityFlash::new(surviving);
    let mut se2 = FidelitySeCounter::new(SE_AT_FLOOR);
    se2.arm_drop_on_update();
    let mut up2 = Updater::new(&root, flash2, se2);
    assert_eq!(up2.on_boot().expect("on_boot"), UpdateState::AwaitingConfirm);
    // The confirm fails at the SE spend, so the counter did not decrement.
    assert!(up2.confirm(NEW_IMAGE_COUNTER).is_err());
    assert!(
        !up2.se_counter().updated(),
        "a dropped SE spend must not decrement the counter"
    );
    // The swap is still committed, the record still Armed, NVCNT not bumped.
    let after_drop = up2.into_flash().into_surviving();
    assert_eq!(after_drop.running, BankId::Bank2, "swap stays committed");
    assert!(
        matches!(after_drop.pending, PendingFlag::Armed(_)),
        "the confirm-owed record must survive a dropped spend"
    );
    assert_eq!(after_drop.nvcnt, BASELINE_NVCNT, "NVCNT not bumped yet");

    // Next boot, channel up: the recovery re-enters AwaitingConfirm and confirms
    // cleanly. The SE counter spends exactly once (no double spend).
    let flash3 = FidelityFlash::new(after_drop);
    let se3 = FidelitySeCounter::new(SE_AT_FLOOR);
    let mut up3 = Updater::new(&root, flash3, se3);
    assert_eq!(up3.on_boot().expect("on_boot"), UpdateState::AwaitingConfirm);
    up3.confirm(NEW_IMAGE_COUNTER).expect("confirm");
    assert!(up3.se_counter().updated(), "the recovery spends the SE once");
    assert_eq!(up3.se_counter().value(), SE_AT_FLOOR - 1, "spent exactly once");
    let settled = up3.into_flash().into_surviving();
    assert_eq!(settled.running, BankId::Bank2, "NEW bank confirmed");
    assert_eq!(settled.pending, PendingFlag::None, "record cleared");
    assert_eq!(settled.nvcnt, NEW_IMAGE_COUNTER, "NVCNT bumped LAST");
}

#[test]
fn reset_after_clean_commit_boots_new_bank_and_confirms()
{
    // A clean run with no cut: commit stages the swap, the modelled reset applies
    // it atomically, on_boot owes a confirm, confirm completes. This pins the
    // staged-swap-atomic-at-reset model end to end, and proves the confirmed NEW
    // bank store verifies (BLOCKER 3 part 1).
    let root = dev_root();
    let image = build_image(NEW_IMAGE_COUNTER, b"clean new firmware payload");
    let (state, _old) = baseline();
    let flash = FidelityFlash::new(state);
    let se = FidelitySeCounter::new(SE_AT_FLOOR);
    let mut up = Updater::new(&root, flash, se);

    up.begin(image.len()).expect("begin");
    up.receive_chunk(0, &image).expect("receive");
    up.verify_and_accept().expect("accept");
    up.commit().expect("commit");

    // Before the reset the swap is staged, the OLD bank still runs.
    assert_eq!(up.flash().persistent().running, BankId::Bank1);
    assert_eq!(up.flash().persistent().staged_swap, Some(BankId::Bank2));

    // Model the reset: the staged option load applies atomically.
    let mut surviving = up.into_flash().into_surviving();
    surviving.apply_reset();
    assert_eq!(surviving.running, BankId::Bank2, "reset applied the swap");

    let flash2 = FidelityFlash::new(surviving);
    let se2 = FidelitySeCounter::new(SE_AT_FLOOR);
    let mut up2 = Updater::new(&root, flash2, se2);
    assert_eq!(
        up2.on_boot().expect("on_boot"),
        UpdateState::AwaitingConfirm
    );
    up2.confirm(NEW_IMAGE_COUNTER).expect("confirm");
    assert_eq!(up2.state(), UpdateState::Confirmed);
    let settled = up2.into_flash().into_surviving();
    assert_eq!(settled.nvcnt, NEW_IMAGE_COUNTER);
    // The confirmed NEW bank store must verify (the bytes that ended bootable).
    let booted = settled.store(BankId::Bank2);
    let len = core::cmp::min(image.len(), booted.len());
    assert!(
        verify_image(&booted[..len], &root).is_ok(),
        "the confirmed NEW bank bytes must verify"
    );
}

#[test]
fn revert_returns_to_old_bank_and_leaves_no_dangling_stage()
{
    // BLOCKER 2: drive the revert branch. on_boot reaches AwaitingConfirm, then
    // revert is driven (modelling the health check failing). After a revert the
    // OLD bank boots, and no settled state leaves a staged swap toward the
    // unverified bank with the pending still Armed.
    let root = dev_root();
    let image = build_image(NEW_IMAGE_COUNTER, b"revert path firmware bytes");
    let (state, old_image) = baseline();
    let flash = FidelityFlash::new(state);
    let se = FidelitySeCounter::new(SE_AT_FLOOR);
    let mut up = Updater::new(&root, flash, se);

    up.begin(image.len()).expect("begin");
    up.receive_chunk(0, &image).expect("receive");
    up.verify_and_accept().expect("accept");
    up.commit().expect("commit");
    let mut surviving = up.into_flash().into_surviving();
    surviving.apply_reset();
    assert_eq!(surviving.running, BankId::Bank2, "swap took effect");

    // First boot of the NEW bank: on_boot owes a confirm, but the health check
    // fails, so revert is driven instead.
    let flash2 = FidelityFlash::new(surviving);
    let se2 = FidelitySeCounter::new(SE_AT_FLOOR);
    let mut up2 = Updater::new(&root, flash2, se2);
    assert_eq!(up2.on_boot().expect("on_boot"), UpdateState::AwaitingConfirm);
    up2.revert().expect("revert");
    assert_eq!(up2.state(), UpdateState::Reverted);
    let mut after_revert = up2.into_flash().into_surviving();

    // The reverse swap is staged. The record is already cleared. (d) holds: no
    // staged swap points at the unverified bank with pending still Armed.
    assert_eq!(after_revert.pending, PendingFlag::None, "record cleared");
    assert_eq!(after_revert.staged_swap, Some(BankId::Bank1), "reverse staged");

    // The reset applies the reverse swap atomically: the OLD bank boots again.
    after_revert.apply_reset();
    assert_eq!(after_revert.running, BankId::Bank1, "OLD bank boots after revert");

    // The OLD bank bytes still verify, and the SE counter was never spent.
    let booted = after_revert.store(BankId::Bank1);
    let len = core::cmp::min(old_image.len(), booted.len());
    assert!(
        verify_image(&booted[..len], &root).is_ok(),
        "the OLD bank bytes must still verify after a revert"
    );
    assert_eq!(after_revert.nvcnt, OLD_BANK_COUNTER, "NVCNT not bumped");

    // A boot after the revert finds no record and stays on the OLD bank.
    let flash3 = FidelityFlash::new(after_revert);
    let se3 = FidelitySeCounter::new(SE_AT_FLOOR);
    let mut up3 = Updater::new(&root, flash3, se3);
    assert_eq!(up3.on_boot().expect("on_boot"), UpdateState::Idle);
}

#[test]
fn cut_before_swap_reset_keeps_old_bank()
{
    // The swap is staged but the option load never commits (a cut before the
    // reset). The surviving state still runs the OLD bank, and a reboot proves
    // the swap never took effect, so on_boot stays on the OLD bank.
    let root = dev_root();
    let image = build_image(NEW_IMAGE_COUNTER, b"new firmware payload bytes");
    let (state, old_image) = baseline();
    let flash = FidelityFlash::new(state);
    let se = FidelitySeCounter::new(SE_AT_FLOOR);
    let mut up = Updater::new(&root, flash, se);

    up.begin(image.len()).expect("begin");
    up.receive_chunk(0, &image).expect("receive");
    up.verify_and_accept().expect("accept");
    up.commit().expect("commit");

    // Model a power cut BEFORE the option load: do NOT apply the staged swap.
    let surviving = up.into_flash().into_surviving();
    assert_eq!(surviving.running, BankId::Bank1, "OLD bank still runs");
    assert_eq!(surviving.staged_swap, Some(BankId::Bank2), "swap still staged");

    let flash2 = FidelityFlash::new(surviving);
    let se2 = FidelitySeCounter::new(SE_AT_FLOOR);
    let mut up2 = Updater::new(&root, flash2, se2);
    // The running bank does not match the armed target, so on_boot clears the
    // record and stays on the OLD bank, arming no reverse swap.
    assert_eq!(up2.on_boot().expect("on_boot"), UpdateState::Idle);
    assert_eq!(up2.flash().persistent().pending, PendingFlag::None);
    let booted = up2.flash().persistent().store(BankId::Bank1);
    let len = core::cmp::min(old_image.len(), booted.len());
    assert!(verify_image(&booted[..len], &root).is_ok());
}

#[test]
fn torn_page_write_makes_bank_fail_verify()
{
    // A torn quad-word during a page write poisons that quad-word, so verify
    // rejects the bank and no swap is armed. The OLD bank boots, and the OLD bank
    // store is never touched by the write to the inactive store.
    let root = dev_root();
    // A multi-page image so a full page flushes during receive, where the tear
    // lands. A sub-page image would only write at accept time.
    let image = build_image(NEW_IMAGE_COUNTER, &[0xCD; 600]);
    let (state, old_image) = baseline();
    let mut flash = FidelityFlash::new(state);
    // Cut index 1 is the first full page write (index 0 is the erase at begin).
    flash.arm_cut(1, CutMode::TornWrite);
    let se = FidelitySeCounter::new(SE_AT_FLOOR);
    let mut up = Updater::new(&root, flash, se);

    up.begin(image.len()).expect("begin");
    // The torn write faults the page write, collapsing the transfer fail-closed.
    assert!(up.receive_chunk(0, &image).is_err());
    assert_ne!(up.state(), UpdateState::Committed);
    assert_eq!(up.flash().persistent().staged_swap, None, "no swap staged");
    // The OLD bank store is untouched: the tear poisoned only the inactive store.
    let booted = up.flash().persistent().store(BankId::Bank1);
    let len = core::cmp::min(old_image.len(), booted.len());
    assert!(
        verify_image(&booted[..len], &root).is_ok(),
        "the OLD bank store must be untouched by an inactive-bank tear"
    );
}
