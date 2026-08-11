//! Host proof of the boot stage.
//!
//! Four layers: the decision state machine (exhaustive over the input
//! space), the four-segment health check, the SECWM wedge, and the whole boot
//! flow over the state mock including a power-cut census that cuts at every
//! persistent-mutation boundary and proves recovery.

use std::panic::AssertUnwindSafe;
use std::string::String;

use fw_update::BankId;
use fw_update::PendingFlag;
use fw_update::UpdateOutcome;
use image_verify::HEADER_LEN;
use image_verify::ImageVersion;
use image_verify::ROOT_KEY_LEN;
use image_verify::RootKey;
use image_verify::SIG_LEN;
use image_verify::encode_header;
use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::Signer;

use crate::decision::BootDecision;
use crate::decision::BootPlan;
use crate::decision::WedgeReason;
use crate::decision::decide;
use crate::glue::BootOutcome;
use crate::glue::run;
use crate::health;
use crate::health::ImageHealth;
use crate::key;
use crate::mock::BankImage;
use crate::mock::MockBootFlash;
use crate::mock::POWER_CUT;
use crate::mock::bringup_signing_key;
use crate::mock::good_secwm;
use crate::secwm::SecwmReadback;
use crate::secwm::SecwmWindow;
use crate::secwm::decode_window;
use crate::secwm::secwm_ok;

/// The public key the fixtures sign with: the bring-up TEST key.
///
/// The boot flow verifies whichever root key is injected into `run` / `assess`, so
/// the tests inject the bring-up key that `mock.rs` signs its fixtures with. This
/// is deliberately independent of the pinned production trust anchor (the slot-82
/// key), which the golden test pins separately. The private half of the production
/// key lives in the YubiKey and cannot sign host fixtures.
fn bringup_root() -> RootKey
{
    let point = bringup_signing_key().verifying_key().to_sec1_point(false);
    let bytes: [u8; ROOT_KEY_LEN] = point
        .as_ref()
        .try_into()
        .expect("uncompressed SEC1 point is 65 bytes");
    RootKey::from_bytes(bytes).expect("bring-up public key is on-curve")
}

#[test]
fn pinned_key_is_a_valid_point()
{
    assert!(key::product_root_key().is_ok());
}

#[test]
fn pinned_key_is_production_key()
{
    // The golden pin: the exact production trust anchor. 
    // This literal is the durable pin: an accidental change 
    // to product_root_key.sec1 fails here.
    const PRODUCTION_ROOT_KEY: [u8; 65] = [
        0x04, 0xdd, 0x0a, 0x85, 0xa4, 0x3d, 0x1f, 0x56,
        0xa9, 0x72, 0x53, 0xd3, 0xd4, 0xe0, 0xf3, 0xcd,
        0x22, 0x9e, 0xcb, 0x6b, 0xdf, 0x0b, 0x63, 0x82,
        0x02, 0x90, 0x5e, 0x0d, 0xa9, 0x06, 0xde, 0x5d,
        0xe8, 0x48, 0xaf, 0x17, 0x4f, 0x37, 0x90, 0xbc,
        0xcb, 0x9b, 0x57, 0xa2, 0x59, 0x80, 0x7a, 0x09,
        0x5f, 0x83, 0xab, 0x34, 0x84, 0xdd, 0x31, 0x88,
        0x96, 0x0f, 0x4c, 0xc3, 0xc9, 0x4d, 0x33, 0xf2,
        0xb8,
    ];
    assert_eq!(key::PROD_ROOT_KEY_SEC1.as_slice(), PRODUCTION_ROOT_KEY.as_slice());
    // The committed bytes are a valid on-curve P-256 point.
    assert!(key::product_root_key().is_ok());
}

#[test]
fn pinned_key_is_not_the_dev_key()
{
    // The all-0x01 dev public key (DEV_ROOT_KEY_TEST_ONLY / the image-verify fuzz
    // key), the pinned production key must differ.
    const DEV_PUBKEY: [u8; 65] = [
        0x04, 0x6f, 0xf0, 0x3b, 0x94, 0x92, 0x41, 0xce,
        0x1d, 0xad, 0xd4, 0x35, 0x19, 0xe6, 0x96, 0x0e,
        0x0a, 0x85, 0xb4, 0x1a, 0x69, 0xa0, 0x5c, 0x32,
        0x81, 0x03, 0xaa, 0x2b, 0xce, 0x15, 0x94, 0xca,
        0x16, 0x3c, 0x4f, 0x75, 0x3a, 0x55, 0xbf, 0x01,
        0xdc, 0x53, 0xf6, 0xc0, 0xb0, 0xc7, 0xee, 0xe7,
        0x8b, 0x40, 0xc6, 0xff, 0x7d, 0x25, 0xa9, 0x6e,
        0x22, 0x82, 0xb9, 0x89, 0xce, 0xf7, 0x1c, 0x14,
        0x4a,
    ];
    assert_ne!(key::PROD_ROOT_KEY_SEC1.as_slice(), DEV_PUBKEY.as_slice());
}

#[test]
fn healthy_image_verifies_and_carries_the_counter()
{
    let image = BankImage::healthy(7, 20);
    let health = health::assess
    (
        &image.descriptor,
        &image.secure_band,
        &image.ns_band,
        &bringup_root(),
    );
    assert_eq!(health, ImageHealth::Verified { security_counter: 7 });
}

#[test]
fn payload_spanning_the_secwm_boundary_verifies()
{
    // A payload longer than the secure band spills into the non-secure band, so
    // the carving in `assess` must split it exactly like the device layout.
    let image = BankImage::healthy(3, 150);
    let health = health::assess
    (
        &image.descriptor,
        &image.secure_band,
        &image.ns_band,
        &bringup_root(),
    );
    assert_eq!(health, ImageHealth::Verified { security_counter: 3 });
}

#[test]
fn tampered_payload_is_rejected()
{
    let mut image = BankImage::healthy(7, 20);
    image.secure_band[0] ^= 0x01;
    let health = health::assess
    (
        &image.descriptor,
        &image.secure_band,
        &image.ns_band,
        &bringup_root(),
    );
    assert_eq!(health, ImageHealth::Rejected);
}

#[test]
fn bad_signature_is_rejected()
{
    let image = BankImage::unhealthy(7, 20);
    let health = health::assess
    (
        &image.descriptor,
        &image.secure_band,
        &image.ns_band,
        &bringup_root(),
    );
    assert_eq!(health, ImageHealth::Rejected);
}

#[test]
fn erased_bank_is_rejected()
{
    let image = BankImage::erased();
    let health = health::assess(
        &image.descriptor,
        &image.secure_band,
        &image.ns_band,
        &bringup_root(),
    );
    assert_eq!(health, ImageHealth::Rejected);
}

#[test]
fn image_signed_by_a_foreign_key_is_rejected()
{
    // Sign a well-formed image with a different scalar than the pinned key.
    let payload = [0xABu8; 20];
    let header = encode_header(
        ImageVersion { major: 1, minor: 0, revision: 0, build: 0 },
        4,
        payload.len() as u32,
    );
    let mut signed = std::vec::Vec::new();
    signed.extend_from_slice(&header);
    signed.extend_from_slice(&payload);
    let foreign = SigningKey::from_slice(&[7u8; 32]).unwrap();
    let sig: p256::ecdsa::Signature = foreign.sign(&signed);
    let sig = sig.normalize_s();
    let mut descriptor = std::vec::Vec::new();
    descriptor.extend_from_slice(&header);
    descriptor.extend_from_slice(&sig.to_bytes());
    let mut secure_band = std::vec![0xFFu8; 96];
    secure_band[..20].copy_from_slice(&payload);
    let ns_band = std::vec![0xFFu8; 96];

    let health =
        health::assess(&descriptor, &secure_band, &ns_band, &bringup_root());
    assert_eq!(health, ImageHealth::Rejected);
}

#[test]
fn short_descriptor_is_rejected()
{
    let image = BankImage::healthy(7, 20);
    let short = &image.descriptor[..HEADER_LEN + SIG_LEN - 4];
    let health =
        health::assess(short, &image.secure_band, &image.ns_band, &bringup_root());
    assert_eq!(health, ImageHealth::Rejected);
}

#[test]
fn payload_len_overrunning_the_bands_is_rejected()
{
    // Rewrite the header's payload_len to a value larger than the two bands hold.
    // The carve bounds-check rejects it before any curve work.
    let mut image = BankImage::healthy(7, 20);
    let huge = 100_000u32.to_le_bytes();
    image.descriptor[18..22].copy_from_slice(&huge);
    let health = health::assess(
        &image.descriptor,
        &image.secure_band,
        &image.ns_band,
        &bringup_root(),
    );
    assert_eq!(health, ImageHealth::Rejected);
}

#[test]
fn payload_len_offset_matches_the_encoder()
{
    // Guard the hardcoded OFF_PAYLOAD_LEN against the image-verify encoder.
    let header = encode_header(
        ImageVersion { major: 1, minor: 0, revision: 0, build: 0 },
        0,
        0xDEAD_BEEF,
    );
    let at = health::OFF_PAYLOAD_LEN_FOR_TEST;
    assert_eq!(&header[at..at + 4], &0xDEAD_BEEFu32.to_le_bytes());
}

#[test]
fn secwm_decode_masks_to_five_bits()
{
    // PSTRT=0, PEND=19 encodes as (19 << 16).
    assert_eq!(decode_window(0x0013_0000), SecwmWindow { start: 0, end: 19 });
    // The upper reserved bits of each field are ignored (masked to 5 bits).
    assert_eq!(decode_window(0x00FF_00E0), SecwmWindow { start: 0, end: 31 });
}

#[test]
fn factory_default_secwm_fails_closed()
{
    // The unprogrammed U535/545 value 0xFFFF_FF80 decodes to pages 0..=31, which
    // is not the provisioned 0..=19, so the wedge fires.
    let window = decode_window(0xFFFF_FF80);
    assert_eq!(window, SecwmWindow { start: 0, end: 31 });
    let readback = SecwmReadback { bank1: window, bank2: window };
    assert!(!secwm_ok(&readback));
}

#[test]
fn provisioned_secwm_passes()
{
    assert!(secwm_ok(&good_secwm()));
}

#[test]
fn one_mis_provisioned_bank_fails_closed()
{
    let readback = SecwmReadback
    {
        bank1: SecwmWindow { start: 0, end: 19 },
        bank2: SecwmWindow { start: 0, end: 18 },
    };
    assert!(!secwm_ok(&readback));
}

#[test]
fn secwm_wedge_fires_in_the_boot_flow()
{
    let mut mock = MockBootFlash::confirmed(
        false,
        BankImage::healthy(3, 20),
        BankImage::healthy(3, 20),
        3,
    );
    mock.secwm = SecwmReadback
    {
        bank1: SecwmWindow { start: 0, end: 31 },
        bank2: SecwmWindow { start: 0, end: 31 },
    };
    assert_eq!(run(&mut mock, &bringup_root()),
        BootOutcome::Wedge(WedgeReason::SecwmMismatch));
}

#[test]
fn bad_partition_wedges_before_trusting_isolation()
{
    let mut mock = MockBootFlash::confirmed(
        false,
        BankImage::healthy(3, 20),
        BankImage::healthy(3, 20),
        3,
    );
    mock.partition_ok = false;
    assert_eq!(run(&mut mock, &bringup_root()),
        BootOutcome::Wedge(WedgeReason::Unreadable));
}

// The four axes of the decision input space.
const RUNNING_CASES: [BankId; 2] = [BankId::Bank1, BankId::Bank2];

const PENDING_CASES: [PendingFlag; 3] =
[
    PendingFlag::None,
    PendingFlag::Armed(BankId::Bank1),
    PendingFlag::Armed(BankId::Bank2),
];

const NVCNT_CASES: [u32; 3] = [0, 5, 10];

const HEALTH_CASES: [ImageHealth; 4] =
[
    ImageHealth::Rejected,
    ImageHealth::Verified { security_counter: 0 },
    ImageHealth::Verified { security_counter: 5 },
    ImageHealth::Verified { security_counter: 10 },
];

/// One point of the decision input space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DecisionInput
{
    running: BankId,
    pending: PendingFlag,
    nvcnt: u32,
    health: ImageHealth,
}

/// Enumerates the cartesian product of the four axes as one flat iterator.
fn decision_inputs() -> impl Iterator<Item = DecisionInput>
{
    RUNNING_CASES
        .into_iter()
        .flat_map(|running|
        {
            PENDING_CASES.into_iter().map(move |pending| (running, pending))
        })
        .flat_map(|(running, pending)|
        {
            NVCNT_CASES
                .into_iter()
                .map(move |nvcnt| (running, pending, nvcnt))
        })
        .flat_map(|(running, pending, nvcnt)|
        {
            HEALTH_CASES.into_iter().map(move |health| DecisionInput
            {
                running,
                pending,
                nvcnt,
                health,
            })
        })
}

/// A Revert only ever follows the swap-applied case with an unhealthy or
/// rolled-back new image.
fn assert_revert_is_justified(input: DecisionInput)
{
    let applied = matches!(input.pending, PendingFlag::Armed(t) if t == input.running);
    assert!(applied, "revert only when the swap applied");
    let bad = match input.health
    {
        ImageHealth::Rejected => true,
        ImageHealth::Verified { security_counter } =>
        {
            security_counter < input.nvcnt
        }
    };
    assert!(bad, "revert only on a bad or rolled-back image");
}

/// A bump only ever advances toward a Verified, non-rolled-back counter.
fn assert_bump_is_justified(input: DecisionInput, plan: BootPlan)
{
    let Some(v) = plan.advance_nvcnt
    else
    {
        return;
    };
    match input.health
    {
        ImageHealth::Verified { security_counter } =>
        {
            assert_eq!(v, security_counter);
            assert!(security_counter >= input.nvcnt);
        }
        ImageHealth::Rejected =>
        {
            panic!("bumped on a rejected image");
        }
    }
}

/// Asserts the enumerated inputs are pairwise distinct.
///
/// A count pin alone still passes when an axis is rewritten to repeat one value,
/// which holds the total while dropping the cases the property constrains, such
/// as a Rejected image or a rolled-back counter.
fn assert_inputs_are_distinct(inputs: &[DecisionInput])
{
    for (i, a) in inputs.iter().enumerate()
    {
        for b in inputs.iter().skip(i + 1)
        {
            assert_ne!(a, b, "the decision axes must enumerate distinct inputs");
        }
    }
}

/// Checks one decision against the never-revert-and-bump property.
fn assert_decision_is_safe(input: DecisionInput)
{
    match decide(input.running, input.pending, input.nvcnt, input.health)
    {
        BootDecision::Revert => assert_revert_is_justified(input),
        BootDecision::Boot(plan) => assert_bump_is_justified(input, plan),
        BootDecision::Wedge(_) => {}
    }
}

#[test]
fn decision_never_reverts_and_bumps_together()
{
    let inputs: std::vec::Vec<DecisionInput> = decision_inputs().collect();
    for input in &inputs
    {
        assert_decision_is_safe(*input);
    }
    assert_eq!(inputs.len(), 72, "the decision space is 72 decisions");
    assert_inputs_are_distinct(&inputs);
}

#[test]
fn normal_boot_of_a_confirmed_healthy_bank()
{
    let d = decide(
        BankId::Bank1,
        PendingFlag::None,
        5,
        ImageHealth::Verified { security_counter: 5 },
    );
    assert_eq!(d, BootDecision::Boot(BootPlan
    {
        clear_outcome: false,
        clear_pending: false,
        advance_nvcnt: None,
    }));
}

#[test]
fn normal_boot_self_heals_a_lagging_nvcnt()
{
    // pending None, running verified sc=8, nvcnt=5: a prior confirm was cut after
    // clearing pending but before the bump. The boot advances the NVCNT.
    let d = decide(
        BankId::Bank1,
        PendingFlag::None,
        5,
        ImageHealth::Verified { security_counter: 8 },
    );
    assert_eq!(d, BootDecision::Boot(BootPlan
    {
        clear_outcome: false,
        clear_pending: false,
        advance_nvcnt: Some(8),
    }));
}

#[test]
fn normal_boot_of_a_rejected_bank_wedges()
{
    let d = decide(BankId::Bank1, PendingFlag::None, 5, ImageHealth::Rejected);
    assert_eq!(d, BootDecision::Wedge(WedgeReason::NoBootableImage));
}

#[test]
fn normal_boot_of_a_rolled_back_bank_wedges()
{
    let d = decide(
        BankId::Bank1,
        PendingFlag::None,
        9,
        ImageHealth::Verified { security_counter: 3 },
    );
    assert_eq!(d, BootDecision::Wedge(WedgeReason::RolledBack));
}

#[test]
fn confirm_of_a_healthy_new_bank()
{
    // Armed(Bank2), running Bank2, healthy sc=5 >= nvcnt=3: confirm.
    let d = decide(
        BankId::Bank2,
        PendingFlag::Armed(BankId::Bank2),
        3,
        ImageHealth::Verified { security_counter: 5 },
    );
    assert_eq!(d, BootDecision::Boot(BootPlan
    {
        clear_outcome: true,
        clear_pending: true,
        advance_nvcnt: Some(5),
    }));
}

#[test]
fn unhealthy_new_bank_reverts()
{
    let d = decide(
        BankId::Bank2,
        PendingFlag::Armed(BankId::Bank2),
        3,
        ImageHealth::Rejected,
    );
    assert_eq!(d, BootDecision::Revert);
}

#[test]
fn rolled_back_new_bank_reverts()
{
    let d = decide(
        BankId::Bank2,
        PendingFlag::Armed(BankId::Bank2),
        9,
        ImageHealth::Verified { security_counter: 3 },
    );
    assert_eq!(d, BootDecision::Revert);
}

#[test]
fn swap_never_applied_clears_the_stale_record_and_boots_old()
{
    // Armed(Bank2) but running Bank1: the swap never took effect. Clear the record
    // and boot the old bank, preserving the outcome.
    let d = decide(
        BankId::Bank1,
        PendingFlag::Armed(BankId::Bank2),
        3,
        ImageHealth::Verified { security_counter: 3 },
    );
    assert_eq!(d, BootDecision::Boot(BootPlan
    {
        clear_outcome: false,
        clear_pending: true,
        advance_nvcnt: None,
    }));
}

#[test]
fn swap_never_applied_with_a_dead_old_bank_wedges()
{
    let d = decide(
        BankId::Bank1,
        PendingFlag::Armed(BankId::Bank2),
        3,
        ImageHealth::Rejected,
    );
    assert_eq!(d, BootDecision::Wedge(WedgeReason::NoBootableImage));
}

/// Runs one boot pass over the mock.
fn boot_once(mock: &mut MockBootFlash) -> BootOutcome
{
    run(mock, &bringup_root())
}

/// Drives to a stable outcome, applying the reset after each revert (bounded).
fn drive_to_stable(mock: &mut MockBootFlash) -> BootOutcome
{
    for _ in 0..8
    {
        match boot_once(mock)
        {
            BootOutcome::Reverted => mock.apply_reset(),
            other => return other,
        }
    }
    panic!("boot did not stabilise");
}

/// Runs one boot pass with a modelled power cut armed at `index`, and asserts the
/// run unwound at exactly that boundary (the cut fired).
fn expect_cut_at(mock: &mut MockBootFlash, index: usize)
{
    mock.arm_cut(Some(index));
    let prev = std::panic::take_hook();
    std::panic::set_hook(std::boxed::Box::new(|_| {}));
    let caught = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let _ = boot_once(mock);
    }));
    std::panic::set_hook(prev);
    let payload = caught.expect_err("expected a power cut but the run completed");
    let message = payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| payload.downcast_ref::<&str>().copied())
        .unwrap_or("");
    assert_eq!(message, POWER_CUT, "unwound for a reason other than the cut");
    // Disarm for the recovery run.
    mock.arm_cut(None);
}

fn confirm_scenario() -> MockBootFlash
{
    // Running = Bank2 (swap true), a pending confirm toward Bank2, the new bank
    // healthy with counter 5, the NVCNT still at the old 3.
    let old = BankImage::healthy(3, 20);
    let new = BankImage::healthy(5, 20);
    let mut mock = MockBootFlash::confirmed(true, old, new, 3);
    mock.pending = PendingFlag::Armed(BankId::Bank2);
    mock
}

fn revert_scenario() -> MockBootFlash
{
    // Running = Bank2 (swap true), a pending confirm toward Bank2, but the new
    // bank is unhealthy. The old Bank1 is healthy at counter 3.
    let old = BankImage::healthy(3, 20);
    let new = BankImage::unhealthy(5, 20);
    let mut mock = MockBootFlash::confirmed(true, old, new, 3);
    mock.pending = PendingFlag::Armed(BankId::Bank2);
    mock
}

/// Counts the persistent mutations a clean run performs (the census length).
fn mutation_count(mut mock: MockBootFlash) -> usize
{
    let _ = drive_to_stable(&mut mock);
    mock.mutations
}

#[test]
fn confirm_flow_reaches_a_confirmed_state()
{
    let mut mock = confirm_scenario();
    assert_eq!(boot_once(&mut mock), BootOutcome::HandOff(BankId::Bank2));
    assert_eq!(mock.pending, PendingFlag::None);
    assert_eq!(mock.nvcnt, 5);
    assert_eq!(mock.outcome, UpdateOutcome::None);
    assert_eq!(mock.running(), BankId::Bank2);
}

#[test]
fn confirm_bumps_the_nvcnt_last()
{
    // Cut at the last mutation index: everything but the bump is applied, and the
    // NVCNT is still the old value. This pins the bump as the terminal step.
    let mut mock = confirm_scenario();
    let count = mutation_count(confirm_scenario());
    assert_eq!(count, 3, "confirm applies outcome-clear, pending-clear, bump");
    expect_cut_at(&mut mock, count - 1);
    assert_eq!(mock.nvcnt, 3, "the bump is last, so it did not run before the cut");
    assert_eq!(mock.pending, PendingFlag::None, "pending was cleared before the bump");
}

#[test]
fn confirm_recovers_from_a_cut_at_every_boundary()
{
    let count = mutation_count(confirm_scenario());
    for index in 0..count
    {
        let mut mock = confirm_scenario();
        expect_cut_at(&mut mock, index);
        // Reboot and run to a stable outcome with no further cut.
        let outcome = drive_to_stable(&mut mock);
        assert_eq!(outcome, BootOutcome::HandOff(BankId::Bank2),
            "cut at {index} must still confirm the new bank");
        assert_eq!(mock.pending, PendingFlag::None, "cut at {index}");
        assert_eq!(mock.nvcnt, 5, "cut at {index}: the NVCNT reaches the new counter");
        assert_eq!(mock.running(), BankId::Bank2, "cut at {index}");
    }
}

#[test]
fn revert_flow_returns_to_the_old_bank_without_bumping()
{
    let mut mock = revert_scenario();
    let outcome = drive_to_stable(&mut mock);
    assert_eq!(outcome, BootOutcome::HandOff(BankId::Bank1));
    assert_eq!(mock.running(), BankId::Bank1, "the old bank boots");
    assert_eq!(mock.nvcnt, 3, "a revert never bumps the NVCNT");
    assert_eq!(mock.outcome, UpdateOutcome::AutoReverted, "the revert is surfaced");
    assert_eq!(mock.pending, PendingFlag::None, "the stale record is cleared");
}

/// Drives across resets with a global cut armed, catching the unwind whenever it
/// fires. The cut index counts persistent mutations across the whole flow,
/// including those after a reset (RM0456 sec 7.5.8), so a cut in the post-reset
/// recovery step is reached. Returns whether the cut fired.
fn drive_catching_global_cut(mock: &mut MockBootFlash) -> bool
{
    for _ in 0..8
    {
        let prev = std::panic::take_hook();
        std::panic::set_hook(std::boxed::Box::new(|_| {}));
        let result = std::panic::catch_unwind(AssertUnwindSafe(|| boot_once(mock)));
        std::panic::set_hook(prev);
        match result
        {
            Err(_) => return true,
            Ok(BootOutcome::Reverted) => mock.apply_reset(),
            Ok(_) => return false,
        }
    }
    false
}

#[test]
fn revert_recovers_from_a_cut_at_every_boundary_and_never_confirms()
{
    // The revert path spans a reset: the outcome write and the swap arm run before
    // the reset, the stale-record clear runs after it. The census cut index is
    // global across that reset boundary, streaming a genuinely rejected image
    // through the full flow and asserting it never reaches a confirmed swap.
    let count = mutation_count(revert_scenario());
    assert!(count >= 2, "revert writes the outcome then arms the swap");
    for index in 0..count
    {
        let mut mock = revert_scenario();
        mock.cut_at = Some(index);
        mock.mutations = 0;
        let fired = drive_catching_global_cut(&mut mock);
        assert!(fired, "the global cut at {index} must fire");
        // Disarm and recover.
        mock.cut_at = None;
        let outcome = drive_to_stable(&mut mock);
        assert_eq!(outcome, BootOutcome::HandOff(BankId::Bank1),
            "cut at {index} must still land on the old bank");
        assert_eq!(mock.running(), BankId::Bank1, "cut at {index}");
        // The safety invariant for a rejected image: the NVCNT is never bumped and
        // the unhealthy new bank is never confirmed.
        assert_eq!(mock.nvcnt, 3, "cut at {index}: no bump on the revert path");
        assert_eq!(mock.pending, PendingFlag::None, "cut at {index}");
    }
}

#[test]
fn revert_survives_an_interrupted_reset()
{
    // Model a cut during the option load: the swap is armed but the reset does not
    // apply it (reboot without apply_reset). The new bank still runs, unhealthy,
    // so the boot re-arms the revert. A later completed reset lands on the old
    // bank. The NVCNT never bumps and the new bank never confirms.
    let mut mock = revert_scenario();

    // First pass arms the revert.
    assert_eq!(boot_once(&mut mock), BootOutcome::Reverted);
    // The reset is interrupted: the staged swap is not applied.
    mock.staged_swap = None;
    assert_eq!(mock.running(), BankId::Bank2, "still on the new bank");
    assert_eq!(mock.nvcnt, 3);

    // A subsequent clean boot re-arms and, on a completed reset, recovers.
    let outcome = drive_to_stable(&mut mock);
    assert_eq!(outcome, BootOutcome::HandOff(BankId::Bank1));
    assert_eq!(mock.running(), BankId::Bank1);
    assert_eq!(mock.nvcnt, 3, "never bumped across the interrupted reset");
}

#[test]
fn steady_state_boot_mutates_nothing()
{
    // A confirmed, healthy bank with a matching NVCNT boots with no persistent
    // write at all (no burn, no wear).
    let mut mock = MockBootFlash::confirmed(
        false,
        BankImage::healthy(4, 20),
        BankImage::erased(),
        4,
    );
    assert_eq!(boot_once(&mut mock), BootOutcome::HandOff(BankId::Bank1));
    assert_eq!(mock.mutations, 0, "steady-state boot writes nothing");
    assert_eq!(mock.nvcnt, 4);
    assert_eq!(mock.pending, PendingFlag::None);
}

#[test]
fn confirmed_but_dead_running_bank_wedges()
{
    let mut mock = MockBootFlash::confirmed(
        false,
        BankImage::erased(),
        BankImage::healthy(3, 20),
        3,
    );
    assert_eq!(boot_once(&mut mock),
        BootOutcome::Wedge(WedgeReason::NoBootableImage));
}
