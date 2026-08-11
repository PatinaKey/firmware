//! The machine-checked power-fault campaign, over the REAL flash driver.
//!
//! This is the register-level successor to the retired seam-level fw-update
//! harness. It drives the `fw-update` [`fw_update::Updater`] through its public
//! API over [`Stm32FlashSeam`] backed by the faithful [`FlashModel`], and injects
//! a power cut at every persistent flash operation the driver issues, across the
//! modelled reset boundary. So each injected cut hits the real driver code (the
//! unlock / program / poll / lock sequencing and the physical-bank addressing)
//! over the register-level model, which the seam-level harness never exercised.
//!
//! # A single global cut index that survives the reset
//!
//! [`FlashModel`] carries the armed cut countdown in its non-volatile state, and a
//! modelled reset ([`FlashModel::apply_reset`]) clears only the volatile
//! controller state, so the countdown rides across the reset. A cut can therefore
//! fire at the flash ops around the post-reset confirm (the pending clear and the
//! NVCNT bump done last) or revert (the reverse-swap arm and the pending clear)
//! path, exactly the most safety-critical orderings. The SE spend is a
//! `SeCounterSeam` op, not a flash op, so it lies outside this flash-cut index
//! domain, and its interruption is proven by the dedicated channel-drop test.
//! Every persistent op is a quad-word program, a page erase, or an option-byte
//! stage, so the cut index walks each one.
//!
//! # The per-index census
//!
//! The campaign measures the confirm and revert flow lengths, then arms a cut at
//! every index of both, over both option-load-at-reset outcomes and all three cut
//! modes. It records which index fired and asserts every reachable index fired at
//! least once, which is the check that catches a cut span with a gap.
//!
//! # Two physically separate banks, real bytes
//!
//! [`FlashModel`] holds two physical bank stores. The old bank (physical Bank 1)
//! is seeded with a valid signed image in the exact de-interleaved layout the
//! driver writes, and the invariant reads the model's real old-bank bytes back
//! (never a rebuilt copy), so the old-bank-bootable assertion cannot pass
//! vacuously. The revert direction is modelled at the SWAP_BANK bit level, and the
//! harness asserts which physical bank boots after the modelled reset by reading
//! the real option state.

#![cfg(test)]

extern crate alloc;

use alloc::rc::Rc;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::RefCell;

use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::Signer;

use fw_update::FlashSeam;
use fw_update::PendingFlag;
use fw_update::SeCounterError;
use fw_update::SeCounterSeam;
use fw_update::UpdateState;
use fw_update::Updater;

use image_verify::HEADER_LEN;
use image_verify::ImageVersion;
use image_verify::ROOT_KEY_LEN;
use image_verify::RootKey;
use image_verify::SIG_LEN;
use image_verify::encode_header;
use image_verify::verify_image;

use crate::bus::FlashAccess;
use crate::driver::Stm32FlashSeam;
use crate::model::CutMode;
use crate::model::FlashModel;
use crate::regs;

// The image security counters. The OLD bank and the stored NVCNT start below the
// new image counter, so the update is a forward step, not a downgrade.
const OLD_BANK_COUNTER: u32 = 4;
const NEW_IMAGE_COUNTER: u32 = 5;
const BASELINE_NVCNT: u32 = 4;

// An SE counter value whose derived anti-rollback floor equals the new image
// counter, so Gate 2 accepts the forward step (floor = ORIGIN - value).
const SE_AT_FLOOR: u32 = fw_update::SE_COUNTER_ORIGIN - NEW_IMAGE_COUNTER;

// A small payload for the census, so the persistent-op count stays bounded and
// each flow is fast. A larger payload for the torn-page test, so a full page
// flushes during receive where the tear lands.
const OLD_PAYLOAD: &[u8] = b"old firmware payload v1..";
const NEW_PAYLOAD: &[u8] = b"new firmware payload bytes for the a/b census";

// The number of erase ops erase_inactive issues (image pages 9..31 of the
// inactive bank), so the torn-page test can arm at the first payload program.
const ERASE_OPS: u32 = regs::PAGES_PER_BANK - regs::IMAGE_PAGE_FIRST;

// The dev private scalar, test only. A publicly known, hardcoded key that makes
// every fixture deterministic. The all-0x01 value is a valid P-256 scalar:
// non-zero, and far below the curve order, which starts with 0xFF.
const DEV_SCALAR: [u8; 32] = [1u8; 32];

/// Which recovery branch the post-reset boot drives once the swap took effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Health
{
    /// The new bank is healthy, so on_boot reaches AwaitingConfirm and confirm is
    /// driven. The flash cut can hit the confirm flash ops (the pending clear and
    /// the NVCNT bump done last). The SE spend is a separate `SeCounterSeam` op,
    /// outside the flash-cut domain, proven by the dedicated channel-drop test.
    Confirm,
    /// The new bank failed its health check, so revert is driven instead (the
    /// reverse-swap arm, the pending clear).
    Revert,
}

/// A shared handle to the FLASH-controller model.
///
/// [`Updater::new`] takes the seam by value, so the harness keeps a clone of this
/// `Rc` to arm the cut, inspect the backing flash, and model a reboot by building
/// a fresh driver over the same model. `RefCell` gives the `&mut self` borrow each
/// [`FlashAccess`] call needs from behind the shared handle.
#[derive(Clone)]
struct Shared
{
    model: Rc<RefCell<FlashModel>>,
}

impl Shared
{
    fn new() -> Shared
    {
        Shared
        {
            model: Rc::new(RefCell::new(FlashModel::new())),
        }
    }
}

impl FlashAccess for Shared
{
    fn read32(&mut self, addr: u32) -> u32
    {
        self.model.borrow_mut().read32(addr)
    }

    fn write32(&mut self, addr: u32, value: u32)
    {
        self.model.borrow_mut().write32(addr, value);
    }

    fn peek32(&self, addr: u32) -> u32
    {
        self.model.borrow_mut().read32(addr)
    }

    fn bank_view(&self, base: u32, len: usize) -> &[u8]
    {
        // Resolve the band read through the model (RM0456 sec 7.5.8 swap mapping
        // plus RM0456 Table 68 RAZ on a wrong-alias read), then return the
        // equivalent borrow. This mirrors the machine-integration double.
        let model = self.model.borrow();
        let (ptr, start, end) = match model.band_ptr(base, len)
        {
            Some(triple) => triple,
            None => return &[],
        };
        // Drop the Ref now that the stable store address is captured. The bytes
        // outlive `&self` because the Rc keeps the model alive and each store (and
        // the RAZ buffer) is a boxed array whose address is stable for the model's
        // life.
        drop(model);
        // SAFETY: this is a TEST double, the host analogue of memory-mapped flash,
        // not the production MMIO port. `ptr` is one of the model's boxed bank
        // arrays or its RAZ buffer, kept alive by the Rc the harness still holds,
        // with a stable address for the model's life. The range `start..end` is
        // clamped inside that array span by `band_ptr`, the bytes are plain `u8`.
        // The returned slice is fully consumed before any other handle is touched,
        // and the borrowed bytes are immutable flash during the verifying read.
        #[allow(unsafe_code)]
        unsafe
        {
            core::slice::from_raw_parts(ptr.add(start), end - start)
        }
    }
}

/// A local secure-element counter double for the census (no drop switch).
///
/// Models the TROPIC01 MCounter abstractly: it counts DOWN from a provisioned
/// origin and [`SeCounterSeam::update`] decrements it. The census rebuilds it per
/// boot, matching the retired harness, so the flash invariants are what the
/// census proves. SE persistence is proven by the dedicated SE-spend test.
struct LocalSeCounter
{
    value: u32,
}

impl LocalSeCounter
{
    fn new(value: u32) -> LocalSeCounter
    {
        LocalSeCounter { value }
    }
}

impl SeCounterSeam for LocalSeCounter
{
    fn read(&mut self) -> Result<u32, SeCounterError>
    {
        Ok(self.value)
    }

    fn update(&mut self) -> Result<(), SeCounterError>
    {
        self.value = self
            .value
            .checked_sub(1)
            .ok_or(SeCounterError::Exhausted)?;
        Ok(())
    }
}

/// A persistent secure-element counter with a one-shot channel-drop switch.
///
/// The value persists across modelled boots (the `Rc`), so the SE-spend test can
/// prove a dropped spend on one boot does not double-spend on the next.
#[derive(Clone)]
struct SharedSe
{
    inner: Rc<RefCell<SeState>>,
}

struct SeState
{
    value: u32,
    updated: bool,
    drop_next: bool,
}

impl SharedSe
{
    fn new(value: u32) -> SharedSe
    {
        SharedSe
        {
            inner: Rc::new(RefCell::new(SeState
            {
                value,
                updated: false,
                drop_next: false,
            })),
        }
    }

    fn arm_drop(&self)
    {
        self.inner.borrow_mut().drop_next = true;
    }

    fn value(&self) -> u32
    {
        self.inner.borrow().value
    }

    fn updated(&self) -> bool
    {
        self.inner.borrow().updated
    }
}

impl SeCounterSeam for SharedSe
{
    fn read(&mut self) -> Result<u32, SeCounterError>
    {
        Ok(self.inner.borrow().value)
    }

    fn update(&mut self) -> Result<(), SeCounterError>
    {
        let mut state = self.inner.borrow_mut();
        if state.drop_next
        {
            // The channel dropped during the spend. The counter does not
            // decrement, so the next boot reads the same value and retries.
            state.drop_next = false;
            return Err(SeCounterError::Unavailable);
        }
        state.value = state
            .value
            .checked_sub(1)
            .ok_or(SeCounterError::Exhausted)?;
        state.updated = true;
        Ok(())
    }
}

// The signing key of the dev scalar.
fn dev_signing_key() -> SigningKey
{
    SigningKey::from_slice(&DEV_SCALAR).expect("the dev scalar is in [1, n-1]")
}

// Builds a HEADER || payload || signature image signed with the dev scalar, using
// the image-verify encode feature so the layout has a single source of truth. The
// signature is normalized to low-s, the only encoding the verifier accepts.
fn dev_image(security_counter: u32, payload: &[u8]) -> Vec<u8>
{
    let version = ImageVersion
    {
        major: 1,
        minor: 0,
        revision: 0,
        build: 0,
    };
    let header = encode_header(version, security_counter, payload.len() as u32);
    let mut signed = Vec::new();
    signed.extend_from_slice(&header);
    signed.extend_from_slice(payload);
    let sig: p256::ecdsa::Signature = dev_signing_key().sign(&signed);
    let sig = sig.normalize_s();
    let mut image = signed;
    image.extend_from_slice(&sig.to_bytes());
    image
}

// The dev root key, derived from the dev scalar, so this crate carries no second
// copy of a key constant to drift.
fn dev_root() -> RootKey
{
    let point = dev_signing_key().verifying_key().to_sec1_point(false);
    let mut bytes = [0u8; ROOT_KEY_LEN];
    bytes.copy_from_slice(point.as_ref());
    RootKey::from_bytes(bytes).expect("the derived dev root key is on-curve")
}

// Seeds a physical bank store with a signed image in the exact de-interleaved
// layout the driver writes: the header into the descriptor page [0:24], the
// signature into the descriptor [24:88], and the payload into the payload band
// from offset 0. The seeding is bank-relative and alias-independent, so it holds
// across a swap. Assumes the payload fits the secure sub-band (true for the small
// census images), so the whole payload lands contiguously at the payload offset.
fn seed_bank_image(model: &mut FlashModel, bank2: bool, image: &[u8])
{
    let payload_len = image.len() - HEADER_LEN - SIG_LEN;
    let descriptor = regs::IMAGE_DESCRIPTOR_OFFSET as usize;
    let payload = regs::IMAGE_PAYLOAD_OFFSET as usize;
    for (i, byte) in image[..HEADER_LEN].iter().enumerate()
    {
        model.poke_phys(bank2, descriptor + i, *byte);
    }
    let sig = &image[HEADER_LEN + payload_len..];
    for (i, byte) in sig.iter().enumerate()
    {
        model.poke_phys(bank2, descriptor + HEADER_LEN + i, *byte);
    }
    for (i, byte) in image[HEADER_LEN..HEADER_LEN + payload_len].iter().enumerate()
    {
        model.poke_phys(bank2, payload + i, *byte);
    }
}

// Reassembles the de-interleaved image out of a physical bank store and verifies
// it against the root key. Reads the model's real bytes (never a rebuilt copy),
// so a passing verify proves the store actually holds a bootable image.
fn bank_verifies
(
    model: &FlashModel,
    bank2: bool,
    payload_len: usize,
    root: &RootKey,
)
    -> bool
{
    let descriptor = regs::IMAGE_DESCRIPTOR_OFFSET as usize;
    let payload = regs::IMAGE_PAYLOAD_OFFSET as usize;
    let mut header = Vec::with_capacity(HEADER_LEN);
    let mut sig = Vec::with_capacity(SIG_LEN);
    let mut body = Vec::with_capacity(payload_len);
    for i in 0..HEADER_LEN
    {
        match model.phys_byte(bank2, descriptor + i)
        {
            Some(byte) => header.push(byte),
            None => return false,
        }
    }
    for i in 0..SIG_LEN
    {
        match model.phys_byte(bank2, descriptor + HEADER_LEN + i)
        {
            Some(byte) => sig.push(byte),
            None => return false,
        }
    }
    for i in 0..payload_len
    {
        match model.phys_byte(bank2, payload + i)
        {
            Some(byte) => body.push(byte),
            None => return false,
        }
    }
    let segments: [&[u8]; 3] = [&header, &body, &sig];
    verify_image(&segments, root).is_ok()
}

// Builds a fresh model seeded with the old bank image (physical Bank 1) plus the
// baseline NVCNT, both poked physically so the seeding never ticks the cut
// counter. The inactive bank (physical Bank 2) stays erased.
fn seeded_shared(old_image: &[u8]) -> Shared
{
    let shared = Shared::new();
    {
        let mut model = shared.model.borrow_mut();
        seed_bank_image(&mut model, false, old_image);
        // Seed the NVCNT log slot 0 directly, so the seeding does not count as a
        // persistent op (the census length must reflect only the flow).
        let base = regs::META_NVCNT_OFFSET as usize;
        for (i, byte) in BASELINE_NVCNT.to_le_bytes().iter().enumerate()
        {
            model.poke_phys(false, base + i, *byte);
        }
    }
    shared
}

// Reads the pending record through a fresh probe driver (a read, no mutation).
fn pending_of(shared: &Shared) -> PendingFlag
{
    let mut probe = Stm32FlashSeam::new(shared.clone());
    probe.pending_read().expect("pending read")
}

// Reads the NVCNT through a fresh probe driver.
fn nvcnt_of(shared: &Shared) -> u32
{
    let mut probe = Stm32FlashSeam::new(shared.clone());
    probe.nvcnt_read().expect("nvcnt read")
}

// Streams the image through the public receive API in small chunks, in order.
// Stops and returns the error on the first faulted chunk.
fn stream_chunks(up: &mut CensusUpdater<'_>, image: &[u8]) -> bool
{
    let mut offset = 0usize;
    for chunk in image.chunks(13)
    {
        if up.receive_chunk(offset, chunk).is_err()
        {
            return false;
        }
        offset += chunk.len();
    }
    true
}

// Convenience alias for the concrete Updater the census drives: the real driver
// over the shared FLASH-controller model, so the injected cuts hit the real
// driver code.
type CensusUpdater<'k> = Updater<'k, Stm32FlashSeam<Shared>, LocalSeCounter>;

// The settled result of driving one flow.
struct FlowOutcome
{
    shared: Shared,
    fired: bool,
    ops: u32,
}

// Drives the whole flow under an optional single global cut.
//
// Segment 1 runs begin -> receive -> accept -> commit with the cut armed. The cut
// countdown that survives rides in the model. `reset_applied` models the
// option-load-at-reset window: true applies the staged swap atomically (RM0456
// sec 7.5.8), false models a cut before the option load committed, dropping the
// stage so the old bank boots. After the reset the harness reboots repeatedly,
// running on_boot recovery and driving confirm or revert by `health`, until the
// state settles.
fn run_flow
(
    root: &RootKey,
    old_image: &[u8],
    new_image: &[u8],
    cut: Option<(u32, CutMode)>,
    reset_applied: bool,
    health: Health,
)
    -> FlowOutcome
{
    let shared = seeded_shared(old_image);
    if let Some((index, mode)) = cut
    {
        shared.model.borrow_mut().arm_cut(index, mode);
    }

    {
        let se = LocalSeCounter::new(SE_AT_FLOOR);
        let driver = Stm32FlashSeam::new(shared.clone());
        let mut up: CensusUpdater = Updater::new(root, driver, se);

        // Stream and accept. Any error here is the cut firing during erase, a page
        // write, a descriptor write, or a read, which collapses the machine
        // fail-closed.
        let accepted = up.begin(new_image.len()).is_ok()
            && stream_chunks(&mut up, new_image)
            && up.verify_and_accept().is_ok();
        // Commit the swap if accepted. A cut here leaves the staged swap either
        // set or not, which the modelled reset resolves.
        let _committed = accepted && up.commit().is_ok();
        // Drop the volatile updater and its driver: this is the reboot. The model
        // persists in the Rc.
    }

    // Model the option-load-at-reset window (RM0456 sec 7.5.8).
    if reset_applied
    {
        shared.model.borrow_mut().apply_reset();
    }
    else
    {
        shared.model.borrow_mut().reboot_without_option_load();
    }

    drive_recovery(root, &shared, health);

    let fired = shared.model.borrow().cut_fired();
    let ops = shared.model.borrow().persistent_ops();
    FlowOutcome
    {
        shared,
        fired,
        ops,
    }
}

// Reboots repeatedly from the surviving model until the state settles, driving
// on_boot recovery and then confirm or revert by `health` on each boot. A cut that
// survived into the post-reset segment fires inside one of these boots and faults
// the recovery mid-way. The next boot runs on fresh silicon (the reset cleared the
// dead flag, the cut is spent) and retries, so the loop runs until the state
// reaches a fixed point with no staged swap and no pending record.
fn drive_recovery(root: &RootKey, shared: &Shared, health: Health)
{
    let mut guard = 0u32;
    loop
    {
        guard += 1;
        assert!(guard < 32, "recovery must settle in a bounded number of boots");

        // Each boot after the first applies the staged option load atomically: a
        // reboot is a reset. The caller resolved the first reset.
        if guard > 1
        {
            shared.model.borrow_mut().apply_reset();
        }

        let ops_before = shared.model.borrow().persistent_ops();
        {
            let se = LocalSeCounter::new(SE_AT_FLOOR);
            let driver = Stm32FlashSeam::new(shared.clone());
            let mut up: CensusUpdater = Updater::new(root, driver, se);
            if let Ok(UpdateState::AwaitingConfirm) = up.on_boot()
            {
                match health
                {
                    Health::Confirm =>
                    {
                        let _ = up.confirm(NEW_IMAGE_COUNTER);
                    }
                    Health::Revert =>
                    {
                        let _ = up.revert();
                    }
                }
            }
        }

        let quiescent = shared.model.borrow().staged_swap().is_none()
            && pending_of(shared) == PendingFlag::None;
        let ops_after = shared.model.borrow().persistent_ops();
        // Settled once no swap is staged, no record dangles, and a full clean boot
        // cycle issued no persistent op (a functional fixed point).
        if quiescent && ops_after == ops_before
        {
            break;
        }
    }
}

/// The end-to-end disposition of a settled flow, decided from its intended health
/// branch and the real physical boot bank.
///
/// A [`Health::Revert`] flow must always settle back on the old bank. A
/// [`Health::Confirm`] flow settles [`Settled::Confirmed`] on the new bank once the
/// swap is confirmed end to end, and on the old bank when a cut kept it from ever
/// confirming. Deciding the required bank from the disposition, not from the raw
/// boot bank alone, is what restores the retired seam-level harness's per-health
/// outcome parity, so a revert that erroneously ends confirmed on the new bank
/// fails the census instead of passing as "whatever boots verifies".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Settled
{
    /// The old bank (physical Bank 1) must boot: the swap was never confirmed.
    OldBank,
    /// The new bank (physical Bank 2) must boot: the swap was confirmed end to end.
    Confirmed,
}

// Decides the settled disposition from the health branch and the real boot bank. A
// confirmed swap requires the Confirm branch and the new bank actually booting.
// Every revert flow, and any confirm flow a cut kept from confirming, is OldBank.
// The pending record is already proven None by the caller, so the disposition
// turns on the health branch and the boot bank alone.
fn settled_disposition(health: Health, boots_new: bool) -> Settled
{
    if health == Health::Confirm && boots_new
    {
        Settled::Confirmed
    }
    else
    {
        Settled::OldBank
    }
}

// Asserts the safety invariant on a settled model, given the flow's health branch
// and the OLD and NEW image payload lengths.
//
// (a) the old bank stays bootable until a swap is confirmed, and a revert flow
//     always returns to the old bank,
// (b) the booting bank always verifies and an unverified image never boots,
// (c) the NVCNT never rises above the security counter of the bank that boots,
// (d) no settled state leaves a staged swap or a dangling pending record.
//
// The expected physical bank is required per disposition (see settled_disposition),
// not merely read off the model, so a Revert flow that ends confirmed on the new
// bank fails here rather than passing as "whatever bank boots verifies".
fn assert_invariants
(
    shared: &Shared,
    old_pl: usize,
    new_pl: usize,
    root: &RootKey,
    health: Health,
)
{
    // (d) No swap may be left staged and no pending record may dangle.
    assert_eq!(
        shared.model.borrow().staged_swap(),
        None,
        "no staged swap may survive a settled recovery"
    );
    assert_eq!(
        pending_of(shared),
        PendingFlag::None,
        "no pending record may survive a settled recovery"
    );

    // Capture the boot bank and the NVCNT through scoped borrows first, so no
    // shared borrow of the model is held while a probe driver takes a mutable one.
    let boots_new = shared.model.borrow().boots_bank2();
    let nvcnt = nvcnt_of(shared);
    let settled = settled_disposition(health, boots_new);

    match settled
    {
        Settled::Confirmed =>
        {
            // The confirm flow reached an end-to-end confirmed swap, so the new
            // bank (physical Bank 2) must boot.
            assert!(boots_new, "a confirmed swap must boot the NEW bank");
            // (b) The booting bank must verify, read from the real store.
            let verified = bank_verifies(&shared.model.borrow(), true, new_pl, root);
            assert!(verified, "the confirmed NEW bank bytes must verify");
            // (c) NVCNT never above the booting bank counter.
            assert!(
                nvcnt <= NEW_IMAGE_COUNTER,
                "NVCNT must not exceed the booting bank counter"
            );
        }
        Settled::OldBank =>
        {
            // A revert flow, or a confirm flow a cut kept from confirming, so the
            // old bank (physical Bank 1) must boot. A wrong-direction revert that
            // left the new bank booting fails this assertion, restoring the retired
            // harness's per-health outcome check across every cut index.
            assert!(
                !boots_new,
                "an unconfirmed or reverted flow must boot the OLD bank"
            );
            // (b) The OLD bank bytes in the MODEL must still verify (non-vacuous:
            // these are the actual seeded bytes, never a rebuilt copy).
            let verified = bank_verifies(&shared.model.borrow(), false, old_pl, root);
            assert!(verified, "the OLD bank bytes must still verify");
            // (c) No Gate-1 poisoning: an unconfirmed update must not raise NVCNT
            // above the OLD bank counter.
            assert!(
                nvcnt <= OLD_BANK_COUNTER,
                "NVCNT must not rise above the OLD bank on an unconfirmed update"
            );
        }
    }
}

const CUT_MODES: [CutMode; 3] =
[
    CutMode::BeforeMutation,
    CutMode::AfterMutation,
    CutMode::TornWrite,
];
const RESET_OUTCOMES: [bool; 2] = [true, false];
const HEALTHS: [Health; 2] = [Health::Confirm, Health::Revert];

/// One census point: a cut index, the mode it fires in, and the reset and health
/// branch the flow takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CensusCase
{
    index: u32,
    mode: CutMode,
    reset_applied: bool,
    health: Health,
}

// Enumerates the census input space as one flat iterator: every cut mode, both
// option-load-at-reset outcomes, both health branches, and every persistent-op
// index below `n`. The index varies fastest, matching the flow order the census
// walks.
fn census_cases(n: u32) -> impl Iterator<Item = CensusCase>
{
    CUT_MODES
        .into_iter()
        .flat_map(|mode|
        {
            RESET_OUTCOMES
                .into_iter()
                .map(move |reset_applied| (mode, reset_applied))
        })
        .flat_map(|(mode, reset_applied)|
        {
            HEALTHS
                .into_iter()
                .map(move |health| (mode, reset_applied, health))
        })
        .flat_map(move |(mode, reset_applied, health)|
        {
            (0..n).map(move |index| CensusCase
            {
                index,
                mode,
                reset_applied,
                health,
            })
        })
}

// Marks the index whose cut fired and returns how many cuts to add to the tally.
fn record_fired(fired_seen: &mut [bool], index: u32, fired: bool) -> u32
{
    if !fired
    {
        return 0;
    }
    if let Some(slot) = fired_seen.get_mut(index as usize)
    {
        *slot = true;
    }
    1
}

// Asserts the enumerated census cases are pairwise distinct. A count pin alone
// still passes when an axis is rewritten to repeat one value, which holds the
// total while dropping the branch that axis exists to cover.
fn assert_cases_are_distinct(cases: &[CensusCase])
{
    for (i, a) in cases.iter().enumerate()
    {
        for b in cases.iter().skip(i + 1)
        {
            assert_ne!(a, b, "the census axes must enumerate distinct cases");
        }
    }
}

// Asserts every persistent-op index fired at least once across the census. This
// is the check that proves the cut spans the whole flow, including the post-reset
// confirm and revert mutations.
fn assert_every_index_fired(fired_seen: &[bool])
{
    for (idx, seen) in fired_seen.iter().enumerate()
    {
        assert!(
            *seen,
            "persistent op index {idx} never fired, the cut span has a gap"
        );
    }
}

#[test]
fn exhaustive_power_fault_interleavings_hold_the_invariant()
{
    let root = dev_root();
    let old_image = dev_image(OLD_BANK_COUNTER, OLD_PAYLOAD);
    let new_image = dev_image(NEW_IMAGE_COUNTER, NEW_PAYLOAD);
    let old_pl = OLD_PAYLOAD.len();
    let new_pl = NEW_PAYLOAD.len();

    // Measure each health branch's flow length with a clean run (no cut). The
    // longer branch defines the census index range, and its ops are contiguous
    // indices 0..len, so arming each index there fires.
    let confirm_len =
        run_flow(&root, &old_image, &new_image, None, true, Health::Confirm).ops;
    let revert_len =
        run_flow(&root, &old_image, &new_image, None, true, Health::Revert).ops;
    let n = confirm_len.max(revert_len);
    assert!(n > ERASE_OPS, "the flow must reach past the inactive-bank erase");
    assert_eq!(n, 38, "the flow length changed, re-review the census");

    let cases: Vec<CensusCase> = census_cases(n).collect();
    let total = cases.len() as u32;
    let mut fired_seen = vec![false; n as usize];
    let mut fired_count = 0u32;

    for case in cases.iter().copied()
    {
        let out = run_flow(
            &root,
            &old_image,
            &new_image,
            Some((case.index, case.mode)),
            case.reset_applied,
            case.health,
        );
        assert_invariants(&out.shared, old_pl, new_pl, &root, case.health);
        fired_count += record_fired(&mut fired_seen, case.index, out.fired);
    }

    assert_eq!(total, 12 * n, "every axis combination must be exercised");
    assert_cases_are_distinct(&cases);

    assert_every_index_fired(&fired_seen);

    std::eprintln!(
        "register-level power-fault harness: {total} interleavings exercised, \
         {fired_count} cuts fired, every one of {n} persistent-op indices fired \
         at least once over the real driver"
    );
    assert!(fired_count > 0, "at least one cut must have fired");
}

#[test]
fn rejected_image_never_commits_at_any_cut()
{
    // Stream an image with a bad signature, drive the full flow with a cut at
    // every index in every mode, and assert it never reaches a confirmed swap and
    // the old bank always boots.
    let root = dev_root();
    let old_image = dev_image(OLD_BANK_COUNTER, OLD_PAYLOAD);
    let mut bad_image = dev_image(NEW_IMAGE_COUNTER, NEW_PAYLOAD);
    // Flip a byte inside the trailing signature so the ECDSA check fails at the
    // signature, not on a structural error. The low half of the s scalar keeps
    // the signature low-s and well-formed.
    let last = bad_image.len() - 1;
    bad_image[last] ^= 0x01;
    let self_check: [&[u8]; 1] = [&bad_image];
    assert_eq!(
        verify_image(&self_check, &root),
        Err(image_verify::VerifyError::BadSignature),
        "the rejected fixture must fail at the signature check"
    );

    let old_pl = OLD_PAYLOAD.len();
    // A rejected flow never commits, so its length is bounded by the confirm flow.
    let n = run_flow(&root, &old_image, &bad_image, None, true, Health::Confirm).ops;

    for mode in CUT_MODES
    {
        for reset_applied in RESET_OUTCOMES
        {
            for k in 0..n
            {
                let out = run_flow(
                    &root,
                    &old_image,
                    &bad_image,
                    Some((k, mode)),
                    reset_applied,
                    Health::Confirm,
                );
                // The image never verifies, so the swap is never confirmed.
                assert!(
                    !out.shared.model.borrow().boots_bank2(),
                    "a rejected image must never boot the NEW bank"
                );
                // The OLD bank still boots and still verifies.
                assert!(
                    bank_verifies(&out.shared.model.borrow(), false, old_pl, &root),
                    "the OLD bank bytes must still verify after a rejection"
                );
                // No swap staged, no record dangling, NVCNT never raised.
                assert_eq!(out.shared.model.borrow().staged_swap(), None);
                assert_eq!(pending_of(&out.shared), PendingFlag::None);
                assert!(
                    nvcnt_of(&out.shared) <= OLD_BANK_COUNTER,
                    "a rejected image must not bump NVCNT"
                );
            }
        }
    }
}

#[test]
fn reset_after_clean_commit_boots_new_bank_and_confirms()
{
    // A clean run with no cut: commit stages the swap, the modelled reset applies
    // it atomically, on_boot owes a confirm, confirm completes. Proves the
    // confirmed new bank store verifies and the NVCNT bumped last.
    let root = dev_root();
    let old_image = dev_image(OLD_BANK_COUNTER, OLD_PAYLOAD);
    let new_image = dev_image(NEW_IMAGE_COUNTER, NEW_PAYLOAD);
    let out = run_flow(
        &root,
        &old_image,
        &new_image,
        None,
        true,
        Health::Confirm,
    );
    assert!(out.shared.model.borrow().boots_bank2(), "the NEW bank boots");
    assert!(
        bank_verifies(&out.shared.model.borrow(), true, NEW_PAYLOAD.len(), &root),
        "the confirmed NEW bank bytes verify"
    );
    assert_eq!(nvcnt_of(&out.shared), NEW_IMAGE_COUNTER, "NVCNT bumped last");
    assert_eq!(pending_of(&out.shared), PendingFlag::None, "record cleared");
}

#[test]
fn revert_returns_to_old_bank_and_leaves_no_dangling_stage()
{
    // Drive the revert branch: on_boot reaches AwaitingConfirm, the health check
    // fails, so revert is driven. After a revert the OLD physical bank boots again
    // and no staged swap dangles toward the unverified bank.
    let root = dev_root();
    let old_image = dev_image(OLD_BANK_COUNTER, OLD_PAYLOAD);
    let new_image = dev_image(NEW_IMAGE_COUNTER, NEW_PAYLOAD);
    let out = run_flow(
        &root,
        &old_image,
        &new_image,
        None,
        true,
        Health::Revert,
    );
    assert!(
        !out.shared.model.borrow().boots_bank2(),
        "the OLD physical bank boots after a revert"
    );
    assert!(
        bank_verifies(&out.shared.model.borrow(), false, OLD_PAYLOAD.len(), &root),
        "the OLD bank bytes still verify after a revert"
    );
    assert_eq!(nvcnt_of(&out.shared), OLD_BANK_COUNTER, "NVCNT not bumped");
    assert_eq!(out.shared.model.borrow().staged_swap(), None, "no dangling stage");
    assert_eq!(pending_of(&out.shared), PendingFlag::None, "record cleared");
}

#[test]
fn cut_before_swap_reset_keeps_old_bank()
{
    // The swap is staged but the option load never commits (a cut before the
    // reset). The OLD bank still boots and still verifies.
    let root = dev_root();
    let old_image = dev_image(OLD_BANK_COUNTER, OLD_PAYLOAD);
    let new_image = dev_image(NEW_IMAGE_COUNTER, NEW_PAYLOAD);
    let out = run_flow(
        &root,
        &old_image,
        &new_image,
        None,
        false,
        Health::Confirm,
    );
    assert!(
        !out.shared.model.borrow().boots_bank2(),
        "a lost option load keeps the OLD bank booting"
    );
    assert!(
        bank_verifies(&out.shared.model.borrow(), false, OLD_PAYLOAD.len(), &root),
        "the OLD bank bytes still verify"
    );
    assert_eq!(pending_of(&out.shared), PendingFlag::None, "record cleared on boot");
}

#[test]
fn torn_page_write_makes_bank_fail_verify()
{
    // A torn quad-word during a payload page write poisons that quad-word, so the
    // inactive bank fails verify and no swap is armed. The OLD bank is untouched.
    let root = dev_root();
    let old_image = dev_image(OLD_BANK_COUNTER, OLD_PAYLOAD);
    // A payload larger than one page, so a full page flushes during receive where
    // the tear lands, not only at accept.
    let big_payload = vec![0xCDu8; 3 * fw_update::PAGE_LEN];
    let new_image = dev_image(NEW_IMAGE_COUNTER, &big_payload);

    let shared = seeded_shared(&old_image);
    // Arm a torn write at the first payload program (index ERASE_OPS, just past
    // the inactive-bank erase).
    shared.model.borrow_mut().arm_cut(ERASE_OPS, CutMode::TornWrite);

    let se = LocalSeCounter::new(SE_AT_FLOOR);
    let driver = Stm32FlashSeam::new(shared.clone());
    let mut up: CensusUpdater = Updater::new(&root, driver, se);
    up.begin(new_image.len()).expect("begin");

    // The torn write faults the page write during receive, collapsing the
    // transfer fail-closed.
    let streamed = stream_chunks(&mut up, &new_image);
    assert!(!streamed, "the torn payload write must fault the transfer");
    assert!(shared.model.borrow().cut_fired(), "the tear fired");
    assert_ne!(up.state(), UpdateState::Committed);
    assert_eq!(shared.model.borrow().staged_swap(), None, "no swap staged");
    drop(up);

    // The inactive bank (physical Bank 2) fails verify: the tear poisoned it.
    assert!(
        !bank_verifies(&shared.model.borrow(), true, big_payload.len(), &root),
        "the poisoned inactive bank must fail verify"
    );
    // The OLD bank store (physical Bank 1) is untouched and still bootable.
    assert!(
        bank_verifies(&shared.model.borrow(), false, OLD_PAYLOAD.len(), &root),
        "the OLD bank store must be untouched by an inactive-bank tear"
    );
}

#[test]
fn se_spend_interrupted_does_not_double_spend_or_strand()
{
    // Interrupt confirm at the SE spend (the channel drops on se.update), then
    // prove the recovery on the next boot does not double-spend the SE counter and
    // does not strand a half-confirmed state. The machine spends the SE first in
    // confirm, so a drop there leaves the swap committed, the record still Armed,
    // and the NVCNT not yet bumped.
    let root = dev_root();
    let old_image = dev_image(OLD_BANK_COUNTER, OLD_PAYLOAD);
    let new_image = dev_image(NEW_IMAGE_COUNTER, NEW_PAYLOAD);

    let shared = seeded_shared(&old_image);
    let se = SharedSe::new(SE_AT_FLOOR);

    // Run to a clean post-reset AwaitingConfirm state (no flash cut).
    {
        let driver = Stm32FlashSeam::new(shared.clone());
        let mut up = Updater::new(&root, driver, se.clone());
        up.begin(new_image.len()).expect("begin");
        let mut offset = 0usize;
        for chunk in new_image.chunks(13)
        {
            up.receive_chunk(offset, chunk).expect("receive");
            offset += chunk.len();
        }
        up.verify_and_accept().expect("accept");
        up.commit().expect("commit");
    }
    shared.model.borrow_mut().apply_reset();
    assert!(shared.model.borrow().boots_bank2(), "the swap took effect");

    // First confirm boot: arm a channel drop on the SE update. The spend faults.
    se.arm_drop();
    {
        let driver = Stm32FlashSeam::new(shared.clone());
        let mut up = Updater::new(&root, driver, se.clone());
        assert_eq!(up.on_boot().expect("on_boot"), UpdateState::AwaitingConfirm);
        assert!(up.confirm(NEW_IMAGE_COUNTER).is_err(), "the spend faults");
    }
    assert!(!se.updated(), "a dropped SE spend must not decrement the counter");
    assert_eq!(se.value(), SE_AT_FLOOR, "the counter did not decrement");
    // The swap is still committed, the record still Armed, NVCNT not bumped.
    assert!(shared.model.borrow().boots_bank2(), "swap stays committed");
    assert!(
        matches!(pending_of(&shared), PendingFlag::Armed(_)),
        "the confirm-owed record survives a dropped spend"
    );
    assert_eq!(nvcnt_of(&shared), BASELINE_NVCNT, "NVCNT not bumped yet");

    // Next boot, channel up: the recovery re-enters AwaitingConfirm and confirms
    // cleanly. The SE counter spends exactly once (no double spend).
    {
        let driver = Stm32FlashSeam::new(shared.clone());
        let mut up = Updater::new(&root, driver, se.clone());
        assert_eq!(up.on_boot().expect("on_boot"), UpdateState::AwaitingConfirm);
        up.confirm(NEW_IMAGE_COUNTER).expect("confirm");
    }
    assert!(se.updated(), "the recovery spends the SE once");
    assert_eq!(se.value(), SE_AT_FLOOR - 1, "spent exactly once");
    assert!(shared.model.borrow().boots_bank2(), "NEW bank confirmed");
    assert_eq!(pending_of(&shared), PendingFlag::None, "record cleared");
    assert_eq!(nvcnt_of(&shared), NEW_IMAGE_COUNTER, "NVCNT bumped last");
}
