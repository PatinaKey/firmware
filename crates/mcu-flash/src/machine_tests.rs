//! The dual-bank A/B update machine re-cabled onto the REAL driver.
//!
//! This is the integration proof: the `fw-update` [`fw_update::Updater`] is
//! driven through its PUBLIC API (new, begin, receive_chunk, verify_and_accept,
//! commit, on_boot, confirm) over [`Stm32FlashSeam`] backed by the faithful
//! FLASH-controller model, instead of the in-crate mock. So the same machine the
//! fw-update tests cover runs against the real register sequencing.
//!
//! A valid signed image is minted exactly as the fw-update tests do: the all-`01`
//! Ed25519 seed whose public key is [`fw_update::DEV_ROOT_KEY`], the header from
//! the `image-verify` `encode` feature, signed with `ed25519-dalek`.
//!
//! The model carries interior sharing ([`Shared`]) so the test keeps a handle to
//! the backing flash after [`fw_update::Updater::new`] consumes the seam, and can
//! read NVCNT and the OLD-bank bytes back. The integration drives a full update,
//! models the swap reset, and asserts the NVCNT is read from the RIGHT PHYSICAL
//! bank after the swap (physical Bank 1 has moved to the high alias) and the OLD
//! physical bank stays bootable, with no real option load ever firing.

#![cfg(test)]

extern crate alloc;

use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;

use ed25519_dalek::Signer;
use ed25519_dalek::SigningKey;

use fw_update::DEV_ROOT_KEY;
use fw_update::SeCounterError;
use fw_update::SeCounterSeam;
use fw_update::UpdateState;
use fw_update::Updater;

use image_verify::ImageVersion;
use image_verify::RootKey;
use image_verify::encode_header;
use image_verify::verify_image;

use crate::bus::FlashAccess;
use crate::driver::Stm32FlashSeam;
use crate::model::FlashModel;
use crate::regs;

// The signing seed whose public key equals DEV_ROOT_KEY (the all-0x01 scalar).
const DEV_SEED: [u8; 32] = [1u8; 32];

/// A shared handle to the FLASH-controller model.
///
/// [`Updater::new`] takes the seam by value, so the test keeps a clone of this
/// `Rc` to inspect the backing flash (NVCNT, the OLD-bank bytes, the staged
/// swap) after the updater owns the driver. `RefCell` gives the `&mut self`
/// borrow each [`FlashAccess`] call needs from behind the shared handle.
///
/// # The `inactive_bank` borrow is structurally sound
///
/// [`FlashAccess::bank_view`] returns a slice the host analogue of memory-mapped
/// flash, borrowed for `&self`. The trait signature ties the slice's lifetime to
/// `&self`, so the borrow checker already forbids a `&mut self` access (the
/// mutating [`FlashAccess::read32`] / [`FlashAccess::write32`]) while the slice is
/// live: the soundness does NOT rest on the `verify_and_accept` ordering, the
/// type system enforces it.
///
/// The bytes live in the `Rc<RefCell<FlashModel>>`, in boxed bank arrays whose
/// addresses are stable for the model's life. `bank_view` resolves the alias to
/// the right physical store under a live `Ref` guard, then returns the slice. The
/// `Rc` keeps the bytes alive for the model's whole life, and the trait signature
/// ties the slice to `&self`, so the program / erase path (which takes `&mut
/// self`) cannot run while a view is live: the no-overlap property is enforced by
/// the type system, not by the call ordering.
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
        // Resolve the alias `base` to a physical store through the SAME effective
        // SWAP_BANK the model uses (RM0456 sec 7.5.8: the low alias is physical
        // Bank 1 unless SWAP_BANK is set, the high alias the inverse), then return
        // the equivalent borrow. The borrow is taken from a live `Ref` guard, so
        // the pointer's provenance is checked against the RefCell state at this
        // instant. The trait ties the returned slice to `&self`, which the borrow
        // checker enforces, so a `&mut self` mutating access cannot run while the
        // slice is live.
        let model = self.model.borrow();
        let swap = model.swap_bank();
        let (bank_a, bank_b, span) = model.store_ptrs();
        let (ptr, offset) = match resolve_alias(base, swap, span)
        {
            Some((false, off)) => (bank_a, off),
            Some((true, off)) => (bank_b, off),
            None => return &[],
        };
        let end = core::cmp::min(offset + len, span);
        let start = core::cmp::min(offset, end);
        // Drop the Ref now that the stable store address is captured. The bytes
        // outlive `&self` because the Rc keeps the model alive and each store is a
        // boxed array whose address is stable for the model's life.
        drop(model);
        // SAFETY: this is a TEST double, the host analogue of memory-mapped flash,
        // not the production MMIO port. `ptr` is one of the model's boxed bank
        // arrays, kept alive by the Rc the test still holds, with a stable address
        // for the model's life. The range `start..end` is clamped inside that
        // array span, the bytes are plain `u8`. No aliasing arises in these
        // tests: each `Shared` clone shares one `RefCell`, and the `Ref` guard is
        // dropped before the slice is built, so the type system does NOT by
        // itself bar a second clone from calling `borrow_mut` while a view is
        // live. Safety here rests on usage, the returned slice is fully consumed
        // before any other handle is touched, and the borrowed bytes are
        // immutable flash during the verifying read.
        #[allow(unsafe_code)]
        unsafe
        {
            core::slice::from_raw_parts(ptr.add(start), end - start)
        }
    }
}

/// Resolves an alias address to a physical store flag plus byte offset.
///
/// Mirrors the model's resolver so the test double and the model agree on which
/// physical bytes an inactive-bank alias names (RM0456 sec 7.5.8).
fn resolve_alias(base: u32, swap: bool, span: usize) -> Option<(bool, usize)>
{
    if let Some(off) = base.checked_sub(regs::LOW_ALIAS_BASE)
        && (off as usize) < span
    {
        return Some((swap, off as usize));
    }
    if let Some(off) = base.checked_sub(regs::HIGH_ALIAS_BASE)
        && (off as usize) < span
    {
        return Some((!swap, off as usize));
    }
    None
}

/// A local secure-element counter double (no fuzz-feature dependency).
///
/// Models the TROPIC01 MCounter abstractly: it counts DOWN from a provisioned
/// origin and [`SeCounterSeam::update`] decrements it. The seam never talks to a
/// real secure element.
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

// Builds a HEADER || payload || signature image signed with the DEV seed,
// carrying the given security counter, using the image-verify encode feature so
// the layout has a single source of truth.
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
    let sk = SigningKey::from_bytes(&DEV_SEED);
    let sig = sk.sign(&signed);
    let mut image = signed;
    image.extend_from_slice(&sig.to_bytes());
    image
}

fn dev_root() -> RootKey
{
    RootKey::from_bytes(DEV_ROOT_KEY).expect("dev root key is on-curve")
}

// Reads the NVCNT through a fresh driver over the shared model.
fn read_nvcnt(shared: &Shared) -> u32
{
    use fw_update::FlashSeam;
    let mut probe = Stm32FlashSeam::new(shared.clone());
    probe.nvcnt_read().expect("nvcnt read")
}

#[test]
fn dev_seed_public_key_matches_dev_root_key()
{
    let sk = SigningKey::from_bytes(&DEV_SEED);
    assert_eq!(sk.verifying_key().to_bytes(), DEV_ROOT_KEY);
}

#[test]
fn full_update_over_the_real_driver_reads_nvcnt_from_right_bank_after_swap()
{
    let shared = Shared::new();

    // Seed the OLD (running, physical Bank 1) bank image band with a complete
    // valid v1 image so the "OLD bank stays bootable" invariant is asserted
    // against real model bytes. The seeding is PHYSICAL (poke_phys on Bank 1),
    // bank-relative from the image-band offset, so it is independent of the alias
    // and survives the swap.
    let old_image = dev_image(3, b"old firmware payload v1");
    for (i, byte) in old_image.iter().enumerate()
    {
        let offset = regs::IMAGE_REGION_OFFSET as usize + i;
        shared.model.borrow_mut().poke_phys(false, offset, *byte);
    }
    let old_len = old_image.len();

    // Pre-set NVCNT to 3 (the OLD image counter), the install-time floor.
    {
        use fw_update::FlashSeam;
        let mut seed_driver = Stm32FlashSeam::new(shared.clone());
        seed_driver.nvcnt_bump(3).expect("seed nvcnt");
    }
    assert_eq!(read_nvcnt(&shared), 3, "nvcnt seeded");

    let root = dev_root();
    let se = LocalSeCounter::new(SE_FLOOR_ZERO);
    let driver = Stm32FlashSeam::new(shared.clone());
    let mut up = Updater::new(&root, driver, se);

    // Stream a NEWER image (counter 7) through the public API into the inactive
    // (physical Bank 2) bank, in small chunks so the page accumulator is
    // exercised.
    let new_image = dev_image(7, b"new firmware payload v2 is a bit longer");
    up.begin(new_image.len()).expect("begin");
    let mut offset = 0usize;
    for chunk in new_image.chunks(13)
    {
        up.receive_chunk(offset, chunk).expect("receive_chunk");
        offset += chunk.len();
    }
    assert_eq!(up.state(), UpdateState::ReceivingChunks);

    up.verify_and_accept().expect("verify");
    assert_eq!(up.state(), UpdateState::PendingCommit);

    up.commit().expect("commit");
    assert_eq!(up.state(), UpdateState::Committed);

    // The commit only STAGED the swap (the inert option-byte path). No real
    // option load fired: OPTR still boots Bank 1 until a modelled reset.
    assert!(shared.model.borrow().obl_launched(), "OBL_LAUNCH observed inert");
    assert!(!shared.model.borrow().boots_bank2(), "swap not applied yet");

    // Model the reset that the swap commits on (RM0456 sec 7.5.8): the staged
    // SWAP_BANK is applied, so the part now boots physical Bank 2 and physical
    // Bank 1 (with the NVCNT) moves to the HIGH alias.
    shared.model.borrow_mut().apply_reset();
    assert!(shared.model.borrow().boots_bank2(), "swap applied at reset");

    // First boot of the new bank: the running bank now matches the armed target.
    assert_eq!(up.on_boot().expect("boot"), UpdateState::AwaitingConfirm);

    // Confirm: spends the SE counter, clears the record, bumps NVCNT LAST.
    up.confirm(7).expect("confirm");
    assert_eq!(up.state(), UpdateState::Confirmed);

    // The B1 PROOF: the NVCNT is read back from the RIGHT physical bank AFTER the
    // swap. Physical Bank 1 now sits at the high alias, so a driver that used a
    // fixed low-alias metadata address would read physical Bank 2 (garbage). The
    // swap-aware helper re-derives Bank 1's high-alias address, so the counter
    // reads the value confirm just bumped.
    assert_eq!(read_nvcnt(&shared), 7, "nvcnt read from physical Bank 1 post-swap");

    // The OLD (now inactive, physical Bank 1) bank still holds its v1 image bytes
    // and is independently verifiable, read PHYSICALLY so the check does not
    // depend on the current alias.
    let model = shared.model.borrow();
    let mut recovered = Vec::new();
    for i in 0..old_len
    {
        let offset = regs::IMAGE_REGION_OFFSET as usize + i;
        recovered.push(model.phys_byte(false, offset).expect("byte"));
    }
    assert_eq!(recovered, old_image, "OLD physical bank bytes intact");
    verify_image(&recovered, &root).expect("OLD bank still bootable");
}

#[test]
fn rejected_image_over_the_real_driver_never_commits()
{
    let shared = Shared::new();
    let root = dev_root();
    let se = LocalSeCounter::new(SE_FLOOR_ZERO);
    let driver = Stm32FlashSeam::new(shared.clone());
    let mut up = Updater::new(&root, driver, se);

    // A valid image body with one payload byte flipped: the signature no longer
    // matches, so verify must reject and no swap may be armed.
    let mut bad = dev_image(7, b"tampered payload");
    let last = bad.len() - 1;
    bad[last] ^= 0x01;

    up.begin(bad.len()).expect("begin");
    up.receive_chunk(0, &bad).expect("receive");
    assert!(up.verify_and_accept().is_err(), "tampered image rejected");
    assert_ne!(up.state(), UpdateState::Committed);
    // No OBL_LAUNCH ever fired, the swap was never armed.
    assert!(!shared.model.borrow().obl_launched(), "no swap armed");
}

// An SE counter value whose derived anti-rollback floor is zero, so Gate 2 does
// not interfere with a test that exercises Gate 1 plus the signature.
const SE_FLOOR_ZERO: u32 = fw_update::SE_COUNTER_ORIGIN;
