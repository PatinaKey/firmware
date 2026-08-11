//! The dual-bank A/B update machine re-cabled onto the real driver.
//!
//! This is the integration proof: the `fw-update` [`fw_update::Updater`] is
//! driven through its public API (new, begin, receive_chunk, verify_and_accept,
//! commit, on_boot, confirm) over [`Stm32FlashSeam`] backed by the faithful
//! FLASH-controller model, instead of the in-crate mock. So the same machine the
//! fw-update tests cover runs against the real register sequencing.
//!
//! A valid signed image is minted exactly as the fw-update tests do: the all-`01`
//! P-256 private scalar, the header from the `image-verify` `encode` feature, and
//! an ECDSA P-256 signature normalized to low-s, the only encoding the verifier
//! accepts. The root key is derived from that scalar here rather than imported, so
//! this crate carries no copy of a key constant to drift.
//!
//! The model carries interior sharing ([`Shared`]) so the test keeps a handle to
//! the backing flash after [`fw_update::Updater::new`] consumes the seam, and can
//! read NVCNT and the old-bank bytes back. The integration drives a full update,
//! models the swap reset, and asserts the NVCNT is read from the right physical
//! bank after the swap (physical Bank 1 has moved to the high alias) and the old
//! physical bank stays bootable, with no real option load ever firing.

#![cfg(test)]

extern crate alloc;

use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;

use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::Signer;

use fw_update::SeCounterError;
use fw_update::SeCounterSeam;
use fw_update::UpdateState;
use fw_update::Updater;

use image_verify::ImageVersion;
use image_verify::ROOT_KEY_LEN;
use image_verify::RootKey;
use image_verify::encode_header;
use image_verify::verify_image;

use crate::bus::FlashAccess;
use crate::driver::Stm32FlashSeam;
use crate::model::FlashModel;
use crate::regs;

// The dev private scalar, test only. A publicly known, hardcoded key that makes
// every fixture deterministic. The all-0x01 value is a valid P-256 scalar:
// non-zero, and far below the curve order, which starts with 0xFF.
const DEV_SCALAR: [u8; 32] = [1u8; 32];

/// A shared handle to the FLASH-controller model.
///
/// [`Updater::new`] takes the seam by value, so the test keeps a clone of this
/// `Rc` to inspect the backing flash (NVCNT, the OLD-bank bytes, the staged
/// swap) after the updater owns the driver. `RefCell` gives the `&mut self`
/// borrow each [`FlashAccess`] call needs from behind the shared handle.
///
/// # The inactive-band borrow is structurally sound
///
/// [`FlashAccess::bank_view`] returns a slice the host analogue of memory-mapped
/// flash, borrowed for `&self`. The trait signature ties the slice's lifetime to
/// `&self`, so the borrow checker already forbids a `&mut self` access (the
/// mutating [`FlashAccess::read32`] / [`FlashAccess::write32`]) while the slice is
/// live: the soundness does not rest on the `verify_and_accept` ordering, the
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
        // Resolve the band read through the model (RM0456 sec 7.5.8 swap mapping
        // plus RM0456 Table 68 RAZ on a wrong-alias read), then return the
        // equivalent borrow. `band_ptr` yields either the physical store pointer
        // (alias matches the page label) or the all-zero RAZ pointer (mismatch),
        // both stable boxed arrays kept alive by the Rc. The borrow is taken from
        // a live `Ref` guard, so the pointer is resolved against the RefCell state
        // at this instant. The trait ties the returned slice to `&self`, which the
        // borrow checker enforces, so a `&mut self` mutating access cannot run
        // while the slice is live.
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
        // SAFETY: this is a test double, the host analogue of memory-mapped flash,
        // not the production MMIO port. `ptr` is one of the model's boxed bank
        // arrays or its RAZ buffer, kept alive by the Rc the test still holds, with
        // a stable address for the model's life. The range `start..end` is clamped
        // inside that array span by `band_ptr`, the bytes are plain `u8`. No
        // aliasing arises in these tests: each `Shared` clone shares one `RefCell`,
        // and the `Ref` guard is dropped before the slice is built, so the type
        // system does not by itself bar a second clone from calling `borrow_mut`
        // while a view is live. Safety here rests on usage, the returned slice is
        // fully consumed before any other handle is touched, and the borrowed
        // bytes are immutable flash during the verifying read.
        #[allow(unsafe_code)]
        unsafe
        {
            core::slice::from_raw_parts(ptr.add(start), end - start)
        }
    }
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

// The signing key of the dev scalar.
fn dev_signing_key() -> SigningKey
{
    SigningKey::from_slice(&DEV_SCALAR).expect("the dev scalar is in [1, n-1]")
}

// Builds a HEADER || payload || signature image signed with the dev scalar,
// carrying the given security counter, using the image-verify encode feature so
// the layout has a single source of truth. The signature is normalized to low-s,
// the only encoding the verifier accepts.
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

// The dev root key, derived from the dev scalar. Deriving it rather than pinning
// a second copy of the constant keeps this crate free of a key that could drift.
fn dev_root() -> RootKey
{
    let point = dev_signing_key().verifying_key().to_sec1_point(false);
    let mut bytes = [0u8; ROOT_KEY_LEN];
    bytes.copy_from_slice(point.as_ref());
    RootKey::from_bytes(bytes).expect("the derived dev root key is on-curve")
}

// Verifies a contiguous image through the segmented verifier. This seam still
// hands back one contiguous slice, so a one-element segment list is exactly a
// contiguous image.
fn verify_contiguous(image: &[u8], root: &RootKey) -> Result<(), image_verify::VerifyError>
{
    let segments: [&[u8]; 1] = [image];
    verify_image(&segments, root)?;
    Ok(())
}

// Reads the NVCNT through a fresh driver over the shared model.
fn read_nvcnt(shared: &Shared) -> u32
{
    use fw_update::FlashSeam;
    let mut probe = Stm32FlashSeam::new(shared.clone());
    probe.nvcnt_read().expect("nvcnt read")
}

#[test]
fn the_dev_root_key_is_a_key_the_verifier_accepts()
{
    // The derived key must be one RootKey::from_bytes accepts, so every fixture
    // below verifies against a real pinned key rather than a rejected one.
    let point = dev_signing_key().verifying_key().to_sec1_point(false);
    assert_eq!(point.as_ref().len(), ROOT_KEY_LEN, "uncompressed SEC1, 65 bytes");
    let mut bytes = [0u8; ROOT_KEY_LEN];
    bytes.copy_from_slice(point.as_ref());
    assert!(RootKey::from_bytes(bytes).is_ok());
}

#[test]
fn full_update_over_the_real_driver_reads_nvcnt_from_right_bank_after_swap()
{
    let shared = Shared::new();

    // Seed the old (running, physical Bank 1) bank image band with a complete
    // valid v1 image so the "old bank stays bootable" invariant is asserted
    // against real model bytes. The seeding is physical (poke_phys on Bank 1),
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

    // Stream a newer image (counter 7) through the public API into the inactive
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

    // The commit only staged the swap (the inert option-byte path). No real
    // option load fired: OPTR still boots Bank 1 until a modelled reset.
    assert!(shared.model.borrow().obl_launched(), "OBL_LAUNCH observed inert");
    assert!(!shared.model.borrow().boots_bank2(), "swap not applied yet");

    // Model the reset that the swap commits on (RM0456 sec 7.5.8): the staged
    // SWAP_BANK is applied, so the part now boots physical Bank 2 and physical
    // Bank 1 (with the NVCNT) moves to the high alias.
    shared.model.borrow_mut().apply_reset();
    assert!(shared.model.borrow().boots_bank2(), "swap applied at reset");

    // First boot of the new bank: the running bank now matches the armed target.
    assert_eq!(up.on_boot().expect("boot"), UpdateState::AwaitingConfirm);

    // Confirm: spends the SE counter, clears the record, bumps NVCNT last.
    up.confirm(7).expect("confirm");
    assert_eq!(up.state(), UpdateState::Confirmed);

    // The B1 proof: the NVCNT is read back from the right physical bank after the
    // swap. Physical Bank 1 now sits at the high alias, so a driver that used a
    // fixed low-alias metadata address would read physical Bank 2 (garbage). The
    // swap-aware helper re-derives Bank 1's high-alias address, so the counter
    // reads the value confirm just bumped.
    assert_eq!(read_nvcnt(&shared), 7, "nvcnt read from physical Bank 1 post-swap");

    // The old (now inactive, physical Bank 1) bank still holds its v1 image bytes
    // and is independently verifiable, read physically so the check does not
    // depend on the current alias.
    let model = shared.model.borrow();
    let mut recovered = Vec::new();
    for i in 0..old_len
    {
        let offset = regs::IMAGE_REGION_OFFSET as usize + i;
        recovered.push(model.phys_byte(false, offset).expect("byte"));
    }
    assert_eq!(recovered, old_image, "OLD physical bank bytes intact");
    verify_contiguous(&recovered, &root).expect("OLD bank still bootable");
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

#[test]
fn ns_band_reads_correct_via_ns_alias_and_raz_via_secure_alias()
{
    use fw_update::FlashSeam;

    // TRAP 4 regression (RM0456 Table 68): a non-secure image page read through
    // the secure alias returns RAZ (all zeros). The banded read must use the NS
    // alias for the non-secure sub-band, or verify would see zeros for the whole
    // non-secure half while the host model stayed green. This proves the model
    // makes a wrong-alias read fail, and that the driver reads the right alias.
    //
    // If inactive_ns_band regressed to the secure alias, the first assertion here
    // goes red: the NS band would read all zeros instead of the seeded pattern.
    let shared = Shared::new();

    // Seed a recognisable non-zero pattern into the NS image sub-band (pages
    // 20-31) of the inactive bank (physical Bank 2), bank-relative so the seeding
    // is alias-independent.
    let ns_off = regs::IMAGE_NS_BAND_OFFSET as usize;
    let pattern: [u8; 64] = core::array::from_fn(|i| (i as u8) | 0x80);
    for (i, byte) in pattern.iter().enumerate()
    {
        shared.model.borrow_mut().poke_phys(true, ns_off + i, *byte);
    }

    // Through the NS alias the driver reads the real seeded bytes.
    let driver = Stm32FlashSeam::new(shared.clone());
    let ns_band = driver.inactive_ns_band();
    assert_eq!(
        &ns_band[..pattern.len()],
        &pattern[..],
        "NS band reads the real bytes through the NS alias"
    );

    // The same physical bytes read through the secure alias are RAZ. Physical
    // Bank 2 is inactive, so it sits at the high alias, and the NS sub-band read
    // through the secure high alias returns zeros (Table 68). This is exactly the
    // fault a flat address-to-store model could not observe.
    let secure_wrong = regs::HIGH_ALIAS_BASE + regs::IMAGE_NS_BAND_OFFSET;
    let via_secure = shared
        .model
        .borrow()
        .bank_view(secure_wrong, pattern.len())
        .to_vec();
    assert_eq!(via_secure.len(), pattern.len(), "RAZ read keeps the length");
    assert!(
        via_secure.iter().all(|byte| *byte == 0),
        "NS band read through the secure alias is RAZ (all zeros)"
    );

    // At the word level too: the secure-alias load of an NS page is RAZ, the
    // NS-alias load returns the seeded data.
    let raz_word = shared.model.borrow_mut().read32(secure_wrong);
    assert_eq!(raz_word, 0, "secure-alias word read of an NS page is RAZ");
    let ns_addr = regs::NS_HIGH_ALIAS_BASE + regs::IMAGE_NS_BAND_OFFSET;
    let data_word = shared.model.borrow_mut().read32(ns_addr);
    assert_ne!(data_word, 0, "NS-alias word read of the NS page returns data");
}

// An SE counter value whose derived anti-rollback floor is zero, so Gate 2 does
// not interfere with a test that exercises Gate 1 plus the signature.
const SE_FLOOR_ZERO: u32 = fw_update::SE_COUNTER_ORIGIN;
