//! First-light bank assembler for the STM32U545 A/B descriptor-page layout.
//!
//! Takes the three raw firmware binaries (immutable boot stage, secure app,
//! non-secure app), a firmware version, a security counter, and a signing backend,
//! and lays out one flashable physical-bank image whose committed bytes are
//! self-verifying and bootable-shaped. The signing reuses
//! [`crate::build_signed_image`], so the signed bytes are identical to what the
//! device verifies.
//!
//! # The on-flash contract (mirrors crates/boot-stage/src/health.rs)
//!
//! Per bank the page size is `0x2000` and the layout is:
//!
//! ```text
//!   pages 0-1   metadata      (left erased 0xFF, initial state)
//!   pages 2-8   boot stage    offset 0x4000
//!   page  9     descriptor    offset 0x12000: header[0:24] then sig[24:88]
//!   pages 10-19 secure app    offset 0x14000, exactly 0x14000 bytes (80K)
//!   pages 20-31 NS app        offset 0x28000, up to 0x18000 bytes (96K)
//! ```
//!
//! The signed file stays contiguous `HEADER || PAYLOAD || SIG`. PAYLOAD is the
//! secure app padded to exactly `SECURE_LEN`, then the NS app, so
//! `payload_len = SECURE_LEN + ns_len`. The device carves
//! `secure_take = min(payload_len, SECURE_LEN)` then the remainder as NS, so the
//! secure part must be exactly `SECURE_LEN` or the NS band is miscarved. The device
//! reads back the full secure band, so the pad bytes are part of the signed and
//! flashed image: this assembler emits the exact padded bytes rather than relying on
//! erased flash matching a gap fill.
//!
//! # Fill choice
//!
//! Every otherwise-unused byte, including the secure pad and the tail of the NS
//! band, is [`FILL`] = `0xFF`, the erased-flash value. A byte the flash tool skips
//! then reads back identical to the signed image, so the read-back the device
//! verifies matches deterministically.

use image_verify::HEADER_LEN;
use image_verify::ImageVersion;
use image_verify::ROOT_KEY_LEN;
use image_verify::RootKey;
use image_verify::SIG_LEN;
use image_verify::VerifyError;
use image_verify::verify_image;

use crate::ImageSigner;
use crate::SignError;
use crate::build_signed_image;

/// The flash page (and erase) granularity in bytes. RM0456 sec 7.3.1 (DUALBANK=1).
pub const PAGE_SIZE: usize = 0x2000;

/// The physical bank size in bytes: 32 pages of `PAGE_SIZE`.
pub const BANK_SIZE: usize = PAGE_SIZE * 32;

/// The erased-flash fill byte used for every unwritten region and every pad.
pub const FILL: u8 = 0xFF;

/// Boot-stage band offset within the bank (page 2). Link origin 0x0C004000.
pub const BOOT_OFFSET: usize = 2 * PAGE_SIZE;

/// Boot-stage band capacity in bytes (pages 2-8, below the descriptor).
pub const BOOT_LEN: usize = DESCRIPTOR_OFFSET - BOOT_OFFSET;

/// Descriptor page offset within the bank (page 9). Link origin 0x0C012000.
pub const DESCRIPTOR_OFFSET: usize = 9 * PAGE_SIZE;

/// Descriptor payload length: the signed header then the signature.
pub const DESCRIPTOR_LEN: usize = HEADER_LEN + SIG_LEN;

/// Secure app band offset within the bank (page 10). Link origin 0x0C014000.
pub const SECURE_OFFSET: usize = 10 * PAGE_SIZE;

/// Secure app band length in bytes (pages 10-19). The secure payload is padded to
/// exactly this so the device carves the SECWM boundary correctly.
pub const SECURE_LEN: usize = 10 * PAGE_SIZE;

/// Non-secure app band offset within the bank (page 20). Link origin 0x08028000.
pub const NS_OFFSET: usize = 20 * PAGE_SIZE;

/// Non-secure app band length in bytes (pages 20-31).
pub const NS_LEN: usize = 12 * PAGE_SIZE;

// The bands tile the bank contiguously with no gap and no overlap: the
// descriptor page is immediately followed by the secure band, which is
// immediately followed by the NS band, which closes the bank. A wrong constant
// breaks the build.
const _: () = assert!(DESCRIPTOR_OFFSET + PAGE_SIZE == SECURE_OFFSET);
const _: () = assert!(SECURE_OFFSET + SECURE_LEN == NS_OFFSET);
const _: () = assert!(NS_OFFSET + NS_LEN == BANK_SIZE);
const _: () = assert!(DESCRIPTOR_LEN <= PAGE_SIZE);

/// Why a bank assembly failed. Every variant is fail-closed: no artifact is
/// produced. No variant carries key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BankError
{
    /// The boot-stage binary exceeds the boot band (pages 2-8).
    BootTooLarge
    {
        /// The boot binary length in bytes.
        got: usize,
    },
    /// The secure app binary exceeds the secure band (pages 10-19).
    SecureTooLarge
    {
        /// The secure binary length in bytes.
        got: usize,
    },
    /// The non-secure app binary exceeds the NS band (pages 20-31).
    NsTooLarge
    {
        /// The non-secure binary length in bytes.
        got: usize,
    },
    /// Signing the assembled payload failed. Carries the signer error.
    Sign(SignError),
    /// The signer's public key does not equal the pinned root key. The device
    /// would reject the image, so no artifact is produced.
    PubkeyMismatch,
    /// The assembled bank failed the four-segment self-verify against the pinned
    /// root key. This must never happen: it means the layout and the signed
    /// bytes disagree, so the image is withheld.
    SelfVerifyFailed(VerifyError),
    /// The external-signature context file is malformed: a wrong magic, a
    /// truncated body, or a field that disagrees with the fixed band geometry.
    /// The FINALIZE step withholds the bank.
    BadContext,
    /// The external signature bytes are neither a valid 64-byte raw `(r, s)` pair
    /// nor a valid ASN.1 DER ECDSA signature, so FINALIZE cannot proceed.
    BadSignatureFormat,
    /// The normalized external signature does not verify against the pinned public
    /// key over the digest recomputed from the context. A wrong key, a wrong digest,
    /// or a corrupt signature all land here.
    ExternalSignatureRejected,
}

impl core::fmt::Display for BankError
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
    {
        match self
        {
            BankError::BootTooLarge { got } =>
            {
                write!(
                    f,
                    "the boot-stage binary is {got} bytes, over the {BOOT_LEN}-byte boot band"
                )
            }
            BankError::SecureTooLarge { got } =>
            {
                write!(
                    f,
                    "the secure app binary is {got} bytes, over the {SECURE_LEN}-byte secure band"
                )
            }
            BankError::NsTooLarge { got } =>
            {
                write!(
                    f,
                    "the non-secure app binary is {got} bytes, over the {NS_LEN}-byte NS band"
                )
            }
            BankError::Sign(e) =>
            {
                write!(f, "signing the assembled payload failed: {e}")
            }
            BankError::PubkeyMismatch =>
            {
                write!(
                    f,
                    "the signer's public key does not match the pinned root key, \
                     the device would reject this image"
                )
            }
            BankError::SelfVerifyFailed(e) =>
            {
                write!(
                    f,
                    "ALARM: the assembled bank failed its own four-segment \
                     self-verify ({e:?}), no image was written"
                )
            }
            BankError::BadContext =>
            {
                write!(
                    f,
                    "the external-signature context file is malformed, \
                     FINALIZE was withheld"
                )
            }
            BankError::BadSignatureFormat =>
            {
                write!(
                    f,
                    "the external signature is neither a 64-byte raw (r, s) pair \
                     nor a valid ASN.1 DER ECDSA signature"
                )
            }
            BankError::ExternalSignatureRejected =>
            {
                write!(
                    f,
                    "the external signature does not verify against the pinned \
                     public key over the context digest, no image was written. \
                     Common bench causes: the card RE-HASHED the digest (wrong \
                     PKCS#11 mechanism, it must sign the 32-byte hash raw), the \
                     wrong slot or key was used, or the context and the signature \
                     came from DIFFERENT prepare runs"
                )
            }
        }
    }
}

/// A fully assembled, self-verified physical-bank image.
pub struct AssembledBank
{
    /// The full `BANK_SIZE` flashable image, regions at their physical offsets,
    /// every other byte [`FILL`].
    pub image: Vec<u8>,
    /// The signer's 65-byte uncompressed SEC1 public key, confirmed equal to the
    /// pinned root key.
    pub public_key: [u8; ROOT_KEY_LEN],
    /// The boot-stage binary length placed in the boot band.
    pub boot_len: usize,
    /// The signed payload length: `SECURE_LEN + ns_len`.
    pub payload_len: usize,
    /// The actual secure app binary length before padding.
    pub secure_len: usize,
    /// The non-secure app binary length.
    pub ns_len: usize,
}

/// Assembles the flashable bank image and self-verifies it.
///
/// # Arguments
///
/// - `boot`: the immutable boot-stage raw binary (link origin 0x0C004000).
/// - `secure`: the secure app raw binary (link origin 0x0C014000).
/// - `nonsecure`: the non-secure app raw binary (link origin 0x08028000).
/// - `version`: the firmware version embedded in the signed header.
/// - `security_counter`: the monotonic anti-rollback counter embedded.
/// - `signer`: the signing backend over `HEADER || PAYLOAD`.
/// - `expected_root_key`: the pinned root public key the device verifies against.
///
/// # Returns
///
/// An [`AssembledBank`] whose image the four-segment device verifier accepts.
///
/// # Errors
///
/// A size overflow of any band, a signing failure, a public-key mismatch against
/// the pinned key, or a failed self-verify. The image is withheld on any of them.
pub fn assemble_bank
(
    boot: &[u8],
    secure: &[u8],
    nonsecure: &[u8],
    version: ImageVersion,
    security_counter: u32,
    signer: &dyn ImageSigner,
    expected_root_key: &[u8; ROOT_KEY_LEN],
)
    -> Result<AssembledBank, BankError>
{
    check_region_sizes(boot, secure, nonsecure)?;

    // The signer's public key must be the pinned root.
    let public_key = signer.public_key();
    if &public_key != expected_root_key
    {
        return Err(BankError::PubkeyMismatch);
    }

    // PAYLOAD = secure padded to exactly SECURE_LEN with FILL, then the NS app. Built
    // through the same helper the external flow uses, so the byte layout has a single
    // source of truth.
    let payload = assemble_payload(secure, nonsecure);
    let payload_len = payload.len();

    // Sign through the same path the device verifies, so the header and signature are
    // byte-identical to a plain signed file. build_signed_image also runs its own
    // contiguous round-trip self-check.
    let signed = build_signed_image(&payload, version, security_counter, signer)
        .map_err(BankError::Sign)?;

    // Split the contiguous signed file into its three logical parts.
    let header: &[u8; HEADER_LEN] = signed
        .get(..HEADER_LEN)
        .and_then(|h| h.try_into().ok())
        .ok_or(BankError::SelfVerifyFailed(VerifyError::TooShort))?;
    let signed_payload = signed
        .get(HEADER_LEN..HEADER_LEN + payload_len)
        .ok_or(BankError::SelfVerifyFailed(VerifyError::TooShort))?;
    let sig: &[u8; SIG_LEN] = signed
        .get(HEADER_LEN + payload_len..)
        .and_then(|s| s.try_into().ok())
        .ok_or(BankError::SelfVerifyFailed(VerifyError::TooShort))?;

    // Lay the bank out at the physical offsets through the same helper the external
    // flow uses. Everything else stays FILL.
    let image = place_bank(boot, header, signed_payload, sig)?;

    // Self-verify the assembled bytes as the device carves and verifies them,
    // against the pinned root key.
    let root = RootKey::from_bytes(*expected_root_key)
        .map_err(BankError::SelfVerifyFailed)?;
    verify_bank_segments(&image, &root).map_err(BankError::SelfVerifyFailed)?;

    Ok(AssembledBank
    {
        image,
        public_key,
        boot_len: boot.len(),
        payload_len,
        secure_len: secure.len(),
        ns_len: nonsecure.len(),
    })
}

/// Checks each firmware region fits its physical band. Shared by the internal
/// bring-up sign and the external-signature flow so the size policy is stated
/// once.
///
/// # Errors
///
/// [`BankError::BootTooLarge`], [`BankError::SecureTooLarge`], or
/// [`BankError::NsTooLarge`] if the matching region overflows its band.
pub(crate) fn check_region_sizes
(
    boot: &[u8],
    secure: &[u8],
    nonsecure: &[u8],
)
    -> Result<(), BankError>
{
    if boot.len() > BOOT_LEN
    {
        return Err(BankError::BootTooLarge { got: boot.len() });
    }
    if secure.len() > SECURE_LEN
    {
        return Err(BankError::SecureTooLarge { got: secure.len() });
    }
    if nonsecure.len() > NS_LEN
    {
        return Err(BankError::NsTooLarge { got: nonsecure.len() });
    }
    Ok(())
}

/// Builds the signed PAYLOAD: the secure app padded to [`SECURE_LEN`] with
/// [`FILL`], then the NS app. `payload_len = SECURE_LEN + nonsecure.len()`.
///
/// The pad bytes are inside the signed payload because the device reads back the
/// whole secure band. The caller must have run [`check_region_sizes`] first, so the
/// two copies are in range. This is the single source of truth for the payload
/// bytes, shared by [`assemble_bank`] and the external-signature flow.
pub(crate) fn assemble_payload(secure: &[u8], nonsecure: &[u8]) -> Vec<u8>
{
    let payload_len = SECURE_LEN + nonsecure.len();
    let mut payload = vec![FILL; payload_len];
    // Both copies are bounded by check_region_sizes.
    if let Some(slot) = payload.get_mut(..secure.len())
    {
        slot.copy_from_slice(secure);
    }
    if let Some(slot) = payload.get_mut(SECURE_LEN..)
    {
        slot.copy_from_slice(nonsecure);
    }
    payload
}

/// Lays the descriptor, boot, and the two payload bands out at their physical
/// offsets in a fresh [`BANK_SIZE`] image, every other byte [`FILL`].
///
/// This is the single source of truth for the bank layout, shared by
/// [`assemble_bank`] and the external-signature flow, so the two paths cannot drift.
/// `signed_payload` is the secure band (padded to [`SECURE_LEN`]) then the NS app,
/// exactly as [`assemble_payload`] built it.
///
/// # Errors
///
/// [`BankError::BootTooLarge`] if the boot region overflows its band,
/// [`BankError::NsTooLarge`] if the NS remainder overflows its band, or
/// [`BankError::SelfVerifyFailed`] if `signed_payload` is shorter than the secure
/// band.
pub(crate) fn place_bank
(
    boot: &[u8],
    header: &[u8; HEADER_LEN],
    signed_payload: &[u8],
    sig: &[u8; SIG_LEN],
)
    -> Result<Vec<u8>, BankError>
{
    if boot.len() > BOOT_LEN
    {
        return Err(BankError::BootTooLarge { got: boot.len() });
    }
    let ns_len = signed_payload
        .len()
        .checked_sub(SECURE_LEN)
        .ok_or(BankError::SelfVerifyFailed(VerifyError::LengthMismatch))?;
    if ns_len > NS_LEN
    {
        return Err(BankError::NsTooLarge { got: ns_len });
    }

    let mut image = vec![FILL; BANK_SIZE];
    // Every slice below is proven in range by the checks above and by the
    // compile-time band tiling asserts, so `?` on the get_mut is defensive only.
    copy_into(&mut image, BOOT_OFFSET, boot)?;
    copy_into(&mut image, DESCRIPTOR_OFFSET, header)?;
    copy_into(&mut image, DESCRIPTOR_OFFSET + HEADER_LEN, sig)?;
    copy_into(&mut image, SECURE_OFFSET, &signed_payload[..SECURE_LEN])?;
    copy_into(&mut image, NS_OFFSET, &signed_payload[SECURE_LEN..])?;
    Ok(image)
}

// Copies `src` into `image` at `offset`, or returns SelfVerifyFailed if the
// destination window is out of range. A panic-free wrapper over copy_from_slice.
fn copy_into
(
    image: &mut [u8],
    offset: usize,
    src: &[u8],
)
    -> Result<(), BankError>
{
    image
        .get_mut(offset..offset + src.len())
        .ok_or(BankError::SelfVerifyFailed(VerifyError::TooShort))?
        .copy_from_slice(src);
    Ok(())
}

/// Verifies a bank image the way the device does: carve four segments from the
/// descriptor page and the two bands, then run the segmented verifier.
///
/// This mirrors `crates/boot-stage/src/health.rs::assess` byte for byte: the
/// header and signature come from the page-9 descriptor, the secure payload from
/// the full secure band, the NS payload from the NS band, cut by the header's
/// declared `payload_len`.
///
/// # Errors
///
/// Any [`VerifyError`] the segmented verifier raises, or [`VerifyError::TooShort`]
/// if the bank is too small to hold the bands.
pub(crate) fn verify_bank_segments
(
    bank: &[u8],
    root: &RootKey,
)
    -> Result<(), VerifyError>
{
    let descriptor = bank
        .get(DESCRIPTOR_OFFSET..DESCRIPTOR_OFFSET + DESCRIPTOR_LEN)
        .ok_or(VerifyError::TooShort)?;
    let secure_band = bank
        .get(SECURE_OFFSET..SECURE_OFFSET + SECURE_LEN)
        .ok_or(VerifyError::TooShort)?;
    let ns_band = bank
        .get(NS_OFFSET..NS_OFFSET + NS_LEN)
        .ok_or(VerifyError::TooShort)?;

    let header = descriptor.get(..HEADER_LEN).ok_or(VerifyError::TooShort)?;
    let sig = descriptor
        .get(HEADER_LEN..HEADER_LEN + SIG_LEN)
        .ok_or(VerifyError::TooShort)?;

    // payload_len is the little-endian u32 at header offset 18. Reading it from the
    // not-yet-verified header is safe: the signature binds the true length, so a lie
    // yields a wrong digest or a bounds rejection.
    let len_bytes: [u8; 4] = header
        .get(18..22)
        .and_then(|b| b.try_into().ok())
        .ok_or(VerifyError::TooShort)?;
    let payload_len = u32::from_le_bytes(len_bytes) as usize;

    let secure_take = core::cmp::min(payload_len, secure_band.len());
    let ns_take = payload_len
        .checked_sub(secure_take)
        .ok_or(VerifyError::LengthMismatch)?;
    let secure_seg = secure_band
        .get(..secure_take)
        .ok_or(VerifyError::TooShort)?;
    let ns_seg = ns_band.get(..ns_take).ok_or(VerifyError::LengthMismatch)?;

    let segments: [&[u8]; 4] = [header, secure_seg, ns_seg, sig];
    verify_image(&segments, root).map(|_| ())
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::SoftwareSigner;
    use crate::derive_public_key;
    use sha2::Digest;
    use sha2::Sha256;

    // The bring-up phrase. Must match crates/boot-stage/src/mock.rs BRINGUP_PHRASE.
    // Any drift is caught by the derivation test below.
    const BRINGUP_PHRASE: &[u8] =
        b"patina_key MCU image root - BRING-UP ONLY - replace at ceremony freeze";

    const BRINGUP_ROOT_KEY: [u8; ROOT_KEY_LEN] = [
        0x04, 0x41, 0xf2, 0xde, 0xd6, 0xe6, 0x07, 0xa0,
        0xe0, 0x6c, 0x41, 0xc2, 0xcf, 0xab, 0x37, 0xf5,
        0xd7, 0x14, 0x90, 0x76, 0x31, 0x14, 0xbd, 0xaa,
        0xf4, 0x1c, 0x87, 0x8c, 0x25, 0xd3, 0xbb, 0x29,
        0x50, 0xbf, 0x26, 0x1e, 0xfb, 0x05, 0xb5, 0xbd,
        0x01, 0x1d, 0xbe, 0x67, 0xd6, 0x3c, 0xdc, 0xc4,
        0x8b, 0x82, 0x0a, 0x64, 0xf7, 0xa3, 0xd5, 0x85,
        0x8c, 0x76, 0xd7, 0x42, 0x24, 0x08, 0xba, 0xfe,
        0xe1,
    ];

    fn bringup_scalar() -> [u8; 32]
    {
        Sha256::digest(BRINGUP_PHRASE).into()
    }

    fn bringup_signer() -> SoftwareSigner
    {
        SoftwareSigner::from_key(&bringup_scalar()).expect("bring-up scalar valid")
    }

    fn version() -> ImageVersion
    {
        ImageVersion
        {
            major: 0,
            minor: 0,
            revision: 1,
            build: 0,
        }
    }

    // These literal offsets, lengths, and addresses must match
    // crates/mcu-flash/src/regs.rs (IMAGE_*) and crates/boot-stage/src/health.rs. The
    // host workspace cannot import the thumbv8m mcu-flash crate, so the
    // cross-workspace agreement stays a manual check, but this test pins bank.rs's own
    // derived layout to explicit values, so an internal drift (a changed page count or
    // PAGE_SIZE) fails here. Re-verify these literals against
    // regs.rs on any layout change.
    #[test]
    fn the_geometry_matches_the_pinned_device_layout()
    {
        assert_eq!(PAGE_SIZE, 0x2000, "8 KB page (regs.rs PAGE_SIZE)");
        assert_eq!(BANK_SIZE, 0x40000, "32 pages per bank (256 KB)");
        assert_eq!(BOOT_OFFSET, 0x4000, "boot band at page 2");
        assert_eq!(BOOT_LEN, 0xE000, "boot band pages 2-8 (56 KB)");
        assert_eq!(DESCRIPTOR_OFFSET, 0x12000, "descriptor at page 9");
        assert_eq!(DESCRIPTOR_LEN, 88, "header 24 + signature 64");
        assert_eq!(SECURE_OFFSET, 0x14000, "secure band at page 10");
        assert_eq!(SECURE_LEN, 0x14000, "secure band pages 10-19 (80 KB)");
        assert_eq!(NS_OFFSET, 0x28000, "NS band at page 20");
        assert_eq!(NS_LEN, 0x18000, "NS band pages 20-31 (96 KB)");
    }

    // The tool's bring-up derivation reproduces the bring-up root key exactly. This
    // is the in-crate guard against phrase drift.
    #[test]
    fn bringup_derivation_matches_the_bringup_key()
    {
        let derived = derive_public_key(&bringup_scalar()).expect("valid scalar");
        assert_eq!(derived, BRINGUP_ROOT_KEY);
    }

    // A representative assembly self-verifies, and the reported geometry matches.
    #[test]
    fn a_representative_bank_self_verifies()
    {
        let boot = vec![0xA5u8; 4096];
        let secure = vec![0x11u8; 6000];
        let ns = vec![0x22u8; 3000];
        let bank = assemble_bank
        (
            &boot,
            &secure,
            &ns,
            version(),
            7,
            &bringup_signer(),
            &BRINGUP_ROOT_KEY,
        )
        .expect("assembly must succeed and self-verify");

        assert_eq!(bank.image.len(), BANK_SIZE);
        assert_eq!(bank.public_key, BRINGUP_ROOT_KEY);
        assert_eq!(bank.secure_len, 6000);
        assert_eq!(bank.ns_len, 3000);
        assert_eq!(bank.payload_len, SECURE_LEN + 3000);

        // The regions landed at their physical offsets.
        assert_eq!(&bank.image[BOOT_OFFSET..BOOT_OFFSET + 4096], &boot[..]);
        assert_eq!(&bank.image[SECURE_OFFSET..SECURE_OFFSET + 6000], &secure[..]);
        assert_eq!(&bank.image[NS_OFFSET..NS_OFFSET + 3000], &ns[..]);
        // The secure pad past the app is FILL.
        assert!(
            bank.image[SECURE_OFFSET + 6000..NS_OFFSET]
                .iter()
                .all(|&b| b == FILL)
        );
        // Metadata pages 0-1 stay erased.
        assert!(bank.image[..BOOT_OFFSET].iter().all(|&b| b == FILL));
    }

    // A wrong expected root key is rejected before any layout, with no artifact.
    #[test]
    fn a_wrong_pinned_key_is_rejected()
    {
        let mut wrong = BRINGUP_ROOT_KEY;
        wrong[10] ^= 0x01;
        let result = assemble_bank(
            b"boot",
            b"secure",
            b"ns",
            version(),
            0,
            &bringup_signer(),
            &wrong,
        );
        assert_eq!(result.err(), Some(BankError::PubkeyMismatch));
    }

    // Assembles a good bank, then proves a one-byte corruption of each region makes
    // the four-segment verify reject. This is the non-vacuity proof.
    fn good_bank() -> Vec<u8>
    {
        assemble_bank(
            &vec![0xA5u8; 4096],
            &vec![0x11u8; 6000],
            &vec![0x22u8; 3000],
            version(),
            7,
            &bringup_signer(),
            &BRINGUP_ROOT_KEY,
        )
        .expect("assembly")
        .image
    }

    #[test]
    fn a_valid_bank_verifies_but_corruption_of_any_region_rejects()
    {
        let root = RootKey::from_bytes(BRINGUP_ROOT_KEY).expect("root");
        let base = good_bank();
        assert!(verify_bank_segments(&base, &root).is_ok());

        // One byte in each of the four device-read regions.
        for &off in &[
            DESCRIPTOR_OFFSET,          // header
            DESCRIPTOR_OFFSET + HEADER_LEN, // signature
            SECURE_OFFSET,              // secure payload
            NS_OFFSET,                  // NS payload
        ]
        {
            let mut corrupt = base.clone();
            corrupt[off] ^= 0xFF;
            assert!(
                verify_bank_segments(&corrupt, &root).is_err(),
                "corruption at offset {off:#x} must be rejected"
            );
        }

        // A byte in the secure pad (past the app, still inside the signed band).
        let mut pad_corrupt = base.clone();
        pad_corrupt[SECURE_OFFSET + SECURE_LEN - 1] ^= 0xFF;
        assert!
        (
            verify_bank_segments(&pad_corrupt, &root).is_err(),
            "corruption in the signed secure pad must be rejected"
        );
    }

    // A payload whose secure part is padded to the wrong length miscarves on the
    // device and must be rejected. This assembles a deliberately mis-sized bank by
    // hand (bypassing assemble_bank's exact padding) and proves the self-verify
    // catches it.
    #[test]
    fn a_wrong_secure_pad_size_is_rejected()
    {
        let signer = bringup_signer();
        let secure = vec![0x11u8; 6000];
        let ns = vec![0x22u8; 3000];

        // Pad the secure part to SECURE_LEN - 8 instead of SECURE_LEN, so the
        // signed payload_len is 8 short of the correct split.
        let bad_secure_len = SECURE_LEN - 8;
        let payload_len = bad_secure_len + ns.len();
        let mut payload = vec![FILL; payload_len];
        payload[..secure.len()].copy_from_slice(&secure);
        payload[bad_secure_len..].copy_from_slice(&ns);

        let signed = build_signed_image(&payload, version(), 7, &signer)
            .expect("build");
        let header = &signed[..HEADER_LEN];
        let signed_payload = &signed[HEADER_LEN..HEADER_LEN + payload_len];
        let sig = &signed[HEADER_LEN + payload_len..];

        // A real assembler places the NS region page-aligned at NS_OFFSET. With the
        // secure part signed 8 bytes short, the secure region leaves an 8-byte FILL
        // gap the device folds into the 80K secure band, and the NS split shifts, so
        // the reconstructed image no longer matches the signed bytes.
        let mut image = vec![FILL; BANK_SIZE];
        image[DESCRIPTOR_OFFSET..DESCRIPTOR_OFFSET + HEADER_LEN]
            .copy_from_slice(header);
        image[DESCRIPTOR_OFFSET + HEADER_LEN..DESCRIPTOR_OFFSET + DESCRIPTOR_LEN]
            .copy_from_slice(sig);
        image[SECURE_OFFSET..SECURE_OFFSET + bad_secure_len]
            .copy_from_slice(&signed_payload[..bad_secure_len]);
        image[NS_OFFSET..NS_OFFSET + ns.len()]
            .copy_from_slice(&signed_payload[bad_secure_len..]);

        let root = RootKey::from_bytes(BRINGUP_ROOT_KEY).expect("root");
        assert!(
            verify_bank_segments(&image, &root).is_err(),
            "a secure part not padded to exactly SECURE_LEN must be rejected"
        );
    }

    // An oversize secure binary is refused with no artifact.
    #[test]
    fn an_oversize_secure_binary_is_refused()
    {
        let secure = vec![0u8; SECURE_LEN + 1];
        let result = assemble_bank(
            b"boot",
            &secure,
            b"ns",
            version(),
            0,
            &bringup_signer(),
            &BRINGUP_ROOT_KEY,
        );
        assert_eq!(
            result.err(),
            Some(BankError::SecureTooLarge { got: SECURE_LEN + 1 })
        );
    }
}
