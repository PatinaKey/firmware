//! Signed firmware-image verifier for patina_key.
//!
//! A `no_std`, heap-free library that parses the patina_key
//! signed-image format and verifies its Ed25519 signature against an
//! out-of-band PINNED root public key supplied by the caller. It writes no
//! flash, touches no lifecycle or option byte, and runs no bootloader or A/B
//! state machine: those are a future crate. This crate decides one thing,
//! is this image authentic under the pinned root, fail-closed.
//!
//! # Trust model
//!
//! The entire image is attacker-controlled until the signature verifies. The
//! root public key is the ONLY trust input and it is a caller argument, so the
//! library stays testable and the real secure binary pins the genuine key
//! out-of-band as a const. No header field inside the signed region is exposed
//! before the Ed25519 check passes. `verify_strict` (not `verify`) is used so a
//! low-order or non-canonical key is rejected.
//!
//! See [`format`] for the exact byte layout and the little-endian choice.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

mod error;
mod format;

pub use crate::error::VerifyError;
pub use crate::format::ImageVersion;
pub use crate::format::HEADER_LEN;
pub use crate::format::SIG_LEN;

use ed25519_dalek::Signature;
use ed25519_dalek::VerifyingKey;

/// A pinned Ed25519 root public key.
///
/// Constructed only through [`RootKey::from_bytes`], which rejects any encoding
/// Ed25519 refuses (a malformed or non-canonical point). Holding a `RootKey`
/// therefore means dalek already accepted the key.
// Debug is intentionally NOT derived so the key bytes can never reach logs.
#[derive(Clone)]
pub struct RootKey
{
    key: VerifyingKey,
}

impl RootKey
{
    /// Builds a pinned root key from its 32-byte Ed25519 encoding.
    ///
    /// # Errors
    ///
    /// Returns [`VerifyError::BadRootKey`] if the bytes are not a valid
    /// compressed Edwards point that dalek accepts.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<RootKey, VerifyError>
    {
        match VerifyingKey::from_bytes(&bytes)
        {
            Ok(key) => Ok(RootKey { key }),
            Err(_) => Err(VerifyError::BadRootKey),
        }
    }
}

/// A verified image view.
///
/// Returned ONLY after the Ed25519 signature passed. Every field here lives
/// inside the signed region, so reading it is safe: an attacker cannot forge it
/// without the root private key. The payload slice borrows the original image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedImage<'a>
{
    image_version: ImageVersion,
    security_counter: u32,
    payload: &'a [u8],
}

impl<'a> VerifiedImage<'a>
{
    /// The firmware version (major.minor.revision.build) from the signed header.
    pub fn image_version(&self) -> ImageVersion
    {
        self.image_version
    }

    /// The monotonic anti-rollback counter from the signed header. Parsed only,
    /// no policy is applied here.
    pub fn security_counter(&self) -> u32
    {
        self.security_counter
    }

    /// The verified payload bytes (the region between the header and the
    /// signature).
    pub fn payload(&self) -> &'a [u8]
    {
        self.payload
    }
}

// Reads a little-endian u16 at `off` from an already-bounds-checked header
// region. The caller guarantees `slice.len() >= off + 2`.
fn read_u16_le(slice: &[u8], off: usize) -> Result<u16, VerifyError>
{
    let bytes = slice
        .get(off..off + 2)
        .ok_or(VerifyError::TooShort)?;
    let arr: [u8; 2] = bytes
        .try_into()
        .map_err(|_| VerifyError::TooShort)?;
    Ok(u16::from_le_bytes(arr))
}

// Reads a little-endian u32 at `off`. Same contract as `read_u16_le`.
fn read_u32_le(slice: &[u8], off: usize) -> Result<u32, VerifyError>
{
    let bytes = slice
        .get(off..off + 4)
        .ok_or(VerifyError::TooShort)?;
    let arr: [u8; 4] = bytes
        .try_into()
        .map_err(|_| VerifyError::TooShort)?;
    Ok(u32::from_le_bytes(arr))
}

/// Verifies a signed firmware image against a pinned root key.
///
/// # Arguments
///
/// - `image`: the full `HEADER || PAYLOAD || SIGNATURE` byte slice. Entirely
///   attacker-controlled until the signature check passes.
/// - `root_key`: the out-of-band pinned Ed25519 root public key.
///
/// # Returns
///
/// On success, a [`VerifiedImage`] exposing the signed `image_version`,
/// `security_counter`, and payload slice.
///
/// # Errors
///
/// Fails closed at the FIRST anomaly, in this fixed order:
/// [`VerifyError::TooShort`] (below the `HEADER_LEN + SIG_LEN` floor),
/// [`VerifyError::BadMagic`], [`VerifyError::UnsupportedFormatVersion`],
/// [`VerifyError::UnsupportedAlgorithm`], [`VerifyError::ReservedNotZero`] (a
/// reserved header byte was not zero), [`VerifyError::LengthMismatch`] (the
/// total length is not `HEADER_LEN + payload_len + SIG_LEN` exactly, including
/// an overflowing `payload_len`), then [`VerifyError::BadSignature`] if Ed25519
/// rejects the signature over `HEADER || PAYLOAD`. No field inside the signed
/// region is read into the result before that final check passes.
pub fn verify_image<'a>
(
    image: &'a [u8],
    root_key: &RootKey,
)
    -> Result<VerifiedImage<'a>, VerifyError>
{
    use crate::format::
    {
        ALG_ED25519, FORMAT_VERSION, HEADER_LEN, MAGIC, OFF_ALGORITHM,
        OFF_FORMAT_VERSION, OFF_MAGIC, OFF_PAYLOAD_LEN, OFF_RESERVED,
        OFF_SECURITY_COUNTER, OFF_VERSION_BUILD, OFF_VERSION_MAJOR,
        OFF_VERSION_MINOR, OFF_VERSION_REVISION, SIG_LEN,
    };

    // a. Length floor: must hold a header plus a signature.
    let floor = HEADER_LEN
        .checked_add(SIG_LEN)
        .ok_or(VerifyError::TooShort)?;
    if image.len() < floor
    {
        return Err(VerifyError::TooShort);
    }

    // The full header is parsed UP FRONT into typed locals, using the bounded
    // combinators with their reachable error variants. Nothing parsed here is
    // returned or otherwise exposed before verify_strict returns Ok: only the
    // local bindings exist, and the VerifiedImage is built solely on the Ok
    // path. This keeps the verifier fail-closed by construction.

    // b. Magic.
    let magic = image
        .get(OFF_MAGIC..OFF_MAGIC + 4)
        .ok_or(VerifyError::TooShort)?;
    if magic != MAGIC
    {
        return Err(VerifyError::BadMagic);
    }

    // c. Format version (parser schema, not firmware version).
    let format_version = *image
        .get(OFF_FORMAT_VERSION)
        .ok_or(VerifyError::TooShort)?;
    if format_version != FORMAT_VERSION
    {
        return Err(VerifyError::UnsupportedFormatVersion);
    }

    // d. Algorithm id.
    let algorithm = *image
        .get(OFF_ALGORITHM)
        .ok_or(VerifyError::TooShort)?;
    if algorithm != ALG_ED25519
    {
        return Err(VerifyError::UnsupportedAlgorithm);
    }

    // e. Firmware version (major.minor.revision.build), inside the signed
    //    region. Read into a local now, returned only after verification.
    let image_version = ImageVersion
    {
        major: *image
            .get(OFF_VERSION_MAJOR)
            .ok_or(VerifyError::TooShort)?,
        minor: *image
            .get(OFF_VERSION_MINOR)
            .ok_or(VerifyError::TooShort)?,
        revision: read_u16_le(image, OFF_VERSION_REVISION)?,
        build: read_u32_le(image, OFF_VERSION_BUILD)?,
    };

    // f. Monotonic anti-rollback counter, inside the signed region.
    let security_counter = read_u32_le(image, OFF_SECURITY_COUNTER)?;

    // g. Declared payload length.
    let payload_len = read_u32_le(image, OFF_PAYLOAD_LEN)? as usize;

    // h. Reserved bytes MUST be zero. They sit inside the signed region, so
    //    this is a structural rejection caught before the signature check.
    let reserved = image
        .get(OFF_RESERVED..OFF_RESERVED + 2)
        .ok_or(VerifyError::TooShort)?;
    if reserved != [0u8, 0u8]
    {
        return Err(VerifyError::ReservedNotZero);
    }

    // i. Exact total length: HEADER_LEN + payload_len + SIG_LEN, no overflow,
    //    no trailing byte, no short read.
    let signed_len = HEADER_LEN
        .checked_add(payload_len)
        .ok_or(VerifyError::LengthMismatch)?;
    let total_len = signed_len
        .checked_add(SIG_LEN)
        .ok_or(VerifyError::LengthMismatch)?;
    if image.len() != total_len
    {
        return Err(VerifyError::LengthMismatch);
    }

    // j. Split the signed region from the trailing signature, both via bounded
    //    slicing.
    let signed = image
        .get(..signed_len)
        .ok_or(VerifyError::LengthMismatch)?;
    let sig_bytes = image
        .get(signed_len..total_len)
        .ok_or(VerifyError::LengthMismatch)?;
    let sig_arr: [u8; SIG_LEN] = sig_bytes
        .try_into()
        .map_err(|_| VerifyError::LengthMismatch)?;
    let signature = Signature::from_bytes(&sig_arr);

    // k. The load-bearing trust step. verify_strict rejects low-order keys.
    //    Any failure collapses to BadSignature: nothing leaks about why.
    root_key
        .key
        .verify_strict(signed, &signature)
        .map_err(|_| VerifyError::BadSignature)?;

    // Authenticated. Only now bind the payload slice and build the result from
    // the already-parsed locals.
    let payload = signed
        .get(HEADER_LEN..signed_len)
        .ok_or(VerifyError::LengthMismatch)?;

    Ok(VerifiedImage
    {
        image_version,
        security_counter,
        payload,
    })
}

/// Fuzzing seam. Exposes the attacker-facing verify path to libFuzzer harnesses.
///
/// Gated behind the `_fuzz` feature so the normal public API stays minimal. The
/// entry point must never panic on any input. Not part of the supported API.
#[cfg(feature = "_fuzz")]
pub mod fuzz
{
    use crate::RootKey;

    // A FIXED, valid Ed25519 public key for the fuzz target. Its exact value is
    // irrelevant: the target exercises the bounded parsing in front of the
    // crypto, which fails closed on essentially every mutated input. The bytes
    // below are the public key of the all-0x01 Ed25519 secret scalar, a
    // genuinely on-curve point that from_bytes accepts.
    const FUZZ_ROOT_KEY: [u8; 32] = [
        0x8a, 0x88, 0xe3, 0xdd, 0x74, 0x09, 0xf1, 0x95,
        0xfd, 0x52, 0xdb, 0x2d, 0x3c, 0xba, 0x5d, 0x72,
        0xca, 0x67, 0x09, 0xbf, 0x1d, 0x94, 0x12, 0x1b,
        0xf3, 0x74, 0x88, 0x01, 0xb4, 0x0f, 0x6f, 0x5c,
    ];

    /// Drives the image verifier over arbitrary bytes under a fixed pinned root
    /// key. Must never panic. Returns either `Ok` (only for a genuinely valid
    /// image under that key, which fuzzing will essentially never produce) or a
    /// typed error. Any panic/abort is a finding.
    pub fn verify_image(data: &[u8])
    {
        if let Ok(root) = RootKey::from_bytes(FUZZ_ROOT_KEY)
        {
            let _ = crate::verify_image(data, &root);
        }
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::format::{
        ALG_ED25519, FORMAT_VERSION, MAGIC, OFF_ALGORITHM, OFF_FORMAT_VERSION,
        OFF_MAGIC, OFF_PAYLOAD_LEN, OFF_RESERVED, OFF_SECURITY_COUNTER,
        OFF_VERSION_BUILD, OFF_VERSION_MAJOR, OFF_VERSION_MINOR,
        OFF_VERSION_REVISION,
    };
    use ed25519_dalek::ed25519::signature::Signer;
    use ed25519_dalek::SigningKey;
    use std::vec::Vec;

    // Deterministic fixtures: a fixed 32-byte seed yields a stable key pair, no
    // RNG needed.
    const TEST_SEED: [u8; 32] = [7u8; 32];
    const OTHER_SEED: [u8; 32] = [9u8; 32];

    const TEST_MAJOR: u8 = 3;
    const TEST_MINOR: u8 = 7;
    const TEST_REVISION: u16 = 0x0102;
    const TEST_BUILD: u32 = 0xAABB_CCDD;
    const TEST_COUNTER: u32 = 0x0000_1234;

    fn signing_key(seed: [u8; 32]) -> SigningKey
    {
        SigningKey::from_bytes(&seed)
    }

    fn root_key_for(seed: [u8; 32]) -> RootKey
    {
        let sk = signing_key(seed);
        let pk = sk.verifying_key().to_bytes();
        RootKey::from_bytes(pk).expect("test key is valid")
    }

    // Builds a header with the given payload length. Returns a HEADER_LEN buffer.
    fn build_header(payload_len: u32) -> [u8; HEADER_LEN]
    {
        let mut h = [0u8; HEADER_LEN];
        h[OFF_MAGIC..OFF_MAGIC + 4].copy_from_slice(&MAGIC);
        h[OFF_FORMAT_VERSION] = FORMAT_VERSION;
        h[OFF_ALGORITHM] = ALG_ED25519;
        h[OFF_VERSION_MAJOR] = TEST_MAJOR;
        h[OFF_VERSION_MINOR] = TEST_MINOR;
        h[OFF_VERSION_REVISION..OFF_VERSION_REVISION + 2]
            .copy_from_slice(&TEST_REVISION.to_le_bytes());
        h[OFF_VERSION_BUILD..OFF_VERSION_BUILD + 4]
            .copy_from_slice(&TEST_BUILD.to_le_bytes());
        h[OFF_SECURITY_COUNTER..OFF_SECURITY_COUNTER + 4]
            .copy_from_slice(&TEST_COUNTER.to_le_bytes());
        h[OFF_PAYLOAD_LEN..OFF_PAYLOAD_LEN + 4]
            .copy_from_slice(&payload_len.to_le_bytes());
        h
    }

    // Builds a fully signed image: HEADER || payload || signature, signed with
    // `seed`'s key over HEADER || payload.
    fn build_signed_image(seed: [u8; 32], payload: &[u8]) -> Vec<u8>
    {
        let payload_len = payload.len() as u32;
        let header = build_header(payload_len);
        let mut signed = Vec::new();
        signed.extend_from_slice(&header);
        signed.extend_from_slice(payload);
        let sk = signing_key(seed);
        let sig = sk.sign(&signed);
        let mut image = signed;
        image.extend_from_slice(&sig.to_bytes());
        image
    }

    #[test]
    fn header_offsets_and_consts_are_pinned()
    {
        assert_eq!(HEADER_LEN, 24);
        assert_eq!(SIG_LEN, 64);
        assert_eq!(MAGIC, *b"PKIM");
        assert_eq!(FORMAT_VERSION, 1);
        assert_eq!(ALG_ED25519, 0x01);
        assert_eq!(OFF_MAGIC, 0);
        assert_eq!(OFF_FORMAT_VERSION, 4);
        assert_eq!(OFF_ALGORITHM, 5);
        assert_eq!(OFF_VERSION_MAJOR, 6);
        assert_eq!(OFF_VERSION_MINOR, 7);
        assert_eq!(OFF_VERSION_REVISION, 8);
        assert_eq!(OFF_VERSION_BUILD, 10);
        assert_eq!(OFF_SECURITY_COUNTER, 14);
        assert_eq!(OFF_PAYLOAD_LEN, 18);
        assert_eq!(OFF_RESERVED, 22);
    }

    #[test]
    fn valid_image_round_trips()
    {
        let payload = b"hello patina firmware payload";
        let image = build_signed_image(TEST_SEED, payload);
        let root = root_key_for(TEST_SEED);
        let v = verify_image(&image, &root).expect("valid image must verify");
        assert_eq!(v.payload(), payload);
        assert_eq!(v.security_counter(), TEST_COUNTER);
        let ver = v.image_version();
        assert_eq!(ver.major, TEST_MAJOR);
        assert_eq!(ver.minor, TEST_MINOR);
        assert_eq!(ver.revision, TEST_REVISION);
        assert_eq!(ver.build, TEST_BUILD);
    }

    #[test]
    fn empty_payload_round_trips()
    {
        let image = build_signed_image(TEST_SEED, b"");
        let root = root_key_for(TEST_SEED);
        let v = verify_image(&image, &root).expect("empty payload must verify");
        assert_eq!(v.payload(), b"");
    }

    #[test]
    fn flipped_payload_byte_is_bad_signature()
    {
        let mut image = build_signed_image(TEST_SEED, b"some payload here");
        // A payload byte sits just past the header.
        image[HEADER_LEN] ^= 0xFF;
        let root = root_key_for(TEST_SEED);
        assert_eq!(verify_image(&image, &root), Err(VerifyError::BadSignature));
    }

    #[test]
    fn wrong_magic_is_bad_magic()
    {
        let mut image = build_signed_image(TEST_SEED, b"x");
        image[OFF_MAGIC] ^= 0xFF;
        let root = root_key_for(TEST_SEED);
        assert_eq!(verify_image(&image, &root), Err(VerifyError::BadMagic));
    }

    #[test]
    fn bad_format_version_is_unsupported_format_version()
    {
        let mut image = build_signed_image(TEST_SEED, b"x");
        image[OFF_FORMAT_VERSION] = 0xEE;
        let root = root_key_for(TEST_SEED);
        assert_eq!(
            verify_image(&image, &root),
            Err(VerifyError::UnsupportedFormatVersion)
        );
    }

    #[test]
    fn wrong_algorithm_is_unsupported_algorithm()
    {
        let mut image = build_signed_image(TEST_SEED, b"x");
        image[OFF_ALGORITHM] = 0x02;
        let root = root_key_for(TEST_SEED);
        assert_eq!(
            verify_image(&image, &root),
            Err(VerifyError::UnsupportedAlgorithm)
        );
    }

    #[test]
    fn truncated_below_floor_is_too_short()
    {
        let image = build_signed_image(TEST_SEED, b"x");
        let root = root_key_for(TEST_SEED);
        let short = &image[..HEADER_LEN + SIG_LEN - 1];
        assert_eq!(verify_image(short, &root), Err(VerifyError::TooShort));
    }

    #[test]
    fn declared_payload_len_too_big_is_length_mismatch()
    {
        let mut image = build_signed_image(TEST_SEED, b"abc");
        // Inflate the declared payload_len by one.
        let inflated = (3u32 + 1).to_le_bytes();
        image[OFF_PAYLOAD_LEN..OFF_PAYLOAD_LEN + 4].copy_from_slice(&inflated);
        let root = root_key_for(TEST_SEED);
        assert_eq!(verify_image(&image, &root), Err(VerifyError::LengthMismatch));
    }

    #[test]
    fn declared_payload_len_too_small_is_length_mismatch()
    {
        let mut image = build_signed_image(TEST_SEED, b"abc");
        let deflated = 2u32.to_le_bytes();
        image[OFF_PAYLOAD_LEN..OFF_PAYLOAD_LEN + 4].copy_from_slice(&deflated);
        let root = root_key_for(TEST_SEED);
        assert_eq!(verify_image(&image, &root), Err(VerifyError::LengthMismatch));
    }

    #[test]
    fn trailing_byte_is_length_mismatch()
    {
        let mut image = build_signed_image(TEST_SEED, b"abc");
        image.push(0x00);
        let root = root_key_for(TEST_SEED);
        assert_eq!(verify_image(&image, &root), Err(VerifyError::LengthMismatch));
    }

    #[test]
    fn overflowing_payload_len_is_length_mismatch()
    {
        let mut image = build_signed_image(TEST_SEED, b"abc");
        let huge = u32::MAX.to_le_bytes();
        image[OFF_PAYLOAD_LEN..OFF_PAYLOAD_LEN + 4].copy_from_slice(&huge);
        let root = root_key_for(TEST_SEED);
        assert_eq!(verify_image(&image, &root), Err(VerifyError::LengthMismatch));
    }

    #[test]
    fn wrong_signing_key_is_bad_signature()
    {
        // Signed with TEST_SEED, verified under OTHER_SEED's public key.
        let image = build_signed_image(TEST_SEED, b"payload");
        let root = root_key_for(OTHER_SEED);
        assert_eq!(verify_image(&image, &root), Err(VerifyError::BadSignature));
    }

    #[test]
    fn bad_signature_image_exposes_nothing()
    {
        // The function returns Err, so no VerifiedImage exists and the signed
        // fields are never readable on a tampered image.
        let mut image = build_signed_image(TEST_SEED, b"payload");
        image[HEADER_LEN] ^= 0x01;
        let root = root_key_for(TEST_SEED);
        let result = verify_image(&image, &root);
        assert!(result.is_err());
        assert_eq!(result, Err(VerifyError::BadSignature));
    }

    #[test]
    fn security_counter_tamper_is_bad_signature()
    {
        // Flipping a byte of the signed security_counter must break the
        // signature, proving the anti-rollback counter is bound by it.
        let mut image = build_signed_image(TEST_SEED, b"payload");
        image[OFF_SECURITY_COUNTER] ^= 0xFF;
        let root = root_key_for(TEST_SEED);
        assert_eq!(verify_image(&image, &root), Err(VerifyError::BadSignature));
    }

    #[test]
    fn image_version_tamper_is_bad_signature()
    {
        // Flipping a byte inside the signed image_version range must break the
        // signature, proving the firmware version is bound by it.
        let mut image = build_signed_image(TEST_SEED, b"payload");
        image[OFF_VERSION_BUILD] ^= 0xFF;
        let root = root_key_for(TEST_SEED);
        assert_eq!(verify_image(&image, &root), Err(VerifyError::BadSignature));
    }

    #[test]
    fn nonzero_reserved_is_reserved_not_zero()
    {
        // Set a reserved byte BEFORE signing so the signature is genuinely
        // valid. The rejection then proves the reserved check is structural,
        // not a side effect of a broken signature.
        let payload = b"payload";
        let payload_len = payload.len() as u32;
        let mut header = build_header(payload_len);
        header[OFF_RESERVED] = 0x01;
        let mut signed = Vec::new();
        signed.extend_from_slice(&header);
        signed.extend_from_slice(payload);
        let sk = signing_key(TEST_SEED);
        let sig = sk.sign(&signed);
        let mut image = signed;
        image.extend_from_slice(&sig.to_bytes());
        let root = root_key_for(TEST_SEED);
        assert_eq!(
            verify_image(&image, &root),
            Err(VerifyError::ReservedNotZero)
        );
    }

    #[test]
    fn from_bytes_rejects_non_canonical_key()
    {
        // The encoding y = 2 (little-endian [0x02, 0x00, ...]) is not a
        // decompressible Edwards point: 1 - y^2 over 1 - d*y^2 is a non-square,
        // so dalek's from_bytes rejects it at construction.
        let mut bad = [0u8; 32];
        bad[0] = 2;
        match RootKey::from_bytes(bad)
        {
            Err(e) => assert_eq!(e, VerifyError::BadRootKey),
            Ok(_) => panic!("a non-canonical key must be rejected"),
        }
    }

    #[test]
    fn from_bytes_accepts_valid_key()
    {
        let sk = signing_key(TEST_SEED);
        let pk = sk.verifying_key().to_bytes();
        assert!(RootKey::from_bytes(pk).is_ok());
    }

    // Pins that the fuzz seam's fixed root key is a key dalek actually accepts,
    // so the fuzz target truly drives verify_image rather than silently skipping
    // on a rejected key. The constant is the public key of the all-0x01 secret
    // scalar.
    #[test]
    fn fuzz_root_key_is_accepted()
    {
        let sk = signing_key([0x01u8; 32]);
        let expected = sk.verifying_key().to_bytes();
        const FUZZ_ROOT_KEY: [u8; 32] = [
            0x8a, 0x88, 0xe3, 0xdd, 0x74, 0x09, 0xf1, 0x95,
            0xfd, 0x52, 0xdb, 0x2d, 0x3c, 0xba, 0x5d, 0x72,
            0xca, 0x67, 0x09, 0xbf, 0x1d, 0x94, 0x12, 0x1b,
            0xf3, 0x74, 0x88, 0x01, 0xb4, 0x0f, 0x6f, 0x5c,
        ];
        assert_eq!(FUZZ_ROOT_KEY, expected);
        assert!(RootKey::from_bytes(FUZZ_ROOT_KEY).is_ok());
    }
}
