//! Host-side signing library for the patina_key signed firmware-image format.
//!
//! Builds a complete `HEADER || PAYLOAD || SIGNATURE` image from a payload, a
//! firmware version, a security counter, and a signing backend. The header bytes
//! come from `image_verify::encode_header`, so the layout has a single source of
//! truth. After signing, the output is re-verified with
//! `image_verify::verify_image`, so a malformed image cannot leave the tool.
//!
//! # Key model
//!
//! The signature is ECDSA P-256 over SHA-256. The private key signs here,
//! on the integrator PC. The matching public key is pinned into the firmware and
//! verifies on the device. The private key never touches the device.
//!
//! # Deterministic signing
//!
//! ECDSA needs a fresh, unbiased nonce `k` per signature. A repeated or biased `k`
//! leaks the private key from two signatures. That foot-gun lives entirely on the
//! signing side.
//!
//! [`SoftwareSigner`] derives `k` by RFC 6979 from the private key and the message
//! digest, with no RNG. The same message and key give the same signature, and two
//! different messages cannot collide on a `k`. The randomized signing variants are
//! deliberately not used.
//!
//! # Backend seam
//!
//! [`ImageSigner`] abstracts the signing operation, so a backend change does not
//! rework the caller. [`SoftwareSigner`] is the only implementation and serves
//! bring-up iteration only. 
//! Production signing does NOT go through this trait: the
//! root key lives in a hardware token and never enters this process, so a release
//! uses the two-step external flow ([`prepare_external`] then
//! [`finalize_external`]), where the operator signs the digest offline.
//!
//! # Low-s normalization
//!
//! The device accepts only the low-s encoding of a signature (see
//! `image_verify::verify_image`). A raw ECDSA signer emits high-s about half the
//! time, so [`build_signed_image`] normalizes whatever the backend returns. `(r, s)`
//! and `(r, n - s)` are both valid over the same message, so the normalized form
//! authenticates exactly what the backend signed. Doing it centrally means a future
//! hardware backend needs no special handling.

#![forbid(unsafe_code)]

mod bank;
mod external;

pub use bank::AssembledBank;
pub use bank::BankError;
pub use bank::assemble_bank;
pub use external::DIGEST_LEN;
pub use external::PreparedExternal;
pub use external::SigFormat;
pub use external::finalize_external;
pub use external::parse_signature;
pub use external::prepare_external;
pub use bank::BANK_SIZE;
pub use bank::BOOT_LEN;
pub use bank::BOOT_OFFSET;
pub use bank::DESCRIPTOR_LEN;
pub use bank::DESCRIPTOR_OFFSET;
pub use bank::FILL;
pub use bank::NS_LEN;
pub use bank::NS_OFFSET;
pub use bank::PAGE_SIZE;
pub use bank::SECURE_LEN;
pub use bank::SECURE_OFFSET;

use image_verify::ImageVersion;
use image_verify::ROOT_KEY_LEN;
use image_verify::RootKey;
use image_verify::SIG_LEN;
use image_verify::encode_header;
use image_verify::verify_image;
use p256::ecdsa::Signature;
use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::Signer;
use zeroize::Zeroizing;

/// Why a signing operation failed.
///
/// Every variant is fail-closed: the tool produces no image on any of them. No
/// variant carries key material, so an error can be printed safely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignError
{
    /// The supplied private key was not exactly 32 bytes.
    BadKeyLength,
    /// The 32 bytes are not a valid P-256 private scalar. A scalar must lie in
    /// `[1, n-1]`: all-zero and any value at or above the curve order are rejected.
    /// Not every 32-byte value is a valid P-256 key, so this check is load-bearing.
    InvalidScalar,
    /// The payload length does not fit in the `u32` header field.
    PayloadTooLarge,
    /// The signer's public key was not a point the verifier accepts, so the
    /// round-trip self-check could not even build a root key.
    BadPublicKey,
    /// The backend returned bytes that are not a well-formed `(r, s)` scalar
    /// pair, so no image could be assembled.
    BadSignatureEncoding,
    /// The freshly built image failed its own `verify_image` round-trip check.
    /// This must never happen: it means the encoder, the signer, and the
    /// verifier disagree.
    RoundTripFailed,
}

impl core::fmt::Display for SignError
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
    {
        match self
        {
            SignError::BadKeyLength =>
            {
                write!(f, "the private key was not exactly 32 bytes")
            }
            SignError::InvalidScalar =>
            {
                write!(
                    f,
                    "the 32 bytes are not a valid P-256 private scalar, it must \
                     be non-zero and below the curve order"
                )
            }
            SignError::PayloadTooLarge =>
            {
                write!(f, "the payload is too large to fit the 32-bit header length field")
            }
            SignError::BadPublicKey =>
            {
                write!(f, "the signer reported a public key the verifier does not accept")
            }
            SignError::BadSignatureEncoding =>
            {
                write!(f, "the signing backend returned bytes that are not a valid ECDSA (r, s) pair")
            }
            SignError::RoundTripFailed =>
            {
                write!(
                    f,
                    "ALARM: the freshly signed image failed its own verify \
                     round-trip, the encoder, signer, and verifier disagree, \
                     no image was written"
                )
            }
        }
    }
}

/// A pluggable ECDSA P-256 signing backend over the firmware-image bytes.
///
/// The signer signs the exact `HEADER || PAYLOAD` message it is handed and reports
/// its own public key, so the caller can pin it and self-check the result.
///
/// # Contract
///
/// - `sign` returns the 64-byte `r || s` pair, two 32-byte big-endian scalars, with
///   no ASN.1 framing. The nonce must be fresh and unbiased for every message. RFC
///   6979 determinism satisfies that, as does a hardware token that generates `k`
///   internally.
/// - The s half need not be low-s normalized: [`build_signed_image`] normalizes it.
///   A backend that cannot normalize is still usable.
/// - `public_key` returns the 65-byte uncompressed SEC1 point matching the signing
///   key.
///
/// A YubiKey PIV backend implements this same trait, so the
/// private key can live in hardware with PIN plus touch enforced. Not implemented
/// here.
pub trait ImageSigner
{
    /// Signs `message` and returns the 64-byte ECDSA `r || s` signature.
    fn sign(&self, message: &[u8]) -> [u8; SIG_LEN];

    /// Returns the 65-byte uncompressed SEC1 public key matching the signing key.
    fn public_key(&self) -> [u8; ROOT_KEY_LEN];
}

/// A software ECDSA P-256 signer built from a raw 32-byte private scalar.
///
/// The 32 bytes are the big-endian private scalar `d`, which must lie in `[1, n-1]`.
/// The tool implements no passphrase crypto: a passphrase-protected key is decrypted
/// out of band (for example by age or gpg) and handed to the CLI through
/// `--key-file`, as a path or piped from stdin via `-`, then to this signer as raw
/// bytes.
///
/// Signing is RFC 6979 deterministic. See the module docs for why that matters.
pub struct SoftwareSigner
{
    key: SigningKey,
}

impl SoftwareSigner
{
    /// Builds a software signer from a raw 32-byte P-256 private scalar.
    ///
    /// # Errors
    ///
    /// Returns [`SignError::InvalidScalar`] if the bytes are not a scalar in
    /// `[1, n-1]`. Not every 32-byte value is a valid P-256 private key.
    pub fn from_key(key: &[u8; 32]) -> Result<SoftwareSigner, SignError>
    {
        let key = SigningKey::from_slice(key)
            .map_err(|_| SignError::InvalidScalar)?;
        Ok(SoftwareSigner { key })
    }

    /// Builds a software signer from a private-key slice of unknown length.
    ///
    /// # Errors
    ///
    /// [`SignError::BadKeyLength`] if the slice is not exactly 32 bytes,
    /// [`SignError::InvalidScalar`] if those 32 bytes are not a scalar in
    /// `[1, n-1]`.
    pub fn from_slice(key: &[u8]) -> Result<SoftwareSigner, SignError>
    {
        let arr: Zeroizing<[u8; 32]> = key
            .try_into()
            .map(Zeroizing::new)
            .map_err(|_| SignError::BadKeyLength)?;
        SoftwareSigner::from_key(&arr)
    }
}

impl ImageSigner for SoftwareSigner
{
    fn sign(&self, message: &[u8]) -> [u8; SIG_LEN]
    {
        // Derives the nonce by RFC 6979 from the key and the message digest. No RNG
        // runs, and no nonce is reused across two different messages.
        let signature: Signature = self.key.sign(message);
        let mut out = [0u8; SIG_LEN];
        out.copy_from_slice(&signature.to_bytes());
        out
    }

    fn public_key(&self) -> [u8; ROOT_KEY_LEN]
    {
        let point = self.key.verifying_key().to_sec1_point(false);
        let mut out = [0u8; ROOT_KEY_LEN];
        // The uncompressed SEC1 encoding of a P-256 point is exactly 65 bytes.
        // On the impossible short branch the buffer stays all-zero, 
        // which is not a point on the curve, so
        // RootKey::from_bytes rejects it and build_signed_image fails closed with
        // BadPublicKey rather than emitting a wrong image.
        let bytes = point.as_ref();
        if bytes.len() == ROOT_KEY_LEN
        {
            out.copy_from_slice(bytes);
        }
        out
    }
}

/// Derives the 65-byte uncompressed SEC1 public key from a 32-byte private key.
///
/// The returned bytes are the value to pin into the firmware as the root key. `pub`
/// so an external CI consumer can derive the pinned key programmatically, the same
/// value the `derive-pubkey` subcommand prints.
///
/// # Errors
///
/// [`SignError::InvalidScalar`] if the bytes are not a scalar in `[1, n-1]`.
pub fn derive_public_key(key: &[u8; 32]) -> Result<[u8; ROOT_KEY_LEN], SignError>
{
    Ok(SoftwareSigner::from_key(key)?.public_key())
}

/// Builds a complete signed firmware image and self-checks it.
///
/// The signature the backend returns is normalized to low-s before it enters the
/// image, the only encoding the device accepts. The round-trip self-check proves
/// the image is internally consistent under the signer's own reported public key. It
/// does not prove that key is the one the operator intended: to guard a wrong key
/// file, the caller must compare `signer.public_key()` against an expected value out
/// of band (the `sign` subcommand offers `--expect-pubkey` for that).
///
/// # Arguments
///
/// - `payload`: the firmware binary bytes that follow the header.
/// - `version`: the firmware version to embed in the signed header.
/// - `security_counter`: the monotonic anti-rollback counter to embed.
/// - `signer`: the signing backend over `HEADER || PAYLOAD`.
///
/// # Returns
///
/// The full `HEADER || PAYLOAD || SIGNATURE` image bytes.
///
/// # Errors
///
/// - [`SignError::PayloadTooLarge`] if the payload length exceeds `u32`.
/// - [`SignError::BadSignatureEncoding`] if the backend's bytes are not a valid
///   `(r, s)` pair.
/// - [`SignError::BadPublicKey`] if the signer's public key is not on-curve.
/// - [`SignError::RoundTripFailed`] if `verify_image` rejects the built image
///   under the signer's own public key. The image is withheld on any of these.
pub fn build_signed_image
(
    payload: &[u8],
    version: ImageVersion,
    security_counter: u32,
    signer: &dyn ImageSigner,
)
    -> Result<Vec<u8>, SignError>
{
    let payload_len: u32 = payload
        .len()
        .try_into()
        .map_err(|_| SignError::PayloadTooLarge)?;

    let header = encode_header(version, security_counter, payload_len);

    // The signed region is HEADER || PAYLOAD. Build it once, sign it, then append
    // the trailing signature.
    let mut image = Vec::with_capacity(header.len() + payload.len() + SIG_LEN);
    image.extend_from_slice(&header);
    image.extend_from_slice(payload);

    let raw = signer.sign(&image);
    let signature = Signature::from_slice(&raw)
        .map_err(|_| SignError::BadSignatureEncoding)?;
    // Canonicalize to low-s, the only encoding the device accepts. (r, n - s) is as
    // valid as (r, s) over the same message, so this changes the bytes and not what
    // they authenticate.
    let signature = signature.normalize_s();
    image.extend_from_slice(&signature.to_bytes());

    // Round-trip self-check: re-verify the exact bytes about to be emitted, under the
    // signer's own public key, through the same segmented verifier the device runs. A
    // malformed image cannot leave the tool.
    let root = RootKey::from_bytes(signer.public_key())
        .map_err(|_| SignError::BadPublicKey)?;
    let segments: [&[u8]; 1] = [&image];
    verify_image(&segments, &root).map_err(|_| SignError::RoundTripFailed)?;

    Ok(image)
}

#[cfg(test)]
mod tests
{
    use super::*;

    // A fixed private scalar: non-zero and far below the curve order, so it is a
    // valid P-256 key and yields a stable key pair with no RNG.
    const KEY: [u8; 32] = [3u8; 32];

    fn signer() -> SoftwareSigner
    {
        SoftwareSigner::from_key(&KEY).expect("the test scalar is valid")
    }

    fn version() -> ImageVersion
    {
        ImageVersion
        {
            major: 1,
            minor: 2,
            revision: 0x0304,
            build: 0x0506_0708,
        }
    }

    // Concatenates the verified payload segments so a test can compare bytes.
    fn payload_of(image: &[u8], root: &RootKey) -> Vec<u8>
    {
        let segments: [&[u8]; 1] = [image];
        let verified = verify_image(&segments, root).expect("verify");
        let mut out = Vec::new();
        for piece in verified.payload_segments()
        {
            out.extend_from_slice(piece);
        }
        out
    }

    #[test]
    fn builds_an_image_the_verifier_accepts()
    {
        let signer = signer();
        let payload = b"firmware payload bytes";
        let image = build_signed_image(payload, version(), 11, &signer)
            .expect("build must succeed");

        let root = RootKey::from_bytes(signer.public_key())
            .expect("public key on-curve");
        assert_eq!(payload_of(&image, &root), payload);

        let segments: [&[u8]; 1] = [&image];
        let verified = verify_image(&segments, &root).expect("verify");
        assert_eq!(verified.security_counter(), 11);
    }

    #[test]
    fn version_fields_survive_the_round_trip()
    {
        let signer = signer();
        let image = build_signed_image(b"x", version(), 1, &signer).expect("build");

        let root = RootKey::from_bytes(signer.public_key()).expect("key");
        let segments: [&[u8]; 1] = [&image];
        let v = verify_image(&segments, &root)
            .expect("verify")
            .image_version();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 2);
        assert_eq!(v.revision, 0x0304);
        assert_eq!(v.build, 0x0506_0708);
    }

    #[test]
    fn empty_payload_round_trips()
    {
        let signer = signer();
        let image = build_signed_image(b"", version(), 0, &signer)
            .expect("build empty");
        let root = RootKey::from_bytes(signer.public_key()).expect("key");
        assert_eq!(payload_of(&image, &root), b"");
    }

    #[test]
    fn derive_public_key_matches_signer()
    {
        let signer = signer();
        assert_eq!(
            derive_public_key(&KEY).expect("valid scalar"),
            signer.public_key()
        );
    }

    // The public key is the uncompressed SEC1 encoding: 65 bytes, tag 0x04. This
    // pins the encoding the firmware pins.
    #[test]
    fn the_public_key_is_an_uncompressed_sec1_point()
    {
        let key = signer().public_key();
        assert_eq!(key.len(), 65);
        assert_eq!(key[0], 0x04, "the uncompressed SEC1 tag");
        assert!(RootKey::from_bytes(key).is_ok());
    }

    // An all-zero private key is not a valid P-256 scalar, so it must fail closed.
    #[test]
    fn an_all_zero_key_is_an_invalid_scalar()
    {
        assert_eq!(
            SoftwareSigner::from_key(&[0u8; 32]).err(),
            Some(SignError::InvalidScalar)
        );
    }

    // A key at or above the curve order n is out of range. n itself is the
    // smallest such value, so it is the exact boundary case.
    #[test]
    fn a_key_at_the_curve_order_is_an_invalid_scalar()
    {
        // n = FFFFFFFF 00000000 FFFFFFFF FFFFFFFF BCE6FAAD A7179E84 F3B9CAC2 FC632551
        let order: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
            0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
        ];
        assert_eq!(
            SoftwareSigner::from_key(&order).err(),
            Some(SignError::InvalidScalar)
        );

        // All-0xFF is far above n, so it is rejected too.
        assert_eq!(
            SoftwareSigner::from_key(&[0xFFu8; 32]).err(),
            Some(SignError::InvalidScalar)
        );
    }

    // n - 1 is the largest valid scalar, so it must be accepted.
    #[test]
    fn the_largest_valid_scalar_is_accepted()
    {
        let order_minus_one: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
            0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x50,
        ];
        assert!(SoftwareSigner::from_key(&order_minus_one).is_ok());
    }

    #[test]
    fn from_slice_rejects_a_short_key()
    {
        let short = [1u8; 31];
        assert_eq!(
            SoftwareSigner::from_slice(&short).err(),
            Some(SignError::BadKeyLength)
        );
    }

    #[test]
    fn from_slice_rejects_a_long_key()
    {
        let long = [1u8; 33];
        assert_eq!(
            SoftwareSigner::from_slice(&long).err(),
            Some(SignError::BadKeyLength)
        );
    }

    #[test]
    fn from_slice_accepts_exactly_32_valid_bytes()
    {
        let key = [4u8; 32];
        let signer = SoftwareSigner::from_slice(&key).expect("32 valid bytes ok");
        assert_eq!(
            signer.public_key(),
            derive_public_key(&key).expect("valid scalar")
        );
    }

    // Signing is RFC 6979 deterministic: the same message and key produce the same
    // signature, byte for byte.
    #[test]
    fn signing_is_deterministic()
    {
        let signer = signer();
        let message = b"the same message signed twice";
        assert_eq!(signer.sign(message), signer.sign(message));
        assert_ne!(signer.sign(b"message one"), signer.sign(b"message two"));
    }

    // A whole image built twice is byte-identical, so a release is reproducible.
    #[test]
    fn the_built_image_is_reproducible()
    {
        let signer = signer();
        let a = build_signed_image(b"reproducible", version(), 3, &signer)
            .expect("build a");
        let b = build_signed_image(b"reproducible", version(), 3, &signer)
            .expect("build b");
        assert_eq!(a, b);
    }

    // The low-s policy from the signing side. A backend that returns a high-s
    // signature must still yield an image the device accepts, because the tool
    // normalizes.
    #[test]
    fn a_high_s_backend_is_normalized_into_an_acceptable_image()
    {
        struct HighSSigner
        {
            inner: SoftwareSigner,
        }

        impl ImageSigner for HighSSigner
        {
            fn sign(&self, message: &[u8]) -> [u8; SIG_LEN]
            {
                let raw = self.inner.sign(message);
                let sig = Signature::from_slice(&raw).expect("the inner sig parses");
                let low = sig.normalize_s();
                let (r, s) = low.split_scalars();
                let flipped = Signature::from_scalars(r, -s).expect("n - s is valid");
                let mut out = [0u8; SIG_LEN];
                out.copy_from_slice(&flipped.to_bytes());
                out
            }

            fn public_key(&self) -> [u8; ROOT_KEY_LEN]
            {
                self.inner.public_key()
            }
        }

        let backend = HighSSigner { inner: signer() };
        let payload = b"high-s backend payload";

        // The raw backend output really is high-s, so the normalization below has
        // real work to do.
        let raw = backend.sign(b"probe");
        let probe = Signature::from_slice(&raw).expect("parses");
        assert!(
            bool::from(p256::elliptic_curve::scalar::IsHigh::is_high(&probe.s())),
            "the test backend must actually emit high-s"
        );

        // The image still builds, and the round-trip self-check inside
        // build_signed_image is what proves the device accepts it.
        let image = build_signed_image(payload, version(), 1, &backend)
            .expect("a high-s backend must still produce a valid image");
        let root = RootKey::from_bytes(backend.public_key()).expect("key");
        assert_eq!(payload_of(&image, &root), payload);

        // And the emitted signature is the low-s twin, byte for byte the same as the
        // software signer's own normalized output.
        let start = image.len() - SIG_LEN;
        let emitted = Signature::from_slice(&image[start..]).expect("parses");
        assert!(!bool::from(p256::elliptic_curve::scalar::IsHigh::is_high(&emitted.s())));
    }

    // A flipped output byte must fail verification, proving the self-check inside
    // build_signed_image has something real to catch.
    #[test]
    fn a_flipped_output_byte_fails_verification()
    {
        let signer = signer();
        let mut image = build_signed_image(b"payload", version(), 1, &signer)
            .expect("build");
        // Flip a payload byte (just past the 24-byte header).
        image[24] ^= 0xFF;
        let root = RootKey::from_bytes(signer.public_key()).expect("key");
        let segments: [&[u8]; 1] = [&image];
        assert!(verify_image(&segments, &root).is_err());
    }

    // A backend that returns a well-formed but wrong signature must be caught by the
    // self-check, so the tool never emits an unverifiable image.
    #[test]
    fn a_lying_signer_is_caught_by_the_self_check()
    {
        struct LyingSigner
        {
            inner: SoftwareSigner,
        }

        impl ImageSigner for LyingSigner
        {
            fn sign(&self, _message: &[u8]) -> [u8; SIG_LEN]
            {
                // A well-formed (r, s) pair over a different message, so it parses
                // cleanly and only the verify can catch it.
                self.inner.sign(b"a message that is not the image")
            }

            fn public_key(&self) -> [u8; ROOT_KEY_LEN]
            {
                self.inner.public_key()
            }
        }

        let signer = LyingSigner { inner: signer() };
        let result = build_signed_image(b"payload", version(), 1, &signer);
        assert_eq!(result.err(), Some(SignError::RoundTripFailed));
    }

    // A backend that returns garbage bytes fails at the parse, before any image is
    // assembled.
    #[test]
    fn a_malformed_backend_signature_is_rejected()
    {
        struct GarbageSigner
        {
            inner: SoftwareSigner,
        }

        impl ImageSigner for GarbageSigner
        {
            fn sign(&self, _message: &[u8]) -> [u8; SIG_LEN]
            {
                // r = s = 0 is not a valid scalar pair.
                [0u8; SIG_LEN]
            }

            fn public_key(&self) -> [u8; ROOT_KEY_LEN]
            {
                self.inner.public_key()
            }
        }

        let signer = GarbageSigner { inner: signer() };
        let result = build_signed_image(b"payload", version(), 1, &signer);
        assert_eq!(result.err(), Some(SignError::BadSignatureEncoding));
    }
}
