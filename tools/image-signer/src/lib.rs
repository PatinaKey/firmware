//! Host-side signing library for the patina_key signed firmware-image format.
//!
//! It builds a complete `HEADER || PAYLOAD || SIGNATURE` image from a payload, a
//! firmware version, a security counter, and a signing backend. The header bytes
//! come from `image_verify::encode_header`, so the layout has a single source of
//! truth. After signing, the library RE-VERIFIES its own output with
//! `image_verify::verify_image` so a malformed image can never leave the tool.
//!
//! # Key model
//!
//! The PRIVATE key signs here, offline, on the integrator PC. The matching
//! PUBLIC key is pinned into the firmware and verifies on the device. The private
//! key never touches the device. Moving from a dev key to a production key is a
//! reversible recompile that swaps the pinned public key, not a one-way gate.
//!
//! # Backend seam
//!
//! [`ImageSigner`] abstracts the signing operation so a future hardware-token
//! backend (a PIV-Ed25519 card) drops in without reworking the caller. Only the
//! software backend [`SoftwareSigner`] ships today.

#![forbid(unsafe_code)]

use ed25519_dalek::SigningKey;
use ed25519_dalek::ed25519::signature::Signer;
use image_verify::ImageVersion;
use image_verify::RootKey;
use image_verify::SIG_LEN;
use image_verify::encode_header;
use image_verify::verify_image;
use zeroize::Zeroizing;

/// Why a signing operation failed.
///
/// Every variant is fail-closed: the tool produces no image on any of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignError
{
    /// The supplied seed was not exactly 32 bytes.
    BadSeedLength,
    /// The payload length does not fit in the `u32` header field.
    PayloadTooLarge,
    /// The signer's public key was not a point Ed25519 accepts, so the
    /// round-trip self-check could not even build a root key.
    BadPublicKey,
    /// The freshly built image failed its own `verify_image` round-trip check.
    /// This must never happen: it means the encoder, the signer, and the
    /// verifier disagree, so the image is withheld.
    RoundTripFailed,
}

impl core::fmt::Display for SignError
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
    {
        match self
        {
            SignError::BadSeedLength =>
            {
                write!(f, "the seed was not exactly 32 bytes")
            }
            SignError::PayloadTooLarge =>
            {
                write!(f, "the payload is too large to fit the 32-bit header length field")
            }
            SignError::BadPublicKey =>
            {
                write!(f, "the signer reported a public key Ed25519 does not accept")
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

/// A pluggable Ed25519 signing backend over the firmware-image bytes.
///
/// The signer signs the exact `HEADER || PAYLOAD` message it is handed and
/// reports its own public key, so the caller can pin it and self-check the
/// result. A future hardware-token backend implements this same trait.
pub trait ImageSigner
{
    /// Signs `message` and returns the 64-byte Ed25519 signature.
    fn sign(&self, message: &[u8]) -> [u8; SIG_LEN];

    /// Returns the 32-byte Ed25519 public key matching the signing key.
    fn public_key(&self) -> [u8; 32];
}

/// A software Ed25519 signer built from a raw 32-byte seed.
///
/// The seed is the RFC 8032 Ed25519 private scalar. The tool implements no
/// passphrase crypto: a passphrase-protected seed is decrypted out of band (for
/// example by age or gpg) and handed to the CLI through `--key-file`, as a path
/// or piped from stdin via `-`, then to this signer as raw bytes. That keeps the
/// audit surface minimal.
pub struct SoftwareSigner
{
    // Debug and Clone are intentionally NOT derived because the field is a
    // private signing key, so it can never reach logs or be silently
    // duplicated. The inner SigningKey zeroizes on drop through ed25519-dalek's
    // zeroize feature.
    key: SigningKey,
}

impl SoftwareSigner
{
    /// Builds a software signer from a raw 32-byte Ed25519 seed.
    ///
    /// This is infallible. Every 32-byte value is a valid Ed25519 seed, and the
    /// fixed-size argument makes a wrong length impossible at the type level.
    /// The fallible path for a slice of unknown length is
    /// [`SoftwareSigner::from_slice`].
    pub fn from_seed(seed: &[u8; 32]) -> SoftwareSigner
    {
        SoftwareSigner
        {
            key: SigningKey::from_bytes(seed),
        }
    }

    /// Builds a software signer from a seed slice of unknown length.
    ///
    /// # Errors
    ///
    /// Returns [`SignError::BadSeedLength`] if the slice is not exactly 32 bytes.
    pub fn from_slice(seed: &[u8]) -> Result<SoftwareSigner, SignError>
    {
        let arr: Zeroizing<[u8; 32]> = seed
            .try_into()
            .map(Zeroizing::new)
            .map_err(|_| SignError::BadSeedLength)?;
        Ok(SoftwareSigner::from_seed(&arr))
    }
}

impl ImageSigner for SoftwareSigner
{
    fn sign(&self, message: &[u8]) -> [u8; SIG_LEN]
    {
        self.key.sign(message).to_bytes()
    }

    fn public_key(&self) -> [u8; 32]
    {
        self.key.verifying_key().to_bytes()
    }
}

/// Derives the 32-byte Ed25519 public key from a raw 32-byte seed.
///
/// The returned bytes are the value to pin into the firmware as the root key.
/// Kept `pub` as a deliberate library API so an external CI consumer can derive
/// the pinned key programmatically, the same value the `derive-pubkey`
/// subcommand prints.
pub fn derive_public_key(seed: &[u8; 32]) -> [u8; 32]
{
    SoftwareSigner::from_seed(seed).public_key()
}

/// Builds a complete signed firmware image and self-checks it.
///
/// The round-trip self-check proves the image is internally consistent under
/// the signer's OWN reported public key. It does NOT prove that key is the one
/// the operator intended. To guard the wrong-key-file error, the caller must
/// compare `signer.public_key()` against an expected value out of band (the
/// `sign` subcommand offers `--expect-pubkey` for that).
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

    // The signed region is HEADER || PAYLOAD. Build it once, sign it, then
    // append the trailing signature.
    let mut image = Vec::with_capacity(header.len() + payload.len() + SIG_LEN);
    image.extend_from_slice(&header);
    image.extend_from_slice(payload);

    let signature = signer.sign(&image);
    image.extend_from_slice(&signature);

    // Round-trip self-check: re-verify the bytes we are about to emit under the
    // signer's own public key. A malformed image can never leave the tool.
    let root = RootKey::from_bytes(signer.public_key())
        .map_err(|_| SignError::BadPublicKey)?;
    verify_image(&image, &root).map_err(|_| SignError::RoundTripFailed)?;

    Ok(image)
}

#[cfg(test)]
mod tests
{
    use super::*;

    // A fixed seed yields a stable key pair, no RNG.
    const SEED: [u8; 32] = [3u8; 32];

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

    #[test]
    fn builds_an_image_the_verifier_accepts()
    {
        let signer = SoftwareSigner::from_seed(&SEED);
        let payload = b"firmware payload bytes";
        let image = build_signed_image(payload, version(), 11, &signer)
            .expect("build must succeed");

        let root = RootKey::from_bytes(signer.public_key())
            .expect("public key on-curve");
        let verified = verify_image(&image, &root).expect("verify");
        assert_eq!(verified.payload(), payload);
        assert_eq!(verified.security_counter(), 11);
    }

    #[test]
    fn version_fields_survive_the_round_trip()
    {
        let signer = SoftwareSigner::from_seed(&SEED);
        let image = build_signed_image(b"x", version(), 1, &signer)
            .expect("build");

        let root = RootKey::from_bytes(signer.public_key()).expect("key");
        let v = verify_image(&image, &root).expect("verify").image_version();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 2);
        assert_eq!(v.revision, 0x0304);
        assert_eq!(v.build, 0x0506_0708);
    }

    #[test]
    fn empty_payload_round_trips()
    {
        let signer = SoftwareSigner::from_seed(&SEED);
        let image = build_signed_image(b"", version(), 0, &signer)
            .expect("build empty");
        let root = RootKey::from_bytes(signer.public_key()).expect("key");
        let verified = verify_image(&image, &root).expect("verify");
        assert_eq!(verified.payload(), b"");
    }

    #[test]
    fn derive_public_key_matches_signer()
    {
        let signer = SoftwareSigner::from_seed(&SEED);
        assert_eq!(derive_public_key(&SEED), signer.public_key());
    }

    #[test]
    fn dev_seed_derives_the_pinned_dev_root_key()
    {
        // The all-0x01 dev seed must derive exactly the public key the firmware
        // pins for the bench. This pins the tool to the existing dev key model.
        const DEV_ROOT_KEY: [u8; 32] = [
            0x8a, 0x88, 0xe3, 0xdd, 0x74, 0x09, 0xf1, 0x95,
            0xfd, 0x52, 0xdb, 0x2d, 0x3c, 0xba, 0x5d, 0x72,
            0xca, 0x67, 0x09, 0xbf, 0x1d, 0x94, 0x12, 0x1b,
            0xf3, 0x74, 0x88, 0x01, 0xb4, 0x0f, 0x6f, 0x5c,
        ];
        assert_eq!(derive_public_key(&[1u8; 32]), DEV_ROOT_KEY);
    }

    #[test]
    fn from_slice_rejects_a_short_seed()
    {
        let short = [0u8; 31];
        assert_eq!(
            SoftwareSigner::from_slice(&short).err(),
            Some(SignError::BadSeedLength)
        );
    }

    #[test]
    fn from_slice_rejects_a_long_seed()
    {
        let long = [0u8; 33];
        assert_eq!(
            SoftwareSigner::from_slice(&long).err(),
            Some(SignError::BadSeedLength)
        );
    }

    #[test]
    fn from_slice_accepts_exactly_32_bytes()
    {
        let seed = [4u8; 32];
        let signer = SoftwareSigner::from_slice(&seed).expect("32 bytes ok");
        assert_eq!(signer.public_key(), derive_public_key(&seed));
    }

    // A flipped output byte must fail the round-trip self-check. A signer that
    // corrupts its own signature output models a buggy or hostile backend: the
    // self-check inside build_signed_image must catch it. Here we test the
    // self-check directly by tampering after a clean build, proving verify_image
    // rejects what the tool would refuse to emit.
    #[test]
    fn a_flipped_output_byte_fails_verification()
    {
        let signer = SoftwareSigner::from_seed(&SEED);
        let mut image = build_signed_image(b"payload", version(), 1, &signer)
            .expect("build");
        // Flip a payload byte (just past the 24-byte header).
        image[24] ^= 0xFF;
        let root = RootKey::from_bytes(signer.public_key()).expect("key");
        assert!(verify_image(&image, &root).is_err());
    }

    // A backend that returns a bogus signature must be caught by the self-check,
    // so the tool never emits an unverifiable image.
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
                // A signature that does not match the message at all.
                [0u8; SIG_LEN]
            }

            fn public_key(&self) -> [u8; 32]
            {
                self.inner.public_key()
            }
        }

        let signer = LyingSigner
        {
            inner: SoftwareSigner::from_seed(&SEED),
        };
        let result = build_signed_image(b"payload", version(), 1, &signer);
        assert_eq!(result.err(), Some(SignError::RoundTripFailed));
    }
}
