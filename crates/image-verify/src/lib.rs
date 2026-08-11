//! Signed firmware-image verifier for patina_key.
//!
//! Parses the patina_key signed-image format and verifies its ECDSA P-256
//! signature against a pinned root public key supplied by the caller. `no_std`
//! and heap-free.
//!
//! # Segmented images
//!
//! [`verify_image`] takes `&[&[u8]]`, a list of slices whose concatenation is the
//! image. On the device an image spans two flash bands with different security
//! attributes, read through different address aliases, so no contiguous view
//! exists and there is no RAM to assemble one. A one-element list is a contiguous
//! image.
//!
//! The digest is streamed across the segments, so the image is never copied. The
//! header, the signature, or any field may straddle a segment boundary, and a
//! segment may be empty. ECDSA verifies over a prehash, so the segmented path
//! needs no reassembly.
//!
//! # Trust model
//!
//! The whole image is attacker-controlled until the signature verifies. The root
//! public key is the only trust input and is a caller argument, so the boot stage
//! pins the genuine key out-of-band. No field inside the signed region is exposed
//! before the signature check passes.
//!
//! See [`format`] for the byte layout.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

#[cfg(feature = "encode")]
mod encode;
mod error;
mod format;
mod segments;

#[cfg(feature = "encode")]
pub use crate::encode::encode_header;
pub use crate::error::VerifyError;
pub use crate::format::HEADER_LEN;
pub use crate::format::ImageVersion;
pub use crate::format::ROOT_KEY_LEN;
pub use crate::format::SIG_LEN;
pub use crate::segments::PayloadSegments;

use p256::ecdsa::Signature;
use p256::ecdsa::VerifyingKey;
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::elliptic_curve::scalar::IsHigh;
use sha2::Digest;
use sha2::Sha256;

/// A pinned ECDSA P-256 root public key.
///
/// Pinned as the 65-byte uncompressed SEC1 point (`0x04 || X || Y`). The
/// uncompressed form carries both coordinates in the clear, so the pinned constant
/// can be diffed byte for byte against the signing ceremony output, and it avoids a
/// point decompression on every construction. Fixing the length at 65 also pins the
/// encoding: a compressed key cannot be passed to [`RootKey::from_bytes`], so there
/// is no encoding ambiguity.
///
/// Constructed only through [`RootKey::from_bytes`], which rejects anything that is
/// not a point on the P-256 curve. Holding a `RootKey` means the point is
/// validated.
// Debug is not derived so the key bytes cannot reach logs.
#[derive(Clone)]
pub struct RootKey
{
    key: VerifyingKey,
}

impl RootKey
{
    /// Builds a pinned root key from its 65-byte uncompressed SEC1 encoding.
    ///
    /// # Errors
    ///
    /// Returns [`VerifyError::BadRootKey`] if the bytes are not an uncompressed
    /// SEC1 point on the P-256 curve: a wrong tag byte, an off-curve point, or
    /// the identity are all rejected.
    pub fn from_bytes(bytes: [u8; ROOT_KEY_LEN]) -> Result<RootKey, VerifyError>
    {
        match VerifyingKey::from_sec1_bytes(&bytes)
        {
            Ok(key) => Ok(RootKey { key }),
            Err(_) => Err(VerifyError::BadRootKey),
        }
    }
}

/// A verified image view.
///
/// Returned only after the signature verifies. Every field lives inside the signed
/// region, so an attacker cannot forge it without the root private key. The payload
/// is exposed as borrowed segments, never copied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedImage<'a>
{
    image_version: ImageVersion,
    security_counter: u32,
    segments: &'a [&'a [u8]],
    payload_start: usize,
    payload_len: usize,
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

    /// The payload length in bytes, as declared by the signed header.
    pub fn payload_len(&self) -> usize
    {
        self.payload_len
    }

    /// The verified payload, as borrowed pieces in logical order.
    ///
    /// Concatenating the yielded slices reproduces the payload. The pieces borrow
    /// the caller's segments, so nothing is copied. A contiguous image yields one
    /// piece, or none for an empty payload.
    pub fn payload_segments(&self) -> PayloadSegments<'a>
    {
        PayloadSegments::new(self.segments, self.payload_start, self.payload_len)
    }
}

// Reads a little-endian u16 at `off` from the fixed-size header buffer.
fn read_u16_le(header: &[u8], off: usize) -> Result<u16, VerifyError>
{
    let bytes = header
        .get(off..off + 2)
        .ok_or(VerifyError::TooShort)?;
    let arr: [u8; 2] = bytes
        .try_into()
        .map_err(|_| VerifyError::TooShort)?;
    Ok(u16::from_le_bytes(arr))
}

// Reads a little-endian u32 at `off`. Same contract as `read_u16_le`.
fn read_u32_le(header: &[u8], off: usize) -> Result<u32, VerifyError>
{
    let bytes = header
        .get(off..off + 4)
        .ok_or(VerifyError::TooShort)?;
    let arr: [u8; 4] = bytes
        .try_into()
        .map_err(|_| VerifyError::TooShort)?;
    Ok(u32::from_le_bytes(arr))
}

/// Verifies a segmented signed firmware image against a pinned root key.
///
/// # Arguments
///
/// - `image`: the segments whose concatenation is
///   `HEADER || PAYLOAD || SIGNATURE`. Any segmentation is legal: an empty list,
///   empty segments, a header or signature straddling a boundary. The bytes are
///   attacker-controlled until the signature check passes.
/// - `root_key`: the pinned P-256 root public key.
///
/// # Returns
///
/// On success, a [`VerifiedImage`] exposing the signed `image_version`,
/// `security_counter`, and the payload as borrowed segments.
///
/// # Only the low-s signature encoding is accepted
///
/// ECDSA admits two encodings of every signature, `(r, s)` and `(r, n - s)`, both
/// of which verify and either of which can be produced from the other without the
/// private key. This verifier rejects the high-s encoding with
/// [`VerifyError::NonCanonicalSignature`].
///
/// The digest covers `HEADER || PAYLOAD`, not the trailing signature, so flipping
/// `s` to `n - s` yields a different byte string in flash that still verifies. This
/// forges nothing, both encodings authenticate the same payload, so no authenticity
/// property depends on the check. What it buys is canonicality: each payload has
/// exactly one accepted byte string per signing key, so an image hash or a
/// byte-for-byte diff of two banks means one thing.
///
/// The signing tool normalizes to low-s, so a legitimate signer never trips this. A
/// hardware backend returning a high-s signature is normalized on the host.
///
/// # Errors
///
/// Fails closed at the first anomaly, in this fixed order:
/// [`VerifyError::TooShort`] (below the `HEADER_LEN + SIG_LEN` floor),
/// [`VerifyError::BadMagic`], [`VerifyError::UnsupportedFormatVersion`],
/// [`VerifyError::UnsupportedAlgorithm`], [`VerifyError::ReservedNotZero`],
/// [`VerifyError::LengthMismatch`] (the total is not
/// `HEADER_LEN + payload_len + SIG_LEN` exactly, including an overflowing
/// `payload_len`), [`VerifyError::BadSignature`] for a signature that is not a
/// well-formed `(r, s)` scalar pair, [`VerifyError::NonCanonicalSignature`] for a
/// high-s encoding, then [`VerifyError::BadSignature`] if ECDSA rejects the
/// signature over the SHA-256 digest of `HEADER || PAYLOAD`. No field inside the
/// signed region is exposed in the result before that final check passes.
pub fn verify_image<'a>
(
    image: &'a [&'a [u8]],
    root_key: &RootKey,
)
    -> Result<VerifiedImage<'a>, VerifyError>
{
    use crate::format::
    {
        ALG_ECDSA_P256_SHA256, FORMAT_VERSION, HEADER_LEN, MAGIC, OFF_ALGORITHM,
        OFF_FORMAT_VERSION, OFF_MAGIC, OFF_PAYLOAD_LEN, OFF_RESERVED,
        OFF_SECURITY_COUNTER, OFF_VERSION_BUILD, OFF_VERSION_MAJOR,
        OFF_VERSION_MINOR, OFF_VERSION_REVISION, SIG_LEN,
    };

    // Length floor: the segments must hold at least a header plus a signature. This
    // establishes the total, which every later bound is checked against.
    let total = segments::total_len(image)?;
    let floor = HEADER_LEN
        .checked_add(SIG_LEN)
        .ok_or(VerifyError::TooShort)?;
    if total < floor
    {
        return Err(VerifyError::TooShort);
    }

    // Parse the full header into typed locals. Nothing here is exposed before the
    // signature verifies: the VerifiedImage is built only on the Ok path, which
    // keeps the verifier fail-closed by construction.
    //
    // The header is copied into a fixed 24-byte stack array because it may straddle
    // a segment boundary. Only the header is copied, not the image.
    let mut header = [0u8; HEADER_LEN];
    segments::copy_out(image, 0, &mut header)?;

    // Magic tag.
    let magic = header
        .get(OFF_MAGIC..OFF_MAGIC + 4)
        .ok_or(VerifyError::TooShort)?;
    if magic != MAGIC
    {
        return Err(VerifyError::BadMagic);
    }

    // Header schema version, not the firmware version.
    let format_version = *header
        .get(OFF_FORMAT_VERSION)
        .ok_or(VerifyError::TooShort)?;
    if format_version != FORMAT_VERSION
    {
        return Err(VerifyError::UnsupportedFormatVersion);
    }

    // Algorithm id. One verifier ships, so every other id is rejected, the retired
    // Ed25519 id included. This is the anti-downgrade guard.
    let algorithm = *header
        .get(OFF_ALGORITHM)
        .ok_or(VerifyError::TooShort)?;
    if algorithm != ALG_ECDSA_P256_SHA256
    {
        return Err(VerifyError::UnsupportedAlgorithm);
    }

    // Firmware version, inside the signed region. Returned only after verification.
    let image_version = ImageVersion
    {
        major: *header
            .get(OFF_VERSION_MAJOR)
            .ok_or(VerifyError::TooShort)?,
        minor: *header
            .get(OFF_VERSION_MINOR)
            .ok_or(VerifyError::TooShort)?,
        revision: read_u16_le(&header, OFF_VERSION_REVISION)?,
        build: read_u32_le(&header, OFF_VERSION_BUILD)?,
    };

    // Monotonic anti-rollback counter, inside the signed region.
    let security_counter = read_u32_le(&header, OFF_SECURITY_COUNTER)?;

    // Declared payload length.
    let payload_len = read_u32_le(&header, OFF_PAYLOAD_LEN)? as usize;

    // Reserved bytes must be zero. They sit inside the signed region, so a non-zero
    // value is a structural rejection caught before the signature check.
    let reserved = header
        .get(OFF_RESERVED..OFF_RESERVED + 2)
        .ok_or(VerifyError::TooShort)?;
    if reserved != [0u8, 0u8]
    {
        return Err(VerifyError::ReservedNotZero);
    }

    // Exact total length: HEADER_LEN + payload_len + SIG_LEN, with no overflow and
    // no trailing byte. This pins the signature boundary, which may fall inside a
    // segment.
    let signed_len = HEADER_LEN
        .checked_add(payload_len)
        .ok_or(VerifyError::LengthMismatch)?;
    let total_len = signed_len
        .checked_add(SIG_LEN)
        .ok_or(VerifyError::LengthMismatch)?;
    if total != total_len
    {
        return Err(VerifyError::LengthMismatch);
    }

    // Copy the trailing signature into a fixed 64-byte stack array. It may straddle
    // a boundary or start inside the segment the payload ends in, so it cannot be
    // sliced out of a single segment.
    let mut sig_bytes = [0u8; SIG_LEN];
    segments::copy_out(image, signed_len, &mut sig_bytes)?;

    // Parse (r, s). Rejects a zero scalar or one at or above the curve order, so the
    // pair is well-formed before any curve arithmetic.
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|_| VerifyError::BadSignature)?;

    // Malleability policy: accept only the low-s encoding. See the doc comment
    // above.
    if bool::from(signature.s().is_high())
    {
        return Err(VerifyError::NonCanonicalSignature);
    }

    // Stream the digest over HEADER || PAYLOAD. Each segment is fed to SHA-256 as
    // is, and the last piece is cut at the signature boundary, so the image is never
    // assembled in RAM.
    let mut hasher = Sha256::new();
    segments::for_each_prefix_piece(image, signed_len, |piece| hasher.update(piece))?;
    let digest = hasher.finalize();

    // The trust step. Any failure collapses to BadSignature, so nothing leaks about
    // why.
    root_key
        .key
        .verify_prehash(&digest, &signature)
        .map_err(|_| VerifyError::BadSignature)?;

    // Authenticated. Build the result from the already-parsed locals.
    Ok(VerifiedImage
    {
        image_version,
        security_counter,
        segments: image,
        payload_start: HEADER_LEN,
        payload_len,
    })
}

/// Fuzzing seam. Exposes the attacker-facing verify path to libFuzzer harnesses.
///
/// Gated behind the `_fuzz` feature so the fixed dev key it carries cannot reach a
/// product build. The entry point must never panic on any input. Not part of the
/// supported API.
#[cfg(feature = "_fuzz")]
pub mod fuzz
{
    use crate::ROOT_KEY_LEN;
    use crate::RootKey;

    /// A fixed, valid P-256 public key for the fuzz target. Test only.
    ///
    /// The uncompressed SEC1 public key of the all-`0x01` private scalar, a publicly
    /// known value. A guard test pins that an image signed with the matching private
    /// scalar is accepted, so the fuzzer reaches the verify path instead of bouncing
    /// off a rejected key.
    pub(crate) const FUZZ_ROOT_KEY_TEST_ONLY: [u8; ROOT_KEY_LEN] = [
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

    /// Drives the segmented image verifier over arbitrary bytes under a fixed pinned
    /// root key. Must never panic.
    ///
    /// The first two bytes choose two cut points, so the header and the signature
    /// are driven across segment boundaries and zero-length segments are reached.
    /// The same bytes also go through the contiguous one-segment path, so every
    /// input attacks both shapes. Any panic or abort is a finding.
    pub fn verify_image(data: &[u8])
    {
        let root = match RootKey::from_bytes(FUZZ_ROOT_KEY_TEST_ONLY)
        {
            Ok(key) => key,
            Err(_) => return,
        };

        // With fewer than two control bytes there is no image to cut. Drive the two
        // edge shapes the parser must survive: an empty segment list, and a single
        // segment holding whatever bytes there are.
        let (control, body) = match data.split_at_checked(2)
        {
            Some(pair) => pair,
            None =>
            {
                let _ = crate::verify_image(&[], &root);
                let _ = crate::verify_image(&[data], &root);
                return;
            }
        };

        // The contiguous shape.
        let _ = crate::verify_image(&[body], &root);

        let cuts: [u8; 2] = match control.try_into()
        {
            Ok(pair) => pair,
            Err(_) => return,
        };

        // The segmented shape. `span` is body.len() + 1, so `first` lands anywhere
        // in [0, len] and `second` anywhere in [first, len]. Either cut can coincide
        // with a boundary or an end, reaching the empty-segment and
        // boundary-straddling cases.
        let span = body.len().saturating_add(1);
        let first = (cuts[0] as usize) % span;
        let second = first + ((cuts[1] as usize) % (span - first));

        let (head, rest) = match body.split_at_checked(first)
        {
            Some(pair) => pair,
            None => return,
        };
        let (middle, tail) = match rest.split_at_checked(second - first)
        {
            Some(pair) => pair,
            None => return,
        };
        let _ = crate::verify_image(&[head, middle, tail], &root);
    }
}

#[cfg(test)]
mod tests;
