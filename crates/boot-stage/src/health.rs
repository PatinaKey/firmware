//! The four-segment health check on the running bank's image.
//!
//! The boot stage reads the bank it is about to boot as four flash segments (the
//! same descriptor-page contract the updater writes): the page-9 descriptor
//! holding the header at [0:24] and the signature at [24:88], the secure payload
//! band (pages 10-19, secure alias), and the non-secure payload band (pages
//! 20-31, non-secure alias). It carves those into the logical image
//! `header || secure_payload || ns_payload || signature` and verifies the ECDSA
//! P-256 signature against the pinned root key.
//!
//! # Fail closed
//!
//! Any anomaly (a short descriptor, a payload length that overruns the bands, a
//! rejected signature) yields [`ImageHealth::Rejected`]. Nothing about the image
//! is trusted before the signature verifies. The anti-rollback comparison against
//! the NVCNT is not done here: [`ImageHealth::Verified`] carries the signed
//! security counter, and the boot decision applies the rollback policy.

use image_verify::HEADER_LEN;
use image_verify::RootKey;
use image_verify::SIG_LEN;
use image_verify::verify_image;

/// The byte offset of `payload_len` (u32 little-endian) inside the signed header.
///
/// Mirrors the image format (magic[0:4], format_version, algorithm, version
/// fields, security_counter, then payload_len at offset 18). The boot stage needs
/// the payload split before verify so it can cut the bands, and the length lives
/// in the header. Reading it from the not-yet-verified header is safe: the
/// signature binds the true length, so a lie yields a wrong digest or a length
/// mismatch and the image is rejected.
const OFF_PAYLOAD_LEN: usize = 18;

/// The verified health of the running bank's image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ImageHealth
{
    /// The four-segment ECDSA verify rejected the image, or it was malformed.
    Rejected,
    /// The signature verified. Carries the signed anti-rollback security counter
    /// for the decision to compare against the NVCNT.
    Verified
    {
        /// The monotonic anti-rollback counter from the signed header.
        security_counter: u32,
    },
}

/// Assesses the running bank's image from its three read-back flash segments.
///
/// # Arguments
///
/// - `descriptor`: the page-9 bytes, header at [0:24] then signature at [24:88].
/// - `secure_band`: the secure payload sub-band (pages 10-19, secure alias).
/// - `ns_band`: the non-secure payload sub-band (pages 20-31, non-secure alias).
/// - `root_key`: the pinned product root public key.
///
/// # Returns
///
/// [`ImageHealth::Verified`] with the signed security counter only after the
/// ECDSA signature passes, [`ImageHealth::Rejected`] on any anomaly.
pub(crate) fn assess
(
    descriptor: &[u8],
    secure_band: &[u8],
    ns_band: &[u8],
    root_key: &RootKey,
)
    -> ImageHealth
{
    let header = match descriptor.get(..HEADER_LEN)
    {
        Some(bytes) => bytes,
        None => return ImageHealth::Rejected,
    };
    let sig = match descriptor.get(HEADER_LEN..HEADER_LEN + SIG_LEN)
    {
        Some(bytes) => bytes,
        None => return ImageHealth::Rejected,
    };
    let payload_len = match header.get(OFF_PAYLOAD_LEN..OFF_PAYLOAD_LEN + 4)
    {
        Some(bytes) => match <[u8; 4]>::try_from(bytes)
        {
            Ok(array) => u32::from_le_bytes(array) as usize,
            Err(_) => return ImageHealth::Rejected,
        },
        None => return ImageHealth::Rejected,
    };

    // Cut the payload across the SECWM boundary exactly as the updater does: the
    // first bytes fill the secure band, the remainder the non-secure band. An
    // over-long payload_len overruns a band and is rejected by the bounds check.
    let secure_take = core::cmp::min(payload_len, secure_band.len());
    let ns_take = match payload_len.checked_sub(secure_take)
    {
        Some(value) => value,
        None => return ImageHealth::Rejected,
    };
    let secure_seg = match secure_band.get(..secure_take)
    {
        Some(bytes) => bytes,
        None => return ImageHealth::Rejected,
    };
    let ns_seg = match ns_band.get(..ns_take)
    {
        Some(bytes) => bytes,
        None => return ImageHealth::Rejected,
    };

    let segments: [&[u8]; 4] = [header, secure_seg, ns_seg, sig];
    match verify_image(&segments, root_key)
    {
        Ok(verified) => ImageHealth::Verified
        {
            security_counter: verified.security_counter(),
        },
        Err(_) => ImageHealth::Rejected,
    }
}

#[cfg(test)]
pub(crate) const OFF_PAYLOAD_LEN_FOR_TEST: usize = OFF_PAYLOAD_LEN;
