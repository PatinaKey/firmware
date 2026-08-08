//! Fail-closed error for the signed firmware-image verifier.
//!
//! Every variant is a rejection. The whole image is attacker-controlled until the
//! signature verifies, so each structural anomaly maps to a distinct typed
//! rejection and no trusted field is exposed before the signature passes.

/// Why an image failed verification.
///
/// Checked in a fixed order (see [`crate::verify_image`]), so the first anomaly
/// wins. Each variant says what was wrong without leaking any pre-verify field
/// value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError
{
    /// The segments hold fewer bytes than the minimum `HEADER_LEN + SIG_LEN`
    /// floor, so they cannot even hold a header plus a signature.
    TooShort,
    /// The leading magic tag did not match the patina_key image constant.
    BadMagic,
    /// The header `format_version` byte was not a value this parser supports.
    /// This is the parser-schema version, not the firmware version.
    UnsupportedFormatVersion,
    /// The `algorithm` byte was not `0x02` (ECDSA P-256 over SHA-256).
    UnsupportedAlgorithm,
    /// The total length did not equal `HEADER_LEN + payload_len + SIG_LEN`
    /// exactly. Catches a truncated payload, an oversized declaration, a
    /// trailing byte, or a `payload_len` whose addition overflows.
    LengthMismatch,
    /// A reserved header byte was not `0x00`. The reserved bytes sit inside the
    /// signed region and are required to be zero, so a non-zero value is a
    /// structural rejection caught before the signature is even checked.
    ReservedNotZero,
    /// The supplied root key was not an uncompressed SEC1 point on the P-256
    /// curve (a wrong tag byte, an off-curve point, or the identity).
    BadRootKey,
    /// The signature `s` scalar sits in the upper half of the curve order. ECDSA
    /// admits two encodings, `(r, s)` and `(r, n - s)`, both of which verify. This
    /// verifier accepts only the low-s encoding, so an image has one valid byte
    /// string per signing key. See [`crate::verify_image`].
    NonCanonicalSignature,
    /// The signature did not verify under the pinned root key over
    /// `HEADER || PAYLOAD`. Also covers a signature whose `r` or `s` is zero or
    /// at least the curve order, which is not a well-formed scalar pair. Any
    /// tampered byte or a wrong signing key lands here.
    BadSignature,
}
