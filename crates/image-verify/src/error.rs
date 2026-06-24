//! Fail-closed error for the signed firmware-image verifier.
//!
//! Every variant is a rejection. The whole image (header plus payload) is
//! attacker-controlled until the Ed25519 signature verifies, so each structural
//! anomaly maps to a distinct, typed rejection and no trusted field is ever
//! exposed before the signature passes. No `Display`, no `std`.

/// Why an image failed verification.
///
/// The variants below are checked in a fixed order (see [`crate::verify_image`])
/// so the first anomaly wins. They communicate WHAT was wrong without leaking
/// any pre-verify field value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError
{
    /// The slice was shorter than the minimum `HEADER_LEN + SIG_LEN` floor, so
    /// it cannot even hold a header plus a signature.
    TooShort,
    /// The leading magic tag did not match the patina_key image constant.
    BadMagic,
    /// The header `format_version` byte was not a value this parser supports.
    /// This is the parser-schema version, not the firmware version.
    UnsupportedFormatVersion,
    /// The `algorithm` byte was not `0x01` (Ed25519). Future-proofs a potential 
    /// later P-256 swap without silently accepting it today.
    UnsupportedAlgorithm,
    /// The total length did not equal `HEADER_LEN + payload_len + SIG_LEN`
    /// exactly. Catches a truncated payload, an oversized declaration, a
    /// trailing byte, or a `payload_len` whose addition overflows.
    LengthMismatch,
    /// A reserved header byte was not `0x00`. The reserved bytes sit inside the
    /// signed region and are required to be zero, so a non-zero value is a
    /// structural rejection caught before the signature is even checked.
    ReservedNotZero,
    /// The supplied root key was not a key Ed25519 accepts (a malformed or
    /// non-canonical point).
    BadRootKey,
    /// The Ed25519 signature did not verify under the pinned root key over
    /// `HEADER || PAYLOAD`. Any tampered byte or a wrong signing key lands here.
    BadSignature,
}
