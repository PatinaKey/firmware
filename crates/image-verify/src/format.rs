//! On-wire layout of the signed firmware image.
//!
//! # Endianness
//!
//! All multi-byte header fields are little-endian, matching the Cortex-M33 native
//! byte order.
//!
//! # Layout
//!
//! ```text
//!   HEADER (HEADER_LEN bytes) || PAYLOAD (payload_len bytes) || SIGNATURE (64)
//! ```
//!
//! The signature covers exactly `HEADER || PAYLOAD`: every byte except the
//! trailing 64 signature bytes. The verifier hashes that region with SHA-256 and
//! checks the ECDSA P-256 signature against the digest.
//!
//! # On-flash placement
//!
//! This file layout, one contiguous `HEADER || PAYLOAD || SIGNATURE`, is what the
//! signer emits and what a host tool sees. It does not change on the device.
//!
//! On the STM32 A/B target the device de-interleaves the file onto flash: the
//! header and signature land in a small descriptor page, and the payload lands
//! page-aligned at its link origin, so the firmware vector table sits where the CPU
//! fetches it. The verifier consumes the image as segments
//! whose logical concatenation is exactly this file, so placement is a device
//! concern.
//!
//! # Header field offsets
//!
//! ```text
//!   off  size  field             type    meaning
//!   ---  ----  ----------------  ------  ------------------------------------
//!     0     4  magic             [u8; 4] fixed tag "PKIM" (patina_key image)
//!     4     1  format_version    u8      header SCHEMA version (this parser)
//!     5     1  algorithm         u8      signature algorithm id, 0x02 = the one
//!                                        accepted algorithm, ECDSA P-256/SHA-256
//!     6     1  image_version_maj u8      firmware version major
//!     7     1  image_version_min u8      firmware version minor
//!     8     2  image_version_rev u16le   firmware version revision
//!    10     4  image_version_bld u32le   firmware version build
//!    14     4  security_counter  u32le   monotonic anti-rollback counter
//!    18     4  payload_len       u32le   PAYLOAD length in bytes
//!    22     2  _reserved         [u8; 2] zero-padding to a 24-byte header
//!   ---  ----
//!    24  HEADER_LEN
//! ```
//!
//! The image_version and security_counter live inside the signed region. This crate
//! only parses them.
//!
//! # Domain separation
//!
//! The magic, format_version, and algorithm byte sit at the front of the signed
//! region, so they are the in-band domain separator bound by the signature. The
//! image root key must sign nothing but firmware images. That exclusivity is
//! enforced by the signing ceremony, not this parser, and it stops a signature over
//! another artifact from being replayed as a firmware image.
//!
//! # Exactly one algorithm ships
//!
//! The `algorithm` byte is a rejection guard. 
//! The byte exists to reject anything else, including the retired Ed25519 id `0x01`.

/// The fixed 4-byte tag identifying a patina_key signed image, ASCII "PKIM".
/// Compared byte for byte, so byte order does not apply.
pub(crate) const MAGIC: [u8; 4] = *b"PKIM";

/// The only header schema version this parser understands. Any other
/// `format_version` is rejected with `UnsupportedFormatVersion`.
///
/// The schema is the field layout, not the algorithm. A retired algorithm is
/// rejected through the `algorithm` byte, not this version.
pub(crate) const FORMAT_VERSION: u8 = 1;

/// The signature-algorithm id for ECDSA P-256 over SHA-256, the only value this
/// verifier accepts. Any other value, including the retired Ed25519 id `0x01`, is
/// rejected with `UnsupportedAlgorithm`.
pub(crate) const ALG_ECDSA_P256_SHA256: u8 = 0x02;

/// Length of the fixed-size header in bytes.
pub const HEADER_LEN: usize = 24;

/// Length of the trailing signature in bytes: the ECDSA P-256 `r || s` pair,
/// two 32-byte big-endian scalars, with no ASN.1 framing.
pub const SIG_LEN: usize = 64;

/// Length of the pinned root public key in bytes: an UNCOMPRESSED SEC1 point,
/// the `0x04` tag then the 32-byte X and 32-byte Y coordinates.
pub const ROOT_KEY_LEN: usize = 65;

// Field offsets within the header. Private: callers read fields through the
// verified accessors, never by raw offset.
pub(crate) const OFF_MAGIC: usize = 0;
pub(crate) const OFF_FORMAT_VERSION: usize = 4;
pub(crate) const OFF_ALGORITHM: usize = 5;
pub(crate) const OFF_VERSION_MAJOR: usize = 6;
pub(crate) const OFF_VERSION_MINOR: usize = 7;
pub(crate) const OFF_VERSION_REVISION: usize = 8;
pub(crate) const OFF_VERSION_BUILD: usize = 10;
pub(crate) const OFF_SECURITY_COUNTER: usize = 14;
pub(crate) const OFF_PAYLOAD_LEN: usize = 18;
pub(crate) const OFF_RESERVED: usize = 22;

// The reserved 2-byte pad closes the header exactly at HEADER_LEN. This
// compile-time check pins the layout.
const _: () = assert!(OFF_RESERVED + 2 == HEADER_LEN);

/// The firmware version carried in the header.
///
/// Parsed from the signed region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageVersion
{
    /// Major component.
    pub major: u8,
    /// Minor component.
    pub minor: u8,
    /// Revision component.
    pub revision: u16,
    /// Build component.
    pub build: u32,
}
