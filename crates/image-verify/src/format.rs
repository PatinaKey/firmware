//! On-wire layout of the signed firmware image.
//!
//! # Endianness
//!
//! ALL multi-byte header fields are LITTLE-ENDIAN. The MCU is a Cortex-M33
//! (little-endian), so this matches the native byte order and avoids a swap on
//! the device. Every reader/writer in this crate uses `u16::from_le_bytes` /
//! `u32::from_le_bytes` and the matching `to_le_bytes`.
//!
//! # Layout
//!
//! ```text
//!   HEADER (HEADER_LEN bytes) || PAYLOAD (payload_len bytes) || SIGNATURE (64)
//! ```
//!
//! The Ed25519 SIGNATURE covers exactly `HEADER || PAYLOAD`: every byte except
//! the trailing 64 signature bytes.
//!
//! # Header field offsets
//!
//! ```text
//!   off  size  field             type    meaning
//!   ---  ----  ----------------  ------  ------------------------------------
//!     0     4  magic             [u8; 4] fixed tag "PKIM" (patina_key image)
//!     4     1  format_version    u8      header SCHEMA version (this parser)
//!     5     1  algorithm         u8      signature algorithm id, 0x01=Ed25519
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
//! The image_version (major.minor.revision.build) and security_counter live
//! INSIDE the signed region. This crate only parses them. Anti-rollback
//! comparison is future work.
//!
//! # Domain separation
//!
//! The magic (4 bytes), format_version, and algorithm byte sit at the FRONT of
//! the signed region, so they are the in-band domain separator bound by the
//! signature. Because verification is a single contiguous no-allocation
//! verify_strict over HEADER || PAYLOAD, the domain tag is carried in-band as
//! the leading signed bytes rather than as a prepended context string. The MCU
//! image root key MUST sign nothing but MCU firmware images. That
//! key-use-exclusivity invariant is enforced by the signing ceremony, not by
//! this parser, and it is what keeps a signature over some other artifact from
//! ever being replayed as a firmware image.
//!
//! # Algorithm agility
//!
//! The algorithm byte exists so a second signature algorithm can be added
//! later, for example 0x02 for P-256. The hard precondition is that adding any
//! second algorithm REQUIRES the signature length, the key type, and the
//! signed-region split to be selected BY that algorithm byte. They must NOT be
//! bolted onto the fixed 64-byte Ed25519 signature and 32-byte key offsets.
//! Today only Ed25519 (RFC 8032) is accepted, with a fixed 64-byte trailing
//! signature.

/// The fixed 4-byte tag that identifies a patina_key signed image. ASCII
/// "PKIM" (Patina Key IMage). Little-endian byte order is irrelevant for a raw
/// `[u8; 4]` tag: it is compared byte-for-byte as written.
pub(crate) const MAGIC: [u8; 4] = *b"PKIM";

/// The only header schema version this parser understands. An image carrying
/// any other `format_version` is rejected with `UnsupportedFormatVersion`.
pub(crate) const FORMAT_VERSION: u8 = 1;

/// The signature-algorithm id for Ed25519. The only value accepted today. The
/// byte exists so a later P-256 image can be distinguished rather than silently
/// misverified.
pub(crate) const ALG_ED25519: u8 = 0x01;

/// Length of the fixed-size header in bytes.
pub const HEADER_LEN: usize = 24;

/// Length of the trailing Ed25519 signature in bytes.
pub const SIG_LEN: usize = 64;

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
// compile-time check pins the layout and keeps OFF_RESERVED load-bearing
// outside the test build.
const _: () = assert!(OFF_RESERVED + 2 == HEADER_LEN);

/// The firmware version carried in the header.
///
/// A plain public value type: the version numbers are not secret, so the fields
/// are public by design. Parsed from the signed region. Ordering is NOT defined
/// here on purpose: the anti-rollback policy that compares two versions is
/// future work.
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
