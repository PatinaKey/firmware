//! The pinned product root public key.
//!
//! The boot stage pins one ECDSA P-256 root public key, the trust anchor every
//! firmware image is verified against. The key is committed as a 65-byte
//! uncompressed SEC1 point in `product_root_key.sec1`, pulled in with
//! `include_bytes!`. A re-ceremony overwrites that one file, with no code change.
//!
//! # The production trust anchor
//!
//! The committed bytes are the production ceremony key, the public half of the
//! ECCP256 keypair held in the YubiKey PIV slot 82. The private key lives in the
//! hardware token and never enters the repo. It differs from the all-`0x01` dev
//! key (`DEV_ROOT_KEY_TEST_ONLY`), so the linked-ELF grep gate that forbids the
//! dev key stays meaningful.
//!
//! # Fail-safe direction
//!
//! The sole build pins this production slot. There is no dev-key fallback and no
//! feature that swaps in a test key, so a build cannot silently trust the wrong
//! anchor.

use image_verify::ROOT_KEY_LEN;
use image_verify::RootKey;
use image_verify::VerifyError;

/// The pinned root public key, a 65-byte uncompressed SEC1 point.
///
/// `include_bytes!` fixes the length at compile time: a file that is not exactly
/// `ROOT_KEY_LEN` bytes fails to build.
pub(crate) const PROD_ROOT_KEY_SEC1: &[u8; ROOT_KEY_LEN] =
    include_bytes!("../product_root_key.sec1");

/// Builds the pinned product root key.
///
/// # Errors
///
/// [`VerifyError::BadRootKey`] if the committed bytes are not an uncompressed
/// SEC1 point on the P-256 curve. The boot stage treats that as a wedge: a build
/// with a corrupt pinned key must never fall back to trusting an image.
pub(crate) fn product_root_key() -> Result<RootKey, VerifyError>
{
    RootKey::from_bytes(*PROD_ROOT_KEY_SEC1)
}
