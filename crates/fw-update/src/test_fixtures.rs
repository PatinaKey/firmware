//! Signed-image fixtures shared by the host tests.
//!
//! The tests mint images, and two mint sites drifting apart (a stale algorithm
//! id, a stale offset) would silently weaken whichever one lagged. So the minting
//! lives here.
//!
//! The header is written by hand from pinned offsets rather than through the
//! `image-verify` encoder, on purpose: it pins the on-wire layout from outside
//! the crate that owns it, so a layout change that the encoder and the verifier
//! agree on still trips these tests.

use image_verify::RootKey;
use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::Signer;
use std::vec::Vec;

use crate::DEV_ROOT_KEY_TEST_ONLY;

/// The dev private scalar, test only. Its public key is
/// [`crate::DEV_ROOT_KEY_TEST_ONLY`].
///
/// The all-`0x01` value is a valid P-256 private scalar 
/// (non-zero, and far below the curve order, which starts with `0xFF`), 
/// so `SigningKey::from_slice` accepts it. 
/// It is `cfg(test)` only and it must never become a production key.
pub(crate) const DEV_SCALAR: [u8; 32] = [1u8; 32];

// Pinned header layout (image-verify format, HEADER_LEN = 24, SIG_LEN = 64).
pub(crate) const HEADER_LEN: usize = 24;
pub(crate) const OFF_MAGIC: usize = 0;
pub(crate) const OFF_FORMAT_VERSION: usize = 4;
pub(crate) const OFF_ALGORITHM: usize = 5;
pub(crate) const OFF_VERSION_MAJOR: usize = 6;
pub(crate) const OFF_SECURITY_COUNTER: usize = 14;
pub(crate) const OFF_PAYLOAD_LEN: usize = 18;
pub(crate) const MAGIC: [u8; 4] = *b"PKIM";
pub(crate) const FORMAT_VERSION: u8 = 1;

/// The algorithm id the verifier accepts: ECDSA P-256 over SHA-256.
pub(crate) const ALG_ECDSA_P256_SHA256: u8 = 0x02;

/// Builds a `header || payload || signature` image signed with `scalar`.
///
/// The signature is the 64-byte `r || s` pair, normalized to low-s, the only
/// encoding the verifier accepts. Signing goes through the RustCrypto `Signer`
/// path, so the nonce is RFC 6979 deterministic and the fixture is reproducible
/// byte for byte.
pub(crate) fn build_image
(
    scalar: [u8; 32],
    security_counter: u32,
    payload: &[u8],
)
    -> Vec<u8>
{
    let mut header = [0u8; HEADER_LEN];
    header[OFF_MAGIC..OFF_MAGIC + 4].copy_from_slice(&MAGIC);
    header[OFF_FORMAT_VERSION] = FORMAT_VERSION;
    header[OFF_ALGORITHM] = ALG_ECDSA_P256_SHA256;
    header[OFF_VERSION_MAJOR] = 1;
    header[OFF_SECURITY_COUNTER..OFF_SECURITY_COUNTER + 4]
        .copy_from_slice(&security_counter.to_le_bytes());
    header[OFF_PAYLOAD_LEN..OFF_PAYLOAD_LEN + 4]
        .copy_from_slice(&(payload.len() as u32).to_le_bytes());

    let mut signed = Vec::new();
    signed.extend_from_slice(&header);
    signed.extend_from_slice(payload);

    let sk = SigningKey::from_slice(&scalar).expect("test scalar is in [1, n-1]");
    let sig: p256::ecdsa::Signature = sk.sign(&signed);
    let sig = sig.normalize_s();

    let mut image = signed;
    image.extend_from_slice(&sig.to_bytes());
    image
}

/// The dev root key, built from the pinned public constant.
pub(crate) fn dev_root() -> RootKey
{
    RootKey::from_bytes(DEV_ROOT_KEY_TEST_ONLY).expect("dev root key is on-curve")
}
