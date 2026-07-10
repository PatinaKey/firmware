//! Host-side header encoder for the signed firmware-image format.
//!
//! Gated behind the `encode` feature so the on-device default build never pulls
//! it in. It writes the SAME fixed header the verifier reads, using the SAME
//! private offset constants, so the on-wire layout has a single source of truth.
//!
//! This module is `no_std` and heap-free: it writes a fixed-size stack array of
//! bytes and cannot fail, so it returns the array directly.

use crate::format::ALG_ED25519;
use crate::format::FORMAT_VERSION;
use crate::format::HEADER_LEN;
use crate::format::ImageVersion;
use crate::format::MAGIC;
use crate::format::OFF_ALGORITHM;
use crate::format::OFF_FORMAT_VERSION;
use crate::format::OFF_MAGIC;
use crate::format::OFF_PAYLOAD_LEN;
use crate::format::OFF_RESERVED;
use crate::format::OFF_SECURITY_COUNTER;
use crate::format::OFF_VERSION_BUILD;
use crate::format::OFF_VERSION_MAJOR;
use crate::format::OFF_VERSION_MINOR;
use crate::format::OFF_VERSION_REVISION;

/// Encodes a fixed-size signed-image header.
///
/// # Arguments
///
/// - `version`: the firmware version (major.minor.revision.build) to embed.
/// - `security_counter`: the monotonic anti-rollback counter to embed.
/// - `payload_len`: the byte length of the payload that will follow the header.
///
/// # Returns
///
/// A `HEADER_LEN`-byte array carrying the magic, the format version, the
/// Ed25519 algorithm id, the version fields little-endian, the security counter
/// little-endian, the payload length little-endian, and zero reserved bytes.
///
/// The caller signs `header || payload` and appends the 64-byte
/// signature to obtain a complete image the verifier accepts.
pub fn encode_header
(
    version: ImageVersion,
    security_counter: u32,
    payload_len: u32,
)
    -> [u8; HEADER_LEN]
{
    let mut header = [0u8; HEADER_LEN];

    header[OFF_MAGIC..OFF_MAGIC + 4].copy_from_slice(&MAGIC);
    header[OFF_FORMAT_VERSION] = FORMAT_VERSION;
    header[OFF_ALGORITHM] = ALG_ED25519;
    header[OFF_VERSION_MAJOR] = version.major;
    header[OFF_VERSION_MINOR] = version.minor;
    header[OFF_VERSION_REVISION..OFF_VERSION_REVISION + 2]
        .copy_from_slice(&version.revision.to_le_bytes());
    header[OFF_VERSION_BUILD..OFF_VERSION_BUILD + 4]
        .copy_from_slice(&version.build.to_le_bytes());
    header[OFF_SECURITY_COUNTER..OFF_SECURITY_COUNTER + 4]
        .copy_from_slice(&security_counter.to_le_bytes());
    header[OFF_PAYLOAD_LEN..OFF_PAYLOAD_LEN + 4]
        .copy_from_slice(&payload_len.to_le_bytes());

    // The reserved bytes stay zero from the initialiser above. They are pinned
    // here only to document the closing field and keep OFF_RESERVED referenced.
    header[OFF_RESERVED..OFF_RESERVED + 2].copy_from_slice(&[0u8, 0u8]);

    header
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::RootKey;
    use crate::verify_image;
    use ed25519_dalek::SigningKey;
    use ed25519_dalek::ed25519::signature::Signer;
    use std::vec::Vec;

    const SEED: [u8; 32] = [5u8; 32];

    fn version() -> ImageVersion
    {
        ImageVersion
        {
            major: 4,
            minor: 2,
            revision: 0x0708,
            build: 0x1122_3344,
        }
    }

    #[test]
    fn encoded_header_matches_verifier_offsets()
    {
        let header = encode_header(version(), 0x00AA_BB00, 7);

        assert_eq!(&header[OFF_MAGIC..OFF_MAGIC + 4], &MAGIC);
        assert_eq!(header[OFF_FORMAT_VERSION], FORMAT_VERSION);
        assert_eq!(header[OFF_ALGORITHM], ALG_ED25519);
        assert_eq!(header[OFF_VERSION_MAJOR], 4);
        assert_eq!(header[OFF_VERSION_MINOR], 2);
        assert_eq!(
            &header[OFF_VERSION_REVISION..OFF_VERSION_REVISION + 2],
            &0x0708u16.to_le_bytes()
        );
        assert_eq!(
            &header[OFF_VERSION_BUILD..OFF_VERSION_BUILD + 4],
            &0x1122_3344u32.to_le_bytes()
        );
        assert_eq!(
            &header[OFF_SECURITY_COUNTER..OFF_SECURITY_COUNTER + 4],
            &0x00AA_BB00u32.to_le_bytes()
        );
        assert_eq!(
            &header[OFF_PAYLOAD_LEN..OFF_PAYLOAD_LEN + 4],
            &7u32.to_le_bytes()
        );
        assert_eq!(&header[OFF_RESERVED..OFF_RESERVED + 2], &[0u8, 0u8]);
    }

    // Builds an image with the encoder, signs it, and proves the verifier
    // accepts it and returns the same fields. This pins the encoder against the
    // real verify path inside the crate that owns both.
    #[test]
    fn encoded_image_round_trips_through_verifier()
    {
        let payload = b"encoder round-trip payload";
        let header = encode_header(version(), 9, payload.len() as u32);

        let mut signed = Vec::new();
        signed.extend_from_slice(&header);
        signed.extend_from_slice(payload);

        let sk = SigningKey::from_bytes(&SEED);
        let sig = sk.sign(&signed);
        let mut image = signed;
        image.extend_from_slice(&sig.to_bytes());

        let root = RootKey::from_bytes(sk.verifying_key().to_bytes())
            .expect("test key is valid");
        let verified = verify_image(&image, &root).expect("must verify");

        assert_eq!(verified.payload(), payload);
        assert_eq!(verified.security_counter(), 9);
        let v = verified.image_version();
        assert_eq!(v.major, 4);
        assert_eq!(v.minor, 2);
        assert_eq!(v.revision, 0x0708);
        assert_eq!(v.build, 0x1122_3344);
    }
}
