//! Host-side header encoder for the signed firmware-image format.
//!
//! Gated behind the `encode` feature so the on-device default build does not
//! include it. It writes the same fixed header the verifier reads, using the same
//! offset constants, so the layout has a single source of truth.

use crate::format::ALG_ECDSA_P256_SHA256;
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
/// A `HEADER_LEN`-byte array carrying the magic, the format version, the ECDSA
/// P-256 algorithm id, the version fields little-endian, the security counter
/// little-endian, the payload length little-endian, and zero reserved bytes.
///
/// The caller signs `header || payload` and appends the 64-byte signature to
/// obtain a complete image the verifier accepts.
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
    header[OFF_ALGORITHM] = ALG_ECDSA_P256_SHA256;
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

    // The reserved bytes are already zero from the initialiser. Written explicitly
    // to document the closing field and keep OFF_RESERVED referenced.
    header[OFF_RESERVED..OFF_RESERVED + 2].copy_from_slice(&[0u8, 0u8]);

    header
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::ROOT_KEY_LEN;
    use crate::RootKey;
    use crate::SIG_LEN;
    use crate::verify_image;
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::Signer;
    use std::vec::Vec;

    // A fixed private scalar: non-zero and far below the curve order.
    const SCALAR: [u8; 32] = [5u8; 32];

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
        assert_eq!(header[OFF_ALGORITHM], ALG_ECDSA_P256_SHA256);
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

    // Builds an image with the encoder, signs it, and checks the verifier accepts
    // it and returns the same fields. Pins the encoder against the real verify path.
    #[test]
    fn encoded_image_round_trips_through_verifier()
    {
        let payload = b"encoder round-trip payload";
        let header = encode_header(version(), 9, payload.len() as u32);

        let mut signed = Vec::new();
        signed.extend_from_slice(&header);
        signed.extend_from_slice(payload);

        let sk = SigningKey::from_slice(&SCALAR).expect("scalar in [1, n-1]");
        let sig: p256::ecdsa::Signature = sk.sign(&signed);
        let sig = sig.normalize_s();
        let mut image = signed;
        image.extend_from_slice(&sig.to_bytes());
        assert_eq!(image.len(), HEADER_LEN + payload.len() + SIG_LEN);

        let point = sk.verifying_key().to_sec1_point(false);
        let mut key_bytes = [0u8; ROOT_KEY_LEN];
        key_bytes.copy_from_slice(point.as_ref());
        let root = RootKey::from_bytes(key_bytes).expect("test key is valid");

        let segs: [&[u8]; 1] = [&image];
        let verified = verify_image(&segs, &root).expect("must verify");

        let mut got = Vec::new();
        for piece in verified.payload_segments()
        {
            got.extend_from_slice(piece);
        }
        assert_eq!(got, payload);
        assert_eq!(verified.security_counter(), 9);
        let v = verified.image_version();
        assert_eq!(v.major, 4);
        assert_eq!(v.minor, 2);
        assert_eq!(v.revision, 0x0708);
        assert_eq!(v.build, 0x1122_3344);
    }
}
