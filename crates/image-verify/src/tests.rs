//! Host tests for the segmented ECDSA P-256 image verifier.
//!
//! Fixtures are minted with fixed private scalars, so every key pair and signature
//! is deterministic and no RNG runs. Signing uses RFC 6979 deterministic nonces, so
//! each fixture is reproducible byte for byte.

use super::*;
use crate::format::
{
    ALG_ECDSA_P256_SHA256, FORMAT_VERSION, MAGIC, OFF_ALGORITHM,
    OFF_FORMAT_VERSION, OFF_MAGIC, OFF_PAYLOAD_LEN, OFF_RESERVED,
    OFF_SECURITY_COUNTER, OFF_VERSION_BUILD, OFF_VERSION_MAJOR,
    OFF_VERSION_MINOR, OFF_VERSION_REVISION,
};
use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::Signer;
use std::vec::Vec;

// Deterministic fixtures. Each value is a valid P-256 private scalar: non-zero
// and far below the curve order n, which starts with 0xFF.
const TEST_SCALAR: [u8; 32] = [7u8; 32];
const OTHER_SCALAR: [u8; 32] = [9u8; 32];

// The all-0x01 scalar, the publicly known dev/test key the fuzz seam pins. It is
// used only by the fuzz-seam guard tests, so it is gated with them.
#[cfg(feature = "_fuzz")]
const DEV_SCALAR: [u8; 32] = [1u8; 32];

const TEST_MAJOR: u8 = 3;
const TEST_MINOR: u8 = 7;
const TEST_REVISION: u16 = 0x0102;
const TEST_BUILD: u32 = 0xAABB_CCDD;
const TEST_COUNTER: u32 = 0x0000_1234;

fn signing_key(scalar: [u8; 32]) -> SigningKey
{
    SigningKey::from_slice(&scalar).expect("test scalar is in [1, n-1]")
}

fn public_key_of(scalar: [u8; 32]) -> [u8; ROOT_KEY_LEN]
{
    let sk = signing_key(scalar);
    let point = sk.verifying_key().to_sec1_point(false);
    let mut out = [0u8; ROOT_KEY_LEN];
    out.copy_from_slice(point.as_ref());
    out
}

fn root_key_for(scalar: [u8; 32]) -> RootKey
{
    RootKey::from_bytes(public_key_of(scalar)).expect("test key is valid")
}

// Builds a header with the given payload length. Returns a HEADER_LEN buffer.
fn build_header(payload_len: u32) -> [u8; HEADER_LEN]
{
    let mut h = [0u8; HEADER_LEN];
    h[OFF_MAGIC..OFF_MAGIC + 4].copy_from_slice(&MAGIC);
    h[OFF_FORMAT_VERSION] = FORMAT_VERSION;
    h[OFF_ALGORITHM] = ALG_ECDSA_P256_SHA256;
    h[OFF_VERSION_MAJOR] = TEST_MAJOR;
    h[OFF_VERSION_MINOR] = TEST_MINOR;
    h[OFF_VERSION_REVISION..OFF_VERSION_REVISION + 2]
        .copy_from_slice(&TEST_REVISION.to_le_bytes());
    h[OFF_VERSION_BUILD..OFF_VERSION_BUILD + 4]
        .copy_from_slice(&TEST_BUILD.to_le_bytes());
    h[OFF_SECURITY_COUNTER..OFF_SECURITY_COUNTER + 4]
        .copy_from_slice(&TEST_COUNTER.to_le_bytes());
    h[OFF_PAYLOAD_LEN..OFF_PAYLOAD_LEN + 4]
        .copy_from_slice(&payload_len.to_le_bytes());
    h
}

// Signs `signed` with `scalar` and returns the low-s 64-byte r || s pair, the only
// encoding the verifier accepts.
fn sign_low_s(scalar: [u8; 32], signed: &[u8]) -> [u8; SIG_LEN]
{
    let sk = signing_key(scalar);
    let sig: p256::ecdsa::Signature = sk.sign(signed);
    let sig = sig.normalize_s();
    let mut out = [0u8; SIG_LEN];
    out.copy_from_slice(&sig.to_bytes());
    out
}

// Builds a fully signed image: HEADER || payload || signature.
fn build_signed_image(scalar: [u8; 32], payload: &[u8]) -> Vec<u8>
{
    let header = build_header(payload.len() as u32);
    let mut signed = Vec::new();
    signed.extend_from_slice(&header);
    signed.extend_from_slice(payload);
    let sig = sign_low_s(scalar, &signed);
    let mut image = signed;
    image.extend_from_slice(&sig);
    image
}

// Concatenates the payload segments back into one buffer, so a test can compare
// against the original payload bytes.
fn collect_payload(verified: &VerifiedImage<'_>) -> Vec<u8>
{
    let mut out = Vec::new();
    for piece in verified.payload_segments()
    {
        assert!(!piece.is_empty(), "the iterator must never yield an empty piece");
        out.extend_from_slice(piece);
    }
    out
}

#[test]
fn header_offsets_and_consts_are_pinned()
{
    assert_eq!(HEADER_LEN, 24);
    assert_eq!(SIG_LEN, 64);
    assert_eq!(ROOT_KEY_LEN, 65);
    assert_eq!(MAGIC, *b"PKIM");
    assert_eq!(FORMAT_VERSION, 1);
    assert_eq!(ALG_ECDSA_P256_SHA256, 0x02);
    assert_eq!(OFF_MAGIC, 0);
    assert_eq!(OFF_FORMAT_VERSION, 4);
    assert_eq!(OFF_ALGORITHM, 5);
    assert_eq!(OFF_VERSION_MAJOR, 6);
    assert_eq!(OFF_VERSION_MINOR, 7);
    assert_eq!(OFF_VERSION_REVISION, 8);
    assert_eq!(OFF_VERSION_BUILD, 10);
    assert_eq!(OFF_SECURITY_COUNTER, 14);
    assert_eq!(OFF_PAYLOAD_LEN, 18);
    assert_eq!(OFF_RESERVED, 22);
}

#[test]
fn valid_image_round_trips()
{
    let payload = b"hello patina firmware payload";
    let image = build_signed_image(TEST_SCALAR, payload);
    let root = root_key_for(TEST_SCALAR);
    let segs: [&[u8]; 1] = [&image];
    let v = verify_image(&segs, &root).expect("valid image must verify");
    assert_eq!(collect_payload(&v), payload);
    assert_eq!(v.payload_len(), payload.len());
    assert_eq!(v.security_counter(), TEST_COUNTER);
    let ver = v.image_version();
    assert_eq!(ver.major, TEST_MAJOR);
    assert_eq!(ver.minor, TEST_MINOR);
    assert_eq!(ver.revision, TEST_REVISION);
    assert_eq!(ver.build, TEST_BUILD);
}

#[test]
fn empty_payload_round_trips()
{
    let image = build_signed_image(TEST_SCALAR, b"");
    let root = root_key_for(TEST_SCALAR);
    let segs: [&[u8]; 1] = [&image];
    let v = verify_image(&segs, &root).expect("empty payload must verify");
    assert_eq!(v.payload_len(), 0);
    assert_eq!(collect_payload(&v), b"");
    assert_eq!(v.payload_segments().count(), 0);
}

// The segmented property: the same image cut at every possible offset must verify
// identically. The cut walks through the header, the payload, and the signature, so
// both a header and a signature straddling a boundary are driven at every byte
// position.
#[test]
fn every_two_way_split_verifies_identically()
{
    let payload = b"a payload long enough to span a cut in many places";
    let image = build_signed_image(TEST_SCALAR, payload);
    let root = root_key_for(TEST_SCALAR);

    for cut in 0..=image.len()
    {
        let (head, tail) = image.split_at(cut);
        let segs: [&[u8]; 2] = [head, tail];
        let v = verify_image(&segs, &root)
            .unwrap_or_else(|e| panic!("split at {cut} must verify, got {e:?}"));
        assert_eq!(collect_payload(&v), payload, "payload wrong at cut {cut}");
        assert_eq!(v.security_counter(), TEST_COUNTER);
    }
}

// A three-way split with empty segments woven in at both ends and in the middle.
// The header, the payload, and the signature all straddle, and the parser must
// step over the empty segments without ever yielding or consuming a byte from
// them.
#[test]
fn empty_segments_are_stepped_over()
{
    let payload = b"straddling payload bytes";
    let image = build_signed_image(TEST_SCALAR, payload);
    let root = root_key_for(TEST_SCALAR);

    // Cut inside the header (10) and inside the signature (image.len() - 20).
    let first = 10;
    let second = image.len() - 20;
    let a = &image[..first];
    let b = &image[first..second];
    let c = &image[second..];

    let segs: [&[u8]; 7] = [&[], a, &[], b, &[], c, &[]];
    let v = verify_image(&segs, &root).expect("empty segments must be skipped");
    assert_eq!(collect_payload(&v), payload);
    assert_eq!(v.security_counter(), TEST_COUNTER);
}

#[test]
fn an_empty_segment_list_is_too_short()
{
    let root = root_key_for(TEST_SCALAR);
    assert_eq!(verify_image(&[], &root), Err(VerifyError::TooShort));
}

#[test]
fn a_list_of_only_empty_segments_is_too_short()
{
    let root = root_key_for(TEST_SCALAR);
    let segs: [&[u8]; 3] = [&[], &[], &[]];
    assert_eq!(verify_image(&segs, &root), Err(VerifyError::TooShort));
}

#[test]
fn a_payload_split_across_segments_is_reassembled_in_order()
{
    // The payload itself is cut in three, so the iterator must yield three pieces
    // in logical order.
    let payload: Vec<u8> = (0..90u8).collect();
    let image = build_signed_image(TEST_SCALAR, &payload);
    let root = root_key_for(TEST_SCALAR);

    let a = &image[..HEADER_LEN + 30];
    let b = &image[HEADER_LEN + 30..HEADER_LEN + 60];
    let c = &image[HEADER_LEN + 60..];
    let segs: [&[u8]; 3] = [a, b, c];
    let v = verify_image(&segs, &root).expect("verify");

    let pieces: Vec<&[u8]> = v.payload_segments().collect();
    assert_eq!(pieces.len(), 3, "one piece per segment the payload spans");
    assert_eq!(collect_payload(&v), payload);
}

#[test]
fn flipped_payload_byte_is_bad_signature()
{
    let mut image = build_signed_image(TEST_SCALAR, b"some payload here");
    image[HEADER_LEN] ^= 0xFF;
    let root = root_key_for(TEST_SCALAR);
    let segs: [&[u8]; 1] = [&image];
    assert_eq!(verify_image(&segs, &root), Err(VerifyError::BadSignature));
}

#[test]
fn wrong_magic_is_bad_magic()
{
    let mut image = build_signed_image(TEST_SCALAR, b"x");
    image[OFF_MAGIC] ^= 0xFF;
    let root = root_key_for(TEST_SCALAR);
    let segs: [&[u8]; 1] = [&image];
    assert_eq!(verify_image(&segs, &root), Err(VerifyError::BadMagic));
}

#[test]
fn bad_format_version_is_unsupported_format_version()
{
    let mut image = build_signed_image(TEST_SCALAR, b"x");
    image[OFF_FORMAT_VERSION] = 0xEE;
    let root = root_key_for(TEST_SCALAR);
    let segs: [&[u8]; 1] = [&image];
    assert_eq!(
        verify_image(&segs, &root),
        Err(VerifyError::UnsupportedFormatVersion)
    );
}

// The retired Ed25519 id must be rejected, not accepted by a second verifier. This
// is the anti-downgrade guard: one algorithm ships and every other id fails.
#[test]
fn the_retired_ed25519_algorithm_id_is_rejected()
{
    let mut image = build_signed_image(TEST_SCALAR, b"x");
    image[OFF_ALGORITHM] = 0x01;
    let root = root_key_for(TEST_SCALAR);
    let segs: [&[u8]; 1] = [&image];
    assert_eq!(
        verify_image(&segs, &root),
        Err(VerifyError::UnsupportedAlgorithm)
    );
}

#[test]
fn an_unknown_algorithm_id_is_rejected()
{
    let mut image = build_signed_image(TEST_SCALAR, b"x");
    image[OFF_ALGORITHM] = 0x03;
    let root = root_key_for(TEST_SCALAR);
    let segs: [&[u8]; 1] = [&image];
    assert_eq!(
        verify_image(&segs, &root),
        Err(VerifyError::UnsupportedAlgorithm)
    );
}

#[test]
fn truncated_below_floor_is_too_short()
{
    let image = build_signed_image(TEST_SCALAR, b"x");
    let root = root_key_for(TEST_SCALAR);
    let short = &image[..HEADER_LEN + SIG_LEN - 1];
    let segs: [&[u8]; 1] = [short];
    assert_eq!(verify_image(&segs, &root), Err(VerifyError::TooShort));
}

// The floor check must count the whole segment list, not one segment: a header
// spread over many tiny segments that together fall one byte short is still
// TooShort, and a parser that looked at only the first segment would say so for
// the wrong reason.
#[test]
fn a_short_image_spread_over_many_segments_is_too_short()
{
    let image = build_signed_image(TEST_SCALAR, b"x");
    let root = root_key_for(TEST_SCALAR);
    let short = &image[..HEADER_LEN + SIG_LEN - 1];
    let pieces: Vec<&[u8]> = short.chunks(3).collect();
    assert_eq!(verify_image(&pieces, &root), Err(VerifyError::TooShort));
}

#[test]
fn declared_payload_len_too_big_is_length_mismatch()
{
    let mut image = build_signed_image(TEST_SCALAR, b"abc");
    let inflated = (3u32 + 1).to_le_bytes();
    image[OFF_PAYLOAD_LEN..OFF_PAYLOAD_LEN + 4].copy_from_slice(&inflated);
    let root = root_key_for(TEST_SCALAR);
    let segs: [&[u8]; 1] = [&image];
    assert_eq!(verify_image(&segs, &root), Err(VerifyError::LengthMismatch));
}

#[test]
fn declared_payload_len_too_small_is_length_mismatch()
{
    let mut image = build_signed_image(TEST_SCALAR, b"abc");
    let deflated = 2u32.to_le_bytes();
    image[OFF_PAYLOAD_LEN..OFF_PAYLOAD_LEN + 4].copy_from_slice(&deflated);
    let root = root_key_for(TEST_SCALAR);
    let segs: [&[u8]; 1] = [&image];
    assert_eq!(verify_image(&segs, &root), Err(VerifyError::LengthMismatch));
}

#[test]
fn trailing_byte_is_length_mismatch()
{
    let mut image = build_signed_image(TEST_SCALAR, b"abc");
    image.push(0x00);
    let root = root_key_for(TEST_SCALAR);
    let segs: [&[u8]; 1] = [&image];
    assert_eq!(verify_image(&segs, &root), Err(VerifyError::LengthMismatch));
}

// A trailing byte in a separate segment must be caught too: the total is what
// counts, not the shape of the split.
#[test]
fn a_trailing_segment_is_length_mismatch()
{
    let image = build_signed_image(TEST_SCALAR, b"abc");
    let root = root_key_for(TEST_SCALAR);
    let segs: [&[u8]; 2] = [&image, &[0x00]];
    assert_eq!(verify_image(&segs, &root), Err(VerifyError::LengthMismatch));
}

#[test]
fn overflowing_payload_len_is_length_mismatch()
{
    let mut image = build_signed_image(TEST_SCALAR, b"abc");
    let huge = u32::MAX.to_le_bytes();
    image[OFF_PAYLOAD_LEN..OFF_PAYLOAD_LEN + 4].copy_from_slice(&huge);
    let root = root_key_for(TEST_SCALAR);
    let segs: [&[u8]; 1] = [&image];
    assert_eq!(verify_image(&segs, &root), Err(VerifyError::LengthMismatch));
}

#[test]
fn wrong_signing_key_is_bad_signature()
{
    let image = build_signed_image(TEST_SCALAR, b"payload");
    let root = root_key_for(OTHER_SCALAR);
    let segs: [&[u8]; 1] = [&image];
    assert_eq!(verify_image(&segs, &root), Err(VerifyError::BadSignature));
}

#[test]
fn an_all_zero_signature_is_bad_signature()
{
    // r = s = 0 is not a well-formed scalar pair, so the parse rejects it before
    // any curve arithmetic runs.
    let mut image = build_signed_image(TEST_SCALAR, b"payload");
    let start = image.len() - SIG_LEN;
    image[start..].fill(0);
    let root = root_key_for(TEST_SCALAR);
    let segs: [&[u8]; 1] = [&image];
    assert_eq!(verify_image(&segs, &root), Err(VerifyError::BadSignature));
}

#[test]
fn bad_signature_image_exposes_nothing()
{
    let mut image = build_signed_image(TEST_SCALAR, b"payload");
    image[HEADER_LEN] ^= 0x01;
    let root = root_key_for(TEST_SCALAR);
    let segs: [&[u8]; 1] = [&image];
    let result = verify_image(&segs, &root);
    assert!(result.is_err());
    assert_eq!(result, Err(VerifyError::BadSignature));
}

#[test]
fn security_counter_tamper_is_bad_signature()
{
    let mut image = build_signed_image(TEST_SCALAR, b"payload");
    image[OFF_SECURITY_COUNTER] ^= 0xFF;
    let root = root_key_for(TEST_SCALAR);
    let segs: [&[u8]; 1] = [&image];
    assert_eq!(verify_image(&segs, &root), Err(VerifyError::BadSignature));
}

#[test]
fn image_version_tamper_is_bad_signature()
{
    let mut image = build_signed_image(TEST_SCALAR, b"payload");
    image[OFF_VERSION_BUILD] ^= 0xFF;
    let root = root_key_for(TEST_SCALAR);
    let segs: [&[u8]; 1] = [&image];
    assert_eq!(verify_image(&segs, &root), Err(VerifyError::BadSignature));
}

#[test]
fn nonzero_reserved_is_reserved_not_zero()
{
    // Set a reserved byte before signing so the signature is genuinely valid. The
    // rejection then proves the reserved check is structural, not a side effect of
    // a broken signature.
    let payload = b"payload";
    let mut header = build_header(payload.len() as u32);
    header[OFF_RESERVED] = 0x01;
    let mut signed = Vec::new();
    signed.extend_from_slice(&header);
    signed.extend_from_slice(payload);
    let sig = sign_low_s(TEST_SCALAR, &signed);
    let mut image = signed;
    image.extend_from_slice(&sig);

    let root = root_key_for(TEST_SCALAR);
    let segs: [&[u8]; 1] = [&image];
    assert_eq!(
        verify_image(&segs, &root),
        Err(VerifyError::ReservedNotZero)
    );
}

// The malleability policy, proven. Flipping s to n - s yields a signature ECDSA
// still considers valid over the same digest and key. The verifier must reject it
// as non-canonical and must still accept the low-s twin. Both halves matter:
// without the second the test could pass on an image broken for another reason.
#[test]
fn a_high_s_signature_is_rejected_and_its_low_s_twin_is_accepted()
{
    let payload = b"malleability policy payload";
    let image = build_signed_image(TEST_SCALAR, payload);
    let root = root_key_for(TEST_SCALAR);

    // The low-s twin (the image as built) is accepted.
    let segs: [&[u8]; 1] = [&image];
    assert!(verify_image(&segs, &root).is_ok(), "the low-s image must verify");

    // Rebuild the same signature with s replaced by n - s. Only the s half of the
    // trailing 64 bytes changes, the digest and the key are untouched.
    let start = image.len() - SIG_LEN;
    let low = p256::ecdsa::Signature::from_slice(&image[start..])
        .expect("the built signature parses");
    let (r, s) = low.split_scalars();
    let high = p256::ecdsa::Signature::from_scalars(r, -s)
        .expect("n - s is a valid non-zero scalar");
    assert!(
        bool::from(high.s().is_high()),
        "the flipped signature must actually be high-s"
    );

    let mut malleable = image.clone();
    malleable[start..].copy_from_slice(&high.to_bytes());
    assert_ne!(malleable, image, "the flipped image must differ in flash");

    let segs: [&[u8]; 1] = [&malleable];
    assert_eq!(
        verify_image(&segs, &root),
        Err(VerifyError::NonCanonicalSignature),
        "the high-s encoding must be rejected by policy"
    );

    // Non-vacuity: raw ECDSA (with no low-s policy) does accept the flipped
    // signature over the same digest, so the rejection above comes from the
    // policy, not from a broken image.
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    let digest = <sha2::Sha256 as sha2::Digest>::digest(&image[..start]);
    let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&public_key_of(TEST_SCALAR))
        .expect("key");
    assert!(
        key.verify_prehash(&digest, &high).is_ok(),
        "raw ECDSA accepts the high-s twin, which is exactly why the policy exists"
    );
}

#[test]
fn from_bytes_rejects_an_off_curve_point()
{
    // A well-formed uncompressed tag with coordinates that satisfy no curve
    // equation. The point must be rejected at construction.
    let mut bad = [0u8; ROOT_KEY_LEN];
    bad[0] = 0x04;
    bad[1] = 0x01;
    bad[33] = 0x01;
    match RootKey::from_bytes(bad)
    {
        Err(e) => assert_eq!(e, VerifyError::BadRootKey),
        Ok(_) => panic!("an off-curve point must be rejected"),
    }
}

#[test]
fn from_bytes_rejects_a_wrong_tag_byte()
{
    // A valid key with its 0x04 uncompressed tag replaced. A 65-byte buffer
    // tagged 0x02 or 0x03 is not a legal SEC1 encoding, so it must be rejected:
    // the pinned encoding is uncompressed and nothing else.
    let mut bad = public_key_of(TEST_SCALAR);
    bad[0] = 0x02;
    match RootKey::from_bytes(bad)
    {
        Err(e) => assert_eq!(e, VerifyError::BadRootKey),
        Ok(_) => panic!("a 65-byte buffer with a compressed tag must be rejected"),
    }
}

#[test]
fn from_bytes_rejects_an_all_zero_buffer()
{
    match RootKey::from_bytes([0u8; ROOT_KEY_LEN])
    {
        Err(e) => assert_eq!(e, VerifyError::BadRootKey),
        Ok(_) => panic!("an all-zero buffer must be rejected"),
    }
}

#[test]
fn from_bytes_accepts_valid_key()
{
    assert!(RootKey::from_bytes(public_key_of(TEST_SCALAR)).is_ok());
}

// Pins that the fuzz seam's fixed root key is the public key of the all-0x01
// scalar and that the verifier accepts it.
#[cfg(feature = "_fuzz")]
#[test]
fn fuzz_root_key_is_the_dev_scalar_public_key()
{
    assert_eq!(crate::fuzz::FUZZ_ROOT_KEY_TEST_ONLY, public_key_of(DEV_SCALAR));
    assert!(RootKey::from_bytes(crate::fuzz::FUZZ_ROOT_KEY_TEST_ONLY).is_ok());
}

// The guard. An image signed with the fuzz seam's matching private scalar must be
// accepted, in both the contiguous and the segmented shape. Without this, a fuzz
// key that failed to parse, or a seam that never reached the crypto, would leave
// the fuzzer exploring only the reject path while reporting coverage.
#[cfg(feature = "_fuzz")]
#[test]
fn the_fuzz_seam_accepts_an_image_signed_with_its_matching_scalar()
{
    let payload = b"the fuzz seam must reach a genuine accept";
    let image = build_signed_image(DEV_SCALAR, payload);
    let root = RootKey::from_bytes(crate::fuzz::FUZZ_ROOT_KEY_TEST_ONLY)
        .expect("the fuzz root key is valid");

    let segs: [&[u8]; 1] = [&image];
    let v = verify_image(&segs, &root).expect("the fuzz key must ACCEPT its own image");
    assert_eq!(collect_payload(&v), payload);

    // The same image, cut through the header and through the signature, must also
    // be accepted, so the segmented path the fuzz target drives really reaches the
    // verify.
    let cut = image.len() - 30;
    let segs: [&[u8]; 2] = [&image[..7], &image[7..]];
    assert!(verify_image(&segs, &root).is_ok(), "a header-straddling split must verify");
    let segs: [&[u8]; 2] = [&image[..cut], &image[cut..]];
    assert!(verify_image(&segs, &root).is_ok(), "a signature-straddling split must verify");
}

// The fuzz entry point itself must never panic, on any shape of input, including
// the degenerate ones (empty, one byte, exactly two control bytes).
#[cfg(feature = "_fuzz")]
#[test]
fn the_fuzz_entry_point_survives_degenerate_inputs()
{
    crate::fuzz::verify_image(&[]);
    crate::fuzz::verify_image(&[0x00]);
    crate::fuzz::verify_image(&[0xFF, 0xFF]);
    crate::fuzz::verify_image(&[0x00, 0x00, 0x01, 0x02, 0x03]);

    // A real image behind two control bytes, so the seam's segmented path runs
    // over a well-formed image at every cut the control bytes can pick.
    let image = build_signed_image(DEV_SCALAR, b"fuzz seam payload");
    for a in [0u8, 1, 37, 200, 255]
    {
        for b in [0u8, 1, 37, 200, 255]
        {
            let mut data = std::vec![a, b];
            data.extend_from_slice(&image);
            crate::fuzz::verify_image(&data);
        }
    }
}
