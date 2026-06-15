//! Concrete crypto wiring for the L3 secure channel and the handshake.
//!
//! Thin adapters over audited RustCrypto/dalek primitives: X25519 DH, SHA-256,
//! HMAC-SHA256, the TROPIC01 custom HKDF, and AES-256-GCM seal/open in place.
//! There is no crypto-agility trait: the algorithms are fixed by the protocol,
//! so an abstraction would only add a downgrade surface.

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::AeadInPlace;
use aes_gcm::Aes256Gcm;
use aes_gcm::KeyInit as AesKeyInit;
use hmac::Hmac;
use hmac::Mac;
use sha2::digest::KeyInit as MacKeyInit;
use sha2::Digest;
use sha2::Sha256;
use x25519_dalek::PublicKey;
use x25519_dalek::StaticSecret;
use zeroize::Zeroizing;

use p384::ecdsa::signature::Verifier;
use p384::ecdsa::Signature as P384Signature;
use p384::ecdsa::VerifyingKey as P384VerifyingKey;
use p521::ecdsa::Signature as P521Signature;
use p521::ecdsa::VerifyingKey as P521VerifyingKey;

/// AES-GCM authentication tag length, in bytes.
pub(crate) const GCM_TAG_LEN: usize = 16;

/// A 32-byte secret that wipes itself on drop.
pub(crate) type Secret32 = Zeroizing<[u8; 32]>;

/// A crypto primitive failed. Carries no detail (kept off the error surface).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CryptoError;

/// Computes the X25519 shared secret `secret * public` (raw 32-byte u-coord).
///
/// Clamping follows RFC 7748, matching the libtropic oracle byte-for-byte.
pub(crate) fn x25519(secret: &[u8; 32], public: &[u8; 32]) -> [u8; 32]
{
    let s = StaticSecret::from(*secret);
    let p = PublicKey::from(*public);
    s.diffie_hellman(&p).to_bytes()
}

/// Derives the X25519 public key for `secret` (basepoint * secret).
pub(crate) fn x25519_base(secret: &[u8; 32]) -> [u8; 32]
{
    let s = StaticSecret::from(*secret);
    PublicKey::from(&s).to_bytes()
}

/// Computes SHA-256 over the concatenation of `parts`.
pub(crate) fn sha256(parts: &[&[u8]]) -> [u8; 32]
{
    let mut h = Sha256::new();
    for p in parts
    {
        h.update(p);
    }
    h.finalize().into()
}

/// Computes HMAC-SHA256 over `msg` keyed by `key`.
///
/// HMAC accepts any key length, so the only error path is unreachable in
/// practice. It is surfaced as `CryptoError` rather than panicking.
pub(crate) fn hmac_sha256
(
    key: &[u8],
    msg: &[u8],
)
-> Result<[u8; 32], CryptoError>
{
    let mut mac = <Hmac<Sha256> as MacKeyInit>::new_from_slice(key).map_err(|_| CryptoError)?;
    mac.update(msg);
    Ok(mac.finalize().into_bytes().into())
}

/// The TROPIC01 custom HKDF, returning both outputs.
///
/// `prk = HMAC(ck, input)`, `out1 = HMAC(prk, [0x01])`,
/// `out2 = HMAC(prk, out1 || [0x02])`. The caller picks which outputs it needs,
/// the chaining-key step uses `out1`, the final step uses both.
///
/// Every named intermediate and both outputs are `Zeroizing`, so the key
/// material wipes itself when the caller drops it.
pub(crate) fn hkdf
(
    ck: &[u8],
    input: &[u8],
)
-> Result<(Secret32, Secret32), CryptoError>
{
    let prk = Zeroizing::new(hmac_sha256(ck, input)?);
    let out1 = Zeroizing::new(hmac_sha256(prk.as_slice(), &[0x01])?);
    let mut helper = Zeroizing::new([0u8; 33]);
    helper[..32].copy_from_slice(out1.as_slice());
    helper[32] = 0x02;
    let out2 = Zeroizing::new(hmac_sha256(prk.as_slice(), helper.as_slice())?);
    Ok((out1, out2))
}

/// Encrypts `buffer` in place with AES-256-GCM and returns the detached tag.
///
/// `iv` is the 12-byte nonce, `aad` the associated data (empty for L3). The
/// buffer holds plaintext on entry and ciphertext on return (same length).
pub(crate) fn aes256gcm_seal
(
    key: &[u8; 32],
    iv: &[u8; 12],
    aad: &[u8],
    buffer: &mut [u8],
)
-> Result<[u8; GCM_TAG_LEN], CryptoError>
{
    let cipher = <Aes256Gcm as AesKeyInit>::new(&GenericArray::from(*key));
    let nonce = GenericArray::from(*iv);
    let tag = cipher
        .encrypt_in_place_detached(&nonce, aad, buffer)
        .map_err(|_| CryptoError)?;
    Ok(tag.into())
}

/// Decrypts `buffer` in place with AES-256-GCM, verifying the detached `tag`.
///
/// The tag is checked in constant time inside `aes-gcm`. On mismatch the call
/// returns `CryptoError` and the buffer contents are unspecified.
pub(crate) fn aes256gcm_open
(
    key: &[u8; 32],
    iv: &[u8; 12],
    aad: &[u8],
    buffer: &mut [u8],
    tag: &[u8; GCM_TAG_LEN],
)
-> Result<(), CryptoError>
{
    let cipher = <Aes256Gcm as AesKeyInit>::new(&GenericArray::from(*key));
    let nonce = GenericArray::from(*iv);
    let tag = GenericArray::from(*tag);
    cipher
        .decrypt_in_place_detached(&nonce, aad, buffer, &tag)
        .map_err(|_| CryptoError)
}

/// Verifies an ECDSA/P-384 signature over `msg` with SHA-384.
///
/// `pubkey_sec1` is the SEC1 uncompressed point (0x04 || X || Y, 97 bytes).
/// `msg` is the raw message (the tbsCertificate bytes). The curve default digest
/// hashes it with SHA-384 internally, matching ecdsa-with-SHA384. `sig_der` is
/// the ECDSA-Sig-Value DER (SEQUENCE { INTEGER r, INTEGER s }). Any parse or
/// verification failure maps to `CryptoError`.
///
/// This operates on PUBLIC certificate data, so constant time is not required.
pub(crate) fn ecdsa_p384_sha384_verify
(
    pubkey_sec1: &[u8],
    msg: &[u8],
    sig_der: &[u8],
)
-> Result<(), CryptoError>
{
    let vk = P384VerifyingKey::from_sec1_bytes(pubkey_sec1).map_err(|_| CryptoError)?;
    let sig = P384Signature::from_der(sig_der).map_err(|_| CryptoError)?;
    // `verify` applies the curve default digest (SHA-384) to `msg`.
    vk.verify(msg, &sig).map_err(|_| CryptoError)
}

/// Verifies an ECDSA/P-521 signature over `msg` with SHA-512.
///
/// `pubkey_sec1` is the SEC1 uncompressed point (0x04 || X || Y, 133 bytes).
/// `msg` is the raw message (the tbsCertificate bytes); the curve default digest
/// hashes it with SHA-512 internally, matching ecdsa-with-SHA512. `sig_der` is
/// the ECDSA-Sig-Value DER (SEQUENCE { INTEGER r, INTEGER s }). Any parse or
/// verification failure maps to `CryptoError`.
///
/// This operates on PUBLIC certificate data, so constant time is not required.
pub(crate) fn ecdsa_p521_sha512_verify
(
    pubkey_sec1: &[u8],
    msg: &[u8],
    sig_der: &[u8],
)
-> Result<(), CryptoError>
{
    let vk = P521VerifyingKey::from_sec1_bytes(pubkey_sec1).map_err(|_| CryptoError)?;
    let sig = P521Signature::from_der(sig_der).map_err(|_| CryptoError)?;
    // `verify` applies the curve default digest (SHA-512) to `msg`.
    vk.verify(msg, &sig).map_err(|_| CryptoError)
}

/// Validates that `point` is a real P-521 curve point (SEC1 uncompressed).
///
/// Attempts to construct a P-521 verifying key from the SEC1 bytes. A point that
/// is off the curve, the wrong length, or not 0x04-prefixed is rejected here, so
/// a malformed pinned anchor fails at construction rather than at first verify.
///
/// This operates on PUBLIC key data, so constant time is not required.
pub(crate) fn p521_validate_point(point: &[u8]) -> Result<(), CryptoError>
{
    P521VerifyingKey::from_sec1_bytes(point).map_err(|_| CryptoError)?;
    Ok(())
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn x25519_base_then_dh_is_symmetric()
    {
        let a = [7u8; 32];
        let b = [9u8; 32];
        let a_pub = x25519_base(&a);
        let b_pub = x25519_base(&b);
        // Both sides reach the same shared secret.
        assert_eq!(x25519(&a, &b_pub), x25519(&b, &a_pub));
    }

    #[test]
    fn gcm_seal_open_round_trips()
    {
        let key = [0x11u8; 32];
        let iv = [0x22u8; 12];
        let mut buf = *b"hello tropic";
        let tag = aes256gcm_seal(&key, &iv, &[], &mut buf).unwrap();
        assert_ne!(&buf, b"hello tropic");
        aes256gcm_open(&key, &iv, &[], &mut buf, &tag).unwrap();
        assert_eq!(&buf, b"hello tropic");
    }

    #[test]
    fn gcm_open_rejects_tampered_tag()
    {
        let key = [0x33u8; 32];
        let iv = [0x44u8; 12];
        let mut buf = [0xABu8; 8];
        let mut tag = aes256gcm_seal(&key, &iv, &[], &mut buf).unwrap();
        tag[0] ^= 0xFF;
        assert_eq!(aes256gcm_open(&key, &iv, &[], &mut buf, &tag), Err(CryptoError));
    }

    #[test]
    fn gcm_aad_is_authenticated()
    {
        let key = [0x55u8; 32];
        let iv = [0x66u8; 12];
        let mut buf = [0u8; 4];
        let tag = aes256gcm_seal(&key, &iv, b"aad", &mut buf).unwrap();
        // Opening with different AAD must fail.
        assert_eq!(aes256gcm_open(&key, &iv, b"bad", &mut buf, &tag), Err(CryptoError));
    }
}
