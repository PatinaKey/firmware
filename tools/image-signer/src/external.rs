//! External-signature two-step flow: prepare then finalize.
//!
//! Splits bank assembly around a signature made by an offline signer 
//! (a YubiKey PIV slot), so the private key never touches this tool.
//!
//! # Prepare
//!
//! [`prepare_external`] takes the three firmware images plus the version and
//! security-counter fields, builds `HEADER || PAYLOAD` exactly as
//! [`crate::assemble_bank`] does, and returns:
//!
//! - `digest` = `SHA-256(HEADER || PAYLOAD)`, the 32 bytes the operator signs.
//! - `context`, a self-describing blob holding the boot bytes, the header, and the
//!   payload, so finalize reconstructs the bank without re-running objcopy or re-assembling.
//!
//! The digest is what the device hashes too: the device streams
//! `SHA-256(header || secure_band || ns)`, and the payload is the secure band
//! (padded to `SECURE_LEN`) then the NS app, so the two digests are equal.
//!
//! # The operator signs the digest, raw ECDSA, no re-hash
//!
//! The 32-byte digest is signed as a raw ECDSA P-256 signature over the hash. The
//! card signs the hash bytes directly and must not hash them again. On a YubiKey
//! that is a touch plus PIN operation.
//!
//! # Finalize
//!
//! [`finalize_external`] takes the context, the external signature, and the pinned
//! public key. It parses the signature (raw 64-byte `r || s` or ASN.1 DER),
//! normalizes it to low-s (the device rejects high-s, an external signer emits it
//! about half the time), verifies it against the pinned key over the digest
//! recomputed from the context, then lays out the bank and runs the same
//! four-segment self-verify [`crate::assemble_bank`] runs. Any failure withholds the
//! bank.

use image_verify::HEADER_LEN;
use image_verify::ImageVersion;
use image_verify::ROOT_KEY_LEN;
use image_verify::RootKey;
use image_verify::SIG_LEN;
use image_verify::VerifyError;
use image_verify::encode_header;
use p256::ecdsa::Signature;
use p256::ecdsa::VerifyingKey;
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use sha2::Digest;
use sha2::Sha256;

use crate::AssembledBank;
use crate::BankError;
use crate::SignError;
use crate::bank::BOOT_LEN;
use crate::bank::NS_LEN;
use crate::bank::SECURE_LEN;
use crate::bank::assemble_payload;
use crate::bank::check_region_sizes;
use crate::bank::place_bank;
use crate::bank::verify_bank_segments;

/// Length of the digest the operator signs: a SHA-256 output, 32 bytes.
pub const DIGEST_LEN: usize = 32;

// The context blob magic, ASCII "PKXCTX01" (Patina Key eXternal ConTeXt, format
// 01). Compared byte for byte, so byte order does not apply.
const CONTEXT_MAGIC: [u8; 8] = *b"PKXCTX01";

// The fixed context header: the 8-byte magic then five little-endian u32 length
// fields (boot, header, payload, secure, ns).
const CONTEXT_FIXED_LEN: usize = 8 + 4 * 5;

/// The output of the prepare step.
///
/// `digest` is signed offline. `context` is fed back into [`finalize_external`]
/// unchanged. None of it is secret: the images, the header, and the digest are
/// all public.
pub struct PreparedExternal
{
    /// `SHA-256(HEADER || PAYLOAD)`, the 32 bytes the operator signs with the
    /// YubiKey as a raw ECDSA P-256 signature (no re-hash).
    pub digest: [u8; DIGEST_LEN],
    /// The self-describing context blob finalize consumes.
    pub context: Vec<u8>,
    /// The signed payload length: `SECURE_LEN + ns_len`.
    pub payload_len: usize,
    /// The actual secure app length before padding.
    pub secure_len: usize,
    /// The non-secure app length.
    pub ns_len: usize,
}

/// How the external signature file is encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigFormat
{
    /// A bare 64-byte `r || s` pair, two 32-byte big-endian scalars.
    Raw,
    /// An ASN.1 DER `SEQUENCE` of two `INTEGER`s (r, s), what openssl and a PIV
    /// or PKCS#11 toolchain emit by default.
    Der,
    /// Decide by length: exactly 64 bytes is treated as raw `r || s`, anything else
    /// is parsed as DER. A 64-byte DER encoding is astronomically rare, and one seen
    /// here would be misread as raw and then fail closed at verify, never accepted.
    /// Pass `--sig-format der` to force DER.
    Auto,
}

/// Builds the digest and the context for the external-signature flow.
///
/// The bytes match [`crate::assemble_bank`] exactly, because the payload and the
/// header are built through the same helpers. See the module docs.
///
/// # Errors
///
/// A band-size overflow ([`BankError::BootTooLarge`],
/// [`BankError::SecureTooLarge`], [`BankError::NsTooLarge`]) or a payload that
/// overflows the 32-bit header length field ([`BankError::Sign`] with
/// [`SignError::PayloadTooLarge`]).
pub fn prepare_external
(
    boot: &[u8],
    secure: &[u8],
    nonsecure: &[u8],
    version: ImageVersion,
    security_counter: u32,
)
    -> Result<PreparedExternal, BankError>
{
    check_region_sizes(boot, secure, nonsecure)?;

    let payload = assemble_payload(secure, nonsecure);
    let payload_len_u32: u32 = payload
        .len()
        .try_into()
        .map_err(|_| BankError::Sign(SignError::PayloadTooLarge))?;
    let header = encode_header(version, security_counter, payload_len_u32);

    // DIGEST = SHA-256(HEADER || PAYLOAD), exactly what the device streams.
    let mut hasher = Sha256::new();
    hasher.update(header);
    hasher.update(&payload);
    let digest: [u8; DIGEST_LEN] = hasher.finalize().into();

    let context =
        serialize_context(boot, &header, &payload, secure.len(), nonsecure.len());

    Ok(PreparedExternal
    {
        digest,
        context,
        payload_len: payload.len(),
        secure_len: secure.len(),
        ns_len: nonsecure.len(),
    })
}

/// Parses the external signature bytes into an ECDSA signature.
///
/// Accepts a bare 64-byte `r || s` pair and an ASN.1 DER encoding, chosen by
/// `format`. The result is not yet low-s normalized: [`finalize_external`]
/// normalizes it.
///
/// # Errors
///
/// [`BankError::BadSignatureFormat`] if the bytes are not a well-formed signature
/// in the requested (or detected) encoding.
pub fn parse_signature
(
    bytes: &[u8],
    format: SigFormat,
)
    -> Result<Signature, BankError>
{
    match format
    {
        SigFormat::Raw =>
        {
            Signature::from_slice(bytes)
                .map_err(|_| BankError::BadSignatureFormat)
        }
        SigFormat::Der =>
        {
            Signature::from_der(bytes)
                .map_err(|_| BankError::BadSignatureFormat)
        }
        SigFormat::Auto =>
        {
            if bytes.len() == SIG_LEN
            {
                Signature::from_slice(bytes)
                    .map_err(|_| BankError::BadSignatureFormat)
            }
            else
            {
                Signature::from_der(bytes)
                    .map_err(|_| BankError::BadSignatureFormat)
            }
        }
    }
}

/// Assembles the flashable bank from a context and an external signature.
///
/// The signature is normalized to low-s, verified against `expected_root_key`
/// over the digest recomputed from `context`, then laid out and self-verified the
/// way the device carves and checks the bank. See the module docs.
///
/// # Errors
///
/// [`BankError::BadContext`] for a malformed context,
/// [`BankError::ExternalSignatureRejected`] if the normalized signature does not
/// verify against the pinned key (wrong key, wrong digest, corrupt signature),
/// [`BankError::SelfVerifyFailed`] if the pinned key is off-curve or the assembled
/// bank fails its own four-segment verify. The bank is withheld on any of them.
pub fn finalize_external
(
    context: &[u8],
    signature: &Signature,
    expected_root_key: &[u8; ROOT_KEY_LEN],
)
    -> Result<AssembledBank, BankError>
{
    let parsed = parse_context(context)?;

    // Normalize to low-s. (r, n - s) authenticates the same digest, and the device
    // accepts only the low-s encoding. An external signer emits high-s about half the
    // time, so this is load-bearing, not cosmetic.
    let normalized = signature.normalize_s();
    let sig_bytes: [u8; SIG_LEN] = normalized.to_bytes().into();

    // Recompute the digest from the context. This is the one digest finalize trusts:
    // it is derived from the exact header and payload the bank will hold, never taken
    // from an external file.
    let mut hasher = Sha256::new();
    hasher.update(parsed.header);
    hasher.update(parsed.payload);
    let digest = hasher.finalize();

    // Validate the pinned key up front, then verify the normalized signature against
    // it over the digest. A mismatch fails closed and withholds the bank. Both
    // library types are parsed from the same pinned key bytes: RootKey for the
    // four-segment self-verify, VerifyingKey for the prehash verify here.
    let root = RootKey::from_bytes(*expected_root_key)
        .map_err(BankError::SelfVerifyFailed)?;
    let verifying = VerifyingKey::from_sec1_bytes(expected_root_key)
        .map_err(|_| BankError::SelfVerifyFailed(VerifyError::BadRootKey))?;
    verifying
        .verify_prehash(&digest, &normalized)
        .map_err(|_| BankError::ExternalSignatureRejected)?;

    // Lay the bank out through the shared helper, then run the same four-segment
    // self-verify assemble_bank runs. A layout bug fails here.
    let image = place_bank(parsed.boot, parsed.header, parsed.payload, &sig_bytes)?;
    verify_bank_segments(&image, &root).map_err(BankError::SelfVerifyFailed)?;

    Ok(AssembledBank
    {
        image,
        public_key: *expected_root_key,
        boot_len: parsed.boot.len(),
        payload_len: parsed.payload.len(),
        secure_len: parsed.secure_len,
        ns_len: parsed.ns_len,
    })
}

// The three verbatim regions plus the two actual lengths, borrowed out of a
// context blob. The header is a fixed-size reference so place_bank needs no
// re-check of its length.
struct ParsedContext<'a>
{
    boot: &'a [u8],
    header: &'a [u8; HEADER_LEN],
    payload: &'a [u8],
    secure_len: usize,
    ns_len: usize,
}

// Serializes the context: the magic, five little-endian u32 length fields, then the
// boot, header, and payload bytes verbatim. Every length is bounded by
// check_region_sizes.
fn serialize_context
(
    boot: &[u8],
    header: &[u8; HEADER_LEN],
    payload: &[u8],
    secure_len: usize,
    ns_len: usize,
)
    -> Vec<u8>
{
    let mut out = Vec::with_capacity(
        CONTEXT_FIXED_LEN + boot.len() + header.len() + payload.len(),
    );
    out.extend_from_slice(&CONTEXT_MAGIC);
    out.extend_from_slice(&len_le(boot.len()));
    out.extend_from_slice(&len_le(header.len()));
    out.extend_from_slice(&len_le(payload.len()));
    out.extend_from_slice(&len_le(secure_len));
    out.extend_from_slice(&len_le(ns_len));
    out.extend_from_slice(boot);
    out.extend_from_slice(header);
    out.extend_from_slice(payload);
    out
}

// Encodes a checked-small length as a little-endian u32. The value is always
// below a band size, so the truncating cast never loses a bit here.
fn len_le(value: usize) -> [u8; 4]
{
    (value as u32).to_le_bytes()
}

// Reads a little-endian u32 length field at `offset`, as a usize.
fn read_len(bytes: &[u8], offset: usize) -> Result<usize, BankError>
{
    let field: [u8; 4] = bytes
        .get(offset..offset + 4)
        .and_then(|b| b.try_into().ok())
        .ok_or(BankError::BadContext)?;
    Ok(u32::from_le_bytes(field) as usize)
}

// Parses and validates a context blob. Every geometry field is checked against
// the fixed band sizes, so a tampered or truncated context is rejected rather
// than trusted.
fn parse_context(bytes: &[u8]) -> Result<ParsedContext<'_>, BankError>
{
    if bytes.len() < CONTEXT_FIXED_LEN
    {
        return Err(BankError::BadContext);
    }
    if bytes.get(..8) != Some(CONTEXT_MAGIC.as_slice())
    {
        return Err(BankError::BadContext);
    }

    let boot_len = read_len(bytes, 8)?;
    let header_len = read_len(bytes, 12)?;
    let payload_len = read_len(bytes, 16)?;
    let secure_len = read_len(bytes, 20)?;
    let ns_len = read_len(bytes, 24)?;

    // The geometry must agree with the fixed bands, else the context is not one this
    // tool produced and finalize must not trust it.
    if header_len != HEADER_LEN
        || boot_len > BOOT_LEN
        || secure_len > SECURE_LEN
        || ns_len > NS_LEN
        || payload_len != SECURE_LEN + ns_len
    {
        return Err(BankError::BadContext);
    }

    // The body length must be exactly the three regions, with no missing and no
    // extra trailing bytes.
    let expected = CONTEXT_FIXED_LEN
        .checked_add(boot_len)
        .and_then(|v| v.checked_add(header_len))
        .and_then(|v| v.checked_add(payload_len))
        .ok_or(BankError::BadContext)?;
    if bytes.len() != expected
    {
        return Err(BankError::BadContext);
    }

    let boot_start = CONTEXT_FIXED_LEN;
    let header_start = boot_start + boot_len;
    let payload_start = header_start + header_len;

    let boot = bytes
        .get(boot_start..header_start)
        .ok_or(BankError::BadContext)?;
    let header: &[u8; HEADER_LEN] = bytes
        .get(header_start..payload_start)
        .and_then(|h| h.try_into().ok())
        .ok_or(BankError::BadContext)?;
    let payload = bytes
        .get(payload_start..payload_start + payload_len)
        .ok_or(BankError::BadContext)?;

    Ok(ParsedContext
    {
        boot,
        header,
        payload,
        secure_len,
        ns_len,
    })
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::SoftwareSigner;
    use crate::assemble_bank;
    use crate::derive_public_key;
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::hazmat::PrehashSigner;

    // The all-0x02 dev private scalar, a valid P-256 key, standing in for the
    // YubiKey. Publicly known, so every fixture is deterministic.
    const KEY: [u8; 32] = [2u8; 32];

    fn version() -> ImageVersion
    {
        ImageVersion
        {
            major: 0,
            minor: 0,
            revision: 1,
            build: 0,
        }
    }

    fn pubkey() -> [u8; ROOT_KEY_LEN]
    {
        derive_public_key(&KEY).expect("the dev scalar is valid")
    }

    fn signing_key() -> SigningKey
    {
        SigningKey::from_slice(&KEY).expect("the dev scalar is valid")
    }

    // Signs a 32-byte digest as a raw ECDSA signature (prehash, no re-hash), the
    // way a YubiKey signs the digest. RFC 6979 deterministic, so the low-s form
    // matches assemble_bank's software signer.
    fn sign_digest_low_s(digest: &[u8]) -> Signature
    {
        let sig: Signature = signing_key().sign_prehash(digest).expect("sign");
        sig.normalize_s()
    }

    fn sign_digest_high_s(digest: &[u8]) -> Signature
    {
        let low = sign_digest_low_s(digest);
        let (r, s) = low.split_scalars();
        Signature::from_scalars(r, -s).expect("n - s is valid")
    }

    fn boot() -> Vec<u8>
    {
        vec![0xA5u8; 4096]
    }

    fn secure() -> Vec<u8>
    {
        vec![0x11u8; 6000]
    }

    fn nonsecure() -> Vec<u8>
    {
        vec![0x22u8; 3000]
    }

    fn prepared() -> PreparedExternal
    {
        prepare_external(&boot(), &secure(), &nonsecure(), version(), 7)
            .expect("prepare must succeed")
    }

    // Prepare's digest must equal SHA-256(HEADER || PAYLOAD), the exact value the
    // device streams. Recomputed here from the context to cross-check.
    #[test]
    fn prepare_digest_is_sha256_of_header_and_payload()
    {
        let p = prepared();
        let ctx = parse_context(&p.context).expect("context parses");
        let mut hasher = Sha256::new();
        hasher.update(ctx.header);
        hasher.update(ctx.payload);
        let expected: [u8; DIGEST_LEN] = hasher.finalize().into();
        assert_eq!(p.digest, expected);
    }

    // A low-s external signature yields a self-verifying bank.
    #[test]
    fn finalize_accepts_a_low_s_signature()
    {
        let p = prepared();
        let sig = sign_digest_low_s(&p.digest);
        let bank = finalize_external(&p.context, &sig, &pubkey())
            .expect("finalize must accept a low-s signature");
        assert_eq!(bank.image.len(), crate::BANK_SIZE);
        assert_eq!(bank.public_key, pubkey());
    }

    // A high-s external signature (what a YubiKey emits half the time) must still
    // yield a self-verifying bank, proving the low-s normalization works.
    #[test]
    fn finalize_normalizes_a_high_s_signature()
    {
        let p = prepared();
        let high = sign_digest_high_s(&p.digest);
        // The input really is high-s, so the normalization is doing real work.
        assert!(bool::from(
            p256::elliptic_curve::scalar::IsHigh::is_high(&high.s())
        ));
        let bank = finalize_external(&p.context, &high, &pubkey())
            .expect("finalize must normalize and accept a high-s signature");
        assert_eq!(bank.image.len(), crate::BANK_SIZE);
    }

    // The external path matches the internal path. For the same inputs and key,
    // finalize and assemble_bank must produce byte-identical banks. The software
    // signer signs the digest deterministically (RFC 6979), the same nonce
    // assemble_bank's signer uses, so the low-s signature is identical.
    #[test]
    fn finalize_matches_assemble_bank_byte_for_byte()
    {
        let p = prepared();
        let sig = sign_digest_low_s(&p.digest);
        let external = finalize_external(&p.context, &sig, &pubkey())
            .expect("finalize");

        let signer = SoftwareSigner::from_key(&KEY).expect("key");
        let internal = assemble_bank(
            &boot(),
            &secure(),
            &nonsecure(),
            version(),
            7,
            &signer,
            &pubkey(),
        )
        .expect("assemble_bank");

        assert_eq!(external.image, internal.image, "the two paths must agree");
    }

    // The high-s path also lands on the exact assemble_bank bytes, since the
    // normalized signature is the same low-s twin.
    #[test]
    fn finalize_high_s_also_matches_assemble_bank()
    {
        let p = prepared();
        let high = sign_digest_high_s(&p.digest);
        let external = finalize_external(&p.context, &high, &pubkey())
            .expect("finalize");

        let signer = SoftwareSigner::from_key(&KEY).expect("key");
        let internal = assemble_bank(
            &boot(),
            &secure(),
            &nonsecure(),
            version(),
            7,
            &signer,
            &pubkey(),
        )
        .expect("assemble_bank");

        assert_eq!(external.image, internal.image);
    }

    // A signature made by a wrong key must be rejected, with no bank. This pins that
    // the accept above is real, not a path that accepts anything.
    #[test]
    fn finalize_rejects_a_wrong_key_signature()
    {
        let p = prepared();
        // Sign the correct digest with a different key.
        let other = SigningKey::from_slice(&[3u8; 32]).expect("valid scalar");
        let sig: Signature = other.sign_prehash(&p.digest).expect("sign");
        let result = finalize_external(&p.context, &sig, &pubkey());
        assert_eq!(result.err(), Some(BankError::ExternalSignatureRejected));
    }

    // A signature over a different digest must be rejected. The signature is valid
    // under the pinned key, only the message is wrong, so only the verify can catch
    // it.
    #[test]
    fn finalize_rejects_a_signature_over_a_different_digest()
    {
        let p = prepared();
        let wrong_digest = Sha256::digest(b"a different message");
        let sig: Signature =
            signing_key().sign_prehash(&wrong_digest).expect("sign");
        let result = finalize_external(&p.context, &sig, &pubkey());
        assert_eq!(result.err(), Some(BankError::ExternalSignatureRejected));
    }

    // A raw signature and its DER encoding of the same (r, s) parse to the same
    // signature, so both toolchain outputs are accepted.
    #[test]
    fn parse_signature_accepts_raw_and_der()
    {
        let p = prepared();
        let sig = sign_digest_low_s(&p.digest);
        let raw_bytes: [u8; SIG_LEN] = sig.to_bytes().into();
        let der_bytes = sig.to_der();

        let from_raw = parse_signature(&raw_bytes, SigFormat::Raw).expect("raw");
        let from_der =
            parse_signature(der_bytes.as_bytes(), SigFormat::Der).expect("der");
        assert_eq!(from_raw, from_der);

        // Auto picks raw for 64 bytes and DER otherwise.
        let auto_raw = parse_signature(&raw_bytes, SigFormat::Auto).expect("raw");
        let auto_der =
            parse_signature(der_bytes.as_bytes(), SigFormat::Auto).expect("der");
        assert_eq!(auto_raw, auto_der);
    }

    // A DER signature drives FINALIZE all the way to a self-verifying bank, the
    // openssl / PIV default path.
    #[test]
    fn finalize_accepts_a_der_signature()
    {
        let p = prepared();
        let sig = sign_digest_low_s(&p.digest);
        let der_bytes = sig.to_der();
        let parsed =
            parse_signature(der_bytes.as_bytes(), SigFormat::Auto).expect("der");
        let bank = finalize_external(&p.context, &parsed, &pubkey())
            .expect("finalize accepts a DER signature");
        assert_eq!(bank.image.len(), crate::BANK_SIZE);
    }

    // Truncated and garbage signature bytes are rejected in every format.
    #[test]
    fn parse_signature_rejects_corrupt_bytes()
    {
        // 63 bytes is one short of a raw pair.
        assert_eq!(
            parse_signature(&[1u8; 63], SigFormat::Raw).err(),
            Some(BankError::BadSignatureFormat)
        );
        // All-zero 64 bytes is r = s = 0, not a valid pair.
        assert_eq!(
            parse_signature(&[0u8; SIG_LEN], SigFormat::Raw).err(),
            Some(BankError::BadSignatureFormat)
        );
        // Not DER at all.
        assert_eq!(
            parse_signature(b"not der bytes", SigFormat::Der).err(),
            Some(BankError::BadSignatureFormat)
        );
        // Auto over an odd length that is not valid DER.
        assert_eq!(
            parse_signature(&[0xFFu8; 10], SigFormat::Auto).err(),
            Some(BankError::BadSignatureFormat)
        );
    }

    // A corrupt context is rejected before any crypto: wrong magic, truncation,
    // and a tampered length field each fail closed.
    #[test]
    fn parse_context_rejects_a_corrupt_context()
    {
        let good = prepared().context;

        // Wrong magic.
        let mut bad_magic = good.clone();
        bad_magic[0] ^= 0xFF;
        assert_eq!(parse_context(&bad_magic).err(), Some(BankError::BadContext));

        // Truncated body.
        let truncated = &good[..good.len() - 1];
        assert_eq!(parse_context(truncated).err(), Some(BankError::BadContext));

        // A tampered payload-length field no longer matches the body length.
        let mut bad_len = good.clone();
        bad_len[16] ^= 0x01;
        assert_eq!(parse_context(&bad_len).err(), Some(BankError::BadContext));

        // Shorter than even the fixed header.
        assert_eq!(parse_context(&[0u8; 4]).err(), Some(BankError::BadContext));
    }

    // FINALIZE over a corrupt context fails closed, no bank.
    #[test]
    fn finalize_rejects_a_corrupt_context()
    {
        let p = prepared();
        let sig = sign_digest_low_s(&p.digest);
        let mut bad = p.context.clone();
        bad[0] ^= 0xFF;
        let result = finalize_external(&bad, &sig, &pubkey());
        assert_eq!(result.err(), Some(BankError::BadContext));
    }

    // An oversize secure image is refused at PREPARE, with no digest.
    #[test]
    fn prepare_refuses_an_oversize_secure_image()
    {
        let big = vec![0u8; SECURE_LEN + 1];
        let result =
            prepare_external(&boot(), &big, &nonsecure(), version(), 0);
        assert_eq!(
            result.err(),
            Some(BankError::SecureTooLarge { got: SECURE_LEN + 1 })
        );
    }
}
