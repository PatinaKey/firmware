//! X.509 certificate-store parsing to extract STPUB.
//!
//! STPUB is the chip static X25519 public key (32 bytes) carried in the DEVICE
//! certificate of the `Get_Info` X.509 store. It seeds the Noise KK1 handshake.
//!
//! This is an ATTACKER-FACING decoder: the DER comes from the chip and is
//! untrusted. Every read goes through the bounds-checked combinators in
//! `parse`; there is no raw indexing, no unwrap, no panic. The DER walk is a
//! depth-bounded recursive descent: each nested object is bounded to its
//! declared length, and the recursion stops at a hard depth cap, so a
//! maliciously nested or malformed cert can neither read out of bounds nor
//! exhaust the stack. (libtropic recurses without a depth cap; this is
//! stricter.)
//!
//! SECURITY: this extracts STPUB ONLY. It does NOT verify the certificate-chain
//! signatures up to the Tropic root. libtropic `lt_get_st_pub` likewise only
//! parses; chain verification is a separate deferred concern (an external X.509
//! verifier consumes the four DER blobs). A wrong or substituted STPUB cannot
//! silently open a session: STPUB is bound into BOTH the handshake transcript
//! hash and the static-key DH, so a bad value breaks the auth tag. The parser is
//! therefore not a standalone trust boundary; the handshake is. Full chain
//! validation is a future slice.

use crate::error::CertError;
use crate::error::SeError;
use crate::parse::take;
use crate::parse::take_array;
use crate::parse::take_be_u16;
use crate::parse::take_u8;

/// X25519 OBJECT IDENTIFIER body bytes (OID 1.3.101.110, id-X25519).
///
/// The id-X25519 OID body is exactly these three bytes; the match requires the
/// whole OID content to equal them, not merely to start with them. Source:
/// libtropic `LT_OBJ_ID_CURVEX25519` (0x2B656E).
const OID_X25519: [u8; 3] = [0x2B, 0x65, 0x6E];

/// STPUB length in bytes (X25519 public key). Source: libtropic `TR01_STPUB_LEN`.
const STPUB_LEN: usize = 32;

/// Maximum DER nesting depth the walk descends.
///
/// Real TROPIC01 device certs nest only a few levels deep
/// (Certificate -> tbsCertificate -> SubjectPublicKeyInfo -> AlgorithmIdentifier).
/// The cap bounds the recursion so an adversarially nested cert cannot exhaust
/// the stack, while leaving ample headroom for any well-formed certificate.
const MAX_DER_DEPTH: u8 = 24;

/// DER tag for a SEQUENCE (constructed). The walk descends into these.
const TAG_SEQUENCE: u8 = 0x30;
/// DER tag for an OBJECT IDENTIFIER. Matched against the X25519 OID.
const TAG_OID: u8 = 0x06;
/// DER tag for a BIT STRING. The X25519 SPKI public key object.
const TAG_BIT_STRING: u8 = 0x03;

/// Extracts STPUB from a raw `Get_Info` X.509 certificate store.
///
/// Parses the 10-byte store header (version 0x01, num_certs 0x04, four big-endian
/// u16 per-cert lengths), takes the DEVICE certificate body, then walks its DER
/// to the X25519 public key and returns the 32 STPUB bytes by value (STPUB is
/// PUBLIC). Trailing store bytes after the certificates are PADDING and ignored.
///
/// Errors: `BadStore` (wrong version/num_certs, truncated header or cert),
/// `Unsupported` (DER length long-form over 2 bytes or nesting past the depth
/// cap), `KeyNotFound` (no X25519 key object), `Malformed` (any other DER
/// bounds/structure fault).
///
/// SECURITY: extracts STPUB only; does NOT validate the certificate chain (see
/// the module note).
pub fn parse_stpub(cert_store: &[u8]) -> Result<[u8; 32], SeError>
{
    let device_cert = device_cert_body(cert_store)?;
    let stpub = walk_to_x25519_key(device_cert)?;
    Ok(stpub)
}

/// Splits the store header off and returns the DEVICE certificate body slice.
///
/// Header layout (big-endian): VERSION(1) || NUM_CERTS(1) || LEN[0..4] (four
/// u16). The DEVICE cert is `LEN[0]` bytes immediately after the 10-byte header.
/// Validates VERSION == 0x01 and NUM_CERTS == 0x04. Bounds are enforced by
/// `take`, so an overrunning `LEN[0]` fails closed.
fn device_cert_body(store: &[u8]) -> Result<&[u8], CertError>
{
    // VERSION(1) || NUM_CERTS(1).
    let (rest, version) = take_u8(store).map_err(|_| CertError::BadStore)?;
    if version != 0x01
    {
        return Err(CertError::BadStore);
    }
    let (rest, num_certs) = take_u8(rest).map_err(|_| CertError::BadStore)?;
    if num_certs != 0x04
    {
        return Err(CertError::BadStore);
    }
    // Four big-endian u16 lengths LEN[0..4]. Only LEN[0] is needed, but all four
    // must be consumed to land at the cert body (offset 10).
    let (rest, len0) = take_be_u16(rest).map_err(|_| CertError::BadStore)?;
    let (rest, _len1) = take_be_u16(rest).map_err(|_| CertError::BadStore)?;
    let (rest, _len2) = take_be_u16(rest).map_err(|_| CertError::BadStore)?;
    let (rest, _len3) = take_be_u16(rest).map_err(|_| CertError::BadStore)?;
    // The DEVICE cert is the first LEN[0] bytes. `take` rejects an overrunning
    // length. The bytes after it (other certs + padding) are ignored.
    let (device_cert, _after) = take(rest, len0 as usize).map_err(|_| CertError::BadStore)?;
    Ok(device_cert)
}

/// Walks the DEVICE certificate DER to the X25519 public key.
///
/// A DER X.509 certificate is exactly one outer SEQUENCE. This requires that
/// outer SEQUENCE to span the whole cert body (rejecting loose trailing
/// objects), then descends its content looking for the X25519 SPKI key.
///
/// Returns `KeyNotFound` when the OID/key is absent, `Unsupported`/`Malformed`
/// on bad DER.
fn walk_to_x25519_key(device_cert: &[u8]) -> Result<[u8; 32], CertError>
{
    let (after_tag, tag) = take_u8(device_cert).map_err(|_| CertError::Malformed)?;
    if tag != TAG_SEQUENCE
    {
        return Err(CertError::Malformed);
    }
    let (after_len, length) = parse_der_len(after_tag)?;
    let (content, trailing) = take(after_len, length).map_err(|_| CertError::Malformed)?;
    if !trailing.is_empty()
    {
        // A certificate is a single SEQUENCE; bytes after it are not part of it.
        return Err(CertError::Malformed);
    }
    let mut sample_next = false;
    let mut key: Option<[u8; 32]> = None;
    walk_der(content, MAX_DER_DEPTH, &mut sample_next, &mut key)?;
    key.ok_or(CertError::KeyNotFound)
}

/// Descends one DER nesting level, threading `sample_next` and `key` in document
/// order.
///
/// Faithful, depth-bounded reimplementation of libtropic `asn1der_find_object`
/// for STPUB. Each object's content is bounded to its declared length, so a
/// child can never read past its parent. SEQUENCE (0x30) is descended; when an
/// OBJECT IDENTIFIER equals the X25519 OID, the next BIT STRING is the key.
/// Other tags are skipped. The `sample_next`/`key` state is shared across the
/// recursion so "the BIT STRING after the OID" works even though the OID sits
/// inside the inner AlgorithmIdentifier SEQUENCE and the key is its sibling.
///
/// Note: if `sample_next` is already set when a SEQUENCE is met, the SEQUENCE is
/// descended rather than sampled. That is correct for the X.509 SPKI shape (the
/// key BIT STRING is a sibling of the AlgorithmIdentifier, not nested under an
/// extra SEQUENCE). The real-cert golden test guards this assumption.
fn walk_der
(
    der: &[u8],
    depth: u8,
    sample_next: &mut bool,
    key: &mut Option<[u8; 32]>,
)
-> Result<(), CertError>
{
    let mut cursor = der;
    while !cursor.is_empty()
    {
        if key.is_some()
        {
            // The key was found in an earlier sibling; stop walking.
            return Ok(());
        }
        let (after_tag, tag) = take_u8(cursor).map_err(|_| CertError::Malformed)?;
        let (after_len, length) = parse_der_len(after_tag)?;
        // Bound the content to its declared length. `take` rejects an object
        // that overruns the enclosing slice, so a child cannot escape its parent.
        let (content, after_content) =
            take(after_len, length).map_err(|_| CertError::Malformed)?;
        if tag == TAG_SEQUENCE
        {
            // SEQUENCE (constructed): descend into the bounded content.
            let next_depth = depth.checked_sub(1).ok_or(CertError::Unsupported)?;
            walk_der(content, next_depth, sample_next, key)?;
        }
        else if *sample_next && tag == TAG_BIT_STRING
        {
            // BIT STRING right after the X25519 OID: this is the SPKI key.
            *key = Some(crop_x25519_key(content)?);
            return Ok(());
        }
        else if tag == TAG_OID && content == OID_X25519
        {
            // Exact id-X25519 OID: the next BIT STRING is the key. A longer OID
            // merely prefixed with these bytes is a different OID and is rejected.
            *sample_next = true;
        }
        // Any other tag (context wrappers, params, SET, ...) is skipped while
        // `sample_next` stays set, so the search continues to the BIT STRING.
        cursor = after_content;
    }
    Ok(())
}

/// Parses a DER length from the front of `input`, returning `(rest, length)`.
///
/// Short form (`b < 0x80`): length is `b`. Long form (`b >= 0x80`): the low 7
/// bits give the count of big-endian length bytes; libtropic supports 1 or 2.
/// `n == 0` (indefinite) and `n > 2` are `Unsupported`. A truncated length is
/// `Malformed`.
fn parse_der_len(input: &[u8]) -> Result<(&[u8], usize), CertError>
{
    let (rest, first) = take_u8(input).map_err(|_| CertError::Malformed)?;
    if first < 0x80
    {
        return Ok((rest, first as usize));
    }
    let n = first ^ 0x80;
    if n == 0 || n > 2
    {
        return Err(CertError::Unsupported);
    }
    let mut value: usize = 0;
    let mut rest = rest;
    for _ in 0..n
    {
        let (next, byte) = take_u8(rest).map_err(|_| CertError::Malformed)?;
        // n <= 2, so value never exceeds 0xFFFF: the shift cannot overflow usize.
        value = (value << 8) | byte as usize;
        rest = next;
    }
    Ok((rest, value))
}

/// Crops a sampled X25519 SPKI BIT STRING to its 32 key bytes.
///
/// The X25519 subjectPublicKey is a 33-byte BIT STRING value: one unused-bits
/// byte (0x00) then the 32 key bytes. This requires exactly that shape - the
/// leading 0x00 and no trailing bytes - so an oversized or malformed object
/// cannot smuggle attacker-chosen bytes through as the key.
fn crop_x25519_key(content: &[u8]) -> Result<[u8; 32], CertError>
{
    let (rest, unused_bits) = take_u8(content).map_err(|_| CertError::Malformed)?;
    if unused_bits != 0x00
    {
        return Err(CertError::Malformed);
    }
    let (tail, key) = take_array::<STPUB_LEN>(rest).map_err(|_| CertError::Malformed)?;
    if !tail.is_empty()
    {
        return Err(CertError::Malformed);
    }
    Ok(key)
}

#[cfg(test)]
mod tests
{
    use super::*;

    // The authoritative STPUB the model and the real device certificate carry.
    const STPUB: [u8; 32] = [
        0x95, 0x08, 0xf0, 0x32, 0x1c, 0xb1, 0xd2, 0xe5, 0xd1, 0xf1, 0xa4, 0x60, 0x9c, 0x05, 0x41,
        0xb7, 0x80, 0xe6, 0xdd, 0x50, 0xd6, 0x48, 0x2b, 0x6b, 0x08, 0xb2, 0xc2, 0x7e, 0x7b, 0x76,
        0x26, 0x47,
    ];

    // The REAL 479-byte TROPIC01 DEVICE certificate (cert[0] of the model's
    // X.509 store, byte-identical to what the live model serves). It is a full
    // certificate: a [0] version wrapper, an ECDSA-SHA384 signature-algid OID
    // (2a8648ce3d040303, which must NOT false-match), issuer/subject Names with
    // their own OIDs inside skipped SETs, validity, the X25519 SubjectPublicKeyInfo,
    // and a [3] extensions block after the key. Parsing it end-to-end proves the
    // walk handles realistic structure and stops at the key.
    const REAL_DEVICE_CERT: [u8; 479] = [
        0x30, 0x82, 0x01, 0xdb, 0x30, 0x82, 0x01, 0x62, 0xa0, 0x03, 0x02, 0x01,
        0x02, 0x02, 0x10, 0x02, 0xf0, 0x02, 0x00, 0x08, 0x82, 0x19, 0x06, 0x1b,
        0x09, 0x33, 0x00, 0x00, 0x04, 0x00, 0x09, 0x30, 0x0a, 0x06, 0x08, 0x2a,
        0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03, 0x30, 0x4c, 0x31, 0x0b, 0x30,
        0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x43, 0x5a, 0x31, 0x1d,
        0x30, 0x1b, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x14, 0x54, 0x72, 0x6f,
        0x70, 0x69, 0x63, 0x20, 0x53, 0x71, 0x75, 0x61, 0x72, 0x65, 0x20, 0x73,
        0x2e, 0x72, 0x2e, 0x6f, 0x2e, 0x31, 0x1e, 0x30, 0x1c, 0x06, 0x03, 0x55,
        0x04, 0x03, 0x0c, 0x15, 0x54, 0x52, 0x4f, 0x50, 0x49, 0x43, 0x30, 0x31,
        0x2d, 0x58, 0x20, 0x54, 0x45, 0x53, 0x54, 0x20, 0x43, 0x41, 0x20, 0x76,
        0x31, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x35, 0x30, 0x36, 0x32, 0x37, 0x30,
        0x38, 0x34, 0x30, 0x35, 0x35, 0x5a, 0x17, 0x0d, 0x34, 0x35, 0x30, 0x36,
        0x32, 0x37, 0x30, 0x38, 0x34, 0x30, 0x35, 0x35, 0x5a, 0x30, 0x1c, 0x31,
        0x1a, 0x30, 0x18, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x11, 0x54, 0x52,
        0x4f, 0x50, 0x49, 0x43, 0x30, 0x31, 0x20, 0x65, 0x53, 0x45, 0x20, 0x54,
        0x45, 0x53, 0x54, 0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e,
        0x03, 0x21, 0x00, 0x95, 0x08, 0xf0, 0x32, 0x1c, 0xb1, 0xd2, 0xe5, 0xd1,
        0xf1, 0xa4, 0x60, 0x9c, 0x05, 0x41, 0xb7, 0x80, 0xe6, 0xdd, 0x50, 0xd6,
        0x48, 0x2b, 0x6b, 0x08, 0xb2, 0xc2, 0x7e, 0x7b, 0x76, 0x26, 0x47, 0xa3,
        0x81, 0x84, 0x30, 0x81, 0x81, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13,
        0x01, 0x01, 0xff, 0x04, 0x02, 0x30, 0x00, 0x30, 0x0e, 0x06, 0x03, 0x55,
        0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x03, 0x08, 0x30,
        0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14,
        0x7b, 0xf3, 0x8c, 0x79, 0x9b, 0x7a, 0x4b, 0x2e, 0xbf, 0x41, 0x05, 0x7d,
        0xd5, 0xd2, 0x6a, 0xeb, 0x5d, 0xa0, 0x40, 0xf3, 0x30, 0x40, 0x06, 0x03,
        0x55, 0x1d, 0x1f, 0x04, 0x39, 0x30, 0x37, 0x30, 0x35, 0xa0, 0x33, 0xa0,
        0x31, 0x86, 0x2f, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x70, 0x6b,
        0x69, 0x2e, 0x74, 0x72, 0x6f, 0x70, 0x69, 0x63, 0x73, 0x71, 0x75, 0x61,
        0x72, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6c, 0x33, 0x2f, 0x74, 0x30,
        0x31, 0x2d, 0x54, 0x76, 0x31, 0x2d, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x63,
        0x72, 0x6c, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04,
        0x03, 0x03, 0x03, 0x67, 0x00, 0x30, 0x64, 0x02, 0x30, 0x41, 0x1d, 0x4e,
        0x3f, 0xf8, 0xc5, 0x1f, 0x7e, 0x76, 0x4c, 0xa6, 0x33, 0x05, 0x2c, 0x32,
        0x40, 0x0d, 0xf7, 0x69, 0xe7, 0xaa, 0x39, 0x00, 0x65, 0xc3, 0xd7, 0xa0,
        0x88, 0xa7, 0xda, 0x9a, 0x48, 0xac, 0xf2, 0x09, 0xd5, 0x09, 0x83, 0x3a,
        0x81, 0x18, 0x52, 0x9c, 0xf8, 0xe3, 0x54, 0x94, 0xb4, 0x02, 0x30, 0x6d,
        0x6d, 0x42, 0xa5, 0x0c, 0x13, 0xf8, 0x1d, 0x52, 0x51, 0x0b, 0x6b, 0xc5,
        0xef, 0x16, 0x5f, 0xa3, 0x01, 0x82, 0xc5, 0xe3, 0x2f, 0x5d, 0x4e, 0xa9,
        0xc0, 0x46, 0x8b, 0x3b, 0x02, 0xf7, 0xa2, 0x8c, 0xee, 0x79, 0xdb, 0xcf,
        0x54, 0x6f, 0xdb, 0x55, 0xe0, 0xf0, 0x3a, 0xd0, 0xd5, 0x98, 0xf7,
    ];

    /// Wraps a DEVICE cert in a valid 10-byte store header (LEN[0] = cert len).
    /// The other three certs are declared zero-length; trailing padding is added
    /// by the caller when needed.
    fn store_with(cert: &[u8], out: &mut [u8])
    {
        out[0] = 0x01; // version
        out[1] = 0x04; // num_certs
        let len0 = cert.len() as u16;
        out[2..4].copy_from_slice(&len0.to_be_bytes());
        // LEN[1..4] stay zero.
        out[10..10 + cert.len()].copy_from_slice(cert);
    }

    // A minimal but realistic DEVICE certificate:
    //   SEQUENCE {
    //     [0] { INTEGER 1 },              // version wrapper, a non-SEQUENCE tag
    //     OID 2.5.4.3 (commonName),       // a non-matching OID (no false match)
    //     OID 1.3.101.110 (id-X25519),    // the match trigger
    //     BIT STRING 00 || <32 STPUB>     // the sampled key object
    //   }
    fn minimal_device_cert() -> [u8; 52]
    {
        let mut cert = [0u8; 52];
        // SEQUENCE, length 50 (short form).
        cert[0] = TAG_SEQUENCE;
        cert[1] = 50;
        // [0] { INTEGER 01 } : a0 03 02 01 01
        cert[2..7].copy_from_slice(&[0xA0, 0x03, 0x02, 0x01, 0x01]);
        // OID commonName (non-matching): 06 03 55 04 03
        cert[7..12].copy_from_slice(&[0x06, 0x03, 0x55, 0x04, 0x03]);
        // OID id-X25519 (match): 06 03 2b 65 6e
        cert[12..17].copy_from_slice(&[0x06, 0x03, 0x2B, 0x65, 0x6E]);
        // BIT STRING 33 bytes: 03 21 00 || STPUB
        cert[17..20].copy_from_slice(&[0x03, 0x21, 0x00]);
        cert[20..52].copy_from_slice(&STPUB);
        cert
    }

    fn minimal_store() -> [u8; 62]
    {
        let mut store = [0u8; 62];
        store_with(&minimal_device_cert(), &mut store);
        store
    }

    #[test]
    fn real_device_cert_yields_stpub()
    {
        // The strongest hermetic proof: the actual chip/model device certificate,
        // with its [0] version wrapper, ECDSA signature-algid OID, Name SETs, and
        // [3] extensions, parses to the authoritative STPUB without false-matching.
        let mut store = [0u8; 10 + 479];
        store_with(&REAL_DEVICE_CERT, &mut store);
        assert_eq!(parse_stpub(&store), Ok(STPUB));
    }

    #[test]
    fn real_device_cert_tolerates_block_padding()
    {
        // The chip serves the store as 30 x 128 = 3840 bytes; the real cert store
        // is shorter, so the tail is padding. parse_stpub must ignore it.
        let mut store = [0u8; 3840];
        store_with(&REAL_DEVICE_CERT, &mut store);
        assert_eq!(parse_stpub(&store), Ok(STPUB));
    }

    #[test]
    fn minimal_store_yields_stpub()
    {
        assert_eq!(parse_stpub(&minimal_store()), Ok(STPUB));
    }

    #[test]
    fn trailing_padding_is_tolerated()
    {
        let minimal = minimal_store();
        let mut padded = [0u8; 256];
        padded[..minimal.len()].copy_from_slice(&minimal);
        assert_eq!(parse_stpub(&padded), Ok(STPUB));
    }

    #[test]
    fn bad_version_rejected()
    {
        let mut store = minimal_store();
        store[0] = 0x02;
        assert_eq!(parse_stpub(&store), Err(SeError::Cert(CertError::BadStore)));
    }

    #[test]
    fn bad_num_certs_rejected()
    {
        let mut store = minimal_store();
        store[1] = 0x03;
        assert_eq!(parse_stpub(&store), Err(SeError::Cert(CertError::BadStore)));
    }

    #[test]
    fn truncated_header_rejected()
    {
        // Fewer than the 10 header bytes: cannot read the four lengths.
        let store = [0x01u8, 0x04, 0x00];
        assert_eq!(parse_stpub(&store), Err(SeError::Cert(CertError::BadStore)));
    }

    #[test]
    fn empty_input_rejected()
    {
        assert_eq!(parse_stpub(&[]), Err(SeError::Cert(CertError::BadStore)));
    }

    #[test]
    fn device_cert_length_overrunning_store_rejected()
    {
        let mut store = minimal_store();
        store[2..4].copy_from_slice(&0xFFFFu16.to_be_bytes());
        assert_eq!(parse_stpub(&store), Err(SeError::Cert(CertError::BadStore)));
    }

    #[test]
    fn truncated_device_cert_does_not_panic()
    {
        // Header declares a 52-byte cert but the store ends early.
        let minimal = minimal_store();
        let store = &minimal[..minimal.len() - 10];
        assert_eq!(parse_stpub(store), Err(SeError::Cert(CertError::BadStore)));
    }

    #[test]
    fn der_length_long_form_over_two_bytes_unsupported()
    {
        // An inner object uses a 3-byte long-form length (0x83), unsupported.
        let cert = [TAG_SEQUENCE, 0x08, 0x06, 0x83, 0x00, 0x00, 0x03, 0x2B, 0x65, 0x6E];
        let mut store = [0u8; 10 + 10];
        store_with(&cert, &mut store);
        assert_eq!(parse_stpub(&store), Err(SeError::Cert(CertError::Unsupported)));
    }

    #[test]
    fn oid_present_but_no_following_key_not_found()
    {
        // SEQUENCE { OID id-X25519 } and nothing after it.
        let cert = [TAG_SEQUENCE, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x6E];
        let mut store = [0u8; 10 + 7];
        store_with(&cert, &mut store);
        assert_eq!(parse_stpub(&store), Err(SeError::Cert(CertError::KeyNotFound)));
    }

    #[test]
    fn bit_string_content_under_32_rejected()
    {
        // SEQUENCE { OID id-X25519, BIT STRING (5 bytes) }: shorter than the key.
        let cert = [
            TAG_SEQUENCE, 0x0C, 0x06, 0x03, 0x2B, 0x65, 0x6E, 0x03, 0x05, 0x00, 0x01, 0x02, 0x03,
            0x04,
        ];
        let mut store = [0u8; 10 + 14];
        store_with(&cert, &mut store);
        assert_eq!(parse_stpub(&store), Err(SeError::Cert(CertError::Malformed)));
    }

    #[test]
    fn key_oid_absent_not_found()
    {
        // SEQUENCE { OID commonName } : no X25519 OID, so no key is sampled.
        let cert = [TAG_SEQUENCE, 0x05, 0x06, 0x03, 0x55, 0x04, 0x03];
        let mut store = [0u8; 10 + 7];
        store_with(&cert, &mut store);
        assert_eq!(parse_stpub(&store), Err(SeError::Cert(CertError::KeyNotFound)));
    }

    // --- Hardening regression tests (red-team attacks A-D). Each crafts a cert
    // that a loose "byte-soup scanner" would mis-extract; the bounded DER walk
    // must reject or not mis-sample it. STPUB substitution is handshake-capped,
    // but the parser must still not be weaker than libtropic ground truth.

    #[test]
    fn loose_object_after_closed_sequence_rejected()
    {
        // Attack D: a closed SEQUENCE then a loose OID outside it. The cert is not
        // a single spanning SEQUENCE, so the trailing loose object is rejected
        // before the walk can reach a relocated key.
        let cert = [
            TAG_SEQUENCE, 0x02, 0x05, 0x00, // SEQUENCE { NULL }
            0x06, 0x03, 0x2B, 0x65, 0x6E, // loose OID id-X25519 outside the SEQUENCE
        ];
        let mut store = [0u8; 10 + 9];
        store_with(&cert, &mut store);
        assert_eq!(parse_stpub(&store), Err(SeError::Cert(CertError::Malformed)));
    }

    #[test]
    fn prefix_oid_does_not_false_match()
    {
        // Attack A: a 5-byte OID whose first three bytes are the X25519 OID. The
        // exact-OID match must not trigger, so nothing is ever sampled.
        let cert = [
            TAG_SEQUENCE, 0x07, //
            0x06, 0x05, 0x2B, 0x65, 0x6E, 0x99, 0x99, // OID 2b656e9999 (a different OID)
        ];
        let mut store = [0u8; 10 + 9];
        store_with(&cert, &mut store);
        // No exact X25519 OID -> never samples -> KeyNotFound.
        assert_eq!(parse_stpub(&store), Err(SeError::Cert(CertError::KeyNotFound)));
    }

    #[test]
    fn context_tag_after_oid_is_not_sampled()
    {
        // Attack B: the object after the X25519 OID is a context wrapper (0xA0),
        // not a BIT STRING. It must be skipped, not cropped as the key.
        let cert = [
            TAG_SEQUENCE, 0x0A, //
            0x06, 0x03, 0x2B, 0x65, 0x6E, // OID id-X25519 -> sample_next
            0xA0, 0x03, 0xBB, 0xBB, 0xBB, // context wrapper with attacker bytes
        ];
        let mut store = [0u8; 10 + 12];
        store_with(&cert, &mut store);
        // sample_next stays set but no BIT STRING follows -> KeyNotFound.
        assert_eq!(parse_stpub(&store), Err(SeError::Cert(CertError::KeyNotFound)));
    }

    #[test]
    fn oversized_bit_string_rejected()
    {
        // Attack C: a 65-byte BIT STRING (00 || 64 attacker bytes). The key object
        // must be exactly 33 bytes (00 || 32), so an oversized one is rejected and
        // cannot smuggle the trailing 32 bytes through as the key.
        let mut cert = [0u8; 7 + 67];
        cert[0] = TAG_SEQUENCE;
        cert[1] = (cert.len() - 2) as u8;
        cert[2..7].copy_from_slice(&[0x06, 0x03, 0x2B, 0x65, 0x6E]); // OID id-X25519
        cert[7..10].copy_from_slice(&[0x03, 0x41, 0x00]); // BIT STRING len 0x41 = 65
        // 64 attacker bytes after the unused-bits byte.
        for b in cert.iter_mut().skip(10)
        {
            *b = 0x11;
        }
        let mut store = [0u8; 10 + 74];
        store_with(&cert, &mut store);
        assert_eq!(parse_stpub(&store), Err(SeError::Cert(CertError::Malformed)));
    }

    #[test]
    fn deeply_nested_sequences_hit_depth_cap_without_panic()
    {
        // A long run of nested empty-ish SEQUENCE headers. Each `30 NN` opens a
        // deeper level; past MAX_DER_DEPTH the walk returns Unsupported rather than
        // recursing further. No stack exhaustion, no panic.
        let mut cert = [0u8; 2 + 200];
        cert[0] = TAG_SEQUENCE;
        cert[1] = 200;
        // Fill the content with 0x30 0x82-style headers is overkill; a simple run
        // of `30 7e` (SEQUENCE, large length) repeatedly nests one level per pair.
        let mut i = 2;
        while i + 1 < cert.len()
        {
            cert[i] = TAG_SEQUENCE;
            cert[i + 1] = (cert.len() - i - 2) as u8;
            i += 2;
        }
        let mut store = [0u8; 10 + 202];
        store_with(&cert, &mut store);
        // Whatever the exact error, it must be a typed CertError and never panic.
        let r = parse_stpub(&store);
        assert!(matches!(r, Err(SeError::Cert(_))));
    }

    #[test]
    fn parse_stpub_never_panics_on_any_truncation()
    {
        // Truncate the REAL cert store at every length and assert no panic. The
        // real cert exercises far more DER structure than the minimal one.
        let mut store = [0u8; 10 + 479];
        store_with(&REAL_DEVICE_CERT, &mut store);
        for cut in 0..=store.len()
        {
            let _ = parse_stpub(&store[..cut]);
        }
    }

    #[test]
    fn parse_der_len_short_form()
    {
        let (rest, len) = parse_der_len(&[0x21, 0xAA]).unwrap();
        assert_eq!(len, 0x21);
        assert_eq!(rest, &[0xAA]);
    }

    #[test]
    fn parse_der_len_long_form_two_bytes()
    {
        let (rest, len) = parse_der_len(&[0x82, 0x01, 0x62, 0xAA]).unwrap();
        assert_eq!(len, 0x0162);
        assert_eq!(rest, &[0xAA]);
    }

    #[test]
    fn parse_der_len_indefinite_unsupported()
    {
        assert_eq!(parse_der_len(&[0x80]), Err(CertError::Unsupported));
    }

    #[test]
    fn parse_der_len_truncated_long_form_malformed()
    {
        // Says two length bytes follow but only one is present.
        assert_eq!(parse_der_len(&[0x82, 0x01]), Err(CertError::Malformed));
    }
}
