//! X.509 certificate-store parsing to extract STPUB.
//!
//! STPUB is the chip static X25519 public key (32 bytes) carried in the DEVICE
//! certificate of the `Get_Info` X.509 store. It seeds the Noise KK1 handshake.
//!
//! This is an ATTACKER-FACING decoder: the DER comes from the chip and is
//! untrusted. Every read goes through the bounds-checked combinators in
//! `parse`. There is no raw indexing, no unwrap, no panic. The DER walk is a
//! depth-bounded recursive descent: each nested object is bounded to its
//! declared length, and the recursion stops at a hard depth cap, so a
//! maliciously nested or malformed cert can neither read out of bounds nor
//! exhaust the stack. (libtropic recurses without a depth cap. This is
//! stricter.)
//!
//! SECURITY: this extracts STPUB ONLY. It does NOT verify the certificate-chain
//! signatures up to the Tropic root. libtropic `lt_get_st_pub` likewise only
//! parses. Chain verification is a separate deferred concern (an external X.509
//! verifier consumes the four DER blobs). A wrong or substituted STPUB cannot
//! silently open a session: STPUB is bound into BOTH the handshake transcript
//! hash and the static-key DH, so a bad value breaks the auth tag. The parser is
//! therefore not a standalone trust boundary, the handshake is. Full chain
//! validation is a future slice.

use crate::crypto;
use crate::error::CertError;
use crate::error::ChainError;
use crate::error::SeError;
use crate::parse::take;
use crate::parse::take_array;
use crate::parse::take_be_u16;
use crate::parse::take_u8;

/// X25519 OBJECT IDENTIFIER body bytes (OID 1.3.101.110, id-X25519).
///
/// The id-X25519 OID body is exactly these three bytes. The match requires the
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

/// ecdsa-with-SHA384 OID content bytes (1.2.840.10045.4.3.3).
const OID_ECDSA_SHA384: [u8; 8] = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
/// ecdsa-with-SHA512 OID content bytes (1.2.840.10045.4.3.4).
const OID_ECDSA_SHA512: [u8; 8] = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04];
/// id-ecPublicKey OID content bytes (1.2.840.10045.2.1).
const OID_EC_PUBLIC_KEY: [u8; 7] = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
/// secp384r1 (P-384) named-curve OID content bytes (1.3.132.0.34).
const OID_SECP384R1: [u8; 5] = [0x2b, 0x81, 0x04, 0x00, 0x22];
/// secp521r1 (P-521) named-curve OID content bytes (1.3.132.0.35).
const OID_SECP521R1: [u8; 5] = [0x2b, 0x81, 0x04, 0x00, 0x23];

/// SEC1 uncompressed point length for P-384: 0x04 || X(48) || Y(48).
const P384_POINT_LEN: usize = 97;
/// SEC1 uncompressed point length for P-521: 0x04 || X(66) || Y(66).
const P521_POINT_LEN: usize = 133;

/// Number of certificates the chain expects in the store.
const CHAIN_CERT_COUNT: usize = 4;

/// Extracts STPUB from a raw `Get_Info` X.509 certificate store.
///
/// WARNING: this does NOT verify the certificate chain. For any trust decision
/// use `parse_verified_stpub`.
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
/// SECURITY: extracts STPUB only. Does NOT validate the certificate chain (see
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
        // A certificate is a single SEQUENCE. Bytes after it are not part of it.
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
/// child can never read past its parent. SEQUENCE (0x30) is descended. When an
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
            // The key was found in an earlier sibling, stop walking.
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
/// bits give the count of big-endian length bytes, libtropic supports 1 or 2.
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

/// Reads a DER length on the CHAIN path, mapping into `ChainError`.
///
/// Wraps the shared `parse_der_len`: an unsupported encoding (long-form over 2
/// bytes or indefinite) becomes `ChainError::Unsupported`, every other fault
/// becomes `ChainError::Malformed`. This keeps the chain path's error taxonomy
/// aligned with the STPUB path while reusing the one length parser.
fn der_len(input: &[u8]) -> Result<(&[u8], usize), ChainError>
{
    parse_der_len(input).map_err(|e| match e
    {
        CertError::Unsupported => ChainError::Unsupported,
        _ => ChainError::Malformed,
    })
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

// ===========================================================================
// Certificate-chain signature verification (slice 2c.7).
// ===========================================================================

/// A pinned X.509 trust anchor: the root CA P-521 public key.
///
/// SECURITY: the anchor is supplied OUT-OF-BAND by the integrator, NEVER taken
/// from the certificate store. The store's own self-signed root cannot be a
/// trust source: an attacker who controls the chip could forge a whole chain
/// under a substituted root. Trust flows only from this pinned key. The product
/// CA's signature is verified under it.
///
/// The wrapped bytes are the SEC1 uncompressed point (0x04 || X || Y, 133 bytes).
/// The TEST root here differs from PROD: the integrator compiles in the correct
/// production root point.
#[derive(Clone, Copy)]
pub struct RootAnchor
{
    point: [u8; P521_POINT_LEN],
}

impl RootAnchor
{
    /// Builds an anchor from a P-521 SEC1 uncompressed point.
    ///
    /// `point` must be 0x04 || X(66) || Y(66) = 133 bytes. The leading 0x04 tag
    /// is checked, then the point is EAGERLY validated as a real P-521 curve
    /// point, so a malformed pin is rejected here, not silently at first verify.
    ///
    /// TROPIC01's root CA is ALWAYS P-521, so this P-521-specific constructor is
    /// intentional: there is deliberately no from_sec1_p384 sibling.
    pub fn from_sec1_p521(point: &[u8; P521_POINT_LEN]) -> Result<Self, SeError>
    {
        if point[0] != 0x04
        {
            return Err(SeError::Chain(ChainError::BadPublicKey));
        }
        crypto::p521_validate_point(point).map_err(|_| SeError::Chain(ChainError::BadPublicKey))?;
        Ok(RootAnchor
        {
            point: *point,
        })
    }

    /// The pinned root point as SEC1 bytes.
    fn point(&self) -> &[u8]
    {
        &self.point
    }
}

/// A certificate's signatureAlgorithm: the ECDSA curve+digest it was signed with.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SigAlg
{
    /// ecdsa-with-SHA384: verified with a P-384 issuer key over SHA-384.
    EcdsaSha384,
    /// ecdsa-with-SHA512: verified with a P-521 issuer key over SHA-512.
    EcdsaSha512,
}

/// A key's elliptic curve, taken from its SubjectPublicKeyInfo named-curve OID.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Curve
{
    /// secp384r1 (P-384).
    P384,
    /// secp521r1 (P-521).
    P521,
}

/// The parsed views into one certificate needed to verify its signature.
///
/// All three are sub-slices of the cert body, never copies. `tbs` is the exact
/// signed byte range (the first inner SEQUENCE INCLUDING its tag+length header).
struct CertParts<'a>
{
    /// The tbsCertificate bytes that were signed (SEQUENCE header included).
    tbs: &'a [u8],
    /// The signatureAlgorithm of THIS certificate.
    sig_alg: SigAlg,
    /// The ECDSA-Sig-Value DER (SEQUENCE { INTEGER r, INTEGER s }).
    sig_der: &'a [u8],
}

/// Verifies the certificate chain up to the PINNED root anchor.
///
/// Parses the 4-certificate `Get_Info` store (leaf-first: DEVICE, XXXX CA,
/// product CA, root) and verifies the three signature links. Link 1: cert[0]
/// (DEVICE) under cert[1]'s P-384 key (ecdsa-with-SHA384). Link 2: cert[1] under
/// cert[2]'s P-384 key (ecdsa-with-SHA384). Link 3: cert[2] (product CA) under
/// the PINNED root P-521 key (ecdsa-with-SHA512). The signature algorithm is
/// dispatched per certificate from its own signatureAlgorithm OID, never
/// hardcoded by index. Returns `Ok(())` only when all three links verify.
///
/// SECURITY: link 3 anchors trust in `anchor`, NOT in the store's self-signed
/// cert[3]. The store cert[3] is not consulted. An attacker who reorders or
/// tampers with any certificate makes a signature fail to verify. No Distinguished
/// Name parsing is needed for security. This relies on the fixed store index
/// order, which the chip's `Get_Info` guarantees.
///
/// SECURITY: this slice does the CRYPTOGRAPHIC path validation only. It does NOT
/// check notBefore/notAfter validity (needs an RTC), CRL/OCSP revocation,
/// basicConstraints CA:TRUE / pathLenConstraint, keyUsage, SubjectKeyId /
/// AuthorityKeyId, or Distinguished-Name chaining. An integrator MUST add date
/// and revocation checks before relying on a certificate for production trust.
pub fn verify_cert_chain(cert_store: &[u8], anchor: &RootAnchor) -> Result<(), SeError>
{
    let mut bodies: [&[u8]; CHAIN_CERT_COUNT] = [&[]; CHAIN_CERT_COUNT];
    split_cert_bodies(cert_store, &mut bodies)?;

    // Link 1: DEVICE signed by the XXXX CA (cert[1]).
    verify_link(bodies[0], bodies[1])?;
    // Link 2: XXXX CA signed by the product CA (cert[2]).
    verify_link(bodies[1], bodies[2])?;
    // Link 3: product CA signed by the PINNED ROOT, NOT by store cert[3].
    verify_under_anchor(bodies[2], anchor)?;
    Ok(())
}

/// Verifies the chain, then extracts STPUB through the now-trusted path.
///
/// Equivalent to `verify_cert_chain` followed by `parse_stpub`, so STPUB is only
/// returned after the chain verifies up to the pinned root. Prefer this over the
/// unverified `parse_stpub` whenever a trust decision depends on STPUB.
///
/// This parses the store TWICE (once to verify, once to extract STPUB). Both
/// passes are bounded and cheap.
pub fn parse_verified_stpub
(
    cert_store: &[u8],
    anchor: &RootAnchor,
)
-> Result<[u8; 32], SeError>
{
    verify_cert_chain(cert_store, anchor)?;
    parse_stpub(cert_store)
}

/// Verifies `subject`'s signature under `issuer`'s embedded EC public key.
///
/// Reads the subject's tbsCertificate, signatureAlgorithm, and signatureValue,
/// reads the issuer's SubjectPublicKeyInfo point, then dispatches the verify by
/// the subject's algorithm. The issuer key's curve must match the algorithm.
fn verify_link(subject: &[u8], issuer: &[u8]) -> Result<(), ChainError>
{
    let parts = parse_cert_parts(subject)?;
    let (issuer_curve, issuer_point) = parse_spki_point(issuer)?;
    verify_with_curve(parts.sig_alg, issuer_curve, issuer_point, parts.tbs, parts.sig_der)
}

/// Verifies `subject`'s signature under the PINNED root anchor (P-521/SHA-512).
///
/// SECURITY: the load-bearing trust step. The anchor is the caller's pinned key,
/// not store bytes. The subject's signatureAlgorithm must be ecdsa-with-SHA512.
fn verify_under_anchor(subject: &[u8], anchor: &RootAnchor) -> Result<(), ChainError>
{
    let parts = parse_cert_parts(subject)?;
    if parts.sig_alg != SigAlg::EcdsaSha512
    {
        return Err(ChainError::UnsupportedSigAlg);
    }
    crypto::ecdsa_p521_sha512_verify(anchor.point(), parts.tbs, parts.sig_der)
        .map_err(|_| ChainError::BadSignature)
}

/// Dispatches an ECDSA verify by naming the valid (signatureAlgorithm, curve) pair.
///
/// The subject's signatureAlgorithm picks the digest. The issuer key's curve must
/// be the matching one (SHA-384 with P-384, SHA-512 with P-521). Any other pairing
/// is rejected as `BadPublicKey` before any crypto runs. This names the
/// curve<->digest constraint instead of comparing two signatureAlgorithm values.
fn verify_with_curve
(
    sig_alg: SigAlg,
    issuer_curve: Curve,
    issuer_point: &[u8],
    tbs: &[u8],
    sig_der: &[u8],
)
-> Result<(), ChainError>
{
    match (sig_alg, issuer_curve)
    {
        (SigAlg::EcdsaSha384, Curve::P384) =>
        {
            crypto::ecdsa_p384_sha384_verify(issuer_point, tbs, sig_der)
                .map_err(|_| ChainError::BadSignature)
        }
        (SigAlg::EcdsaSha512, Curve::P521) =>
        {
            crypto::ecdsa_p521_sha512_verify(issuer_point, tbs, sig_der)
                .map_err(|_| ChainError::BadSignature)
        }
        _ => Err(ChainError::BadPublicKey),
    }
}

/// Splits the store header off and fills `out` with the 4 certificate bodies.
///
/// Header layout (big-endian): VERSION(1) || NUM_CERTS(1) || LEN[0..4]. Requires
/// VERSION == 0x01 and NUM_CERTS == 4. Each cert body is `LEN[i]` bytes, taken in
/// order, `take` rejects any length that overruns the store. Trailing padding is
/// ignored.
fn split_cert_bodies<'a>
(
    store: &'a [u8],
    out: &mut [&'a [u8]; CHAIN_CERT_COUNT],
)
-> Result<(), ChainError>
{
    let (rest, version) = take_u8(store).map_err(|_| ChainError::Malformed)?;
    if version != 0x01
    {
        return Err(ChainError::Malformed);
    }
    let (mut rest, num_certs) = take_u8(rest).map_err(|_| ChainError::Malformed)?;
    if num_certs as usize != CHAIN_CERT_COUNT
    {
        return Err(ChainError::WrongCertCount);
    }
    // Read the four big-endian u16 lengths, then take that many cert bytes each.
    let mut lengths = [0u16; CHAIN_CERT_COUNT];
    for slot in lengths.iter_mut()
    {
        let (next, len) = take_be_u16(rest).map_err(|_| ChainError::Malformed)?;
        *slot = len;
        rest = next;
    }
    for (i, len) in lengths.iter().enumerate()
    {
        let (body, after) = take(rest, *len as usize).map_err(|_| ChainError::Malformed)?;
        // `i` is bounded by the array iteration, so the index cannot overrun.
        match out.get_mut(i)
        {
            Some(cell) => *cell = body,
            None => return Err(ChainError::Malformed),
        }
        rest = after;
    }
    Ok(())
}

/// Extracts the tbsCertificate range, signatureAlgorithm, and signatureValue.
///
/// A certificate is SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }.
/// The tbs is the FIRST inner SEQUENCE, returned INCLUDING its own tag+length
/// header (the exact signed byte range). The signatureAlgorithm is the next
/// SEQUENCE, its first OID selects the algorithm. The signatureValue is the
/// trailing BIT STRING. Its content is one 0x00 unused-bits byte then the
/// ECDSA-Sig-Value DER.
fn parse_cert_parts(cert: &[u8]) -> Result<CertParts<'_>, ChainError>
{
    // Outer cert SEQUENCE must span the whole body.
    let (inner, trailing) = der_sequence_content(cert)?;
    if !trailing.is_empty()
    {
        return Err(ChainError::Malformed);
    }
    // tbsCertificate: the first element, kept WITH its header (the signed bytes).
    // der_element_with_header discards the tag, so assert it is a SEQUENCE here:
    // a non-SEQUENCE first element must not be accepted as the tbsCertificate.
    let (tbs, after_tbs) = der_element_with_header(inner)?;
    match tbs.first()
    {
        Some(&TAG_SEQUENCE) =>
        {}
        _ => return Err(ChainError::Malformed),
    }
    // signatureAlgorithm SEQUENCE.
    let (alg_seq, after_alg) = der_sequence_content(after_tbs)?;
    let sig_alg = parse_sig_alg(alg_seq)?;
    // signatureValue BIT STRING.
    let (sig_der, trailing2) = parse_signature_value(after_alg)?;
    if !trailing2.is_empty()
    {
        return Err(ChainError::Malformed);
    }
    Ok(CertParts
    {
        tbs,
        sig_alg,
        sig_der,
    })
}

/// Reads the signatureAlgorithm from an AlgorithmIdentifier SEQUENCE content.
///
/// The first object is the algorithm OID. It must equal ecdsa-with-SHA384 or
/// ecdsa-with-SHA512. Trailing params (if any) are ignored.
fn parse_sig_alg(alg_seq: &[u8]) -> Result<SigAlg, ChainError>
{
    let (oid, _rest) = der_oid(alg_seq)?;
    if oid == OID_ECDSA_SHA384
    {
        Ok(SigAlg::EcdsaSha384)
    }
    else if oid == OID_ECDSA_SHA512
    {
        Ok(SigAlg::EcdsaSha512)
    }
    else
    {
        Err(ChainError::UnsupportedSigAlg)
    }
}

/// Parses a signatureValue BIT STRING, returning the inner ECDSA-Sig-Value DER.
///
/// The BIT STRING content is one 0x00 unused-bits byte then SEQUENCE { r, s }.
/// Returns `(sig_der, trailing)` where `sig_der` is the bytes after the 0x00.
fn parse_signature_value(input: &[u8]) -> Result<(&[u8], &[u8]), ChainError>
{
    let (after_tag, tag) = take_u8(input).map_err(|_| ChainError::Malformed)?;
    if tag != TAG_BIT_STRING
    {
        return Err(ChainError::Malformed);
    }
    let (after_len, length) = der_len(after_tag)?;
    let (content, trailing) = take(after_len, length).map_err(|_| ChainError::Malformed)?;
    // take_u8 returns (rest, value): sig_der = rest (the ECDSA-Sig-Value DER), unused_bits = the leading byte.
    let (sig_der, unused_bits) = take_u8(content).map_err(|_| ChainError::Malformed)?;
    if unused_bits != 0x00
    {
        return Err(ChainError::Malformed);
    }
    Ok((sig_der, trailing))
}

/// Extracts the EC public-key (curve, SEC1 point) from a certificate's SPKI.
///
/// Walks the cert to its tbsCertificate, then locates the SubjectPublicKeyInfo:
/// SEQUENCE { SEQUENCE { OID id-ecPublicKey, OID curve }, BIT STRING point }. The
/// returned point is the 0x04 || X || Y SEC1 form (the BIT STRING content minus
/// its leading 0x00 unused-bits byte). The curve is derived from the curve OID
/// (secp384r1 -> P-384, secp521r1 -> P-521).
fn parse_spki_point(cert: &[u8]) -> Result<(Curve, &[u8]), ChainError>
{
    let (inner, _trailing) = der_sequence_content(cert)?;
    let (tbs, _after) = der_sequence_content(inner)?;
    // Scan the tbsCertificate elements for the SubjectPublicKeyInfo: the SEQUENCE
    // whose first child is an AlgorithmIdentifier holding id-ecPublicKey.
    let mut cursor = tbs;
    while !cursor.is_empty()
    {
        let (elem, after) = der_element_with_header(cursor)?;
        if let Some(found) = try_spki(elem)?
        {
            return Ok(found);
        }
        cursor = after;
    }
    Err(ChainError::BadPublicKey)
}

/// Tests one tbs element for being a SubjectPublicKeyInfo, returning the key.
///
/// Returns `Ok(Some(..))` when `elem` is `SEQUENCE { SEQUENCE { OID
/// id-ecPublicKey, OID curve }, BIT STRING }`, `Ok(None)` when it is not an SPKI
/// (so scanning continues), and `Err` only on a structurally broken SPKI.
fn try_spki(elem: &[u8]) -> Result<Option<(Curve, &[u8])>, ChainError>
{
    let (after_tag, tag) = take_u8(elem).map_err(|_| ChainError::Malformed)?;
    if tag != TAG_SEQUENCE
    {
        return Ok(None);
    }
    let (after_len, length) = der_len(after_tag)?;
    let (content, _trailing) = take(after_len, length).map_err(|_| ChainError::Malformed)?;
    // First child must be an AlgorithmIdentifier SEQUENCE.
    let (alg_tag_after, alg_tag) = match take_u8(content)
    {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };
    if alg_tag != TAG_SEQUENCE
    {
        return Ok(None);
    }
    let (alg_len_after, alg_len) = match parse_der_len(alg_tag_after)
    {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };
    let (alg_content, after_alg) = match take(alg_len_after, alg_len)
    {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };
    // The AlgorithmIdentifier must begin with id-ecPublicKey, then a curve OID.
    let (oid1, after_oid1) = match der_oid(alg_content)
    {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };
    if oid1 != OID_EC_PUBLIC_KEY
    {
        return Ok(None);
    }
    let (curve_oid, _rest) = der_oid(after_oid1)?;
    let curve = curve_from_oid(curve_oid)?;
    let expected_len = match curve
    {
        Curve::P384 => P384_POINT_LEN,
        Curve::P521 => P521_POINT_LEN,
    };
    // The subjectPublicKey BIT STRING follows the AlgorithmIdentifier.
    let point = parse_ec_point(after_alg, expected_len)?;
    Ok(Some((curve, point)))
}

/// Maps a named-curve OID to the matching curve.
fn curve_from_oid(curve_oid: &[u8]) -> Result<Curve, ChainError>
{
    if curve_oid == OID_SECP384R1
    {
        Ok(Curve::P384)
    }
    else if curve_oid == OID_SECP521R1
    {
        Ok(Curve::P521)
    }
    else
    {
        Err(ChainError::BadPublicKey)
    }
}

/// Parses a subjectPublicKey BIT STRING into its SEC1 uncompressed point.
///
/// The BIT STRING content is one 0x00 unused-bits byte then 0x04 || X || Y. The
/// returned slice is the 0x04 || X || Y part and must be exactly `expected_len`
/// bytes with a leading 0x04, else the key is rejected.
fn parse_ec_point(input: &[u8], expected_len: usize) -> Result<&[u8], ChainError>
{
    let (after_tag, tag) = take_u8(input).map_err(|_| ChainError::BadPublicKey)?;
    if tag != TAG_BIT_STRING
    {
        return Err(ChainError::BadPublicKey);
    }
    let (after_len, length) = der_len(after_tag)?;
    let (content, _trailing) = take(after_len, length).map_err(|_| ChainError::BadPublicKey)?;
    let (point, unused_bits) = take_u8(content).map_err(|_| ChainError::BadPublicKey)?;
    if unused_bits != 0x00
    {
        return Err(ChainError::BadPublicKey);
    }
    if point.len() != expected_len
    {
        return Err(ChainError::BadPublicKey);
    }
    // SEC1 uncompressed points start with 0x04. from_sec1_bytes also checks this,
    // but rejecting it here keeps the error specific.
    let (_rest, first) = take_u8(point).map_err(|_| ChainError::BadPublicKey)?;
    if first != 0x04
    {
        return Err(ChainError::BadPublicKey);
    }
    Ok(point)
}

/// Reads a DER SEQUENCE, returning its `(content, trailing)`.
///
/// The leading tag must be 0x30. The content is bounded to the declared length,
/// `trailing` is whatever follows the SEQUENCE in `input`.
fn der_sequence_content(input: &[u8]) -> Result<(&[u8], &[u8]), ChainError>
{
    let (after_tag, tag) = take_u8(input).map_err(|_| ChainError::Malformed)?;
    if tag != TAG_SEQUENCE
    {
        return Err(ChainError::Malformed);
    }
    let (after_len, length) = der_len(after_tag)?;
    take(after_len, length).map_err(|_| ChainError::Malformed)
}

/// Reads one DER element and returns it WITH its tag+length header.
///
/// Returns `(element, rest)` where `element` is the contiguous tag || length ||
/// content byte range and `rest` is what follows. This is how the exact signed
/// tbsCertificate byte range is captured.
fn der_element_with_header(input: &[u8]) -> Result<(&[u8], &[u8]), ChainError>
{
    let (after_tag, _tag) = take_u8(input).map_err(|_| ChainError::Malformed)?;
    let (after_len, length) = der_len(after_tag)?;
    // Header length = bytes consumed reading tag+length = input.len() - after_len.len().
    let header_len = input
        .len()
        .checked_sub(after_len.len())
        .ok_or(ChainError::Malformed)?;
    let total = header_len.checked_add(length).ok_or(ChainError::Malformed)?;
    take(input, total).map_err(|_| ChainError::Malformed)
}

/// Reads a DER OBJECT IDENTIFIER, returning its `(content, rest)`.
fn der_oid(input: &[u8]) -> Result<(&[u8], &[u8]), ChainError>
{
    let (after_tag, tag) = take_u8(input).map_err(|_| ChainError::Malformed)?;
    if tag != TAG_OID
    {
        return Err(ChainError::Malformed);
    }
    let (after_len, length) = der_len(after_tag)?;
    take(after_len, length).map_err(|_| ChainError::Malformed)
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
    /// The other three certs are declared zero-length, trailing padding is added
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
        // The chip serves the store as 30 x 128 = 3840 bytes, The real cert store
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

    #[test]
    fn prefix_oid_does_not_false_match()
    {
        // Attack A: a 5-byte OID whose first three bytes are the X25519 OID. The
        // exact-OID match must not trigger, so nothing is ever sampled.
        let cert = [
            TAG_SEQUENCE, 0x07,
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
            TAG_SEQUENCE, 0x0A,
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
    fn deeply_nested_sequences_hit_depth_cap_without_panic()
    {
        // A long run of nested empty-ish SEQUENCE headers. Each `30 NN` opens a
        // deeper level. Past MAX_DER_DEPTH the walk returns Unsupported rather than
        // recursing further. No stack exhaustion, no panic.
        let mut cert = [0u8; 2 + 200];
        cert[0] = TAG_SEQUENCE;
        cert[1] = 200;
        // Fill the content with 0x30 0x82-style headers is overkill. A simple run
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

    // Chain-verification tests
    //
    // Hermetic golden: the exact 2385-byte store the live ts-tvl model serves,
    // its pinned P-521 TEST root point, and the authoritative STPUB. Captured
    // and cross-checked with openssl (the full TEST chain verifies, the root is
    // self-signed, cert[0] STPUB == model s_t_pub). See golden_chain module.

    fn test_anchor() -> RootAnchor
    {
        RootAnchor::from_sec1_p521(&golden_chain::MODEL_TEST_ROOT_PUBKEY)
            .expect("pinned root point is well-formed")
    }

    /// Embeds the un-padded store into a 3840-byte buffer like the chip serves.
    fn store_padded_3840() -> [u8; 3840]
    {
        let mut padded = [0u8; 3840];
        padded[..golden_chain::MODEL_CERT_STORE.len()]
            .copy_from_slice(&golden_chain::MODEL_CERT_STORE);
        padded
    }

    #[test]
    fn verify_cert_chain_accepts_the_model_chain()
    {
        assert_eq!(verify_cert_chain(&golden_chain::MODEL_CERT_STORE, &test_anchor()), Ok(()));
    }

    #[test]
    fn verify_cert_chain_accepts_block_padded_store()
    {
        assert_eq!(verify_cert_chain(&store_padded_3840(), &test_anchor()), Ok(()));
    }

    #[test]
    fn parse_verified_stpub_returns_model_stpub()
    {
        assert_eq!(
            parse_verified_stpub(&golden_chain::MODEL_CERT_STORE, &test_anchor()),
            Ok(golden_chain::MODEL_STPUB)
        );
    }

    #[test]
    fn parse_verified_stpub_matches_unverified_on_good_chain()
    {
        // The verified path returns the same STPUB the unverified parser does.
        let verified = parse_verified_stpub(&golden_chain::MODEL_CERT_STORE, &test_anchor());
        let unverified = parse_stpub(&golden_chain::MODEL_CERT_STORE);
        assert_eq!(verified, unverified);
    }

    /// Absolute index of sub-slice `inner` within `outer` (both same allocation).
    ///
    /// Computed from the pointer offset, so the test byte to flip is DERIVED from
    /// the parsed structure rather than a hard-coded magic number.
    fn abs_offset(outer: &[u8], inner: &[u8]) -> usize
    {
        (inner.as_ptr() as usize) - (outer.as_ptr() as usize)
    }

    /// Returns the absolute store index of a byte inside cert[i]'s sig_der.
    fn sig_byte_index(store: &[u8], cert_index: usize) -> usize
    {
        let mut bodies: [&[u8]; CHAIN_CERT_COUNT] = [&[]; CHAIN_CERT_COUNT];
        split_cert_bodies(store, &mut bodies).expect("split");
        let parts = parse_cert_parts(bodies[cert_index]).expect("parts");
        // A byte in the middle of the located ECDSA-Sig-Value DER.
        abs_offset(store, parts.sig_der) + parts.sig_der.len() / 2
    }

    #[test]
    fn flipping_a_signature_byte_fails_bad_signature()
    {
        // DERIVE the target: parse cert[0], locate its sig_der, flip a byte inside
        // it. A flip inside the signature must yield BadSignature.
        let mut store = golden_chain::MODEL_CERT_STORE;
        let i = sig_byte_index(&store, 0);
        store[i] ^= 0x01;
        assert_eq!(
            verify_cert_chain(&store, &test_anchor()),
            Err(SeError::Chain(ChainError::BadSignature))
        );
    }

    #[test]
    fn flipping_a_tbs_byte_fails()
    {
        // DERIVE the target: parse cert[0], locate its tbs, flip a byte mid-tbs
        // (inside the signed CONTENT, away from the length header) so the crypto
        // catches it deterministically as BadSignature.
        let mut store = golden_chain::MODEL_CERT_STORE;
        let i = {
            let mut bodies: [&[u8]; CHAIN_CERT_COUNT] = [&[]; CHAIN_CERT_COUNT];
            split_cert_bodies(&store, &mut bodies).expect("split");
            let parts = parse_cert_parts(bodies[0]).expect("parts");
            abs_offset(&store, parts.tbs) + parts.tbs.len() / 2
        };
        store[i] ^= 0x01;
        assert_eq!(
            verify_cert_chain(&store, &test_anchor()),
            Err(SeError::Chain(ChainError::BadSignature)),
            "a flip inside the signed tbs range must be caught by the crypto"
        );
    }

    #[test]
    fn flipping_cert1_signature_fails_bad_signature()
    {
        // Link 2: cert[1] signed under cert[2]. A flip inside cert[1]'s signature
        // must fail that link, proving link 2 is actually exercised.
        let mut store = golden_chain::MODEL_CERT_STORE;
        let i = sig_byte_index(&store, 1);
        store[i] ^= 0x01;
        assert_eq!(
            verify_cert_chain(&store, &test_anchor()),
            Err(SeError::Chain(ChainError::BadSignature))
        );
    }

    #[test]
    fn flipping_cert2_signature_fails_bad_signature()
    {
        // Link 3: cert[2] (product CA) signed under the PINNED anchor. A flip
        // inside cert[2]'s signature must fail under the anchor, proving link 3 is
        // exercised on the failure path.
        let mut store = golden_chain::MODEL_CERT_STORE;
        let i = sig_byte_index(&store, 2);
        store[i] ^= 0x01;
        assert_eq!(
            verify_cert_chain(&store, &test_anchor()),
            Err(SeError::Chain(ChainError::BadSignature))
        );
    }

    #[test]
    fn wrong_anchor_fails_bad_signature()
    {
        // A DIFFERENT but VALID P-521 anchor: the product-CA signature no longer
        // verifies under it. This is the load-bearing trust check. The point must
        // be on-curve (the anchor now validates eagerly), so it is derived from a
        // fixed scalar rather than by flipping a golden byte.
        let point = other_valid_p521_point();
        let anchor = RootAnchor::from_sec1_p521(&point).expect("valid P-521 point");
        assert_eq!(
            verify_cert_chain(&golden_chain::MODEL_CERT_STORE, &anchor),
            Err(SeError::Chain(ChainError::BadSignature))
        );
    }

    /// A valid-but-unrelated P-521 SEC1 point, for "wrong anchor" tests.
    ///
    /// Derived from a fixed non-trivial scalar so it is a real on-curve point and
    /// is accepted by the eagerly-validating anchor constructor, yet differs from
    /// the model TEST root, so signatures fail to verify under it.
    fn other_valid_p521_point() -> [u8; P521_POINT_LEN]
    {
        use p521::ecdsa::SigningKey;
        let mut scalar = p521::FieldBytes::default();
        scalar[65] = 0x02;
        let sk = SigningKey::from_bytes(&scalar).expect("nonzero scalar");
        let enc = sk.verifying_key().to_sec1_point(false);
        let mut out = [0u8; P521_POINT_LEN];
        out.copy_from_slice(enc.as_bytes());
        out
    }

    #[test]
    fn anchor_without_uncompressed_tag_rejected()
    {
        let mut point = golden_chain::MODEL_TEST_ROOT_PUBKEY;
        point[0] = 0x05;
        assert!(matches!(
            RootAnchor::from_sec1_p521(&point),
            Err(SeError::Chain(ChainError::BadPublicKey))
        ));
    }

    #[test]
    fn wrong_num_certs_in_header_rejected()
    {
        let mut store = golden_chain::MODEL_CERT_STORE;
        store[1] = 0x03;
        assert_eq!(
            verify_cert_chain(&store, &test_anchor()),
            Err(SeError::Chain(ChainError::WrongCertCount))
        );
    }

    #[test]
    fn bad_version_in_header_rejected()
    {
        let mut store = golden_chain::MODEL_CERT_STORE;
        store[0] = 0x02;
        assert_eq!(
            verify_cert_chain(&store, &test_anchor()),
            Err(SeError::Chain(ChainError::Malformed))
        );
    }

    #[test]
    fn empty_store_rejected()
    {
        let r = verify_cert_chain(&[], &test_anchor());
        assert!(matches!(r, Err(SeError::Chain(_))));
    }

    #[test]
    fn verify_cert_chain_never_panics_on_any_truncation()
    {
        // Truncate the real store at every length and assert no panic. Every cut
        // must yield a typed error (or Ok only for the full store).
        let store = golden_chain::MODEL_CERT_STORE;
        let anchor = test_anchor();
        for cut in 0..=store.len()
        {
            let _ = verify_cert_chain(&store[..cut], &anchor);
        }
    }

    #[test]
    fn verify_cert_chain_never_panics_on_single_byte_flips_across_store()
    {
        // Flip each of the first 800 bytes (covering the header, the whole leaf,
        // and into the second cert) one at a time. None may panic. Each must be
        // a typed result. This stresses the DER walk over realistic mutations.
        let anchor = test_anchor();
        for i in 0..800.min(golden_chain::MODEL_CERT_STORE.len())
        {
            let mut store = golden_chain::MODEL_CERT_STORE;
            store[i] ^= 0xFF;
            let _ = verify_cert_chain(&store, &anchor);
        }
    }

    #[test]
    fn parse_spki_point_reads_the_xxxx_ca_p384_key()
    {
        // cert[1] (the XXXX CA) carries a P-384 key. Splitting the bodies and
        // reading its SPKI must yield a P-384 algorithm and a 97-byte point.
        let mut bodies: [&[u8]; CHAIN_CERT_COUNT] = [&[]; CHAIN_CERT_COUNT];
        split_cert_bodies(&golden_chain::MODEL_CERT_STORE, &mut bodies).expect("split");
        let (curve, point) = parse_spki_point(bodies[1]).expect("spki");
        assert!(matches!(curve, Curve::P384));
        assert_eq!(point.len(), P384_POINT_LEN);
        assert_eq!(point[0], 0x04);
    }

    #[test]
    fn parse_spki_point_reads_the_root_p521_key()
    {
        // cert[3] (the store's self-signed root) carries a P-521 key equal to the
        // pinned anchor point. Defense-in-depth cross-check: the store root key
        // matches the out-of-band pin for the TEST chain.
        let mut bodies: [&[u8]; CHAIN_CERT_COUNT] = [&[]; CHAIN_CERT_COUNT];
        split_cert_bodies(&golden_chain::MODEL_CERT_STORE, &mut bodies).expect("split");
        let (curve, point) = parse_spki_point(bodies[3]).expect("spki");
        assert!(matches!(curve, Curve::P521));
        assert_eq!(point, &golden_chain::MODEL_TEST_ROOT_PUBKEY[..]);
    }

    #[test]
    fn each_leaf_sig_alg_is_dispatched_from_its_own_oid()
    {
        // cert[0] and cert[1] are ecdsa-with-SHA384, cert[2] and cert[3] are
        // ecdsa-with-SHA512. Dispatch must come from each cert's own OID.
        let mut bodies: [&[u8]; CHAIN_CERT_COUNT] = [&[]; CHAIN_CERT_COUNT];
        split_cert_bodies(&golden_chain::MODEL_CERT_STORE, &mut bodies).expect("split");
        assert!(matches!(parse_cert_parts(bodies[0]).unwrap().sig_alg, SigAlg::EcdsaSha384));
        assert!(matches!(parse_cert_parts(bodies[1]).unwrap().sig_alg, SigAlg::EcdsaSha384));
        assert!(matches!(parse_cert_parts(bodies[2]).unwrap().sig_alg, SigAlg::EcdsaSha512));
        assert!(matches!(parse_cert_parts(bodies[3]).unwrap().sig_alg, SigAlg::EcdsaSha512));
    }

    #[test]
    fn algorithm_confusion_in_leaf_is_rejected_bad_public_key()
    {
        // Mutate cert[0]'s top-level signatureAlgorithm from ecdsa-with-SHA384
        // (..0403 03) to ecdsa-with-SHA512 (..0403 04). cert[0] then claims SHA512
        // but its issuer cert[1] key is P-384, so verify_with_curve hits the
        // (EcdsaSha512, P384) mismatch and rejects with BadPublicKey, NOT
        // BadSignature. The OID appears more than once in cert[0], the top-level
        // signatureAlgorithm is the LAST occurrence in the cert body.
        let mut store = golden_chain::MODEL_CERT_STORE;
        let oid = OID_ECDSA_SHA384;
        let abs = {
            let mut bodies: [&[u8]; CHAIN_CERT_COUNT] = [&[]; CHAIN_CERT_COUNT];
            split_cert_bodies(&store, &mut bodies).expect("split");
            let body = bodies[0];
            // Find the LAST window equal to the ecdsa-with-SHA384 OID content.
            let last = body
                .windows(oid.len())
                .enumerate()
                .filter(|(_, w)| *w == oid)
                .map(|(i, _)| i)
                .next_back()
                .expect("ecdsa-with-SHA384 OID present in cert[0]");
            // Absolute index of the OID's final byte (the 0x03 to flip to 0x04).
            abs_offset(&store, body) + last + oid.len() - 1
        };
        assert_eq!(store[abs], 0x03);
        store[abs] = 0x04;
        assert_eq!(
            verify_cert_chain(&store, &test_anchor()),
            Err(SeError::Chain(ChainError::BadPublicKey))
        );
    }

    #[test]
    fn chain_der_length_long_form_over_two_bytes_unsupported()
    {
        // A synthetic store whose cert[0] uses a 3-byte long-form length (0x83)
        // that the chain parser reaches. der_len must surface ChainError::
        // Unsupported (not Malformed), mirroring the 2c.6 STPUB-path test.
        //
        // cert[0] = outer SEQUENCE whose first element (the tbsCertificate slot)
        // is a SEQUENCE using a 3-byte length. parse_cert_parts reaches der_len on
        // that inner element via der_element_with_header.
        let cert0: [u8; 8] = [
            0x30, 0x06, // outer SEQUENCE, length 6
            0x30, 0x83, 0x00, 0x00, 0x01, 0x00, // inner SEQUENCE with 3-byte length
        ];
        let mut store = [0u8; 10 + 8];
        store[0] = 0x01; // version
        store[1] = 0x04; // num_certs
        store[2..4].copy_from_slice(&(cert0.len() as u16).to_be_bytes());
        // cert[1..4] declared zero-length, the verifier reaches cert[0] first.
        store[10..10 + cert0.len()].copy_from_slice(&cert0);
        assert_eq!(
            verify_cert_chain(&store, &test_anchor()),
            Err(SeError::Chain(ChainError::Unsupported))
        );
    }

    #[test]
    fn parse_spki_point_without_ec_public_key_is_bad_public_key()
    {
        // An issuer cert whose tbs holds no id-ecPublicKey SPKI must yield
        // BadPublicKey from parse_spki_point. Crafted minimal cert: outer SEQUENCE
        // { tbs SEQUENCE { SEQUENCE { OID commonName } } } - a SEQUENCE child that
        // is not an SPKI (its first OID is not id-ecPublicKey).
        let cert: [u8; 13] = [
            0x30, 0x0b, // outer SEQUENCE, len 11
            0x30, 0x09, // tbs SEQUENCE, len 9
            0x30, 0x07, // a child SEQUENCE, len 7
            0x06, 0x03, 0x55, 0x04, 0x03, // OID commonName (not id-ecPublicKey)
            0x05, 0x00, // a trailing NULL to round out the child
        ];
        assert!(matches!(parse_spki_point(&cert), Err(ChainError::BadPublicKey)));
    }
}

#[cfg(test)]
mod golden_chain
{
    // HERMETIC GOLDEN for chain verification
    // Captured from the live model model_cfg.yml x509_certificate (the exact
    // bytes the chip serves) and verified with openssl: the full TEST chain
    // DEVICE->XXXX->TROPIC01->ROOT verifies, root is self-signed, cert[0] STPUB
    // == model s_t_pub. TEST root SHA-256 fp 7175C709...EB3FE3 (serial 101).

    /// The exact 2385-byte store the live model serves (header 01 04 then BE u16
    /// lengths 479,620,663,613, then the 4 cert bodies).
    pub(super) const MODEL_CERT_STORE: [u8; 2385] = [

        0x01, 0x04, 0x01, 0xdf, 0x02, 0x6c, 0x02, 0x97, 0x02, 0x65, 0x30, 0x82,
        0x01, 0xdb, 0x30, 0x82, 0x01, 0x62, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02,
        0x10, 0x02, 0xf0, 0x02, 0x00, 0x08, 0x82, 0x19, 0x06, 0x1b, 0x09, 0x33,
        0x00, 0x00, 0x04, 0x00, 0x09, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48,
        0xce, 0x3d, 0x04, 0x03, 0x03, 0x30, 0x4c, 0x31, 0x0b, 0x30, 0x09, 0x06,
        0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x43, 0x5a, 0x31, 0x1d, 0x30, 0x1b,
        0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x14, 0x54, 0x72, 0x6f, 0x70, 0x69,
        0x63, 0x20, 0x53, 0x71, 0x75, 0x61, 0x72, 0x65, 0x20, 0x73, 0x2e, 0x72,
        0x2e, 0x6f, 0x2e, 0x31, 0x1e, 0x30, 0x1c, 0x06, 0x03, 0x55, 0x04, 0x03,
        0x0c, 0x15, 0x54, 0x52, 0x4f, 0x50, 0x49, 0x43, 0x30, 0x31, 0x2d, 0x58,
        0x20, 0x54, 0x45, 0x53, 0x54, 0x20, 0x43, 0x41, 0x20, 0x76, 0x31, 0x30,
        0x1e, 0x17, 0x0d, 0x32, 0x35, 0x30, 0x36, 0x32, 0x37, 0x30, 0x38, 0x34,
        0x30, 0x35, 0x35, 0x5a, 0x17, 0x0d, 0x34, 0x35, 0x30, 0x36, 0x32, 0x37,
        0x30, 0x38, 0x34, 0x30, 0x35, 0x35, 0x5a, 0x30, 0x1c, 0x31, 0x1a, 0x30,
        0x18, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x11, 0x54, 0x52, 0x4f, 0x50,
        0x49, 0x43, 0x30, 0x31, 0x20, 0x65, 0x53, 0x45, 0x20, 0x54, 0x45, 0x53,
        0x54, 0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21,
        0x00, 0x95, 0x08, 0xf0, 0x32, 0x1c, 0xb1, 0xd2, 0xe5, 0xd1, 0xf1, 0xa4,
        0x60, 0x9c, 0x05, 0x41, 0xb7, 0x80, 0xe6, 0xdd, 0x50, 0xd6, 0x48, 0x2b,
        0x6b, 0x08, 0xb2, 0xc2, 0x7e, 0x7b, 0x76, 0x26, 0x47, 0xa3, 0x81, 0x84,
        0x30, 0x81, 0x81, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01,
        0xff, 0x04, 0x02, 0x30, 0x00, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f,
        0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x03, 0x08, 0x30, 0x1f, 0x06,
        0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x7b, 0xf3,
        0x8c, 0x79, 0x9b, 0x7a, 0x4b, 0x2e, 0xbf, 0x41, 0x05, 0x7d, 0xd5, 0xd2,
        0x6a, 0xeb, 0x5d, 0xa0, 0x40, 0xf3, 0x30, 0x40, 0x06, 0x03, 0x55, 0x1d,
        0x1f, 0x04, 0x39, 0x30, 0x37, 0x30, 0x35, 0xa0, 0x33, 0xa0, 0x31, 0x86,
        0x2f, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x70, 0x6b, 0x69, 0x2e,
        0x74, 0x72, 0x6f, 0x70, 0x69, 0x63, 0x73, 0x71, 0x75, 0x61, 0x72, 0x65,
        0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6c, 0x33, 0x2f, 0x74, 0x30, 0x31, 0x2d,
        0x54, 0x76, 0x31, 0x2d, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x63, 0x72, 0x6c,
        0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03,
        0x03, 0x67, 0x00, 0x30, 0x64, 0x02, 0x30, 0x41, 0x1d, 0x4e, 0x3f, 0xf8,
        0xc5, 0x1f, 0x7e, 0x76, 0x4c, 0xa6, 0x33, 0x05, 0x2c, 0x32, 0x40, 0x0d,
        0xf7, 0x69, 0xe7, 0xaa, 0x39, 0x00, 0x65, 0xc3, 0xd7, 0xa0, 0x88, 0xa7,
        0xda, 0x9a, 0x48, 0xac, 0xf2, 0x09, 0xd5, 0x09, 0x83, 0x3a, 0x81, 0x18,
        0x52, 0x9c, 0xf8, 0xe3, 0x54, 0x94, 0xb4, 0x02, 0x30, 0x6d, 0x6d, 0x42,
        0xa5, 0x0c, 0x13, 0xf8, 0x1d, 0x52, 0x51, 0x0b, 0x6b, 0xc5, 0xef, 0x16,
        0x5f, 0xa3, 0x01, 0x82, 0xc5, 0xe3, 0x2f, 0x5d, 0x4e, 0xa9, 0xc0, 0x46,
        0x8b, 0x3b, 0x02, 0xf7, 0xa2, 0x8c, 0xee, 0x79, 0xdb, 0xcf, 0x54, 0x6f,
        0xdb, 0x55, 0xe0, 0xf0, 0x3a, 0xd0, 0xd5, 0x98, 0xf7, 0x30, 0x82, 0x02,
        0x68, 0x30, 0x82, 0x01, 0xee, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02,
        0x27, 0x11, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04,
        0x03, 0x03, 0x30, 0x4a, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04,
        0x06, 0x13, 0x02, 0x43, 0x5a, 0x31, 0x1d, 0x30, 0x1b, 0x06, 0x03, 0x55,
        0x04, 0x0a, 0x0c, 0x14, 0x54, 0x72, 0x6f, 0x70, 0x69, 0x63, 0x20, 0x53,
        0x71, 0x75, 0x61, 0x72, 0x65, 0x20, 0x73, 0x2e, 0x72, 0x2e, 0x6f, 0x2e,
        0x31, 0x1c, 0x30, 0x1a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x13, 0x54,
        0x52, 0x4f, 0x50, 0x49, 0x43, 0x30, 0x31, 0x20, 0x54, 0x45, 0x53, 0x54,
        0x20, 0x43, 0x41, 0x20, 0x76, 0x31, 0x30, 0x20, 0x17, 0x0d, 0x32, 0x35,
        0x30, 0x33, 0x32, 0x34, 0x31, 0x33, 0x31, 0x34, 0x34, 0x33, 0x5a, 0x18,
        0x0f, 0x32, 0x30, 0x36, 0x30, 0x30, 0x33, 0x32, 0x34, 0x31, 0x33, 0x31,
        0x34, 0x34, 0x33, 0x5a, 0x30, 0x4c, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03,
        0x55, 0x04, 0x06, 0x13, 0x02, 0x43, 0x5a, 0x31, 0x1d, 0x30, 0x1b, 0x06,
        0x03, 0x55, 0x04, 0x0a, 0x0c, 0x14, 0x54, 0x72, 0x6f, 0x70, 0x69, 0x63,
        0x20, 0x53, 0x71, 0x75, 0x61, 0x72, 0x65, 0x20, 0x73, 0x2e, 0x72, 0x2e,
        0x6f, 0x2e, 0x31, 0x1e, 0x30, 0x1c, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,
        0x15, 0x54, 0x52, 0x4f, 0x50, 0x49, 0x43, 0x30, 0x31, 0x2d, 0x58, 0x20,
        0x54, 0x45, 0x53, 0x54, 0x20, 0x43, 0x41, 0x20, 0x76, 0x31, 0x30, 0x76,
        0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
        0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04, 0xb5, 0xb7,
        0x29, 0xf4, 0x82, 0x5b, 0xca, 0x3a, 0xda, 0x2d, 0xee, 0xae, 0xca, 0xca,
        0xb5, 0xc4, 0x77, 0x96, 0xe4, 0x7f, 0x72, 0x27, 0x89, 0x88, 0xa0, 0xe6,
        0xbd, 0xf2, 0xa8, 0x3c, 0x02, 0xca, 0xe2, 0x2d, 0xca, 0xa6, 0x43, 0xbc,
        0x7c, 0xac, 0xd4, 0x5d, 0xe5, 0x15, 0x35, 0x45, 0x97, 0xde, 0x07, 0x72,
        0x33, 0x88, 0xff, 0x79, 0x86, 0x42, 0x3f, 0x83, 0x8f, 0x25, 0x3f, 0x30,
        0x4c, 0xe0, 0xad, 0x0a, 0xf0, 0x21, 0x53, 0x05, 0xa7, 0x80, 0x50, 0x7a,
        0x57, 0x94, 0x41, 0xaa, 0xc2, 0x56, 0x3b, 0xcd, 0x8f, 0xcf, 0x10, 0x61,
        0x2d, 0x3c, 0xb7, 0x88, 0x2b, 0xfa, 0x6c, 0xe4, 0xcd, 0xd3, 0xa3, 0x81,
        0xa2, 0x30, 0x81, 0x9f, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04,
        0x16, 0x04, 0x14, 0x7b, 0xf3, 0x8c, 0x79, 0x9b, 0x7a, 0x4b, 0x2e, 0xbf,
        0x41, 0x05, 0x7d, 0xd5, 0xd2, 0x6a, 0xeb, 0x5d, 0xa0, 0x40, 0xf3, 0x30,
        0x12, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x08, 0x30,
        0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x06, 0x03, 0x55,
        0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x01, 0x06, 0x30,
        0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14,
        0xcc, 0x69, 0x7a, 0x4a, 0x99, 0x65, 0xfb, 0x80, 0xcc, 0x0b, 0x3b, 0x2d,
        0x8e, 0xde, 0x93, 0x5e, 0xcb, 0x2a, 0x69, 0x5a, 0x30, 0x39, 0x06, 0x03,
        0x55, 0x1d, 0x1f, 0x04, 0x32, 0x30, 0x30, 0x30, 0x2e, 0xa0, 0x2c, 0xa0,
        0x2a, 0x86, 0x28, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x70, 0x6b,
        0x69, 0x2e, 0x74, 0x72, 0x6f, 0x70, 0x69, 0x63, 0x73, 0x71, 0x75, 0x61,
        0x72, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6c, 0x32, 0x2f, 0x74, 0x30,
        0x31, 0x76, 0x31, 0x2e, 0x63, 0x72, 0x6c, 0x30, 0x0a, 0x06, 0x08, 0x2a,
        0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03, 0x03, 0x68, 0x00, 0x30, 0x65,
        0x02, 0x31, 0x00, 0x8e, 0xea, 0x68, 0xa9, 0xa1, 0x9b, 0xbd, 0x69, 0x2c,
        0xf0, 0x6d, 0x54, 0x59, 0x3d, 0xce, 0x28, 0x61, 0x43, 0xa3, 0x7d, 0x76,
        0x70, 0x13, 0x54, 0x25, 0x82, 0x1b, 0xb0, 0x44, 0xd9, 0xf2, 0xdc, 0x78,
        0x18, 0x40, 0x45, 0x81, 0x1b, 0x30, 0x26, 0x4e, 0x77, 0x72, 0x35, 0x42,
        0x2f, 0xdc, 0xeb, 0x02, 0x30, 0x3e, 0x22, 0xa2, 0x99, 0xde, 0x91, 0x73,
        0x3b, 0xd3, 0xec, 0x3a, 0x95, 0x78, 0xff, 0x6c, 0x7f, 0xc0, 0x19, 0x99,
        0xa3, 0xa2, 0xc9, 0x8c, 0xe4, 0xad, 0x99, 0x91, 0x0c, 0xc2, 0x3b, 0xb1,
        0xc2, 0xfb, 0x61, 0x7b, 0x71, 0xa0, 0xc0, 0x67, 0x13, 0x3c, 0x66, 0x79,
        0xc0, 0x68, 0x64, 0x78, 0xdf, 0x30, 0x82, 0x02, 0x93, 0x30, 0x82, 0x01,
        0xf6, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x03, 0xe9, 0x30, 0x0a,
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04, 0x30, 0x54,
        0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x43,
        0x5a, 0x31, 0x1d, 0x30, 0x1b, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x14,
        0x54, 0x72, 0x6f, 0x70, 0x69, 0x63, 0x20, 0x53, 0x71, 0x75, 0x61, 0x72,
        0x65, 0x20, 0x73, 0x2e, 0x72, 0x2e, 0x6f, 0x2e, 0x31, 0x26, 0x30, 0x24,
        0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x1d, 0x54, 0x72, 0x6f, 0x70, 0x69,
        0x63, 0x20, 0x53, 0x71, 0x75, 0x61, 0x72, 0x65, 0x20, 0x54, 0x45, 0x53,
        0x54, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x43, 0x41, 0x20, 0x76, 0x31,
        0x30, 0x20, 0x17, 0x0d, 0x32, 0x35, 0x30, 0x33, 0x32, 0x34, 0x31, 0x33,
        0x31, 0x34, 0x34, 0x32, 0x5a, 0x18, 0x0f, 0x32, 0x30, 0x36, 0x35, 0x30,
        0x33, 0x32, 0x34, 0x31, 0x33, 0x31, 0x34, 0x34, 0x32, 0x5a, 0x30, 0x4a,
        0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x43,
        0x5a, 0x31, 0x1d, 0x30, 0x1b, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x14,
        0x54, 0x72, 0x6f, 0x70, 0x69, 0x63, 0x20, 0x53, 0x71, 0x75, 0x61, 0x72,
        0x65, 0x20, 0x73, 0x2e, 0x72, 0x2e, 0x6f, 0x2e, 0x31, 0x1c, 0x30, 0x1a,
        0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x13, 0x54, 0x52, 0x4f, 0x50, 0x49,
        0x43, 0x30, 0x31, 0x20, 0x54, 0x45, 0x53, 0x54, 0x20, 0x43, 0x41, 0x20,
        0x76, 0x31, 0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce,
        0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62,
        0x00, 0x04, 0x76, 0x7a, 0x06, 0xca, 0x5c, 0xda, 0xa1, 0xda, 0x5b, 0x81,
        0x77, 0xdc, 0x4f, 0x92, 0xd9, 0x6b, 0xdc, 0x6d, 0x34, 0xc8, 0x33, 0xfb,
        0xcb, 0x67, 0x43, 0x6f, 0xbc, 0x5d, 0xf8, 0x0d, 0xe0, 0x61, 0xb2, 0x91,
        0x82, 0x2b, 0x32, 0x82, 0xd9, 0xd1, 0x0a, 0x63, 0x3d, 0x6d, 0x5c, 0x39,
        0x15, 0xcc, 0xc4, 0x61, 0x8b, 0x01, 0x5d, 0x23, 0x87, 0x89, 0x13, 0xd9,
        0xd1, 0x2d, 0x50, 0x6d, 0x1d, 0x12, 0xdb, 0x0c, 0x5d, 0xc2, 0x79, 0x66,
        0x78, 0x74, 0x5f, 0xc6, 0x44, 0xe9, 0x3b, 0x17, 0x41, 0x70, 0x45, 0x16,
        0x46, 0x67, 0x70, 0x3f, 0xeb, 0xcb, 0x42, 0xb8, 0x6a, 0xb8, 0x8d, 0x81,
        0xd8, 0xc4, 0xa3, 0x81, 0xa2, 0x30, 0x81, 0x9f, 0x30, 0x1d, 0x06, 0x03,
        0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xcc, 0x69, 0x7a, 0x4a, 0x99,
        0x65, 0xfb, 0x80, 0xcc, 0x0b, 0x3b, 0x2d, 0x8e, 0xde, 0x93, 0x5e, 0xcb,
        0x2a, 0x69, 0x5a, 0x30, 0x12, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01,
        0xff, 0x04, 0x08, 0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x01, 0x30,
        0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03,
        0x02, 0x01, 0x06, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18,
        0x30, 0x16, 0x80, 0x14, 0x2e, 0x9b, 0xa5, 0x40, 0x34, 0x39, 0x25, 0x34,
        0x8a, 0xc6, 0x01, 0x6b, 0xe5, 0x0d, 0x70, 0x2d, 0x78, 0x68, 0xb6, 0x88,
        0x30, 0x39, 0x06, 0x03, 0x55, 0x1d, 0x1f, 0x04, 0x32, 0x30, 0x30, 0x30,
        0x2e, 0xa0, 0x2c, 0xa0, 0x2a, 0x86, 0x28, 0x68, 0x74, 0x74, 0x70, 0x3a,
        0x2f, 0x2f, 0x70, 0x6b, 0x69, 0x2e, 0x74, 0x72, 0x6f, 0x70, 0x69, 0x63,
        0x73, 0x71, 0x75, 0x61, 0x72, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6c,
        0x31, 0x2f, 0x74, 0x73, 0x72, 0x76, 0x31, 0x2e, 0x63, 0x72, 0x6c, 0x30,
        0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04, 0x03,
        0x81, 0x8a, 0x00, 0x30, 0x81, 0x86, 0x02, 0x41, 0x10, 0x0b, 0xa6, 0x8d,
        0xf6, 0x0c, 0x0d, 0xa8, 0x12, 0xa1, 0xbf, 0xc8, 0x56, 0xe8, 0x75, 0x01,
        0x93, 0x18, 0x00, 0xaa, 0x70, 0xfa, 0x0e, 0xe8, 0xde, 0x3f, 0xc3, 0x43,
        0x6c, 0x99, 0x4f, 0x49, 0x47, 0xae, 0xb5, 0x54, 0x11, 0xb6, 0x3a, 0xc8,
        0x5f, 0x35, 0xe3, 0x1a, 0x72, 0x8d, 0x23, 0x4d, 0x98, 0xb9, 0xe8, 0x60,
        0x36, 0x77, 0x14, 0x08, 0x90, 0x61, 0xd8, 0x6d, 0x34, 0xff, 0xb9, 0x88,
        0xf9, 0x02, 0x41, 0x35, 0xeb, 0xc4, 0xef, 0x2d, 0x2c, 0x7c, 0xae, 0x46,
        0x2d, 0x1f, 0x31, 0xf8, 0x4d, 0xc7, 0xf9, 0xd5, 0x80, 0xcd, 0xc6, 0xc8,
        0x5b, 0xa0, 0x25, 0xc8, 0x66, 0x40, 0x15, 0x3b, 0xfc, 0xf2, 0xfb, 0x62,
        0xb2, 0xd3, 0xc7, 0x7e, 0xee, 0xe3, 0x45, 0x47, 0xce, 0x7f, 0x51, 0x74,
        0x1c, 0x68, 0x13, 0xd2, 0x59, 0x31, 0xd2, 0x79, 0x6d, 0x33, 0xb0, 0x94,
        0x04, 0xfa, 0xe6, 0xee, 0x3c, 0x19, 0x93, 0x0f, 0x30, 0x82, 0x02, 0x61,
        0x30, 0x82, 0x01, 0xc4, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x65,
        0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04,
        0x30, 0x54, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
        0x02, 0x43, 0x5a, 0x31, 0x1d, 0x30, 0x1b, 0x06, 0x03, 0x55, 0x04, 0x0a,
        0x0c, 0x14, 0x54, 0x72, 0x6f, 0x70, 0x69, 0x63, 0x20, 0x53, 0x71, 0x75,
        0x61, 0x72, 0x65, 0x20, 0x73, 0x2e, 0x72, 0x2e, 0x6f, 0x2e, 0x31, 0x26,
        0x30, 0x24, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x1d, 0x54, 0x72, 0x6f,
        0x70, 0x69, 0x63, 0x20, 0x53, 0x71, 0x75, 0x61, 0x72, 0x65, 0x20, 0x54,
        0x45, 0x53, 0x54, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x43, 0x41, 0x20,
        0x76, 0x31, 0x30, 0x20, 0x17, 0x0d, 0x32, 0x35, 0x30, 0x33, 0x32, 0x34,
        0x31, 0x33, 0x31, 0x34, 0x33, 0x38, 0x5a, 0x18, 0x0f, 0x32, 0x30, 0x37,
        0x35, 0x30, 0x33, 0x32, 0x34, 0x31, 0x33, 0x31, 0x34, 0x33, 0x38, 0x5a,
        0x30, 0x54, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
        0x02, 0x43, 0x5a, 0x31, 0x1d, 0x30, 0x1b, 0x06, 0x03, 0x55, 0x04, 0x0a,
        0x0c, 0x14, 0x54, 0x72, 0x6f, 0x70, 0x69, 0x63, 0x20, 0x53, 0x71, 0x75,
        0x61, 0x72, 0x65, 0x20, 0x73, 0x2e, 0x72, 0x2e, 0x6f, 0x2e, 0x31, 0x26,
        0x30, 0x24, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x1d, 0x54, 0x72, 0x6f,
        0x70, 0x69, 0x63, 0x20, 0x53, 0x71, 0x75, 0x61, 0x72, 0x65, 0x20, 0x54,
        0x45, 0x53, 0x54, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x43, 0x41, 0x20,
        0x76, 0x31, 0x30, 0x81, 0x9b, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48,
        0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23, 0x03,
        0x81, 0x86, 0x00, 0x04, 0x01, 0x35, 0xc7, 0xa2, 0x4d, 0x16, 0xb3, 0x74,
        0xb2, 0x07, 0xad, 0xe8, 0xfe, 0x50, 0xf5, 0x03, 0xad, 0x34, 0xe0, 0xe5,
        0x96, 0xc8, 0x3f, 0xc9, 0x8a, 0xdb, 0x4c, 0x43, 0x88, 0xca, 0x0a, 0xd9,
        0xb2, 0x4e, 0x77, 0xe9, 0x84, 0xb8, 0x97, 0x82, 0x53, 0xa8, 0xe0, 0xd6,
        0xfd, 0x68, 0xea, 0xa8, 0xd9, 0xc9, 0xa9, 0xa6, 0xc8, 0x83, 0x5a, 0x13,
        0x8c, 0xcc, 0xff, 0x51, 0x13, 0x0d, 0xa1, 0x09, 0x86, 0x80, 0x00, 0xcd,
        0xf7, 0xfa, 0xd5, 0xa0, 0x2b, 0xbd, 0x84, 0x45, 0x3c, 0x56, 0x36, 0xf2,
        0x5f, 0x1c, 0x39, 0x5b, 0xdc, 0x22, 0xee, 0x7b, 0x44, 0x1a, 0x81, 0xb5,
        0x9f, 0x20, 0x40, 0x53, 0x89, 0xf4, 0x7d, 0x65, 0xf0, 0x74, 0xa6, 0x02,
        0xf9, 0x33, 0x2d, 0xf1, 0x33, 0x79, 0xf2, 0x7d, 0x65, 0x4f, 0x4e, 0x1b,
        0x0f, 0xd4, 0x56, 0xc1, 0xa9, 0x9f, 0x54, 0x36, 0x64, 0x0f, 0x7e, 0xe0,
        0x4e, 0x1b, 0x48, 0x81, 0xa3, 0x42, 0x30, 0x40, 0x30, 0x1d, 0x06, 0x03,
        0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x2e, 0x9b, 0xa5, 0x40, 0x34,
        0x39, 0x25, 0x34, 0x8a, 0xc6, 0x01, 0x6b, 0xe5, 0x0d, 0x70, 0x2d, 0x78,
        0x68, 0xb6, 0x88, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01,
        0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x0e, 0x06, 0x03,
        0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x01, 0x06,
        0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04,
        0x03, 0x81, 0x8a, 0x00, 0x30, 0x81, 0x86, 0x02, 0x41, 0x6a, 0x2d, 0x9d,
        0x72, 0xb4, 0x35, 0x30, 0x35, 0x72, 0x5e, 0x9d, 0x60, 0x7f, 0x62, 0xf9,
        0x27, 0xe8, 0x87, 0xb6, 0x07, 0xc9, 0xfe, 0x7f, 0xd7, 0xbd, 0xdf, 0x00,
        0xa4, 0xd9, 0x4b, 0x5d, 0x57, 0xf3, 0xc9, 0x37, 0x70, 0xa2, 0xbe, 0x25,
        0xc1, 0x3f, 0x59, 0xee, 0x9f, 0x41, 0x97, 0x17, 0x9f, 0x94, 0x06, 0xec,
        0x2a, 0x8c, 0xea, 0xb1, 0xd5, 0x19, 0x05, 0x47, 0xec, 0x24, 0x48, 0x6f,
        0x8b, 0x95, 0x02, 0x41, 0x3c, 0x0a, 0x74, 0xa1, 0x61, 0x3b, 0xd5, 0xdb,
        0x29, 0xf5, 0x8e, 0xa4, 0xc7, 0x92, 0xcf, 0xfe, 0x01, 0xe0, 0xbe, 0x5c,
        0x28, 0x22, 0x24, 0xe7, 0xff, 0x93, 0xf5, 0x12, 0x58, 0xa5, 0xf2, 0x2e,
        0x3b, 0xa4, 0xa1, 0x83, 0xe8, 0x82, 0xa5, 0xc5, 0x4f, 0x5c, 0x39, 0xce,
        0x14, 0x02, 0xd1, 0xb2, 0x67, 0x4c, 0xc3, 0x4a, 0x41, 0x82, 0xea, 0xf0,
        0x61, 0xc4, 0xf6, 0x6e, 0x30, 0xe9, 0x68, 0x32, 0x12,
    
    ];

    /// The pinned TEST trust anchor: P-521 root public key, SEC1 uncompressed
    /// point 0x04 || X(66) || Y(66). PROD root differs (integrator supplies it).
    pub(super) const MODEL_TEST_ROOT_PUBKEY: [u8; 133] = [

        0x04, 0x01, 0x35, 0xc7, 0xa2, 0x4d, 0x16, 0xb3, 0x74, 0xb2, 0x07, 0xad,
        0xe8, 0xfe, 0x50, 0xf5, 0x03, 0xad, 0x34, 0xe0, 0xe5, 0x96, 0xc8, 0x3f,
        0xc9, 0x8a, 0xdb, 0x4c, 0x43, 0x88, 0xca, 0x0a, 0xd9, 0xb2, 0x4e, 0x77,
        0xe9, 0x84, 0xb8, 0x97, 0x82, 0x53, 0xa8, 0xe0, 0xd6, 0xfd, 0x68, 0xea,
        0xa8, 0xd9, 0xc9, 0xa9, 0xa6, 0xc8, 0x83, 0x5a, 0x13, 0x8c, 0xcc, 0xff,
        0x51, 0x13, 0x0d, 0xa1, 0x09, 0x86, 0x80, 0x00, 0xcd, 0xf7, 0xfa, 0xd5,
        0xa0, 0x2b, 0xbd, 0x84, 0x45, 0x3c, 0x56, 0x36, 0xf2, 0x5f, 0x1c, 0x39,
        0x5b, 0xdc, 0x22, 0xee, 0x7b, 0x44, 0x1a, 0x81, 0xb5, 0x9f, 0x20, 0x40,
        0x53, 0x89, 0xf4, 0x7d, 0x65, 0xf0, 0x74, 0xa6, 0x02, 0xf9, 0x33, 0x2d,
        0xf1, 0x33, 0x79, 0xf2, 0x7d, 0x65, 0x4f, 0x4e, 0x1b, 0x0f, 0xd4, 0x56,
        0xc1, 0xa9, 0x9f, 0x54, 0x36, 0x64, 0x0f, 0x7e, 0xe0, 0x4e, 0x1b, 0x48,
        0x81,
    
    ];

    /// The authoritative STPUB the DEVICE certificate carries (32 bytes).
    pub(super) const MODEL_STPUB: [u8; 32] = [

        0x95, 0x08, 0xf0, 0x32, 0x1c, 0xb1, 0xd2, 0xe5, 0xd1, 0xf1, 0xa4, 0x60,
        0x9c, 0x05, 0x41, 0xb7, 0x80, 0xe6, 0xdd, 0x50, 0xd6, 0x48, 0x2b, 0x6b,
        0x08, 0xb2, 0xc2, 0x7e, 0x7b, 0x76, 0x26, 0x47,
    
    ];
}
