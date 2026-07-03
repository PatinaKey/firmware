//! Secure-world TROPIC01 crypto + attestation bring-up, exported to the NSC veneer.
//!
//! Proves real ECC crypto UNDER an L3 session plus the full X.509 attestation
//! chain on silicon: verify the chip certificate chain up to the PINNED
//! production Tropic Square root, open a Noise KK1 session on the VERIFIED
//! STPUB, then run a sequence of session-encrypted commands (TRNG draw, Ed25519
//! generate/sign/verify, P-256 generate/sign/shape-check) and tear down with the
//! chip-notifying abort. It is the secure side of the `patinakey_nsc_se_crypto`
//! non-secure-callable veneer: the non-secure world calls the veneer, the veneer
//! forwards here, this code drives the flow, packs the outcome into a `u32`, and
//! returns.
//!
//! FEATURE-GATED: the whole module compiles ONLY under the `se-session` cargo
//! feature. With the feature off the product firmware is byte-unchanged and never
//! references this path.
//!
//! BRING-UP ONLY: this path uses a FIXED ephemeral key and the PUBLIC factory
//! slot-0 pairing key (both re-used from se_session.rs). It is a silicon test,
//! never a product build.
//!
//! QUARANTINE: the `extern "C"` entry needs `#[unsafe(no_mangle)]` so the C
//! veneer in csrc/secure_nsc.c can resolve it by its C ABI name.

use tropic01_driver::EccCurve;
use tropic01_driver::EccSlot;
use tropic01_driver::RootAnchor;
use tropic01_driver::SeCommands;
use tropic01_driver::SeError;

use crate::se_session::open_bringup_session;
use crate::se_session::CERT_SCRATCH_LEN;
use crate::se_smoke::build_device;
use crate::se_smoke::se_error_code;

/// Pinned Tropic Square Root CA v1 public key, serial 301, P-521, SEC1
/// uncompressed (133 bytes).
///
/// This is a PUBLIC vendor certificate, published with the Tropic Square SDK and
/// at pki.tropicsquare.com. It is the out-of-band trust anchor the chip
/// certificate chain is verified against. A corrupted constant is rejected by
/// [`RootAnchor::from_sec1_p521`] (off-curve or bad prefix), so the attestation
/// step fails loudly rather than trusting a wrong root.
const TROPIC_ROOT_CA_V1_SEC1: [u8; 133] =
[
    0x04, 0x01, 0x87, 0xcc, 0xea, 0x62, 0x83, 0x7e,
    0x23, 0x09, 0x2d, 0x8a, 0x71, 0x35, 0x78, 0x9f,
    0xcc, 0x6f, 0xbc, 0x3d, 0x35, 0xe7, 0x9f, 0xc0,
    0x1f, 0x4f, 0x49, 0x8f, 0xc5, 0xc2, 0xc4, 0x09,
    0xce, 0x77, 0x2f, 0x90, 0x13, 0x40, 0x09, 0x04,
    0x03, 0xe8, 0xba, 0x4d, 0x97, 0xe1, 0x3f, 0x1e,
    0x75, 0x94, 0xac, 0x6d, 0x2f, 0x51, 0xfd, 0x22,
    0x39, 0xf8, 0xd4, 0x57, 0x76, 0x9f, 0x37, 0x84,
    0x40, 0xa1, 0x80, 0x00, 0x71, 0x2b, 0xf1, 0x6a,
    0x48, 0xea, 0x20, 0x25, 0x83, 0x7b, 0xef, 0xd0,
    0x50, 0x2a, 0x56, 0x2f, 0xd9, 0x39, 0x41, 0xd5,
    0x2c, 0xc4, 0x0e, 0xd9, 0x55, 0x3c, 0xa7, 0x9b,
    0x14, 0x5b, 0xa5, 0x85, 0xf3, 0x24, 0x92, 0xbf,
    0xd7, 0x92, 0xeb, 0x96, 0xd9, 0x49, 0xd3, 0x16,
    0x76, 0xcd, 0x09, 0x9f, 0x19, 0xce, 0x88, 0x48,
    0x69, 0x7b, 0x8c, 0x34, 0x30, 0xaf, 0x01, 0x6f,
    0xed, 0x98, 0x5e, 0x1e, 0xb4,
];

/// Fixed ASCII message signed by the Ed25519 path and verified on-host.
///
/// The chip hashes it internally (RFC 8032). The host verifier re-checks the
/// signature over these exact bytes, so an SE-produced EdDSA signature is proven
/// to verify under a standard verifier.
const MESSAGE: &[u8] = b"patinakey EdDSA attest";

/// Fixed 32-byte digest signed by the P-256 (ECDSA) path.
///
/// An arbitrary documented byte pattern. The chip signs a caller-supplied digest
/// (the host pre-hashes with SHA-256 in production), so any fixed 32 bytes prove
/// the command round trip. No P-256 verifier is linked, so only the signature
/// shape is checked.
const DIGEST: [u8; 32] =
[
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

/// ECC slot the Ed25519 test key lives in (bring-up scratch slot).
const ED25519_SLOT: u8 = 31;
/// ECC slot the P-256 test key lives in (bring-up scratch slot).
const P256_SLOT: u8 = 30;

// Status-word encoding.
//
// CROSS-CRATE COUPLING: SCR_OK / SCR_ERR / the step codes / SCR_OK_MARKER MUST
// match the encoding decoded on the non-secure side
// (crates/nonsecure/src/main.rs). The two crates do not share a type, so the bit
// layout is duplicated by hand and the two copies must stay in sync.
//
// Layout:
//   bit 31    SCR_ERR : the crypto bring-up failed.
//   bit 8     SCR_OK  : the crypto bring-up succeeded.
//   bits 15..8 (on ERR) step code: which step failed (1..=11, 0x01..=0x0B).
//   bits 7..0  (on ERR) the SeError code (se_error_code, shared with se_smoke),
//                       or a RESERVED non-SeError code (0xF1..0xF4, see below).
//   bits 7..0  (on OK)  SCR_OK_MARKER: a fixed pattern the NS logs as "crypto +
//                       attestation OK".
// An error word can also set bit 8 incidentally (an odd step shifts a 1 into bit
// 8 via step << 8). SCR_ERR (bit 31) is the discriminator: the NS tests SCR_ERR
// FIRST, so an error word with bit 8 set is read as an error.
//
// RESERVED non-SeError low-byte codes (secure-side, ONE place). These are NOT
// se_error_code values, so they never collide with a real SeError code:
//   0xF0  echo mismatch                (used by se_session.rs, not here).
//   0xF1  EdDSA signature verify reject (host verifier rejected the signature).
//   0xF2  random sanity failure         (all 32 TRNG bytes identical).
//   0xF3  ECDSA signature shape failure (R half or S half all zero).
//   0xF4  Ed25519 public-key length mismatch (not the expected 32 bytes).

/// Status bit: the crypto bring-up succeeded.
const SCR_OK: u32 = 1 << 8;
/// Status bit: the crypto bring-up failed. Bits 15..8 then carry the step, bits
/// 7..0 the [`SeError`] code or a RESERVED code.
const SCR_ERR: u32 = 1 << 31;

/// Low-byte marker returned on success. The non-secure side logs it as "crypto +
/// attestation OK". It appears only with bit 31 clear, error codes only with bit
/// 31 set, so there is no ambiguity.
const SCR_OK_MARKER: u32 = 0x52;

/// RESERVED code: the host EdDSA verifier rejected the SE-produced signature (or
/// the pubkey did not parse). Not an [`SeError`].
const SCR_EDDSA_REJECT: u32 = 0xF1;
/// RESERVED code: the TRNG draw returned 32 identical bytes (a dead bus or stuck
/// RNG). Not an [`SeError`].
const SCR_RANDOM_SANITY: u32 = 0xF2;
/// RESERVED code: the ECDSA signature had an all-zero R or S half. Not an
/// [`SeError`].
const SCR_ECDSA_SHAPE: u32 = 0xF3;
/// RESERVED code: the Ed25519 public key was not the expected 32 bytes. Not an
/// [`SeError`]. Only the Ed25519 read checks length, the P-256 path reads no
/// public key.
const SCR_PUBKEY_LEN: u32 = 0xF4;

/// Step code: verify the chain and read the VERIFIED STPUB (attestation).
const STEP_ATTEST: u32 = 0x01;
/// Step code: open the Noise KK1 session on the verified STPUB.
const STEP_OPEN_SESSION: u32 = 0x02;
/// Step code: draw 32 TRNG bytes and sanity-check them.
const STEP_RANDOM: u32 = 0x03;
// Step 4 (pre-clean, 0x04) has no secure-side error word: its erase result is
// deliberately ignored (see the pre-clean comment in the flow), so no
// STEP_PRE_CLEAN const exists. The non-secure decoder still labels step 4 for
// completeness.
/// Step code: generate the Ed25519 key.
const STEP_ED_GENERATE: u32 = 0x05;
/// Step code: read the Ed25519 public key.
const STEP_ED_PUBKEY: u32 = 0x06;
/// Step code: sign MESSAGE with the Ed25519 key.
const STEP_ED_SIGN: u32 = 0x07;
/// Step code: verify the EdDSA signature on-host.
const STEP_ED_VERIFY: u32 = 0x08;
/// Step code: erase the Ed25519 key (checked).
const STEP_ED_ERASE: u32 = 0x09;
/// Step code: the P-256 generate/sign/shape/erase round trip.
const STEP_ECDSA: u32 = 0x0A;
/// Step code: the chip-notifying session abort.
const STEP_SESSION_ABORT: u32 = 0x0B;

/// Packs a failing step and an [`SeError`] into the error status word.
///
/// `SCR_ERR | (step << 8) | error_code`. The step lives in bits 15..8, the error
/// code in the low byte, so the non-secure log names both the failing step and
/// the fault.
fn err_word(step: u32, err: SeError) -> u32
{
    SCR_ERR | (step << 8) | se_error_code(err)
}

/// Packs a failing step and a RESERVED low-byte code into the error status word.
///
/// Used for the non-[`SeError`] sanity codes (0xF1..0xF4). Same layout as
/// [`err_word`] but with a caller-supplied low byte.
fn err_word_code(step: u32, code: u32) -> u32
{
    SCR_ERR | (step << 8) | (code & 0xFF)
}

/// Verifies an Ed25519 signature over MESSAGE under a 32-byte public key.
///
/// Uses the standard RFC 8032 verifier (`ed25519_dalek`). Returns true only when
/// the pubkey parses AND the strict verification passes. A parse or verify
/// failure returns false, which the caller maps to [`SCR_EDDSA_REJECT`].
fn eddsa_verify_host(pubkey: &[u8], signature: &[u8; 64]) -> bool
{
    let key_bytes: [u8; 32] = match pubkey.try_into()
    {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    let verifying_key = match ed25519_dalek::VerifyingKey::from_bytes(&key_bytes)
    {
        Ok(key) => key,
        Err(_) => return false,
    };
    let sig = ed25519_dalek::Signature::from_bytes(signature);
    verifying_key.verify_strict(MESSAGE, &sig).is_ok()
}

/// Runs the crypto + attestation bring-up and returns a packed status word.
///
/// Drives the flow step by step so the returned word names WHICH step failed:
///   1. verify the chain to the pinned root and read the VERIFIED STPUB,
///   2. open the Noise KK1 session on that STPUB (shared with se_session.rs),
///   3. draw 32 TRNG bytes and sanity-check them,
///   4. best-effort pre-clean erase of the Ed25519 slot (result ignored),
///   5. generate an Ed25519 key,
///   6. read its public key (expect 32 bytes),
///   7. sign MESSAGE (EdDSA),
///   8. verify the signature on-host under the public key,
///   9. erase the Ed25519 key (checked),
///  10. generate a P-256 key, sign DIGEST (ECDSA), shape-check, erase (checked),
///  11. chip-notifying teardown.
///
/// The chip must already be in Application FW mode (the L3 channel lives there).
///
/// On any [`SeError`] returns [`err_word`]. On a sanity or verify failure returns
/// [`err_word_code`] with the matching RESERVED code. On success returns `SCR_OK
/// | SCR_OK_MARKER`. If a session is open when a step fails, it is torn down
/// before returning.
///
/// This is the non-secure-callable entry the crypto veneer forwards to.
// QUARANTINE: the stable C export name needs `#[unsafe(no_mangle)]`.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn patinakey_se_crypto() -> u32
{
    let ed_slot = match EccSlot::new(ED25519_SLOT)
    {
        Ok(slot) => slot,
        Err(e) => return err_word(STEP_ATTEST, e),
    };
    let p256_slot = match EccSlot::new(P256_SLOT)
    {
        Ok(slot) => slot,
        Err(e) => return err_word(STEP_ATTEST, e),
    };

    let mut dev = build_device();

    // Step 1: build the pinned anchor and verify the FULL chain, returning the
    // VERIFIED STPUB.
    let anchor = match RootAnchor::from_sec1_p521(&TROPIC_ROOT_CA_V1_SEC1)
    {
        Ok(anchor) => anchor,
        Err(e) => return err_word(STEP_ATTEST, e),
    };
    let mut scratch = [0u8; CERT_SCRATCH_LEN];
    let stpub = match dev.read_verified_chip_stpub(&mut scratch, &anchor)
    {
        Ok(stpub) => stpub,
        Err(e) => return err_word(STEP_ATTEST, e),
    };

    // Step 2: open the Noise KK1 session on the VERIFIED STPUB. The shared helper
    // uses the same prod0 SH0 keys and fixed ephemeral as se_session.rs.
    let mut session = match open_bringup_session(dev, &stpub)
    {
        Ok(session) => session,
        Err((_dev, e)) => return err_word(STEP_OPEN_SESSION, e),
    };

    // Step 3: draw 32 TRNG bytes.
    let mut rnd = [0u8; 32];
    match session.random_into(&mut rnd)
    {
        Ok(n) if n == rnd.len() => {}
        Ok(_) =>
        {
            let (_dev, _ack) = session.abort_session();
            return err_word_code(STEP_RANDOM, SCR_RANDOM_SANITY);
        }
        Err(e) =>
        {
            let (_dev, _ack) = session.abort_session();
            return err_word(STEP_RANDOM, e);
        }
    }
    if rnd.iter().all(|&b| b == rnd[0])
    {
        let (_dev, _ack) = session.abort_session();
        return err_word_code(STEP_RANDOM, SCR_RANDOM_SANITY);
    }

    // Step 4: best-effort pre-clean erase of the Ed25519 slot, result IGNORED.
    // The API documentation is silent on the erase-on-an-empty-slot result code,
    // and the vendor SDK reference sequence erases unconditionally before
    // generating, so the pre-clean tolerates any outcome. The checked cleanup
    // erase at step 9 later proves erase works. A transport-dead chip fails the
    // next step anyway.
    let _ = session.ecc_key_erase(ed_slot);

    // Step 5: generate the Ed25519 key. On error erase best-effort (the slot may
    // hold a partial key) then tear down.
    if let Err(e) = session.ecc_key_generate(ed_slot, EccCurve::Ed25519)
    {
        // Best-effort cleanup: the generate may have left a key.
        let _ = session.ecc_key_erase(ed_slot);
        let (_dev, _ack) = session.abort_session();
        return err_word(STEP_ED_GENERATE, e);
    }

    // Step 6: read the Ed25519 public key. Expect exactly 32 bytes.
    let ed_pubkey = match session.ecc_public_key(ed_slot)
    {
        Ok(key) => key,
        Err(e) =>
        {
            let _ = session.ecc_key_erase(ed_slot);
            let (_dev, _ack) = session.abort_session();
            return err_word(STEP_ED_PUBKEY, e);
        }
    };
    if ed_pubkey.bytes().len() != 32
    {
        let _ = session.ecc_key_erase(ed_slot);
        let (_dev, _ack) = session.abort_session();
        return err_word_code(STEP_ED_PUBKEY, SCR_PUBKEY_LEN);
    }
    let mut ed_pub_bytes = [0u8; 32];
    ed_pub_bytes.copy_from_slice(ed_pubkey.bytes());

    // Step 7: sign MESSAGE with the Ed25519 key (EdDSA).
    let ed_sig = match session.eddsa_sign(ed_slot, MESSAGE)
    {
        Ok(sig) => sig,
        Err(e) =>
        {
            let _ = session.ecc_key_erase(ed_slot);
            let (_dev, _ack) = session.abort_session();
            return err_word(STEP_ED_SIGN, e);
        }
    };

    // Step 8: verify the 64-byte signature on-host under the 32-byte pubkey with
    // a standard RFC 8032 verifier.
    if !eddsa_verify_host(&ed_pub_bytes, &ed_sig.0)
    {
        let _ = session.ecc_key_erase(ed_slot);
        let (_dev, _ack) = session.abort_session();
        return err_word_code(STEP_ED_VERIFY, SCR_EDDSA_REJECT);
    }

    // Step 9: checked erase of the Ed25519 key.
    if let Err(e) = session.ecc_key_erase(ed_slot)
    {
        let (_dev, _ack) = session.abort_session();
        return err_word(STEP_ED_ERASE, e);
    }

    // Step 10: the P-256 (ECDSA) round trip. Generate, sign a fixed digest,
    // SHAPE-check only, then checked erase.
    //
    // No P-256 verifier is linked, so
    // this proves the command round trip and the signature shape, NOT
    // cryptographic verification.
    let _ = session.ecc_key_erase(p256_slot);
    if let Err(e) = session.ecc_key_generate(p256_slot, EccCurve::P256)
    {
        let _ = session.ecc_key_erase(p256_slot);
        let (_dev, _ack) = session.abort_session();
        return err_word(STEP_ECDSA, e);
    }
    let p256_sig = match session.ecdsa_sign(p256_slot, &DIGEST)
    {
        Ok(sig) => sig,
        Err(e) =>
        {
            let _ = session.ecc_key_erase(p256_slot);
            let (_dev, _ack) = session.abort_session();
            return err_word(STEP_ECDSA, e);
        }
    };
    // SHAPE check: 64 bytes with neither the R half (first 32) nor the S half
    // (last 32) all zero. An all-zero half is a malformed signature.
    let r_zero = p256_sig.0[..32].iter().all(|&b| b == 0);
    let s_zero = p256_sig.0[32..].iter().all(|&b| b == 0);
    if r_zero || s_zero
    {
        let _ = session.ecc_key_erase(p256_slot);
        let (_dev, _ack) = session.abort_session();
        return err_word_code(STEP_ECDSA, SCR_ECDSA_SHAPE);
    }
    if let Err(e) = session.ecc_key_erase(p256_slot)
    {
        let (_dev, _ack) = session.abort_session();
        return err_word(STEP_ECDSA, e);
    }

    // Step 11: chip-notifying teardown.
    let (_dev, ack) = session.abort_session();
    match ack
    {
        Ok(()) => SCR_OK | SCR_OK_MARKER,
        Err(e) => err_word(STEP_SESSION_ABORT, e),
    }
}
