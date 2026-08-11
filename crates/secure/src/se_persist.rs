//! Secure-world TROPIC01 persistent-but-reversible state bring-up, exported to
//! the NSC veneer.
//!
//! Proves the chip's persistent-yet-reversible state commands on silicon, all of
//! them undoable by a reboot, a re-init, or an erase: 
//! the monotonic counters, MAC-and-Destroy, and ECC_Key_Store.
//! It opens a Noise KK1 session on the plain STPUB, then drives a sequence that
//! sets, reads, decrements, re-initializes, and boundary-tests a counter, proves
//! a MAC-and-Destroy slot re-initializes to the identical state after a destroy,
//! and runs a full Ed25519 known-answer test through ECC_Key_Store (import the
//! RFC 8032 seed, read the public key, sign, host-verify, erase), then tears down
//! with the chip-notifying abort. It is the secure side of the
//! `patinakey_nsc_se_persist` non-secure-callable veneer: the non-secure world
//! calls the veneer, the veneer forwards here, this code drives the flow, packs
//! the outcome into a `u32`, and returns.
//!
//! FEATURE-GATED: the whole module compiles ONLY under the `se-session` cargo
//! feature. With the feature off the product firmware is byte-unchanged and never
//! references this path.
//!
//! BRING-UP ONLY: this path uses a FIXED ephemeral key and the PUBLIC factory
//! slot-0 pairing key (both re-used from se_session.rs). It is a silicon test,
//! never a product build. It touches only reversible R-Memory state (counters,
//! MAC-and-Destroy slots, ECC slots), never OTP, config, or pairing keys.
//!
//! QUARANTINE: the `extern "C"` entry needs `#[unsafe(no_mangle)]` so the C
//! veneer in csrc/secure_nsc.c can resolve it by its C ABI name.

use tropic01_driver::EccCurve;
use tropic01_driver::EccSlot;
use tropic01_driver::L3Error;
use tropic01_driver::L3Status;
use tropic01_driver::MCounterIdx;
use tropic01_driver::MacDestroySlot;
use tropic01_driver::SeCommands;
use tropic01_driver::SeError;
use zeroize::Zeroizing;

use crate::se_session::open_bringup_session;
use crate::se_session::BringupSession;
use crate::se_session::CERT_SCRATCH_LEN;
use crate::se_smoke::build_device;
use crate::se_smoke::se_error_code;

/// Monotonic counter index exercised by the counter steps (bring-up scratch).
const MCOUNTER_IDX: u8 = 15;
/// MAC-and-Destroy slot exercised by the repeatability step (bring-up scratch).
const MAC_DESTROY_SLOT: u8 = 127;
/// ECC slot the imported Ed25519 test key lives in (bring-up scratch slot).
///
/// 29 keeps this key off slot 28 (se_readonly.rs), so the feature-gated bring-up
/// paths never share an ECC slot.
const ECC_SLOT: u8 = 29;

/// The counter value the first init sets (step 2).
const MCOUNTER_INIT_VALUE: u32 = 5;
/// The counter value the upward re-init sets (step 5), higher than the first
/// init to prove a counter is fully resettable, not one-shot.
const MCOUNTER_REINIT_VALUE: u32 = 10;

/// First MAC-and-Destroy input, the "initialize" value.
///
/// An arbitrary fixed 32-byte pattern. Per the TROPIC01 PIN-verification
/// app note (New PIN Setup, steps 6.1 and 6.5), a MAC-and-Destroy call overwrites
/// the slot with a value derived from the input and the slot index ALONE, so this
/// input deterministically drives the slot to one fixed state regardless of its
/// prior content. That is what makes a destroyed slot re-initializable.
const MAC_INPUT_INIT: [u8; 32] =
[
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
];
/// Second MAC-and-Destroy input, the "measure" value.
///
/// An arbitrary fixed 32-byte pattern distinct from [`MAC_INPUT_INIT`].
/// Per the app note step 6.2 the output of a call with this input is a function
/// of the PRE-overwrite slot content, this input, and the index, so from a slot
/// driven to the fixed [`MAC_INPUT_INIT`] state the output is deterministic.
const MAC_INPUT_MEASURE: [u8; 32] =
[
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
];

/// RFC 8032 TEST 1 Ed25519 secret seed, a PUBLIC standard test vector.
///
/// Imported into the ECC slot via ECC_Key_Store. It is not a secret (it is
/// published in RFC 8032).
const ED25519_SEED: [u8; 32] =
[
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
    0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
    0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];

/// RFC 8032 TEST 1 Ed25519 public key, the expected answer for [`ED25519_SEED`].
///
/// A mismatch means ECC_Key_Store or the on-chip RFC 8032 expansion diverged 
/// from the standard, reported as [`SPR_PUBKEY_KAT`].
const ED25519_EXPECTED_PUBKEY: [u8; 32] =
[
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
    0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
    0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];

/// Fixed ASCII message signed by the imported Ed25519 key and verified on-host.
///
/// The chip hashes it internally (RFC 8032). The host verifier re-checks the
/// signature over these exact bytes under the read public key, so an SE-produced
/// EdDSA signature from an IMPORTED key is proven to verify under a standard
/// verifier.
const MESSAGE: &[u8] = b"patinakey persist EdDSA";

// Status-word encoding.
//
// CROSS-CRATE COUPLING: SPR_OK / SPR_ERR / the step codes / SPR_OK_MARKER MUST
// match the encoding decoded on the non-secure side
// (crates/nonsecure/src/main.rs). The two crates do not share a type, so the bit
// layout is duplicated by hand and the two copies must stay in sync.
//
// Layout:
//   bit 31    SPR_ERR : the persistent-state bring-up failed.
//   bit 8     SPR_OK  : the persistent-state bring-up succeeded.
//   bits 15..8 (on ERR) step code: which step failed (1..=14, 0x01..=0x0E).
//   bits 7..0  (on ERR) the SeError code (se_error_code, shared with se_smoke),
//                       or a RESERVED non-SeError code (0xF5..0xFA, see below).
//   bits 7..0  (on OK)  SPR_OK_MARKER: a fixed pattern the NS logs as "persistent
//                       state OK".
// An error word can also set bit 8 incidentally (an odd step shifts a 1 into bit
// 8 via step << 8). SPR_ERR (bit 31) is the discriminator: the NS tests SPR_ERR
// FIRST, so an error word with bit 8 set is read as an error.
//
// RESERVED non-SeError low-byte codes (secure-side, ONE place). These are NOT
// se_error_code values, so they never collide with a real SeError code:
//   0xF5  mcounter value mismatch          (a counter read back a wrong value).
//   0xF6  mcounter zero-boundary surprise  (the at-zero boundary behaved wrong).
//   0xF7  MAC-and-Destroy determinism miss (two identical cycles differed).
//   0xF8  stored-key pubkey KAT mismatch   (chip pubkey != RFC 8032 answer).
//   0xF9  stored-key EdDSA verify reject   (host verifier rejected the signature).
//   0xFA  post-erase sign unexpectedly Ok  (a sign on an erased slot succeeded).

/// Status bit: the persistent-state bring-up succeeded.
const SPR_OK: u32 = 1 << 8;
/// Status bit: the persistent-state bring-up failed. Bits 15..8 then carry the
/// step, bits 7..0 the [`SeError`] code or a RESERVED code.
const SPR_ERR: u32 = 1 << 31;

/// Low-byte marker returned on success. The non-secure side logs it as
/// "persistent state OK". It appears only with bit 31 clear, error codes only
/// with bit 31 set.
const SPR_OK_MARKER: u32 = 0x53;

/// RESERVED code: a monotonic counter read back a value other than the one just
/// written. Not an [`SeError`].
const SPR_MCOUNTER_MISMATCH: u32 = 0xF5;
/// RESERVED code: the counter at-zero boundary behaved unexpectedly (a decrement
/// at one failed, the value was not zero after it, or the decrement at zero did
/// not report the expected under-run). Not an [`SeError`].
const SPR_ZERO_BOUNDARY: u32 = 0xF6;
/// RESERVED code: the two identical MAC-and-Destroy cycles produced different
/// outputs, so the slot did not re-initialize to the same state. Not an
/// [`SeError`].
const SPR_MACDESTROY_MISMATCH: u32 = 0xF7;
/// RESERVED code: the public key read back from the imported Ed25519 key did not
/// match the RFC 8032 known answer. Not an [`SeError`].
const SPR_PUBKEY_KAT: u32 = 0xF8;
/// RESERVED code: the host EdDSA verifier rejected the signature from the
/// imported key (or the pubkey did not parse). Not an [`SeError`].
const SPR_EDDSA_REJECT: u32 = 0xF9;
/// RESERVED code: a sign on the erased slot succeeded when it had to fail. Not an
/// [`SeError`].
const SPR_POST_ERASE_SIGN: u32 = 0xFA;

/// Step code: open the Noise KK1 session (read STPUB then handshake on slot 0).
const STEP_OPEN_SESSION: u32 = 0x01;
/// Step code: initialize the counter to [`MCOUNTER_INIT_VALUE`].
const STEP_MCOUNTER_INIT: u32 = 0x02;
/// Step code: read the counter and check it equals [`MCOUNTER_INIT_VALUE`].
const STEP_MCOUNTER_GET: u32 = 0x03;
/// Step code: decrement the counter and check it read back one less.
const STEP_MCOUNTER_UPDATE: u32 = 0x04;
/// Step code: upward re-init to [`MCOUNTER_REINIT_VALUE`] and check the read.
const STEP_MCOUNTER_REINIT: u32 = 0x05;
/// Step code: the counter at-zero boundary behaviour.
const STEP_MCOUNTER_ZERO: u32 = 0x06;
/// Step code: the MAC-and-Destroy repeatability (two identical cycles).
const STEP_MACDESTROY: u32 = 0x07;
// Step 8 (pre-clean, 0x08) has no secure-side error word: its erase result is
// deliberately ignored (see the pre-clean comment in the flow), so no
// STEP_PRE_CLEAN const exists. The non-secure decoder still labels step 8 for
// completeness.
/// Step code: import the Ed25519 seed with ECC_Key_Store.
const STEP_ECC_STORE: u32 = 0x09;
/// Step code: read the imported public key and check the RFC 8032 answer.
const STEP_ECC_PUBKEY: u32 = 0x0A;
/// Step code: sign MESSAGE and host-verify the signature.
const STEP_ECC_SIGN: u32 = 0x0B;
/// Step code: erase the imported key (checked).
const STEP_ECC_ERASE: u32 = 0x0C;
/// Step code: a post-erase sign that must fail.
const STEP_POST_ERASE: u32 = 0x0D;
/// Step code: the chip-notifying session abort.
const STEP_SESSION_ABORT: u32 = 0x0E;

/// Packs a failing step and an [`SeError`] into the error status word.
///
/// `SPR_ERR | (step << 8) | error_code`. The step lives in bits 15..8, the error
/// code in the low byte, so the non-secure log names both the failing step and
/// the fault.
fn err_word(step: u32, err: SeError) -> u32
{
    SPR_ERR | (step << 8) | se_error_code(err)
}

/// Packs a failing step and a RESERVED low-byte code into the error status word.
///
/// Used for the non-[`SeError`] sanity codes (0xF5..0xFA). Same layout as
/// [`err_word`] but with a caller-supplied low byte.
fn err_word_code(step: u32, code: u32) -> u32
{
    SPR_ERR | (step << 8) | (code & 0xFF)
}

/// Verifies an Ed25519 signature over MESSAGE under a 32-byte public key.
///
/// Uses the standard RFC 8032 verifier (`ed25519_dalek`). Returns true only when
/// the pubkey parses AND the strict verification passes. A parse or verify
/// failure returns false, which the caller maps to [`SPR_EDDSA_REJECT`].
fn eddsa_verify_host(pubkey: &[u8; 32], signature: &[u8; 64]) -> bool
{
    let verifying_key = match ed25519_dalek::VerifyingKey::from_bytes(pubkey)
    {
        Ok(key) => key,
        Err(_) => return false,
    };
    let sig = ed25519_dalek::Signature::from_bytes(signature);
    verifying_key.verify_strict(MESSAGE, &sig).is_ok()
}

/// Steps 2..5: set the counter, read it, decrement it, then upward re-init.
///
/// Proves the counter reads back the written value, decrements by one, and is
/// fully resettable to a higher value. Returns the packed error word on any fault
/// and never tears the session down, the caller owns teardown.
fn run_mcounter_set_read
(
    session: &mut BringupSession,
    counter: MCounterIdx,
)
    -> Result<(), u32>
{
    // Step 2: initialize the counter to 5.
    if let Err(e) = session.mcounter_init(counter, MCOUNTER_INIT_VALUE)
    {
        return Err(err_word(STEP_MCOUNTER_INIT, e));
    }

    // Step 3: read the counter and expect exactly the init value.
    match session.mcounter_get(counter)
    {
        Ok(v) if v == MCOUNTER_INIT_VALUE => {}
        Ok(_) => return Err(err_word_code(STEP_MCOUNTER_GET, SPR_MCOUNTER_MISMATCH)),
        Err(e) => return Err(err_word(STEP_MCOUNTER_GET, e)),
    }

    // Step 4: decrement the counter, then expect one less than the init value.
    if let Err(e) = session.mcounter_update(counter)
    {
        return Err(err_word(STEP_MCOUNTER_UPDATE, e));
    }
    match session.mcounter_get(counter)
    {
        Ok(v) if v == MCOUNTER_INIT_VALUE - 1 => {}
        Ok(_) => return Err(err_word_code(STEP_MCOUNTER_UPDATE, SPR_MCOUNTER_MISMATCH)),
        Err(e) => return Err(err_word(STEP_MCOUNTER_UPDATE, e)),
    }

    // Step 5: RE-INIT proof. Init to a HIGHER value and read it back. An upward
    // re-init succeeding proves the counter is fully resettable, not a one-shot
    // latch.
    if let Err(e) = session.mcounter_init(counter, MCOUNTER_REINIT_VALUE)
    {
        return Err(err_word(STEP_MCOUNTER_REINIT, e));
    }
    match session.mcounter_get(counter)
    {
        Ok(v) if v == MCOUNTER_REINIT_VALUE => {}
        Ok(_) => return Err(err_word_code(STEP_MCOUNTER_REINIT, SPR_MCOUNTER_MISMATCH)),
        Err(e) => return Err(err_word(STEP_MCOUNTER_REINIT, e)),
    }
    Ok(())
}

/// Step 6: the counter at-zero boundary behaviour.
///
/// Init to 1, decrement to 0, confirm the read is 0, then a decrement at zero
/// must report the under-run (UpdateErr) and keep the session live. Returns the
/// packed error word on any fault and never tears the session down.
fn run_mcounter_zero_boundary
(
    session: &mut BringupSession,
    counter: MCounterIdx,
)
    -> Result<(), u32>
{
    if let Err(e) = session.mcounter_init(counter, 1)
    {
        return Err(err_word(STEP_MCOUNTER_ZERO, e));
    }
    if let Err(e) = session.mcounter_update(counter)
    {
        // A decrement from one to zero must succeed. A failure here is a genuine
        // fault, surfaced as its own error.
        return Err(err_word(STEP_MCOUNTER_ZERO, e));
    }
    match session.mcounter_get(counter)
    {
        Ok(0) => {}
        Ok(_) => return Err(err_word_code(STEP_MCOUNTER_ZERO, SPR_ZERO_BOUNDARY)),
        Err(e) => return Err(err_word(STEP_MCOUNTER_ZERO, e)),
    }
    match session.mcounter_update(counter)
    {
        // The documented at-zero under-run: a decrement below zero is refused with
        // UpdateErr and the session stays live.
        Err(SeError::L3(L3Error::Result(L3Status::UpdateErr))) => {}
        // Any other Err is a genuine fault, surfaced as itself.
        Err(e) => return Err(err_word(STEP_MCOUNTER_ZERO, e)),
        // A decrement at zero must not succeed.
        Ok(()) => return Err(err_word_code(STEP_MCOUNTER_ZERO, SPR_ZERO_BOUNDARY)),
    }
    Ok(())
}

/// Step 7: MAC-and-Destroy repeatability on the slot.
///
/// Two identical minimal cycles (initialize, measure) must return identical
/// measure outputs, proving the destroy is undone by re-initialization. The
/// init-call outputs are ignored, only the two measure outputs are compared.
/// Returns the packed error word on any fault and never tears the session down.
fn run_macdestroy_repeatability
(
    session: &mut BringupSession,
    mac_slot: MacDestroySlot,
)
    -> Result<(), u32>
{
    // Cycle one: initialize, then measure.
    if let Err(e) = session.mac_and_destroy(mac_slot, &MAC_INPUT_INIT)
    {
        return Err(err_word(STEP_MACDESTROY, e));
    }
    let measure_one = match session.mac_and_destroy(mac_slot, &MAC_INPUT_MEASURE)
    {
        Ok(out) => out,
        Err(e) => return Err(err_word(STEP_MACDESTROY, e)),
    };
    // Cycle two: re-initialize the destroyed slot, then measure again.
    if let Err(e) = session.mac_and_destroy(mac_slot, &MAC_INPUT_INIT)
    {
        return Err(err_word(STEP_MACDESTROY, e));
    }
    let measure_two = match session.mac_and_destroy(mac_slot, &MAC_INPUT_MEASURE)
    {
        Ok(out) => out,
        Err(e) => return Err(err_word(STEP_MACDESTROY, e)),
    };
    if measure_one.expose() != measure_two.expose()
    {
        return Err(err_word_code(STEP_MACDESTROY, SPR_MACDESTROY_MISMATCH));
    }
    Ok(())
}

/// Steps 8..13: the imported-Ed25519 known-answer test through ECC_Key_Store.
///
/// Pre-clean, import the RFC 8032 seed, check the pubkey KAT, sign and host-verify,
/// checked erase, then a post-erase sign that must fail. On a fault after import
/// the slot is erased best-effort before returning, so the erase-before-teardown
/// order holds once the caller tears down. Never tears the session down itself.
fn run_ecc_store_kat
(
    session: &mut BringupSession,
    ecc_slot: EccSlot,
)
    -> Result<(), u32>
{
    // Step 8: best-effort pre-clean erase, result IGNORED.
    let _ = session.ecc_key_erase(ecc_slot);

    // Step 9: import the RFC 8032 seed with ECC_Key_Store. On error erase
    // best-effort (the slot may hold a partial key) then return.
    let seed = Zeroizing::new(ED25519_SEED);
    if let Err(e) = session.ecc_key_store(ecc_slot, EccCurve::Ed25519, &seed)
    {
        let _ = session.ecc_key_erase(ecc_slot);
        return Err(err_word(STEP_ECC_STORE, e));
    }

    // Step 10: read the public key and check it against the RFC 8032 known answer.
    let pubkey = match session.ecc_public_key(ecc_slot)
    {
        Ok(key) => key,
        Err(e) =>
        {
            let _ = session.ecc_key_erase(ecc_slot);
            return Err(err_word(STEP_ECC_PUBKEY, e));
        }
    };
    if pubkey.bytes() != ED25519_EXPECTED_PUBKEY.as_slice()
    {
        let _ = session.ecc_key_erase(ecc_slot);
        return Err(err_word_code(STEP_ECC_PUBKEY, SPR_PUBKEY_KAT));
    }
    let mut pub_bytes = [0u8; 32];
    pub_bytes.copy_from_slice(pubkey.bytes());

    // Step 11: sign MESSAGE with the imported key, then host-verify.
    let sig = match session.eddsa_sign(ecc_slot, MESSAGE)
    {
        Ok(sig) => sig,
        Err(e) =>
        {
            let _ = session.ecc_key_erase(ecc_slot);
            return Err(err_word(STEP_ECC_SIGN, e));
        }
    };
    if !eddsa_verify_host(&pub_bytes, &sig.0)
    {
        let _ = session.ecc_key_erase(ecc_slot);
        return Err(err_word_code(STEP_ECC_SIGN, SPR_EDDSA_REJECT));
    }

    // Step 12: checked erase of the imported key.
    if let Err(e) = session.ecc_key_erase(ecc_slot)
    {
        return Err(err_word(STEP_ECC_ERASE, e));
    }

    // Step 13: a post-erase sign MUST fail. ANY Err is accepted as the expected
    // outcome and only an unexpected Ok is a fault. This proves the erase removed
    // the key.
    match session.eddsa_sign(ecc_slot, MESSAGE)
    {
        Err(_) => {}
        Ok(_) => return Err(err_word_code(STEP_POST_ERASE, SPR_POST_ERASE_SIGN)),
    }
    Ok(())
}

/// Runs steps 2..13 under the open session, in order.
///
/// Returns the packed error word at the first failing step and never tears the
/// session down. The caller owns the single teardown, so a helper that erased a
/// slot before returning keeps the erase-before-teardown order.
fn run_persist_under_session
(
    session: &mut BringupSession,
    counter: MCounterIdx,
    mac_slot: MacDestroySlot,
    ecc_slot: EccSlot,
)
    -> Result<(), u32>
{
    run_mcounter_set_read(session, counter)?;
    run_mcounter_zero_boundary(session, counter)?;
    run_macdestroy_repeatability(session, mac_slot)?;
    run_ecc_store_kat(session, ecc_slot)?;
    Ok(())
}

/// Runs the persistent-but-reversible state bring-up and returns a packed status
/// word.
///
/// Drives the flow step by step so the returned word names WHICH step failed:
///   1. read STPUB and open the Noise KK1 session on slot 0,
///   2. init the counter to 5,
///   3. read it and expect 5,
///   4. decrement it and expect 4,
///   5. upward re-init to 10 and expect 10 (proves the counter is resettable),
///   6. at-zero boundary: init to 1, decrement (Ok, now 0), then a decrement at
///      zero must report the under-run and leave the value at zero,
///   7. MAC-and-Destroy repeatability: two identical cycles on the slot must
///      produce identical outputs (proves the slot fully re-initializes),
///   8. best-effort pre-clean erase of the ECC slot (result ignored),
///   9. import the RFC 8032 Ed25519 seed with ECC_Key_Store,
///  10. read the public key and check it equals the RFC 8032 known answer,
///  11. sign MESSAGE and host-verify the signature under the read pubkey,
///  12. erase the imported key (checked),
///  13. a post-erase sign that MUST fail,
///  14. chip-notifying teardown.
///
/// The chip must already be in Application FW mode (the L3 channel lives there).
///
/// On any [`SeError`] returns [`err_word`]. On a value, determinism, or verify
/// surprise returns [`err_word_code`] with the matching RESERVED code. On success
/// returns `SPR_OK | SPR_OK_MARKER`. If a session is open when a step fails, it is
/// torn down before returning.
///
/// SAFETY OF SCOPE: every command here is reversible. The counters re-init at
/// will, the MAC-and-Destroy slot re-initializes, the ECC slot is erased at the
/// end. Nothing writes OTP, config, or a pairing key.
///
/// This is the non-secure-callable entry the persist veneer forwards to.
// QUARANTINE: the stable C export name needs `#[unsafe(no_mangle)]`.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn patinakey_se_persist() -> u32
{
    let counter = match MCounterIdx::new(MCOUNTER_IDX)
    {
        Ok(idx) => idx,
        Err(e) => return err_word(STEP_OPEN_SESSION, e),
    };
    let mac_slot = match MacDestroySlot::new(MAC_DESTROY_SLOT)
    {
        Ok(slot) => slot,
        Err(e) => return err_word(STEP_OPEN_SESSION, e),
    };
    let ecc_slot = match EccSlot::new(ECC_SLOT)
    {
        Ok(slot) => slot,
        Err(e) => return err_word(STEP_OPEN_SESSION, e),
    };

    let mut dev = build_device();

    // Step 1: read STPUB from the chip certificate, then open the Noise KK1
    // session on slot 0 via the shared helper (the same prod0 SH0 keys and fixed
    // ephemeral every bring-up path uses). On a read error the chip is
    // untouched, so no teardown is owed. On an open error the helper returns the
    // NoSession handle plus the error, both dropped here.
    let mut scratch = [0u8; CERT_SCRATCH_LEN];
    let stpub = match dev.read_chip_stpub(&mut scratch)
    {
        Ok(stpub) => stpub,
        Err(e) => return err_word(STEP_OPEN_SESSION, e),
    };
    let mut session = match open_bringup_session(dev, &stpub)
    {
        Ok(session) => session,
        Err((_dev, e)) => return err_word(STEP_OPEN_SESSION, e),
    };

    // Steps 2..13 run under the open session. On a failure the session is torn
    // down and the returned word is surfaced, matching the original per-step
    // teardown.
    match run_persist_under_session(&mut session, counter, mac_slot, ecc_slot)
    {
        Err(word) =>
        {
            let (_dev, _ack) = session.abort_session();
            word
        }
        Ok(()) =>
        {
            // Step 14: chip-notifying teardown.
            let (_dev, ack) = session.abort_session();
            match ack
            {
                Ok(()) => SPR_OK | SPR_OK_MARKER,
                Err(e) => err_word(STEP_SESSION_ABORT, e),
            }
        }
    }
}
