//! Secure side of the `patinakey_nsc_se_readonly` NSC veneer.
//!
//! An on-silicon self-test that drives the TROPIC01 commands which read chip state
//! or touch only reversible state, and exports the bytes a host needs to check an
//! SE-produced ECDSA P-256 signature. Under an L3 session on factory pairing slot
//! 0 it reads the chip id, reads the four pairing key slots, dumps the R-Config and
//! I-Config objects, reads a high user R-Memory slot and erases it, then generates
//! a P-256 key, signs a fixed digest, and erases the key. The chip id, the pairing
//! and P-256 public keys, the signature, and the digest go into the shared output
//! window (below) for the non-secure side to log and a host tool to verify.
//!
//! The flow issues no pairing, config, or R-Memory write and no one-time command.
//! Its only mutation is erasing one R-Memory slot that is already empty, so a run
//! leaves the chip in its prior state.
//!
//! FEATURE-GATED: compiles only under the `se-session` feature. The default product
//! build never references this module and is byte-identical without the feature.
//!
//! TEST KEYS: the public factory slot-0 pairing key and a fixed X25519 ephemeral,
//! both reused from se_session.rs. This is a test path, not a product build.
//!
//! SHARED OUTPUT WINDOW: the status `u32` cannot carry the exported record, so the
//! veneer writes it to a fixed compile-time address, the pinned shared non-secure
//! output window ([`SHARED_OUT_ADDR`], [`SHARED_OUT_LEN`]).
//! The length is the compile-time [`RECORD_LEN`], static-asserted to fit the
//! window, and the secure MPU maps exactly that window RW + XN
//! (crates/platform/src/map.rs, 4th region), so a write outside it faults instead
//! of corrupting memory. Only public bytes are written, never a secret or session
//! key.
//!
//! QUARANTINE: the `extern "C"` entry needs `#[unsafe(no_mangle)]` so the C veneer
//! in csrc/secure_nsc.c can resolve it by its C ABI name.

use tropic01_driver::ConfigObjectAddr;
use tropic01_driver::EccCurve;
use tropic01_driver::EccSlot;
use tropic01_driver::L3Error;
use tropic01_driver::L3Status;
use tropic01_driver::PairingKeySlot;
use tropic01_driver::RMemSlot;
use tropic01_driver::SeCommands;
use tropic01_driver::SeError;

use crate::se_session::open_bringup_session;
use crate::se_session::CERT_SCRATCH_LEN;
use crate::se_session::SH0_PUB;
use crate::se_smoke::build_device;
use crate::se_smoke::se_error_code;

/// ECC slot for the P-256 test key.
///
/// 28 keeps this key off slots 29 (se_persist.rs) and 30, 31 (se_crypto.rs), so
/// the feature-gated tests never share an ECC slot.
const P256_SLOT: u8 = 28;

/// High user R-Memory slot read then erased.
///
/// 511 is the top user slot. This test never writes R-Memory, so the slot stays
/// empty and the erase is a no-op on empty flash. Erase is the only mutation in
/// the flow, reversible R-Memory, the reset
/// primitive libtropic's own tests use.
const RMEM_SLOT: u16 = 511;

/// Scratch length for the R-Memory read.
///
/// `rmem_read_into` requires a buffer of at least the driver's protocol maximum
/// (475 bytes at the current target firmware) up front, else it returns
/// `BufferTooSmall`. 512 covers that with headroom for a future firmware cap. The
/// slot is expected empty, so no bytes are actually returned.
const RMEM_READ_BUF: usize = 512;

/// Fixed 32-byte digest signed by the P-256 (ECDSA) path.
///
/// An arbitrary byte pattern, the same one se_crypto.rs uses. The chip
/// signs a caller-supplied digest (the host pre-hashes with SHA-256 in
/// production), so any fixed 32 bytes prove the command round trip. The host
/// verifier re-checks the exported signature over exactly these bytes.
const DIGEST: [u8; 32] =
[
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

/// Number of named configuration objects dumped for R-Config and I-Config.
const CONFIG_OBJECT_COUNT: usize = 27;

/// Every named configuration object, dumped in this fixed order for both
/// R-Config and I-Config.
///
/// The order defines the record byte layout, so the host reads object `i` at the
/// documented offset. It matches the whole [`ConfigObjectAddr`] whitelist.
const CONFIG_OBJECTS: [ConfigObjectAddr; CONFIG_OBJECT_COUNT] =
[
    ConfigObjectAddr::CfgStartUp,
    ConfigObjectAddr::CfgSensors,
    ConfigObjectAddr::CfgDebug,
    ConfigObjectAddr::CfgGpo,
    ConfigObjectAddr::CfgSleepMode,
    ConfigObjectAddr::CfgUapPairingKeyWrite,
    ConfigObjectAddr::CfgUapPairingKeyRead,
    ConfigObjectAddr::CfgUapPairingKeyInvalidate,
    ConfigObjectAddr::CfgUapRConfigWriteErase,
    ConfigObjectAddr::CfgUapRConfigRead,
    ConfigObjectAddr::CfgUapIConfigWrite,
    ConfigObjectAddr::CfgUapIConfigRead,
    ConfigObjectAddr::CfgUapPing,
    ConfigObjectAddr::CfgUapRMemDataWrite,
    ConfigObjectAddr::CfgUapRMemDataRead,
    ConfigObjectAddr::CfgUapRMemDataErase,
    ConfigObjectAddr::CfgUapRandomValueGet,
    ConfigObjectAddr::CfgUapEccKeyGenerate,
    ConfigObjectAddr::CfgUapEccKeyStore,
    ConfigObjectAddr::CfgUapEccKeyRead,
    ConfigObjectAddr::CfgUapEccKeyErase,
    ConfigObjectAddr::CfgUapEcdsaSign,
    ConfigObjectAddr::CfgUapEddsaSign,
    ConfigObjectAddr::CfgUapMcounterInit,
    ConfigObjectAddr::CfgUapMcounterGet,
    ConfigObjectAddr::CfgUapMcounterUpdate,
    ConfigObjectAddr::CfgUapMacAndDestroy,
];

// Exported-record byte layout (documented offsets, all lengths fixed).
//
// The non-secure side logs each field over RTT so the operator pipes the P-256
// fields to the host verifier. Every byte is PUBLIC.
//
//   [  0 ..   4)  MAGIC "PK54" (0x50 0x4B 0x35 0x34), a sanity tag.
//   [  4 .. 132)  chip id (128 bytes, the Get_Info CHIP_ID block).
//   [132 .. 164)  pairing slot 0 public key (32 bytes, S_HiPub).
//   [164 .. 228)  P-256 public key, raw X || Y (64 bytes, no 0x04 prefix).
//   [228 .. 292)  P-256 ECDSA signature, r || s (64 bytes).
//   [292 .. 324)  the signed digest (32 bytes).
//   [324 .. 432)  R-Config dump: 27 objects, each a u32 little-endian (108 bytes).
//   [432 .. 540)  I-Config dump: 27 objects, each a u32 little-endian (108 bytes).
//
// RECORD_LEN is the total written length, static-asserted to fit SHARED_OUT_LEN.

/// Record field offset: the magic tag.
const OFF_MAGIC: usize = 0;
/// Record field offset: the chip id.
const OFF_CHIP_ID: usize = 4;
/// Record field offset: the pairing slot 0 public key.
const OFF_PAIRING0: usize = 132;
/// Record field offset: the P-256 public key.
const OFF_P256_PUB: usize = 164;
/// Record field offset: the P-256 signature.
const OFF_P256_SIG: usize = 228;
/// Record field offset: the signed digest.
const OFF_DIGEST: usize = 292;
/// Record field offset: the R-Config dump.
const OFF_R_CONFIG: usize = 324;
/// Record field offset: the I-Config dump.
const OFF_I_CONFIG: usize = 432;
/// Total record length, static-asserted to fit the pinned shared window.
const RECORD_LEN: usize = 540;

/// The four-byte record magic tag ("PK54").
const RECORD_MAGIC: [u8; 4] = [0x50, 0x4B, 0x35, 0x34];

// Pinned shared non-secure OUTPUT window, the only memory this veneer writes.
//
// HAND-SYNCED PIN (exactly like the NSC sgstubs --section-start pin): these MUST
// match MPU_NS_SHARED_BASE / MPU_NS_SHARED_LIMIT in crates/platform/src/map.rs
// (the 4th secure MPU region, RW + XN) AND the SHARED_OUT MEMORY region +
// .shared_out section in crates/nonsecure/memory.x. The value is duplicated here
// by hand because the secure crate cannot see platform's pub(crate) map
// constants, and the three copies must stay in lock-step. Base 0x2002_FC00,
// length 0x400 (1 KiB), at the top of the non-secure SRAM half.

/// Pinned shared non-secure output window base (compile-time fixed write target).
const SHARED_OUT_ADDR: u32 = 0x2002_FC00;
/// Pinned shared non-secure output window length in bytes (1 KiB).
const SHARED_OUT_LEN: usize = 0x400;

// OVERFLOW GUARD: the record must fit inside the pinned window. RECORD_LEN and
// SHARED_OUT_LEN are both compile-time constants, so a record that outgrows the
// window fails the build here, never at runtime.
const _: () = assert!(RECORD_LEN <= SHARED_OUT_LEN);

// Status-word encoding.
//
// CROSS-CRATE COUPLING: RDO_OK / RDO_ERR / the step codes / RDO_OK_MARKER MUST
// match the encoding decoded on the non-secure side
// (crates/nonsecure/src/main.rs). The two crates do not share a type, so the bit
// layout is duplicated by hand and the two copies must stay in sync.
//
// Layout:
//   bit 31    RDO_ERR : the read-only sweep failed.
//   bit 8     RDO_OK  : the read-only sweep succeeded.
//   bits 15..8 (on ERR) step code: which step failed (1..=9, 0x01..=0x09).
//   bits 7..0  (on ERR) the SeError code (se_error_code, shared with se_smoke),
//                       or a RESERVED non-SeError code (0xFB..0xFE, see below).
//   bits 7..0  (on OK)  RDO_OK_MARKER: a fixed pattern the NS logs as "read-only
//                       sweep OK".
// An error word can also set bit 8 incidentally (an odd step shifts a 1 into bit
// 8 via step << 8). RDO_ERR (bit 31) is the discriminator: the NS tests RDO_ERR
// FIRST, so an error word with bit 8 set is read as an error.
//
// RESERVED non-SeError low-byte codes (secure-side, ONE place). These are NOT
// se_error_code values (which occupy 0x01..0x7F and 0xE1..0xE7), so they never
// collide with a real SeError code, nor with the 0xF0..0xFA codes the other three
// veneers use in their own status words:
//   0xFB  prod0 pairing pubkey mismatch (slot 0 pubkey != the embedded SH0_PUB).
//   0xFD  slot not empty                (a slot that had to be empty was not).
//   0xFE  length surprise               (a chip-id / pubkey read returned a wrong
//                                        length).

/// Status bit: the read-only sweep succeeded.
const RDO_OK: u32 = 1 << 8;
/// Status bit: the read-only sweep failed. Bits 15..8 then carry the step, bits
/// 7..0 the [`SeError`] code or a RESERVED code.
const RDO_ERR: u32 = 1 << 31;

/// Low-byte marker returned on success. The non-secure side logs it as "read-only
/// sweep OK". It appears only with bit 31 clear, error codes only with bit 31 set,
/// so there is no ambiguity.
const RDO_OK_MARKER: u32 = 0x54;

/// RESERVED code: pairing slot 0 read back a public key other than the embedded
/// prod0 [`SH0_PUB`]. Not an [`SeError`].
const RDO_PROD0_MISMATCH: u32 = 0xFB;
/// RESERVED code: a slot that had to be empty (pairing slot 1..3, or the high
/// R-Memory slot) held data. Not an [`SeError`].
const RDO_SLOT_NOT_EMPTY: u32 = 0xFD;
/// RESERVED code: a chip-id or public-key read returned an unexpected length. Not
/// an [`SeError`].
const RDO_LEN_SURPRISE: u32 = 0xFE;

/// Step code: read the chip id (no session needed).
const STEP_CHIP_ID: u32 = 0x01;
/// Step code: read STPUB then open the Noise KK1 session on slot 0.
const STEP_OPEN_SESSION: u32 = 0x02;
/// Step code: read the four pairing key slots.
const STEP_PAIRING: u32 = 0x03;
/// Step code: dump the R-Config objects.
const STEP_R_CONFIG: u32 = 0x04;
/// Step code: dump the I-Config objects.
const STEP_I_CONFIG: u32 = 0x05;
/// Step code: read the high R-Memory slot (expect empty).
const STEP_RMEM_READ: u32 = 0x06;
/// Step code: erase the high R-Memory slot (the one reversible mutation).
const STEP_RMEM_ERASE: u32 = 0x07;
/// Step code: the P-256 generate / sign / erase round trip.
const STEP_P256: u32 = 0x08;
/// Step code: the chip-notifying session abort.
const STEP_SESSION_ABORT: u32 = 0x09;

/// Packs a failing step and an [`SeError`] into the error status word.
///
/// `RDO_ERR | (step << 8) | error_code`. The step lives in bits 15..8, the error
/// code in the low byte, so the non-secure log names both the failing step and
/// the fault.
fn err_word(step: u32, err: SeError) -> u32
{
    RDO_ERR | (step << 8) | se_error_code(err)
}

/// Packs a failing step and a RESERVED low-byte code into the error status word.
///
/// Used for the non-[`SeError`] sanity codes (0xFB..0xFE). Same layout as
/// [`err_word`] but with a caller-supplied low byte.
fn err_word_code(step: u32, code: u32) -> u32
{
    RDO_ERR | (step << 8) | (code & 0xFF)
}

/// Runs the read-only sweep plus the P-256 export and returns a packed status
/// word.
///
/// Drives the flow step by step so the returned word names WHICH step failed:
///   1. read the chip id (no session),
///   2. read STPUB and open the Noise KK1 session on slot 0,
///   3. read pairing slot 0 (must equal the prod0 SH0 pubkey) and slots 1..3
///      (must be empty),
///   4. dump the R-Config objects,
///   5. dump the I-Config objects,
///   6. read the high R-Memory slot (must be empty),
///   7. erase the high R-Memory slot (the one reversible mutation),
///   8. generate a P-256 key, sign the fixed digest, export the pubkey /
///      signature / digest, erase the key (checked),
///   9. chip-notifying teardown, then write the record to the pinned shared
///      non-secure output window.
///
/// The chip must already be in Application FW mode (the L3 channel lives there).
///
/// On any [`SeError`] returns [`err_word`]. On a sanity failure returns
/// [`err_word_code`] with the matching RESERVED code. On success writes the record
/// to the pinned [`SHARED_OUT_ADDR`] window and returns `RDO_OK | RDO_OK_MARKER`.
/// If a session is open when a step fails, it is torn down before returning. On
/// success the record is written only after a clean teardown.
///
/// The write target is a COMPILE-TIME constant address, and the length is the
/// compile-time [`RECORD_LEN`] (static-asserted `<= SHARED_OUT_LEN`), so no
/// non-secure input can steer the write. The bytes written are PUBLIC (chip id,
/// pairing and ECC public keys, a signature, a digest, config dumps).
///
/// This is the non-secure-callable entry the read-only veneer forwards to. It
/// takes no argument and returns a scalar, matching the other three veneers.
// QUARANTINE: the stable C export name needs `#[unsafe(no_mangle)]`.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn patinakey_se_readonly() -> u32
{
    // The slot constructors take compile-time-constant slot numbers, so they
    // cannot fail at runtime, but the API is fallible: surface any error at the
    // step where the slot is first used.
    let p256_slot = match EccSlot::new(P256_SLOT)
    {
        Ok(slot) => slot,
        Err(e) => return err_word(STEP_P256, e),
    };
    let rmem_slot = match RMemSlot::new(RMEM_SLOT)
    {
        Ok(slot) => slot,
        Err(e) => return err_word(STEP_RMEM_READ, e),
    };

    // The record is assembled in this SECURE local and copied to the pinned shared
    // non-secure output window once, at the very end, only on the fully-successful
    // path.
    let mut record = [0u8; RECORD_LEN];
    record[OFF_MAGIC..OFF_MAGIC + RECORD_MAGIC.len()].copy_from_slice(&RECORD_MAGIC);

    let mut dev = build_device();

    // Step 1: read the 128-byte chip id (a no-session Get_Info block). On error the
    // chip has no session, so no teardown is owed.
    let mut chip_id = [0u8; 128];
    match dev.chip_id_into(&mut chip_id)
    {
        Ok(n) if n == chip_id.len() => {}
        Ok(_) => return err_word_code(STEP_CHIP_ID, RDO_LEN_SURPRISE),
        Err(e) => return err_word(STEP_CHIP_ID, e),
    }
    record[OFF_CHIP_ID..OFF_CHIP_ID + chip_id.len()].copy_from_slice(&chip_id);

    // Step 2: read STPUB then open the Noise KK1 session on slot 0 via the shared
    // helper (identical prod0 SH0 keys and fixed ephemeral as the other paths). On
    // a read or open error no session is live, so no teardown is owed.
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

    // Step 3: read pairing slot 0 and expect the embedded prod0 SH0 public key,
    // then read slots 1..3 and expect each to be empty (never provisioned).
    let slot0 = match PairingKeySlot::new(0)
    {
        Ok(slot) => slot,
        Err(e) =>
        {
            let (_dev, _ack) = session.abort_session();
            return err_word(STEP_PAIRING, e);
        }
    };
    match session.pairing_key_read(slot0)
    {
        Ok(key) =>
        {
            if key != SH0_PUB
            {
                let (_dev, _ack) = session.abort_session();
                return err_word_code(STEP_PAIRING, RDO_PROD0_MISMATCH);
            }
            record[OFF_PAIRING0..OFF_PAIRING0 + key.len()].copy_from_slice(&key);
        }
        Err(e) =>
        {
            let (_dev, _ack) = session.abort_session();
            return err_word(STEP_PAIRING, e);
        }
    }
    // Slots 1, 2, 3 must be empty. The chip reports an empty slot as a recoverable
    // SlotEmpty result, so that Err is the EXPECTED outcome and maps to success. An
    // Ok (the slot holds a key) is a surprise, and any other Err is a genuine
    // fault surfaced as itself.
    for raw_slot in 1u8..=3u8
    {
        let slot = match PairingKeySlot::new(raw_slot)
        {
            Ok(slot) => slot,
            Err(e) =>
            {
                let (_dev, _ack) = session.abort_session();
                return err_word(STEP_PAIRING, e);
            }
        };
        match session.pairing_key_read(slot)
        {
            Err(SeError::L3(L3Error::Result(L3Status::SlotEmpty))) => {}
            Ok(_) =>
            {
                let (_dev, _ack) = session.abort_session();
                return err_word_code(STEP_PAIRING, RDO_SLOT_NOT_EMPTY);
            }
            Err(e) =>
            {
                let (_dev, _ack) = session.abort_session();
                return err_word(STEP_PAIRING, e);
            }
        }
    }

    // Step 4: dump the R-Config objects (read only, never write or erase). Each
    // read returns a u32 stored little-endian at its fixed offset.
    for (i, addr) in CONFIG_OBJECTS.iter().enumerate()
    {
        match session.r_config_read(*addr)
        {
            Ok(value) =>
            {
                let off = OFF_R_CONFIG + i * 4;
                record[off..off + 4].copy_from_slice(&value.to_le_bytes());
            }
            Err(e) =>
            {
                let (_dev, _ack) = session.abort_session();
                return err_word(STEP_R_CONFIG, e);
            }
        }
    }

    // Step 5: dump the I-Config objects (read only, never write). Same layout as
    // the R-Config dump.
    for (i, addr) in CONFIG_OBJECTS.iter().enumerate()
    {
        match session.i_config_read(*addr)
        {
            Ok(value) =>
            {
                let off = OFF_I_CONFIG + i * 4;
                record[off..off + 4].copy_from_slice(&value.to_le_bytes());
            }
            Err(e) =>
            {
                let (_dev, _ack) = session.abort_session();
                return err_word(STEP_I_CONFIG, e);
            }
        }
    }

    // Step 6: read the high R-Memory slot and expect it empty. rmem_read_into
    // returns Ok(0) for an empty slot (a stored slot is never zero-length). Any
    // non-zero length is a surprise, any Err a genuine fault.
    let mut rmem_buf = [0u8; RMEM_READ_BUF];
    match session.rmem_read_into(rmem_slot, &mut rmem_buf)
    {
        Ok(0) => {}
        Ok(_) =>
        {
            let (_dev, _ack) = session.abort_session();
            return err_word_code(STEP_RMEM_READ, RDO_SLOT_NOT_EMPTY);
        }
        Err(e) =>
        {
            let (_dev, _ack) = session.abort_session();
            return err_word(STEP_RMEM_READ, e);
        }
    }

    // Step 7: erase the high R-Memory slot. This is the ONE mutation in the sweep,
    // reversible R-Memory on a guaranteed-empty slot (not in any errata brick
    // list), the same reset primitive libtropic's own tests use.
    if let Err(e) = session.rmem_erase(rmem_slot)
    {
        let (_dev, _ack) = session.abort_session();
        return err_word(STEP_RMEM_ERASE, e);
    }

    // Step 8: the P-256 (ECDSA) export. Best-effort pre-clean erase (result
    // ignored, the API is silent on erase-on-empty), generate, read the 64-byte
    // public key, sign the fixed digest, export all three, then checked erase.
    let _ = session.ecc_key_erase(p256_slot);
    if let Err(e) = session.ecc_key_generate(p256_slot, EccCurve::P256)
    {
        let _ = session.ecc_key_erase(p256_slot);
        let (_dev, _ack) = session.abort_session();
        return err_word(STEP_P256, e);
    }
    let pubkey = match session.ecc_public_key(p256_slot)
    {
        Ok(key) => key,
        Err(e) =>
        {
            let _ = session.ecc_key_erase(p256_slot);
            let (_dev, _ack) = session.abort_session();
            return err_word(STEP_P256, e);
        }
    };
    if pubkey.bytes().len() != 64
    {
        let _ = session.ecc_key_erase(p256_slot);
        let (_dev, _ack) = session.abort_session();
        return err_word_code(STEP_P256, RDO_LEN_SURPRISE);
    }
    record[OFF_P256_PUB..OFF_P256_PUB + 64].copy_from_slice(pubkey.bytes());

    let sig = match session.ecdsa_sign(p256_slot, &DIGEST)
    {
        Ok(sig) => sig,
        Err(e) =>
        {
            let _ = session.ecc_key_erase(p256_slot);
            let (_dev, _ack) = session.abort_session();
            return err_word(STEP_P256, e);
        }
    };
    record[OFF_P256_SIG..OFF_P256_SIG + 64].copy_from_slice(&sig.0);
    record[OFF_DIGEST..OFF_DIGEST + DIGEST.len()].copy_from_slice(&DIGEST);

    if let Err(e) = session.ecc_key_erase(p256_slot)
    {
        let (_dev, _ack) = session.abort_session();
        return err_word(STEP_P256, e);
    }

    // Step 9: chip-notifying teardown, then commit the record. The write happens
    // ONLY on this fully-successful path, so there is a single write site and a
    // failed teardown writes nothing.
    let (_dev, ack) = session.abort_session();
    if let Err(e) = ack
    {
        return err_word(STEP_SESSION_ABORT, e);
    }

    // SAFETY: SHARED_OUT_ADDR is a FIXED compile-time address, the base of the
    // pinned shared non-secure output window that the secure MPU maps RW + XN (the
    // 4th region in platform map.rs). RECORD_LEN <= SHARED_OUT_LEN is
    // static-asserted, so this copies exactly RECORD_LEN bytes inside that mapped
    // window and writes nothing outside it. No non-secure input influences the
    // address or the length, so there is no injection surface. The bytes are
    // PUBLIC (magic tag, chip id, pairing and ECC public keys, an ECDSA signature,
    // the signed digest, and the config dumps), never a secret or session key.
    unsafe
    {
        core::ptr::copy_nonoverlapping(
            record.as_ptr(),
            SHARED_OUT_ADDR as *mut u8,
            RECORD_LEN,
        );
    }

    RDO_OK | RDO_OK_MARKER
}
