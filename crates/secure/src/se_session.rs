//! Secure-world TROPIC01 L3 secure-channel bring-up, exported to the NSC veneer.
//!
//! Proves the full L3 secure channel on silicon: read STPUB from the chip
//! certificate, open a Noise KK1 session against pairing slot 0, run one
//! encrypted L3 Ping round trip with an echo compare, then tear down with the
//! chip-notifying abort. It is the secure side of the
//! `patinakey_nsc_se_session_ping` non-secure-callable veneer: the non-secure
//! world calls the veneer, the veneer forwards here, this code drives the L3
//! flow, packs the outcome into a `u32`, and returns.
//!
//! FEATURE-GATED: the whole module compiles ONLY under the `se-session` cargo
//! feature. With the feature off the product firmware is byte-unchanged and never
//! references this path.
//!
//! BRING-UP ONLY: this path uses a FIXED ephemeral key and the PUBLIC factory
//! slot-0 pairing key. It is a silicon test, never a product build. The security
//! caveats live on the constants below.
//!
//! QUARANTINE: the `extern "C"` entry needs `#[unsafe(no_mangle)]` so the C
//! veneer in csrc/secure_nsc.c can resolve it by its C ABI name.

use tropic01_driver::ActiveSession;
use tropic01_driver::NoSession;
use tropic01_driver::SeError;
use tropic01_driver::SessionConfig;
use tropic01_driver::Tropic01;
use zeroize::Zeroizing;

use mcu_spi::MmioSpiBus;
use mcu_spi::Spi1Device;
use mcu_spi::SysTickWait;
use platform::MmioBus;

use crate::se_smoke::build_device;
use crate::se_smoke::se_error_code;

/// SH0 private key of the factory slot-0 pairing pair for production parts.
///
/// One of the libtropic SDK default production SH0 pairing keys (public
/// constants). These are the PUBLIC default keys shipped with the SDK, NOT
/// secrets. They let a bring-up test open a session against a factory-default
/// slot 0 before any provisioning writes a real pairing key.
///
/// Shared with the persistent-state and read-only paths through
/// [`open_bringup_session`] so every bring-up opens with identical keys.
pub(crate) const SH0_PRIV: [u8; 32] =
[
    0x28, 0x3f, 0x5a, 0x0f, 0xfc, 0x41, 0xcf, 0x50,
    0x98, 0xa8, 0xe1, 0x7d, 0xb6, 0x37, 0x2c, 0x3c,
    0xaa, 0xd1, 0xee, 0xee, 0xdf, 0x0f, 0x75, 0xbc,
    0x3f, 0xbf, 0xcd, 0x9c, 0xab, 0x3d, 0xe9, 0x72,
];

/// SH0 public key of the factory slot-0 pairing pair for production parts.
///
/// One of the libtropic SDK default production SH0 pairing keys (public
/// constants). The matching public half of [`SH0_PRIV`]. It is the `S_HiPub`
/// the chip authenticates the handshake against in slot 0.
pub(crate) const SH0_PUB: [u8; 32] =
[
    0xf9, 0x75, 0xeb, 0x3c, 0x2f, 0xd7, 0x90, 0xc9,
    0x6f, 0x29, 0x4f, 0x15, 0x57, 0xa5, 0x03, 0x17,
    0x80, 0xc9, 0xaa, 0xfa, 0x14, 0x0d, 0xa2, 0x8f,
    0x55, 0xe7, 0x51, 0x57, 0x37, 0xb2, 0x50, 0x2c,
];

/// Fixed host ephemeral X25519 private key, BRING-UP ONLY.
///
/// A clearly-arbitrary non-zero pattern. The secure world has no TRNG driver
/// yet, so this test cannot draw a fresh ephemeral. 
/// PRODUCTION session opening MUST draw the ephemeral from a real TRNG.
/// This module is bring-up only and never enters the product build.
///
/// Shared with the persistent-state and read-only paths through
/// [`open_bringup_session`].
pub(crate) const EPHEMERAL_PRIV: [u8; 32] =
[
    0xa5, 0x5a, 0xa5, 0x5a, 0xa5, 0x5a, 0xa5, 0x5a,
    0xa5, 0x5a, 0xa5, 0x5a, 0xa5, 0x5a, 0xa5, 0x5a,
    0xa5, 0x5a, 0xa5, 0x5a, 0xa5, 0x5a, 0xa5, 0x5a,
    0xa5, 0x5a, 0xa5, 0x5a, 0xa5, 0x5a, 0xa5, 0x5a,
];

/// Fixed Ping payload used for the echo compare.
const PING_PAYLOAD: &[u8] = b"patinakey L3 ping";

/// Stack scratch buffer length for the X.509 cert-store read.
///
/// The store is 30 blocks of 128 bytes = 3840 bytes. `read_chip_stpub` requires
/// the full store buffer up front. STPUB is returned by value, so the buffer is
/// not retained after the read.
///
/// Shared with the persistent-state and read-only paths, which read STPUB into a
/// scratch of the same size.
pub(crate) const CERT_SCRATCH_LEN: usize = 3840;

// Status-word encoding.
//
// CROSS-CRATE COUPLING: SES_OK / SES_ERR / the step codes / SES_OK_MARKER MUST
// match the encoding decoded on the non-secure side
// (crates/nonsecure/src/main.rs). The two crates do not share a type, so the bit
// layout is duplicated by hand and the two copies must stay in sync.
//
// Layout:
//   bit 31    SES_ERR : the L3 bring-up failed.
//   bit 8     SES_OK  : the L3 bring-up succeeded.
//   bits 15..8 (on ERR) step code: which step failed (1..=4).
//   bits 7..0  (on ERR) the SeError code (se_error_code, shared with se_smoke),
//                       or SES_ECHO_MISMATCH on a good L3 reply that did not echo.
//   bits 7..0  (on OK)  SES_OK_MARKER: a fixed pattern the NS logs as "L3 session
//                       + Ping OK".
// An error word can also set bit 8 incidentally (an odd step shifts a 1 into bit
// 8 via step << 8). SES_ERR (bit 31) is the discriminator: the NS tests SES_ERR
// FIRST, so an error word with bit 8 set is read as an error.

/// Status bit: the L3 bring-up succeeded.
const SES_OK: u32 = 1 << 8;
/// Status bit: the L3 bring-up failed. Bits 15..8 then carry the step, bits 7..0
/// the [`SeError`] code (or [`SES_ECHO_MISMATCH`]).
const SES_ERR: u32 = 1 << 31;

/// Low-byte marker returned on success. The non-secure side logs it as "L3
/// session + Ping OK". The value numerically equals the `se_error_code` byte
/// for `BufferTooSmall`, the marker appears only with bit 31
/// clear, error codes only with bit 31 set.
const SES_OK_MARKER: u32 = 0x51;

/// Low-byte code for an echo mismatch: the L3 Ping returned OK but the echoed
/// bytes or length did not match the payload. This is NOT an [`SeError`], so it
/// gets its own RESERVED code that no `se_error_code` value uses.
const SES_ECHO_MISMATCH: u32 = 0xF0;

/// Step code: reading STPUB from the chip certificate failed.
const STEP_READ_STPUB: u32 = 0x01;
/// Step code: opening the Noise KK1 session failed (handshake or transport).
const STEP_OPEN_SESSION: u32 = 0x02;
/// Step code: the encrypted L3 Ping failed, or its echo did not match.
const STEP_PING: u32 = 0x03;
/// Step code: the chip-notifying session abort was not acknowledged.
const STEP_SESSION_ABORT: u32 = 0x04;

/// Packs a failing step and an [`SeError`] into the error status word.
///
/// `SES_ERR | (step << 8) | error_code`. The step lives in bits 15..8, the error
/// code in the low byte, so the non-secure log names both the failing step and
/// the fault.
fn err_word(step: u32, err: SeError) -> u32
{
    SES_ERR | (step << 8) | se_error_code(err)
}

/// Packs a failing step and a RESERVED low-byte code into the error status word.
///
/// Used for the echo-mismatch case, which is not an [`SeError`]. Same layout as
/// [`err_word`] but with a caller-supplied low byte.
fn err_word_code(step: u32, code: u32) -> u32
{
    SES_ERR | (step << 8) | (code & 0xFF)
}

/// The bring-up device handle with no session open (over the real SPI1).
pub(crate) type BringupNoSession =
    Tropic01<Spi1Device<MmioSpiBus>, SysTickWait<MmioBus>, NoSession>;
/// The bring-up device handle with an active L3 session (over the real SPI1).
pub(crate) type BringupSession =
    Tropic01<Spi1Device<MmioSpiBus>, SysTickWait<MmioBus>, ActiveSession>;

/// Opens the Noise KK1 bring-up session against slot 0 on a supplied STPUB.
///
/// Shared by every bring-up path so they open with identical parameters:
/// the PUBLIC prod0 SH0 pairing key pair and the fixed bring-up ephemeral.
/// `stpub` is the chip static public key the caller read from the cert store.
/// The private keys are wrapped in `Zeroizing` as `SessionConfig` requires and
/// dropped when this returns.
///
/// On success returns the active-session handle. On failure returns the
/// `NoSession` handle plus the [`SeError`], both moved back to the caller.
#[expect(
    clippy::result_large_err,
    reason = "the handle is a large static singleton moved by value through the \
              type-state transition, mirroring open_session. Returning it on the \
              error path lets the caller keep it, and boxing is impossible under \
              no_std/no heap."
)]
pub(crate) fn open_bringup_session
(
    dev: BringupNoSession,
    stpub: &[u8; 32],
)
-> Result<BringupSession, (BringupNoSession, SeError)>
{
    let ehpriv = Zeroizing::new(EPHEMERAL_PRIV);
    let shipriv = Zeroizing::new(SH0_PRIV);
    let cfg = SessionConfig
    {
        ehpriv: &ehpriv,
        shipriv: &shipriv,
        shipub: &SH0_PUB,
        stpub,
        pkey_index: 0,
    };
    dev.open_session(cfg)
}

/// Runs the L3 secure-channel bring-up and returns a packed status word.
///
/// Drives the driver's own L3 primitives step by step so the returned word names
/// which step failed:
///   1. `read_chip_stpub` (walks the cert store for the chip static public key),
///   2. `open_session` (the Noise KK1 handshake against slot 0),
///   3. `ping_into` (one encrypted L3 Ping) plus an echo compare,
///   4. `abort_session` (the chip-notifying teardown).
///
/// The chip must already be in Application FW mode (the L3 channel lives there).
/// This path issues no reboot, mirroring the smoke path's "chip is already up"
/// assumption.
///
/// On any [`SeError`] returns [`err_word`] (bit 31 set, the step in bits 15..8,
/// the error code in the low byte). On an echo mismatch returns [`err_word_code`]
/// at step 3 with [`SES_ECHO_MISMATCH`]. On success returns `SES_OK |
/// SES_OK_MARKER`.
///
/// SECRETS: the session secrets are wiped by `abort_session` before its notify
/// round-trip, so a step-4 error still leaves no live
/// session key. The private keys handed to `open_session` are wrapped in
/// `Zeroizing` and dropped at the end of this call.
///
/// This is the non-secure-callable entry the session veneer forwards to.
// QUARANTINE: the stable C export name needs `#[unsafe(no_mangle)]`.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn patinakey_se_session_ping() -> u32
{
    let mut dev = build_device();

    // Step 1: read STPUB from the chip certificate. The 3840-byte scratch holds
    // the whole cert store. On error the chip is untouched, so no teardown is owed.
    let mut scratch = [0u8; CERT_SCRATCH_LEN];
    let stpub = match dev.read_chip_stpub(&mut scratch)
    {
        Ok(stpub) => stpub,
        Err(e) => return err_word(STEP_READ_STPUB, e),
    };

    // Step 2: open the Noise KK1 session against slot 0 via the shared helper
    // (the same prod0 SH0 keys and fixed ephemeral every bring-up path uses). On
    // error open_bringup_session returns the NoSession handle plus the error,
    // both dropped here.
    let mut session = match open_bringup_session(dev, &stpub)
    {
        Ok(session) => session,
        Err((_dev, e)) => return err_word(STEP_OPEN_SESSION, e),
    };

    // Step 3: one encrypted L3 Ping, then compare the echo byte for byte.
    // `ping_into` returns Ok only with the full payload length (a wrong-length
    // echo surfaces as an SeError), so the length check below is pure defense
    // and the reachable mismatch case is a byte mismatch. Reported as a
    // RESERVED code (not an SeError). The session still tears down below.
    let mut echo = [0u8; PING_PAYLOAD.len()];
    let ping_result = session.ping_into(PING_PAYLOAD, &mut echo);
    let echo_ok = match ping_result
    {
        Ok(n) => n == PING_PAYLOAD.len() && echo == *PING_PAYLOAD,
        Err(e) =>
        {
            // A transport or crypto fault on the Ping. Tear the session down
            // before returning so the chip forgets it too.
            let (_dev, _ack) = session.abort_session();
            return err_word(STEP_PING, e);
        }
    };

    // Step 4: chip-notifying teardown. The driver wipes the session secrets
    // before the notify, so the ack Result only reports whether the chip
    // acknowledged.
    let (_dev, ack) = session.abort_session();

    if !echo_ok
    {
        // The Ping succeeded at L3 but did not echo the payload. Report it at
        // step 3 after the teardown, so the session is already down.
        return err_word_code(STEP_PING, SES_ECHO_MISMATCH);
    }
    match ack
    {
        Ok(()) => SES_OK | SES_OK_MARKER,
        Err(e) => err_word(STEP_SESSION_ABORT, e),
    }
}
