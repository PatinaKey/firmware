//! The device handle and its type-state markers.
//!
//! `Tropic01<SPI, W, State>` owns the SPI port, the wait provider, and the
//! fixed L2/L3 buffers. The `State` type parameter encodes the session
//! lifecycle at compile time: L3 commands are reachable only on
//! `ActiveSession`, firmware update only on `Bootloader`.
//!
//! The handle is ~4.4 KiB and MUST live as a `static` singleton in the secure
//! binary, accessed by `&mut`. It must never sit on a call stack. A
//! size-regression test pins its footprint.
//!
//! This module wires the session lifecycle: `open_session` (Noise KK1),
//! `close_session`, and `ping_into`, a diagnostic round-trip that enforces the
//! session teardown gate. The `SeCommands` methods build on the same gate.

use embedded_hal::spi::SpiDevice;
use zeroize::Zeroize;
use zeroize::Zeroizing;

use crate::buf::L2Buf;
use crate::buf::L2_FRAME_MAX;
use crate::buf::L3Buf;
use crate::crypto;
use crate::error::L2Error;
use crate::error::L3Error;
use crate::error::SeError;
use crate::handshake;
use crate::error::ParseError;
use crate::ids::CmdId;
use crate::ids::L2ReqId;
use crate::ids::L2Status;
use crate::ids::L3Status;
use crate::l1;
use crate::l2::frame;
use crate::l3;
use crate::parse::take_array;
use crate::session::SessionKeys;
use crate::wait::SeWait;

/// State marker: no secure channel is open. Plain-L2 ops are available.
#[derive(Debug, Clone, Copy)]
pub struct NoSession;

/// State marker: a secure channel is open. L3 commands are available.
///
/// Holds the session keys (zeroized on drop) and a `poisoned` flag. On a
/// session-fatal error the command path zeroizes the keys and sets `poisoned`,
/// so every subsequent L3 call fast-fails with `SessionLost` without touching
/// the chip. Carries no `Debug`/`Clone`/`Copy` because it holds secrets.
pub struct ActiveSession
{
    keys: SessionKeys,
    poisoned: bool,
}

impl ActiveSession
{
    /// Wraps derived session keys into the active state.
    ///
    /// `pub(crate)`: only the handshake builds this. Starts un-poisoned.
    pub(crate) fn new(keys: SessionKeys) -> Self
    {
        ActiveSession
        {
            keys,
            poisoned: false,
        }
    }

    /// Reports whether this session has been torn down.
    pub(crate) fn is_poisoned(&self) -> bool
    {
        self.poisoned
    }

    /// Marks the session fatal and zeroizes the keys.
    ///
    /// Idempotent. After this, the session can only be closed and replaced.
    pub(crate) fn poison(&mut self)
    {
        self.keys.wipe();
        self.poisoned = true;
    }
}

/// State marker: the chip is in bootloader (start-up) mode for firmware update.
#[derive(Debug, Clone, Copy)]
pub struct Bootloader;

/// The TROPIC01 device handle.
///
/// Generic over the SPI device port and the wait provider, with a type-state
/// parameter for the session lifecycle. Owns the no-heap L2 and L3 buffers.
pub struct Tropic01<SPI, W, State = NoSession>
{
    spi: SPI,
    wait: W,
    l2: L2Buf,
    l3: L3Buf,
    state: State,
}

impl<SPI, W> Tropic01<SPI, W, NoSession>
where
    SPI: SpiDevice,
    W: SeWait,
{
    /// Creates a handle in the `NoSession` state.
    ///
    /// Takes ownership of the SPI port and the wait provider. Allocates the
    /// fixed L2/L3 buffers inline. Open a secure channel before any L3 command.
    pub fn new(spi: SPI, wait: W) -> Tropic01<SPI, W, NoSession>
    {
        Tropic01
        {
            spi,
            wait,
            l2: [0u8; L2_FRAME_MAX],
            l3: L3Buf::new(),
            state: NoSession,
        }
    }
}

/// Parameters for opening a Noise KK1 secure channel.
///
/// All key material is borrowed. The config owns no secrets. `ehpriv` is the
/// host ephemeral private (fresh per session, from the platform TRNG). The
/// driver derives the matching public key and sends it in the handshake.
pub struct SessionConfig<'a>
{
    /// Host ephemeral X25519 private key (fresh per session).
    pub ehpriv: &'a Zeroizing<[u8; 32]>,
    /// Host static pairing private key.
    pub shipriv: &'a Zeroizing<[u8; 32]>,
    /// Host static pairing public key.
    pub shipub: &'a [u8; 32],
    /// Chip static public key (from the device certificate).
    pub stpub: &'a [u8; 32],
    /// Pairing key slot index (0..=3).
    pub pkey_index: u8,
}

impl<SPI, W> Tropic01<SPI, W, NoSession>
where
    SPI: SpiDevice,
    W: SeWait,
{
    /// Opens a secure channel via the Noise KK1 handshake.
    ///
    /// Consumes the handle. On success returns an `ActiveSession` handle ready
    /// for L3 commands. On failure returns the `NoSession` handle plus the
    /// error, so the caller can retry without rebuilding the device.
    #[expect(
        clippy::result_large_err,
        reason = "the handle is a large static singleton moved by value through \
                  this type-state transition. Returning it on the error path lets \
                  the caller keep it, and boxing is impossible under no_std/no heap."
    )]
    pub fn open_session
    (
        self,
        cfg: SessionConfig<'_>,
    )
    -> Result<Tropic01<SPI, W, ActiveSession>, (Self, SeError)>
    {
        let ehpub = crypto::x25519_base(cfg.ehpriv);
        let Tropic01
        {
            mut spi,
            mut wait,
            mut l2,
            l3,
            state: _,
        } = self;
        match handshake_exchange(&mut spi, &mut wait, &mut l2, &cfg, &ehpub)
        {
            Ok(keys) => Ok(Tropic01
            {
                spi,
                wait,
                l2,
                l3,
                state: ActiveSession::new(keys),
            }),
            Err(e) =>
            {
                // Clear any handshake bytes left in the L2 buffer on failure.
                l2.zeroize();
                Err((
                    Tropic01
                    {
                        spi,
                        wait,
                        l2,
                        l3,
                        state: NoSession,
                    },
                    e,
                ))
            }
        }
    }
}

/// Sends the handshake request and derives the session keys from the response.
fn handshake_exchange<SPI, W>
(
    spi: &mut SPI,
    wait: &mut W,
    l2: &mut [u8],
    cfg: &SessionConfig<'_>,
    ehpub: &[u8; 32],
)
-> Result<SessionKeys, SeError>
where
    SPI: SpiDevice,
    W: SeWait,
{
    // Handshake_Req body = EHPUB(32) || PKEY_INDEX(1).
    let mut body = [0u8; 33];
    body[..32].copy_from_slice(ehpub);
    body[32] = cfg.pkey_index;
    let n = frame::build_request(L2ReqId::Handshake as u8, &body, l2)?;
    l1::send_request(spi, &l2[..n]).map_err(L2Error::from)?;
    let frame_len = l1::read_response(spi, wait, l2).map_err(L2Error::from)?;
    let resp = frame::parse_response(&l2[..frame_len])?;
    // The handshake response is a single, complete frame. A continuation status
    // (`*Cont`) is anomalous here and must not be accepted.
    if matches!(resp.status, L2Status::RequestCont | L2Status::ResultCont)
    {
        return Err(SeError::L2(L2Error::BadFrame));
    }
    let (etpub, t_tauth) = parse_handshake_resp(resp.data)?;
    let keys = handshake::run
    (
        cfg.ehpriv,
        ehpub,
        cfg.shipriv,
        cfg.shipub,
        cfg.stpub,
        cfg.pkey_index,
        &etpub,
        &t_tauth,
    )?;
    Ok(keys)
}

/// Splits a Handshake_Resp body into `(ETPUB, T_TAUTH)`.
///
/// The body must be exactly 48 bytes: ETPUB(32) || T_TAUTH(16). libtropic
/// enforces the same exact length (`TR01_L2_HANDSHAKE_RSP_LEN`). Errors with
/// `ShortFrame` on a truncated body and `BadFrame` on trailing bytes.
pub(crate) fn parse_handshake_resp(data: &[u8]) -> Result<([u8; 32], [u8; 16]), L2Error>
{
    let (rest, etpub) = take_array::<32>(data).map_err(|_| L2Error::ShortFrame)?;
    let (tail, t_tauth) = take_array::<16>(rest).map_err(|_| L2Error::ShortFrame)?;
    if !tail.is_empty()
    {
        return Err(L2Error::BadFrame);
    }
    Ok((etpub, t_tauth))
}

impl<SPI, W> Tropic01<SPI, W, ActiveSession>
where
    SPI: SpiDevice,
    W: SeWait,
{
    /// Closes the secure channel, returning a `NoSession` handle.
    ///
    /// Always succeeds. Dropping the `ActiveSession` state zeroizes the session
    /// keys. This method then wipes both buffers, leaving no plaintext residue.
    pub fn close_session(self) -> Tropic01<SPI, W, NoSession>
    {
        let Tropic01
        {
            spi,
            wait,
            mut l2,
            mut l3,
            state,
        } = self;
        drop(state);
        l2.zeroize();
        l3.as_mut_slice().zeroize();
        Tropic01
        {
            spi,
            wait,
            l2,
            l3,
            state: NoSession,
        }
    }

    /// Sends a `Ping` and writes the echoed payload into `out`.
    ///
    /// A diagnostic round-trip (not part of `SeCommands`). Returns the echoed
    /// byte count, which equals `payload.len()`.
    ///
    /// Teardown gate: any fault between encrypt and verified decrypt (and a
    /// wrong-size echo, mirroring libtropic's `lt_in__ping`) poisons the
    /// session. A poisoned session fast-fails with `SessionLost` and touches
    /// neither the keys nor the chip. A non-OK result status is a valid,
    /// authenticated response: it returns an error but keeps the session live.
    /// This method wipes the L3 buffer after every round-trip, success or not.
    pub fn ping_into(&mut self, payload: &[u8], out: &mut [u8]) -> Result<usize, SeError>
    {
        if self.state.is_poisoned()
        {
            return Err(SeError::SessionLost);
        }
        // Argument checks come first: no nonce, no crypto, no chip traffic, so
        // a rejection here leaves the session untouched.
        let plaintext_len = 1usize
            .checked_add(payload.len())
            .ok_or(SeError::InvalidArgument)?;
        let needed = plaintext_len
            .checked_add(2 + crypto::GCM_TAG_LEN)
            .ok_or(SeError::InvalidArgument)?;
        if needed > self.l3.as_slice().len()
        {
            return Err(SeError::InvalidArgument);
        }
        if out.len() < payload.len()
        {
            return Err(SeError::BufferTooSmall);
        }
        // Plaintext = CMD_ID(1) || payload, laid out at l3[2..].
        {
            let l3 = self.l3.as_mut_slice();
            l3[2] = CmdId::Ping as u8;
            l3[3..3 + payload.len()].copy_from_slice(payload);
        }
        let result = self.ping_round_trip(plaintext_len, payload.len(), out);
        // The L3 buffer held command and result plaintext: wipe it on every
        // path, success included.
        self.l3.as_mut_slice().zeroize();
        result
    }

    /// Runs the gated round-trip and interprets the authenticated result.
    ///
    /// Phase 1 (seal -> transport -> verified open) poisons on ANY error: the
    /// nonces may be out of step and the keys must not be reused. Phase 2 reads
    /// the decrypted, authenticated plaintext. Its errors keep the session
    /// live, except a wrong-size echo, which libtropic also treats as fatal.
    fn ping_round_trip
    (
        &mut self,
        plaintext_len: usize,
        payload_len: usize,
        out: &mut [u8],
    )
    -> Result<usize, SeError>
    {
        let plain_len = match l3::round_trip
        (
            &mut self.spi,
            &mut self.wait,
            &mut self.l2,
            &mut self.l3,
            &mut self.state.keys,
            plaintext_len,
        )
        {
            Ok(n) => n,
            Err(e) =>
            {
                self.state.poison();
                return Err(e);
            }
        };
        // Result plaintext at l3[2..2 + plain_len] = RESULT(1) || RES_DATA. An
        // authenticated but empty result has no RESULT byte: it is a structural
        // protocol violation by the (authenticated) peer, so fail closed and
        // poison rather than continue on a channel the chip is misusing.
        if plain_len == 0
        {
            self.state.poison();
            return Err(SeError::L3(L3Error::Parse(ParseError::UnexpectedEnd)));
        }
        let l3 = self.l3.as_slice();
        let result_byte = *l3.get(2).ok_or(SeError::L3(L3Error::Parse(ParseError::UnexpectedEnd)))?;
        let status = L3Status::try_from(result_byte)
            .map_err(|_| SeError::L3(L3Error::Parse(ParseError::InvalidValue)))?;
        if status != L3Status::Ok
        {
            // A valid authenticated result (FAIL, UNAUTHORIZED, ...): the
            // session stays live, mirroring lt_l3_decrypt_response.
            return Err(SeError::L3(L3Error::Result(status)));
        }
        let echo_len = plain_len - 1;
        if echo_len != payload_len
        {
            // Authenticated but wrong-size echo. libtropic invalidates the
            // session here (lt_in__ping RES_SIZE check), so do we.
            self.state.poison();
            return Err(SeError::L3(L3Error::Oversize));
        }
        let echo = l3
            .get(3..3 + echo_len)
            .ok_or(SeError::L3(L3Error::Parse(ParseError::UnexpectedEnd)))?;
        out[..echo_len].copy_from_slice(echo);
        Ok(echo_len)
    }
}

/// Test-only accessor to the SPI port, for inspecting the chip mock.
#[cfg(test)]
impl<SPI, W, State> Tropic01<SPI, W, State>
{
    pub(crate) fn spi_ref(&self) -> &SPI
    {
        &self.spi
    }
}

/// Test-only seam to drive the nonce counters toward exhaustion.
#[cfg(test)]
impl<SPI, W> Tropic01<SPI, W, ActiveSession>
{
    pub(crate) fn seed_nonces(&mut self, cmd: u32, res: u32)
    {
        self.state.keys.set_nonces_for_test(cmd, res);
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::error::L1Error;
    use crate::test_support::vectors;
    use crate::test_support::ChipFault;
    use crate::test_support::ChipMockSpi;
    use crate::test_support::MockSpi;
    use crate::test_support::MockWait;

    /// Opens a session over a chip mock configured with `fault`.
    fn open(fault: ChipFault) -> Tropic01<ChipMockSpi, MockWait, ActiveSession>
    {
        let spi = ChipMockSpi::new(vectors::KCMD, vectors::KRES, vectors::ETPUB, vectors::T_TAUTH, fault);
        let dev = Tropic01::new(spi, MockWait::new());
        let ehpriv = Zeroizing::new(vectors::EHPRIV);
        let shipriv = Zeroizing::new(vectors::SHIPRIV);
        let shipub = vectors::SHIPUB;
        let stpub = vectors::STPUB;
        let cfg = SessionConfig
        {
            ehpriv: &ehpriv,
            shipriv: &shipriv,
            shipub: &shipub,
            stpub: &stpub,
            pkey_index: 0,
        };
        match dev.open_session(cfg)
        {
            Ok(d) => d,
            Err((_, e)) => panic!("open_session failed: {e:?}"),
        }
    }

    #[test]
    fn open_session_then_ping_echoes_payload()
    {
        let mut dev = open(ChipFault::None);
        let payload = b"patina ping";
        let mut out = [0u8; 32];
        let n = dev.ping_into(payload, &mut out).unwrap();
        assert_eq!(&out[..n], payload);
    }

    #[test]
    fn ping_empty_payload_round_trips()
    {
        let mut dev = open(ChipFault::None);
        let mut out = [0u8; 4];
        let n = dev.ping_into(&[], &mut out).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn repeated_pings_advance_both_nonces_in_lockstep()
    {
        let mut dev = open(ChipFault::None);
        let mut out = [0u8; 16];
        for i in 1..=5u32
        {
            dev.ping_into(b"x", &mut out).unwrap();
            // The chip advances each nonce once per verified round-trip. Equal
            // counters prove the host's two nonces stayed in step (otherwise the
            // GCM tag would have failed). Each (key, nonce) pair is thus unique.
            assert_eq!(dev.spi_ref().nonces(), (i, i));
        }
    }

    #[test]
    fn buffer_too_small_is_rejected_before_any_traffic()
    {
        let mut dev = open(ChipFault::None);
        let before = dev.spi_ref().transaction_count();
        let mut out = [0u8; 2];
        assert_eq!(dev.ping_into(b"too long", &mut out), Err(SeError::BufferTooSmall));
        // Rejected up front: no nonce burned, no SPI traffic, session intact.
        assert_eq!(dev.spi_ref().transaction_count(), before);
        let mut ok_out = [0u8; 16];
        assert_eq!(dev.ping_into(b"still ok", &mut ok_out), Ok(8));
    }

    #[test]
    fn non_ok_result_status_is_recoverable()
    {
        // A FAIL result is a valid authenticated response: the error surfaces
        // but the session stays live and the nonces stay in step.
        let mut dev = open(ChipFault::ResultFail);
        let mut out = [0u8; 16];
        assert_eq!
        (
            dev.ping_into(b"hi", &mut out),
            Err(SeError::L3(L3Error::Result(L3Status::Fail)))
        );
        // The session is NOT poisoned: the next ping reaches the chip again.
        let before = dev.spi_ref().transaction_count();
        let r = dev.ping_into(b"hi", &mut out);
        assert_eq!(r, Err(SeError::L3(L3Error::Result(L3Status::Fail))));
        assert!(dev.spi_ref().transaction_count() > before, "chip traffic continues");
        assert_eq!(dev.spi_ref().nonces(), (2, 2), "nonces stay in lockstep");
    }

    #[test]
    fn wrong_size_echo_poisons_session()
    {
        // An authenticated OK result with a short echo mirrors libtropic's
        // lt_in__ping RES_SIZE check: session-fatal.
        let mut dev = open(ChipFault::ShortEcho);
        let mut out = [0u8; 16];
        assert_eq!(dev.ping_into(b"hi", &mut out), Err(SeError::L3(L3Error::Oversize)));
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn l3_buffer_is_wiped_after_a_successful_ping()
    {
        let mut dev = open(ChipFault::None);
        let mut out = [0u8; 16];
        dev.ping_into(b"wipe me", &mut out).unwrap();
        assert!(dev.l3.as_slice().iter().all(|&b| b == 0), "plaintext residue");
    }

    #[test]
    fn handshake_resp_body_must_be_exactly_48_bytes()
    {
        let body = [0u8; 48];
        let (etpub, t_tauth) = parse_handshake_resp(&body).unwrap();
        assert_eq!(etpub, [0u8; 32]);
        assert_eq!(t_tauth, [0u8; 16]);
        assert_eq!(parse_handshake_resp(&body[..47]), Err(L2Error::ShortFrame));
        let long = [0u8; 49];
        assert_eq!(parse_handshake_resp(&long), Err(L2Error::BadFrame));
    }

    #[test]
    fn bad_result_tag_poisons_session()
    {
        let mut dev = open(ChipFault::BadResultTag);
        let mut out = [0u8; 16];
        assert_eq!(dev.ping_into(b"hi", &mut out), Err(SeError::L3(L3Error::Tag)));
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn l2_tag_err_poisons_session()
    {
        let mut dev = open(ChipFault::L2TagErr);
        let mut out = [0u8; 16];
        let r = dev.ping_into(b"hi", &mut out);
        assert!(matches!(r, Err(SeError::L2(_))), "got {r:?}");
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn l2_crc_err_poisons_session()
    {
        let mut dev = open(ChipFault::L2CrcErr);
        let mut out = [0u8; 16];
        assert_eq!(dev.ping_into(b"hi", &mut out), Err(SeError::L2(L2Error::Crc)));
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn alarm_poisons_session()
    {
        let mut dev = open(ChipFault::Alarm);
        let mut out = [0u8; 16];
        assert_eq!(dev.ping_into(b"hi", &mut out), Err(SeError::L2(L2Error::L1(L1Error::Alarm))));
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn empty_authenticated_result_poisons_session()
    {
        // An authenticated result with no RESULT byte is a structural violation.
        // The session must fail closed even though the tag verified.
        let mut dev = open(ChipFault::EmptyResult);
        let mut out = [0u8; 16];
        assert_eq!(
            dev.ping_into(b"hi", &mut out),
            Err(SeError::L3(L3Error::Parse(ParseError::UnexpectedEnd)))
        );
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn nonce_exhaustion_poisons_before_touching_the_chip()
    {
        let mut dev = open(ChipFault::None);
        dev.seed_nonces(u32::MAX, u32::MAX);
        let before = dev.spi_ref().transaction_count();
        let mut out = [0u8; 16];
        assert_eq!(dev.ping_into(b"hi", &mut out), Err(SeError::NonceExhausted));
        // Exhaustion is caught before any SPI traffic.
        assert_eq!(dev.spi_ref().transaction_count(), before);
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn close_session_returns_no_session_handle()
    {
        let dev = open(ChipFault::None);
        let dev = dev.close_session();
        // Back to NoSession: buffers wiped, ready to re-open.
        assert!(dev.l2.iter().all(|&b| b == 0));
        assert!(dev.l3.as_slice().iter().all(|&b| b == 0));
    }

    /// Asserts a poisoned session fast-fails with `SessionLost` and issues no
    /// further SPI transaction.
    fn assert_session_lost_and_quiet(dev: &mut Tropic01<ChipMockSpi, MockWait, ActiveSession>)
    {
        let before = dev.spi_ref().transaction_count();
        let mut out = [0u8; 16];
        assert_eq!(dev.ping_into(b"again", &mut out), Err(SeError::SessionLost));
        assert_eq!(dev.spi_ref().transaction_count(), before, "no chip traffic after poison");
    }

    #[test]
    fn new_builds_a_no_session_handle()
    {
        let dev = Tropic01::new(MockSpi::new(), MockWait::new());
        // Buffers start zeroed.
        assert!(dev.l2.iter().all(|&b| b == 0));
        assert!(dev.l3.as_slice().iter().all(|&b| b == 0));
        // The ports are owned and reachable: no transactions or waits yet.
        assert_eq!(dev.spi.transaction_count(), 0);
        assert_eq!(dev.wait.wait_count(), 0);
        let _ = dev.state;
    }

    #[test]
    fn handle_size_is_bounded()
    {
        // The handle must stay small enough to live in the secure binary's
        // static singleton. Design budget: <= 5000 bytes.
        assert!(core::mem::size_of::<Tropic01<MockSpi, MockWait, NoSession>>() <= 5000);
    }

    #[test]
    fn active_session_poison_is_sticky()
    {
        let keys = SessionKeys::new([1u8; 32], [2u8; 32]);
        let mut s = ActiveSession::new(keys);
        assert!(!s.is_poisoned());
        s.poison();
        assert!(s.is_poisoned());
        // Idempotent.
        s.poison();
        assert!(s.is_poisoned());
    }
}
