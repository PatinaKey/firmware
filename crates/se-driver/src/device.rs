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
use crate::parse::take;
use crate::parse::take_array;
use crate::port::MCounterIdx;
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

    /// Runs one gated L3 command end to end and returns the parsed value.
    ///
    /// On entry `l3[2..2 + cmd_plaintext_len]` holds `CMD_ID || CMD_DATA`. The
    /// template owns every session duty so a command author cannot forget one:
    ///
    /// - A poisoned session fast-fails with `SessionLost`, no keys, no chip.
    /// - Any fault in seal -> transport -> verified open poisons the session.
    ///   The nonces may be out of step and the keys must not be reused.
    /// - An authenticated but empty result has no RESULT byte. The peer is
    ///   misusing the channel, so poison and fail closed.
    /// - A known non-OK RESULT (FAIL, COUNTER_INVALID, ...) is a valid
    ///   authenticated reply. It returns `L3Error::Result` and keeps the
    ///   session live, mirroring `lt_l3_decrypt_response`.
    /// - An unknown RESULT byte returns `L3Error::Parse(InvalidValue)` and
    ///   keeps the session live, mirroring libtropic's `LT_L3_RESULT_UNKNOWN`.
    /// - On an OK result, when `expected_res_data_len` is `Some(n)` and the
    ///   RES_DATA length is not `n`, poison (a structural anomaly on an
    ///   authenticated OK result, mirroring libtropic's RES_SIZE invalidate).
    /// - `parse` consumes the RES_DATA slice `l3[3..2 + plain_len]`. When it
    ///   returns `Err`, poison before returning. A failed or forgotten parse on
    ///   an OK result thus tears the session down rather than continuing.
    ///
    /// The L3 plaintext buffer is zeroized on every return path. The wipe lives
    /// here so no command author can leave plaintext behind.
    fn run<T>
    (
        &mut self,
        cmd_plaintext_len: usize,
        expected_res_data_len: Option<usize>,
        parse: impl FnOnce(&[u8]) -> Result<T, L3Error>,
    )
    -> Result<T, SeError>
    {
        let result = self.run_gated(cmd_plaintext_len, expected_res_data_len, parse);
        // The L3 buffer held command and result plaintext. Wipe it on every
        // path, success or failure, before handing control back.
        self.l3.as_mut_slice().zeroize();
        result
    }

    /// Non-generic gate body for `run`, less the L3 wipe.
    ///
    /// Outlined from `run` so the heavy session logic compiles once instead of
    /// per `T`. `run` adds only the wipe, which keeps the monomorphized stub
    /// tiny. See `run` for the per-step contract.
    fn run_gated<T>
    (
        &mut self,
        cmd_plaintext_len: usize,
        expected_res_data_len: Option<usize>,
        parse: impl FnOnce(&[u8]) -> Result<T, L3Error>,
    )
    -> Result<T, SeError>
    {
        if self.state.is_poisoned()
        {
            return Err(SeError::SessionLost);
        }
        let plain_len = match l3::round_trip
        (
            &mut self.spi,
            &mut self.wait,
            &mut self.l2,
            &mut self.l3,
            &mut self.state.keys,
            cmd_plaintext_len,
        )
        {
            Ok(n) => n,
            Err(e) =>
            {
                self.state.poison();
                return Err(e);
            }
        };
        if plain_len == 0
        {
            // An authenticated but empty result has no RESULT byte. This is
            // STRICTER than libtropic on purpose: libtropic would read the
            // first sealed byte as a tag and map it to LT_L3_RESULT_UNKNOWN,
            // whereas a structurally impossible authenticated result here fails
            // closed and poisons the session.
            self.state.poison();
            return Err(SeError::L3(L3Error::Parse(ParseError::UnexpectedEnd)));
        }
        let result_byte = *self
            .l3
            .as_slice()
            .get(2)
            .ok_or(SeError::L3(L3Error::Parse(ParseError::UnexpectedEnd)))?;
        let status = match L3Status::try_from(result_byte)
        {
            Ok(s) => s,
            Err(_) =>
            {
                // Unknown RESULT byte: recoverable, session left live, mirroring
                // libtropic's LT_L3_RESULT_UNKNOWN handling.
                return Err(SeError::L3(L3Error::Parse(ParseError::InvalidValue)));
            }
        };
        if status != L3Status::Ok
        {
            // A valid authenticated result (FAIL, COUNTER_INVALID, ...): the
            // session stays live, mirroring lt_l3_decrypt_response.
            return Err(SeError::L3(L3Error::Result(status)));
        }
        // RES_DATA = everything after the RESULT byte: l3[3..2 + plain_len].
        let res_data = self
            .l3
            .as_slice()
            .get(3..2 + plain_len)
            .ok_or(SeError::L3(L3Error::Parse(ParseError::UnexpectedEnd)))?;
        if let Some(expected) = expected_res_data_len
            && res_data.len() != expected
        {
            // Structural anomaly on an authenticated OK result, mirroring
            // libtropic's RES_SIZE invalidate. Read the length before the
            // disjoint &mut-self poison call to satisfy the borrow checker.
            self.state.poison();
            return Err(SeError::L3(L3Error::Oversize));
        }
        match parse(res_data)
        {
            Ok(value) => Ok(value),
            Err(e) =>
            {
                // Fail-closed: a parse failure on an OK result tears the session
                // down. The res_data borrow ends with `parse`, so poisoning self
                // here is a disjoint borrow.
                self.state.poison();
                Err(SeError::L3(e))
            }
        }
    }

    /// Sends a `Ping` and writes the echoed payload into `out`.
    ///
    /// A diagnostic round-trip (not part of `SeCommands`). Returns the echoed
    /// byte count, which equals `payload.len()`.
    ///
    /// The shared `run` gate governs the session. The parse closure enforces
    /// the ping RES_SIZE check: a wrong-size echo on an OK result returns
    /// `L3Error::Oversize`, which `run` turns into a session poison, mirroring
    /// libtropic's `lt_in__ping`.
    pub fn ping_into(&mut self, payload: &[u8], out: &mut [u8]) -> Result<usize, SeError>
    {
        // Argument checks come first: no nonce, no crypto, no chip traffic, so
        // a rejection here leaves the session untouched. Re-check poison up
        // front so a poisoned session rejects before argument work.
        if self.state.is_poisoned()
        {
            return Err(SeError::SessionLost);
        }
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
        let payload_len = payload.len();
        // Echo length varies, so the size check lives in the closure: a
        // wrong-size echo returns Oversize, which run poisons (lt_in__ping).
        self.run
        (
            plaintext_len,
            None,
            |res_data|
            {
                if res_data.len() != payload_len
                {
                    return Err(L3Error::Oversize);
                }
                out[..payload_len].copy_from_slice(res_data);
                Ok(payload_len)
            },
        )
    }

    /// Fills `out` with TRNG bytes from the chip.
    ///
    /// Inherent twin of `SeCommands::random_into`. Returns the number of bytes
    /// written, which equals `out.len()`. An empty `out` returns `Ok(0)` with
    /// no chip traffic. Rejects `out.len() > 255` with `InvalidArgument`
    /// (chunking is a caller concern). A wrong-size authenticated result
    /// poisons the session, mirroring libtropic's RES_SIZE check.
    // The `SeCommands` impl that exposes this is not wired yet, so it is dead in
    // the non-test build. The device tests call it, so `#[allow]` is required
    // (an `#[expect]` would fire `unfulfilled_lint_expectations` in the test
    // build). Same pattern as `ids::ObjectId`.
    #[allow(dead_code)]
    pub(crate) fn random_into(&mut self, out: &mut [u8]) -> Result<usize, SeError>
    {
        if self.state.is_poisoned()
        {
            return Err(SeError::SessionLost);
        }
        if out.is_empty()
        {
            return Ok(0);
        }
        let n_bytes = u8::try_from(out.len()).map_err(|_| SeError::InvalidArgument)?;
        // CMD plaintext (2 bytes): CMD_ID || N_BYTES, laid out at l3[2..].
        {
            let l3 = self.l3.as_mut_slice();
            l3[2] = CmdId::RandomValueGet as u8;
            l3[3] = n_bytes;
        }
        let n = out.len();
        // RES_DATA = PADDING(3) || RANDOM(N): skip the padding, copy the bytes.
        self.run
        (
            2,
            Some(3 + n),
            |res_data|
            {
                let (_padding, random) = take(res_data, 3)?;
                out[..n].copy_from_slice(random);
                Ok(n)
            },
        )
    }

    /// Reads monotonic counter `idx` and returns its 32-bit value.
    ///
    /// Inherent twin of `SeCommands::mcounter_get`. The index range is enforced
    /// by `MCounterIdx`. A `CounterInvalid` result is recoverable: it surfaces
    /// as `L3Error::Result` and keeps the session live. A wrong-size
    /// authenticated result poisons the session.
    // The `SeCommands` impl that exposes this is not wired yet, so it is dead in
    // the non-test build. The device tests call it, so `#[allow]` is required.
    // Same pattern as `ids::ObjectId`.
    #[allow(dead_code)]
    pub(crate) fn mcounter_get(&mut self, idx: MCounterIdx) -> Result<u32, SeError>
    {
        // CMD plaintext (3 bytes): CMD_ID || MCOUNTER_INDEX(u16 LE).
        {
            let l3 = self.l3.as_mut_slice();
            l3[2] = CmdId::McounterGet as u8;
            let index = u16::from(idx.get()).to_le_bytes();
            l3[3] = index[0];
            l3[4] = index[1];
        }
        // RES_DATA = PADDING(3) || VALUE(u32 LE).
        self.run
        (
            3,
            Some(7),
            |res_data|
            {
                let (_padding, rest) = take(res_data, 3)?;
                let (_tail, value) = take_array::<4>(rest)?;
                Ok(u32::from_le_bytes(value))
            },
        )
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

    pub(crate) fn spi_mut(&mut self) -> &mut SPI
    {
        &mut self.spi
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
    fn random_into_fills_buffer_and_advances_nonces()
    {
        let mut dev = open(ChipFault::None);
        let mut out = [0u8; 16];
        let n = dev.random_into(&mut out).unwrap();
        assert_eq!(n, 16);
        // The chip fills RANDOM(N) with 0xA0 + i. Assert the bytes landed and
        // the nonces advanced once in lockstep.
        for (i, b) in out.iter().enumerate()
        {
            assert_eq!(*b, 0xA0u8.wrapping_add(i as u8));
        }
        assert_eq!(dev.spi_ref().nonces(), (1, 1));
    }

    #[test]
    fn random_into_empty_out_makes_no_traffic()
    {
        let mut dev = open(ChipFault::None);
        let before = dev.spi_ref().transaction_count();
        let mut out = [0u8; 0];
        assert_eq!(dev.random_into(&mut out), Ok(0));
        assert_eq!(dev.spi_ref().transaction_count(), before);
        assert_eq!(dev.spi_ref().nonces(), (0, 0));
    }

    #[test]
    fn random_into_rejects_oversize_request_before_traffic()
    {
        let mut dev = open(ChipFault::None);
        let before = dev.spi_ref().transaction_count();
        let mut out = [0u8; 256];
        assert_eq!(dev.random_into(&mut out), Err(SeError::InvalidArgument));
        // Rejected up front: no nonce burned, no SPI traffic, session intact.
        assert_eq!(dev.spi_ref().transaction_count(), before);
        let mut ok_out = [0u8; 8];
        assert_eq!(dev.random_into(&mut ok_out), Ok(8));
    }

    #[test]
    fn random_into_wrong_size_result_poisons_session()
    {
        let mut dev = open(ChipFault::ResultWrongSize);
        let mut out = [0u8; 16];
        assert_eq!(dev.random_into(&mut out), Err(SeError::L3(L3Error::Oversize)));
        assert_session_lost_and_quiet(&mut dev);
    }

    /// Builds a counter index, panicking only in test code on a bad constant.
    fn mc(value: u8) -> MCounterIdx
    {
        MCounterIdx::new(value).expect("test mcounter index out of range")
    }

    #[test]
    fn mcounter_get_returns_little_endian_value()
    {
        let mut dev = open(ChipFault::None);
        dev.spi_mut().set_mcounter_val(0x01020304);
        assert_eq!(dev.mcounter_get(mc(3)), Ok(0x01020304));
        assert_eq!(dev.spi_ref().nonces(), (1, 1));
    }

    #[test]
    fn mcounter_get_counter_invalid_is_recoverable()
    {
        // A CounterInvalid result is a valid authenticated response: the error
        // surfaces but the session stays live and the nonces stay in step.
        let mut dev = open(ChipFault::CounterInvalid);
        assert_eq!
        (
            dev.mcounter_get(mc(0)),
            Err(SeError::L3(L3Error::Result(L3Status::CounterInvalid)))
        );
        let before = dev.spi_ref().transaction_count();
        let r = dev.mcounter_get(mc(0));
        assert_eq!(r, Err(SeError::L3(L3Error::Result(L3Status::CounterInvalid))));
        assert!(dev.spi_ref().transaction_count() > before, "chip traffic continues");
        assert_eq!(dev.spi_ref().nonces(), (2, 2), "nonces stay in lockstep");
    }

    #[test]
    fn mcounter_get_wrong_size_result_poisons_session()
    {
        // An authenticated OK result whose RES_DATA is one byte short is a
        // structural anomaly: run poisons via the expected_res_data_len check.
        let mut dev = open(ChipFault::ResultWrongSize);
        assert_eq!(dev.mcounter_get(mc(0)), Err(SeError::L3(L3Error::Oversize)));
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn unknown_result_status_is_recoverable()
    {
        // The chip seals an OK-tag result whose RESULT byte is unrecognized.
        // run surfaces Parse(InvalidValue) and leaves the session live, so the
        // next command reaches the chip and the nonces advance.
        let mut dev = open(ChipFault::UnknownResultStatus);
        let mut out = [0u8; 16];
        assert_eq!
        (
            dev.ping_into(b"hi", &mut out),
            Err(SeError::L3(L3Error::Parse(ParseError::InvalidValue)))
        );
        let before = dev.spi_ref().transaction_count();
        let r = dev.ping_into(b"hi", &mut out);
        assert_eq!(r, Err(SeError::L3(L3Error::Parse(ParseError::InvalidValue))));
        assert!(dev.spi_ref().transaction_count() > before, "chip traffic continues");
        assert_eq!(dev.spi_ref().nonces(), (2, 2), "nonces stay in lockstep");
    }

    #[test]
    fn random_l3_buffer_is_wiped_after_success()
    {
        let mut dev = open(ChipFault::None);
        let mut out = [0u8; 16];
        dev.random_into(&mut out).unwrap();
        assert!(dev.l3.as_slice().iter().all(|&b| b == 0), "plaintext residue");
    }

    #[test]
    fn mixed_command_sequence_keeps_nonces_in_lockstep()
    {
        // A ping, a random, and an mcounter_get each advance both nonces once.
        let mut dev = open(ChipFault::None);
        dev.spi_mut().set_mcounter_val(0xDEADBEEF);
        let mut buf = [0u8; 16];
        dev.ping_into(b"x", &mut buf).unwrap();
        assert_eq!(dev.spi_ref().nonces(), (1, 1));
        dev.random_into(&mut buf).unwrap();
        assert_eq!(dev.spi_ref().nonces(), (2, 2));
        assert_eq!(dev.mcounter_get(mc(0)), Ok(0xDEADBEEF));
        assert_eq!(dev.spi_ref().nonces(), (3, 3));
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
