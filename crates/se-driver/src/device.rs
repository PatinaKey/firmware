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
use crate::parse::take_u8;
use crate::port::EccCurve;
use crate::port::EccPublicKey;
use crate::port::EccSlot;
use crate::port::MCounterIdx;
use crate::port::MacAndDestroyOutput;
use crate::port::MacDestroySlot;
use crate::port::RMemSlot;
use crate::port::SeCommands;
use crate::port::Signature;
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

/// Which mode the chip reboots into for a `Startup_Req`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupId
{
    /// Restart and initialize as after a power cycle (loads Application FW).
    Reboot,
    /// Restart but stay in Start-up (Maintenance) Mode; do not load Application FW.
    MaintenanceReboot,
}

impl StartupId
{
    /// Returns the `Startup_Req` `startup_id` wire byte (0x01 / 0x03).
    ///
    /// Source: libtropic `lt_startup_id_t` (`TR01_REBOOT`,
    /// `TR01_MAINTENANCE_REBOOT`).
    const fn wire_byte(self) -> u8
    {
        match self
        {
            StartupId::Reboot => 0x01,
            StartupId::MaintenanceReboot => 0x03,
        }
    }
}

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

    /// Reboots the chip into the mode selected by `startup_id`.
    ///
    /// Sends a `Startup_Req` (L2 0xB3). The chip boots into Start-up Mode after a
    /// power cycle; `StartupId::Reboot` loads the Application FW (required before
    /// `open_session`, since the secure channel and L3 commands live there).
    /// Returns `Ok(())` on the empty success ack. Errors on a bus fault or an
    /// unexpected acknowledgement. Mirrors libtropic `lt_reboot`.
    pub fn reboot(&mut self, startup_id: StartupId) -> Result<(), SeError>
    {
        // Startup_Req body = STARTUP_ID(1). REQ_LEN = 1, RSP carries no data.
        let body = [startup_id.wire_byte()];
        let n = frame::build_request(L2ReqId::Startup as u8, &body, &mut self.l2)?;
        l1::send_request(&mut self.spi, &self.l2[..n]).map_err(L2Error::from)?;
        let frame_len =
            l1::read_response(&mut self.spi, &mut self.wait, &mut self.l2).map_err(L2Error::from)?;
        let resp = frame::parse_response(&self.l2[..frame_len])?;
        // A successful Startup_Req is acknowledged with an empty RequestOk frame.
        if !matches!(resp.status, L2Status::RequestOk) || !resp.data.is_empty()
        {
            return Err(SeError::L2(L2Error::BadFrame));
        }
        Ok(())
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

    /// Returns the CMD plaintext region, indexed from 0 like the spec tables.
    ///
    /// The L3 buffer reserves bytes `l3[0..2]` for the CMD_SIZE prefix. A
    /// command writes its plaintext (`CMD_ID` at offset 0) into this view, so
    /// the byte layout matches the datasheet and libtropic tables directly.
    fn cmd_plaintext(&mut self) -> &mut [u8]
    {
        &mut self.l3.as_mut_slice()[2..]
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
    pub(crate) fn mcounter_get(&mut self, idx: MCounterIdx) -> Result<u32, SeError>
    {
        if self.state.is_poisoned()
        {
            return Err(SeError::SessionLost);
        }
        // CMD plaintext (3 bytes): CMD_ID || MCOUNTER_INDEX(u16 LE).
        {
            let cmd = self.cmd_plaintext();
            cmd[0] = CmdId::McounterGet as u8;
            let index = u16::from(idx.get()).to_le_bytes();
            cmd[1] = index[0];
            cmd[2] = index[1];
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

    /// Reads R-Memory user-data `slot` into `out`.
    ///
    /// Inherent twin of `SeCommands::rmem_read_into`. Returns the DATA byte
    /// count, which is 0 for an empty slot. A read returns up to
    /// `R_MEM_DATA_MAX` DATA bytes, so `out` must be at least that long. A
    /// shorter `out` is rejected with `BufferTooSmall` up front, before any
    /// nonce, crypto, or chip traffic, leaving the session untouched.
    ///
    /// A RES_DATA too short to hold the 3 padding bytes, or an implied DATA
    /// length past `R_MEM_DATA_MAX`, is a structural anomaly on an authenticated
    /// OK result: the parse closure returns `Err`, which poisons the session via
    /// `run`. An empty slot reads back RESULT=OK with no DATA and returns
    /// `Ok(0)`, keeping the session live.
    pub(crate) fn rmem_read_into
    (
        &mut self,
        slot: RMemSlot,
        out: &mut [u8],
    )
    -> Result<usize, SeError>
    {
        if self.state.is_poisoned()
        {
            return Err(SeError::SessionLost);
        }
        // A read returns up to R_MEM_DATA_MAX DATA bytes. Require out to hold the
        // maximum up front, before any nonce or chip traffic, so a too-small
        // buffer is rejected with the session untouched (matching libtropic's
        // LT_PARAM_ERR, which does not invalidate the session). This makes the
        // in-closure DATA-vs-out check below unreachable.
        if out.len() < R_MEM_DATA_MAX
        {
            return Err(SeError::BufferTooSmall);
        }
        // CMD plaintext (3 bytes): CMD_ID || UDATA_SLOT(u16 LE).
        {
            let cmd = self.cmd_plaintext();
            cmd[0] = CmdId::RMemDataRead as u8;
            let slot_bytes = slot.get().to_le_bytes();
            cmd[1] = slot_bytes[0];
            cmd[2] = slot_bytes[1];
        }
        // RES_DATA = PADDING(3) || DATA(0..=R_MEM_DATA_MAX). The length is
        // variable, so pass None and enforce the structural bounds here.
        self.run
        (
            3,
            None,
            |res_data|
            {
                let (_padding, data) = take(res_data, 3)?;
                if data.len() > R_MEM_DATA_MAX
                {
                    // A DATA length past the target-firmware cap is a structural
                    // anomaly on an authenticated result. Fail closed.
                    return Err(L3Error::Oversize);
                }
                out[..data.len()].copy_from_slice(data);
                Ok(data.len())
            },
        )
    }

    /// Writes `data` to R-Memory user-data `slot`.
    ///
    /// Inherent twin of `SeCommands::rmem_write`. The slot must be erased first.
    /// Returns `Ok(())` on a stored write.
    ///
    /// Validates `data.len()` in `1..=R_MEM_DATA_MAX` up front, before any
    /// nonce, crypto, or chip traffic, so a rejection leaves the session
    /// untouched. An empty or oversize payload returns `InvalidArgument`.
    ///
    /// A non-OK RESULT (SLOT_NOT_EMPTY, HARDWARE_FAIL, FAIL, ...) is a valid
    /// authenticated reply: it surfaces as `L3Error::Result` and keeps the
    /// session live, mirroring libtropic.
    pub(crate) fn rmem_write(&mut self, slot: RMemSlot, data: &[u8]) -> Result<(), SeError>
    {
        // Argument checks come first: no nonce, no crypto, no chip traffic, so a
        // rejection here leaves the session untouched. Re-check poison up front
        // so a poisoned session rejects before argument work.
        if self.state.is_poisoned()
        {
            return Err(SeError::SessionLost);
        }
        if data.is_empty() || data.len() > R_MEM_DATA_MAX
        {
            return Err(SeError::InvalidArgument);
        }
        // CMD plaintext (4 + data.len() bytes): CMD_ID || UDATA_SLOT(u16 LE) ||
        // PADDING(1, 0) || DATA.
        let plaintext_len = 4usize
            .checked_add(data.len())
            .ok_or(SeError::InvalidArgument)?;
        // Bound the wire footprint against the L3 buffer before the DATA copy,
        // mirroring ping_into. Plaintext, the 2-byte CMD_SIZE prefix, and the
        // GCM tag must all fit. Explicit and local, so the cmd[4..] copy stays
        // in bounds even if R_MEM_DATA_MAX later grows.
        let needed = plaintext_len
            .checked_add(2 + crypto::GCM_TAG_LEN)
            .ok_or(SeError::InvalidArgument)?;
        if needed > self.l3.as_slice().len()
        {
            return Err(SeError::InvalidArgument);
        }
        {
            let cmd = self.cmd_plaintext();
            cmd[0] = CmdId::RMemDataWrite as u8;
            let slot_bytes = slot.get().to_le_bytes();
            cmd[1] = slot_bytes[0];
            cmd[2] = slot_bytes[1];
            cmd[3] = 0;
            cmd[4..4 + data.len()].copy_from_slice(data);
        }
        // No RES_DATA: expect an empty payload after the RESULT byte.
        self.run(plaintext_len, Some(0), |_res_data| Ok(()))
    }

    /// Generates an ECC key pair on the chip in `slot` for `curve`.
    ///
    /// Inherent twin of `SeCommands::ecc_key_generate`. The private key never
    /// leaves the chip. The slot range is enforced by `EccSlot::new`. A non-OK
    /// RESULT (SlotNotEmpty, Fail, ...) is a valid authenticated reply: it
    /// surfaces as `L3Error::Result` and keeps the session live, mirroring
    /// libtropic. A bad tag, CRC, alarm, or empty result poisons the session.
    pub(crate) fn ecc_key_generate
    (
        &mut self,
        slot: EccSlot,
        curve: EccCurve,
    )
    -> Result<(), SeError>
    {
        if self.state.is_poisoned()
        {
            return Err(SeError::SessionLost);
        }
        // CMD plaintext (4 bytes): CMD_ID || SLOT(u16 LE) || CURVE(1).
        {
            let cmd = self.cmd_plaintext();
            cmd[0] = CmdId::EccKeyGenerate as u8;
            let slot_bytes = u16::from(slot.get()).to_le_bytes();
            cmd[1] = slot_bytes[0];
            cmd[2] = slot_bytes[1];
            cmd[3] = curve.wire_byte();
        }
        // No RES_DATA: expect an empty payload after the RESULT byte.
        self.run(4, Some(0), |_res_data| Ok(()))
    }

    /// Reads the public key for `slot`.
    ///
    /// Inherent twin of `SeCommands::ecc_public_key`. Returns the key by value,
    /// carrying its curve: 32 bytes for Ed25519, 64 for P-256 (raw X || Y, no
    /// 0x04 prefix). The slot range is enforced by `EccSlot::new`.
    ///
    /// RES_DATA = CURVE(1) || ORIGIN(1) || PADDING(13) || PUBKEY. The length is
    /// variable per curve, so `run` gets `None` and the parse closure validates
    /// the structure: an unknown CURVE byte, a RES_DATA shorter than the 15-byte
    /// header, or a PUBKEY length that does not match the curve is a structural
    /// anomaly on an authenticated OK result. The closure returns `Err`, which
    /// poisons the session via `run`. An empty or corrupt slot reads back the
    /// recoverable `L3Error::Result(InvalidKey)`, keeping the session live.
    pub(crate) fn ecc_public_key
    (
        &mut self,
        slot: EccSlot,
    )
    -> Result<EccPublicKey, SeError>
    {
        if self.state.is_poisoned()
        {
            return Err(SeError::SessionLost);
        }
        // CMD plaintext (3 bytes): CMD_ID || SLOT(u16 LE).
        {
            let cmd = self.cmd_plaintext();
            cmd[0] = CmdId::EccKeyRead as u8;
            let slot_bytes = u16::from(slot.get()).to_le_bytes();
            cmd[1] = slot_bytes[0];
            cmd[2] = slot_bytes[1];
        }
        // RES_DATA = CURVE(1) || ORIGIN(1) || PADDING(13) || PUBKEY. The PUBKEY
        // length is variable per curve, so pass None and enforce the structural
        // bounds here.
        self.run
        (
            3,
            None,
            |res_data|
            {
                let (rest, curve_byte) = take_u8(res_data)?;
                let (rest, _origin) = take_u8(rest)?;
                let (_padding, pubkey) = take(rest, ECC_READ_PADDING)?;
                let curve = EccCurve::from_wire_byte(curve_byte)
                    .ok_or(L3Error::Parse(ParseError::InvalidValue))?;
                if pubkey.len() != curve.pubkey_len()
                {
                    // A PUBKEY length that does not match the curve is a
                    // structural anomaly on an authenticated OK result. Fail
                    // closed.
                    return Err(L3Error::Oversize);
                }
                // Copy the curve-length prefix into a zeroed 64-byte store. The
                // tail stays zero and EccPublicKey::bytes trims it off.
                let mut bytes = [0u8; ECC_PUBKEY_MAX];
                bytes[..pubkey.len()].copy_from_slice(pubkey);
                Ok(EccPublicKey::new(curve, bytes))
            },
        )
    }

    /// Imports an external private key into ECC `slot` for `curve`.
    ///
    /// Inherent twin of `SeCommands::ecc_key_store`. `private_key` is the raw
    /// 32-byte scalar: the P-256 private integer or the Ed25519 seed (both 32
    /// bytes). It travels INSIDE the AES-GCM-encrypted L3 channel, and the shared
    /// `run` gate zeroizes the L3 plaintext on every return path, so the secret
    /// does not linger in the buffer. The slot range is enforced by `EccSlot`.
    ///
    /// SECURITY: an imported key is NON-ATTESTABLE. On-chip it is
    /// indistinguishable from a chip-generated key, so it cannot prove the
    /// private key never left a secure element. FIDO2 credentials must use
    /// chip-generated keys (`ecc_key_generate`); confine import to the OpenPGP /
    /// PKCS#11 / imported-SSH path. The driver enforces no such policy.
    ///
    /// A non-OK RESULT is a valid authenticated reply that keeps the session
    /// live, mirroring libtropic: SlotNotEmpty when the slot already holds a key,
    /// InvalidKey when the scalar is malformed, plus Unauthorized / Fail /
    /// HardwareFail. The command has no RES_DATA, so it declares `Some(0)`: an OK
    /// result carrying any payload poisons. A bad tag, CRC, alarm, or empty
    /// result poisons the session.
    pub(crate) fn ecc_key_store
    (
        &mut self,
        slot: EccSlot,
        curve: EccCurve,
        private_key: &Zeroizing<[u8; 32]>,
    )
    -> Result<(), SeError>
    {
        if self.state.is_poisoned()
        {
            return Err(SeError::SessionLost);
        }
        // CMD plaintext (48 bytes): CMD_ID || SLOT(u16 LE) || CURVE(1) ||
        // PADDING(12, 0) || K(32). libtropic never writes the padding, so zero it
        // explicitly: stale L3 bytes must not enter the authenticated command.
        {
            let cmd = self.cmd_plaintext();
            cmd[0] = CmdId::EccKeyStore as u8;
            let slot_bytes = u16::from(slot.get()).to_le_bytes();
            cmd[1] = slot_bytes[0];
            cmd[2] = slot_bytes[1];
            cmd[3] = curve.wire_byte();
            cmd[4..ECC_STORE_KEY_OFFSET].fill(0);
            cmd[ECC_STORE_KEY_OFFSET..ECC_STORE_CMD_LEN].copy_from_slice(&private_key[..]);
        }
        // The secret scalar is now live in the L3 plaintext buffer until `run`
        // seals it and wipes the buffer. `run` owns every return path, so no
        // early return can skip that wipe: keep it that way on any refactor.
        self.run(ECC_STORE_CMD_LEN, Some(0), |_res_data| Ok(()))
    }

    /// Erases ECC `slot`, removing any stored key.
    ///
    /// Inherent twin of `SeCommands::ecc_key_erase`. The slot range is enforced
    /// by `EccSlot`. Returns `Ok(())` on an erased slot.
    ///
    /// A non-OK RESULT is a valid authenticated reply that keeps the session
    /// live, mirroring libtropic: SlotEmpty when the slot already holds no key,
    /// plus Unauthorized / Fail / HardwareFail. The command has no RES_DATA, so
    /// it declares `Some(0)`: an OK result carrying any payload poisons. A bad
    /// tag, CRC, alarm, or empty result poisons the session.
    pub(crate) fn ecc_key_erase(&mut self, slot: EccSlot) -> Result<(), SeError>
    {
        if self.state.is_poisoned()
        {
            return Err(SeError::SessionLost);
        }
        // CMD plaintext (3 bytes): CMD_ID || SLOT(u16 LE).
        {
            let cmd = self.cmd_plaintext();
            cmd[0] = CmdId::EccKeyErase as u8;
            let slot_bytes = u16::from(slot.get()).to_le_bytes();
            cmd[1] = slot_bytes[0];
            cmd[2] = slot_bytes[1];
        }
        // No RES_DATA: expect an empty payload after the RESULT byte.
        self.run(3, Some(0), |_res_data| Ok(()))
    }

    /// Signs a 32-byte SHA-256 digest with the P-256 key in `slot` (ECDSA).
    ///
    /// Inherent twin of `SeCommands::ecdsa_sign`. The host pre-hashes the
    /// message: the chip has no hash engine. The digest length is fixed by the
    /// `&[u8; 32]` type, so no length check is needed. The slot range is
    /// enforced by `EccSlot::new`. A non-OK RESULT (InvalidKey on a missing or
    /// wrong-curve slot, Fail, Unauthorized, HardwareFail) is a valid
    /// authenticated reply: it surfaces as `L3Error::Result` and keeps the
    /// session live, mirroring libtropic. A bad tag, CRC, alarm, empty result,
    /// or wrong-size result poisons the session.
    pub(crate) fn ecdsa_sign
    (
        &mut self,
        slot: EccSlot,
        digest: &[u8; 32],
    )
    -> Result<Signature, SeError>
    {
        if self.state.is_poisoned()
        {
            return Err(SeError::SessionLost);
        }
        // CMD plaintext (48 bytes): CMD_ID || SLOT(u16 LE) || PADDING(13, 0) ||
        // MSG_HASH(32).
        {
            let cmd = self.cmd_plaintext();
            cmd[0] = CmdId::EcdsaSign as u8;
            let slot_bytes = u16::from(slot.get()).to_le_bytes();
            cmd[1] = slot_bytes[0];
            cmd[2] = slot_bytes[1];
            cmd[3..SIGN_CMD_HEADER].fill(0);
            cmd[SIGN_CMD_HEADER..ECDSA_CMD_LEN].copy_from_slice(digest);
        }
        // RES_DATA = PADDING(15) || R(32) || S(32) = 79 bytes (fixed).
        self.run(ECDSA_CMD_LEN, Some(SIGN_RES_DATA_LEN), parse_signature)
    }

    /// Signs `msg` with the Ed25519 key in `slot` (EdDSA).
    ///
    /// Inherent twin of `SeCommands::eddsa_sign`. The chip hashes the message
    /// internally (RFC 8032), so an empty message is valid. Validates
    /// `msg.len() <= EDDSA_MSG_MAX` up front, before any nonce, crypto, or chip
    /// traffic, so an oversize message returns `InvalidArgument` with the
    /// session untouched. The slot range is enforced by `EccSlot::new`. A non-OK
    /// RESULT (InvalidKey, Fail, Unauthorized, HardwareFail) is a valid
    /// authenticated reply: it surfaces as `L3Error::Result` and keeps the
    /// session live. A bad tag, CRC, alarm, empty result, or wrong-size result
    /// poisons the session.
    pub(crate) fn eddsa_sign
    (
        &mut self,
        slot: EccSlot,
        msg: &[u8],
    )
    -> Result<Signature, SeError>
    {
        // Argument checks come first: no nonce, no crypto, no chip traffic, so a
        // rejection here leaves the session untouched. Re-check poison up front
        // so a poisoned session rejects before argument work.
        if self.state.is_poisoned()
        {
            return Err(SeError::SessionLost);
        }
        if msg.len() > EDDSA_MSG_MAX
        {
            return Err(SeError::InvalidArgument);
        }
        // CMD plaintext (16 + msg.len() bytes): CMD_ID || SLOT(u16 LE) ||
        // PADDING(13, 0) || MSG.
        let plaintext_len = SIGN_CMD_HEADER
            .checked_add(msg.len())
            .ok_or(SeError::InvalidArgument)?;
        // Bound the wire footprint against the L3 buffer before the MSG copy,
        // mirroring rmem_write. Plaintext, the 2-byte CMD_SIZE prefix, and the
        // GCM tag must all fit. A 4096-byte message hits this bound exactly, so
        // the cmd[16..] copy stays in bounds.
        let needed = plaintext_len
            .checked_add(2 + crypto::GCM_TAG_LEN)
            .ok_or(SeError::InvalidArgument)?;
        if needed > self.l3.as_slice().len()
        {
            return Err(SeError::InvalidArgument);
        }
        {
            let cmd = self.cmd_plaintext();
            cmd[0] = CmdId::EddsaSign as u8;
            let slot_bytes = u16::from(slot.get()).to_le_bytes();
            cmd[1] = slot_bytes[0];
            cmd[2] = slot_bytes[1];
            cmd[3..SIGN_CMD_HEADER].fill(0);
            cmd[SIGN_CMD_HEADER..SIGN_CMD_HEADER + msg.len()].copy_from_slice(msg);
        }
        // RES_DATA = PADDING(15) || R(32) || S(32) = 79 bytes (fixed).
        self.run(plaintext_len, Some(SIGN_RES_DATA_LEN), parse_signature)
    }

    /// Runs MAC-and-Destroy on `slot` with `input`, returning the output.
    ///
    /// Inherent twin of `SeCommands::mac_and_destroy`. One L3 round-trip: the
    /// chip mixes `input` with the pre-overwrite slot value, returns a 32-byte
    /// output, and destroys the slot. The output is secret (it feeds the PIN
    /// KDF), so it returns wrapped in `MacAndDestroyOutput`, zeroized on drop.
    ///
    /// The slot range is enforced by `MacDestroySlot::new` and the input length
    /// by the `&[u8; 32]` type, so no runtime argument check is needed. A non-OK
    /// RESULT (Fail, Unauthorized, InvalidCmd) is a valid authenticated reply:
    /// it surfaces as `L3Error::Result` and keeps the session live, mirroring
    /// libtropic. A consumed slot still replies OK with a changed output;
    /// destruction is observed host-side, so Fail never means "slot consumed".
    /// A bad tag, CRC, alarm, empty result, or wrong-size result poisons the
    /// session.
    pub(crate) fn mac_and_destroy
    (
        &mut self,
        slot: MacDestroySlot,
        input: &[u8; 32],
    )
    -> Result<MacAndDestroyOutput, SeError>
    {
        if self.state.is_poisoned()
        {
            return Err(SeError::SessionLost);
        }
        // CMD plaintext (36 bytes): CMD_ID || SLOT(u16 LE) || PADDING(1, 0) ||
        // DATA_IN(32).
        {
            let cmd = self.cmd_plaintext();
            cmd[0] = CmdId::MacAndDestroy as u8;
            let slot_bytes = u16::from(slot.get()).to_le_bytes();
            cmd[1] = slot_bytes[0];
            cmd[2] = slot_bytes[1];
            cmd[3] = 0;
            cmd[MAC_DESTROY_CMD_HEADER..MAC_DESTROY_CMD_LEN].copy_from_slice(input);
        }
        // RES_DATA = PADDING(3) || DATA_OUT(32) = 35 bytes (fixed).
        self.run(MAC_DESTROY_CMD_LEN, Some(MAC_DESTROY_RES_DATA_LEN), parse_mac_destroy)
    }

    /// Erases R-Memory user-data `slot`, clearing it for a fresh write.
    ///
    /// Inherent twin of `SeCommands::rmem_erase`. An `rmem_write` requires the
    /// target slot to be empty, so a rewrite is erase-then-write. The slot range
    /// is enforced by `RMemSlot::new`. Returns `Ok(())` on an erased slot.
    ///
    /// The command has no RES_DATA, so it declares `Some(0)`: an OK result that
    /// carries any payload is a structural anomaly and poisons the session. A
    /// non-OK RESULT (FAIL, UNAUTHORIZED, ...) is a valid authenticated reply: it
    /// surfaces as `L3Error::Result` and keeps the session live, mirroring
    /// libtropic. A bad tag, CRC, alarm, or empty result poisons the session.
    pub(crate) fn rmem_erase(&mut self, slot: RMemSlot) -> Result<(), SeError>
    {
        if self.state.is_poisoned()
        {
            return Err(SeError::SessionLost);
        }
        // CMD plaintext (3 bytes): CMD_ID || UDATA_SLOT(u16 LE).
        {
            let cmd = self.cmd_plaintext();
            cmd[0] = CmdId::RMemDataErase as u8;
            let slot_bytes = slot.get().to_le_bytes();
            cmd[1] = slot_bytes[0];
            cmd[2] = slot_bytes[1];
        }
        // No RES_DATA: expect an empty payload after the RESULT byte.
        self.run(3, Some(0), |_res_data| Ok(()))
    }

    /// Initializes monotonic counter `idx` to `value`.
    ///
    /// Inherent twin of `SeCommands::mcounter_init`. The chip's anti-clone
    /// counters must be initialized before a decrement. The index range is
    /// enforced by `MCounterIdx`; any 32-bit `value` is accepted. Returns
    /// `Ok(())` on an initialized counter.
    ///
    /// PROVISIONING ONLY. Init can re-set a counter to any value, including a
    /// higher one, which would defeat the anti-rollback guarantee. The upper
    /// layer must call this only during provisioning and never during normal
    /// operation; the driver is a faithful transport and enforces no such policy.
    ///
    /// The command has no RES_DATA, so it declares `Some(0)`: an OK result
    /// carrying any payload poisons the session. A non-OK RESULT is a valid
    /// authenticated reply: it surfaces as `L3Error::Result` and keeps the
    /// session live, mirroring libtropic. A bad tag, CRC, alarm, or empty result
    /// poisons the session.
    pub(crate) fn mcounter_init(&mut self, idx: MCounterIdx, value: u32) -> Result<(), SeError>
    {
        if self.state.is_poisoned()
        {
            return Err(SeError::SessionLost);
        }
        // CMD plaintext (8 bytes): CMD_ID || MCOUNTER_INDEX(u16 LE) ||
        // PADDING(1, 0) || MCOUNTER_VAL(u32 LE). libtropic never writes the
        // padding byte, so zero it here explicitly.
        {
            let cmd = self.cmd_plaintext();
            cmd[0] = CmdId::McounterInit as u8;
            let index = u16::from(idx.get()).to_le_bytes();
            cmd[1] = index[0];
            cmd[2] = index[1];
            cmd[3] = 0;
            cmd[MCOUNTER_INIT_HEADER..MCOUNTER_INIT_CMD_LEN]
                .copy_from_slice(&value.to_le_bytes());
        }
        // No RES_DATA: expect an empty payload after the RESULT byte.
        self.run(MCOUNTER_INIT_CMD_LEN, Some(0), |_res_data| Ok(()))
    }

    /// Decrements monotonic counter `idx` by one.
    ///
    /// Inherent twin of `SeCommands::mcounter_update`. The decrement is fixed at
    /// one (the command carries no amount). The index range is enforced by
    /// `MCounterIdx`. Returns `Ok(())` on a successful decrement.
    ///
    /// Two non-OK RESULTs are expected and recoverable, mirroring libtropic: a
    /// counter already at zero replies `UpdateErr` (a decrement would underflow),
    /// and an uninitialized or locked counter replies `CounterInvalid`. Both
    /// surface as `L3Error::Result` and keep the session live. The command has no
    /// RES_DATA, so it declares `Some(0)`: an OK result carrying any payload
    /// poisons the session. A bad tag, CRC, alarm, or empty result poisons the
    /// session.
    pub(crate) fn mcounter_update(&mut self, idx: MCounterIdx) -> Result<(), SeError>
    {
        if self.state.is_poisoned()
        {
            return Err(SeError::SessionLost);
        }
        // CMD plaintext (3 bytes): CMD_ID || MCOUNTER_INDEX(u16 LE).
        {
            let cmd = self.cmd_plaintext();
            cmd[0] = CmdId::McounterUpdate as u8;
            let index = u16::from(idx.get()).to_le_bytes();
            cmd[1] = index[0];
            cmd[2] = index[1];
        }
        // No RES_DATA: expect an empty payload after the RESULT byte.
        self.run(3, Some(0), |_res_data| Ok(()))
    }
}

/// The high-level command port over an active session.
///
/// Each method delegates to the inherent twin, which carries the gate, the
/// teardown duties, and the byte layout. The trait keeps transport and crypto
/// detail out of the CTAP2 / OpenPGP / PKCS#11 layers above.
impl<SPI, W> SeCommands for Tropic01<SPI, W, ActiveSession>
where
    SPI: SpiDevice,
    W: SeWait,
{
    fn ecc_key_generate
    (
        &mut self,
        slot: EccSlot,
        curve: EccCurve,
    )
    -> Result<(), SeError>
    {
        self.ecc_key_generate(slot, curve)
    }

    fn ecc_public_key
    (
        &mut self,
        slot: EccSlot,
    )
    -> Result<EccPublicKey, SeError>
    {
        self.ecc_public_key(slot)
    }

    fn ecc_key_store
    (
        &mut self,
        slot: EccSlot,
        curve: EccCurve,
        private_key: &Zeroizing<[u8; 32]>,
    )
    -> Result<(), SeError>
    {
        self.ecc_key_store(slot, curve, private_key)
    }

    fn ecc_key_erase
    (
        &mut self,
        slot: EccSlot,
    )
    -> Result<(), SeError>
    {
        self.ecc_key_erase(slot)
    }

    fn ecdsa_sign
    (
        &mut self,
        slot: EccSlot,
        digest: &[u8; 32],
    )
    -> Result<Signature, SeError>
    {
        self.ecdsa_sign(slot, digest)
    }

    fn eddsa_sign
    (
        &mut self,
        slot: EccSlot,
        message: &[u8],
    )
    -> Result<Signature, SeError>
    {
        self.eddsa_sign(slot, message)
    }

    fn random_into
    (
        &mut self,
        out: &mut [u8],
    )
    -> Result<usize, SeError>
    {
        self.random_into(out)
    }

    fn rmem_read_into
    (
        &mut self,
        slot: RMemSlot,
        out: &mut [u8],
    )
    -> Result<usize, SeError>
    {
        self.rmem_read_into(slot, out)
    }

    fn rmem_write
    (
        &mut self,
        slot: RMemSlot,
        data: &[u8],
    )
    -> Result<(), SeError>
    {
        self.rmem_write(slot, data)
    }

    fn mcounter_get
    (
        &mut self,
        idx: MCounterIdx,
    )
    -> Result<u32, SeError>
    {
        self.mcounter_get(idx)
    }

    fn mac_and_destroy
    (
        &mut self,
        slot: MacDestroySlot,
        input: &[u8; 32],
    )
    -> Result<MacAndDestroyOutput, SeError>
    {
        self.mac_and_destroy(slot, input)
    }

    fn rmem_erase
    (
        &mut self,
        slot: RMemSlot,
    )
    -> Result<(), SeError>
    {
        self.rmem_erase(slot)
    }

    fn mcounter_init
    (
        &mut self,
        idx: MCounterIdx,
        value: u32,
    )
    -> Result<(), SeError>
    {
        self.mcounter_init(idx, value)
    }

    fn mcounter_update
    (
        &mut self,
        idx: MCounterIdx,
    )
    -> Result<(), SeError>
    {
        self.mcounter_update(idx)
    }
}

/// Parses a sign result `PADDING(15) || R(32) || S(32)` into a `Signature`.
///
/// `run` proves `res_data.len() == SIGN_RES_DATA_LEN` via `expected_res_data_len`
/// before calling this, so the `take` bounds hold structurally. Skips the 15
/// padding bytes, then copies R || S into the 64-byte signature. Rejects any
/// trailing byte so a caller passing `None` cannot silently accept an oversize
/// result: a too-long result is a structural anomaly, so fail closed.
fn parse_signature(res_data: &[u8]) -> Result<Signature, L3Error>
{
    let (_padding, sig) = take(res_data, SIGN_RES_PADDING)?;
    let (tail, bytes) = take_array::<64>(sig)?;
    if !tail.is_empty()
    {
        return Err(L3Error::Oversize);
    }
    Ok(Signature(bytes))
}

/// Parses a MAC-and-Destroy result `PADDING(3) || DATA_OUT(32)`.
///
/// `run` proves `res_data.len() == MAC_DESTROY_RES_DATA_LEN` via
/// `expected_res_data_len` before calling this, so the `take` bounds hold
/// structurally. Skips the 3 padding bytes, then copies DATA_OUT into the
/// secret output value. Rejects any trailing byte so a caller passing `None`
/// cannot silently accept an oversize result: fail closed.
fn parse_mac_destroy(res_data: &[u8]) -> Result<MacAndDestroyOutput, L3Error>
{
    let (_padding, rest) = take(res_data, MAC_DESTROY_RES_PADDING)?;
    let (tail, data_out) = take_array::<32>(rest)?;
    if !tail.is_empty()
    {
        return Err(L3Error::Oversize);
    }
    Ok(MacAndDestroyOutput::new(data_out))
}

/// Maximum R-Memory user-data DATA length in bytes (target firmware >= 2.0.0).
///
/// Source: libtropic `R_MEM_DATA_SIZE_MAX`.
const R_MEM_DATA_MAX: usize = 475;

/// Maximum ECC public-key length in bytes (P-256, raw X || Y).
///
/// Ed25519 returns 32 bytes. `EccPublicKey` backs every key with this many
/// bytes and trims to the curve length on read.
const ECC_PUBKEY_MAX: usize = 64;

/// Padding bytes between the ORIGIN field and the PUBKEY in an EccKeyRead
/// result (CURVE(1) || ORIGIN(1) || PADDING(13) || PUBKEY).
///
/// Source: libtropic `struct lt_l3_ecc_key_read_res_t` (`padding[13]`).
const ECC_READ_PADDING: usize = 13;

/// Byte offset of the imported key within the EccKeyStore command plaintext.
///
/// Layout: CMD_ID(1) || SLOT(2) || CURVE(1) || PADDING(12) || K(32). Source:
/// libtropic `struct lt_l3_ecc_key_store_cmd_t` (`padding[12]` before `k[32]`).
const ECC_STORE_KEY_OFFSET: usize = 16;

/// EccKeyStore command plaintext length: header+padding(16) || K(32) = 48.
///
/// The imported scalar is 32 bytes for both curves (libtropic
/// `TR01_CURVE_PRIVKEY_LEN`). Total matches `TR01_L3_ECC_KEY_STORE_CMD_SIZE`.
const ECC_STORE_CMD_LEN: usize = ECC_STORE_KEY_OFFSET + 32;

/// Padding bytes between the SLOT field and the message in a sign command
/// (CMD_ID(1) || SLOT(2) || PADDING(13) || MSG...).
///
/// Source: libtropic `struct lt_l3_ecdsa_sign_cmd_t` / `lt_l3_eddsa_sign_cmd_t`
/// (`padding[13]`).
const SIGN_CMD_PADDING: usize = 13;

/// Sign-command header length in bytes: CMD_ID(1) || SLOT(2) || PADDING(13).
///
/// The message (ECDSA digest or EdDSA payload) follows this header.
const SIGN_CMD_HEADER: usize = 3 + SIGN_CMD_PADDING;

/// ECDSA sign command plaintext length: header(16) || MSG_HASH(32).
const ECDSA_CMD_LEN: usize = SIGN_CMD_HEADER + 32;

/// Padding bytes before R in a sign result (PADDING(15) || R(32) || S(32)).
///
/// Source: libtropic `struct lt_l3_ecdsa_sign_res_t` and
/// `struct lt_l3_eddsa_sign_res_t` (`padding[15]`). The two result structs are
/// byte-identical, which is what justifies the shared `parse_signature`.
const SIGN_RES_PADDING: usize = 15;

/// Sign-result RES_DATA length in bytes: PADDING(15) || R(32) || S(32).
const SIGN_RES_DATA_LEN: usize = SIGN_RES_PADDING + 64;

/// Maximum EdDSA message length in bytes.
///
/// Source: libtropic `TR01_L3_EDDSA_SIGN_CMD_MSG_LEN_MAX`. A 4096-byte message
/// yields a 4112-byte plaintext, which fills the L3 buffer to capacity.
const EDDSA_MSG_MAX: usize = 4096;

/// MAC-and-Destroy command header length: CMD_ID(1) || SLOT(2) || PADDING(1).
///
/// Source: libtropic `struct lt_l3_mac_and_destroy_cmd_t` (`slot` u16, then
/// `padding` before `data_in`). DATA_IN(32) follows this header.
const MAC_DESTROY_CMD_HEADER: usize = 4;

/// MAC-and-Destroy command plaintext length: header(4) || DATA_IN(32).
const MAC_DESTROY_CMD_LEN: usize = MAC_DESTROY_CMD_HEADER + 32;

/// Padding bytes before DATA_OUT in a MAC-and-Destroy result.
///
/// Source: libtropic `struct lt_l3_mac_and_destroy_res_t` (`padding[3]`).
const MAC_DESTROY_RES_PADDING: usize = 3;

/// MAC-and-Destroy result RES_DATA length: PADDING(3) || DATA_OUT(32).
const MAC_DESTROY_RES_DATA_LEN: usize = MAC_DESTROY_RES_PADDING + 32;

/// McounterInit command header length: CMD_ID(1) || MCOUNTER_INDEX(2) ||
/// PADDING(1). The u32 init value follows this header.
///
/// Source: libtropic `struct lt_l3_mcounter_init_cmd_t` (index u16, then a
/// padding byte before `mcounter_val`).
const MCOUNTER_INIT_HEADER: usize = 4;

/// McounterInit command plaintext length: header(4) || MCOUNTER_VAL(u32 LE).
///
/// Source: libtropic `TR01_L3_MCOUNTER_INIT_CMD_SIZE` (CMD_ID + index + padding
/// + 4-byte value = 8).
const MCOUNTER_INIT_CMD_LEN: usize = MCOUNTER_INIT_HEADER + 4;

// Compile-time invariant: the maximum EdDSA wire packet fills the L3 buffer
// exactly. The packet is 2 (L3 CMD_SIZE prefix) || SIGN_CMD_HEADER ||
// EDDSA_MSG_MAX || GCM_TAG_LEN. If any term drifts, the build fails here
// instead of silently overflowing the eddsa_sign cmd[16..] copy. The runtime
// bound in eddsa_sign mirrors this for the local copy.
const _: () =
{
    assert!(
        2 + SIGN_CMD_HEADER + EDDSA_MSG_MAX + crypto::GCM_TAG_LEN
            == crate::buf::L3_FRAME_MAX
    );
};

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
    use crate::test_support::l2_frame;
    use crate::test_support::vectors;
    use crate::test_support::ChipFault;
    use crate::test_support::ChipMockSpi;
    use crate::test_support::MockSpi;
    use crate::test_support::MockWait;
    use crate::test_support::RecordingSpi;

    #[test]
    fn reboot_request_frame_matches_libtropic_golden()
    {
        // Byte-exact Startup_Req for TR01_REBOOT, captured from real libtropic:
        // REQ_ID 0xB3, REQ_LEN 1, STARTUP_ID 0x01, CRC 0xF98F.
        let mut buf = [0u8; L2_FRAME_MAX];
        let n = frame::build_request(L2ReqId::Startup as u8, &[StartupId::Reboot.wire_byte()], &mut buf)
            .unwrap();
        assert_eq!(&buf[..n], &[0xB3, 0x01, 0x01, 0xF9, 0x8F]);
        assert_eq!(StartupId::MaintenanceReboot.wire_byte(), 0x03);
    }

    #[test]
    fn reboot_succeeds_on_empty_request_ok_ack()
    {
        let acks = std::vec![l2_frame(L2Status::RequestOk as u8, &[])];
        let mut dev = Tropic01::new(RecordingSpi::new(acks), MockWait::new());
        assert!(dev.reboot(StartupId::Reboot).is_ok());
    }

    #[test]
    fn reboot_rejects_a_nonempty_ack()
    {
        // A Startup ack must carry no data; a non-empty one is a malformed reply.
        let acks = std::vec![l2_frame(L2Status::RequestOk as u8, &[0xAA])];
        let mut dev = Tropic01::new(RecordingSpi::new(acks), MockWait::new());
        assert_eq!(dev.reboot(StartupId::Reboot), Err(SeError::L2(L2Error::BadFrame)));
    }

    #[test]
    fn reboot_rejects_a_continuation_status()
    {
        // Only RequestOk acknowledges a Startup_Req; a *Cont status is anomalous.
        let acks = std::vec![l2_frame(L2Status::RequestCont as u8, &[])];
        let mut dev = Tropic01::new(RecordingSpi::new(acks), MockWait::new());
        assert_eq!(dev.reboot(StartupId::Reboot), Err(SeError::L2(L2Error::BadFrame)));
    }

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

    /// Builds an R-Memory slot index, panicking only in test code on a bad
    /// constant.
    fn rslot(value: u16) -> RMemSlot
    {
        RMemSlot::new(value).expect("test rmem slot out of range")
    }

    #[test]
    fn rmem_read_round_trips_known_bytes()
    {
        let mut dev = open(ChipFault::None);
        let stored = b"patina rmem payload";
        dev.spi_mut().set_rmem_slot(7, stored);
        let mut out = [0u8; R_MEM_DATA_MAX];
        let n = dev.rmem_read_into(rslot(7), &mut out).unwrap();
        assert_eq!(n, stored.len());
        assert_eq!(&out[..n], stored);
        assert_eq!(dev.spi_ref().nonces(), (1, 1));
    }

    #[test]
    fn rmem_read_handles_a_near_max_length_payload()
    {
        // A 475-byte read forces the result across multiple L2 chunks. The
        // driver must reassemble it and copy every byte.
        let mut dev = open(ChipFault::None);
        let mut stored = [0u8; R_MEM_DATA_MAX];
        for (i, b) in stored.iter_mut().enumerate()
        {
            *b = (i as u8).wrapping_mul(3).wrapping_add(1);
        }
        dev.spi_mut().set_rmem_slot(0, &stored);
        let mut out = [0u8; R_MEM_DATA_MAX];
        let n = dev.rmem_read_into(rslot(0), &mut out).unwrap();
        assert_eq!(n, R_MEM_DATA_MAX);
        assert_eq!(out, stored);
        assert_eq!(dev.spi_ref().nonces(), (1, 1));
    }

    #[test]
    fn rmem_read_empty_slot_returns_zero()
    {
        // An unset slot reads back RESULT=OK with no DATA. The driver reports
        // Ok(0) and keeps the session live.
        let mut dev = open(ChipFault::None);
        let mut out = [0u8; R_MEM_DATA_MAX];
        let n = dev.rmem_read_into(rslot(3), &mut out).unwrap();
        assert_eq!(n, 0);
        assert_eq!(dev.spi_ref().nonces(), (1, 1));
        // The session stays live: a follow-up read still reaches the chip.
        let before = dev.spi_ref().transaction_count();
        assert_eq!(dev.rmem_read_into(rslot(3), &mut out), Ok(0));
        assert!(dev.spi_ref().transaction_count() > before, "chip traffic continues");
    }

    #[test]
    fn rmem_read_too_small_out_is_rejected_before_any_traffic()
    {
        // A read can return up to R_MEM_DATA_MAX DATA bytes, so out must hold at
        // least that many. A shorter out is rejected up front, before any nonce
        // or chip traffic, leaving the session live (matching libtropic's
        // LT_PARAM_ERR, which does not invalidate the session).
        let mut dev = open(ChipFault::None);
        dev.spi_mut().set_rmem_slot(5, b"twelve bytes");
        let before = dev.spi_ref().transaction_count();
        let mut out = [0u8; R_MEM_DATA_MAX - 1];
        assert_eq!(dev.rmem_read_into(rslot(5), &mut out), Err(SeError::BufferTooSmall));
        // Rejected up front: no nonce burned, no SPI traffic, session intact.
        assert_eq!(dev.spi_ref().transaction_count(), before);
        assert_eq!(dev.spi_ref().nonces(), (0, 0), "nonce did not move");
        // The session is still usable: a full-size buffer reads the slot back.
        let mut ok_out = [0u8; R_MEM_DATA_MAX];
        let n = dev.rmem_read_into(rslot(5), &mut ok_out).unwrap();
        assert_eq!(&ok_out[..n], b"twelve bytes");
    }

    #[test]
    fn rmem_read_wrong_size_result_poisons_session()
    {
        // An authenticated OK result whose RES_DATA is one byte short truncates
        // below the 3 padding bytes only at the boundary. Here the generic
        // ResultWrongSize fault drops the last byte, leaving DATA one short of
        // the stored content but still structurally valid. To exercise the
        // padding-too-short anomaly, store nothing so RES_DATA = PADDING(3),
        // then drop a byte: PADDING(2) fails the take(3) bound and poisons.
        let mut dev = open(ChipFault::ResultWrongSize);
        let mut out = [0u8; R_MEM_DATA_MAX];
        assert_eq!
        (
            dev.rmem_read_into(rslot(0), &mut out),
            Err(SeError::L3(L3Error::Parse(ParseError::UnexpectedEnd)))
        );
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn rmem_read_bad_tag_poisons_session()
    {
        let mut dev = open(ChipFault::BadResultTag);
        let mut out = [0u8; R_MEM_DATA_MAX];
        assert_eq!(dev.rmem_read_into(rslot(0), &mut out), Err(SeError::L3(L3Error::Tag)));
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn rmem_read_l2_tag_err_poisons_session()
    {
        let mut dev = open(ChipFault::L2TagErr);
        let mut out = [0u8; R_MEM_DATA_MAX];
        let r = dev.rmem_read_into(rslot(0), &mut out);
        assert!(matches!(r, Err(SeError::L2(_))), "got {r:?}");
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn rmem_read_l2_crc_err_poisons_session()
    {
        let mut dev = open(ChipFault::L2CrcErr);
        let mut out = [0u8; R_MEM_DATA_MAX];
        assert_eq!(dev.rmem_read_into(rslot(0), &mut out), Err(SeError::L2(L2Error::Crc)));
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn rmem_read_alarm_poisons_session()
    {
        let mut dev = open(ChipFault::Alarm);
        let mut out = [0u8; R_MEM_DATA_MAX];
        assert_eq!
        (
            dev.rmem_read_into(rslot(0), &mut out),
            Err(SeError::L2(L2Error::L1(L1Error::Alarm)))
        );
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn rmem_read_empty_authenticated_result_poisons_session()
    {
        let mut dev = open(ChipFault::EmptyResult);
        let mut out = [0u8; R_MEM_DATA_MAX];
        assert_eq!
        (
            dev.rmem_read_into(rslot(0), &mut out),
            Err(SeError::L3(L3Error::Parse(ParseError::UnexpectedEnd)))
        );
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn rmem_write_round_trips_and_stores_payload()
    {
        let mut dev = open(ChipFault::None);
        let data = b"stored via write";
        assert_eq!(dev.rmem_write(rslot(9), data), Ok(()));
        assert_eq!(dev.spi_ref().nonces(), (1, 1));
        assert_eq!(dev.spi_ref().rmem_slot(9), Some(&data[..]));
    }

    #[test]
    fn rmem_write_near_max_payload_round_trips()
    {
        // A 475-byte write forces the command across multiple L2 chunks on the
        // send path and stores the full payload.
        let mut dev = open(ChipFault::None);
        let mut data = [0u8; R_MEM_DATA_MAX];
        for (i, b) in data.iter_mut().enumerate()
        {
            *b = (i as u8).wrapping_mul(7).wrapping_add(2);
        }
        assert_eq!(dev.rmem_write(rslot(1), &data), Ok(()));
        assert_eq!(dev.spi_ref().rmem_slot(1), Some(&data[..]));
        assert_eq!(dev.spi_ref().nonces(), (1, 1));
    }

    #[test]
    fn rmem_write_rejects_empty_payload_before_any_traffic()
    {
        let mut dev = open(ChipFault::None);
        let before = dev.spi_ref().transaction_count();
        assert_eq!(dev.rmem_write(rslot(0), &[]), Err(SeError::InvalidArgument));
        // Rejected up front: no nonce burned, no SPI traffic, session intact.
        assert_eq!(dev.spi_ref().transaction_count(), before);
        assert_eq!(dev.spi_ref().nonces(), (0, 0), "nonce did not move");
        // The session is still usable.
        assert_eq!(dev.rmem_write(rslot(0), b"ok"), Ok(()));
    }

    #[test]
    fn rmem_write_rejects_oversize_payload_before_any_traffic()
    {
        let mut dev = open(ChipFault::None);
        let before = dev.spi_ref().transaction_count();
        let data = [0u8; R_MEM_DATA_MAX + 1];
        assert_eq!(dev.rmem_write(rslot(0), &data), Err(SeError::InvalidArgument));
        // Rejected up front: no nonce burned, no SPI traffic, session intact.
        assert_eq!(dev.spi_ref().transaction_count(), before);
        assert_eq!(dev.spi_ref().nonces(), (0, 0), "nonce did not move");
    }

    #[test]
    fn rmem_write_slot_not_empty_is_recoverable()
    {
        // SlotNotEmpty (0x10) is a known L3Status: run maps it to a recoverable
        // L3Error::Result and keeps the session live, so the caller can erase
        // and retry. No poison, nonces stay in lockstep.
        let mut dev = open(ChipFault::SlotNotEmpty);
        assert_eq!
        (
            dev.rmem_write(rslot(2), b"payload"),
            Err(SeError::L3(L3Error::Result(L3Status::SlotNotEmpty)))
        );
        let before = dev.spi_ref().transaction_count();
        let r = dev.rmem_write(rslot(2), b"payload");
        assert_eq!(r, Err(SeError::L3(L3Error::Result(L3Status::SlotNotEmpty))));
        assert!(dev.spi_ref().transaction_count() > before, "chip traffic continues");
        assert_eq!(dev.spi_ref().nonces(), (2, 2), "nonces stay in lockstep");
    }

    #[test]
    fn rmem_write_extra_result_byte_poisons_session()
    {
        // rmem_write is a Some(0) command: it expects no RES_DATA. One
        // unexpected byte trips the expected-length check and poisons. This
        // guards against a regression to None with a trivial closure.
        let mut dev = open(ChipFault::ExtraResultByte);
        assert_eq!
        (
            dev.rmem_write(rslot(0), b"x"),
            Err(SeError::L3(L3Error::Oversize))
        );
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn rmem_write_bad_tag_poisons_session()
    {
        let mut dev = open(ChipFault::BadResultTag);
        assert_eq!(dev.rmem_write(rslot(0), b"x"), Err(SeError::L3(L3Error::Tag)));
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn rmem_write_l2_crc_err_poisons_session()
    {
        let mut dev = open(ChipFault::L2CrcErr);
        assert_eq!(dev.rmem_write(rslot(0), b"x"), Err(SeError::L2(L2Error::Crc)));
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn rmem_write_alarm_poisons_session()
    {
        let mut dev = open(ChipFault::Alarm);
        assert_eq!
        (
            dev.rmem_write(rslot(0), b"x"),
            Err(SeError::L2(L2Error::L1(L1Error::Alarm)))
        );
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn rmem_l3_buffer_is_wiped_after_a_successful_read()
    {
        let mut dev = open(ChipFault::None);
        dev.spi_mut().set_rmem_slot(4, b"wipe me");
        let mut out = [0u8; R_MEM_DATA_MAX];
        dev.rmem_read_into(rslot(4), &mut out).unwrap();
        assert!(dev.l3.as_slice().iter().all(|&b| b == 0), "plaintext residue");
    }

    #[test]
    fn mixed_read_write_sequence_keeps_nonces_in_lockstep()
    {
        // A write, then a ping, then a read of the written slot each advance
        // both nonces once. The read returns exactly what the write stored,
        // proving the round-trips stayed in step across the mixed sequence.
        let mut dev = open(ChipFault::None);
        let payload = b"mixed sequence";
        let mut buf = [0u8; R_MEM_DATA_MAX];
        assert_eq!(dev.rmem_write(rslot(6), payload), Ok(()));
        assert_eq!(dev.spi_ref().nonces(), (1, 1));
        dev.ping_into(b"between", &mut buf).unwrap();
        assert_eq!(dev.spi_ref().nonces(), (2, 2));
        let n = dev.rmem_read_into(rslot(6), &mut buf).unwrap();
        assert_eq!(dev.spi_ref().nonces(), (3, 3));
        assert_eq!(&buf[..n], payload);
    }

    /// Builds an ECC slot index, panicking only in test code on a bad constant.
    fn eslot(value: u8) -> EccSlot
    {
        EccSlot::new(value).expect("test ecc slot out of range")
    }

    #[test]
    fn ecc_key_generate_round_trips_both_curves()
    {
        let mut dev = open(ChipFault::None);
        assert_eq!(dev.ecc_key_generate(eslot(0), EccCurve::P256), Ok(()));
        assert_eq!(dev.spi_ref().nonces(), (1, 1));
        assert_eq!(dev.ecc_key_generate(eslot(31), EccCurve::Ed25519), Ok(()));
        assert_eq!(dev.spi_ref().nonces(), (2, 2));
    }

    #[test]
    fn ecc_key_generate_slot_not_empty_is_recoverable()
    {
        // SlotNotEmpty is a known L3Status: run maps it to a recoverable
        // L3Error::Result and keeps the session live. No poison.
        let mut dev = open(ChipFault::SlotNotEmpty);
        assert_eq!
        (
            dev.ecc_key_generate(eslot(2), EccCurve::P256),
            Err(SeError::L3(L3Error::Result(L3Status::SlotNotEmpty)))
        );
        let before = dev.spi_ref().transaction_count();
        let r = dev.ecc_key_generate(eslot(2), EccCurve::P256);
        assert_eq!(r, Err(SeError::L3(L3Error::Result(L3Status::SlotNotEmpty))));
        assert!(dev.spi_ref().transaction_count() > before, "chip traffic continues");
        assert_eq!(dev.spi_ref().nonces(), (2, 2), "nonces stay in lockstep");
    }

    #[test]
    fn ecc_key_generate_empty_result_poisons_session()
    {
        let mut dev = open(ChipFault::EmptyResult);
        assert_eq!
        (
            dev.ecc_key_generate(eslot(0), EccCurve::P256),
            Err(SeError::L3(L3Error::Parse(ParseError::UnexpectedEnd)))
        );
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn ecc_key_generate_extra_result_byte_poisons_session()
    {
        // ecc_key_generate is a Some(0) command: it expects no RES_DATA. One
        // unexpected byte trips the expected-length check and poisons. This
        // guards against a regression to None with a trivial closure.
        let mut dev = open(ChipFault::ExtraResultByte);
        assert_eq!
        (
            dev.ecc_key_generate(eslot(0), EccCurve::P256),
            Err(SeError::L3(L3Error::Oversize))
        );
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn ecc_key_generate_bad_tag_poisons_session()
    {
        let mut dev = open(ChipFault::BadResultTag);
        assert_eq!
        (
            dev.ecc_key_generate(eslot(0), EccCurve::P256),
            Err(SeError::L3(L3Error::Tag))
        );
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn ecc_key_generate_l2_crc_err_poisons_session()
    {
        let mut dev = open(ChipFault::L2CrcErr);
        assert_eq!
        (
            dev.ecc_key_generate(eslot(0), EccCurve::P256),
            Err(SeError::L2(L2Error::Crc))
        );
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn ecc_key_generate_alarm_poisons_session()
    {
        let mut dev = open(ChipFault::Alarm);
        assert_eq!
        (
            dev.ecc_key_generate(eslot(0), EccCurve::P256),
            Err(SeError::L2(L2Error::L1(L1Error::Alarm)))
        );
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn ecc_public_key_reads_p256_64_bytes()
    {
        let mut dev = open(ChipFault::None);
        let mut pubkey = [0u8; 64];
        for (i, b) in pubkey.iter_mut().enumerate()
        {
            *b = (i as u8).wrapping_mul(5).wrapping_add(1);
        }
        dev.spi_mut().set_ecc_pubkey(0x01, &pubkey);
        let pk = dev.ecc_public_key(eslot(4)).unwrap();
        assert_eq!(pk.curve(), EccCurve::P256);
        assert_eq!(pk.bytes().len(), 64);
        assert_eq!(pk.bytes(), &pubkey);
        assert_eq!(dev.spi_ref().nonces(), (1, 1));
    }

    #[test]
    fn ecc_public_key_reads_ed25519_32_bytes()
    {
        let mut dev = open(ChipFault::None);
        let mut pubkey = [0u8; 32];
        for (i, b) in pubkey.iter_mut().enumerate()
        {
            *b = (i as u8).wrapping_mul(9).wrapping_add(7);
        }
        dev.spi_mut().set_ecc_pubkey(0x02, &pubkey);
        let pk = dev.ecc_public_key(eslot(10)).unwrap();
        assert_eq!(pk.curve(), EccCurve::Ed25519);
        assert_eq!(pk.bytes().len(), 32);
        assert_eq!(pk.bytes(), &pubkey);
        assert_eq!(dev.spi_ref().nonces(), (1, 1));
    }

    #[test]
    fn ecc_public_key_invalid_key_is_recoverable()
    {
        // InvalidKey (0x12) = empty or corrupt slot: a valid authenticated
        // reply. The session stays live and the nonces stay in step.
        let mut dev = open(ChipFault::InvalidKey);
        assert_eq!
        (
            dev.ecc_public_key(eslot(0)),
            Err(SeError::L3(L3Error::Result(L3Status::InvalidKey)))
        );
        let before = dev.spi_ref().transaction_count();
        let r = dev.ecc_public_key(eslot(0));
        assert_eq!(r, Err(SeError::L3(L3Error::Result(L3Status::InvalidKey))));
        assert!(dev.spi_ref().transaction_count() > before, "chip traffic continues");
        assert_eq!(dev.spi_ref().nonces(), (2, 2), "nonces stay in lockstep");
    }

    #[test]
    fn ecc_public_key_unknown_curve_byte_poisons_session()
    {
        // An unknown CURVE byte on an authenticated OK result is a structural
        // anomaly. The parse closure returns Err, which poisons the session.
        let mut dev = open(ChipFault::None);
        dev.spi_mut().set_ecc_pubkey(0x07, &[0u8; 32]);
        assert_eq!
        (
            dev.ecc_public_key(eslot(0)),
            Err(SeError::L3(L3Error::Parse(ParseError::InvalidValue)))
        );
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn ecc_public_key_length_mismatch_poisons_session()
    {
        // CURVE says Ed25519 (expects 32) but the PUBKEY is 33 bytes: a
        // structural anomaly. The closure returns Oversize, which poisons.
        let mut dev = open(ChipFault::None);
        dev.spi_mut().set_ecc_pubkey(0x02, &[0u8; 33]);
        assert_eq!
        (
            dev.ecc_public_key(eslot(0)),
            Err(SeError::L3(L3Error::Oversize))
        );
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn ecc_public_key_truncated_header_poisons_session()
    {
        // A RES_DATA shorter than the 15-byte CURVE||ORIGIN||PADDING(13) header
        // fails the take bound in the closure, which poisons the session.
        let mut dev = open(ChipFault::None);
        dev.spi_mut().set_ecc_pubkey(0x02, &[]);
        dev.spi_mut().set_ecc_read_pad(11); // header = 1 + 1 + 11 = 13 < 15
        assert_eq!
        (
            dev.ecc_public_key(eslot(0)),
            Err(SeError::L3(L3Error::Parse(ParseError::UnexpectedEnd)))
        );
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn ecc_public_key_bad_tag_poisons_session()
    {
        let mut dev = open(ChipFault::BadResultTag);
        assert_eq!
        (
            dev.ecc_public_key(eslot(0)),
            Err(SeError::L3(L3Error::Tag))
        );
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn ecc_public_key_alarm_poisons_session()
    {
        let mut dev = open(ChipFault::Alarm);
        assert_eq!
        (
            dev.ecc_public_key(eslot(0)),
            Err(SeError::L2(L2Error::L1(L1Error::Alarm)))
        );
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn ecc_public_key_empty_result_poisons_session()
    {
        let mut dev = open(ChipFault::EmptyResult);
        assert_eq!
        (
            dev.ecc_public_key(eslot(0)),
            Err(SeError::L3(L3Error::Parse(ParseError::UnexpectedEnd)))
        );
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn ecc_l3_buffer_is_wiped_after_a_successful_read()
    {
        let mut dev = open(ChipFault::None);
        dev.spi_mut().set_ecc_pubkey(0x02, &[0xAB; 32]);
        dev.ecc_public_key(eslot(0)).unwrap();
        assert!(dev.l3.as_slice().iter().all(|&b| b == 0), "plaintext residue");
    }

    #[test]
    fn mixed_ecc_sequence_keeps_nonces_in_lockstep()
    {
        // A keygen, a public-key read, then a ping each advance both nonces
        // once across the mixed sequence.
        let mut dev = open(ChipFault::None);
        dev.spi_mut().set_ecc_pubkey(0x01, &[0x11; 64]);
        let mut buf = [0u8; 64];
        assert_eq!(dev.ecc_key_generate(eslot(0), EccCurve::P256), Ok(()));
        assert_eq!(dev.spi_ref().nonces(), (1, 1));
        let pk = dev.ecc_public_key(eslot(0)).unwrap();
        assert_eq!(pk.curve(), EccCurve::P256);
        assert_eq!(pk.bytes().len(), 64);
        assert_eq!(dev.spi_ref().nonces(), (2, 2));
        dev.ping_into(b"between", &mut buf).unwrap();
        assert_eq!(dev.spi_ref().nonces(), (3, 3));
    }

    /// Builds a deterministic 32-byte private scalar for the import tests.
    fn sample_privkey() -> Zeroizing<[u8; 32]>
    {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate()
        {
            *b = (i as u8).wrapping_mul(3).wrapping_add(1);
        }
        Zeroizing::new(k)
    }

    #[test]
    fn ecc_key_store_round_trips_both_curves()
    {
        let mut dev = open(ChipFault::None);
        let key = sample_privkey();
        assert_eq!(dev.ecc_key_store(eslot(0), EccCurve::P256, &key), Ok(()));
        assert_eq!(dev.spi_ref().nonces(), (1, 1));
        assert_eq!(dev.ecc_key_store(eslot(31), EccCurve::Ed25519, &key), Ok(()));
        assert_eq!(dev.spi_ref().nonces(), (2, 2));
    }

    #[test]
    fn ecc_key_store_slot_not_empty_is_recoverable()
    {
        // SlotNotEmpty (0x10): the target slot already holds a key. A valid
        // authenticated reply that keeps the session live.
        let mut dev = open(ChipFault::SlotNotEmpty);
        let key = sample_privkey();
        assert_eq!
        (
            dev.ecc_key_store(eslot(2), EccCurve::Ed25519, &key),
            Err(SeError::L3(L3Error::Result(L3Status::SlotNotEmpty)))
        );
        let before = dev.spi_ref().transaction_count();
        let r = dev.ecc_key_store(eslot(2), EccCurve::Ed25519, &key);
        assert_eq!(r, Err(SeError::L3(L3Error::Result(L3Status::SlotNotEmpty))));
        assert!(dev.spi_ref().transaction_count() > before, "chip traffic continues");
        assert_eq!(dev.spi_ref().nonces(), (2, 2), "nonces stay in lockstep");
    }

    #[test]
    fn ecc_key_store_invalid_key_is_recoverable()
    {
        // InvalidKey (0x12): the imported scalar is malformed (e.g. out of range
        // for the curve). Recoverable: the session stays live.
        let mut dev = open(ChipFault::InvalidKey);
        let key = sample_privkey();
        assert_eq!
        (
            dev.ecc_key_store(eslot(0), EccCurve::P256, &key),
            Err(SeError::L3(L3Error::Result(L3Status::InvalidKey)))
        );
        let before = dev.spi_ref().transaction_count();
        let r = dev.ecc_key_store(eslot(0), EccCurve::P256, &key);
        assert_eq!(r, Err(SeError::L3(L3Error::Result(L3Status::InvalidKey))));
        assert!(dev.spi_ref().transaction_count() > before, "chip traffic continues");
        assert_eq!(dev.spi_ref().nonces(), (2, 2), "nonces stay in lockstep");
    }

    #[test]
    fn ecc_key_store_extra_result_byte_poisons_session()
    {
        // ecc_key_store is a Some(0) command: one unexpected RES_DATA byte trips
        // the expected-length check and poisons.
        let mut dev = open(ChipFault::ExtraResultByte);
        let key = sample_privkey();
        assert_eq!
        (
            dev.ecc_key_store(eslot(0), EccCurve::P256, &key),
            Err(SeError::L3(L3Error::Oversize))
        );
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn ecc_key_store_bad_tag_poisons_session()
    {
        let mut dev = open(ChipFault::BadResultTag);
        let key = sample_privkey();
        assert_eq!
        (
            dev.ecc_key_store(eslot(0), EccCurve::P256, &key),
            Err(SeError::L3(L3Error::Tag))
        );
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn ecc_key_store_l2_crc_err_poisons_session()
    {
        let mut dev = open(ChipFault::L2CrcErr);
        let key = sample_privkey();
        assert_eq!
        (
            dev.ecc_key_store(eslot(0), EccCurve::P256, &key),
            Err(SeError::L2(L2Error::Crc))
        );
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn ecc_key_store_alarm_poisons_session()
    {
        let mut dev = open(ChipFault::Alarm);
        let key = sample_privkey();
        assert_eq!
        (
            dev.ecc_key_store(eslot(0), EccCurve::P256, &key),
            Err(SeError::L2(L2Error::L1(L1Error::Alarm)))
        );
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn ecc_key_store_empty_result_poisons_session()
    {
        let mut dev = open(ChipFault::EmptyResult);
        let key = sample_privkey();
        assert_eq!
        (
            dev.ecc_key_store(eslot(0), EccCurve::P256, &key),
            Err(SeError::L3(L3Error::Parse(ParseError::UnexpectedEnd)))
        );
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn ecc_key_store_wipes_the_imported_key_from_the_l3_buffer()
    {
        // SECURITY: the imported private scalar sits in the L3 plaintext buffer.
        // The shared run gate must zeroize it on the success path so the secret
        // does not linger after the command returns.
        let mut dev = open(ChipFault::None);
        let key = sample_privkey();
        dev.ecc_key_store(eslot(5), EccCurve::Ed25519, &key).unwrap();
        assert!(dev.l3.as_slice().iter().all(|&b| b == 0), "secret key residue");
    }

    #[test]
    fn ecc_key_store_wipes_the_imported_key_even_on_poison()
    {
        // SECURITY: even when the command poisons the session, the imported
        // scalar must not survive in the L3 buffer.
        let mut dev = open(ChipFault::BadResultTag);
        let key = sample_privkey();
        let _ = dev.ecc_key_store(eslot(5), EccCurve::Ed25519, &key);
        assert!(dev.l3.as_slice().iter().all(|&b| b == 0), "secret key residue after poison");
    }

    #[test]
    fn ecc_key_erase_round_trips_and_advances_nonces()
    {
        let mut dev = open(ChipFault::None);
        assert_eq!(dev.ecc_key_erase(eslot(4)), Ok(()));
        assert_eq!(dev.spi_ref().nonces(), (1, 1));
    }

    #[test]
    fn ecc_key_erase_slot_empty_is_recoverable()
    {
        // SlotEmpty (0x15): erasing an already-empty slot. A valid authenticated
        // reply that keeps the session live (erase is idempotent for the caller).
        let mut dev = open(ChipFault::SlotEmpty);
        assert_eq!
        (
            dev.ecc_key_erase(eslot(0)),
            Err(SeError::L3(L3Error::Result(L3Status::SlotEmpty)))
        );
        let before = dev.spi_ref().transaction_count();
        let r = dev.ecc_key_erase(eslot(0));
        assert_eq!(r, Err(SeError::L3(L3Error::Result(L3Status::SlotEmpty))));
        assert!(dev.spi_ref().transaction_count() > before, "chip traffic continues");
        assert_eq!(dev.spi_ref().nonces(), (2, 2), "nonces stay in lockstep");
    }

    #[test]
    fn ecc_key_erase_extra_result_byte_poisons_session()
    {
        let mut dev = open(ChipFault::ExtraResultByte);
        assert_eq!(dev.ecc_key_erase(eslot(0)), Err(SeError::L3(L3Error::Oversize)));
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn ecc_key_erase_bad_tag_poisons_session()
    {
        let mut dev = open(ChipFault::BadResultTag);
        assert_eq!(dev.ecc_key_erase(eslot(0)), Err(SeError::L3(L3Error::Tag)));
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn ecc_key_erase_l2_crc_err_poisons_session()
    {
        let mut dev = open(ChipFault::L2CrcErr);
        assert_eq!(dev.ecc_key_erase(eslot(0)), Err(SeError::L2(L2Error::Crc)));
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn ecc_key_erase_alarm_poisons_session()
    {
        let mut dev = open(ChipFault::Alarm);
        assert_eq!
        (
            dev.ecc_key_erase(eslot(0)),
            Err(SeError::L2(L2Error::L1(L1Error::Alarm)))
        );
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn ecc_key_erase_empty_result_poisons_session()
    {
        let mut dev = open(ChipFault::EmptyResult);
        assert_eq!
        (
            dev.ecc_key_erase(eslot(0)),
            Err(SeError::L3(L3Error::Parse(ParseError::UnexpectedEnd)))
        );
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn mixed_ecc_lifecycle_keeps_nonces_in_lockstep()
    {
        // store, public-key read, then erase each advance both nonces once
        // across the full ECC key lifecycle.
        let mut dev = open(ChipFault::None);
        dev.spi_mut().set_ecc_pubkey(0x02, &[0x44; 32]);
        let key = sample_privkey();
        dev.ecc_key_store(eslot(6), EccCurve::Ed25519, &key).unwrap();
        assert_eq!(dev.spi_ref().nonces(), (1, 1));
        let pk = dev.ecc_public_key(eslot(6)).unwrap();
        assert_eq!(pk.curve(), EccCurve::Ed25519);
        assert_eq!(dev.spi_ref().nonces(), (2, 2));
        dev.ecc_key_erase(eslot(6)).unwrap();
        assert_eq!(dev.spi_ref().nonces(), (3, 3));
    }

    /// Builds a deterministic 64-byte R || S signature for the sign tests.
    fn sample_sig() -> [u8; 64]
    {
        let mut sig = [0u8; 64];
        for (i, b) in sig.iter_mut().enumerate()
        {
            *b = (i as u8).wrapping_mul(13).wrapping_add(5);
        }
        sig
    }

    #[test]
    fn ecdsa_sign_round_trips_known_signature()
    {
        let mut dev = open(ChipFault::None);
        let sig = sample_sig();
        dev.spi_mut().set_signature(sig);
        let digest = [0x42u8; 32];
        let out = dev.ecdsa_sign(eslot(0), &digest).unwrap();
        // The 15 padding bytes are skipped and R || S land verbatim.
        assert_eq!(out, Signature(sig));
        assert_eq!(dev.spi_ref().nonces(), (1, 1));
    }

    #[test]
    fn ecdsa_sign_invalid_key_is_recoverable()
    {
        // InvalidKey (0x12) = missing or wrong-curve slot: a valid authenticated
        // reply. The session stays live and the nonces stay in step.
        let mut dev = open(ChipFault::InvalidKey);
        let digest = [0u8; 32];
        assert_eq!
        (
            dev.ecdsa_sign(eslot(0), &digest),
            Err(SeError::L3(L3Error::Result(L3Status::InvalidKey)))
        );
        let before = dev.spi_ref().transaction_count();
        let r = dev.ecdsa_sign(eslot(0), &digest);
        assert_eq!(r, Err(SeError::L3(L3Error::Result(L3Status::InvalidKey))));
        assert!(dev.spi_ref().transaction_count() > before, "chip traffic continues");
        assert_eq!(dev.spi_ref().nonces(), (2, 2), "nonces stay in lockstep");
    }

    #[test]
    fn ecdsa_sign_wrong_size_result_poisons_session()
    {
        // An authenticated OK result one byte short of the fixed 79-byte RES_DATA
        // trips run's expected_res_data_len check and poisons.
        let mut dev = open(ChipFault::ResultWrongSize);
        dev.spi_mut().set_signature(sample_sig());
        assert_eq!
        (
            dev.ecdsa_sign(eslot(0), &[0u8; 32]),
            Err(SeError::L3(L3Error::Oversize))
        );
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn ecdsa_sign_extra_result_byte_poisons_session()
    {
        // One byte past the fixed 79-byte RES_DATA trips the expected-length
        // check and poisons.
        let mut dev = open(ChipFault::ExtraResultByte);
        dev.spi_mut().set_signature(sample_sig());
        assert_eq!
        (
            dev.ecdsa_sign(eslot(0), &[0u8; 32]),
            Err(SeError::L3(L3Error::Oversize))
        );
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn ecdsa_sign_bad_tag_poisons_session()
    {
        let mut dev = open(ChipFault::BadResultTag);
        assert_eq!
        (
            dev.ecdsa_sign(eslot(0), &[0u8; 32]),
            Err(SeError::L3(L3Error::Tag))
        );
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn ecdsa_sign_l2_crc_err_poisons_session()
    {
        let mut dev = open(ChipFault::L2CrcErr);
        assert_eq!
        (
            dev.ecdsa_sign(eslot(0), &[0u8; 32]),
            Err(SeError::L2(L2Error::Crc))
        );
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn ecdsa_sign_alarm_poisons_session()
    {
        let mut dev = open(ChipFault::Alarm);
        assert_eq!
        (
            dev.ecdsa_sign(eslot(0), &[0u8; 32]),
            Err(SeError::L2(L2Error::L1(L1Error::Alarm)))
        );
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn ecdsa_sign_empty_result_poisons_session()
    {
        let mut dev = open(ChipFault::EmptyResult);
        assert_eq!
        (
            dev.ecdsa_sign(eslot(0), &[0u8; 32]),
            Err(SeError::L3(L3Error::Parse(ParseError::UnexpectedEnd)))
        );
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn ecdsa_l3_buffer_is_wiped_after_a_successful_sign()
    {
        let mut dev = open(ChipFault::None);
        dev.spi_mut().set_signature(sample_sig());
        dev.ecdsa_sign(eslot(0), &[0xAB; 32]).unwrap();
        assert!(dev.l3.as_slice().iter().all(|&b| b == 0), "plaintext residue");
    }

    #[test]
    fn eddsa_sign_empty_message_round_trips()
    {
        // An empty message is valid: the chip hashes internally (RFC 8032).
        let mut dev = open(ChipFault::None);
        let sig = sample_sig();
        dev.spi_mut().set_signature(sig);
        let out = dev.eddsa_sign(eslot(0), &[]).unwrap();
        assert_eq!(out, Signature(sig));
        assert_eq!(dev.spi_ref().nonces(), (1, 1));
    }

    #[test]
    fn eddsa_sign_small_message_round_trips()
    {
        let mut dev = open(ChipFault::None);
        let sig = sample_sig();
        dev.spi_mut().set_signature(sig);
        let out = dev.eddsa_sign(eslot(7), b"patina eddsa").unwrap();
        assert_eq!(out, Signature(sig));
        assert_eq!(dev.spi_ref().nonces(), (1, 1));
    }

    #[test]
    fn eddsa_sign_max_message_round_trips()
    {
        // A 4096-byte message yields a 4112-byte plaintext that fills the L3
        // buffer to capacity and forces a multi-chunk L2 send. The driver must
        // chunk it, the mock reassemble it, and the round-trip still succeed.
        let mut dev = open(ChipFault::None);
        let sig = sample_sig();
        dev.spi_mut().set_signature(sig);
        let msg = [0x5Au8; EDDSA_MSG_MAX];
        let out = dev.eddsa_sign(eslot(0), &msg).unwrap();
        assert_eq!(out, Signature(sig));
        assert_eq!(dev.spi_ref().nonces(), (1, 1));
    }

    #[test]
    fn eddsa_sign_rejects_oversize_message_before_any_traffic()
    {
        // One byte past EDDSA_MSG_MAX is rejected up front: no nonce, no SPI
        // traffic, session intact.
        let mut dev = open(ChipFault::None);
        let before = dev.spi_ref().transaction_count();
        let msg = [0u8; EDDSA_MSG_MAX + 1];
        assert_eq!(dev.eddsa_sign(eslot(0), &msg), Err(SeError::InvalidArgument));
        assert_eq!(dev.spi_ref().transaction_count(), before);
        assert_eq!(dev.spi_ref().nonces(), (0, 0), "nonce did not move");
        // The session is still usable: a max-size message still signs.
        dev.spi_mut().set_signature(sample_sig());
        let ok = [0u8; EDDSA_MSG_MAX];
        assert_eq!(dev.eddsa_sign(eslot(0), &ok), Ok(Signature(sample_sig())));
    }

    #[test]
    fn eddsa_sign_invalid_key_is_recoverable()
    {
        let mut dev = open(ChipFault::InvalidKey);
        assert_eq!
        (
            dev.eddsa_sign(eslot(0), b"msg"),
            Err(SeError::L3(L3Error::Result(L3Status::InvalidKey)))
        );
        let before = dev.spi_ref().transaction_count();
        let r = dev.eddsa_sign(eslot(0), b"msg");
        assert_eq!(r, Err(SeError::L3(L3Error::Result(L3Status::InvalidKey))));
        assert!(dev.spi_ref().transaction_count() > before, "chip traffic continues");
        assert_eq!(dev.spi_ref().nonces(), (2, 2), "nonces stay in lockstep");
    }

    #[test]
    fn eddsa_sign_wrong_size_result_poisons_session()
    {
        let mut dev = open(ChipFault::ResultWrongSize);
        dev.spi_mut().set_signature(sample_sig());
        assert_eq!
        (
            dev.eddsa_sign(eslot(0), b"msg"),
            Err(SeError::L3(L3Error::Oversize))
        );
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn eddsa_sign_bad_tag_poisons_session()
    {
        let mut dev = open(ChipFault::BadResultTag);
        assert_eq!
        (
            dev.eddsa_sign(eslot(0), b"msg"),
            Err(SeError::L3(L3Error::Tag))
        );
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn eddsa_sign_alarm_poisons_session()
    {
        let mut dev = open(ChipFault::Alarm);
        assert_eq!
        (
            dev.eddsa_sign(eslot(0), b"msg"),
            Err(SeError::L2(L2Error::L1(L1Error::Alarm)))
        );
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn eddsa_sign_empty_result_poisons_session()
    {
        let mut dev = open(ChipFault::EmptyResult);
        assert_eq!
        (
            dev.eddsa_sign(eslot(0), b"msg"),
            Err(SeError::L3(L3Error::Parse(ParseError::UnexpectedEnd)))
        );
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn mixed_sign_sequence_keeps_nonces_in_lockstep()
    {
        // An ecdsa_sign, an eddsa_sign, and a public-key read each advance both
        // nonces once across the mixed sequence.
        let mut dev = open(ChipFault::None);
        dev.spi_mut().set_signature(sample_sig());
        dev.spi_mut().set_ecc_pubkey(0x02, &[0x33; 32]);
        dev.ecdsa_sign(eslot(0), &[0x11; 32]).unwrap();
        assert_eq!(dev.spi_ref().nonces(), (1, 1));
        dev.eddsa_sign(eslot(1), b"sign me").unwrap();
        assert_eq!(dev.spi_ref().nonces(), (2, 2));
        let pk = dev.ecc_public_key(eslot(2)).unwrap();
        assert_eq!(pk.curve(), EccCurve::Ed25519);
        assert_eq!(dev.spi_ref().nonces(), (3, 3));
    }

    /// Builds a MAC-and-Destroy slot index, panicking only in test code on a
    /// bad constant.
    fn mdslot(value: u8) -> MacDestroySlot
    {
        MacDestroySlot::new(value).expect("test mac-destroy slot out of range")
    }

    /// Recomputes the chip mock's deterministic DATA_OUT for a (slot, input).
    fn expected_mac_out(slot: u8, input: &[u8; 32]) -> [u8; 32]
    {
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate()
        {
            *b = input[i] ^ slot ^ (i as u8);
        }
        out
    }

    #[test]
    fn mac_and_destroy_round_trips_known_output()
    {
        let mut dev = open(ChipFault::None);
        let mut input = [0u8; 32];
        for (i, b) in input.iter_mut().enumerate()
        {
            *b = (i as u8).wrapping_mul(11).wrapping_add(3);
        }
        let out = dev.mac_and_destroy(mdslot(5), &input).unwrap();
        assert_eq!(out.expose(), &expected_mac_out(5, &input));
        assert_eq!(dev.spi_ref().nonces(), (1, 1));
    }

    #[test]
    fn mac_and_destroy_fail_is_recoverable()
    {
        // FAIL (0x3C) is a valid authenticated reply: the session stays live
        // and the nonces stay in step. A consumed slot replies OK (not FAIL),
        // so FAIL is not a slot-exhaustion signal here.
        let mut dev = open(ChipFault::ResultFail);
        let input = [0x11u8; 32];
        assert_eq!
        (
            dev.mac_and_destroy(mdslot(0), &input).map(|o| *o.expose()),
            Err(SeError::L3(L3Error::Result(L3Status::Fail)))
        );
        let before = dev.spi_ref().transaction_count();
        let r = dev.mac_and_destroy(mdslot(0), &input).map(|o| *o.expose());
        assert_eq!(r, Err(SeError::L3(L3Error::Result(L3Status::Fail))));
        assert!(dev.spi_ref().transaction_count() > before, "chip traffic continues");
        assert_eq!(dev.spi_ref().nonces(), (2, 2), "nonces stay in lockstep");
    }

    #[test]
    fn mac_and_destroy_wrong_size_result_poisons_session()
    {
        // An authenticated OK result one byte short of the fixed 35-byte RES_DATA
        // trips run's expected_res_data_len check and poisons.
        let mut dev = open(ChipFault::ResultWrongSize);
        assert_eq!
        (
            dev.mac_and_destroy(mdslot(0), &[0u8; 32]).map(|o| *o.expose()),
            Err(SeError::L3(L3Error::Oversize))
        );
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn mac_and_destroy_extra_result_byte_poisons_session()
    {
        // One byte past the fixed 35-byte RES_DATA trips the expected-length
        // check and poisons.
        let mut dev = open(ChipFault::ExtraResultByte);
        assert_eq!
        (
            dev.mac_and_destroy(mdslot(0), &[0u8; 32]).map(|o| *o.expose()),
            Err(SeError::L3(L3Error::Oversize))
        );
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn mac_and_destroy_bad_tag_poisons_session()
    {
        let mut dev = open(ChipFault::BadResultTag);
        assert_eq!
        (
            dev.mac_and_destroy(mdslot(0), &[0u8; 32]).map(|o| *o.expose()),
            Err(SeError::L3(L3Error::Tag))
        );
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn mac_and_destroy_alarm_poisons_session()
    {
        let mut dev = open(ChipFault::Alarm);
        assert_eq!
        (
            dev.mac_and_destroy(mdslot(0), &[0u8; 32]).map(|o| *o.expose()),
            Err(SeError::L2(L2Error::L1(L1Error::Alarm)))
        );
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn mac_and_destroy_empty_result_poisons_session()
    {
        let mut dev = open(ChipFault::EmptyResult);
        assert_eq!
        (
            dev.mac_and_destroy(mdslot(0), &[0u8; 32]).map(|o| *o.expose()),
            Err(SeError::L3(L3Error::Parse(ParseError::UnexpectedEnd)))
        );
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn mac_and_destroy_poisoned_session_fast_fails()
    {
        // A prior poison makes the next call fast-fail with SessionLost before
        // any chip traffic.
        let mut dev = open(ChipFault::BadResultTag);
        let _ = dev.mac_and_destroy(mdslot(0), &[0u8; 32]).map(|o| *o.expose());
        let before = dev.spi_ref().transaction_count();
        assert_eq!
        (
            dev.mac_and_destroy(mdslot(0), &[0u8; 32]).map(|o| *o.expose()),
            Err(SeError::SessionLost)
        );
        assert_eq!(dev.spi_ref().transaction_count(), before, "no chip traffic after poison");
    }

    #[test]
    fn mac_and_destroy_l3_buffer_is_wiped_after_success()
    {
        let mut dev = open(ChipFault::None);
        let _ = dev.mac_and_destroy(mdslot(3), &[0xAB; 32]).unwrap();
        assert!(dev.l3.as_slice().iter().all(|&b| b == 0), "plaintext residue");
    }

    #[test]
    fn mac_and_destroy_l3_buffer_is_wiped_even_on_poison()
    {
        // SECURITY: DATA_IN is secret material in the L3 plaintext buffer. Even
        // when the command poisons the session, the input must not survive.
        let mut dev = open(ChipFault::BadResultTag);
        let _ = dev.mac_and_destroy(mdslot(3), &[0xAB; 32]).map(|o| *o.expose());
        assert!(dev.l3.as_slice().iter().all(|&b| b == 0), "secret input residue after poison");
    }

    #[test]
    fn rmem_erase_round_trips_and_advances_nonces()
    {
        let mut dev = open(ChipFault::None);
        assert_eq!(dev.rmem_erase(rslot(7)), Ok(()));
        assert_eq!(dev.spi_ref().nonces(), (1, 1));
    }

    #[test]
    fn rmem_erase_non_ok_result_is_recoverable()
    {
        // A FAIL result is a valid authenticated reply: the error surfaces but
        // the session stays live and the nonces stay in step.
        let mut dev = open(ChipFault::ResultFail);
        assert_eq!
        (
            dev.rmem_erase(rslot(2)),
            Err(SeError::L3(L3Error::Result(L3Status::Fail)))
        );
        let before = dev.spi_ref().transaction_count();
        let r = dev.rmem_erase(rslot(2));
        assert_eq!(r, Err(SeError::L3(L3Error::Result(L3Status::Fail))));
        assert!(dev.spi_ref().transaction_count() > before, "chip traffic continues");
        assert_eq!(dev.spi_ref().nonces(), (2, 2), "nonces stay in lockstep");
    }

    #[test]
    fn rmem_erase_extra_result_byte_poisons_session()
    {
        // rmem_erase is a Some(0) command: it expects no RES_DATA. One unexpected
        // byte trips the expected-length check and poisons. Guards a regression
        // to None with a trivial closure.
        let mut dev = open(ChipFault::ExtraResultByte);
        assert_eq!(dev.rmem_erase(rslot(0)), Err(SeError::L3(L3Error::Oversize)));
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn rmem_erase_bad_tag_poisons_session()
    {
        let mut dev = open(ChipFault::BadResultTag);
        assert_eq!(dev.rmem_erase(rslot(0)), Err(SeError::L3(L3Error::Tag)));
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn rmem_erase_l2_crc_err_poisons_session()
    {
        let mut dev = open(ChipFault::L2CrcErr);
        assert_eq!(dev.rmem_erase(rslot(0)), Err(SeError::L2(L2Error::Crc)));
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn rmem_erase_alarm_poisons_session()
    {
        let mut dev = open(ChipFault::Alarm);
        assert_eq!
        (
            dev.rmem_erase(rslot(0)),
            Err(SeError::L2(L2Error::L1(L1Error::Alarm)))
        );
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn rmem_erase_empty_result_poisons_session()
    {
        let mut dev = open(ChipFault::EmptyResult);
        assert_eq!
        (
            dev.rmem_erase(rslot(0)),
            Err(SeError::L3(L3Error::Parse(ParseError::UnexpectedEnd)))
        );
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn mcounter_init_round_trips_and_advances_nonces()
    {
        let mut dev = open(ChipFault::None);
        assert_eq!(dev.mcounter_init(mc(0), 0x0102_0304), Ok(()));
        assert_eq!(dev.spi_ref().nonces(), (1, 1));
        // A second init at the max index and max value also round-trips, proving
        // the 8-byte plaintext (including the u32 value) reaches the chip.
        assert_eq!(dev.mcounter_init(mc(15), u32::MAX), Ok(()));
        assert_eq!(dev.spi_ref().nonces(), (2, 2));
    }

    #[test]
    fn mcounter_init_non_ok_result_is_recoverable()
    {
        let mut dev = open(ChipFault::ResultFail);
        assert_eq!
        (
            dev.mcounter_init(mc(0), 7),
            Err(SeError::L3(L3Error::Result(L3Status::Fail)))
        );
        let before = dev.spi_ref().transaction_count();
        let r = dev.mcounter_init(mc(0), 7);
        assert_eq!(r, Err(SeError::L3(L3Error::Result(L3Status::Fail))));
        assert!(dev.spi_ref().transaction_count() > before, "chip traffic continues");
        assert_eq!(dev.spi_ref().nonces(), (2, 2), "nonces stay in lockstep");
    }

    #[test]
    fn mcounter_init_extra_result_byte_poisons_session()
    {
        // mcounter_init is a Some(0) command: one unexpected RES_DATA byte trips
        // the expected-length check and poisons.
        let mut dev = open(ChipFault::ExtraResultByte);
        assert_eq!(dev.mcounter_init(mc(0), 1), Err(SeError::L3(L3Error::Oversize)));
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn mcounter_init_bad_tag_poisons_session()
    {
        let mut dev = open(ChipFault::BadResultTag);
        assert_eq!(dev.mcounter_init(mc(0), 1), Err(SeError::L3(L3Error::Tag)));
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn mcounter_init_l2_crc_err_poisons_session()
    {
        let mut dev = open(ChipFault::L2CrcErr);
        assert_eq!(dev.mcounter_init(mc(0), 1), Err(SeError::L2(L2Error::Crc)));
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn mcounter_init_empty_result_poisons_session()
    {
        let mut dev = open(ChipFault::EmptyResult);
        assert_eq!
        (
            dev.mcounter_init(mc(0), 1),
            Err(SeError::L3(L3Error::Parse(ParseError::UnexpectedEnd)))
        );
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn mcounter_update_round_trips_and_advances_nonces()
    {
        let mut dev = open(ChipFault::None);
        assert_eq!(dev.mcounter_update(mc(4)), Ok(()));
        assert_eq!(dev.spi_ref().nonces(), (1, 1));
    }

    #[test]
    fn mcounter_update_at_zero_is_recoverable()
    {
        // UpdateErr (0x13) = the counter is already at zero (a decrement would
        // underflow). It is a valid authenticated reply per libtropic / user-API
        // Table 36: the session stays live and the nonces stay in step.
        let mut dev = open(ChipFault::UpdateErr);
        assert_eq!
        (
            dev.mcounter_update(mc(0)),
            Err(SeError::L3(L3Error::Result(L3Status::UpdateErr)))
        );
        let before = dev.spi_ref().transaction_count();
        let r = dev.mcounter_update(mc(0));
        assert_eq!(r, Err(SeError::L3(L3Error::Result(L3Status::UpdateErr))));
        assert!(dev.spi_ref().transaction_count() > before, "chip traffic continues");
        assert_eq!(dev.spi_ref().nonces(), (2, 2), "nonces stay in lockstep");
    }

    #[test]
    fn mcounter_update_counter_invalid_is_recoverable()
    {
        // CounterInvalid (0x14) = an uninitialized or locked counter: a valid
        // authenticated reply. The session stays live and the nonces stay in step.
        let mut dev = open(ChipFault::CounterInvalid);
        assert_eq!
        (
            dev.mcounter_update(mc(0)),
            Err(SeError::L3(L3Error::Result(L3Status::CounterInvalid)))
        );
        let before = dev.spi_ref().transaction_count();
        let r = dev.mcounter_update(mc(0));
        assert_eq!(r, Err(SeError::L3(L3Error::Result(L3Status::CounterInvalid))));
        assert!(dev.spi_ref().transaction_count() > before, "chip traffic continues");
        assert_eq!(dev.spi_ref().nonces(), (2, 2), "nonces stay in lockstep");
    }

    #[test]
    fn mcounter_update_extra_result_byte_poisons_session()
    {
        // mcounter_update is a Some(0) command: one unexpected RES_DATA byte
        // trips the expected-length check and poisons.
        let mut dev = open(ChipFault::ExtraResultByte);
        assert_eq!(dev.mcounter_update(mc(0)), Err(SeError::L3(L3Error::Oversize)));
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn mcounter_update_bad_tag_poisons_session()
    {
        let mut dev = open(ChipFault::BadResultTag);
        assert_eq!(dev.mcounter_update(mc(0)), Err(SeError::L3(L3Error::Tag)));
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn mcounter_update_l2_crc_err_poisons_session()
    {
        let mut dev = open(ChipFault::L2CrcErr);
        assert_eq!(dev.mcounter_update(mc(0)), Err(SeError::L2(L2Error::Crc)));
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn mcounter_update_alarm_poisons_session()
    {
        let mut dev = open(ChipFault::Alarm);
        assert_eq!
        (
            dev.mcounter_update(mc(0)),
            Err(SeError::L2(L2Error::L1(L1Error::Alarm)))
        );
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn mcounter_update_empty_result_poisons_session()
    {
        let mut dev = open(ChipFault::EmptyResult);
        assert_eq!
        (
            dev.mcounter_update(mc(0)),
            Err(SeError::L3(L3Error::Parse(ParseError::UnexpectedEnd)))
        );
        assert_session_lost_and_quiet(&mut dev);
    }

    #[test]
    fn mcounter_l3_buffer_is_wiped_after_a_successful_init()
    {
        let mut dev = open(ChipFault::None);
        dev.mcounter_init(mc(0), 0xDEAD_BEEF).unwrap();
        assert!(dev.l3.as_slice().iter().all(|&b| b == 0), "plaintext residue");
    }

    #[test]
    fn mixed_mcounter_rmem_erase_sequence_keeps_nonces_in_lockstep()
    {
        // An init, an update, an rmem_erase, and a ping each advance both nonces
        // once across the mixed 2c-command sequence.
        let mut dev = open(ChipFault::None);
        let mut buf = [0u8; 16];
        dev.mcounter_init(mc(2), 50).unwrap();
        assert_eq!(dev.spi_ref().nonces(), (1, 1));
        dev.mcounter_update(mc(2)).unwrap();
        assert_eq!(dev.spi_ref().nonces(), (2, 2));
        dev.rmem_erase(rslot(3)).unwrap();
        assert_eq!(dev.spi_ref().nonces(), (3, 3));
        dev.ping_into(b"x", &mut buf).unwrap();
        assert_eq!(dev.spi_ref().nonces(), (4, 4));
    }

    #[test]
    fn se_commands_trait_dispatch_round_trips()
    {
        // Drive several commands through the SeCommands trait, not the inherent
        // methods, to prove the trait dispatch compiles and runs. A generic
        // helper bounds the call to the trait surface alone.
        fn exercise<T: SeCommands>
        (
            se: &mut T,
            slot: MacDestroySlot,
            input: &[u8; 32],
        )
        -> Result<MacAndDestroyOutput, SeError>
        {
            let mut out = [0u8; 8];
            se.random_into(&mut out)?;
            se.rmem_erase(RMemSlot::new(3).expect("test slot"))?;
            se.mcounter_init(MCounterIdx::new(1).expect("test idx"), 9)?;
            se.mcounter_update(MCounterIdx::new(1).expect("test idx"))?;
            let key = Zeroizing::new([7u8; 32]);
            se.ecc_key_store(EccSlot::new(8).expect("test slot"), EccCurve::Ed25519, &key)?;
            se.ecc_key_erase(EccSlot::new(8).expect("test slot"))?;
            se.mac_and_destroy(slot, input)
        }

        let mut dev = open(ChipFault::None);
        let input = [0x42u8; 32];
        let out = exercise(&mut dev, mdslot(9), &input).unwrap();
        assert_eq!(out.expose(), &expected_mac_out(9, &input));
        // random_into, rmem_erase, mcounter_init, mcounter_update, ecc_key_store,
        // ecc_key_erase, then mac_and_destroy each advance both nonces once:
        // seven round-trips.
        assert_eq!(dev.spi_ref().nonces(), (7, 7));
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
