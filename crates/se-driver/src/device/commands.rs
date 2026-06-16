//! The `ActiveSession` command surface and the shared `run` gate.
//!
//! Holds the session lifecycle (`close_session`), the `ping_into` diagnostic,
//! the fail-closed `run`/`run_gated` template that owns the session teardown
//! duties, and every L3 command (random, counters, R-memory, ECC, sign,
//! MAC-and-Destroy, pairing keys, config objects). The result parsers shared by
//! several commands live at the end. Command-layout constants are imported by
//! name from the parent module.

use embedded_hal::spi::SpiDevice;
use zeroize::Zeroize;
use zeroize::Zeroizing;

use crate::crypto;
use crate::error::L3Error;
use crate::error::ParseError;
use crate::error::SeError;
use crate::ids::CmdId;
use crate::ids::L3Status;
use crate::l3;
use crate::parse::take;
use crate::parse::take_array;
use crate::parse::take_u8;
use crate::port::ConfigBitIndex;
use crate::port::ConfigObjectAddr;
use crate::port::EccCurve;
use crate::port::EccPublicKey;
use crate::port::EccSlot;
use crate::port::MCounterIdx;
use crate::port::MacAndDestroyOutput;
use crate::port::MacDestroySlot;
use crate::port::PairingKeySlot;
use crate::port::RMemSlot;
use crate::port::Signature;
use crate::wait::SeWait;

use super::ActiveSession;
use super::NoSession;
use super::Tropic01;
use super::CONFIG_READ_PADDING;
use super::ECC_PUBKEY_MAX;
use super::ECC_READ_PADDING;
use super::ECC_STORE_CMD_LEN;
use super::ECC_STORE_KEY_OFFSET;
use super::ECDSA_CMD_LEN;
use super::EDDSA_MSG_MAX;
use super::MAC_DESTROY_CMD_HEADER;
use super::MAC_DESTROY_CMD_LEN;
use super::MAC_DESTROY_RES_DATA_LEN;
use super::MAC_DESTROY_RES_PADDING;
use super::MCOUNTER_INIT_CMD_LEN;
use super::MCOUNTER_INIT_HEADER;
use super::PAIRING_KEY_WRITE_CMD_LEN;
use super::PAIRING_KEY_WRITE_KEY_OFFSET;
use super::R_CONFIG_WRITE_CMD_LEN;
use super::R_CONFIG_WRITE_VALUE_OFFSET;
use super::R_MEM_DATA_MAX;
use super::SIGN_CMD_HEADER;
use super::SIGN_RES_DATA_LEN;
use super::SIGN_RES_PADDING;

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
    /// The shared `run` gate governs the session.
    ///
    /// # Errors
    ///
    /// `SeError::InvalidArgument` or `SeError::BufferTooSmall` when `payload` or
    /// `out` does not fit the L3 buffer. A wrong-size echo on an OK result
    /// returns `L3Error::Oversize`, which `run` turns into a session poison,
    /// mirroring libtropic's `lt_in__ping`. Otherwise `SeError` on a transport or
    /// crypto fault.
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
    /// chip-generated keys (`ecc_key_generate`). Confine import to the OpenPGP /
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
    /// libtropic. A consumed slot still replies OK with a changed output.
    /// Destruction is observed host-side, so Fail never means "slot consumed".
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
    /// enforced by `MCounterIdx`. Any 32-bit `value` is accepted. Returns
    /// `Ok(())` on an initialized counter.
    ///
    /// PROVISIONING ONLY. Init can re-set a counter to any value, including a
    /// higher one, which would defeat the anti-rollback guarantee. The upper
    /// layer must call this only during provisioning and never during normal
    /// operation. The driver is a faithful transport and enforces no such policy.
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

    /// Writes the host pairing public key `public_key` into pairing `slot`.
    ///
    /// Inherent twin of `SeCommands::pairing_key_write`. Provisions one of the
    /// four pairing slots the Noise KK1 handshake authenticates against:
    /// `SessionConfig.shipub` is the same `S_HiPub` key and `pkey_index` selects
    /// the slot chip-side. `public_key` is a PUBLIC key, not a secret, so it is
    /// not wrapped in `Zeroizing`. The slot range is enforced by
    /// `PairingKeySlot`. Returns `Ok(())` on a stored write.
    ///
    /// PROVISIONING ONLY. A pairing slot backs a future handshake. Overwriting
    /// the slot named by the session `pkey_index` (the active handshake key) can
    /// permanently prevent re-establishing a secure channel, so treat this as a
    /// provisioning step. The driver enforces no policy on when it runs.
    ///
    /// A non-OK RESULT is a valid authenticated reply that keeps the session
    /// live, mirroring libtropic: HardwareFail on an OTP write error (the slot is
    /// then permanently invalidated), plus Unauthorized / Fail. The command has
    /// no RES_DATA, so it declares `Some(0)`: an OK result carrying any payload
    /// poisons. A bad tag, CRC, alarm, or empty result poisons the session.
    pub(crate) fn pairing_key_write
    (
        &mut self,
        slot: PairingKeySlot,
        public_key: &[u8; 32],
    )
    -> Result<(), SeError>
    {
        if self.state.is_poisoned()
        {
            return Err(SeError::SessionLost);
        }
        // CMD plaintext (36 bytes): CMD_ID || SLOT(u16 LE) || PADDING(1, 0) ||
        // S_HIPUB(32). libtropic never writes the padding byte, so zero it here
        // explicitly: stale L3 bytes must not enter the authenticated command.
        {
            let cmd = self.cmd_plaintext();
            cmd[0] = CmdId::PairingKeyWrite as u8;
            let slot_bytes = u16::from(slot.get()).to_le_bytes();
            cmd[1] = slot_bytes[0];
            cmd[2] = slot_bytes[1];
            cmd[3] = 0;
            cmd[PAIRING_KEY_WRITE_KEY_OFFSET..PAIRING_KEY_WRITE_CMD_LEN]
                .copy_from_slice(public_key);
        }
        // No RES_DATA: expect an empty payload after the RESULT byte.
        self.run(PAIRING_KEY_WRITE_CMD_LEN, Some(0), |_res_data| Ok(()))
    }

    /// Reads the host pairing public key stored in pairing `slot`.
    ///
    /// Inherent twin of `SeCommands::pairing_key_read`. Returns the slot's
    /// 32-byte public pairing key (`S_HiPub`) by value. The slot range is
    /// enforced by `PairingKeySlot`.
    ///
    /// RES_DATA = PADDING(3) || S_HIPUB(32) = 35 bytes (fixed). A non-OK RESULT
    /// is a valid authenticated reply that keeps the session live, mirroring
    /// libtropic: SlotEmpty on an unprovisioned slot, SlotInvalid on an
    /// invalidated one, plus Unauthorized / Fail. A bad tag, CRC, alarm, empty
    /// result, or wrong-size result poisons the session.
    pub(crate) fn pairing_key_read
    (
        &mut self,
        slot: PairingKeySlot,
    )
    -> Result<[u8; 32], SeError>
    {
        if self.state.is_poisoned()
        {
            return Err(SeError::SessionLost);
        }
        // CMD plaintext (3 bytes): CMD_ID || SLOT(u16 LE).
        {
            let cmd = self.cmd_plaintext();
            cmd[0] = CmdId::PairingKeyRead as u8;
            let slot_bytes = u16::from(slot.get()).to_le_bytes();
            cmd[1] = slot_bytes[0];
            cmd[2] = slot_bytes[1];
        }
        // RES_DATA = PADDING(3) || S_HIPUB(32) = 35 bytes (fixed). Skip the
        // padding, then copy the 32 key bytes.
        self.run
        (
            3,
            // PADDING(3) + S_HIPUB(32).
            Some(35),
            |res_data|
            {
                let (_padding, rest) = take(res_data, 3)?;
                let (tail, key) = take_array::<32>(rest)?;
                if !tail.is_empty()
                {
                    // Standalone-correct: reject any trailing byte instead of
                    // leaning on run's Some(35) check, mirroring parse_signature.
                    return Err(L3Error::Oversize);
                }
                Ok(key)
            },
        )
    }

    /// Invalidates pairing `slot`, blocking future handshakes against it.
    ///
    /// Inherent twin of `SeCommands::pairing_key_invalidate`. The slot range is
    /// enforced by `PairingKeySlot`. Returns `Ok(())` on an invalidated slot.
    ///
    /// PROVISIONING ONLY. Invalidating the slot named by the session `pkey_index`
    /// (the active handshake key) can permanently prevent re-establishing a secure
    /// channel. The driver enforces no policy on when it runs.
    ///
    /// A non-OK RESULT is a valid authenticated reply that keeps the session
    /// live, mirroring libtropic: HardwareFail on an OTP write error, plus
    /// Unauthorized / Fail. The command has no RES_DATA, so it declares `Some(0)`:
    /// an OK result carrying any payload poisons. A bad tag, CRC, alarm, or empty
    /// result poisons the session.
    pub(crate) fn pairing_key_invalidate
    (
        &mut self,
        slot: PairingKeySlot,
    )
    -> Result<(), SeError>
    {
        if self.state.is_poisoned()
        {
            return Err(SeError::SessionLost);
        }
        // CMD plaintext (3 bytes): CMD_ID || SLOT(u16 LE).
        {
            let cmd = self.cmd_plaintext();
            cmd[0] = CmdId::PairingKeyInvalidate as u8;
            let slot_bytes = u16::from(slot.get()).to_le_bytes();
            cmd[1] = slot_bytes[0];
            cmd[2] = slot_bytes[1];
        }
        // No RES_DATA: expect an empty payload after the RESULT byte.
        self.run(3, Some(0), |_res_data| Ok(()))
    }

    /// Writes the 32-bit `value` to R-Config object `addr`.
    ///
    /// Inherent twin of `SeCommands::r_config_write`. R-Config is the reversible
    /// working copy of the chip configuration: a write can be undone by
    /// `r_config_erase`. `value` is a PUBLIC config word, not a secret, so it is
    /// not wrapped in `Zeroizing`. The address is constrained to a named CO by
    /// `ConfigObjectAddr`, so no invalid address can reach the wire.
    ///
    /// The chip enforces the bitwise AND of I-Config and R-Config AFTER the next
    /// boot, so a write here does not change the running session's access.
    /// `CfgUapRConfigWriteErase` gates both this write and the erase.
    ///
    /// A non-OK RESULT (Unauthorized, Fail, ...) is a valid authenticated reply
    /// that keeps the session live, mirroring libtropic. The command has no
    /// RES_DATA, so it declares `Some(0)`: an OK result carrying any payload
    /// poisons. A bad tag, CRC, alarm, or empty result poisons the session.
    pub(crate) fn r_config_write
    (
        &mut self,
        addr: ConfigObjectAddr,
        value: u32,
    )
    -> Result<(), SeError>
    {
        if self.state.is_poisoned()
        {
            return Err(SeError::SessionLost);
        }
        // CMD plaintext (8 bytes): CMD_ID || ADDRESS(u16 LE) || PADDING(1, 0) ||
        // VALUE(u32 LE). libtropic leaves the padding byte uninitialized, so zero
        // it here explicitly: stale L3 bytes must not enter the authenticated
        // command.
        {
            let cmd = self.cmd_plaintext();
            cmd[0] = CmdId::RConfigWrite as u8;
            let addr_bytes = addr.wire_addr().to_le_bytes();
            cmd[1] = addr_bytes[0];
            cmd[2] = addr_bytes[1];
            cmd[3] = 0;
            cmd[R_CONFIG_WRITE_VALUE_OFFSET..R_CONFIG_WRITE_CMD_LEN]
                .copy_from_slice(&value.to_le_bytes());
        }
        // No RES_DATA: expect an empty payload after the RESULT byte.
        self.run(R_CONFIG_WRITE_CMD_LEN, Some(0), |_res_data| Ok(()))
    }

    /// Reads the 32-bit value of R-Config object `addr`.
    ///
    /// Inherent twin of `SeCommands::r_config_read`. Returns the reversible
    /// working-copy value. The address is constrained to a named CO by
    /// `ConfigObjectAddr`.
    ///
    /// RES_DATA = PADDING(3) || VALUE(u32 LE) = 7 bytes (fixed). A non-OK RESULT
    /// keeps the session live, mirroring libtropic. A bad tag, CRC, alarm, empty
    /// result, or wrong-size result poisons the session.
    pub(crate) fn r_config_read
    (
        &mut self,
        addr: ConfigObjectAddr,
    )
    -> Result<u32, SeError>
    {
        if self.state.is_poisoned()
        {
            return Err(SeError::SessionLost);
        }
        // CMD plaintext (3 bytes): CMD_ID || ADDRESS(u16 LE).
        {
            let cmd = self.cmd_plaintext();
            cmd[0] = CmdId::RConfigRead as u8;
            let addr_bytes = addr.wire_addr().to_le_bytes();
            cmd[1] = addr_bytes[0];
            cmd[2] = addr_bytes[1];
        }
        // RES_DATA = PADDING(3) || VALUE(u32 LE).
        self.run(3, Some(7), parse_config_value)
    }

    /// Erases the ENTIRE R-Config, setting every object back to all-ones.
    ///
    /// Inherent twin of `SeCommands::r_config_erase`. This is NOT a per-object
    /// erase: it wipes the WHOLE R-Config (all configuration objects to all-1s)
    /// in one command (libtropic `lt_l3_r_config_erase`). A caller expecting to
    /// clear a single object will instead reset the entire reversible config.
    /// `CfgUapRConfigWriteErase` gates both this erase and `r_config_write`.
    ///
    /// A non-OK RESULT keeps the session live, mirroring libtropic. The command
    /// has no RES_DATA, so it declares `Some(0)`: an OK result carrying any
    /// payload poisons. A bad tag, CRC, alarm, or empty result poisons the
    /// session.
    pub(crate) fn r_config_erase(&mut self) -> Result<(), SeError>
    {
        if self.state.is_poisoned()
        {
            return Err(SeError::SessionLost);
        }
        // CMD plaintext (1 byte): CMD_ID only. There is no address: the whole
        // R-Config is erased.
        {
            let cmd = self.cmd_plaintext();
            cmd[0] = CmdId::RConfigErase as u8;
        }
        // No RES_DATA: expect an empty payload after the RESULT byte.
        self.run(1, Some(0), |_res_data| Ok(()))
    }

    /// Burns a single bit of I-Config object `addr` from 1 to 0.
    ///
    /// Inherent twin of `SeCommands::i_config_write`. The address is constrained
    /// to a named CO by `ConfigObjectAddr` and the bit to 0..=31 by
    /// `ConfigBitIndex`, so no invalid value can reach the wire. Returns `Ok(())`
    /// on a burned bit.
    ///
    /// WARNING: I-Config is OTP and IRREVERSIBLE. This command flips ONE bit from
    /// 1 to 0 (never a 32-bit value write), and the bit can NEVER be restored:
    /// app note 006 sec 3.1, "Only 1 -> 0 transition ... cannot be reverted".
    /// There is no I-Config erase. The chip enforces the bitwise AND of I-Config
    /// and R-Config AFTER the next boot (app note 006 sec 3.1). Burning all access
    /// bits of a CFG_UAP_* object to 0 PERMANENTLY disables that command for every
    /// pairing key: CFG_UAP_I_CONFIG_WRITE locks out all future config changes,
    /// CFG_UAP_R_CONFIG_WRITE_ERASE locks out R-Config recovery, and
    /// CFG_UAP_MAC_AND_DESTROY permanently kills the PIN primitive (app note 006
    /// sec 4.2 and 4.3.3 warnings). A HardwareFail (0x17) on an I-Config write is
    /// FATAL: the chip switches permanently to ALARM (user-API Table 22). The
    /// chip's response to re-writing an already-cleared bit is NOT documented by
    /// the TROPIC01 docs, so the caller must not rely on a particular status.
    ///
    /// PROVISIONING ONLY. The driver enforces no policy on when this runs. The
    /// upper layer must. A non-OK RESULT is a valid authenticated reply that
    /// keeps the session live, mirroring libtropic. The command has no RES_DATA,
    /// so it declares `Some(0)`: an OK result carrying any payload poisons. A bad
    /// tag, CRC, alarm, or empty result poisons the session.
    pub(crate) fn i_config_write
    (
        &mut self,
        addr: ConfigObjectAddr,
        bit: ConfigBitIndex,
    )
    -> Result<(), SeError>
    {
        // SECURITY: this burns an OTP bit (1 -> 0) that can never be restored.
        // The byte layout below carries ADDRESS and BIT_INDEX only, no value: a
        // single-bit burn, not a word write. See the doc warning above for the
        // lock-out and ALARM hazards.
        if self.state.is_poisoned()
        {
            return Err(SeError::SessionLost);
        }
        // CMD plaintext (4 bytes): CMD_ID || ADDRESS(u16 LE) || BIT_INDEX(1).
        // There is NO value and NO padding: this burns one bit, it does not write
        // a word.
        {
            let cmd = self.cmd_plaintext();
            cmd[0] = CmdId::IConfigWrite as u8;
            let addr_bytes = addr.wire_addr().to_le_bytes();
            cmd[1] = addr_bytes[0];
            cmd[2] = addr_bytes[1];
            cmd[3] = bit.get();
        }
        // No RES_DATA: expect an empty payload after the RESULT byte.
        self.run(4, Some(0), |_res_data| Ok(()))
    }

    /// Reads the 32-bit value of I-Config object `addr`.
    ///
    /// Inherent twin of `SeCommands::i_config_read`. Returns the irreversible
    /// config value. The address is constrained to a named CO by
    /// `ConfigObjectAddr`. The result shape is identical to `r_config_read`, so
    /// the two share `parse_config_value`.
    ///
    /// RES_DATA = PADDING(3) || VALUE(u32 LE) = 7 bytes (fixed). A non-OK RESULT
    /// keeps the session live, mirroring libtropic. A bad tag, CRC, alarm, empty
    /// result, or wrong-size result poisons the session.
    pub(crate) fn i_config_read
    (
        &mut self,
        addr: ConfigObjectAddr,
    )
    -> Result<u32, SeError>
    {
        if self.state.is_poisoned()
        {
            return Err(SeError::SessionLost);
        }
        // CMD plaintext (3 bytes): CMD_ID || ADDRESS(u16 LE).
        {
            let cmd = self.cmd_plaintext();
            cmd[0] = CmdId::IConfigRead as u8;
            let addr_bytes = addr.wire_addr().to_le_bytes();
            cmd[1] = addr_bytes[0];
            cmd[2] = addr_bytes[1];
        }
        // RES_DATA = PADDING(3) || VALUE(u32 LE).
        self.run(3, Some(7), parse_config_value)
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

/// Parses a config-read result `PADDING(3) || VALUE(u32 LE)` into a `u32`.
///
/// Shared by `r_config_read` and `i_config_read`: their result structs are
/// byte-identical (libtropic `lt_l3_r_config_read_res_t` /
/// `lt_l3_i_config_read_res_t`). Standalone-correct: it owns the 3-byte padding
/// skip, the little-endian u32 read, and the empty-tail check, so it does not
/// lean on the caller's `Some(7)` precondition. Mirrors `mcounter_get`'s parser
/// while rejecting any trailing byte, so a future `None` caller cannot silently
/// accept an oversize result.
fn parse_config_value(res_data: &[u8]) -> Result<u32, L3Error>
{
    let (_padding, rest) = take(res_data, CONFIG_READ_PADDING)?;
    let (tail, value) = take_array::<4>(rest)?;
    if !tail.is_empty()
    {
        return Err(L3Error::Oversize);
    }
    Ok(u32::from_le_bytes(value))
}
