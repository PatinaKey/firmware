//! Host-only test doubles for the SPI and wait ports.
//!
//! Compiled only under `cfg(test)`. These satisfy the `SpiDevice` and `SeWait`
//! bounds, so you can exercise the device handle and its generics without
//! hardware. `ChipMockSpi` simulates the chip side of the wire protocol for
//! the driver's commands, including injectable faults for the teardown
//! gate tests. The `vectors` module carries the golden handshake KAT.

extern crate std;

use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::vec::Vec;

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::AeadInPlace;
use aes_gcm::aead::KeyInit;
use aes_gcm::Aes256Gcm;
use embedded_hal::spi::ErrorKind;
use embedded_hal::spi::ErrorType;
use embedded_hal::spi::Operation;
use embedded_hal::spi::SpiDevice;

use crate::crc::crc16_bytes;
use crate::ids::L2ReqId;
use crate::ids::L2Status;
use crate::wait::SeWait;

/// A mock SPI error that maps to a generic bus failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MockSpiError;

impl embedded_hal::spi::Error for MockSpiError
{
    fn kind(&self) -> ErrorKind
    {
        ErrorKind::Other
    }
}

/// A do-nothing SPI device that records the number of transactions.
pub(crate) struct MockSpi
{
    transactions: usize,
}

impl MockSpi
{
    /// Creates a fresh mock with no recorded transactions.
    pub(crate) fn new() -> Self
    {
        MockSpi
        {
            transactions: 0,
        }
    }

    /// Returns how many transactions have been performed.
    pub(crate) fn transaction_count(&self) -> usize
    {
        self.transactions
    }
}

impl ErrorType for MockSpi
{
    type Error = MockSpiError;
}

impl SpiDevice for MockSpi
{
    fn transaction
    (
        &mut self,
        operations: &mut [Operation<'_, u8>],
    )
    -> Result<(), Self::Error>
    {
        self.transactions += 1;
        // Echo zeros into every read buffer to keep callers deterministic.
        for op in operations
        {
            match op
            {
                Operation::Read(buf) => buf.fill(0),
                Operation::Transfer(read, _) => read.fill(0),
                Operation::TransferInPlace(buf) => buf.fill(0),
                Operation::Write(_) | Operation::DelayNs(_) =>
                {}
            }
        }
        Ok(())
    }
}

/// A wait provider that never blocks and never times out.
pub(crate) struct MockWait
{
    waits: usize,
    delays: usize,
}

impl MockWait
{
    /// Creates a fresh mock with no recorded calls.
    pub(crate) fn new() -> Self
    {
        MockWait
        {
            waits: 0,
            delays: 0,
        }
    }

    /// Returns how many `wait_ready` calls were made.
    pub(crate) fn wait_count(&self) -> usize
    {
        self.waits
    }

    /// Returns how many `delay_ms` calls were made.
    pub(crate) fn delay_count(&self) -> usize
    {
        self.delays
    }
}

impl SeWait for MockWait
{
    type Error = MockSpiError;

    fn wait_ready
    (
        &mut self,
        _timeout_ms: u32,
    )
    -> Result<(), Self::Error>
    {
        self.waits += 1;
        Ok(())
    }

    fn delay_ms
    (
        &mut self,
        _ms: u32,
    )
    -> Result<(), Self::Error>
    {
        self.delays += 1;
        Ok(())
    }
}

/// Golden handshake KAT vectors from the real libtropic (openssl backend).
///
/// Generated with pinned inputs (see `tests/oracle/README.md`). Shared by the
/// handshake KAT and the device round-trip tests so there is one source of
/// truth.
pub(crate) mod vectors
{
    /// Host ephemeral private key (pinned test input).
    pub(crate) const EHPRIV: [u8; 32] =
        hex32("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
    /// Host ephemeral public key (derived from `EHPRIV`).
    pub(crate) const EHPUB: [u8; 32] =
        hex32("07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c");
    /// Host static pairing private key (pinned test input).
    pub(crate) const SHIPRIV: [u8; 32] =
        hex32("2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40");
    /// Host static pairing public key.
    pub(crate) const SHIPUB: [u8; 32] =
        hex32("5869aff450549732cbaaed5e5df9b30a6da31cb0e5742bad5ad4a1a768f1a67b");
    /// Chip static public key.
    pub(crate) const STPUB: [u8; 32] =
        hex32("244fe3b963e899dd295baffce248d3530f3a9a7479ba063002680ebfe7adad49");
    /// Chip ephemeral public key (from the handshake response).
    pub(crate) const ETPUB: [u8; 32] =
        hex32("64b101b1d0be5a8704bd078f9895001fc03e8e9f9522f188dd128d9846d48466");
    /// Final transcript hash.
    pub(crate) const H_TRANSCRIPT: [u8; 32] =
        hex32("e61391c0f92f0afaf1e29c9483833dc925aa5fb790f2e61597c90a63d6c57be4");
    /// Derived command-direction key.
    pub(crate) const KCMD: [u8; 32] =
        hex32("37bce877e9d5650607c67c0ea83e8df3ba89a22092b3746ce7a9301ab711d82c");
    /// Derived result-direction key.
    pub(crate) const KRES: [u8; 32] =
        hex32("339beec5e3943a18b6204def5cf59d8bef013862e0d863324d32a176472be8d7");
    /// Derived handshake authentication key.
    pub(crate) const KAUTH: [u8; 32] =
        hex32("168a193996fdeaace79a0c878c246a6fd0ec61d3273fb7805f0c31b08c3158aa");
    /// Chip authentication tag over the empty plaintext.
    pub(crate) const T_TAUTH: [u8; 16] = hex16("8c0ab7c77d48e6d224fd6bd46d8cd53a");

    /// Decodes a 64-char hex string to 32 bytes at compile time.
    pub(crate) const fn hex32(s: &str) -> [u8; 32]
    {
        let b = s.as_bytes();
        let mut out = [0u8; 32];
        let mut i = 0;
        while i < 32
        {
            out[i] = (nib(b[2 * i]) << 4) | nib(b[2 * i + 1]);
            i += 1;
        }
        out
    }

    /// Decodes a 32-char hex string to 16 bytes at compile time.
    pub(crate) const fn hex16(s: &str) -> [u8; 16]
    {
        let b = s.as_bytes();
        let mut out = [0u8; 16];
        let mut i = 0;
        while i < 16
        {
            out[i] = (nib(b[2 * i]) << 4) | nib(b[2 * i + 1]);
            i += 1;
        }
        out
    }

    /// Maps one hex digit to its nibble value.
    const fn nib(c: u8) -> u8
    {
        match c
        {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => 0,
        }
    }
}

/// A fault the chip mock injects on the result of the next command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChipFault
{
    /// Behave correctly.
    None,
    /// Corrupt the result AES-GCM tag (host decrypt must fail).
    BadResultTag,
    /// Return an L2 TAG_ERR status instead of the result.
    L2TagErr,
    /// Corrupt the result frame CRC.
    L2CrcErr,
    /// Raise the CHIP_STATUS ALARM bit on the result read.
    Alarm,
    /// Seal a valid result whose RESULT status is FAIL (recoverable).
    ResultFail,
    /// Seal a valid OK result that echoes one byte short (size mismatch).
    ShortEcho,
    /// Seal an authenticated but empty result (no RESULT byte, RES_SIZE = 0).
    EmptyResult,
    /// Seal a valid OK result whose RES_DATA is one byte short (size mismatch).
    ///
    /// Command-agnostic counterpart of `ShortEcho`. It drops the last RES_DATA
    /// byte after the RESULT byte, so any command's structural size check fires.
    ResultWrongSize,
    /// Seal a valid OK result with one extra RES_DATA byte appended.
    ///
    /// Guards `Some(0)` commands (ecc_key_generate, rmem_write): a regression to
    /// `None` with a trivial closure would silently accept the extra byte. With
    /// this fault, the unexpected byte trips run_gated's expected-length check.
    ExtraResultByte,
    /// Seal a valid result whose RESULT status is CounterInvalid (recoverable).
    CounterInvalid,
    /// Seal a valid result whose RESULT status is UpdateErr (recoverable).
    ///
    /// A McounterUpdate on a counter already at zero (a decrement would
    /// underflow). The session stays live so the caller can react.
    UpdateErr,
    /// Seal a valid result whose RESULT status is SlotNotEmpty (recoverable).
    ///
    /// A write to an un-erased R-Memory slot. The session stays live so the
    /// caller can erase and retry.
    SlotNotEmpty,
    /// Seal a valid result whose RESULT status is InvalidKey (recoverable).
    ///
    /// An EccKeyRead of an empty or corrupt slot. The session stays live so the
    /// caller can generate a key and retry.
    InvalidKey,
    /// Seal a valid result whose RESULT status is SlotEmpty (recoverable).
    ///
    /// An EccKeyErase of an already-empty slot, or a PairingKeyRead of an
    /// unprovisioned pairing slot. The session stays live.
    SlotEmpty,
    /// Seal a valid result whose RESULT status is SlotInvalid (recoverable).
    ///
    /// A PairingKeyRead of an invalidated pairing slot. The session stays live.
    SlotInvalid,
    /// Seal a valid result whose RESULT status is HardwareFail (recoverable).
    ///
    /// A PairingKeyWrite / PairingKeyInvalidate OTP write error. The session
    /// stays live so the caller can react.
    HardwareFail,
    /// Seal a valid result whose RESULT status is Unauthorized (recoverable).
    ///
    /// An R-Config / I-Config command the active pairing key may not run. The
    /// session stays live so the caller can react.
    Unauthorized,
    /// Seal a valid (OK-tag) result whose RESULT byte is an unrecognized value.
    ///
    /// The GCM tag verifies, but the status byte (0x55) maps to no `L3Status`.
    /// The host must surface a recoverable parse error and keep the session.
    UnknownResultStatus,
}

/// A fault the chip mock injects on the next `Get_Info` reply.
///
/// `Get_Info` is a plain L2 command (no secure channel), so its faults live on
/// the L2 frame, not the L3 result: a wrong RSP_LEN, an error status, a bad CRC,
/// or no response at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GetInfoFault
{
    /// Reply faithfully with the configured object payload.
    None,
    /// Drop the last RSP_DATA byte so the reply length is one short.
    WrongLen,
    /// Reply with an L2 UnknownErr status instead of the data.
    ErrorStatus,
    /// Corrupt the reply frame CRC.
    BadCrc,
    /// Queue no response (the read path then sees RSP_LEN = 0xFF).
    NoResp,
    /// Reply with a valid-CRC frame carrying a RequestCont (more-chunks) status.
    ///
    /// A single-frame Get_Info reply must be RequestOk. A *Cont status is a
    /// malformed reply for this command and must be rejected, not mistaken for a
    /// complete frame (a truncated read).
    ContStatus,
}

/// One queued chip output: a full L2 frame, or an alarm signal on the read.
enum Pending
{
    Frame(Vec<u8>),
    Alarm,
}

/// Builds the 12-byte IV for nonce `n` (LE counter in bytes 0..4, zero tail).
fn iv(n: u32) -> [u8; 12]
{
    let mut v = [0u8; 12];
    v[..4].copy_from_slice(&n.to_le_bytes());
    v
}

/// AES-256-GCM seal: returns `ciphertext || tag`.
fn seal(key: &[u8; 32], n: u32, pt: &[u8]) -> Vec<u8>
{
    let cipher = Aes256Gcm::new(&GenericArray::from(*key));
    let mut buf = pt.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(&GenericArray::from(iv(n)), &[], &mut buf)
        .unwrap();
    buf.extend_from_slice(&tag);
    buf
}

/// AES-256-GCM open of `ciphertext || tag`, returning the plaintext.
fn open(key: &[u8; 32], n: u32, ct_tag: &[u8]) -> Vec<u8>
{
    let cipher = Aes256Gcm::new(&GenericArray::from(*key));
    let (ct, tag) = ct_tag.split_at(ct_tag.len() - 16);
    let mut buf = ct.to_vec();
    let tag = GenericArray::clone_from_slice(tag);
    cipher
        .decrypt_in_place_detached(&GenericArray::from(iv(n)), &[], &mut buf, &tag)
        .unwrap();
    buf
}

/// A transcript-faithful chip-side simulator over the `SpiDevice` seam.
///
/// Mirrors the TROPIC01 wire protocol for the driver's commands: it answers a
/// Handshake_Req with the golden ETPUB||T_TAUTH, acknowledges encrypted-command
/// chunks, and for a Ping decrypts with kCMD, echoes the payload, and re-seals
/// the result with kRES. Both nonces start at 0 and advance one step per
/// round-trip, exactly like the driver. An optional `ChipFault` corrupts the
/// result so a test can drive the driver's teardown gate.
pub(crate) struct ChipMockSpi
{
    kcmd: [u8; 32],
    kres: [u8; 32],
    etpub: [u8; 32],
    t_tauth: [u8; 16],
    cmd_nonce: u32,
    res_nonce: u32,
    accum: Vec<u8>,
    pending: VecDeque<Pending>,
    fault: ChipFault,
    transactions: usize,
    mcounter_val: u32,
    rmem_slots: BTreeMap<u16, Vec<u8>>,
    ecc_read_curve: u8,
    ecc_read_pubkey: Vec<u8>,
    ecc_read_pad: usize,
    sign_signature: [u8; 64],
    pairing_key: [u8; 32],
    config_value: u32,
    get_info_objects: BTreeMap<(u8, u8), Vec<u8>>,
    get_info_fault: GetInfoFault,
    last_cmd: Vec<u8>,
}

impl ChipMockSpi
{
    /// Builds a chip mock keyed with the (golden) session keys and handshake
    /// response, with the given fault behaviour.
    pub(crate) fn new
    (
        kcmd: [u8; 32],
        kres: [u8; 32],
        etpub: [u8; 32],
        t_tauth: [u8; 16],
        fault: ChipFault,
    )
    -> Self
    {
        ChipMockSpi
        {
            kcmd,
            kres,
            etpub,
            t_tauth,
            cmd_nonce: 0,
            res_nonce: 0,
            accum: Vec::new(),
            pending: VecDeque::new(),
            fault,
            transactions: 0,
            mcounter_val: 0,
            rmem_slots: BTreeMap::new(),
            ecc_read_curve: 0x02,
            ecc_read_pubkey: Vec::new(),
            ecc_read_pad: 13,
            sign_signature: [0u8; 64],
            pairing_key: [0u8; 32],
            config_value: 0,
            last_cmd: Vec::new(),
            get_info_objects: BTreeMap::new(),
            get_info_fault: GetInfoFault::None,
        }
    }

    /// Sets the RSP_DATA the mock returns for `Get_Info(object_id, block_index)`.
    ///
    /// An object/block left unset replies with the configured fault, or (with
    /// `GetInfoFault::None`) an empty RSP_DATA frame.
    pub(crate) fn set_get_info(&mut self, object_id: u8, block_index: u8, data: &[u8])
    {
        self.get_info_objects
            .insert((object_id, block_index), data.to_vec());
    }

    /// Selects the fault the mock injects on the next `Get_Info` reply.
    pub(crate) fn set_get_info_fault(&mut self, fault: GetInfoFault)
    {
        self.get_info_fault = fault;
    }

    /// Sets the 32-byte S_HIPUB the mock returns for a PairingKeyRead.
    pub(crate) fn set_pairing_key(&mut self, key: [u8; 32])
    {
        self.pairing_key = key;
    }

    /// Sets the u32 value the mock returns for an R-Config or I-Config read.
    pub(crate) fn set_config_value(&mut self, value: u32)
    {
        self.config_value = value;
    }

    /// Sets the 64-byte R || S signature the mock returns for a sign command.
    pub(crate) fn set_signature(&mut self, sig: [u8; 64])
    {
        self.sign_signature = sig;
    }

    /// Configures the EccKeyRead response: CURVE byte and raw PUBKEY bytes.
    ///
    /// The mock returns CURVE || ORIGIN(0) || PADDING(13) || PUBKEY for an
    /// EccKeyRead. A test sets a curve byte and a matching-length pubkey.
    pub(crate) fn set_ecc_pubkey(&mut self, curve_byte: u8, pubkey: &[u8])
    {
        self.ecc_read_curve = curve_byte;
        self.ecc_read_pubkey = pubkey.to_vec();
    }

    /// Overrides the EccKeyRead padding length, to forge a truncated header.
    ///
    /// A value below 13 leaves the result one or more bytes short of the
    /// CURVE || ORIGIN || PADDING(13) header, exercising the parser's
    /// structural-bound check.
    pub(crate) fn set_ecc_read_pad(&mut self, pad: usize)
    {
        self.ecc_read_pad = pad;
    }

    /// Sets the value the mock returns for a McounterGet command.
    pub(crate) fn set_mcounter_val(&mut self, value: u32)
    {
        self.mcounter_val = value;
    }

    /// Pre-loads R-Memory `slot` with `data` for an RMemDataRead round-trip.
    ///
    /// A slot left unset reads back as empty (DATA length 0).
    pub(crate) fn set_rmem_slot(&mut self, slot: u16, data: &[u8])
    {
        self.rmem_slots.insert(slot, data.to_vec());
    }

    /// Returns the stored content of R-Memory `slot`, if any.
    ///
    /// Lets a write test confirm the chip recorded the payload.
    pub(crate) fn rmem_slot(&self, slot: u16) -> Option<&[u8]>
    {
        self.rmem_slots.get(&slot).map(Vec::as_slice)
    }

    /// Returns how many SPI transactions the host has issued.
    pub(crate) fn transaction_count(&self) -> usize
    {
        self.transactions
    }

    /// Returns the chip's `(cmd_nonce, res_nonce)` for lock-step assertions.
    pub(crate) fn nonces(&self) -> (u32, u32)
    {
        (self.cmd_nonce, self.res_nonce)
    }

    /// Returns the last decrypted command plaintext (CMD_ID || CMD_DATA).
    ///
    /// Lets a write test pin the byte-exact request layout the chip received,
    /// including fields the mock otherwise ignores (a write command's payload).
    pub(crate) fn last_command(&self) -> &[u8]
    {
        &self.last_cmd
    }

    /// Frames `data` into a full L2 response frame `[STATUS|LEN|DATA|CRC]`.
    fn frame(status: u8, data: &[u8]) -> Vec<u8>
    {
        let mut f = Vec::with_capacity(2 + data.len() + 2);
        f.push(status);
        f.push(u8::try_from(data.len()).expect("chip mock frame data exceeds 255 bytes"));
        f.extend_from_slice(data);
        let crc = crc16_bytes(&f);
        f.extend_from_slice(&crc);
        f
    }

    /// Handles a request frame written by the host.
    fn handle_write(&mut self, frame: &[u8])
    {
        if frame.len() < 2
        {
            return;
        }
        let id = frame[0];
        let len = frame[1] as usize;
        let data = &frame[2..2 + len.min(frame.len().saturating_sub(2))];
        if id == L2ReqId::GetInfo as u8
        {
            // Get_Info_Req REQ_DATA = OBJECT_ID(1) || BLOCK_INDEX(1).
            let object_id = data.first().copied().unwrap_or(0);
            let block_index = data.get(1).copied().unwrap_or(0);
            self.handle_get_info(object_id, block_index);
        }
        else if id == L2ReqId::Handshake as u8
        {
            let mut body = Vec::with_capacity(48);
            body.extend_from_slice(&self.etpub);
            body.extend_from_slice(&self.t_tauth);
            self.pending
                .push_back(Pending::Frame(Self::frame(L2Status::ResultOk as u8, &body)));
        }
        else if id == L2ReqId::EncryptedCmd as u8
        {
            // The real chip caps each request chunk at L2_CHUNK_MAX_DATA. A
            // driver that sent an over-large chunk would split the wire packet
            // wrong, so reject it here and fail the round-trip. This makes the
            // multi-chunk send path prove chunk-cap compliance, not just byte
            // reassembly.
            if len > crate::buf::L2_CHUNK_MAX_DATA
            {
                self.pending
                    .push_back(Pending::Frame(Self::frame(L2Status::GenErr as u8, &[])));
                self.accum.clear();
                return;
            }
            self.accum.extend_from_slice(data);
            // Need the 2-byte CMD_SIZE before completeness can be judged.
            if self.accum.len() < 2
            {
                self.pending
                    .push_back(Pending::Frame(Self::frame(L2Status::RequestCont as u8, &[])));
                return;
            }
            let cmd_size = u16::from_le_bytes([self.accum[0], self.accum[1]]) as usize;
            let total = 2 + cmd_size + 16;
            if self.accum.len() < total
            {
                self.pending
                    .push_back(Pending::Frame(Self::frame(L2Status::RequestCont as u8, &[])));
                return;
            }
            // Final chunk: ack, then produce the result.
            self.pending
                .push_back(Pending::Frame(Self::frame(L2Status::RequestOk as u8, &[])));
            self.produce_result(cmd_size);
            self.accum.clear();
        }
    }

    /// Queues the `Get_Info` reply for `(object_id, block_index)`.
    ///
    /// Replies with a single RequestOk frame carrying the configured RSP_DATA
    /// (empty if unset). The active `GetInfoFault` perturbs the reply for the
    /// driver's error paths.
    fn handle_get_info(&mut self, object_id: u8, block_index: u8)
    {
        if self.get_info_fault == GetInfoFault::NoResp
        {
            return;
        }
        if self.get_info_fault == GetInfoFault::ErrorStatus
        {
            self.pending
                .push_back(Pending::Frame(Self::frame(L2Status::UnknownErr as u8, &[])));
            return;
        }
        if self.get_info_fault == GetInfoFault::ContStatus
        {
            // A valid-CRC frame with a continuation status: the driver must
            // reject it rather than treat it as a complete reply.
            let data = self
                .get_info_objects
                .get(&(object_id, block_index))
                .cloned()
                .unwrap_or_default();
            self.pending
                .push_back(Pending::Frame(Self::frame(L2Status::RequestCont as u8, &data)));
            return;
        }
        let mut data = self
            .get_info_objects
            .get(&(object_id, block_index))
            .cloned()
            .unwrap_or_default();
        if self.get_info_fault == GetInfoFault::WrongLen && !data.is_empty()
        {
            data.truncate(data.len() - 1);
        }
        let mut f = Self::frame(L2Status::RequestOk as u8, &data);
        if self.get_info_fault == GetInfoFault::BadCrc
        {
            let idx = f.len() - 1;
            f[idx] ^= 0xFF;
        }
        self.pending.push_back(Pending::Frame(f));
    }

    /// Decrypts the accumulated command and queues the (possibly faulted) result.
    fn produce_result(&mut self, cmd_size: usize)
    {
        let pt = open(&self.kcmd, self.cmd_nonce, &self.accum[2..2 + cmd_size + 16]);
        self.cmd_nonce += 1;
        // Record the decrypted command plaintext (CMD_ID || CMD_DATA) so a write
        // test can assert the byte-exact request layout the chip actually saw.
        self.last_cmd = pt.clone();
        let mut res_pt = self.build_result_pt(&pt);
        if self.fault == ChipFault::ResultWrongSize && res_pt.len() > 1
        {
            // Authenticated but one RES_DATA byte short: a RES_SIZE mismatch.
            res_pt.truncate(res_pt.len() - 1);
        }
        if self.fault == ChipFault::EmptyResult
        {
            // EmptyResult seals a zero-length plaintext: authenticated, but with
            // no RESULT byte (a structural protocol violation).
            res_pt.clear();
        }
        let mut sealed = seal(&self.kres, self.res_nonce, &res_pt);
        self.res_nonce += 1;

        match self.fault
        {
            ChipFault::BadResultTag =>
            {
                let last = sealed.len() - 1;
                sealed[last] ^= 0xFF;
            }
            ChipFault::L2TagErr =>
            {
                self.pending
                    .push_back(Pending::Frame(Self::frame(L2Status::TagErr as u8, &[])));
                return;
            }
            ChipFault::Alarm =>
            {
                self.pending.push_back(Pending::Alarm);
                return;
            }
            ChipFault::None
            | ChipFault::L2CrcErr
            | ChipFault::ResultFail
            | ChipFault::ShortEcho
            | ChipFault::EmptyResult
            | ChipFault::ResultWrongSize
            | ChipFault::ExtraResultByte
            | ChipFault::CounterInvalid
            | ChipFault::UpdateErr
            | ChipFault::SlotNotEmpty
            | ChipFault::InvalidKey
            | ChipFault::SlotEmpty
            | ChipFault::SlotInvalid
            | ChipFault::HardwareFail
            | ChipFault::Unauthorized
            | ChipFault::UnknownResultStatus =>
            {}
        }

        let res_size = res_pt.len();
        let mut wire = Vec::with_capacity(2 + sealed.len());
        wire.extend_from_slice(&(res_size as u16).to_le_bytes());
        wire.extend_from_slice(&sealed);
        self.push_result_frames(&wire);
    }

    /// Chunks `wire` into L2 result frames and queues them for the read path.
    ///
    /// Splits the result into 252-byte chunks. Each non-final chunk is a
    /// `ResultCont` frame, the last is `ResultOk`, mirroring the chip. A
    /// single-chunk result is one `ResultOk` frame. The `L2CrcErr` fault
    /// corrupts the CRC of the final frame.
    fn push_result_frames(&mut self, wire: &[u8])
    {
        let chunk_max = crate::buf::L2_CHUNK_MAX_DATA;
        let mut offset = 0usize;
        loop
        {
            let remaining = wire.len() - offset;
            let chunk_len = remaining.min(chunk_max);
            let chunk = &wire[offset..offset + chunk_len];
            offset += chunk_len;
            let last = offset >= wire.len();
            let status = if last
            {
                L2Status::ResultOk as u8
            }
            else
            {
                L2Status::ResultCont as u8
            };
            let mut f = Self::frame(status, chunk);
            if last && self.fault == ChipFault::L2CrcErr
            {
                let idx = f.len() - 1;
                f[idx] ^= 0xFF;
            }
            self.pending.push_back(Pending::Frame(f));
            if last
            {
                break;
            }
        }
    }

    /// Maps the active `ChipFault` to the L3 RESULT status byte.
    ///
    /// Returns the fault-forced status, or `Ok` when no status-overriding fault
    /// is set. `0x55` is a deliberately unknown RESULT byte.
    fn fault_status_byte(&self) -> u8
    {
        use crate::ids::L3Status;

        match self.fault
        {
            ChipFault::ResultFail => L3Status::Fail as u8,
            ChipFault::CounterInvalid => L3Status::CounterInvalid as u8,
            ChipFault::UpdateErr => L3Status::UpdateErr as u8,
            ChipFault::SlotNotEmpty => L3Status::SlotNotEmpty as u8,
            ChipFault::InvalidKey => L3Status::InvalidKey as u8,
            ChipFault::SlotEmpty => L3Status::SlotEmpty as u8,
            ChipFault::SlotInvalid => L3Status::SlotInvalid as u8,
            ChipFault::HardwareFail => L3Status::HardwareFail as u8,
            ChipFault::Unauthorized => L3Status::Unauthorized as u8,
            // 0x55 maps to no known L3Status: an unrecognized RESULT byte.
            ChipFault::UnknownResultStatus => 0x55,
            _ => L3Status::Ok as u8,
        }
    }

    /// Builds the result plaintext `RESULT || RES_DATA` for a command.
    ///
    /// `pt` is the decrypted command plaintext `CMD_ID || CMD_DATA`. Dispatches
    /// on CMD_ID to shape RES_DATA: Ping echoes the payload, RandomValueGet
    /// returns padding plus deterministic bytes, McounterGet returns padding
    /// plus the configured value, RMemDataRead returns padding plus the slot
    /// content, RMemDataWrite stores the payload and returns no RES_DATA,
    /// MacAndDestroy returns padding plus a deterministic DATA_OUT,
    /// PairingKeyRead returns padding plus the configured S_HIPUB, RConfigRead
    /// and IConfigRead return padding plus the configured u32 config value. The
    /// `ResultFail`/`CounterInvalid`/`UpdateErr`/`SlotNotEmpty`/`SlotEmpty`/
    /// `SlotInvalid`/`HardwareFail` faults override the status. RMemDataErase,
    /// McounterInit, McounterUpdate, EccKeyStore, EccKeyErase, PairingKeyWrite,
    /// PairingKeyInvalidate, RConfigWrite, RConfigErase, and IConfigWrite carry no
    /// RES_DATA, so they fall through to the default arm (status byte only). The
    /// model integration tests cover their store/erase/decrement/provisioning
    /// semantics.
    fn build_result_pt(&mut self, pt: &[u8]) -> Vec<u8>
    {
        use crate::ids::CmdId;
        use crate::ids::L3Status;

        let status_byte = self.fault_status_byte();
        let status_ok = status_byte == L3Status::Ok as u8;
        let cmd_id = pt.first().copied().unwrap_or(0);
        let mut res_pt = Vec::new();
        res_pt.push(status_byte);
        // Dispatch on the decoded CMD_ID. An unknown id yields no RES_DATA.
        match CmdId::try_from(cmd_id)
        {
            Ok(CmdId::Ping) =>
            {
                let mut payload = &pt[1..];
                if self.fault == ChipFault::ShortEcho && !payload.is_empty()
                {
                    // Authenticated but one byte short: a RES_SIZE mismatch.
                    payload = &payload[..payload.len() - 1];
                }
                res_pt.extend_from_slice(payload);
            }
            Ok(CmdId::RandomValueGet) =>
            {
                // CMD_DATA[0] = N_BYTES. RES_DATA = PADDING(3) || RANDOM(N).
                let n = pt.get(1).copied().unwrap_or(0) as usize;
                res_pt.extend_from_slice(&[0u8; 3]);
                for i in 0..n
                {
                    res_pt.push(0xA0u8.wrapping_add(i as u8));
                }
            }
            Ok(CmdId::McounterGet) =>
            {
                // RES_DATA = PADDING(3) || VALUE(u32 LE).
                res_pt.extend_from_slice(&[0u8; 3]);
                res_pt.extend_from_slice(&self.mcounter_val.to_le_bytes());
            }
            Ok(CmdId::RMemDataRead) =>
            {
                // CMD_DATA = UDATA_SLOT(u16 LE). RES_DATA = PADDING(3) || DATA.
                let slot = u16::from_le_bytes([
                    pt.get(1).copied().unwrap_or(0),
                    pt.get(2).copied().unwrap_or(0),
                ]);
                res_pt.extend_from_slice(&[0u8; 3]);
                if let Some(data) = self.rmem_slots.get(&slot)
                {
                    res_pt.extend_from_slice(data);
                }
            }
            // CMD_DATA = UDATA_SLOT(u16 LE) || PADDING(1) || DATA. RES_DATA is
            // empty. Store the payload only on an OK status.
            Ok(CmdId::RMemDataWrite) if status_ok =>
            {
                let slot = u16::from_le_bytes([
                    pt.get(1).copied().unwrap_or(0),
                    pt.get(2).copied().unwrap_or(0),
                ]);
                let data = pt.get(4..).unwrap_or(&[]).to_vec();
                self.rmem_slots.insert(slot, data);
            }
            Ok(CmdId::EccKeyGenerate) =>
            {
                // CMD_DATA = SLOT(u16 LE) || CURVE(1). RES_DATA is empty.
            }
            Ok(CmdId::EccKeyRead) =>
            {
                // RES_DATA = CURVE(1) || ORIGIN(1) || PADDING(13) || PUBKEY. The
                // padding length is configurable so a test can forge a truncated
                // header.
                res_pt.push(self.ecc_read_curve);
                res_pt.push(0); // ORIGIN
                res_pt.extend(core::iter::repeat_n(0u8, self.ecc_read_pad));
                res_pt.extend_from_slice(&self.ecc_read_pubkey);
            }
            Ok(CmdId::EcdsaSign | CmdId::EddsaSign) =>
            {
                // RES_DATA = PADDING(15) || R(32) || S(32). The configured 64-byte
                // signature fills R || S so a test can assert the exact bytes.
                res_pt.extend_from_slice(&[0u8; 15]);
                res_pt.extend_from_slice(&self.sign_signature);
            }
            Ok(CmdId::MacAndDestroy) =>
            {
                // CMD_DATA = SLOT(u16 LE) || PADDING(1) || DATA_IN(32). RES_DATA =
                // PADDING(3) || DATA_OUT(32). DATA_OUT is a deterministic function of
                // the slot low byte and DATA_IN, so a test can predict it without
                // modelling the chip's real KDF.
                let slot_lo = pt.get(1).copied().unwrap_or(0);
                res_pt.extend_from_slice(&[0u8; 3]);
                for i in 0..32usize
                {
                    let din = pt.get(4 + i).copied().unwrap_or(0);
                    res_pt.push(din ^ slot_lo ^ (i as u8));
                }
            }
            Ok(CmdId::PairingKeyRead) =>
            {
                // RES_DATA = PADDING(3) || S_HIPUB(32). Returns the configured
                // pairing key so a test can assert the 3-byte padding skip.
                res_pt.extend_from_slice(&[0u8; 3]);
                res_pt.extend_from_slice(&self.pairing_key);
            }
            Ok(CmdId::RConfigRead | CmdId::IConfigRead) =>
            {
                // RES_DATA = PADDING(3) || VALUE(u32 LE). Both reads share one
                // result shape, so the configured value covers both commands.
                res_pt.extend_from_slice(&[0u8; 3]);
                res_pt.extend_from_slice(&self.config_value.to_le_bytes());
            }
            _ =>
            {}
        }
        if self.fault == ChipFault::ExtraResultByte && status_ok
        {
            // One unexpected RES_DATA byte on an OK result. A Some(0) command
            // (no RES_DATA expected) then sees 1 byte and must fail closed.
            res_pt.push(0xEE);
        }
        res_pt
    }

    /// Handles a GET_RESPONSE read: sets CHIP_STATUS and fills the frame.
    fn handle_read(&mut self, status: &mut [u8], out: &mut [u8])
    {
        match self.pending.pop_front()
        {
            Some(Pending::Frame(f)) =>
            {
                status[0] = 0x01; // READY
                out[..f.len()].copy_from_slice(&f);
            }
            Some(Pending::Alarm) =>
            {
                status[0] = 0x02; // ALARM
            }
            None =>
            {
                // No response queued: report READY but RSP_LEN = 0xFF.
                status[0] = 0x01;
                out[0] = 0x00;
                out[1] = 0xFF;
            }
        }
    }
}

impl ErrorType for ChipMockSpi
{
    type Error = MockSpiError;
}

impl SpiDevice for ChipMockSpi
{
    fn transaction
    (
        &mut self,
        operations: &mut [Operation<'_, u8>],
    )
    -> Result<(), Self::Error>
    {
        self.transactions += 1;
        match operations
        {
            [Operation::Write(frame)] =>
            {
                self.handle_write(frame);
            }
            [Operation::TransferInPlace(status), Operation::Read(out)] =>
            {
                self.handle_read(status, out);
            }
            _ =>
            {}
        }
        Ok(())
    }
}

/// Builds a full L2 response frame `[STATUS | LEN | DATA | CRC]` for tests.
pub(crate) fn l2_frame(status: u8, data: &[u8]) -> Vec<u8>
{
    let mut f = Vec::with_capacity(2 + data.len() + 2);
    f.push(status);
    f.push(u8::try_from(data.len()).expect("test frame data exceeds 255 bytes"));
    f.extend_from_slice(data);
    let crc = crc16_bytes(&f);
    f.extend_from_slice(&crc);
    f
}

/// A `SpiDevice` that replays a fixed script of response frames.
///
/// Each GET_RESPONSE read pops the next queued frame (with CHIP_STATUS READY)
/// and writes are ignored. Lets the L2 transport reassembly be driven directly,
/// without the full chip simulation, to cover multi-chunk and bound paths.
pub(crate) struct ScriptedSpi
{
    frames: VecDeque<Vec<u8>>,
}

impl ScriptedSpi
{
    /// Builds a replayer over `frames`, emitted in order on successive reads.
    pub(crate) fn new(frames: Vec<Vec<u8>>) -> Self
    {
        ScriptedSpi
        {
            frames: frames.into_iter().collect(),
        }
    }
}

impl ErrorType for ScriptedSpi
{
    type Error = MockSpiError;
}

impl SpiDevice for ScriptedSpi
{
    fn transaction
    (
        &mut self,
        operations: &mut [Operation<'_, u8>],
    )
    -> Result<(), Self::Error>
    {
        match operations
        {
            [Operation::Write(_)] =>
            {}
            [Operation::TransferInPlace(status), Operation::Read(out)] =>
            {
                match self.frames.pop_front()
                {
                    Some(f) =>
                    {
                        status[0] = 0x01; // READY
                        out[..f.len()].copy_from_slice(&f);
                    }
                    None =>
                    {
                        // Nothing left: report READY with RSP_LEN = 0xFF.
                        status[0] = 0x01;
                        out[1] = 0xFF;
                    }
                }
            }
            _ =>
            {}
        }
        Ok(())
    }
}

/// A `SpiDevice` that records every written frame and replays scripted reads.
///
/// Like `ScriptedSpi`, but it captures each MOSI `Write` so a test can assert
/// the exact on-wire frames the driver emitted. Used by the L2 SEND golden KAT
/// to compare the chunked frames byte-for-byte against real libtropic.
pub(crate) struct RecordingSpi
{
    writes: Vec<Vec<u8>>,
    frames: VecDeque<Vec<u8>>,
}

impl RecordingSpi
{
    /// Builds a recorder whose reads replay `frames` in order.
    pub(crate) fn new(frames: Vec<Vec<u8>>) -> Self
    {
        RecordingSpi
        {
            writes: Vec::new(),
            frames: frames.into_iter().collect(),
        }
    }

    /// The full frames written by the driver, in send order.
    pub(crate) fn writes(&self) -> &[Vec<u8>]
    {
        &self.writes
    }
}

impl ErrorType for RecordingSpi
{
    type Error = MockSpiError;
}

impl SpiDevice for RecordingSpi
{
    fn transaction
    (
        &mut self,
        operations: &mut [Operation<'_, u8>],
    )
    -> Result<(), Self::Error>
    {
        match operations
        {
            [Operation::Write(frame)] =>
            {
                self.writes.push(frame.to_vec());
            }
            [Operation::TransferInPlace(status), Operation::Read(out)] =>
            {
                match self.frames.pop_front()
                {
                    Some(f) =>
                    {
                        status[0] = 0x01; // READY
                        out[..f.len()].copy_from_slice(&f);
                    }
                    None =>
                    {
                        // Nothing left: report READY with RSP_LEN = 0xFF.
                        status[0] = 0x01;
                        out[1] = 0xFF;
                    }
                }
            }
            _ =>
            {}
        }
        Ok(())
    }
}

/// The default firmware version the fw-update mock reports everywhere.
///
/// Matches the `golden_b0_reqdata` chunk-0 version bytes `[00,00,00,02]` (LE
/// `0x02000000`), so the happy-path orchestration tests find every bank `ver`
/// and every running version equal to the image version.
pub(crate) const FW_UPDATE_DEFAULT_VERSION: [u8; 4] = [0x00, 0x00, 0x00, 0x02];

/// A purpose-built chip mock for the firmware-update orchestrator tests.
///
/// Acks every `Startup_Req` (0xB3), `Mutable_FW_Update` (0xB0), and
/// `Mutable_FW_Update_Data` (0xB1) with an empty `RequestOk` frame, answers a
/// `Get_Info` FW_BANK read with a 52-byte BOOT_V2 header whose `ver` (offset 4)
/// defaults to the image version, and answers the post-reboot RISC-V / SPECT
/// version reads with the same image version by default. It records the
/// `(req_id, REQ_DATA)` of every request so a test can assert the exact
/// orchestration sequence. An optional `gen_err_on_nth_b0` makes the nth
/// (1-based) 0xB0 reply a `GenErr`, to drive the failure-stop path. The bank
/// header `ver`, its size, and the running version are configurable so a test
/// can force a version mismatch or a wrong-size header.
pub(crate) struct FwUpdateSpi
{
    requests: Vec<(u8, Vec<u8>)>,
    pending: VecDeque<Vec<u8>>,
    b0_count: u32,
    b3_count: u32,
    gen_err_on_nth_b0: Option<u32>,
    gen_err_on_nth_b3: Option<u32>,
    version_response: [u8; 4],
    bank_version: [u8; 4],
    bank_header_len: usize,
}

impl FwUpdateSpi
{
    /// Builds a mock that acks the full update sequence faithfully.
    pub(crate) fn new() -> Self
    {
        FwUpdateSpi
        {
            requests: Vec::new(),
            pending: VecDeque::new(),
            b0_count: 0,
            b3_count: 0,
            gen_err_on_nth_b0: None,
            gen_err_on_nth_b3: None,
            // By default every reported version equals the golden image version,
            // so the happy-path orchestration succeeds under exact equality.
            version_response: FW_UPDATE_DEFAULT_VERSION,
            bank_version: FW_UPDATE_DEFAULT_VERSION,
            // A populated 52-byte BOOT_V2 header by default.
            bank_header_len: 52,
        }
    }

    /// Makes the nth (1-based) `Mutable_FW_Update` (0xB0) reply a `GenErr`.
    pub(crate) fn fail_nth_b0(&mut self, n: u32)
    {
        self.gen_err_on_nth_b0 = Some(n);
    }

    /// Makes the nth (1-based) `Startup_Req` (0xB3) reply a `GenErr`.
    ///
    /// Drives the reboot-failure paths: a failed `exit_to_application` on the
    /// success path, and a failed best-effort exit after an update failure.
    pub(crate) fn fail_nth_b3(&mut self, n: u32)
    {
        self.gen_err_on_nth_b3 = Some(n);
    }

    /// Sets the 4-byte value returned for the post-reboot version reads.
    ///
    /// A value that differs from the image version drives the update-incomplete
    /// path in the one-call orchestrator's post-reboot equality check.
    pub(crate) fn set_version_response(&mut self, version: [u8; 4])
    {
        self.version_response = version;
    }

    /// Sets the `ver` u32 (LE, offset 4) carried by the 52-byte FW_BANK header.
    ///
    /// A value that differs from the image version drives the bootloader-side
    /// per-bank version-equality failure.
    pub(crate) fn set_bank_version(&mut self, version: [u8; 4])
    {
        self.bank_version = version;
    }

    /// Sets the byte length of the FW_BANK header the mock returns.
    ///
    /// Defaults to 52 (BOOT_V2). A test sets 20 (BOOT_V1) or 0 (empty) to drive
    /// the wrong-header-size failure: the version check requires exactly 52.
    pub(crate) fn set_bank_header_len(&mut self, len: usize)
    {
        self.bank_header_len = len;
    }

    /// The recorded `(req_id, REQ_DATA)` of every request, in send order.
    pub(crate) fn requests(&self) -> &[(u8, Vec<u8>)]
    {
        &self.requests
    }

    /// The ordered list of recorded request ids.
    pub(crate) fn req_ids(&self) -> Vec<u8>
    {
        self.requests.iter().map(|(id, _)| *id).collect()
    }

    /// Frames `data` into a full L2 response frame `[STATUS|LEN|DATA|CRC]`.
    fn frame(status: u8, data: &[u8]) -> Vec<u8>
    {
        let mut f = Vec::with_capacity(2 + data.len() + 2);
        f.push(status);
        f.push(u8::try_from(data.len()).expect("fw-update mock frame data exceeds 255 bytes"));
        f.extend_from_slice(data);
        let crc = crc16_bytes(&f);
        f.extend_from_slice(&crc);
        f
    }

    /// Queues a `GenErr` reply on the `fail_on` nth request, else `RequestOk`.
    ///
    /// Single-sources the ack-or-fail logic shared by the 0xB3 and 0xB0
    /// branches: both push an empty-data frame, only the status byte differs.
    fn ack_or_fail(&mut self, count: u32, fail_on: Option<u32>)
    {
        if fail_on == Some(count)
        {
            self.pending
                .push_back(Self::frame(L2Status::GenErr as u8, &[]));
        }
        else
        {
            self.pending
                .push_back(Self::frame(L2Status::RequestOk as u8, &[]));
        }
    }

    /// Answers a `Get_Info` read from the recorded REQ_DATA.
    ///
    /// REQ_DATA = OBJECT_ID(1) || BLOCK_INDEX(1). A FW_BANK read returns a
    /// configured-length BOOT_V2 header. Any other object returns the 4-byte
    /// running-version value.
    fn handle_get_info(&mut self, data: &[u8])
    {
        let object_id = data.first().copied().unwrap_or(0);
        if object_id == crate::ids::ObjectId::FwBank as u8
        {
            // A BOOT_V2 header of the configured length, carrying `ver` at
            // offset 4 (LE) when the header is long enough to hold it.
            let mut header = std::vec![0xABu8; self.bank_header_len];
            if header.len() >= 8
            {
                header[4..8].copy_from_slice(&self.bank_version);
            }
            self.pending
                .push_back(Self::frame(L2Status::RequestOk as u8, &header));
        }
        else
        {
            // RISC-V / SPECT version reads: the configured 4-byte value
            // (non-sentinel by default).
            self.pending.push_back(Self::frame(
                L2Status::RequestOk as u8,
                &self.version_response,
            ));
        }
    }

    /// Handles a request frame, recording it and queuing the reply.
    fn handle_write(&mut self, frame: &[u8])
    {
        if frame.len() < 2
        {
            return;
        }
        let id = frame[0];
        let len = frame[1] as usize;
        let end = (2 + len).min(frame.len());
        let data = frame[2..end].to_vec();
        self.requests.push((id, data.clone()));

        match L2ReqId::try_from(id)
        {
            Ok(L2ReqId::Startup) =>
            {
                self.b3_count += 1;
                self.ack_or_fail(self.b3_count, self.gen_err_on_nth_b3);
            }
            Ok(L2ReqId::MutableFwUpdate) =>
            {
                self.b0_count += 1;
                self.ack_or_fail(self.b0_count, self.gen_err_on_nth_b0);
            }
            Ok(L2ReqId::MutableFwUpdateData) =>
            {
                self.pending
                    .push_back(Self::frame(L2Status::RequestOk as u8, &[]));
            }
            Ok(L2ReqId::GetInfo) =>
            {
                self.handle_get_info(&data);
            }
            _ =>
            {}
        }
    }

    /// Handles a GET_RESPONSE read: pops the next queued frame.
    fn handle_read(&mut self, status: &mut [u8], out: &mut [u8])
    {
        match self.pending.pop_front()
        {
            Some(f) =>
            {
                status[0] = 0x01; // READY
                out[..f.len()].copy_from_slice(&f);
            }
            None =>
            {
                // Nothing queued: report READY with RSP_LEN = 0xFF.
                status[0] = 0x01;
                out[1] = 0xFF;
            }
        }
    }
}

impl ErrorType for FwUpdateSpi
{
    type Error = MockSpiError;
}

impl SpiDevice for FwUpdateSpi
{
    fn transaction
    (
        &mut self,
        operations: &mut [Operation<'_, u8>],
    )
    -> Result<(), Self::Error>
    {
        match operations
        {
            [Operation::Write(frame)] =>
            {
                self.handle_write(frame);
            }
            [Operation::TransferInPlace(status), Operation::Read(out)] =>
            {
                self.handle_read(status, out);
            }
            _ =>
            {}
        }
        Ok(())
    }
}

/// A `SpiDevice` that answers a CHIP_STATUS poll with a fixed status byte.
///
/// `read_chip_status` issues a single-operation `TransferInPlace` transaction to
/// clock 0xAA and read CHIP_STATUS back. This mock writes the configured byte
/// into that buffer, letting a `chip_mode` test drive any CHIP_STATUS pattern
/// (READY / ALARM / STARTUP and their combinations) without the full chip
/// simulation. Other transaction shapes are ignored.
pub(crate) struct StatusSpi
{
    status: u8,
}

impl StatusSpi
{
    /// Builds a mock that reports `status` as the CHIP_STATUS byte.
    pub(crate) fn new(status: u8) -> Self
    {
        StatusSpi
        {
            status,
        }
    }
}

impl ErrorType for StatusSpi
{
    type Error = MockSpiError;
}

impl SpiDevice for StatusSpi
{
    fn transaction
    (
        &mut self,
        operations: &mut [Operation<'_, u8>],
    )
    -> Result<(), Self::Error>
    {
        if let [Operation::TransferInPlace(buf)] = operations
            && let Some(b) = buf.first_mut()
        {
            *b = self.status;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn mock_spi_records_transactions_and_zero_fills()
    {
        let mut spi = MockSpi::new();
        let mut rd = [0xFFu8; 4];
        spi.transaction(&mut [Operation::Read(&mut rd)]).unwrap();
        assert_eq!(spi.transaction_count(), 1);
        assert_eq!(rd, [0, 0, 0, 0]);
    }

    #[test]
    fn mock_wait_records_calls()
    {
        let mut w = MockWait::new();
        w.wait_ready(10).unwrap();
        w.delay_ms(1).unwrap();
        assert_eq!(w.wait_count(), 1);
        assert_eq!(w.delay_count(), 1);
    }
}
