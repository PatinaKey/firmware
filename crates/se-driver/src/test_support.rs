//! Host-only test doubles for the SPI and wait ports.
//!
//! Compiled only under `cfg(test)`. These satisfy the `SpiDevice` and `SeWait`
//! bounds, so you can exercise the device handle and its generics without
//! hardware. `ChipMockSpi` simulates the chip side of the wire protocol for
//! the ping vertical slice, including injectable faults for the teardown
//! gate tests. The `vectors` module carries the golden handshake KAT.

extern crate std;

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
    /// Seal a valid result whose RESULT status is CounterInvalid (recoverable).
    CounterInvalid,
    /// Seal a valid (OK-tag) result whose RESULT byte is an unrecognized value.
    ///
    /// The GCM tag verifies, but the status byte (0x55) maps to no `L3Status`.
    /// The host must surface a recoverable parse error and keep the session.
    UnknownResultStatus,
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
/// Mirrors the TROPIC01 wire protocol for the ping vertical slice: it answers a
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
        }
    }

    /// Sets the value the mock returns for a McounterGet command.
    pub(crate) fn set_mcounter_val(&mut self, value: u32)
    {
        self.mcounter_val = value;
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
        if id == L2ReqId::Handshake as u8
        {
            let mut body = Vec::with_capacity(48);
            body.extend_from_slice(&self.etpub);
            body.extend_from_slice(&self.t_tauth);
            self.pending
                .push_back(Pending::Frame(Self::frame(L2Status::ResultOk as u8, &body)));
        }
        else if id == L2ReqId::EncryptedCmd as u8
        {
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

    /// Decrypts the accumulated command and queues the (possibly faulted) result.
    fn produce_result(&mut self, cmd_size: usize)
    {
        let pt = open(&self.kcmd, self.cmd_nonce, &self.accum[2..2 + cmd_size + 16]);
        self.cmd_nonce += 1;
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
            | ChipFault::CounterInvalid
            | ChipFault::UnknownResultStatus =>
            {}
        }

        let res_size = res_pt.len();
        let mut wire = Vec::with_capacity(2 + sealed.len());
        wire.extend_from_slice(&(res_size as u16).to_le_bytes());
        wire.extend_from_slice(&sealed);
        let mut f = Self::frame(L2Status::ResultOk as u8, &wire);
        if self.fault == ChipFault::L2CrcErr
        {
            let last = f.len() - 1;
            f[last] ^= 0xFF;
        }
        self.pending.push_back(Pending::Frame(f));
    }

    /// Builds the result plaintext `RESULT || RES_DATA` for a command.
    ///
    /// `pt` is the decrypted command plaintext `CMD_ID || CMD_DATA`. Dispatches
    /// on CMD_ID to shape RES_DATA: Ping echoes the payload, RandomValueGet
    /// returns padding plus deterministic bytes, McounterGet returns padding
    /// plus the configured value. The `ResultFail`/`CounterInvalid` faults
    /// override the RESULT status.
    fn build_result_pt(&self, pt: &[u8]) -> Vec<u8>
    {
        use crate::ids::CmdId;
        use crate::ids::L3Status;

        let status_byte = match self.fault
        {
            ChipFault::ResultFail => L3Status::Fail as u8,
            ChipFault::CounterInvalid => L3Status::CounterInvalid as u8,
            // 0x55 maps to no known L3Status: an unrecognized RESULT byte.
            ChipFault::UnknownResultStatus => 0x55,
            _ => L3Status::Ok as u8,
        };
        let cmd_id = pt.first().copied().unwrap_or(0);
        let mut res_pt = Vec::new();
        res_pt.push(status_byte);
        if cmd_id == CmdId::Ping as u8
        {
            let mut payload = &pt[1..];
            if self.fault == ChipFault::ShortEcho && !payload.is_empty()
            {
                // Authenticated but one byte short: a RES_SIZE mismatch.
                payload = &payload[..payload.len() - 1];
            }
            res_pt.extend_from_slice(payload);
        }
        else if cmd_id == CmdId::RandomValueGet as u8
        {
            // CMD_DATA[0] = N_BYTES. RES_DATA = PADDING(3) || RANDOM(N).
            let n = pt.get(1).copied().unwrap_or(0) as usize;
            res_pt.extend_from_slice(&[0u8; 3]);
            for i in 0..n
            {
                res_pt.push(0xA0u8.wrapping_add(i as u8));
            }
        }
        else if cmd_id == CmdId::McounterGet as u8
        {
            // RES_DATA = PADDING(3) || VALUE(u32 LE).
            res_pt.extend_from_slice(&[0u8; 3]);
            res_pt.extend_from_slice(&self.mcounter_val.to_le_bytes());
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
