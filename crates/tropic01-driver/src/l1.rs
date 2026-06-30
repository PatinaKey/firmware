//! Layer 1: SPI transport and CHIP_STATUS polling.
//!
//! Sends a built L2 request in one SPI transaction and reads a response by
//! polling GET_RESPONSE (0xAA) until a frame is present. CS is owned by the
//! `SpiDevice` implementation. One `transaction` call holds CS for its whole
//! duration, which is how the multi-byte response read stays under a single CS
//! assertion.
//!
//! The response read over-clocks a fixed maximum (the full L2 frame) in one
//! transaction, because `SpiDevice` fixes each operation length before the call
//! and releases CS between transactions. Bytes clocked past the declared frame
//! are clocked out but discarded. The parser sees only `out[..frame_len]`, so
//! the extra bus bytes never reach any layer above.

use embedded_hal::spi::Operation;
use embedded_hal::spi::SpiDevice;

use crate::buf::L2_FRAME_MAX;
use crate::error::L1Error;
use crate::ids::L2ReqId;
use crate::wait::SeWait;

/// CHIP_STATUS READY bit: the chip has a response ready.
pub(crate) const CHIP_STATUS_READY: u8 = 0x01;
/// CHIP_STATUS ALARM bit: the chip is in alarm mode.
pub(crate) const CHIP_STATUS_ALARM: u8 = 0x02;
/// CHIP_STATUS STARTUP bit: the chip is in Start-up (Maintenance) Mode.
pub(crate) const CHIP_STATUS_STARTUP: u8 = 0x04;
/// GET_RESPONSE request id (clocked out to fetch a response).
const GET_RESPONSE_REQ_ID: u8 = L2ReqId::GetResponse as u8;
/// STATUS-byte sentinel meaning "no response available yet".
///
/// libtropic `lt_l1_read` keys NO_RESP off the response STATUS byte. In its
/// combined buffer CHIP_STATUS is at offset 0 and STATUS at offset 1, so that
/// STATUS maps to `out[0]` in the split over-read here. A real STATUS is never
/// 0xFF, so 0xFF marks "no frame".
const NO_RESPONSE_STATUS: u8 = 0xFF;
/// Maximum CHIP_STATUS poll attempts before declaring the chip busy.
const READ_MAX_TRIES: u32 = 50;
/// Delay between CHIP_STATUS polls, in milliseconds.
const READ_RETRY_DELAY_MS: u32 = 25;

/// Sends a built L2 request frame in a single SPI transaction.
///
/// `frame` is the complete `[id | len | data | crc]` request.
/// Maps any bus fault to `L1Error::Bus`.
pub(crate) fn send_request<SPI>
(
    spi: &mut SPI,
    frame: &[u8],
)
-> Result<(), L1Error>
where
    SPI: SpiDevice,
{
    spi.transaction(&mut [Operation::Write(frame)])
        .map_err(|_| L1Error::Bus)
}

/// Polls GET_RESPONSE until a frame is present, then reads one L2 response frame.
///
/// Writes the `[STATUS | LEN | DATA | CRC]` frame into `out` (which must hold at
/// least one full L2 frame) and returns its byte length. A frame is present once
/// the STATUS byte `out[0]` is not the NO_RESP sentinel 0xFF. ALARM maps to
/// `L1Error::Alarm`, a bus fault to `L1Error::Bus`, and exhausting the retry
/// budget to `L1Error::ChipBusy`. The returned length is bounded by the
/// declared RSP_LEN and validated against `out`, so no downstream read can overrun.
pub(crate) fn read_response<SPI, W>
(
    spi: &mut SPI,
    wait: &mut W,
    out: &mut [u8],
)
-> Result<usize, L1Error>
where
    SPI: SpiDevice,
    W: SeWait,
{
    if out.len() < L2_FRAME_MAX
    {
        return Err(L1Error::BadChipStatus);
    }
    let mut tries = 0u32;
    while tries < READ_MAX_TRIES
    {
        // One transaction, CS held: clock 0xAA to read CHIP_STATUS, then clock
        // out the full frame. MISO = [CHIP_STATUS][STATUS|LEN|DATA|CRC...].
        let mut status = [GET_RESPONSE_REQ_ID];
        spi.transaction
        (
            &mut
            [
                Operation::TransferInPlace(&mut status),
                Operation::Read(&mut out[..L2_FRAME_MAX]),
            ],
        )
        .map_err(|_| L1Error::Bus)?;

        let chip_status = status[0];
        if chip_status & CHIP_STATUS_ALARM != 0
        {
            return Err(L1Error::Alarm);
        }
        if out[0] != NO_RESPONSE_STATUS
        {
            // out[1] is RSP_LEN (out[0] is STATUS). out.len() >= L2_FRAME_MAX.
            let rsp_len = out[1];
            // STATUS + LEN + DATA(rsp_len) + CRC(2).
            let frame_len = 2 + rsp_len as usize + 2;
            if frame_len > L2_FRAME_MAX
            {
                return Err(L1Error::BadChipStatus);
            }
            return Ok(frame_len);
        }
        wait.delay_ms(READ_RETRY_DELAY_MS).map_err(|_| L1Error::Bus)?;
        tries += 1;
    }
    Err(L1Error::ChipBusy)
}

/// Polls GET_RESPONSE until the chip settles, returning the raw CHIP_STATUS byte.
///
/// Clocks 0xAA to read CHIP_STATUS using the same constants as `read_response`
/// (`READ_MAX_TRIES`, `READ_RETRY_DELAY_MS`), but returns the byte UNINTERPRETED
/// once the chip is settled (READY or ALARM
/// set). Unlike `read_response`, ALARM is NOT mapped to an error here: the chip
/// mode is a value the caller decodes, so it must survive to the caller. Exhausting
/// the retry budget returns `L1Error::ChipBusy`. Mirrors libtropic
/// `lt_get_tr01_mode`'s CHIP_STATUS poll.
///
/// # Errors
///
/// `L1Error::Bus` on a bus fault and `L1Error::ChipBusy` when the chip never
/// settles within the retry budget.
pub(crate) fn read_chip_status<SPI, W>
(
    spi: &mut SPI,
    wait: &mut W,
)
-> Result<u8, L1Error>
where
    SPI: SpiDevice,
    W: SeWait,
{
    let mut tries = 0u32;
    while tries < READ_MAX_TRIES
    {
        // Clock 0xAA and read back CHIP_STATUS only. No frame follows: the mode
        // poll needs the status byte alone.
        let mut status = [GET_RESPONSE_REQ_ID];
        spi.transaction(&mut [Operation::TransferInPlace(&mut status)])
            .map_err(|_| L1Error::Bus)?;
        let chip_status = status[0];
        // ALARM short-circuits the poll like in libtropic: it is a settled mode,
        // not a transient busy state. READY likewise means the chip has settled.
        if chip_status & (CHIP_STATUS_ALARM | CHIP_STATUS_READY) != 0
        {
            return Ok(chip_status);
        }
        wait.delay_ms(READ_RETRY_DELAY_MS).map_err(|_| L1Error::Bus)?;
        tries += 1;
    }
    Err(L1Error::ChipBusy)
}

#[cfg(test)]
mod tests
{
    use super::*;
    use embedded_hal::spi::Error as SpiError;
    use embedded_hal::spi::ErrorKind;
    use embedded_hal::spi::ErrorType;

    /// A minimal SPI error for the race double.
    #[derive(Debug)]
    struct RaceSpiError;

    impl SpiError for RaceSpiError
    {
        fn kind(&self) -> ErrorKind
        {
            ErrorKind::Other
        }
    }

    /// A wait provider for the L1 tests.
    struct RaceWait;

    impl SeWait for RaceWait
    {
        type Error = RaceSpiError;

        fn wait_ready
        (
            &mut self,
            _timeout_ms: u32,
        )
        -> Result<(), Self::Error>
        {
            Ok(())
        }

        fn delay_ms
        (
            &mut self,
            _ms: u32,
        )
        -> Result<(), Self::Error>
        {
            Ok(())
        }
    }

    /// A GET_RESPONSE read double that sets CHIP_STATUS independently of the
    /// response bytes, so a test can reproduce the silicon over-read race: a
    /// READY-clear CHIP_STATUS while a valid frame is already in out[].
    struct RaceSpi
    {
        chip_status: u8,
        frame: std::vec::Vec<u8>,
    }

    impl ErrorType for RaceSpi
    {
        type Error = RaceSpiError;
    }

    impl SpiDevice for RaceSpi
    {
        fn transaction
        (
            &mut self,
            operations: &mut [Operation<'_, u8>],
        )
        -> Result<(), Self::Error>
        {
            if let [Operation::TransferInPlace(status), Operation::Read(out)] = operations
            {
                status[0] = self.chip_status;
                out[..self.frame.len()].copy_from_slice(&self.frame);
            }
            Ok(())
        }
    }

    /// The silicon race: CHIP_STATUS reads READY-clear (0x00) at the start of the
    /// over-read while a VALID response frame is already streaming into out[].
    /// The fix gates on the STATUS byte out[0], so the frame must be returned and
    /// not dropped.
    #[test]
    fn read_response_returns_a_frame_present_with_chip_status_ready_clear()
    {
        // out[0] = real STATUS (RequestOk 0x01), out[1] = RSP_LEN 1, 1 data byte,
        // 2 CRC bytes. STATUS is 0x01, never the 0xFF NO_RESP sentinel.
        let frame = std::vec![0x01u8, 0x01u8, 0xEEu8, 0x00u8, 0x00u8];
        let mut spi = RaceSpi
        {
            chip_status: 0x00, // READY bit CLEAR: the race condition.
            frame,
        };
        let mut wait = RaceWait;
        let mut out = [0u8; L2_FRAME_MAX];
        let r = read_response(&mut spi, &mut wait, &mut out);
        // STATUS+LEN(2) + DATA(1) + CRC(2) = 5.
        assert_eq!(r, Ok(5));
        assert_eq!(out[0], 0x01);
        assert_eq!(out[1], 0x01);
    }

    /// A no-response read (STATUS = 0xFF, the NO_RESP sentinel) with CHIP_STATUS
    /// reading READY exhausts the retry budget rather than parsing garbage.
    #[test]
    fn read_response_treats_status_ff_as_no_response()
    {
        let frame = std::vec![0xFFu8];
        let mut spi = RaceSpi
        {
            chip_status: CHIP_STATUS_READY,
            frame,
        };
        let mut wait = RaceWait;
        let mut out = [0u8; L2_FRAME_MAX];
        assert_eq!(read_response(&mut spi, &mut wait, &mut out), Err(L1Error::ChipBusy));
    }

    /// ALARM still maps to `L1Error::Alarm`, independent of the STATUS byte.
    #[test]
    fn read_response_maps_alarm()
    {
        let frame = std::vec![0xFFu8];
        let mut spi = RaceSpi
        {
            chip_status: CHIP_STATUS_ALARM,
            frame,
        };
        let mut wait = RaceWait;
        let mut out = [0u8; L2_FRAME_MAX];
        assert_eq!(read_response(&mut spi, &mut wait, &mut out), Err(L1Error::Alarm));
    }
}
