//! Layer 1: SPI transport and CHIP_STATUS polling.
//!
//! Sends a built L2 request in one SPI transaction and reads a response by
//! polling GET_RESPONSE (0xAA) until the chip signals READY. CS is owned by the
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
/// RSP_LEN sentinel meaning "no response available yet".
const NO_RESPONSE_LEN: u8 = 0xFF;
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

/// Polls GET_RESPONSE until the chip is READY, then reads one L2 response frame.
///
/// Writes the `[STATUS | LEN | DATA | CRC]` frame into `out` (which must hold at
/// least one full L2 frame) and returns its byte length. ALARM maps to
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
        if chip_status & CHIP_STATUS_READY != 0
        {
            // out[1] is RSP_LEN (out[0] is STATUS). out.len() >= L2_FRAME_MAX.
            let rsp_len = out[1];
            if rsp_len != NO_RESPONSE_LEN
            {
                // STATUS + LEN + DATA(rsp_len) + CRC(2).
                let frame_len = 2 + rsp_len as usize + 2;
                if frame_len > L2_FRAME_MAX
                {
                    return Err(L1Error::BadChipStatus);
                }
                return Ok(frame_len);
            }
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
