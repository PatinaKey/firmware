//! L2 request frame building and response frame parsing.
//!
//! Request frame layout (on the wire after the L1 transfer prefix):
//!   `[REQ_ID | REQ_LEN | REQ_DATA(0..252) | REQ_CRC(2)]`
//! Response frame layout (after the CHIP_STATUS byte):
//!   `[STATUS | RSP_LEN | RSP_DATA(0..252) | RSP_CRC(2)]`
//!
//! The CRC covers REQ_ID/REQ_LEN/REQ_DATA (request) or STATUS/RSP_LEN/RSP_DATA
//! (response), exactly as libtropic `add_crc()` and `lt_l2_frame_check()`.
//!
//! All parsing goes through the bounds-checked combinators in `parse`. There
//! is no raw indexing on received bytes, no unwrap, and no panic path.

use crate::buf::L2_CHUNK_MAX_DATA;
use crate::crc::crc16;
use crate::crc::crc16_bytes;
use crate::error::L2Error;
use crate::ids::L2Status;
use crate::parse::take;
use crate::parse::take_array;
use crate::parse::take_u8;

/// A parsed L2 response frame view.
///
/// Borrows the data slice out of the caller's frame buffer. The status is
/// always one of the OK variants (`RequestOk` / `ResultOk`). The parser maps
/// any other status to `L2Error::Status` before building this struct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct L2Response<'a>
{
    /// The accepted status byte (RequestOk or ResultOk).
    pub(crate) status: L2Status,
    /// The RSP_DATA payload (0..=252 bytes).
    pub(crate) data: &'a [u8],
}

/// Builds an L2 request frame into `out`.
///
/// Writes `[id | len | data | crc_hi | crc_lo]`. Returns the total number of
/// bytes written. The CRC covers id, len, and data.
///
/// Errors:
/// - `L2Error::BadFrame` when `data.len() > 252` (would overflow the u8 len).
/// - `L2Error::ShortFrame` when `out` cannot hold the whole frame.
pub(crate) fn build_request
(
    id: u8,
    data: &[u8],
    out: &mut [u8],
)
-> Result<usize, L2Error>
{
    if data.len() > L2_CHUNK_MAX_DATA
    {
        return Err(L2Error::BadFrame);
    }
    // Total = id(1) + len(1) + data + crc(2). No overflow: data <= 252.
    let total = 2 + data.len() + 2;
    if out.len() < total
    {
        return Err(L2Error::ShortFrame);
    }
    // The length cast is safe: checked `data.len() <= 252` above.
    let len_byte = data.len() as u8;
    out[0] = id;
    out[1] = len_byte;
    let data_end = 2 + data.len();
    out[2..data_end].copy_from_slice(data);
    // CRC over id + len + data (the first `data_end` bytes).
    let crc = crc16_bytes(&out[..data_end]);
    out[data_end] = crc[0];
    out[data_end + 1] = crc[1];
    Ok(total)
}

/// Parses an L2 response frame out of `frame`.
///
/// `frame` is the bytes AFTER the CHIP_STATUS byte, i.e. starting at STATUS.
/// Validates the length field, checks the CRC, and maps non-OK statuses to
/// `L2Error::Status`.
///
/// Errors:
/// - `L2Error::ShortFrame` when the slice is too short for the declared frame.
/// - `L2Error::BadFrame` when RSP_LEN exceeds 252 or the status byte is unknown.
/// - `L2Error::Crc` when the trailing CRC does not match.
/// - `L2Error::Status(s)` for any non-OK chip status.
pub(crate) fn parse_response(frame: &[u8]) -> Result<L2Response<'_>, L2Error>
{
    // STATUS then RSP_LEN.
    let (rest, status_byte) = take_u8(frame).map_err(|_| L2Error::ShortFrame)?;
    let (rest, len) = take_u8(rest).map_err(|_| L2Error::ShortFrame)?;
    let len = len as usize;
    if len > L2_CHUNK_MAX_DATA
    {
        return Err(L2Error::BadFrame);
    }
    // RSP_DATA then RSP_CRC. `take_array::<2>` yields the CRC as a fixed pair,
    // so reading it needs no raw indexing on chip-sourced bytes.
    let (data, rest) = take(rest, len).map_err(|_| L2Error::ShortFrame)?;
    let (_trailing, crc_bytes) = take_array::<2>(rest).map_err(|_| L2Error::ShortFrame)?;
    let status = match L2Status::try_from(status_byte)
    {
        Ok(s) => s,
        Err(_) => return Err(L2Error::BadFrame),
    };

    // Check the CRC only for the OK statuses, mirroring lt_l2_frame_check.
    // Return non-OK statuses as-is so the caller can act on them.
    match status
    {
        L2Status::RequestOk | L2Status::ResultOk =>
        {
            // CRC covers STATUS + RSP_LEN + RSP_DATA = the first `2 + len` bytes.
            // `get` keeps the bounds check on attacker-influenced input.
            let covered = 2 + len;
            let covered_bytes = frame.get(..covered).ok_or(L2Error::ShortFrame)?;
            let computed = crc16(covered_bytes);
            // crc_bytes is [hi, lo] in transmit order.
            let received = u16::from_be_bytes(crc_bytes);
            if received != computed
            {
                return Err(L2Error::Crc);
            }
            Ok(L2Response
            {
                status,
                data,
            })
        }
        other => Err(L2Error::Status(other)),
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::crc::crc16_bytes as crc_of;

    #[test]
    fn build_then_parse_round_trips()
    {
        let id = 0x04u8;
        let data = [0xDE, 0xAD, 0xBE, 0xEF];
        let mut buf = [0u8; 256];
        let n = build_request(id, &data, &mut buf).unwrap();
        assert_eq!(n, 2 + data.len() + 2);
        // Re-shape the built request as a "response" with status ResultOk to
        // reuse the parser: build a fresh frame [status|len|data|crc].
        let mut frame = [0u8; 256];
        frame[0] = L2Status::ResultOk as u8;
        frame[1] = data.len() as u8;
        frame[2..2 + data.len()].copy_from_slice(&data);
        let crc = crc_of(&frame[..2 + data.len()]);
        frame[2 + data.len()] = crc[0];
        frame[2 + data.len() + 1] = crc[1];
        let resp = parse_response(&frame[..2 + data.len() + 2]).unwrap();
        assert_eq!(resp.status, L2Status::ResultOk);
        assert_eq!(resp.data, &data);
    }

    #[test]
    fn build_request_crc_matches_libtropic_layout()
    {
        // id=0x01, no data: frame is [01,00,crc_hi,crc_lo].
        let mut buf = [0u8; 16];
        let n = build_request(0x01, &[], &mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(buf[0], 0x01);
        assert_eq!(buf[1], 0x00);
        // CRC over [0x01, 0x00] is 0x0386 -> bytes [0x03, 0x86].
        assert_eq!(&buf[2..4], &[0x03, 0x86]);
    }

    #[test]
    fn build_rejects_oversize_data()
    {
        let data = [0u8; 253];
        let mut buf = [0u8; 512];
        assert_eq!(build_request(0x04, &data, &mut buf), Err(L2Error::BadFrame));
    }

    #[test]
    fn build_rejects_small_output()
    {
        let data = [1u8, 2, 3];
        let mut buf = [0u8; 4];
        assert_eq!(build_request(0x04, &data, &mut buf), Err(L2Error::ShortFrame));
    }

    #[test]
    fn parse_detects_bad_crc()
    {
        let data = [0x11, 0x22];
        let mut frame = [0u8; 16];
        frame[0] = L2Status::ResultOk as u8;
        frame[1] = data.len() as u8;
        frame[2] = data[0];
        frame[3] = data[1];
        let crc = crc_of(&frame[..4]);
        frame[4] = crc[0] ^ 0xFF; // corrupt
        frame[5] = crc[1];
        assert_eq!(parse_response(&frame[..6]), Err(L2Error::Crc));
    }

    #[test]
    fn parse_maps_non_ok_status()
    {
        // STATUS = TAG_ERR (0x7B), len 0, then two CRC bytes (unchecked here).
        let frame = [0x7B, 0x00, 0x00, 0x00];
        let r = parse_response(&frame);
        assert_eq!(r.err(), Some(L2Error::Status(L2Status::TagErr)));
    }

    #[test]
    fn parse_rejects_unknown_status()
    {
        let frame = [0x55, 0x00, 0x00, 0x00];
        assert_eq!(parse_response(&frame).err(), Some(L2Error::BadFrame));
    }

    #[test]
    fn parse_rejects_oversize_len()
    {
        let frame = [L2Status::ResultOk as u8, 253, 0x00, 0x00];
        assert_eq!(parse_response(&frame).err(), Some(L2Error::BadFrame));
    }

    #[test]
    fn parse_short_frame_never_panics()
    {
        // Every truncation of a valid frame must return Err, never panic.
        let data = [0xAB, 0xCD, 0xEF];
        let mut frame = [0u8; 16];
        frame[0] = L2Status::ResultOk as u8;
        frame[1] = data.len() as u8;
        frame[2..5].copy_from_slice(&data);
        let crc = crc_of(&frame[..5]);
        frame[5] = crc[0];
        frame[6] = crc[1];
        let full = &frame[..7];
        for cut in 0..full.len()
        {
            let _ = parse_response(&full[..cut]);
        }
    }

    #[test]
    fn parse_max_data_chunk()
    {
        let data = [0x5Au8; L2_CHUNK_MAX_DATA];
        let mut frame = [0u8; 256];
        frame[0] = L2Status::RequestOk as u8;
        frame[1] = L2_CHUNK_MAX_DATA as u8;
        frame[2..2 + L2_CHUNK_MAX_DATA].copy_from_slice(&data);
        let crc = crc_of(&frame[..2 + L2_CHUNK_MAX_DATA]);
        frame[2 + L2_CHUNK_MAX_DATA] = crc[0];
        frame[2 + L2_CHUNK_MAX_DATA + 1] = crc[1];
        let resp = parse_response(&frame[..2 + L2_CHUNK_MAX_DATA + 2]).unwrap();
        assert_eq!(resp.data.len(), L2_CHUNK_MAX_DATA);
        assert_eq!(resp.status, L2Status::RequestOk);
    }
}
