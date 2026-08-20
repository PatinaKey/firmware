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
//! All parsing goes through the bounds-checked combinators in `parse`.

use crate::buf::L2_CHUNK_MAX_DATA;
use crate::crc::crc16;
use crate::crc::crc16_bytes;
use crate::error::L2Error;
use crate::ids::L2Status;
use crate::parse::take;
use crate::parse::take_array;
use crate::parse::take_u8;

/// Byte offset of RSP_DATA inside a response frame: STATUS(1) || RSP_LEN(1).
pub(crate) const RSP_DATA_OFFSET: usize = 2;

/// A parsed L2 response frame.
///
/// The status is one of the accepted framed-response variants (`RequestOk` /
/// `ResultOk` / `RequestCont` / `ResultCont`). The `*Cont` variants signal that
/// more chunks follow. The parser maps any error status to `L2Error::Status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct L2ResponseInfo
{
    /// The accepted status byte.
    pub(crate) status: L2Status,
    /// The RSP_DATA length in bytes (0..=252).
    pub(crate) data_len: usize,
}

/// Re-slices RSP_DATA out of `frame` for a previously parsed `info`.
///
/// CALLER OBLIGATION: `info` must come from the last read performed into this
/// buffer. Nothing may write to `frame` between the parse and this call.
///
/// Errors with `L2Error::ShortFrame` when the frame no longer holds the data.
pub(crate) fn rsp_data<'a>
(
    frame: &'a [u8],
    info: &L2ResponseInfo,
)
-> Result<&'a [u8], L2Error>
{
    // data_len <= 252 and the offset is 2, so the sum cannot overflow a usize.
    frame
        .get(RSP_DATA_OFFSET..RSP_DATA_OFFSET + info.data_len)
        .ok_or(L2Error::ShortFrame)
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

/// Selects how strictly the trailing RSP_CRC is validated.
#[derive(Debug, Clone, Copy)]
enum CrcCheck
{
    /// Compare both RSP_CRC bytes (the strict default).
    Full,
    /// Allow the `Startup_Req` erratum frame, under libtropic's exact gate.
    StartupErratum,
}

/// Parses an L2 response frame with full RSP_CRC validation.
///
/// `frame` is the bytes AFTER the CHIP_STATUS byte, i.e. starting at STATUS.
/// The strict rule every L2 response uses except the `Startup_Req` reply.
///
/// Errors:
/// - `L2Error::ShortFrame` when the slice is too short for the declared frame.
/// - `L2Error::BadFrame` when RSP_LEN exceeds 252 or the status byte is unknown.
/// - `L2Error::Crc` when the trailing CRC does not match.
/// - `L2Error::Status(s)` for any non-OK chip status.
pub(crate) fn parse_response(frame: &[u8]) -> Result<L2ResponseInfo, L2Error>
{
    parse_response_with(frame, CrcCheck::Full)
}

/// Parses a `Startup_Req` response, tolerating the RSP_CRC erratum.
///
/// TROPIC01 mutable firmware up to 1.0.1 reboots after the host has read the
/// first RSP_CRC byte of a `Startup_Req` response, so the second byte can arrive
/// mangled. libtropic v2.0.0 tolerates that in `lt_l2_receive`, and only for the
/// exact frame the erratum produces.
///
/// This wrapper reproduces that gate condition for condition: the tolerance
/// applies only when the status is `RequestOk`, RSP_LEN is 0, and the first
/// RSP_CRC byte matches the value recomputed over the frame. Anything else falls
/// back to the strict rule, so a longer reply, an error status, or a wrong first
/// CRC byte is rejected exactly as on any other response.
///
/// Errors: same as `parse_response`, except that `L2Error::Crc` does not fire on
/// a second-CRC-byte mismatch of that one tolerated frame.
pub(crate) fn parse_startup_response(frame: &[u8]) -> Result<L2ResponseInfo, L2Error>
{
    parse_response_with(frame, CrcCheck::StartupErratum)
}

/// Shared response parser. `crc_check` selects strict-vs-erratum RSP_CRC.
fn parse_response_with
(
    frame: &[u8],
    crc_check: CrcCheck,
)
-> Result<L2ResponseInfo, L2Error>
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

    // CRC-check the framed-response statuses, mirroring lt_l2_frame_check. The
    // `*Cont` variants are valid data-bearing frames (more chunks follow), so
    // they are accepted here and the reassembly loop decides continue-vs-done.
    // Error statuses are returned as-is so the caller can act on them.
    match status
    {
        L2Status::RequestOk
        | L2Status::ResultOk
        | L2Status::RequestCont
        | L2Status::ResultCont =>
        {
            // CRC covers STATUS + RSP_LEN + RSP_DATA.
            let covered = RSP_DATA_OFFSET + len;
            let covered_bytes = frame.get(..covered).ok_or(L2Error::ShortFrame)?;
            // `crc16` returns the already-swapped value, so `to_be_bytes` yields
            // the on-wire pair [hi, lo] in the same order as `crc_bytes`.
            let computed = crc16(covered_bytes).to_be_bytes();
            // `crc_bytes` is [hi, lo] in transmit order. The first transmitted
            // byte is the high byte at index 0.
            let crc_ok = match crc_check
            {
                CrcCheck::Full => crc_bytes == computed,
                // libtropic `lt_l2_receive` gates the erratum tolerance on the
                // whole frame shape, not on the CRC alone: REQUEST_OK status,
                // RSP_LEN 0, and the expected first CRC byte. Reproduced here.
                // Any other frame falls back to the strict comparison, so the
                // relaxation cannot widen to a data-bearing reply.
                CrcCheck::StartupErratum =>
                {
                    if status == L2Status::RequestOk && len == 0
                    {
                        crc_bytes[0] == computed[0]
                    }
                    else
                    {
                        crc_bytes == computed
                    }
                }
            };
            if !crc_ok
            {
                return Err(L2Error::Crc);
            }
            Ok(L2ResponseInfo
            {
                status,
                data_len: data.len(),
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
        assert_eq!(rsp_data(&frame[..2 + data.len() + 2], &resp), Ok(&data[..]));
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

    /// Builds a framed response with `status` and `data`, CRC included.
    ///
    /// `corrupt_index` optionally flips one CRC byte (0 = first/high byte,
    /// 1 = second/low byte). Returns the frame buffer and its used length.
    fn framed_response
    (
        status: L2Status,
        data: &[u8],
        corrupt_index: Option<usize>,
    )
    -> ([u8; 16], usize)
    {
        let mut frame = [0u8; 16];
        frame[0] = status as u8;
        frame[1] = data.len() as u8;
        frame[2..2 + data.len()].copy_from_slice(data);
        let crc = crc_of(&frame[..2 + data.len()]);
        frame[2 + data.len()] = crc[0];
        frame[2 + data.len() + 1] = crc[1];
        if let Some(i) = corrupt_index
        {
            frame[2 + data.len() + i] ^= 0xFF;
        }
        (frame, 2 + data.len() + 2)
    }

    /// The exact frame the Startup_Req erratum produces: RequestOk, RSP_LEN 0.
    fn startup_ack(corrupt_index: Option<usize>) -> ([u8; 16], usize)
    {
        framed_response(L2Status::RequestOk, &[], corrupt_index)
    }

    #[test]
    fn startup_response_accepts_corrupt_second_crc_byte()
    {
        // Startup_Req erratum: the premature reset corrupts the SECOND CRC byte
        // of an empty RequestOk ack. That one frame shape is tolerated.
        let (frame, n) = startup_ack(Some(1));
        // The strict path still rejects it, proving the test is non-vacuous.
        assert_eq!(parse_response(&frame[..n]), Err(L2Error::Crc));
        let resp = parse_startup_response(&frame[..n]).unwrap();
        assert_eq!(resp.status, L2Status::RequestOk);
        assert_eq!(resp.data_len, 0);
    }

    #[test]
    fn startup_response_rejects_corrupt_first_crc_byte()
    {
        // Integrity is not fully abandoned: a corrupt FIRST CRC byte is still
        // rejected on the tolerated frame shape.
        let (frame, n) = startup_ack(Some(0));
        assert_eq!(parse_startup_response(&frame[..n]), Err(L2Error::Crc));
    }

    #[test]
    fn startup_tolerance_does_not_extend_to_a_data_bearing_reply()
    {
        // libtropic gates its tolerance on RSP_LEN == 0. A reply carrying
        // RSP_DATA is not the erratum frame, so its second CRC byte still counts.
        let (frame, n) = framed_response(L2Status::RequestOk, &[0x11, 0x22], Some(1));
        assert_eq!(parse_startup_response(&frame[..n]), Err(L2Error::Crc));
    }

    #[test]
    fn startup_tolerance_does_not_extend_to_a_continuation_status()
    {
        // libtropic gates on STATUS == REQUEST_OK. Any other accepted status
        // stays under the strict comparison.
        let (frame, n) = framed_response(L2Status::RequestCont, &[], Some(1));
        assert_eq!(parse_startup_response(&frame[..n]), Err(L2Error::Crc));
    }

    #[test]
    fn startup_path_still_accepts_an_intact_data_bearing_reply()
    {
        // The tightened gate must not reject a clean frame: only the erratum
        // tolerance narrows, the strict comparison is unchanged.
        let (frame, n) = framed_response(L2Status::RequestOk, &[0x11, 0x22], None);
        let resp = parse_startup_response(&frame[..n]).unwrap();
        assert_eq!(resp.data_len, 2);
    }

    #[test]
    fn full_path_still_rejects_corrupt_second_crc_byte()
    {
        // No regression: the relaxation must not leak into the normal path.
        let (frame, n) = startup_ack(Some(1));
        assert_eq!(parse_response(&frame[..n]), Err(L2Error::Crc));
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
        assert_eq!(resp.data_len, L2_CHUNK_MAX_DATA);
        assert_eq!(resp.status, L2Status::RequestOk);
    }
}
