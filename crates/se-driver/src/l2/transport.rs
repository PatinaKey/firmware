//! L2 transport of L3 packets: chunked send and reassembled receive.
//!
//! An L3 packet (`[size | ciphertext | tag]`) is split into 252-byte chunks,
//! each sent as an `Encrypted_Cmd` (REQ_ID 0x04) frame and acknowledged. The
//! result is read back as one or more `RESULT_CONT`/`RESULT_OK` frames and
//! reassembled into the L3 buffer. The reassembly loop is bounded, never
//! spins unbounded on a misbehaving chip.

use embedded_hal::spi::SpiDevice;

use crate::buf::L2_CHUNK_MAX_DATA;
use crate::error::L2Error;
use crate::ids::L2ReqId;
use crate::ids::L2Status;
use crate::l1;
use crate::l2::frame;
use crate::wait::SeWait;

/// Maximum number of result chunks to reassemble.
///
/// Source: libtropic `LT_L2_RECV_ENC_RES_MAX_CHUNKS`. The largest L3 result is
/// well within this bound. Exceeding it is treated as a malformed exchange.
const RECV_MAX_CHUNKS: usize = 42;

/// Sends an L3 `packet` as chunked `Encrypted_Cmd` frames.
///
/// Each chunk is framed into `l2`, sent, and the ack is read back and checked.
/// A `RequestCont` or `RequestOk` ack is accepted on every chunk (the chip uses
/// `RequestCont` while more chunks are expected and `RequestOk` on the last, but
/// this matches libtropic in not enforcing which one arrives on which chunk).
/// Any other status aborts the send.
pub(crate) fn send_encrypted<SPI, W>
(
    spi: &mut SPI,
    wait: &mut W,
    l2: &mut [u8],
    packet: &[u8],
)
-> Result<(), L2Error>
where
    SPI: SpiDevice,
    W: SeWait,
{
    if packet.is_empty()
    {
        return Err(L2Error::BadFrame);
    }
    let mut offset = 0usize;
    while offset < packet.len()
    {
        let remaining = packet.len() - offset;
        let chunk_len = remaining.min(L2_CHUNK_MAX_DATA);
        let chunk = &packet[offset..offset + chunk_len];
        let n = frame::build_request(L2ReqId::EncryptedCmd as u8, chunk, l2)?;
        l1::send_request(spi, &l2[..n])?;
        let frame_len = l1::read_response(spi, wait, l2)?;
        let resp = frame::parse_response(&l2[..frame_len])?;
        offset += chunk_len;
        match resp.status
        {
            L2Status::RequestCont | L2Status::RequestOk =>
            {}
            _ => return Err(L2Error::BadFrame),
        }
    }
    Ok(())
}

/// Reassembles an L3 result into `l3` and returns its total byte length.
///
/// Reads `RESULT_CONT` frames until a `RESULT_OK` frame ends the result. The
/// running length is checked against `l3` on every chunk, and the chunk count
/// is capped at `RECV_MAX_CHUNKS`.
pub(crate) fn recv_encrypted<SPI, W>
(
    spi: &mut SPI,
    wait: &mut W,
    l2: &mut [u8],
    l3: &mut [u8],
)
-> Result<usize, L2Error>
where
    SPI: SpiDevice,
    W: SeWait,
{
    let mut total = 0usize;
    let mut chunks = 0usize;
    loop
    {
        if chunks >= RECV_MAX_CHUNKS
        {
            return Err(L2Error::BadFrame);
        }
        let frame_len = l1::read_response(spi, wait, l2)?;
        let resp = frame::parse_response(&l2[..frame_len])?;
        let data = resp.data;
        let end = total.checked_add(data.len()).ok_or(L2Error::BadFrame)?;
        if end > l3.len()
        {
            return Err(L2Error::BadFrame);
        }
        l3[total..end].copy_from_slice(data);
        total = end;
        chunks += 1;
        match resp.status
        {
            L2Status::ResultCont => continue,
            L2Status::ResultOk => return Ok(total),
            _ => return Err(L2Error::BadFrame),
        }
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::buf::L2_FRAME_MAX;
    use crate::buf::L3_FRAME_MAX;
    use crate::test_support::l2_frame;
    use crate::test_support::MockWait;
    use crate::test_support::ScriptedSpi;

    #[test]
    fn recv_reassembles_a_multi_chunk_result_in_order()
    {
        let c1 = l2_frame(L2Status::ResultCont as u8, &[0xAAu8; L2_CHUNK_MAX_DATA]);
        let c2 = l2_frame(L2Status::ResultCont as u8, &[0xBBu8; L2_CHUNK_MAX_DATA]);
        let c3 = l2_frame(L2Status::ResultOk as u8, &[0xCCu8; 10]);
        let mut spi = ScriptedSpi::new(alloc_frames([c1, c2, c3]));
        let mut wait = MockWait::new();
        let mut l2 = [0u8; L2_FRAME_MAX];
        let mut l3 = [0u8; L3_FRAME_MAX];
        let n = recv_encrypted(&mut spi, &mut wait, &mut l2, &mut l3).unwrap();
        assert_eq!(n, 2 * L2_CHUNK_MAX_DATA + 10);
        assert!(l3[..L2_CHUNK_MAX_DATA].iter().all(|&b| b == 0xAA));
        assert!(l3[L2_CHUNK_MAX_DATA..2 * L2_CHUNK_MAX_DATA].iter().all(|&b| b == 0xBB));
        assert!(l3[2 * L2_CHUNK_MAX_DATA..n].iter().all(|&b| b == 0xCC));
    }

    #[test]
    fn recv_caps_the_chunk_count()
    {
        // RECV_MAX_CHUNKS continuation frames with no terminating ResultOk must
        // stop with an error, never loop unbounded.
        let mut frames = std::vec::Vec::new();
        for _ in 0..RECV_MAX_CHUNKS
        {
            frames.push(l2_frame(L2Status::ResultCont as u8, &[0x01u8; 4]));
        }
        let mut spi = ScriptedSpi::new(frames);
        let mut wait = MockWait::new();
        let mut l2 = [0u8; L2_FRAME_MAX];
        let mut l3 = [0u8; L3_FRAME_MAX];
        assert_eq!(
            recv_encrypted(&mut spi, &mut wait, &mut l2, &mut l3),
            Err(L2Error::BadFrame)
        );
    }

    #[test]
    fn recv_rejects_a_result_larger_than_the_l3_buffer()
    {
        let c1 = l2_frame(L2Status::ResultCont as u8, &[0u8; L2_CHUNK_MAX_DATA]);
        let c2 = l2_frame(L2Status::ResultOk as u8, &[0u8; L2_CHUNK_MAX_DATA]);
        let mut spi = ScriptedSpi::new(alloc_frames([c1, c2]));
        let mut wait = MockWait::new();
        let mut l2 = [0u8; L2_FRAME_MAX];
        // A deliberately tiny L3 buffer: the second chunk overruns it.
        let mut l3 = [0u8; 300];
        assert_eq!(
            recv_encrypted(&mut spi, &mut wait, &mut l2, &mut l3),
            Err(L2Error::BadFrame)
        );
    }

    /// Collects a fixed set of frames into the owned vec `ScriptedSpi` expects.
    fn alloc_frames<const N: usize>(frames: [std::vec::Vec<u8>; N]) -> std::vec::Vec<std::vec::Vec<u8>>
    {
        frames.into_iter().collect()
    }
}
