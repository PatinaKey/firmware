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
    use crate::test_support::RecordingSpi;
    use crate::test_support::ScriptedSpi;

    // Golden L2 SEND frames captured from real libtropic talking to the official
    // TROPIC01 model (ts-tvl). A 600-byte Ping produces a 619-byte L3 packet that
    // libtropic splits into 252 + 252 + 115 byte chunks. A 16-byte Random_Get is
    // a single 20-byte chunk. Each string is the full on-wire frame
    // `[REQ_ID | REQ_LEN | REQ_DATA | CRC(2)]`. Provenance + regeneration steps
    // are in tests/oracle/README.md ("L2 SEND multi-chunk KAT").
    // Regenerate only on a libtropic tag bump.
    const PING_FRAME_0: &str = "04fc5902a65555702757dd4cc280ba0bf17b3efb378ddd7a913a8b1c5c6f755ef80b67aacf8ecb353e172918bd8f030c6656d6e8434fc5814ff4b0e1438eef9338c329b39d4a3e5f2b1ff8045ad2a5fce065c4285306bc41895b20b21f2a401e5cada563489ee02ca095092bb7a4b3f980737820d9dd02a85349e17432b8b312e1269d7f07c32ff48a0a2b044f0487131577a8ba60c9bb01a67dcb4000b30af45989496f3d4cbbb2591abf91b894872f473cd71a0bec415ad9062c9f6fac60ad4d0ea3d0e06aa73b01a8f5819c28d6b3c3ae085ccd82f253d4de6cc352334126ab4b61841561047eaeaf0921e05a22c16c46b4461447f62528bacc0a9fa0a7bb";
    const PING_FRAME_1: &str = "04fc92ebcf60319660dc83a10b3983f605534fa3cf07bc7b36da35ed54963b1a076142ff8a42c4eebcd65b6491e5870a99499da6fe135f0200788d446d84958261bb48b6671f279011e9dc1e135baa96987f06d9d0f69423eba36a2e478fcacb69c0035b4ad1c6a918b20a1aaf5f13df47f8a861c40579afefece1a884bb15e130e7e92cec58f9a8ed83c068e36a4e961ee75763186a7211aa32ef786aa55e223bd995e6b6d208a0fd8791e57b2deecfb34da8efe0ecd70de5f4358eff31f99bf34895e9ba8be22504bf0b51baae92208bb67fa0e7c3a28fb6428a620928ae6807c2476454658d2b33372236717a334dd13a04747cdafd9d5afac87317814f9e";
    const PING_FRAME_2: &str = "0473168199b01097758e0525fc1dc2a13da2e5b44ed1eda0ca3496c247b13483785be00a7179cccd642656ddc8b63eabe0b3b758e751d34145206d4cbb9c92f50a4f794b8819e0c3dfe2ebf6a1e43c4fde69afd206740bdf2b9687bf7d0e00c39963cb44e5b4a961457365bf50cd9d68b636771ce05e26";
    const RANDOM_FRAME: &str = "041402001a4436bd4f5b327dafc33897240d2b819a5e4cc7";

    /// Decodes a hex string to bytes (test helper for the golden frames).
    fn unhex(s: &str) -> std::vec::Vec<u8>
    {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    /// Reconstructs the contiguous L3 packet from a set of SEND frames by
    /// concatenating each frame's REQ_DATA field (`frame[2..2 + REQ_LEN]`).
    fn packet_from_frames(frames: &[std::vec::Vec<u8>]) -> std::vec::Vec<u8>
    {
        let mut packet = std::vec::Vec::new();
        for f in frames
        {
            let dl = f[1] as usize;
            packet.extend_from_slice(&f[2..2 + dl]);
        }
        packet
    }

    #[test]
    fn send_encrypted_chunks_match_libtropic_multi_chunk_golden()
    {
        // Real libtropic split a 619-byte L3 packet into 252/252/115 chunks.
        // Feed our chunker the same packet and assert byte-identical frames.
        let golden: std::vec::Vec<std::vec::Vec<u8>> =
            [PING_FRAME_0, PING_FRAME_1, PING_FRAME_2].iter().map(|h| unhex(h)).collect();
        let packet = packet_from_frames(&golden);
        assert_eq!(packet.len(), 619);
        // One ack per chunk: RequestCont, RequestCont, RequestOk.
        let acks = alloc_frames([
            l2_frame(L2Status::RequestCont as u8, &[]),
            l2_frame(L2Status::RequestCont as u8, &[]),
            l2_frame(L2Status::RequestOk as u8, &[]),
        ]);
        let mut spi = RecordingSpi::new(acks);
        let mut wait = MockWait::new();
        let mut l2 = [0u8; L2_FRAME_MAX];
        send_encrypted(&mut spi, &mut wait, &mut l2, &packet).unwrap();
        assert_eq!(spi.writes(), golden.as_slice());
    }

    #[test]
    fn send_encrypted_single_chunk_matches_libtropic_golden()
    {
        // A 20-byte L3 packet (16-byte Random_Get) is one 0x14-length chunk.
        let golden = alloc_frames([unhex(RANDOM_FRAME)]);
        let packet = packet_from_frames(&golden);
        assert_eq!(packet.len(), 20);
        let acks = alloc_frames([l2_frame(L2Status::RequestOk as u8, &[])]);
        let mut spi = RecordingSpi::new(acks);
        let mut wait = MockWait::new();
        let mut l2 = [0u8; L2_FRAME_MAX];
        send_encrypted(&mut spi, &mut wait, &mut l2, &packet).unwrap();
        assert_eq!(spi.writes(), golden.as_slice());
    }

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
