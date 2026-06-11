//! Fixed-capacity, no-heap buffer types and the protocol size constants.
//!
//! All buffers are plain `[u8; N]` arrays owned inside the device handle.
//! The L3 buffer is 16-byte aligned for future SAES/AES-HW/DMA use.

/// Maximum L2 frame size in bytes.
///
/// Layout: 1 id/status + 1 len + 252 data + 2 crc = 256. Matches libtropic's
/// `TR01_L2_MAX_FRAME_SIZE` (status/len/data/crc), one byte over the data cap.
pub(crate) const L2_FRAME_MAX: usize = 256;

/// Maximum L2 data chunk (REQ_DATA / RSP_DATA) in bytes.
///
/// Source: libtropic `TR01_L2_CHUNK_MAX_DATA_SIZE`.
pub(crate) const L2_CHUNK_MAX_DATA: usize = 252;

/// Maximum L3 packet size in bytes.
///
/// Layout: 2 size + 4112 ciphertext-max + 16 tag = 4130. 
/// Matches libtropic's `TR01_L3_PACKET_MAX_SIZE`.
pub(crate) const L3_FRAME_MAX: usize = 4130;

/// A fixed L2 frame buffer.
pub(crate) type L2Buf = [u8; L2_FRAME_MAX];

/// A fixed, 16-byte aligned L3 packet buffer.
///
/// The alignment is pre-emptive for AES hardware and DMA. It costs nothing on
/// a static singleton and never appears in a public signature.
///
/// Not `Clone`/`Copy`: this buffer holds L3 plaintext, a secret. `Copy` would
/// enable a silent, un-zeroized stack duplication.
#[repr(align(16))]
pub(crate) struct L3Buf
{
    bytes: [u8; L3_FRAME_MAX],
}

impl L3Buf
{
    /// Creates a zero-initialized L3 buffer.
    pub(crate) const fn new() -> Self
    {
        L3Buf
        {
            bytes: [0u8; L3_FRAME_MAX],
        }
    }

    /// Borrows the whole buffer immutably.
    pub(crate) fn as_slice(&self) -> &[u8]
    {
        &self.bytes
    }

    /// Borrows the whole buffer mutably.
    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8]
    {
        &mut self.bytes
    }
}

impl Default for L3Buf
{
    fn default() -> Self
    {
        L3Buf::new()
    }
}

// Compile-time invariants. These fail the build if a constant drifts.
const _: () =
{
    // The L2 frame must hold id + len + max data + crc exactly.
    assert!(L2_FRAME_MAX == 1 + 1 + L2_CHUNK_MAX_DATA + 2);
    // The data chunk must fit in a single u8 length field.
    assert!(L2_CHUNK_MAX_DATA <= 252);
    // The L3 frame must hold the 2-byte size, the ciphertext, and the 16 tag.
    assert!(L3_FRAME_MAX == 2 + 4112 + 16);
    // The aligned wrapper holds the whole payload. `align(16)` rounds the
    // struct size up to the next multiple of 16 (4130 -> 4144), so it is at
    // least the payload and within one alignment unit of it.
    assert!(core::mem::size_of::<L3Buf>() >= L3_FRAME_MAX);
    assert!(core::mem::size_of::<L3Buf>() < L3_FRAME_MAX + 16);
    assert!(core::mem::size_of::<L3Buf>().is_multiple_of(16));
};

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn constants_have_expected_values()
    {
        assert_eq!(L2_FRAME_MAX, 256);
        assert_eq!(L2_CHUNK_MAX_DATA, 252);
        assert_eq!(L3_FRAME_MAX, 4130);
    }

    #[test]
    fn l3buf_is_16_byte_aligned()
    {
        assert_eq!(core::mem::align_of::<L3Buf>(), 16);
    }

    #[test]
    fn l3buf_size_is_payload_rounded_to_alignment()
    {
        // align(16) rounds 4130 up to 4144. Still holds the full payload.
        let sz = core::mem::size_of::<L3Buf>();
        assert!(sz >= L3_FRAME_MAX);
        assert!(sz.is_multiple_of(16));
        assert_eq!(sz, 4144);
    }

    #[test]
    fn l3buf_new_is_zeroed()
    {
        let b = L3Buf::new();
        assert!(b.as_slice().iter().all(|&x| x == 0));
    }

    #[test]
    fn l3buf_as_mut_slice_is_writable()
    {
        let mut b = L3Buf::new();
        b.as_mut_slice()[0] = 0xA5;
        assert_eq!(b.as_slice()[0], 0xA5);
        assert!(b.as_slice()[1..].iter().all(|&x| x == 0));
    }
}
