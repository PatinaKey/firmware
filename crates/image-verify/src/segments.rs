//! Logical view over a segmented image.
//!
//! The image is a list of slices whose concatenation is
//! `HEADER || PAYLOAD || SIGNATURE`. On the device the two bands of a flash bank
//! carry different security attributes and are read through different address
//! aliases, so no contiguous view exists and there is no RAM to assemble one.
//!
//! This module walks the segments by logical offset. Only the header and the
//! signature are ever copied out, into fixed 24- and 64-byte stack arrays. A
//! segment may be empty, the list may be empty, and any field may straddle a
//! boundary.

use crate::error::VerifyError;

/// Sums the segment lengths into the total logical image length.
///
/// # Errors
///
/// [`VerifyError::LengthMismatch`] if the sum overflows `usize`.
pub(crate) fn total_len(segments: &[&[u8]]) -> Result<usize, VerifyError>
{
    let mut total: usize = 0;
    for segment in segments
    {
        total = total
            .checked_add(segment.len())
            .ok_or(VerifyError::LengthMismatch)?;
    }
    Ok(total)
}

/// Copies the logical bytes `[start, start + out.len())` into `out`.
///
/// Walks the segments, skipping past `start`, then fills `out` piece by piece.
/// The range may straddle any number of boundaries and may start or end inside a
/// segment. Used for the two fixed-size fields, the 24-byte header and the
/// 64-byte signature.
///
/// # Errors
///
/// [`VerifyError::TooShort`] if the segments hold fewer than `start + out.len()`
/// bytes.
pub(crate) fn copy_out
(
    segments: &[&[u8]],
    start: usize,
    out: &mut [u8],
)
    -> Result<(), VerifyError>
{
    let mut skip = start;
    let mut written: usize = 0;

    for segment in segments
    {
        if written >= out.len()
        {
            break;
        }
        if skip >= segment.len()
        {
            // The whole segment sits before the range. An empty segment lands
            // here too and is skipped.
            skip -= segment.len();
            continue;
        }
        let src = segment
            .get(skip..)
            .ok_or(VerifyError::TooShort)?;
        skip = 0;
        let room = out
            .len()
            .checked_sub(written)
            .ok_or(VerifyError::TooShort)?;
        let take = core::cmp::min(room, src.len());
        let from = src
            .get(..take)
            .ok_or(VerifyError::TooShort)?;
        let into = out
            .get_mut(written..written + take)
            .ok_or(VerifyError::TooShort)?;
        into.copy_from_slice(from);
        written += take;
    }

    if written != out.len()
    {
        return Err(VerifyError::TooShort);
    }
    Ok(())
}

/// Hands the logical bytes `[0, end)` to `sink`, one borrowed piece per segment.
///
/// Used to stream the digest: the caller passes a hasher update as `sink`, so the
/// signed region is fed to SHA-256 without being copied into one buffer. The last
/// piece is truncated at `end`, which may fall inside a segment. Empty segments are
/// skipped, so `sink` never sees an empty piece.
///
/// # Errors
///
/// [`VerifyError::LengthMismatch`] if the segments hold fewer than `end` bytes.
pub(crate) fn for_each_prefix_piece<F>
(
    segments: &[&[u8]],
    end: usize,
    mut sink: F,
)
    -> Result<(), VerifyError>
where
    F: FnMut(&[u8]),
{
    let mut remaining = end;

    for segment in segments
    {
        if remaining == 0
        {
            break;
        }
        if segment.is_empty()
        {
            continue;
        }
        let take = core::cmp::min(remaining, segment.len());
        let piece = segment
            .get(..take)
            .ok_or(VerifyError::LengthMismatch)?;
        sink(piece);
        remaining -= take;
    }

    if remaining != 0
    {
        return Err(VerifyError::LengthMismatch);
    }
    Ok(())
}

/// The verified payload, yielded as borrowed pieces in logical order.
///
/// Obtained from [`crate::VerifiedImage::payload_segments`]. Concatenating the
/// yielded slices reproduces the payload exactly. The iterator borrows the
/// original segments and copies nothing, so a caller can hash, stream, or flash
/// the payload with no allocation. It never yields an empty piece.
#[derive(Debug, Clone, Copy)]
pub struct PayloadSegments<'a>
{
    segments: &'a [&'a [u8]],
    // Index of the segment the next piece starts in.
    seg: usize,
    // Byte offset of the next piece inside that segment.
    off: usize,
    // Payload bytes still owed.
    remaining: usize,
}

impl<'a> PayloadSegments<'a>
{
    /// Builds an iterator over the logical range `[start, start + len)`.
    ///
    /// The caller has already proven the range lies inside the segments (the
    /// exact-total-length check in [`crate::verify_image`]), so this only positions
    /// the cursor. A range past the end yields nothing, keeping the iterator
    /// panic-free on any input.
    pub(crate) fn new
    (
        segments: &'a [&'a [u8]],
        start: usize,
        len: usize,
    )
        -> PayloadSegments<'a>
    {
        let mut seg: usize = 0;
        let mut skip = start;

        while let Some(segment) = segments.get(seg)
        {
            if skip < segment.len()
            {
                break;
            }
            skip -= segment.len();
            seg += 1;
        }

        PayloadSegments
        {
            segments,
            seg,
            off: skip,
            remaining: len,
        }
    }
}

impl<'a> Iterator for PayloadSegments<'a>
{
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]>
    {
        while self.remaining > 0
        {
            let segment = self.segments.get(self.seg)?;
            let available = segment.len().saturating_sub(self.off);
            if available == 0
            {
                // An empty segment, or one already exhausted. Step over it.
                self.seg += 1;
                self.off = 0;
                continue;
            }
            let take = core::cmp::min(available, self.remaining);
            let piece = segment.get(self.off..self.off + take)?;
            self.off += take;
            self.remaining -= take;
            return Some(piece);
        }
        None
    }
}
