//! Bounds-checked slice parsing combinators.
//!
//! Every function returns a `Result`. None of them index raw, panic, unwrap,
//! or `debug_assert`. Each consumes from the front of the input and returns
//! the remaining tail plus the parsed value. This is the only sanctioned way
//! to read attacker-influenced L2/L3 bytes.

use crate::error::ParseError;

/// Splits `input` into the first `n` bytes and the rest.
///
/// Returns `(head, tail)` where `head.len() == n`. Errors with
/// `ParseError::UnexpectedEnd` when fewer than `n` bytes are present.
pub(crate) fn take(input: &[u8], n: usize) -> Result<(&[u8], &[u8]), ParseError>
{
    match input.split_at_checked(n)
    {
        Some((head, tail)) => Ok((head, tail)),
        None => Err(ParseError::UnexpectedEnd),
    }
}

/// Reads a single byte from the front of `input`.
///
/// Returns `(rest, byte)`. Errors when `input` is empty. Built on
/// `take_array::<1>`, so there is no raw indexing and no dead `None` arm.
pub(crate) fn take_u8(input: &[u8]) -> Result<(&[u8], u8), ParseError>
{
    let (rest, bytes) = take_array::<1>(input)?;
    Ok((rest, bytes[0]))
}

/// Reads a little-endian `u16` from the front of `input`.
///
/// Returns `(rest, value)`. Errors when fewer than 2 bytes remain.
pub(crate) fn take_le_u16(input: &[u8]) -> Result<(&[u8], u16), ParseError>
{
    let (rest, bytes) = take_array::<2>(input)?;
    Ok((rest, u16::from_le_bytes(bytes)))
}

/// Reads a big-endian `u16` from the front of `input`.
///
/// Returns `(rest, value)`. Errors when fewer than 2 bytes remain. The X.509
/// certificate-store header lengths are big-endian, unlike the L2/L3 fields.
pub(crate) fn take_be_u16(input: &[u8]) -> Result<(&[u8], u16), ParseError>
{
    let (rest, bytes) = take_array::<2>(input)?;
    Ok((rest, u16::from_be_bytes(bytes)))
}

/// Reads exactly `N` bytes and returns them as a fixed-size array.
///
/// The array type carries the length proof, so callers avoid a second
/// fallible `try_into`. Returns `(rest, array)`. Errors when fewer than `N`
/// bytes remain.
pub(crate) fn take_array<const N: usize>(input: &[u8]) -> Result<(&[u8], [u8; N]), ParseError>
{
    let (head, tail) = take(input, N)?;
    let mut out = [0u8; N];
    // `head.len()` is exactly N by construction of `take`.
    out.copy_from_slice(head);
    Ok((tail, out))
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn take_splits_and_returns_tail()
    {
        let input = [1u8, 2, 3, 4, 5];
        let (head, tail) = take(&input, 2).unwrap();
        assert_eq!(head, &[1, 2]);
        assert_eq!(tail, &[3, 4, 5]);
    }

    #[test]
    fn take_zero_is_ok()
    {
        let input = [9u8];
        let (head, tail) = take(&input, 0).unwrap();
        assert_eq!(head, &[] as &[u8]);
        assert_eq!(tail, &[9]);
    }

    #[test]
    fn take_too_many_errors()
    {
        let input = [1u8, 2];
        assert_eq!(take(&input, 3), Err(ParseError::UnexpectedEnd));
    }

    #[test]
    fn take_u8_reads_one()
    {
        let (rest, b) = take_u8(&[0xAB, 0xCD]).unwrap();
        assert_eq!(b, 0xAB);
        assert_eq!(rest, &[0xCD]);
    }

    #[test]
    fn take_u8_on_empty_errors()
    {
        assert_eq!(take_u8(&[]), Err(ParseError::UnexpectedEnd));
    }

    #[test]
    fn take_le_u16_is_little_endian()
    {
        let (rest, v) = take_le_u16(&[0x34, 0x12, 0x99]).unwrap();
        assert_eq!(v, 0x1234);
        assert_eq!(rest, &[0x99]);
    }

    #[test]
    fn take_le_u16_short_errors()
    {
        assert_eq!(take_le_u16(&[0x01]), Err(ParseError::UnexpectedEnd));
    }

    #[test]
    fn take_be_u16_is_big_endian()
    {
        let (rest, v) = take_be_u16(&[0x12, 0x34, 0x99]).unwrap();
        assert_eq!(v, 0x1234);
        assert_eq!(rest, &[0x99]);
    }

    #[test]
    fn take_be_u16_short_errors()
    {
        assert_eq!(take_be_u16(&[0x01]), Err(ParseError::UnexpectedEnd));
    }

    #[test]
    fn take_array_reads_fixed()
    {
        let (rest, arr): (&[u8], [u8; 3]) = take_array(&[1, 2, 3, 4]).unwrap();
        assert_eq!(arr, [1, 2, 3]);
        assert_eq!(rest, &[4]);
    }

    #[test]
    fn take_array_short_errors()
    {
        let r: Result<(&[u8], [u8; 4]), ParseError> = take_array(&[1, 2, 3]);
        assert_eq!(r, Err(ParseError::UnexpectedEnd));
    }

    #[test]
    fn combinators_never_panic_on_any_truncation()
    {
        // Exhaustively truncate a buffer and run every combinator. No panic.
        let full = [0x11u8, 0x22, 0x33, 0x44, 0x55];
        for cut in 0..=full.len()
        {
            let s = &full[..cut];
            let _ = take(s, 3);
            let _ = take_u8(s);
            let _ = take_le_u16(s);
            let _: Result<(&[u8], [u8; 4]), ParseError> = take_array(s);
        }
    }
}
