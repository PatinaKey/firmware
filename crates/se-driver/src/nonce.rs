//! AES-GCM nonce counter for the L3 secure channel.
//!
//! The TROPIC01 nonce is a 32-bit counter sitting in the 4 least-significant
//! bytes of the 12-byte IV, little-endian. Bytes 4..12 are always zero.
//! Initial value after a handshake is 0. Usage is post-increment: the current
//! `n` builds the IV, then `n` advances by one.
//!
//! Nonce reuse under a fixed key is catastrophic, so this counter NEVER wraps.
//! At `u32::MAX` it refuses to produce an IV and returns `NonceExhausted`,
//! which the caller treats as session-fatal (teardown + re-handshake).

use crate::error::SeError;

/// A non-wrapping 32-bit AES-GCM nonce counter.
///
/// Not `Clone`, not `Copy`, not public. One owner per session direction.
#[derive(Debug)]
pub(crate) struct NonceCounter(u32);

impl NonceCounter
{
    /// Creates a fresh counter at the post-handshake initial value of 0.
    pub(crate) const fn new() -> Self
    {
        NonceCounter(0)
    }

    /// Resets the counter back to the post-handshake initial value of 0.
    ///
    /// Used by the session teardown path so a re-handshake starts clean.
    pub(crate) fn reset(&mut self)
    {
        self.0 = 0;
    }

    /// Builds the full 12-byte IV for the current counter then advances by one.
    ///
    /// The returned IV is `n` little-endian in bytes `[0..4]`, with bytes
    /// `[4..12]` always zero. On success the counter is incremented. This owns
    /// the whole IV layout, so the caller has no "pre-zero the tail" footgun.
    ///
    /// Returns `Err(SeError::NonceExhausted)` when the counter is already at
    /// `u32::MAX`. In that case no IV is produced and the counter does not
    /// advance, so no nonce is ever reused.
    ///
    /// Any failure between obtaining an IV and a committed transfer MUST poison
    /// the session (enforced in increment 2).
    pub(crate) fn next_iv(&mut self) -> Result<[u8; 12], SeError>
    {
        if self.0 == u32::MAX
        {
            return Err(SeError::NonceExhausted);
        }
        let le = self.0.to_le_bytes();
        let mut iv = [0u8; 12];
        iv[0] = le[0];
        iv[1] = le[1];
        iv[2] = le[2];
        iv[3] = le[3];
        self.0 += 1;
        Ok(iv)
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn starts_at_zero_and_counts_up()
    {
        let mut n = NonceCounter::new();
        for expected in 0u32..5
        {
            let iv = n.next_iv().unwrap();
            assert_eq!(u32::from_le_bytes([iv[0], iv[1], iv[2], iv[3]]), expected);
        }
    }

    #[test]
    fn builds_little_endian_in_first_four()
    {
        // 0x04030201 has four distinct bytes, so LE ordering is unambiguous.
        let mut n = NonceCounter(0x04030201);
        let iv = n.next_iv().unwrap();
        assert_eq!(&iv[0..4], &[0x01, 0x02, 0x03, 0x04]);
        assert!(iv[4..12].iter().all(|&b| b == 0));
    }

    #[test]
    fn returned_iv_tail_is_zero()
    {
        // The returned array owns its layout: the tail must always be zero,
        // regardless of the counter value.
        let mut n = NonceCounter(0xDEADBEEF);
        let iv = n.next_iv().unwrap();
        assert!(iv[4..12].iter().all(|&b| b == 0));
    }

    #[test]
    fn exhaustion_at_u32_max_returns_error()
    {
        let mut n = NonceCounter(u32::MAX);
        let r = n.next_iv();
        assert_eq!(r, Err(SeError::NonceExhausted));
        // Still exhausted on a second attempt (no wrap, no advance).
        assert_eq!(n.next_iv(), Err(SeError::NonceExhausted));
    }

    #[test]
    fn last_valid_value_then_exhausts()
    {
        let mut n = NonceCounter(u32::MAX - 1);
        // The penultimate value is usable.
        let iv = n.next_iv().unwrap();
        assert_eq!(u32::from_le_bytes([iv[0], iv[1], iv[2], iv[3]]), u32::MAX - 1);
        // Now the counter is at MAX and must refuse.
        assert_eq!(n.next_iv(), Err(SeError::NonceExhausted));
    }

    #[test]
    fn reset_returns_counter_to_zero()
    {
        let mut n = NonceCounter(0x1234);
        n.reset();
        let iv = n.next_iv().unwrap();
        assert_eq!(u32::from_le_bytes([iv[0], iv[1], iv[2], iv[3]]), 0);
    }
}
