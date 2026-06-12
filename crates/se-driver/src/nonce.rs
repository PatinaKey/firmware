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
// No Debug: the counter lives inside the secret-bearing SessionKeys, and
// nothing in that containment chain may be printable.
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

    /// Builds a counter at a chosen value, to exercise exhaustion. Test-only.
    #[cfg(test)]
    pub(crate) fn from_value(v: u32) -> Self
    {
        NonceCounter(v)
    }

    /// Builds the 12-byte IV for the current counter WITHOUT advancing it.
    ///
    /// The IV is `n` little-endian in bytes `[0..4]`, with bytes `[4..12]`
    /// always zero, so the caller has no "pre-zero the tail" footgun.
    ///
    /// Returns `Err(SeError::NonceExhausted)` when the counter is already at
    /// `u32::MAX` (the value the chip refuses): no IV is produced. Pair every
    /// successful `peek_iv` with one `commit` AFTER the crypto operation that
    /// used the IV succeeds, so a failed encrypt/decrypt never advances the
    /// counter and the cmd/res counters cannot desync even without a poison.
    pub(crate) fn peek_iv(&self) -> Result<[u8; 12], SeError>
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
        Ok(iv)
    }

    /// Advances the counter by one after a successful use of the peeked IV.
    ///
    /// Call only after `peek_iv` returned `Ok` and the crypto step committed.
    /// Uses a saturating add so even a misuse (commit without a fresh peek)
    /// pins at `u32::MAX` rather than wrapping back to a reusable nonce.
    pub(crate) fn commit(&mut self)
    {
        self.0 = self.0.saturating_add(1);
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn starts_at_zero_and_counts_up_on_commit()
    {
        let mut n = NonceCounter::new();
        for expected in 0u32..5
        {
            let iv = n.peek_iv().unwrap();
            assert_eq!(u32::from_le_bytes([iv[0], iv[1], iv[2], iv[3]]), expected);
            n.commit();
        }
    }

    #[test]
    fn peek_without_commit_does_not_advance()
    {
        // The whole point of peek/commit: a peeked IV that is never committed
        // (e.g. the crypto step failed) must not advance the counter.
        let n = NonceCounter::new();
        let a = n.peek_iv().unwrap();
        let b = n.peek_iv().unwrap();
        assert_eq!(a, b);
        assert_eq!(u32::from_le_bytes([a[0], a[1], a[2], a[3]]), 0);
    }

    #[test]
    fn builds_little_endian_in_first_four()
    {
        // 0x04030201 has four distinct bytes, so LE ordering is unambiguous.
        let n = NonceCounter(0x04030201);
        let iv = n.peek_iv().unwrap();
        assert_eq!(&iv[0..4], &[0x01, 0x02, 0x03, 0x04]);
        assert!(iv[4..12].iter().all(|&b| b == 0));
    }

    #[test]
    fn returned_iv_tail_is_zero()
    {
        // The returned array owns its layout: the tail must always be zero,
        // regardless of the counter value.
        let n = NonceCounter(0xDEADBEEF);
        let iv = n.peek_iv().unwrap();
        assert!(iv[4..12].iter().all(|&b| b == 0));
    }

    #[test]
    fn exhaustion_at_u32_max_returns_error()
    {
        let n = NonceCounter(u32::MAX);
        assert_eq!(n.peek_iv(), Err(SeError::NonceExhausted));
        // Still exhausted on a second attempt (no wrap, no advance).
        assert_eq!(n.peek_iv(), Err(SeError::NonceExhausted));
    }

    #[test]
    fn last_valid_value_then_exhausts()
    {
        let mut n = NonceCounter(u32::MAX - 1);
        // The penultimate value is usable.
        let iv = n.peek_iv().unwrap();
        assert_eq!(u32::from_le_bytes([iv[0], iv[1], iv[2], iv[3]]), u32::MAX - 1);
        n.commit();
        // Now the counter is at MAX and must refuse.
        assert_eq!(n.peek_iv(), Err(SeError::NonceExhausted));
    }

    #[test]
    fn commit_saturates_and_never_wraps()
    {
        // Defensive: a commit at MAX (misuse) pins at MAX, never wraps to 0.
        let mut n = NonceCounter(u32::MAX);
        n.commit();
        assert_eq!(n.peek_iv(), Err(SeError::NonceExhausted));
    }

    #[test]
    fn reset_returns_counter_to_zero()
    {
        let mut n = NonceCounter(0x1234);
        n.reset();
        let iv = n.peek_iv().unwrap();
        assert_eq!(u32::from_le_bytes([iv[0], iv[1], iv[2], iv[3]]), 0);
    }
}
