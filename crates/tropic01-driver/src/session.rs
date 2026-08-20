//! Session key material and the L3 seal/open primitives.
//!
//! `SessionKeys` owns kCMD, kRES, and the two nonce counters. It seals
//! outgoing commands and opens incoming results in place over the L3 buffer.
//! The type is `ZeroizeOnDrop` and carries no `Debug`/`Clone`/`Copy`, so it
//! cannot leak or duplicate a secret.

use zeroize::Zeroize;
use zeroize::ZeroizeOnDrop;

use crate::crypto;
use crate::error::L3Error;
use crate::error::SeError;
use crate::nonce::NonceCounter;
use crate::parse::take_le_u16;

/// Derived secure-channel keys plus the two nonce counters.
///
/// The AES-256 command and result keys are 32-byte arrays, zeroized on drop.
/// Both nonce counters start at 0. The command nonce advances at seal, the
/// result nonce at verified open. A fault between the two MUST poison the
/// session (the caller's teardown gate), so a desync is never observable.
#[derive(ZeroizeOnDrop)]
pub(crate) struct SessionKeys
{
    /// AES-256-GCM key for the command (host -> chip) direction.
    k_cmd: [u8; 32],
    /// AES-256-GCM key for the result (chip -> host) direction.
    k_res: [u8; 32],
    // The nonce counters are NOT key material, so `ZeroizeOnDrop` skips them.
    // They are still reset to 0 in `wipe()` so a re-handshake on the same holder
    // cannot resume a stale counter.
    /// Command-direction nonce counter.
    #[zeroize(skip)]
    cmd_nonce: NonceCounter,
    /// Result-direction nonce counter.
    #[zeroize(skip)]
    res_nonce: NonceCounter,
}

impl SessionKeys
{
    /// Builds a session-keys holder from derived key material.
    ///
    /// Both nonce counters start at 0 per the protocol. This is `pub(crate)`:
    /// only the handshake constructs it, never an upper layer.
    pub(crate) fn new(k_cmd: [u8; 32], k_res: [u8; 32]) -> Self
    {
        SessionKeys
        {
            k_cmd,
            k_res,
            cmd_nonce: NonceCounter::new(),
            res_nonce: NonceCounter::new(),
        }
    }

    /// Explicitly zeroizes all key bytes and resets both nonce counters.
    /// Idempotent.
    ///
    /// The teardown path calls this on a session-fatal error, in addition to
    /// the `ZeroizeOnDrop` that runs on a normal return. Both IVs are wiped too,
    /// so the two counters are reset to 0 here and a re-handshake starts clean.
    pub(crate) fn wipe(&mut self)
    {
        self.k_cmd.zeroize();
        self.k_res.zeroize();
        self.cmd_nonce.reset();
        self.res_nonce.reset();
    }

    /// Seals an L3 command in place and returns the total wire length.
    ///
    /// On entry `l3[2..2 + plaintext_len]` holds `CMD_ID || CMD_DATA`. Writes
    /// `CMD_SIZE` (little-endian) at `l3[0..2]`, encrypts the plaintext with
    /// kCMD and the next command nonce, and appends the 16-byte tag. Returns
    /// `2 + plaintext_len + 16`. Advances the command nonce.
    ///
    /// Errors with `NonceExhausted` on counter overflow (no encryption happens),
    /// or `L3(Oversize)` if the wire frame would not fit `l3`.
    pub(crate) fn seal_command
    (
        &mut self,
        l3: &mut [u8],
        plaintext_len: usize,
    )
    -> Result<usize, SeError>
    {
        let tag_len = crypto::GCM_TAG_LEN;
        let total = plaintext_len
            .checked_add(2 + tag_len)
            .ok_or(SeError::L3(L3Error::Oversize))?;
        if total > l3.len()
        {
            return Err(SeError::L3(L3Error::Oversize));
        }
        let size = u16::try_from(plaintext_len).map_err(|_| SeError::L3(L3Error::Oversize))?;
        // Peek the IV (exhaustion returns before any I/O). The counter advances
        // ONLY after the encryption below succeeds, so a failed seal never burns
        // a nonce and the cmd/res counters cannot desync.
        let iv = self.cmd_nonce.peek_iv()?;
        l3[0..2].copy_from_slice(&size.to_le_bytes());
        let tag = crypto::aes256gcm_seal(&self.k_cmd, &iv, &[], &mut l3[2..2 + plaintext_len])
            .map_err(|_| SeError::L3(L3Error::Crypto))?;
        l3[2 + plaintext_len..total].copy_from_slice(&tag);
        self.cmd_nonce.commit();
        Ok(total)
    }

    /// Opens an L3 result in place and returns the plaintext length.
    ///
    /// Reads `RES_SIZE` from `l3[0..2]`, decrypts `l3[2..2 + RES_SIZE]` with
    /// kRES and the next result nonce, verifying the trailing 16-byte tag. On
    /// success `l3[2..2 + len]` holds `RESULT || RES_DATA`. Advances the result
    /// nonce.
    ///
    /// Errors with `L3(Oversize)` if the declared size disagrees with `wire_len`
    /// or overruns `l3`, `L3(Tag)` on a tag-verification failure, or
    /// `NonceExhausted` on overflow.
    pub(crate) fn open_result
    (
        &mut self,
        l3: &mut [u8],
        wire_len: usize,
    )
    -> Result<usize, SeError>
    {
        let tag_len = crypto::GCM_TAG_LEN;
        let head = l3.get(..2).ok_or(SeError::L3(L3Error::Oversize))?;
        let (_, res_size) = take_le_u16(head).map_err(|e| SeError::L3(L3Error::Parse(e)))?;
        let res_size = res_size as usize;
        let need = res_size
            .checked_add(2 + tag_len)
            .ok_or(SeError::L3(L3Error::Oversize))?;
        // The reassembled result must be EXACTLY `[RES_SIZE | ct | tag]`: a
        // declared size that disagrees with the received length (trailing bytes
        // or a short frame) is a malformed result, not a valid short read.
        if need != wire_len || need > l3.len()
        {
            return Err(SeError::L3(L3Error::Oversize));
        }
        // Copy the tag out so the ciphertext slice can be borrowed mutably.
        // Bounds: `need == wire_len <= l3.len()` proven above and
        // `need == 2 + res_size + tag_len`, so both ranges are in bounds.
        let mut tag = [0u8; crypto::GCM_TAG_LEN];
        tag.copy_from_slice(&l3[2 + res_size..2 + res_size + tag_len]);
        // Peek the IV. The result counter advances ONLY after the tag verifies,
        // so a tag failure leaves the counter untouched (no desync, no reuse)
        // even before the caller poisons the session.
        let iv = self.res_nonce.peek_iv()?;
        crypto::aes256gcm_open(&self.k_res, &iv, &[], &mut l3[2..2 + res_size], &tag)
            .map_err(|_| SeError::L3(L3Error::Tag))?;
        self.res_nonce.commit();
        Ok(res_size)
    }

    /// Returns the raw `(kCMD, kRES)` for KAT assertions. Test-only.
    #[cfg(test)]
    pub(crate) fn keys_for_test(&self) -> ([u8; 32], [u8; 32])
    {
        (self.k_cmd, self.k_res)
    }

    /// Seeds both nonce counters to exercise exhaustion paths. Test-only.
    #[cfg(test)]
    pub(crate) fn set_nonces_for_test(&mut self, cmd: u32, res: u32)
    {
        self.cmd_nonce = NonceCounter::from_value(cmd);
        self.res_nonce = NonceCounter::from_value(res);
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// Plaintext length of the sealed frame the helpers below build.
    const PLAIN_LEN: usize = 4;

    /// Seals a `PLAIN_LEN`-byte frame and returns the keys, buffer, wire length.
    fn sealed_frame() -> (SessionKeys, [u8; 64], usize)
    {
        let mut keys = SessionKeys::new([0x11u8; 32], [0x11u8; 32]);
        let mut l3 = [0u8; 64];
        l3[2..2 + PLAIN_LEN].copy_from_slice(&[0xA1, 0xA2, 0xA3, 0xA4]);
        let wire = keys.seal_command(&mut l3, PLAIN_LEN).unwrap();
        (keys, l3, wire)
    }

    #[test]
    fn open_result_accepts_the_exact_wire_length()
    {
        let (mut keys, mut l3, wire) = sealed_frame();
        assert_eq!(wire, 2 + PLAIN_LEN + 16);
        assert_eq!(keys.open_result(&mut l3, wire), Ok(PLAIN_LEN));
    }

    #[test]
    fn open_result_rejects_a_wire_length_longer_than_the_declared_size()
    {
        let (mut keys, mut l3, wire) = sealed_frame();
        assert_eq!(
            keys.open_result(&mut l3, wire + 1),
            Err(SeError::L3(L3Error::Oversize))
        );
    }

    #[test]
    fn open_result_rejects_a_wire_length_shorter_than_the_declared_size()
    {
        let (mut keys, mut l3, wire) = sealed_frame();
        assert_eq!(
            keys.open_result(&mut l3, wire - 1),
            Err(SeError::L3(L3Error::Oversize))
        );
    }

    #[test]
    fn open_result_leaves_the_nonce_untouched_on_a_length_rejection()
    {
        let (mut keys, mut l3, wire) = sealed_frame();
        let _ = keys.open_result(&mut l3, wire + 1);
        assert_eq!(keys.open_result(&mut l3, wire), Ok(PLAIN_LEN));
    }
}
