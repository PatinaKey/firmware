//! Session key material for the L3 secure channel.
//!
//! Increment 1 ships a minimal placeholder so the type-state compiles. The
//! Noise KK1 handshake and the real key derivation arrive in a later increment.
//! The type is already `ZeroizeOnDrop` and carries no `Debug`/`Clone`/`Copy`,
//! so the type cannot leak or duplicate a secret.

use zeroize::Zeroize;
use zeroize::ZeroizeOnDrop;

use crate::nonce::NonceCounter;

/// Derived secure-channel keys plus the two lock-step nonce counters.
///
/// Placeholder layout for increment 1: the AES-256 command and result keys
/// are 32-byte arrays, zeroized on drop. The nonce counters start at 0 and
/// advance one step per round-trip.
#[derive(ZeroizeOnDrop)]
pub(crate) struct SessionKeys
{
    /// AES-256-GCM key for the command (host -> chip) direction.
    k_cmd: [u8; 32],
    /// AES-256-GCM key for the result (chip -> host) direction.
    k_res: [u8; 32],
    // The nonce counters are NOT key material, so `ZeroizeOnDrop` skips them.
    // They are still reset to 0 in `wipe()` (design sec 3.1: wipe both IVs) so
    // a re-handshake on the same holder cannot resume a stale counter.
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
    /// the `ZeroizeOnDrop` that runs on a normal return. Design sec 3.1
    /// requires wiping both IVs, so the two counters are reset to 0 here.
    pub(crate) fn wipe(&mut self)
    {
        self.k_cmd.zeroize();
        self.k_res.zeroize();
        self.cmd_nonce.reset();
        self.res_nonce.reset();
    }
}
