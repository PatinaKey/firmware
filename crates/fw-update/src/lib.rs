//! Dual-bank A/B firmware-update state machine for the MCU's own firmware.
//!
//! A `no_std`, heap-free, fail-closed library that accumulates a signed update
//! image, verifies it with the `image-verify` crate against a pinned root key,
//! enforces a two-gate anti-rollback, then commits an in-application SWAP_BANK
//! flip as the atomic commit (RM0456 sec 7.5.8) and confirms or reverts on the
//! first boot of the new bank.
//!
//! # Mocked dangerous seam
//!
//! Every irreversible or brick-risk operation (a flash write, an erase, a
//! SWAP_BANK flip, an option load) is reachable only through [`FlashSeam`]. This
//! crate ships the trait, the state machine, and a host mock ([`mock`], gated to
//! tests and the fuzz harness). It emits no real flash write, no real erase, no
//! real SWAP_BANK write, no option-byte write, and no OBL_LAUNCH. The real
//! volatile-flash MMIO driver is a separate hardware-gated crate.
//!
//! # Anti-rollback
//!
//! Gate 1 (UM2851 NVCNT): at install time the verified image security counter is
//! compared against a monotone flash counter read through the seam. A downgrade
//! is rejected. A confirmed update bumps the counter. Gate 2 (the TROPIC01
//! down-counter): after the secure channel is up, a monotonic secure-element
//! counter gates the key-ops accept, not the boot decision. Both gate values are
//! trusted only after the image signature verifies, because the counter lives in
//! the signed region.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

mod machine;
mod mock;
mod seam;

pub use crate::machine::CONFIRM_BOOTS;
pub use crate::machine::PAGE_LEN;
pub use crate::machine::SE_COUNTER_ORIGIN;
pub use crate::machine::UpdateError;
pub use crate::machine::UpdateState;
pub use crate::machine::Updater;
pub use crate::seam::BankId;
pub use crate::seam::FlashError;
pub use crate::seam::FlashSeam;
pub use crate::seam::PageIndex;
pub use crate::seam::PendingFlag;
pub use crate::seam::SeCounterError;
pub use crate::seam::SeCounterSeam;
pub use crate::seam::UpdateOutcome;

#[cfg(any(test, feature = "_fuzz"))]
pub use crate::mock::BANK_LEN;
#[cfg(any(test, feature = "_fuzz"))]
pub use crate::mock::FaultPoint;
#[cfg(any(test, feature = "_fuzz"))]
pub use crate::mock::MockFlash;
#[cfg(any(test, feature = "_fuzz"))]
pub use crate::mock::MockSeCounter;

/// A dev root public key, test only.
///
/// The uncompressed SEC1 P-256 public key of the all-`0x01` private scalar.
/// It is gated to `cfg(test)` and the `_fuzz` feature.
///
/// The production key is pinned by the boot stage. A build that
/// forgets a feature flag must never fall back to this.
#[cfg(any(test, feature = "_fuzz"))]
pub const DEV_ROOT_KEY_TEST_ONLY: [u8; image_verify::ROOT_KEY_LEN] = [
    0x04, 0x6f, 0xf0, 0x3b, 0x94, 0x92, 0x41, 0xce,
    0x1d, 0xad, 0xd4, 0x35, 0x19, 0xe6, 0x96, 0x0e,
    0x0a, 0x85, 0xb4, 0x1a, 0x69, 0xa0, 0x5c, 0x32,
    0x81, 0x03, 0xaa, 0x2b, 0xce, 0x15, 0x94, 0xca,
    0x16, 0x3c, 0x4f, 0x75, 0x3a, 0x55, 0xbf, 0x01,
    0xdc, 0x53, 0xf6, 0xc0, 0xb0, 0xc7, 0xee, 0xe7,
    0x8b, 0x40, 0xc6, 0xff, 0x7d, 0x25, 0xa9, 0x6e,
    0x22, 0x82, 0xb9, 0x89, 0xce, 0xf7, 0x1c, 0x14,
    0x4a,
];

/// The fuzz seam over the receive -> verify -> commit state machine.
///
/// Gated behind the `_fuzz` feature so the normal public API stays minimal. The
/// entry point must never panic on any input. Not part of the supported API.
#[cfg(feature = "_fuzz")]
pub mod fuzz
{
    use crate::MockFlash;
    use crate::MockSeCounter;
    use crate::SE_COUNTER_ORIGIN;
    use crate::UpdateState;
    use crate::Updater;
    use image_verify::RootKey;

    /// Drives the full update machine with attacker-controlled chunk ordering.
    ///
    /// Reads a declared length and a stream of (offset, length, bytes) chunks
    /// from `data`, feeds them through [`Updater::receive_chunk`], then runs
    /// verify, commit, boot, and confirm. The machine must never panic and must
    /// never reach [`UpdateState::Committed`] for an image the verifier did not
    /// accept.
    ///
    /// Returns true when the machine armed the commit.
    pub fn drive_machine(data: &[u8]) -> bool
    {
        let root = match RootKey::from_bytes(crate::DEV_ROOT_KEY_TEST_ONLY)
        {
            Ok(key) => key,
            Err(_) => return false,
        };
        let flash = MockFlash::new(0);
        let se = MockSeCounter::new(SE_COUNTER_ORIGIN);
        let mut up = Updater::new(&root, flash, se);

        // The first two bytes pick a declared length inside the modelled bank.
        let (total_len, mut rest) = match data.split_at_checked(2)
        {
            Some((head, tail)) =>
            {
                let raw = [head[0], head[1]];
                let len = (u16::from_le_bytes(raw) as usize) % (crate::BANK_LEN + 1);
                (len, tail)
            }
            None => (0usize, data),
        };

        if up.begin(total_len).is_err()
        {
            return false;
        }

        // Each record is a 1-byte length prefix then that many payload bytes,
        // fed in order at the running offset. A short tail ends the stream.
        let mut offset = 0usize;
        while let Some((&len, after)) = rest.split_first()
        {
            let take = core::cmp::min(len as usize, after.len());
            let (chunk, tail) = match after.split_at_checked(take)
            {
                Some(pair) => pair,
                None => break,
            };
            if up.receive_chunk(offset, chunk).is_err()
            {
                // A rejected chunk fails closed: the machine must not commit.
                assert_ne!(up.state(), UpdateState::Committed);
                return false;
            }
            offset = offset.saturating_add(chunk.len());
            rest = tail;
        }

        let accepted = up.verify_and_accept().is_ok();
        if !accepted
        {
            // A rejected image must never have armed a swap.
            assert!(!up.flash().committed());
            assert_ne!(up.state(), UpdateState::Committed);
            return false;
        }

        // The verifier accepted: the commit/confirm path must also stay sound.
        if up.commit().is_err()
        {
            return false;
        }
        assert_eq!(up.state(), UpdateState::Committed);
        assert!(up.flash().committed());
        let _ = up.on_boot();
        let _ = up.confirm(0);
        true
    }
}

#[cfg(test)]
mod test_fixtures;

#[cfg(test)]
mod tests;
