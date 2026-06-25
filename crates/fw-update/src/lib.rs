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
//! SWAP_BANK flip, an option load) is reachable ONLY through [`FlashSeam`]. This
//! crate ships the trait, the state machine, and a HOST MOCK ([`mock`], gated to
//! tests and the fuzz harness). It emits NO real flash write, NO real erase, NO
//! real SWAP_BANK write, NO option-byte write, and NO OBL_LAUNCH. The real
//! volatile-flash MMIO driver is a separate hardware-gated crate.
//!
//! # Anti-rollback
//!
//! Gate 1 (UM2851 NVCNT): at install time the verified image security counter is
//! compared against a monotone flash counter read through the seam. A downgrade
//! is rejected. A confirmed update bumps the counter. Gate 2 (the TROPIC01
//! down-counter): after the secure channel is up, a monotonic secure-element
//! counter gates the key-ops accept, not the boot decision. Both gate values are
//! trusted only after the Ed25519 signature verifies, because the counter lives
//! in the signed region.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

#[cfg(test)]
mod fidelity;
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

#[cfg(any(test, feature = "_fuzz"))]
pub use crate::mock::BANK_LEN;
#[cfg(any(test, feature = "_fuzz"))]
pub use crate::mock::FaultPoint;
#[cfg(any(test, feature = "_fuzz"))]
pub use crate::mock::MockFlash;
#[cfg(any(test, feature = "_fuzz"))]
pub use crate::mock::MockSeCounter;

/// A DEV / placeholder Ed25519 root public key for host tests.
///
/// This is NOT the production key. The secure binary pins the genuine public key
/// out-of-band as a const when the boot flow lands. Compiling a PUBLIC key into
/// the firmware is fully reversible by a reflash. It is NOT the irreversible
/// TROPIC01 pairing-key write, so no brick rule is triggered. The verify path
/// takes the key as input, so this library stays testable.
///
/// The bytes are the public key of the all-`0x01` Ed25519 secret scalar, an
/// on-curve point that `RootKey::from_bytes` accepts.
pub const DEV_ROOT_KEY: [u8; 32] = [
    0x8a, 0x88, 0xe3, 0xdd, 0x74, 0x09, 0xf1, 0x95,
    0xfd, 0x52, 0xdb, 0x2d, 0x3c, 0xba, 0x5d, 0x72,
    0xca, 0x67, 0x09, 0xbf, 0x1d, 0x94, 0x12, 0x1b,
    0xf3, 0x74, 0x88, 0x01, 0xb4, 0x0f, 0x6f, 0x5c,
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
    use crate::UpdateState;
    use crate::Updater;
    use image_verify::RootKey;

    /// Drives the full update machine with attacker-controlled chunk ordering.
    ///
    /// Reads a declared length and a stream of (offset, length, bytes) chunks
    /// from `data`, feeds them through [`Updater::receive_chunk`], then runs
    /// verify, commit, boot, and confirm. The machine must never panic and must
    /// never reach [`UpdateState::Committed`] for an image the verifier did not
    /// accept. A genuinely valid image is essentially never produced by mutation,
    /// so the path under test is the fail-closed rejection across the whole flow.
    pub fn drive_machine(data: &[u8])
    {
        let root = match RootKey::from_bytes(crate::DEV_ROOT_KEY)
        {
            Ok(key) => key,
            Err(_) => return,
        };
        let flash = MockFlash::new(0);
        let se = MockSeCounter::new(0);
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
            return;
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
                return;
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
            return;
        }

        // The verifier accepted: the commit/confirm path must also stay sound.
        if up.commit().is_ok()
        {
            let _ = up.on_boot();
            let _ = up.confirm(0);
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod power_fault;
