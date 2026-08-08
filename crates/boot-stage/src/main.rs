//! Immutable first-stage boot code for the A/B update model.
//!
//! Runs from pages 2-8 of whichever bank the hardware boots (SECBOOTADD0 =
//! 0x0C004000, selected by SWAP_BANK). It checks the partition and the secure
//! watermarks, verifies the running bank's signed image against the pinned
//! product root key, confirms or reverts a pending A/B swap, then hands off to the
//! secure app at 0x0C014000.
//!
//! # Two builds
//!
//! - Target (`target_os = "none"`): a `no_std` / `no_main` cortex-m-rt binary. The
//!   `entry` and `real` modules hold the untestable silicon glue (the real flash
//!   driver port, the register reads, and the secure-to-secure hand-off jump).
//! - Host: an empty `main`, so the whole workspace stays host-checkable. The pure
//!   decision, the health check, the SECWM decode, and the boot flow over a state
//!   mock are all exercised by `cargo test`.
//!
//! # Anti-brick contract
//!
//! The boot decision is a pure function ([`decision::decide`]) over the persistent
//! state, proven exhaustively on the host across every post-cut state. The NVCNT
//! anti-rollback bump is done last and is mutually exclusive with a revert, so the
//! rollback floor can never rise above a bank that is then reverted away. Nothing
//! irreversible runs on silicon in this crate's host-proof build.

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]
// The host build with no test harness is an empty `main` that references none of
// the boot logic, so its pub(crate) items are unused there by design. dead_code
// stays a live warning in the test and target builds, where the logic is used.
#![cfg_attr(not(any(test, target_os = "none")), allow(dead_code))]

mod decision;
mod glue;
mod health;
mod key;
mod seam;
mod secwm;

// Silicon-only glue, compiled only for the embedded target.
#[cfg(target_os = "none")]
mod entry;
#[cfg(target_os = "none")]
mod real;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

/// Host stub entry. The real reset vector is the target-only `entry` module.
#[cfg(not(target_os = "none"))]
fn main()
{
}
