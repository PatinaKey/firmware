//! STM32U545 embedded-flash driver behind the `fw-update` [`fw_update::FlashSeam`].
//!
//! Provides [`Stm32FlashSeam`], a hand-rolled raw-MMIO flash driver that
//! implements the dual-bank A/B update seam the `fw-update` machine consumes. It
//! bridges the machine's 256-byte logical pages and whole-bank erase to the real
//! hardware granularities: an 8 KB erase page and a 16-byte quad-word program
//! (RM0456 sec 7.3.1 Table 51, sec 7.3.6, sec 7.3.7). Every op returns a typed
//! [`fw_update::FlashError`] and fails closed, clearing the rc_w1 error flags and
//! re-locking the control register from a known state.
//!
//! # Design for testability
//!
//! The driver runs against [`FlashAccess`], a 32-bit register-access seam, so it
//! is hardware-independent and host-testable. [`MmioFlash`] is the real
//! volatile-MMIO implementation (the crate's only `unsafe`, gated to the
//! embedded target). Host tests drive the driver over a faithful FLASH-controller
//! state model that holds TWO physical bank stores whose address-to-store mapping
//! flips on a modelled reset, and reproduces the BSY / WDW handshake, the rc_w1
//! error flags, program-clears-bits, and the staged SWAP_BANK applied only at
//! that reset. So the silicon-only failure modes, including a metadata read from
//! the wrong physical bank after a swap, stay observable rather than hidden
//! behind a green host test.
//!
//! # Brick-safety: the option-byte path is present but inert
//!
//! The [`Stm32FlashSeam`] [`commit_swap`](fw_update::FlashSeam::commit_swap) and
//! [`revert_swap`](fw_update::FlashSeam::revert_swap) impls carry the
//! FULL real option-byte register sequence (OPTR SWAP_BANK plus OPTSTRT plus
//! OBL_LAUNCH, RM0456 sec 7.4.2). OBL_LAUNCH triggers the reset that applies the
//! option load on real silicon, which is the irreversible brick-class step. The
//! whole real register surface is the [`MmioFlash`] port, which does NOT compile
//! on the host. No host build and no test ever performs a real option-byte
//! write: the tests run the state model, which stages the swap and applies it
//! only at a modelled reset, never a real OBL_LAUNCH. The capability is complete
//! but inert. Its on-silicon invocation stays gated on a deliberate operator
//! action.
//!
//! # Register definitions
//!
//! The registers, key values, and bank geometry are HAND-ROLLED and cited
//! (`regs`). Every address, bit, key value, and geometry
//! constant is pinned to a primary-source literal in the `regs` pinning tests.
//! The sources are RM0456 ch.7 (registers, sequences, geometry, the SWAP_BANK
//! physical-versus-mapped contract sec 7.5.8) and AN5347 Table 2 (the
//! secure-alias offset).

#![cfg_attr(not(test), no_std)]

mod bus;
mod driver;
mod regs;

#[cfg(test)]
mod model;

#[cfg(test)]
mod driver_tests;

#[cfg(test)]
mod machine_tests;

#[cfg(target_os = "none")]
pub use crate::bus::MmioFlash;
pub use crate::bus::FlashAccess;
pub use crate::driver::Stm32FlashSeam;
