//! STM32U545 MCU platform foundation.
//!
//! The TrustZone runtime partition (SAU/GTZC/GPIO/GPDMA/MPU/TZIC). [`apply_partition`]
//! runs the ordered SAU/GTZC bring-up sequence that the first secure code
//! executes to isolate the device: SAU memory attribution, GTZC peripheral/SRAM/DMA
//! security, GPIO security, the TZIC illegal-access watch, and the sticky in-RAM
//! config locks. [`apply_secure_mpu`] programs the secure-bank MPU (W^X / DEP on
//! the secure world) as the LAST isolation step, which the secure binary applies
//! right before the non-secure hand-off. Neither `apply_partition` nor
//! `apply_secure_mpu` issues an irreversible option-byte write (no TZEN / RDP /
//! BOOT_LOCK / WRP). Those silicon-lifecycle steps wait on the hardware
//! power-fault validation.
//!
//! # Design for testability
//!
//! The whole sequence is written against the [`RegisterBus`] port, so the logic
//! is hardware-independent and 100% host-testable. [`MmioBus`] is the real
//! volatile-MMIO implementation (the crate's ONLY `unsafe`, gated to the embedded
//! target). A host test drives the sequence through a recording bus that captures
//! the exact ordered `(address, value)` write trace, and asserts both the ORDER
//! (encoding the sequence's ordering hazards as regression tests) and the values.
//!
//! # Register definitions
//!
//! The registers in use are HAND-ROLLED and cited (`regs`), not pulled from the
//! full `stm32u5` PAC. A security product's audit surface should be the handful of
//! registers it programs, each traceable to a manual line. The SAU registers are
//! architectural (Armv8-M, not in the device PAC). Every register address and key
//! bit is pinned to a primary-source literal in the `regs` pinning tests.
//!
//! # Out of scope here
//!
//! - The NS hand-off: `SCB_NS->VTOR` + NS MSP + `BXNS` plus the `DSB`/`ISB`
//!   barriers after the MPU enable, which use CPU intrinsics with no register-bus
//!   form. They live in the secure binary's glue.
//! - The C `-mcmse` NSC veneer shim, pending the C toolchain + linker wiring
//!   (no C / build.rs here).

#![cfg_attr(not(test), no_std)]

mod bus;
mod error;
mod map;
mod mpu;
mod partition;
mod regs;

pub use crate::bus::RegisterBus;
#[cfg(target_os = "none")]
pub use crate::bus::MmioBus;
pub use crate::error::PartitionError;
pub use crate::map::SauRegion;
pub use crate::map::SAU_PROGRAMMED_REGIONS;
pub use crate::mpu::apply_secure_mpu;
pub use crate::partition::apply_partition;
