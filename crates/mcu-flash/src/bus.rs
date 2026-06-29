//! The FLASH register-access seam (the testability boundary).
//!
//! The driver never touches a raw pointer. It goes through [`FlashAccess`],
//! which does 32-bit reads / writes / read-modify-writes of the FLASH
//! controller registers (RM0456 sec 7.9.35 Table 79) and 32-bit reads of the
//! memory-mapped bank contents (the inactive bank is memory-mapped, so a
//! readback is a load). This mirrors the `mcu-spi` `SpiBusAccess` pattern.
//!
//! Two implementations exist:
//!   - [`MmioFlash`]: the real one (volatile word MMIO). This is the ONLY
//!     `unsafe` surface of the crate, each block carrying a `// SAFETY:` note.
//!     It is gated to the embedded target so the host build never references a
//!     fixed MMIO address and never compiles a real flash access.
//!   - the host FLASH-controller model (test-only, in `model`): it models the
//!     real controller state (the BSY / WDW handshake, the rc_w1 error flags,
//!     program-clears-bits, the staged SWAP_BANK applied only at a modelled
//!     reset), so the driver's sequencing and fail-closed paths are host-tested
//!     against faithful silicon behaviour, not a per-address value queue.

/// A 32-bit register-access port for the FLASH driver.
///
/// `read32` / `write32` / `modify32` move the FLASH controller registers and
/// load the memory-mapped bank contents. Implementors decide how the access is
/// realized (volatile MMIO on hardware, a state model on the host).
pub trait FlashAccess
{
    /// Reads the 32-bit word at `addr`.
    fn read32(&mut self, addr: u32) -> u32;

    /// Writes the 32-bit `value` to `addr`.
    fn write32(&mut self, addr: u32, value: u32);

    /// Read-modify-writes `addr`: clears the bits in `clear`, then sets `set`.
    ///
    /// Applied as `(old & !clear) | set`. The default impl composes `read32`
    /// and `write32`. It is for CONTROL registers only, where a read returns
    /// the live control value. It must never target a STATUS register whose
    /// flags change on their own.
    fn modify32(&mut self, addr: u32, clear: u32, set: u32)
    {
        let old = self.read32(addr);
        let new = (old & !clear) | set;
        self.write32(addr, new);
    }

    /// Reads the 32-bit word at `addr` through a shared borrow.
    ///
    /// A device-register or memory-mapped-flash load needs no exclusive access,
    /// so the seam exposes a `&self` read used by the inactive-bank borrow,
    /// which the [`fw_update::FlashSeam`] exposes as `&self`.
    fn peek32(&self, addr: u32) -> u32;

    /// Borrows `len` bytes of memory-mapped flash at `base` as a slice.
    ///
    /// On real silicon the inactive bank is memory-mapped, so this is a borrow
    /// of the mapped region with no copy. The host model returns a borrow of its
    /// backing bytes. The seam uses this so verify reads the EXACT bytes commit
    /// boots, the verified image and the committed image being the same bytes by
    /// construction. The [`fw_update::FlashSeam`] trait this driver implements
    /// exposes the same borrow as `inactive_bank`.
    fn bank_view(&self, base: u32, len: usize) -> &[u8];
}

/// The real memory-mapped-I/O port for the FLASH controller (hardware only).
///
/// Volatile 32-bit accesses to the FLASH registers and the memory-mapped bank.
/// It is gated to `target_os = "none"` so the host (test) build never compiles 
/// a fixed-address dereference. 
/// Host code drives the driver through the FLASH-controller model instead.
#[cfg(target_os = "none")]
pub struct MmioFlash;

#[cfg(target_os = "none")]
impl MmioFlash
{
    /// Builds the MMIO port.
    ///
    /// Zero-sized: it holds no state, every access targets an absolute address.
    pub const fn new() -> Self
    {
        MmioFlash
    }
}

#[cfg(target_os = "none")]
impl Default for MmioFlash
{
    fn default() -> Self
    {
        MmioFlash::new()
    }
}

#[cfg(target_os = "none")]
#[allow(unsafe_code)]
impl FlashAccess for MmioFlash
{
    fn read32(&mut self, addr: u32) -> u32
    {
        // SAFETY: `addr` is one of the FLASH register addresses in
        // `regs.rs` or an address inside a memory-mapped bank (RM0456 sec
        // 7.3.1 Table 51), each a 32-bit-aligned location on the
        // STM32U545. A volatile read of a device register or memory-mapped
        // flash has no Rust aliasing concern (the address is not backed by a
        // Rust object), and the secure-world update path is the sole,
        // single-threaded owner of the FLASH controller.
        unsafe
        {
            core::ptr::read_volatile(addr as *const u32)
        }
    }

    fn write32(&mut self, addr: u32, value: u32)
    {
        // SAFETY: `addr` is one of the FLASH register addresses in
        // `regs.rs` (32-bit-aligned MMIO). The write targets a device
        // register, not a Rust object, so there is no aliasing or provenance
        // concern. The secure-world update path is single-threaded and owns the
        // FLASH controller exclusively.
        unsafe
        {
            core::ptr::write_volatile(addr as *mut u32, value);
        }
    }

    fn peek32(&self, addr: u32) -> u32
    {
        // SAFETY: same contract as `read32`, a volatile load of a
        // FLASH register or a memory-mapped flash address. A `&self` read of a
        // device register is sound, the address is not a Rust object and the
        // secure update path is the single-threaded owner.
        unsafe
        {
            core::ptr::read_volatile(addr as *const u32)
        }
    }

    fn bank_view(&self, base: u32, len: usize) -> &[u8]
    {
        // SAFETY: `base` is a bank base inside the memory-mapped flash (RM0456
        // sec 7.3.1 Table 51) and `len` is the pinned bank size, so the whole
        // range is valid, readable, memory-mapped flash. The secure update path
        // is the single-threaded owner, the mapped flash is not written while
        // this borrow is held (the borrow is `&self`), and the bytes are plain
        // `u8` with no alignment constraint.
        unsafe
        {
            core::slice::from_raw_parts(base as *const u8, len)
        }
    }
}
