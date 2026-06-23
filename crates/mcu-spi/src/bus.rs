//! The SPI1 register-access seam (the testability boundary).
//!
//! The driver and init code never touch a raw pointer. They go through
//! [`SpiBusAccess`], which does:
//!   - 32-bit reads/writes/read-modify-writes for the SPI control, configuration,
//!     and STATUS registers, the RCC clock-enable registers, and the GPIO config
//!     registers, and
//!   - 8-bit reads/writes for the SPI data registers `TXDR` / `RXDR`. The data
//!     registers MUST be accessed at the configured data width. A WIDER access
//!     (a 32-bit access at `DSIZE` = 8) is the hardware data-packing path: it
//!     packs four frames into one register access (RM0456 sec 68.4.12 p.2921).
//!     This driver clocks ONE frame per access, so it needs a byte-wide path.
//!     RM0456 sec 68.8.9-68.8.10 (p.2947) also forbid an access narrower than the
//!     data size.
//!
//! This mirrors the pattern in the `platform` crate's `RegisterBus`, but adds the
//! byte access `platform` does not expose, so the SPI transfer loop and its mock
//! can sit on ONE trait.
//!
//! Two implementations exist:
//!   - [`MmioSpiBus`]: the real one (volatile word and byte MMIO). This is the
//!     ONLY `unsafe` surface of the crate, each block carrying a `// SAFETY:`
//!     note. It is gated to the embedded target so the host build never references
//!     a fixed MMIO address.
//!   - [`ScriptedBus`] (test-only): returns a PROGRAMMED sequence of reads for the
//!     STATUS / data registers, so the transfer loop's status polling can be
//!     host-tested. The `platform` `RecordingBus` cannot do this: it models config
//!     registers (read == last write) and explicitly must not target a STATUS
//!     register whose value changes on its own. `ScriptedBus` is the new test
//!     double the SPI loop needs.

/// A combined word + byte register-access port for the SPI1 driver.
///
/// `read32` / `write32` / `modify32` move the SPI control / config / STATUS, RCC,
/// and GPIO registers. `read8` / `write8` move the SPI `TXDR` / `RXDR` data
/// registers at the byte width `DSIZE` = 8 requires. Implementors decide how the
/// access is realized (volatile MMIO on hardware, a scripted trace on the host).
pub trait SpiBusAccess
{
    /// Reads the 32-bit word at `addr`.
    fn read32(&mut self, addr: u32) -> u32;

    /// Writes the 32-bit `value` to `addr`.
    fn write32(&mut self, addr: u32, value: u32);

    /// Read-modify-writes `addr`: clears the bits in `clear`, then sets `set`.
    ///
    /// Applied as `(old & !clear) | set`. The default impl composes `read32` and
    /// `write32`. It is for CONFIG registers only, where a read returns the last
    /// write. It must never target a STATUS register.
    fn modify32(&mut self, addr: u32, clear: u32, set: u32)
    {
        let old = self.read32(addr);
        let new = (old & !clear) | set;
        self.write32(addr, new);
    }

    /// Reads the 8-bit byte at `addr` (an SPI data register).
    fn read8(&mut self, addr: u32) -> u8;

    /// Writes the 8-bit `value` to `addr` (an SPI data register).
    fn write8(&mut self, addr: u32, value: u8);
}

/// The real memory-mapped-I/O bus for SPI1 (hardware only).
///
/// Volatile 32-bit accesses for the control / config / STATUS / RCC / GPIO
/// registers and volatile 8-bit accesses for `TXDR` / `RXDR`. This is the single
/// `unsafe` surface of the crate. It is gated to `target_os = "none"` so the host
/// (test) build never compiles a fixed-address dereference. Host code drives the
/// driver through [`ScriptedBus`] instead.
#[cfg(target_os = "none")]
pub struct MmioSpiBus;

#[cfg(target_os = "none")]
impl MmioSpiBus
{
    /// Builds the MMIO bus.
    ///
    /// Zero-sized: it holds no state, every access targets an absolute address.
    pub const fn new() -> Self
    {
        MmioSpiBus
    }
}

#[cfg(target_os = "none")]
impl Default for MmioSpiBus
{
    fn default() -> Self
    {
        MmioSpiBus::new()
    }
}

#[cfg(target_os = "none")]
// QUARANTINE: this impl is the crate's ONLY audited `unsafe` surface (raw volatile
// MMIO). The crate denies `unsafe_code` by default (overriding the workspace
// `forbid`). This targeted allow opts in just these volatile accesses, each of
// which carries its own `// SAFETY:` justification below.
#[allow(unsafe_code)]
impl SpiBusAccess for MmioSpiBus
{
    fn read32(&mut self, addr: u32) -> u32
    {
        // SAFETY: `addr` is one of the audited 32-bit register addresses in
        // `regs.rs` (SPI control / config / STATUS, RCC, GPIO), each a valid
        // 32-bit-aligned MMIO location on the STM32U545. A volatile read of a
        // device register has no Rust aliasing concern (the address is not backed
        // by a Rust object), and the secure SPI bring-up is the sole,
        // single-threaded owner of these registers.
        unsafe
        {
            core::ptr::read_volatile(addr as *const u32)
        }
    }

    fn write32(&mut self, addr: u32, value: u32)
    {
        // SAFETY: `addr` is one of the audited 32-bit register addresses in
        // `regs.rs` (valid, 32-bit-aligned MMIO). The write targets a device
        // register, not a Rust object, so there is no aliasing or provenance
        // concern. Secure SPI bring-up is single-threaded and owns these registers
        // exclusively.
        unsafe
        {
            core::ptr::write_volatile(addr as *mut u32, value);
        }
    }

    fn read8(&mut self, addr: u32) -> u8
    {
        // SAFETY: `addr` is the SPI1 `RXDR` data register. RM0456 sec 68.8.10
        // requires a byte-wide access when `DSIZE` = 8, so this reads exactly one
        // byte. The address is a device register, not a Rust object, so a volatile
        // byte read has no aliasing concern. Single-threaded ownership holds as
        // above.
        unsafe
        {
            core::ptr::read_volatile(addr as *const u8)
        }
    }

    fn write8(&mut self, addr: u32, value: u8)
    {
        // SAFETY: `addr` is the SPI1 `TXDR` data register. RM0456 sec 68.8.9
        // requires a byte-wide access when `DSIZE` = 8, so this writes exactly one
        // byte. The address is a device register, not a Rust object, so a volatile
        // byte write has no aliasing concern. Single-threaded ownership holds as
        // above.
        unsafe
        {
            core::ptr::write_volatile(addr as *mut u8, value);
        }
    }
}

#[cfg(test)]
mod scripted;

#[cfg(test)]
pub(crate) use scripted::ScriptedBus;
#[cfg(test)]
pub(crate) use scripted::Write;
