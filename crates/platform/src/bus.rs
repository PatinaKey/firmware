//! The register-access abstraction (the testability seam).
//!
//! The whole partition sequence is written against [`RegisterBus`]: a port that
//! does 32-bit reads and writes at absolute `u32` addresses, plus a
//! read-modify-write helper. The sequence logic NEVER touches a raw pointer.
//!
//! Two implementations exist:
//!   - [`MmioBus`]: the real one. Volatile reads/writes at the actual peripheral
//!     addresses. This is the ONLY place `unsafe` appears in the crate, each block
//!     carrying a `// SAFETY:` note. It is compile-gated to the embedded target so
//!     the host build never references a fixed MMIO address.
//!   - [`RecordingBus`] (test-only): records the exact ordered sequence of writes
//!     as `(address, value)` pairs, and reads back the last value written. Tests
//!     assert BOTH the values AND their order, which is how the sequence's ordering
//!     hazards become regression tests.

/// A 32-bit register-access port.
///
/// `read32`/`write32` move one word at an absolute address. `modify32` is the
/// read-modify-write used to set/clear individual bits without disturbing the
/// rest of a register. Implementors decide how the access is realized (volatile
/// MMIO on hardware, an in-memory trace on the host).
pub trait RegisterBus
{
    /// Reads the 32-bit word at `addr`.
    fn read32(&mut self, addr: u32) -> u32;

    /// Writes the 32-bit `value` to `addr`.
    fn write32(&mut self, addr: u32, value: u32);

    /// Read-modify-writes `addr`: clears the bits in `clear`, then sets `set`.
    ///
    /// Applied as `(old & !clear) | set`. The default impl composes `read32` and
    /// `write32`, so a mock records exactly the resulting write.
    fn modify32(&mut self, addr: u32, clear: u32, set: u32)
    {
        let old = self.read32(addr);
        let new = (old & !clear) | set;
        self.write32(addr, new);
    }
}

/// The real memory-mapped-I/O bus (hardware only).
///
/// Performs volatile 32-bit accesses at the literal peripheral addresses. This is
/// the single `unsafe` surface of the crate. It is gated to `target_os = "none"`
/// so the host (test) build never compiles a fixed-address dereference. Host code
/// drives the sequence through [`RecordingBus`] instead.
#[cfg(target_os = "none")]
pub struct MmioBus;

#[cfg(target_os = "none")]
impl MmioBus
{
    /// Builds the MMIO bus.
    ///
    /// Zero-sized: it holds no state, every access targets an absolute address.
    pub const fn new() -> Self
    {
        MmioBus
    }
}

#[cfg(target_os = "none")]
impl Default for MmioBus
{
    fn default() -> Self
    {
        MmioBus::new()
    }
}

#[cfg(target_os = "none")]
// QUARANTINE: this impl is the crate's ONLY audited `unsafe` surface (raw volatile
// MMIO). The crate denies `unsafe_code` by default (overriding the workspace
// `forbid`). This targeted allow opts in just these two volatile accesses, each of
// which carries its own `// SAFETY:` justification below.
#[allow(unsafe_code)]
impl RegisterBus for MmioBus
{
    fn read32(&mut self, addr: u32) -> u32
    {
        // SAFETY: `addr` is one of the audited peripheral register addresses in
        // `regs.rs`, every one a valid 32-bit-aligned MMIO location on the
        // STM32U545. A volatile read of a device register has no Rust-level
        // aliasing concern (the address is not backed by a Rust object), and the
        // partition sequence is the sole, single-threaded owner of these registers
        // during secure bring-up. The read has no side effect beyond the device's
        // own defined read behaviour.
        unsafe
        {
            core::ptr::read_volatile(addr as *const u32)
        }
    }

    fn write32(&mut self, addr: u32, value: u32)
    {
        // SAFETY: `addr` is one of the audited peripheral register addresses in
        // `regs.rs` (valid, 32-bit-aligned MMIO). The write targets a device
        // register, not a Rust object, so there is no aliasing or provenance
        // concern. Secure bring-up is single-threaded and owns these registers
        // exclusively, so no concurrent access races this store.
        unsafe
        {
            core::ptr::write_volatile(addr as *mut u32, value);
        }
    }
}

#[cfg(test)]
extern crate alloc;

/// A recording register bus for host tests.
///
/// Every `write32` is appended to an ordered log of `(address, value)` pairs, so
/// a test can assert the EXACT order and values the sequence emitted.
///
/// READ-BACK INVARIANT: `read32(addr)` returns the LAST value written to `addr`
/// (or 0 if never written, the reset default). This makes `modify32`
/// (read-modify-write) faithful ONLY on read-write configuration registers, the
/// only kind the partition sequence touches. It does NOT model write-1-to-clear
/// or status registers, where a read does not return the last write, so
/// `modify32` must never target such a register.
#[cfg(test)]
pub struct RecordingBus
{
    writes: alloc::vec::Vec<(u32, u32)>,
}

#[cfg(test)]
impl RecordingBus
{
    /// Builds an empty recording bus (every unwritten address reads 0).
    pub fn new() -> Self
    {
        RecordingBus
        {
            writes: alloc::vec::Vec::new(),
        }
    }

    /// Borrows the ordered write log as `(address, value)` pairs.
    pub fn writes(&self) -> &[(u32, u32)]
    {
        &self.writes
    }

    /// Returns the index of the first write to `addr`, or `None`.
    ///
    /// The ordering-hazard tests compare these indices (e.g. clock-enable index <
    /// any TZSC-write index).
    pub fn first_write_index(&self, addr: u32) -> Option<usize>
    {
        self.writes.iter().position(|(a, _)| *a == addr)
    }

    /// Returns the value of the last write to `addr`, or `None`.
    pub fn last_value(&self, addr: u32) -> Option<u32>
    {
        self.writes.iter().rev().find(|(a, _)| *a == addr).map(|(_, v)| *v)
    }
}

#[cfg(test)]
impl Default for RecordingBus
{
    fn default() -> Self
    {
        RecordingBus::new()
    }
}

#[cfg(test)]
impl RegisterBus for RecordingBus
{
    fn read32(&mut self, addr: u32) -> u32
    {
        // Read-back == last write (see the READ-BACK INVARIANT on the struct).
        // An address never written reads 0, the reset default.
        self.last_value(addr).unwrap_or(0)
    }

    fn write32(&mut self, addr: u32, value: u32)
    {
        self.writes.push((addr, value));
    }
}
