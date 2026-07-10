//! Typed errors for the platform partition bring-up.
//!
//! Most of the partition sequence is a series of infallible MMIO writes, so a
//! `Result` appears only where a failure mode exists: an out-of-range SAU region
//! index, a misaligned or inverted SAU region, or a misaligned or inverted MPU
//! region. No stringly errors.

/// Errors raised while programming the partition.
///
/// `Copy` and small: the bring-up runs once at boot and these are programming
/// faults (a bad constant in the region table), not runtime conditions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionError
{
    /// An SAU region index was >= the 8 architectural regions.
    ///
    /// Armv8-M defines exactly 8 SAU regions (RNR selects 0..=7). A higher index
    /// cannot be programmed.
    SauRegionOutOfRange,
    /// An SAU region base or limit was not 32-byte aligned.
    ///
    /// `SAU_RBAR.BADDR` / `SAU_RLAR.LADDR` cover bits [31:5], the low 5 bits are
    /// architecturally fixed, so a base or limit with any low bit set is a bug in
    /// the region table (AN5347 Table 1 alignment note).
    SauRegionMisaligned,
    /// An SAU region limit was below its base.
    ///
    /// A region must cover a non-empty, ascending inclusive address range.
    SauRegionInverted,
    /// An MPU region base or limit was not 32-byte aligned.
    ///
    /// `MPU_RBAR.BASE` covers bits [31:5] (low 5 bits architecturally 0) and
    /// `MPU_RLAR.LIMIT` is the inclusive top of a 32-byte unit (low 5 bits 1), so
    /// a base or limit that breaks this granule is a bug in the region table
    /// (PM0264 sec 4.5.13 / 4.5.15).
    MpuRegionMisaligned,
    /// An MPU region limit was below its base.
    ///
    /// A region must cover a non-empty, ascending inclusive address range.
    MpuRegionInverted,
}
