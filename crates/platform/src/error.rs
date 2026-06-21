//! Typed errors for the platform partition bring-up.
//!
//! Most of the partition sequence is a series of infallible MMIO writes, so a
//! `Result` appears only where a failure mode exists: an out-of-range SAU region
//! index or a misaligned SAU region base/limit. No stringly errors.

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
    /// A region must cover a non-empty, ascending address range.
    SauRegionInverted,
}
