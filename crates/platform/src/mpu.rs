//! The secure MPU (Armv8-M PMSAv8, banked secure bank) programming.
//!
//! [`apply_secure_mpu`] programs the secure-bank MPU to enforce W^X / DEP on the
//! secure world: secure code is read-only executable, secure data and the secure
//! peripheral aliases are read-write execute-never. It runs as the LAST isolation
//! step, right before the non-secure hand-off, driven through the [`RegisterBus`]
//! seam so the sequence is 100% host-testable.
//!
//! No background map: `MPU_CTRL.PRIVDEFENA` stays 0, so every secure access must
//! match one of the three enabled regions or fault (strict least privilege). The
//! SCS region 0xE000_E000-0xE000_EFFF is always Device + XN accessible regardless
//! of the MPU, so the SAU / MPU / SCB registers need no region (PM0264 line 13199).
//!
//! This is RUNTIME configuration only. It touches NO irreversible / lifecycle bit
//! (no TZEN / RDP / BOOT_LOCK / WRP / option byte / OBL_LAUNCH).

use crate::bus::RegisterBus;
use crate::error::PartitionError;
use crate::map;
use crate::regs;

/// The number of secure MPU regions programmed (of the 8 implemented).
pub(crate) const MPU_PROGRAMMED_REGIONS: usize = 3;

/// Data-access permission for a region (`MPU_RBAR.AP`).
///
/// Only the two privileged-only encodings are used: the secure world runs
/// privileged, and no region grants unprivileged access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Access
{
    /// Read-write, privileged only (`AP = 0b00`).
    ReadWritePriv,
    /// Read-only, privileged only (`AP = 0b10`).
    ReadOnlyPriv,
}

impl Access
{
    /// The 2-bit `AP` field value.
    const fn ap_bits(self) -> u32
    {
        match self
        {
            Access::ReadWritePriv => regs::MPU_AP_RW_PRIV,
            Access::ReadOnlyPriv => regs::MPU_AP_RO_PRIV,
        }
    }

    /// True when the region grants any write access.
    ///
    /// Used by the W^X invariant test to prove no region is both writable and
    /// executable.
    #[allow(dead_code)]
    const fn is_writable(self) -> bool
    {
        matches!(self, Access::ReadWritePriv)
    }
}

/// Execute permission for a region (`MPU_RBAR.XN`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Exec
{
    /// Execution allowed (`XN = 0`).
    Allow,
    /// Execute-never (`XN = 1`).
    Never,
}

impl Exec
{
    /// The 1-bit `XN` field value.
    const fn xn_bit(self) -> u32
    {
        match self
        {
            Exec::Allow => 0,
            Exec::Never => regs::MPU_RBAR_XN,
        }
    }
}

/// A single secure MPU region: an inclusive `[base, limit]` range plus its
/// access, execute, and memory-attribute settings.
///
/// Built only through [`MpuRegion::new`], which enforces the 32-byte alignment
/// and ascending-range invariants, so a malformed region can never reach the
/// register-write step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MpuRegion
{
    base: u32,
    limit: u32,
    access: Access,
    exec: Exec,
    attr_index: u32,
}

impl MpuRegion
{
    /// Builds a validated MPU region covering the inclusive range `[base, limit]`.
    ///
    /// `access` sets the data permission, `exec` the execute permission, and
    /// `attr_index` selects the MAIR attribute byte (0 = Normal, 1 = Device).
    ///
    /// # Errors
    ///
    /// - `PartitionError::MpuRegionMisaligned` if `base` is not 32-byte aligned
    ///   (low 5 bits set) or `limit` is not an inclusive 32-byte top (low 5 bits
    ///   clear).
    /// - `PartitionError::MpuRegionInverted` if `limit < base`.
    pub(crate) const fn new(
        base: u32,
        limit: u32,
        access: Access,
        exec: Exec,
        attr_index: u32,
    ) -> Result<Self, PartitionError>
    {
        // BASE[31:5] requires the low 5 bits of `base` clear. LIMIT is the
        // inclusive top of a 32-byte unit, so the low 5 bits of `limit` must all
        // read as 1. Same granule contract as the SAU region.
        if base & regs::MPU_ALIGN_MASK != 0
        {
            return Err(PartitionError::MpuRegionMisaligned);
        }
        if limit & regs::MPU_ALIGN_MASK != regs::MPU_ALIGN_MASK
        {
            return Err(PartitionError::MpuRegionMisaligned);
        }
        if limit < base
        {
            return Err(PartitionError::MpuRegionInverted);
        }
        Ok(MpuRegion
        {
            base,
            limit,
            access,
            exec,
            attr_index,
        })
    }

    /// The value to write to `MPU_RBAR`: BASE[31:5] | SH[4:3] | AP[2:1] | XN.
    ///
    /// SH is fixed non-shareable (0b00) for all three regions.
    pub(crate) const fn rbar(self) -> u32
    {
        // `base` is already 32-byte aligned (the constructor cleared the low 5
        // bits), so it is the BASE field directly.
        let base = self.base;
        let sh = regs::MPU_SH_NON_SHAREABLE << regs::MPU_RBAR_SH_SHIFT;
        let ap = self.access.ap_bits() << regs::MPU_RBAR_AP_SHIFT;
        let xn = self.exec.xn_bit();
        base | sh | ap | xn
    }

    /// The value to write to `MPU_RLAR`: LIMIT[31:5] | AttrIndx[3:1] | EN.
    ///
    /// LIMIT is `limit` with its low 5 bits cleared. The region is always enabled.
    pub(crate) const fn rlar(self) -> u32
    {
        let limit = self.limit & !regs::MPU_ALIGN_MASK;
        let attr = self.attr_index << regs::MPU_RLAR_ATTRINDX_SHIFT;
        limit | attr | regs::MPU_RLAR_EN
    }
}

/// Builds the validated secure MPU region table in `MPU_RNR` order.
///
/// - R0 secure code: RX read-only (AP RO priv, XN allow), Normal memory.
/// - R1 secure SRAM: RW execute-never (AP RW priv, XN never), Normal memory.
/// - R2 secure peripherals: RW execute-never (AP RW priv, XN never), Device.
///
/// # Errors
///
/// `PartitionError` if any constant in the table violates the MPU alignment or
/// ordering invariants. The fault surfaces before any hardware write, so a bad
/// edit fails the host tests rather than mis-programming silicon.
pub(crate) fn mpu_table() -> Result<[MpuRegion; MPU_PROGRAMMED_REGIONS], PartitionError>
{
    Ok([
        // R0: secure code, read-only executable (W^X: the only X region, never W).
        MpuRegion::new(
            map::MPU_CODE_BASE,
            map::MPU_CODE_LIMIT,
            Access::ReadOnlyPriv,
            Exec::Allow,
            regs::MPU_ATTRINDX_NORMAL,
        )?,
        // R1: secure SRAM, read-write execute-never (W^X: writable, never X).
        MpuRegion::new(
            map::MPU_SRAM_BASE,
            map::MPU_SRAM_LIMIT,
            Access::ReadWritePriv,
            Exec::Never,
            regs::MPU_ATTRINDX_NORMAL,
        )?,
        // R2: secure peripherals, read-write execute-never device memory.
        MpuRegion::new(
            map::MPU_PERIPH_BASE,
            map::MPU_PERIPH_LIMIT,
            Access::ReadWritePriv,
            Exec::Never,
            regs::MPU_ATTRINDX_DEVICE,
        )?,
    ])
}

/// Programs and enables the secure MPU in the one safe order.
///
/// FAIL-CLOSED: the region table is built and validated FIRST, before any write,
/// so a malformed table aborts with no half-applied MPU state. Then:
/// 1. `MPU_CTRL = 0` to disable the MPU while programming,
/// 2. `MPU_MAIR0` with the Normal / Device attribute bytes,
/// 3. per region in `MPU_RNR` order: `MPU_RNR`, `MPU_RBAR`, `MPU_RLAR`,
/// 4. `MPU_CTRL = ENABLE | HFNMIENA` (PRIVDEFENA stays 0: no background map).
///
/// The caller MUST issue `DSB` then `ISB` after this returns so the new MPU
/// configuration takes effect before any dependent access. Those barriers are CPU
/// intrinsics with no register-bus form, so they live in the secure binary glue.
///
/// # Errors
///
/// `PartitionError` only from building the region table, surfaced before any
/// hardware write. Every other step is an infallible register write.
pub fn apply_secure_mpu<B>(bus: &mut B) -> Result<(), PartitionError>
where
    B: RegisterBus,
{
    // FAIL-CLOSED: validate the whole table before touching the MPU. A bad
    // constant aborts here with the MPU still disabled (its reset state), never
    // half-programmed.
    let table = mpu_table()?;

    // Disable the MPU while reprogramming.
    bus.write32(regs::MPU_CTRL, 0);

    // Memory attributes: Attr0 = Normal, Attr1 = Device. MAIR1 stays at reset (0).
    bus.write32(regs::MPU_MAIR0, regs::MPU_MAIR0_VALUE);

    for (region, entry) in (0u32..).zip(table.iter())
    {
        bus.write32(regs::MPU_RNR, region);
        bus.write32(regs::MPU_RBAR, entry.rbar());
        bus.write32(regs::MPU_RLAR, entry.rlar());
    }

    // Enable with HFNMIENA so the MPU stays active in HardFault / NMI. PRIVDEFENA
    // is left 0: no background map, every secure access must hit a region.
    bus.write32(regs::MPU_CTRL, regs::MPU_CTRL_ENABLE | regs::MPU_CTRL_HFNMIENA);
    Ok(())
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::bus::RecordingBus;

    /// Runs the sequence and returns the recording bus for inspection.
    fn run() -> RecordingBus
    {
        let mut bus = RecordingBus::new();
        apply_secure_mpu(&mut bus).expect("secure MPU must apply");
        bus
    }

    #[test]
    fn table_builds_and_validates()
    {
        let t = mpu_table().expect("table must validate");
        assert_eq!(t.len(), MPU_PROGRAMMED_REGIONS);
    }

    #[test]
    fn region_rejects_misaligned_base()
    {
        assert_eq!(
            MpuRegion::new(
                0x0C00_0001,
                0x0C03_FFFF,
                Access::ReadOnlyPriv,
                Exec::Allow,
                regs::MPU_ATTRINDX_NORMAL
            ),
            Err(PartitionError::MpuRegionMisaligned)
        );
    }

    #[test]
    fn region_rejects_misaligned_limit()
    {
        // A limit must be the inclusive top of a 32-byte unit (low 5 bits set).
        assert_eq!(
            MpuRegion::new(
                0x0C00_0000,
                0x0C03_FFF0,
                Access::ReadOnlyPriv,
                Exec::Allow,
                regs::MPU_ATTRINDX_NORMAL
            ),
            Err(PartitionError::MpuRegionMisaligned)
        );
    }

    #[test]
    fn region_rejects_inverted_range()
    {
        assert_eq!(
            MpuRegion::new(
                0x2002_0000,
                0x2000_001F,
                Access::ReadWritePriv,
                Exec::Never,
                regs::MPU_ATTRINDX_NORMAL
            ),
            Err(PartitionError::MpuRegionInverted)
        );
    }

    #[test]
    fn region_rbar_rlar_encode_code_region()
    {
        // R0 secure code: AP RO priv (0b10), XN allow (0), SH 00, Normal index.
        let r = MpuRegion::new(
            0x0C00_0000,
            0x0C03_FFFF,
            Access::ReadOnlyPriv,
            Exec::Allow,
            regs::MPU_ATTRINDX_NORMAL,
        )
        .expect("valid");
        // RBAR low bits: SH 00 | AP 10 | XN 0 = 0b0100 = 0x4.
        assert_eq!(r.rbar(), 0x0C00_0004);
        // RLAR: LIMIT[31:5] | (Normal=0 << 1) | EN.
        assert_eq!(r.rlar(), 0x0C03_FFE0 | regs::MPU_RLAR_EN);
    }

    #[test]
    fn region_rbar_rlar_encode_sram_region()
    {
        // R1 secure SRAM: AP RW priv (0b00), XN never (1), SH 00, Normal index.
        let r = MpuRegion::new(
            0x2000_0000,
            0x2001_FFFF,
            Access::ReadWritePriv,
            Exec::Never,
            regs::MPU_ATTRINDX_NORMAL,
        )
        .expect("valid");
        // RBAR low bits: SH 00 | AP 00 | XN 1 = 0x1.
        assert_eq!(r.rbar(), 0x2000_0001);
        assert_eq!(r.rlar(), 0x2001_FFE0 | regs::MPU_RLAR_EN);
    }

    #[test]
    fn region_rbar_rlar_encode_periph_region()
    {
        // R2 secure peripherals: AP RW priv (0b00), XN never (1), Device index 1.
        let r = MpuRegion::new(
            0x5000_0000,
            0x5FFF_FFFF,
            Access::ReadWritePriv,
            Exec::Never,
            regs::MPU_ATTRINDX_DEVICE,
        )
        .expect("valid");
        assert_eq!(r.rbar(), 0x5000_0001);
        // RLAR: LIMIT[31:5] | (Device index << AttrIndx shift) | EN.
        assert_eq!(
            r.rlar(),
            0x5FFF_FFE0
                | (regs::MPU_ATTRINDX_DEVICE << regs::MPU_RLAR_ATTRINDX_SHIFT)
                | regs::MPU_RLAR_EN
        );
    }

    #[test]
    fn ctrl_disabled_first_then_enabled_last()
    {
        let bus = run();
        let ctrl: alloc::vec::Vec<u32> = bus
            .writes()
            .iter()
            .filter(|(a, _)| *a == regs::MPU_CTRL)
            .map(|(_, v)| *v)
            .collect();
        // First CTRL write disables, last enables with ENABLE | HFNMIENA.
        assert_eq!(ctrl.first(), Some(&0u32), "MPU disabled first");
        assert_eq!(
            ctrl.last(),
            Some(&(regs::MPU_CTRL_ENABLE | regs::MPU_CTRL_HFNMIENA)),
            "MPU enabled last"
        );
        assert_eq!(ctrl.last(), Some(&0x0000_0003u32), "final CTRL = 0x3");
    }

    #[test]
    fn privdefena_never_set()
    {
        // No background map: PRIVDEFENA must be absent from every CTRL write.
        let bus = run();
        for (addr, value) in bus.writes()
        {
            if *addr == regs::MPU_CTRL
            {
                assert_eq!(
                    value & regs::MPU_CTRL_PRIVDEFENA,
                    0,
                    "PRIVDEFENA must never be set"
                );
            }
        }
    }

    #[test]
    fn mair0_written_before_regions_and_correct()
    {
        let bus = run();
        let mair = bus.first_write_index(regs::MPU_MAIR0).expect("MAIR0 write");
        let first_rnr = bus.first_write_index(regs::MPU_RNR).expect("RNR write");
        assert!(mair < first_rnr, "MAIR0 before region programming");
        assert_eq!(bus.last_value(regs::MPU_MAIR0), Some(0x0000_00AA));
    }

    #[test]
    fn regions_programmed_in_rnr_order()
    {
        let bus = run();
        let rnr: alloc::vec::Vec<u32> = bus
            .writes()
            .iter()
            .filter(|(a, _)| *a == regs::MPU_RNR)
            .map(|(_, v)| *v)
            .collect();
        let expected: alloc::vec::Vec<u32> = (0..MPU_PROGRAMMED_REGIONS as u32).collect();
        assert_eq!(rnr, expected);
    }

    #[test]
    fn exact_ordered_write_trace()
    {
        // The full trace is the contract: CTRL=0, MAIR0, then per region
        // RNR/RBAR/RLAR in order, then CTRL=ENABLE|HFNMIENA last.
        let bus = run();
        let expected: alloc::vec::Vec<(u32, u32)> = alloc::vec![
            (regs::MPU_CTRL, 0),
            (regs::MPU_MAIR0, 0x0000_00AA),
            (regs::MPU_RNR, 0),
            (regs::MPU_RBAR, 0x0C00_0004),
            (regs::MPU_RLAR, 0x0C03_FFE0 | regs::MPU_RLAR_EN),
            (regs::MPU_RNR, 1),
            (regs::MPU_RBAR, 0x2000_0001),
            (regs::MPU_RLAR, 0x2001_FFE0 | regs::MPU_RLAR_EN),
            (regs::MPU_RNR, 2),
            (regs::MPU_RBAR, 0x5000_0001),
            (
                regs::MPU_RLAR,
                0x5FFF_FFE0
                    | (regs::MPU_ATTRINDX_DEVICE << regs::MPU_RLAR_ATTRINDX_SHIFT)
                    | regs::MPU_RLAR_EN
            ),
            (regs::MPU_CTRL, regs::MPU_CTRL_ENABLE | regs::MPU_CTRL_HFNMIENA),
        ];
        assert_eq!(bus.writes(), expected.as_slice());
    }

    #[test]
    fn w_xor_x_invariant_holds()
    {
        // W^X: the code region is RO + executable, the data and peripheral regions
        // are writable + execute-never. No region is both writable and executable.
        let t = mpu_table().expect("table");
        // R0 code: not writable, executable.
        assert!(!t[0].access.is_writable(), "code region must not be writable");
        assert_eq!(t[0].exec, Exec::Allow, "code region must be executable");
        // R1 SRAM + R2 periph: writable, execute-never.
        for region in &t[1..]
        {
            assert!(region.access.is_writable(), "data region must be writable");
            assert_eq!(region.exec, Exec::Never, "data region must be execute-never");
        }
        // No region grants unprivileged access (RBAR AP bit[1] is 0 for both
        // privileged-only encodings: 0b00 and 0b10).
        for region in &t
        {
            let ap = (region.rbar() >> regs::MPU_RBAR_AP_SHIFT) & 0b11;
            assert_eq!(ap & 0b01, 0, "no region may grant unprivileged access");
        }
    }

    extern crate alloc;
}
