//! A blocking [`SeWait`] backed by a Cortex-M cycle busy-loop.
//!
//! The TROPIC01 L1 seam polls `CHIP_STATUS` on a 25 ms cadence and bounds each
//! command with a millisecond timeout. Neither needs a precise clock: an
//! approximate busy delay is enough, and it keeps this bring-up free of a timer
//! peripheral and an interrupt. [`CycleWait`] spins `mcu_arch::delay` for an
//! estimated cycle count per millisecond.
//!
//! The SE GPO ready line (PB1) is NOT used here: `wait_ready` falls back to a
//! plain delay, because the driver also polls `CHIP_STATUS` over SPI to learn the
//! chip is ready. Wiring PB1/EXTI as the ready signal is a later optimisation.

use tropic01_driver::SeWait;

/// A blocking wait provider using a CPU cycle busy-loop.
///
/// `cycles_per_ms` is the estimated core-clock cycles in one millisecond. An
/// over-estimate makes the delays longer (safe for a poll cadence), an
/// under-estimate makes them shorter. The value is supplied by the caller from
/// the known core clock at bring-up.
pub struct CycleWait
{
    cycles_per_ms: u32,
}

impl CycleWait
{
    /// Builds a wait provider from the core-clock cycles per millisecond.
    ///
    /// For an MSI core clock at `f` Hz, pass `f / 1000`. An approximate value is
    /// fine: the L1 cadence tolerates a coarse delay.
    pub const fn new(cycles_per_ms: u32) -> Self
    {
        CycleWait
        {
            cycles_per_ms,
        }
    }

    /// Busy-spins approximately `ms` milliseconds.
    fn spin_ms(&self, ms: u32)
    {
        let cycles = (ms as u64).saturating_mul(self.cycles_per_ms as u64);
        let cycles = u32::try_from(cycles).unwrap_or(u32::MAX);
        delay_cycles(cycles);
    }
}

impl SeWait for CycleWait
{
    /// A delay never fails on this busy-loop backend.
    type Error = core::convert::Infallible;

    /// Waits up to `timeout_ms` for the SE ready signal.
    ///
    /// No hardware ready line is wired in this bring-up, so this is a plain delay:
    /// the driver also polls `CHIP_STATUS` over SPI to detect readiness. Returns
    /// `Ok(())` once the delay elapses.
    fn wait_ready(&mut self, timeout_ms: u32) -> Result<(), Self::Error>
    {
        self.spin_ms(timeout_ms);
        Ok(())
    }

    /// Delays approximately `ms` milliseconds between `CHIP_STATUS` polls.
    fn delay_ms(&mut self, ms: u32) -> Result<(), Self::Error>
    {
        self.spin_ms(ms);
        Ok(())
    }
}

/// Busy-spins `cycles` core-clock cycles via the Armv8-M countdown loop.
///
/// This is the single seam where cycle-calibrated timing enters the SE driver.
/// The whole `CHIP_STATUS` poll cadence rests on it, and a miscompiled spin is a
/// silicon-only fault no host test can observe.
///
/// The disassembly gate in scripts/asm-gate.sh anchors on this symbol. Dropping
/// `inline(never)` fails the gate.
#[inline(never)]
fn delay_cycles(cycles: u32)
{
    mcu_arch::delay(cycles);
}
