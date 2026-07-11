//! A blocking [`SeWait`] backed by the secure SysTick polled with TICKINT = 0.
//!
//! The TROPIC01 L1 seam polls `CHIP_STATUS` on a 25 ms cadence and bounds each
//! command with a millisecond timeout. [`SysTickWait`] serves both by delegating
//! to [`platform::SysTick`], which runs the 24-bit SysTick down counter and
//! polls COUNTFLAG. The delay derives its reload count from the one HCLK source
//! of truth (`platform::HCLK_HZ`), so raising the core clock never desyncs it.
//!
//! The SE GPO ready line (PB1) is NOT wired here: `wait_ready` runs adelay of 
//! `timeout_ms`, because the driver also polls `CHIP_STATUS`
//! over SPI to learn the chip is ready. Wiring PB1/EXTI as the ready signal is a
//! later optimisation.

use core::convert::Infallible;

use platform::RegisterBus;
use platform::SysTick;
use tropic01_driver::SeWait;

/// A blocking wait provider driven by the secure SysTick.
///
/// Wraps a [`platform::SysTick`] over the same register bus the SPI driver runs
/// on. A delay never fails, so its error type is [`Infallible`].
pub struct SysTickWait<B: RegisterBus>
{
    st: SysTick<B>,
}

impl<B: RegisterBus> SysTickWait<B>
{
    /// Builds the wait provider from a configured [`platform::SysTick`].
    ///
    /// The caller supplies the SysTick already bound to the register bus and the
    /// core-clock rate, so this crate does not restate HCLK.
    pub fn new(st: SysTick<B>) -> Self
    {
        SysTickWait
        {
            st,
        }
    }
}

impl<B: RegisterBus> SeWait for SysTickWait<B>
{
    /// A SysTick delay never fails on this backend.
    type Error = Infallible;

    /// Waits `timeout_ms` for the SE ready signal.
    ///
    /// No hardware ready line is wired, so this is a delay of `timeout_ms`.
    /// The driver also polls `CHIP_STATUS` over SPI to detect readiness. 
    /// Returns `Ok(())` once the delay elapses.
    fn wait_ready(&mut self, timeout_ms: u32) -> Result<(), Self::Error>
    {
        self.st.delay_ms(timeout_ms);
        Ok(())
    }

    /// Delays `ms` milliseconds between `CHIP_STATUS` polls.
    fn delay_ms(&mut self, ms: u32) -> Result<(), Self::Error>
    {
        self.st.delay_ms(ms);
        Ok(())
    }
}
