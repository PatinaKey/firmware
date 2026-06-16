//! The `SeWait` port: an explicit wait/timeout seam.
//!
//! Models the SE ready signal (GPO/IRQ) and per-command timeouts without a
//! runtime, so deadlines stay observable and mockable on the host. Injecting a
//! mock implementor lets you test every L1 poll path with zero hardware.

/// A wait/delay provider for L1 readiness polling and command timeouts.
///
/// The associated `Error` is the implementor's own. The L1 seam erases it to
/// `L1Error::Bus`, so it never reaches the public surface.
pub trait SeWait
{
    /// The implementor-specific error type.
    type Error;

    /// Blocks until the SE asserts ready, or until `timeout_ms` elapses.
    ///
    /// Returns `Ok(())` on ready. Returns `Err` on timeout or signal fault.
    fn wait_ready
    (
        &mut self,
        timeout_ms: u32,
    )
    -> Result<(), Self::Error>;

    /// Pure delay used between L1 CHIP_STATUS polls.
    ///
    /// Returns `Ok(())` once `ms` milliseconds have elapsed.
    fn delay_ms
    (
        &mut self,
        ms: u32,
    )
    -> Result<(), Self::Error>;
}
