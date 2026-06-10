//! Host-only test doubles for the SPI and wait ports.
//!
//! Compiled only under `cfg(test)`. These satisfy the `SpiDevice` and `SeWait`
//! bounds, so you can exercise the device handle and its generics without
//! hardware. Increment 1 only needs them to construct the handle and pin its
//! size; richer transcript-replay behaviour arrives with the L1/L2 wiring.

use embedded_hal::spi::ErrorKind;
use embedded_hal::spi::ErrorType;
use embedded_hal::spi::Operation;
use embedded_hal::spi::SpiDevice;

use crate::wait::SeWait;

/// A mock SPI error that maps to a generic bus failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MockSpiError;

impl embedded_hal::spi::Error for MockSpiError
{
    fn kind(&self) -> ErrorKind
    {
        ErrorKind::Other
    }
}

/// A do-nothing SPI device that records the number of transactions.
pub(crate) struct MockSpi
{
    transactions: usize,
}

impl MockSpi
{
    /// Creates a fresh mock with no recorded transactions.
    pub(crate) fn new() -> Self
    {
        MockSpi
        {
            transactions: 0,
        }
    }

    /// Returns how many transactions have been performed.
    pub(crate) fn transaction_count(&self) -> usize
    {
        self.transactions
    }
}

impl ErrorType for MockSpi
{
    type Error = MockSpiError;
}

impl SpiDevice for MockSpi
{
    fn transaction
    (
        &mut self,
        operations: &mut [Operation<'_, u8>],
    )
    -> Result<(), Self::Error>
    {
        self.transactions += 1;
        // Echo zeros into every read buffer to keep callers deterministic.
        for op in operations
        {
            match op
            {
                Operation::Read(buf) => buf.fill(0),
                Operation::Transfer(read, _) => read.fill(0),
                Operation::TransferInPlace(buf) => buf.fill(0),
                Operation::Write(_) | Operation::DelayNs(_) =>
                {}
            }
        }
        Ok(())
    }
}

/// A wait provider that never blocks and never times out.
pub(crate) struct MockWait
{
    waits: usize,
    delays: usize,
}

impl MockWait
{
    /// Creates a fresh mock with no recorded calls.
    pub(crate) fn new() -> Self
    {
        MockWait
        {
            waits: 0,
            delays: 0,
        }
    }

    /// Returns how many `wait_ready` calls were made.
    pub(crate) fn wait_count(&self) -> usize
    {
        self.waits
    }

    /// Returns how many `delay_ms` calls were made.
    pub(crate) fn delay_count(&self) -> usize
    {
        self.delays
    }
}

impl SeWait for MockWait
{
    type Error = MockSpiError;

    fn wait_ready
    (
        &mut self,
        _timeout_ms: u32,
    )
    -> Result<(), Self::Error>
    {
        self.waits += 1;
        Ok(())
    }

    fn delay_ms
    (
        &mut self,
        _ms: u32,
    )
    -> Result<(), Self::Error>
    {
        self.delays += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn mock_spi_records_transactions_and_zero_fills()
    {
        let mut spi = MockSpi::new();
        let mut rd = [0xFFu8; 4];
        spi.transaction(&mut [Operation::Read(&mut rd)]).unwrap();
        assert_eq!(spi.transaction_count(), 1);
        assert_eq!(rd, [0, 0, 0, 0]);
    }

    #[test]
    fn mock_wait_records_calls()
    {
        let mut w = MockWait::new();
        w.wait_ready(10).unwrap();
        w.delay_ms(1).unwrap();
        assert_eq!(w.wait_count(), 1);
        assert_eq!(w.delay_count(), 1);
    }
}
