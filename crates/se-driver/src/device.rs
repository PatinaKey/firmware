//! The device handle and its type-state markers.
//!
//! `Tropic01<SPI, W, State>` owns the SPI port, the wait provider, and the
//! fixed L2/L3 buffers. The `State` type parameter encodes the session
//! lifecycle at compile time: L3 commands are reachable only on
//! `ActiveSession`, firmware update only on `Bootloader`.
//!
//! The handle is ~4.4 KiB and MUST live as a `static` singleton in the secure
//! binary, accessed by `&mut`. It must never sit on a call stack. A
//! size-regression test pins its footprint.
//!
//! Increment 1 provides the state types, the struct, and `new()`. Session
//! establishment, teardown, and the L3 command impls land later.

use embedded_hal::spi::SpiDevice;

use crate::buf::L2Buf;
use crate::buf::L2_FRAME_MAX;
use crate::buf::L3Buf;
use crate::session::SessionKeys;
use crate::wait::SeWait;

/// State marker: no secure channel is open. Plain-L2 ops are available.
#[derive(Debug, Clone, Copy)]
pub struct NoSession;

/// State marker: a secure channel is open. L3 commands are available.
///
/// Holds the session keys (zeroized on drop) and a `poisoned` flag. On a
/// session-fatal error the command path zeroizes the keys and sets `poisoned`,
/// so every subsequent L3 call fast-fails with `SessionLost` without touching
/// the chip. Carries no `Debug`/`Clone`/`Copy` because it holds secrets.
pub struct ActiveSession
{
    keys: SessionKeys,
    poisoned: bool,
}

impl ActiveSession
{
    /// Wraps derived session keys into the active state.
    ///
    /// `pub(crate)`: only the handshake builds this. Starts un-poisoned.
    pub(crate) fn new(keys: SessionKeys) -> Self
    {
        ActiveSession
        {
            keys,
            poisoned: false,
        }
    }

    /// Reports whether this session has been torn down.
    pub(crate) fn is_poisoned(&self) -> bool
    {
        self.poisoned
    }

    /// Marks the session fatal and zeroizes the keys.
    ///
    /// Idempotent. After this, the session can only be closed and replaced.
    pub(crate) fn poison(&mut self)
    {
        self.keys.wipe();
        self.poisoned = true;
    }
}

/// State marker: the chip is in bootloader (start-up) mode for firmware update.
#[derive(Debug, Clone, Copy)]
pub struct Bootloader;

/// The TROPIC01 device handle.
///
/// Generic over the SPI device port and the wait provider, with a type-state
/// parameter for the session lifecycle. Owns the no-heap L2 and L3 buffers.
pub struct Tropic01<SPI, W, State = NoSession>
{
    spi: SPI,
    wait: W,
    l2: L2Buf,
    l3: L3Buf,
    state: State,
}

impl<SPI, W> Tropic01<SPI, W, NoSession>
where
    SPI: SpiDevice,
    W: SeWait,
{
    /// Creates a handle in the `NoSession` state.
    ///
    /// Takes ownership of the SPI port and the wait provider. Allocates the
    /// fixed L2/L3 buffers inline. Open a secure channel before any L3 command.
    pub fn new(spi: SPI, wait: W) -> Tropic01<SPI, W, NoSession>
    {
        Tropic01
        {
            spi,
            wait,
            l2: [0u8; L2_FRAME_MAX],
            l3: L3Buf::new(),
            state: NoSession,
        }
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::test_support::MockSpi;
    use crate::test_support::MockWait;

    #[test]
    fn new_builds_a_no_session_handle()
    {
        let dev = Tropic01::new(MockSpi::new(), MockWait::new());
        // Buffers start zeroed.
        assert!(dev.l2.iter().all(|&b| b == 0));
        assert!(dev.l3.as_slice().iter().all(|&b| b == 0));
        // The ports are owned and reachable: no transactions or waits yet.
        assert_eq!(dev.spi.transaction_count(), 0);
        assert_eq!(dev.wait.wait_count(), 0);
        let _ = dev.state;
    }

    #[test]
    fn handle_size_is_bounded()
    {
        // The handle must stay small enough to live in the secure binary's
        // static singleton. Design budget: <= 5000 bytes.
        assert!(core::mem::size_of::<Tropic01<MockSpi, MockWait, NoSession>>() <= 5000);
    }

    #[test]
    fn active_session_poison_is_sticky()
    {
        let keys = SessionKeys::new([1u8; 32], [2u8; 32]);
        let mut s = ActiveSession::new(keys);
        assert!(!s.is_poisoned());
        s.poison();
        assert!(s.is_poisoned());
        // Idempotent.
        s.poison();
        assert!(s.is_poisoned());
    }
}
