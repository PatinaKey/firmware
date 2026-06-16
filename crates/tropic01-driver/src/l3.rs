//! Layer 3: the round-trip engine for encrypted commands.
//!
//! Orchestrates seal -> send -> receive -> open over the L2 transport. The
//! command plaintext is laid out at `l3[2..]` on entry. On success the result
//! plaintext is at `l3[2..]` on return. Any error here is session-fatal: the
//! caller (a command method) must poison the session before returning, so the
//! two nonce counters can never be observed out of step.

use embedded_hal::spi::SpiDevice;

use crate::buf::L3Buf;
use crate::error::SeError;
use crate::l2::transport;
use crate::session::SessionKeys;
use crate::wait::SeWait;

/// Runs one encrypted command round-trip.
///
/// On entry `l3[2..2 + plaintext_len]` holds the command plaintext
/// (`CMD_ID || CMD_DATA`). On success returns the result plaintext length. The
/// result (`RESULT || RES_DATA`) is then at `l3[2..2 + len]`. Advances the
/// command nonce (at seal) and the result nonce (at verified open) by one each.
pub(crate) fn round_trip<SPI, W>
(
    spi: &mut SPI,
    wait: &mut W,
    l2: &mut [u8],
    l3: &mut L3Buf,
    keys: &mut SessionKeys,
    plaintext_len: usize,
)
-> Result<usize, SeError>
where
    SPI: SpiDevice,
    W: SeWait,
{
    let wire = keys.seal_command(l3.as_mut_slice(), plaintext_len)?;
    transport::send_encrypted(spi, wait, l2, &l3.as_slice()[..wire])?;
    let recv_len = transport::recv_encrypted(spi, wait, l2, l3.as_mut_slice())?;
    let plain_len = keys.open_result(l3.as_mut_slice(), recv_len)?;
    Ok(plain_len)
}
