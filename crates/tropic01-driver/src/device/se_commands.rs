//! The `SeCommands` trait implementation for an active session.
//!
//! Each method delegates to the inherent twin on `Tropic01<_, _, ActiveSession>`
//! (defined in `commands`), which carries the `run` gate, the teardown duties,
//! and the byte layout. The trait keeps transport and crypto detail out of the
//! CTAP2 / OpenPGP / PKCS#11 layers above.

use embedded_hal::spi::SpiDevice;
use zeroize::Zeroizing;

use crate::error::SeError;
use crate::port::ConfigBitIndex;
use crate::port::ConfigObjectAddr;
use crate::port::EccCurve;
use crate::port::EccPublicKey;
use crate::port::EccSlot;
use crate::port::MCounterIdx;
use crate::port::MacAndDestroyOutput;
use crate::port::MacDestroySlot;
use crate::port::PairingKeySlot;
use crate::port::RMemSlot;
use crate::port::SeCommands;
use crate::port::Signature;
use crate::wait::SeWait;

use super::ActiveSession;
use super::Tropic01;

/// The high-level command port over an active session.
///
/// Each method delegates to the inherent twin, which carries the gate, the
/// teardown duties, and the byte layout. The trait keeps transport and crypto
/// detail out of the CTAP2 / OpenPGP / PKCS#11 layers above.
impl<SPI, W> SeCommands for Tropic01<SPI, W, ActiveSession>
where
    SPI: SpiDevice,
    W: SeWait,
{
    fn ecc_key_generate
    (
        &mut self,
        slot: EccSlot,
        curve: EccCurve,
    )
    -> Result<(), SeError>
    {
        self.ecc_key_generate(slot, curve)
    }

    fn ecc_public_key
    (
        &mut self,
        slot: EccSlot,
    )
    -> Result<EccPublicKey, SeError>
    {
        self.ecc_public_key(slot)
    }

    fn ecc_key_store
    (
        &mut self,
        slot: EccSlot,
        curve: EccCurve,
        private_key: &Zeroizing<[u8; 32]>,
    )
    -> Result<(), SeError>
    {
        self.ecc_key_store(slot, curve, private_key)
    }

    fn ecc_key_erase
    (
        &mut self,
        slot: EccSlot,
    )
    -> Result<(), SeError>
    {
        self.ecc_key_erase(slot)
    }

    fn ecdsa_sign
    (
        &mut self,
        slot: EccSlot,
        digest: &[u8; 32],
    )
    -> Result<Signature, SeError>
    {
        self.ecdsa_sign(slot, digest)
    }

    fn eddsa_sign
    (
        &mut self,
        slot: EccSlot,
        message: &[u8],
    )
    -> Result<Signature, SeError>
    {
        self.eddsa_sign(slot, message)
    }

    fn random_into
    (
        &mut self,
        out: &mut [u8],
    )
    -> Result<usize, SeError>
    {
        self.random_into(out)
    }

    fn rmem_read_into
    (
        &mut self,
        slot: RMemSlot,
        out: &mut [u8],
    )
    -> Result<usize, SeError>
    {
        self.rmem_read_into(slot, out)
    }

    fn rmem_write
    (
        &mut self,
        slot: RMemSlot,
        data: &[u8],
    )
    -> Result<(), SeError>
    {
        self.rmem_write(slot, data)
    }

    fn mcounter_get
    (
        &mut self,
        idx: MCounterIdx,
    )
    -> Result<u32, SeError>
    {
        self.mcounter_get(idx)
    }

    fn mac_and_destroy
    (
        &mut self,
        slot: MacDestroySlot,
        input: &[u8; 32],
    )
    -> Result<MacAndDestroyOutput, SeError>
    {
        self.mac_and_destroy(slot, input)
    }

    fn rmem_erase
    (
        &mut self,
        slot: RMemSlot,
    )
    -> Result<(), SeError>
    {
        self.rmem_erase(slot)
    }

    fn mcounter_init
    (
        &mut self,
        idx: MCounterIdx,
        value: u32,
    )
    -> Result<(), SeError>
    {
        self.mcounter_init(idx, value)
    }

    fn mcounter_update
    (
        &mut self,
        idx: MCounterIdx,
    )
    -> Result<(), SeError>
    {
        self.mcounter_update(idx)
    }

    fn pairing_key_write
    (
        &mut self,
        slot: PairingKeySlot,
        public_key: &[u8; 32],
    )
    -> Result<(), SeError>
    {
        self.pairing_key_write(slot, public_key)
    }

    fn pairing_key_read
    (
        &mut self,
        slot: PairingKeySlot,
    )
    -> Result<[u8; 32], SeError>
    {
        self.pairing_key_read(slot)
    }

    fn pairing_key_invalidate
    (
        &mut self,
        slot: PairingKeySlot,
    )
    -> Result<(), SeError>
    {
        self.pairing_key_invalidate(slot)
    }

    fn r_config_write
    (
        &mut self,
        addr: ConfigObjectAddr,
        value: u32,
    )
    -> Result<(), SeError>
    {
        self.r_config_write(addr, value)
    }

    fn r_config_read
    (
        &mut self,
        addr: ConfigObjectAddr,
    )
    -> Result<u32, SeError>
    {
        self.r_config_read(addr)
    }

    fn r_config_erase
    (
        &mut self,
    )
    -> Result<(), SeError>
    {
        self.r_config_erase()
    }

    fn i_config_write
    (
        &mut self,
        addr: ConfigObjectAddr,
        bit: ConfigBitIndex,
    )
    -> Result<(), SeError>
    {
        self.i_config_write(addr, bit)
    }

    fn i_config_read
    (
        &mut self,
        addr: ConfigObjectAddr,
    )
    -> Result<u32, SeError>
    {
        self.i_config_read(addr)
    }
}
