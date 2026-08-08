//! The real [`BootFlash`] backing, over the `mcu_flash` MMIO driver.
//!
//! Compiled only for the embedded target. The metadata, running-bank, and swap
//! methods delegate to the driver's `fw_update::FlashSeam` impl (the persistent
//! records and the revert). The image reads and the SECWM readback delegate to
//! the driver's running-bank accessors. So the boot stage drives the same
//! flash driver the updater does, with no second MMIO surface.

use fw_update::BankId;
use fw_update::FlashError;
use fw_update::FlashSeam;
use fw_update::PendingFlag;
use fw_update::UpdateOutcome;
use mcu_flash::MmioFlash;
use mcu_flash::Stm32FlashSeam;

use crate::secwm::SecwmReadback;
use crate::secwm::decode_window;
use crate::seam::BootFlash;

/// The real flash seam: the MMIO driver over the volatile FLASH controller.
pub(crate) type RealFlash = Stm32FlashSeam<MmioFlash>;

/// Builds the real flash seam.
pub(crate) fn real_flash() -> RealFlash
{
    Stm32FlashSeam::new(MmioFlash::new())
}

impl BootFlash for RealFlash
{
    fn require_partition(&mut self) -> Result<(), FlashError>
    {
        Stm32FlashSeam::require_partition(self)
    }

    fn read_secwm(&mut self) -> Result<SecwmReadback, FlashError>
    {
        let (bank1, bank2) = self.read_secwm_raw()?;
        Ok(SecwmReadback
        {
            bank1: decode_window(bank1),
            bank2: decode_window(bank2),
        })
    }

    fn running_bank(&mut self) -> Result<BankId, FlashError>
    {
        FlashSeam::running_bank(self)
    }

    fn pending_read(&mut self) -> Result<PendingFlag, FlashError>
    {
        FlashSeam::pending_read(self)
    }

    fn nvcnt_read(&mut self) -> Result<u32, FlashError>
    {
        FlashSeam::nvcnt_read(self)
    }

    fn active_descriptor(&self) -> &[u8]
    {
        Stm32FlashSeam::active_descriptor(self)
    }

    fn active_secure_band(&self) -> &[u8]
    {
        Stm32FlashSeam::active_secure_band(self)
    }

    fn active_ns_band(&self) -> &[u8]
    {
        Stm32FlashSeam::active_ns_band(self)
    }

    fn update_outcome_clear(&mut self) -> Result<(), FlashError>
    {
        FlashSeam::update_outcome_clear(self)
    }

    fn update_outcome_write
    (
        &mut self,
        outcome: UpdateOutcome,
    )
        -> Result<(), FlashError>
    {
        FlashSeam::update_outcome_write(self, outcome)
    }

    fn pending_write(&mut self, flag: PendingFlag) -> Result<(), FlashError>
    {
        FlashSeam::pending_write(self, flag)
    }

    fn nvcnt_bump(&mut self, value: u32) -> Result<(), FlashError>
    {
        FlashSeam::nvcnt_bump(self, value)
    }

    fn revert_swap(&mut self) -> Result<(), FlashError>
    {
        FlashSeam::revert_swap(self)
    }
}
