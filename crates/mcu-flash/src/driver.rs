//! The real STM32U545 embedded-flash driver behind the [`FlashSeam`].
//!
//! [`Stm32FlashSeam`] implements the `fw-update` [`FlashSeam`] over a
//! [`FlashAccess`] register port. It bridges the update machine's 256-byte
//! logical pages (`fw_update::PAGE_LEN`) and the inactive-bank erase to the real
//! hardware granularities: an 8 KB erase page and a 16-byte quad-word program
//! (RM0456 sec 7.3.1 Table 51, sec 7.3.6, sec 7.3.7). Every op returns a typed
//! [`FlashError`] and fails closed, clearing the error flags and re-locking the
//! control register from a known state so a sticky fault never carries into the
//! next op.
//!
//! # The physical-bank-versus-mapped-address contract (RM0456 sec 7.5.8)
//!
//! SWAP_BANK remaps the address of each bank, but the BKER erase selector and the
//! SECWM / WRP protections follow the physical bank (RM0456 sec 7.5.8 Fig 23/24). So
//! erase (BKER) and program / read (address) must be derived from the same physical
//! bank or they diverge under SWAP_BANK=1. This driver names a physical bank with
//! [`regs::PhysBank`] and asks it for both the BKER bit and the mapped base, reading
//! `OPTR.SWAP_BANK` (RM0456 sec 7.9.13) at runtime on every address computation. The
//! inactive-bank erase, program, and read all go through the same physical bank, and
//! the fixed-Bank-1 metadata band re-derives its mapped address from SWAP_BANK on
//! every access, so the NVCNT, the pending record, the boot-count, and the
//! update-outcome record survive a swap.
//!
//! # Posture assertion before any destructive op
//!
//! Erase, program, and the swap arm all assert `OPTR.DUALBANK` and `OPTR.TZEN` first
//! (RM0456 sec 7.9.13). A mis-provisioned part (single-bank or TZEN clear) means the
//! geometry the constants pin does not hold, so the driver fails closed with
//! [`FlashError::Hardware`] rather than erasing or programming blind.
//!
//! # Brick-safety: the option-byte / SWAP_BANK path is present but inert
//!
//! The [`Stm32FlashSeam`] [`commit_swap`](fw_update::FlashSeam::commit_swap) and
//! [`revert_swap`](fw_update::FlashSeam::revert_swap) impls carry the full real
//! register sequence (OPTR SWAP_BANK plus OPTSTRT plus OBL_LAUNCH, RM0456 sec 7.4.2).
//! OBL_LAUNCH triggers the reset that applies the option load on real silicon, the
//! irreversible brick-class step. The whole real register surface is the
//! [`FlashAccess`] MMIO port, which is gated to `target_os = "none"` and does not
//! compile on the host. No host build and no test ever drives a real option-byte
//! write: the tests run a state model that stages the swap and applies it only at a
//! modelled reset, never a real OBL_LAUNCH. The capability is complete but inert. Its
//! on-silicon invocation stays gated on a deliberate operator action.

use fw_update::BankId;
use fw_update::FlashError;
use fw_update::FlashSeam;
use fw_update::PageIndex;
use fw_update::PendingFlag;
use fw_update::UpdateOutcome;

use crate::bus::FlashAccess;
use crate::regs;
use crate::regs::PhysBank;

/// A bound on the busy-poll spin, so a stuck controller fails closed instead of
/// hanging the secure world forever. The count is generous: a page erase is the
/// longest flash op and completes well within this many register reads on the
/// real part. A timeout maps to [`FlashError::Hardware`].
const BSY_POLL_LIMIT: u32 = 2_000_000;

/// The real STM32U545 flash driver, generic over the register-access port.
///
/// On hardware `A` is the target-gated MMIO port. In host tests `A` is a
/// faithful FLASH-controller state model. The driver code is identical for
/// both, so the host proof exercises the exact sequencing the silicon runs.
pub struct Stm32FlashSeam<A>
{
    access: A,
}

impl<A> Stm32FlashSeam<A>
where
    A: FlashAccess,
{
    /// Builds the driver over the given register-access port.
    pub const fn new(access: A) -> Stm32FlashSeam<A>
    {
        Stm32FlashSeam { access }
    }

    /// Borrows the register-access port (test inspection only).
    #[cfg(test)]
    pub(crate) fn access(&self) -> &A
    {
        &self.access
    }

    /// Mutably borrows the register-access port (test control only).
    ///
    /// Lets a test model a reset on the backing FLASH-controller model after the
    /// driver staged a swap, so the swap-aware metadata addressing can be proven
    /// across the reset boundary.
    #[cfg(test)]
    pub(crate) fn access_mut(&mut self) -> &mut A
    {
        &mut self.access
    }

    // The B1 core: physical-bank addressing from the live SWAP_BANK.

    /// Reads the live `OPTR.SWAP_BANK` bit state.
    ///
    /// RM0456 sec 7.9.13. Read on every address computation, never cached across
    /// a reset, so a swap is always reflected in the next mapped address.
    fn swap_bank(&mut self) -> bool
    {
        regs::swap_bank_set(self.access.read32(regs::FLASH_OPTR))
    }

    /// The mapped secure-alias base of a physical bank for the live SWAP_BANK.
    ///
    /// This is the one helper the B1 resolution turns on: it pairs the physical bank
    /// with the current SWAP_BANK state to yield the address erase and program must
    /// both use (RM0456 sec 7.5.8).
    fn phys_base(&mut self, bank: PhysBank) -> u32
    {
        bank.mapped_base(self.swap_bank())
    }

    /// The inactive (staging) physical bank, derived from the live SWAP_BANK.
    ///
    /// RM0456 sec 7.5.8 / 7.9.13: SWAP_BANK clear boots Bank 1, so the inactive
    /// bank is Bank 2, and the reverse when SWAP_BANK is set.
    fn inactive_phys(&mut self) -> PhysBank
    {
        regs::inactive_phys_bank(self.swap_bank())
    }

    /// Polls `BSY` and `WDW` in the given status register down to clear, bounded.
    ///
    /// RM0456 sec 7.3.7 / 7.3.6: a program or erase must wait for BSY to clear,
    /// and a program must also see WDW clear before the next data write. `sr` is
    /// SECSR for the secure controller or NSSR for the non-secure controller
    /// (the BSY / WDW positions match, RM0456 sec 7.9.7 / 7.9.8). A bounded spin
    /// fails closed with [`FlashError::Hardware`] rather than hanging.
    fn wait_ready_on(&mut self, sr: u32) -> Result<(), FlashError>
    {
        let mut spins = 0u32;
        loop
        {
            let status = self.access.read32(sr);
            if status & (regs::SR_BSY | regs::SR_WDW) == 0
            {
                return Ok(());
            }
            spins = spins
                .checked_add(1)
                .ok_or(FlashError::Hardware)?;
            if spins >= BSY_POLL_LIMIT
            {
                return Err(FlashError::Hardware);
            }
        }
    }

    /// Clears every program / erase error flag (rc_w1) in the given status reg.
    ///
    /// RM0456 sec 7.9.7 / 7.9.8: each error flag is rc_w1, write 1 to clear.
    /// Clearing from a known state before every op is part of failing closed.
    fn clear_errors_on(&mut self, sr: u32)
    {
        self.access.write32(sr, regs::SR_ALL_ERRORS);
    }

    /// Reads the given status register and maps any error flag to an error.
    ///
    /// RM0456 sec 7.9.7 / 7.9.8: PROGERR, WRPERR, PGAERR, SIZERR, PGSERR, OPERR.
    /// Any set flag means the op did not take effect, so it fails closed. A
    /// secure access to a non-secure page raises WRPERR here (Write-Ignored,
    /// RM0456 Table 68).
    fn check_errors_on(&mut self, sr: u32) -> Result<(), FlashError>
    {
        let status = self.access.read32(sr);
        if status & regs::SR_ALL_ERRORS != 0
        {
            return Err(FlashError::WriteFailed);
        }
        Ok(())
    }

    /// Unlocks the given control register with the KEY1 / KEY2 sequence.
    ///
    /// RM0456 sec 7.3.5: write KEY1 then KEY2 to the CR's key register. A wrong
    /// value or order locks the CR until reset, so the driver only writes the
    /// canonical pair. `cr` is SECCR or NSCR, `keyr` its matching key register.
    /// The LOCK bit is bit 31 in both CRs. A no-op if already unlocked.
    fn unlock_cr_on(&mut self, cr: u32, keyr: u32)
    {
        if self.access.read32(cr) & regs::SECCR_LOCK == 0
        {
            return;
        }
        self.access.write32(keyr, regs::FLASH_KEY1);
        self.access.write32(keyr, regs::FLASH_KEY2);
    }

    /// Re-locks the given control register, returning to a known idle state.
    ///
    /// RM0456 sec 7.9.9 / 7.9.10: setting the CR LOCK bit re-locks it. The driver
    /// locks after every op so a later op must unlock deliberately.
    fn lock_cr_on(&mut self, cr: u32)
    {
        self.access.modify32(cr, 0, regs::SECCR_LOCK);
    }

    /// Programs one 16-byte quad-word at `addr` on the given band's controller.
    ///
    /// RM0456 sec 7.3.7: poll ready, clear errors, set PG, write 4 consecutive
    /// 32-bit words to a quad-word-aligned address, poll BSY, check EOP, clear
    /// PG. A short tail pads with the erased value so a sub-quad-word write never
    /// raises SIZERR. `addr` MUST be quad-word aligned and reachable through the
    /// band's alias. `band` selects the controller (SEC* or NS*), matching the
    /// page's SECWM label (RM0456 Table 68). The caller has already unlocked the
    /// matching CR.
    fn program_quad_word
    (
        &mut self,
        band: regs::PageBand,
        addr: u32,
        data: &[u8],
    )
        -> Result<(), FlashError>
    {
        if data.len() > regs::QUAD_WORD_LEN as usize
        {
            return Err(FlashError::OutOfRange);
        }
        let sr = band.sr();
        let cr = band.cr();
        self.wait_ready_on(sr)?;
        self.clear_errors_on(sr);

        // Set PG, then write the four words. A read of a fully-erased quad-word
        // is all-ones, so padding a short tail with the erased word leaves those
        // bytes untouched (program clears bits only, RM0456 sec 7.3.1).
        self.access.modify32(cr, 0, regs::SECCR_PG);

        let mut buf = [regs::ERASED_BYTE; regs::QUAD_WORD_LEN as usize];
        let slot = buf
            .get_mut(..data.len())
            .ok_or(FlashError::OutOfRange)?;
        slot.copy_from_slice(data);

        for word_index in 0..regs::QUAD_WORD_WORDS
        {
            let byte_off = (word_index * 4) as usize;
            let chunk = buf
                .get(byte_off..byte_off + 4)
                .ok_or(FlashError::OutOfRange)?;
            let arr: [u8; 4] = chunk
                .try_into()
                .map_err(|_| FlashError::OutOfRange)?;
            let word = u32::from_le_bytes(arr);
            let word_addr = addr
                .checked_add(word_index * 4)
                .ok_or(FlashError::OutOfRange)?;
            self.access.write32(word_addr, word);
        }

        self.wait_ready_on(sr)?;
        let result = self.check_eop_then_clear_errors_on(sr);
        // Clear PG whatever happened, so the controller returns to idle.
        self.access.modify32(cr, regs::SECCR_PG, 0);
        result
    }

    /// Confirms `EOP` rose then folds in any error flag, clearing both (rc_w1).
    ///
    /// RM0456 sec 7.3.7 / 7.3.6: a successful op sets EOP. The driver treats a
    /// set error flag as the authority (fail closed) and clears EOP and the
    /// error flags so the next op starts from a known SR. `sr` is the band's
    /// status register.
    fn check_eop_then_clear_errors_on(&mut self, sr: u32) -> Result<(), FlashError>
    {
        let errors = self.check_errors_on(sr);
        // Clear EOP (rc_w1) regardless, so it does not leak into the next op.
        self.access.write32(sr, regs::SR_EOP);
        errors
    }

    /// Erases one 8 KB page of the given physical bank on the band's controller.
    ///
    /// RM0456 sec 7.3.6: poll ready, clear errors, write PER plus BKER plus PNB,
    /// set STRT, poll BSY, check EOP, clear PER. The caller has unlocked the
    /// band's CR. `page` is bank-relative (0..[`regs::PAGES_PER_BANK`]). BKER
    /// comes from the physical bank (SWAP_BANK-independent, RM0456 sec 7.5.8).
    /// `band` selects the controller matching the page's SECWM label: a secure
    /// controller erasing a non-secure page raises WRPERR (RM0456 Table 68).
    fn erase_page
    (
        &mut self,
        bank: PhysBank,
        band: regs::PageBand,
        page: u32,
    )
        -> Result<(), FlashError>
    {
        if page >= regs::PAGES_PER_BANK
        {
            return Err(FlashError::OutOfRange);
        }
        let sr = band.sr();
        let cr = band.cr();
        self.wait_ready_on(sr)?;
        self.clear_errors_on(sr);

        let bker = bank.bker();
        let pnb = (page << regs::SECCR_PNB_SHIFT) & regs::SECCR_PNB_MASK;
        // Write PER plus BKER plus PNB in one word, first clearing every stale
        // operation-select bit so no mass-erase, burst-write, or interrupt
        // request rides along (RM0456 sec 7.9.9 / 7.9.10), then set STRT in a
        // second write (RM0456 sec 7.3.6).
        self.access.modify32(
            cr,
            regs::SECCR_PER
                | regs::SECCR_PG
                | regs::SECCR_PNB_MASK
                | regs::SECCR_BKER
                | regs::SECCR_MER1
                | regs::SECCR_MER2
                | regs::SECCR_BWR
                | regs::SECCR_EOPIE
                | regs::SECCR_ERRIE
                | regs::SECCR_STRT,
            regs::SECCR_PER | bker | pnb,
        );
        self.access.modify32(cr, 0, regs::SECCR_STRT);

        self.wait_ready_on(sr)?;
        let result = self.check_eop_then_clear_errors_on(sr);
        self.access.modify32(cr, regs::SECCR_PER, 0);
        result
    }

    /// Erases the bank-relative page range `[first, last)` on one band.
    ///
    /// Unlocks the band's control register once, erases each page in the range
    /// through the band's controller, then re-locks. RM0456 Table 68 rejects a
    /// secure erase of a non-secure page (WRPERR), so the whole range MUST share
    /// the `band`'s SECWM label. The image band is split at the SECWM boundary by
    /// the two callers (secure pages 9-19, non-secure pages 20-31), so each call
    /// is homogeneous. Fail-closed: a page-erase fault stops the loop, re-locks,
    /// and returns the typed error, leaving the already-erased pages erased.
    fn erase_band
    (
        &mut self,
        bank: PhysBank,
        band: regs::PageBand,
        first: u32,
        last: u32,
    )
        -> Result<(), FlashError>
    {
        self.unlock_cr_on(band.cr(), band.keyr());
        let mut result = Ok(());
        let mut page = first;
        while page < last
        {
            if let Err(error) = self.erase_page(bank, band, page)
            {
                result = Err(error);
                break;
            }
            page = match page.checked_add(1)
            {
                Some(next) => next,
                None =>
                {
                    result = Err(FlashError::OutOfRange);
                    break;
                }
            };
        }
        self.lock_cr_on(band.cr());
        result
    }

    /// Maps a logical PAYLOAD page index to its band and absolute address in the
    /// inactive bank.
    ///
    /// The machine writes `fw_update::PAGE_LEN`-byte payload pages across the
    /// payload band (pages 10-31), page-aligned at the secure app link origin.
    /// Page index 0 maps to physical page 10 (0x0C014000). The byte offset from
    /// the payload base decides the page's [`regs::PageBand`]: an offset below the
    /// secure payload size is a secure page (0x0C.. alias, SEC* controller), the
    /// rest is a non-secure page (0x08.. alias, NS* controller). RM0456 Table 68
    /// forbids the secure controller from writing a non-secure page, so the band
    /// routing is load-bearing. The descriptor page (page 9) is programmed separately
    /// through [`Self::write_descriptor`].
    ///
    /// A [`fw_update::PAGE_LEN`]-byte page never straddles the SECWM boundary: the
    /// boundary is at payload offset [`regs::IMAGE_PAYLOAD_SECURE_SIZE`] (0x14000),
    /// a multiple of `PAGE_LEN`, so each page lies wholly in one band. The alias
    /// base is the same physical bank the erase loop targets, so erase and program
    /// agree. Overflow-safe, bounds-checked to the payload band.
    fn logical_page_addr
    (
        &mut self,
        page: PageIndex,
    )
        -> Result<(regs::PageBand, u32), FlashError>
    {
        let offset = (page as u32)
            .checked_mul(fw_update::PAGE_LEN as u32)
            .ok_or(FlashError::OutOfRange)?;
        let end = offset
            .checked_add(fw_update::PAGE_LEN as u32)
            .ok_or(FlashError::OutOfRange)?;
        if end > regs::IMAGE_PAYLOAD_SIZE
        {
            return Err(FlashError::OutOfRange);
        }
        // Byte offset from the payload base. Below the secure payload size it is a
        // secure page, at or above it a non-secure page. `end <= size` and the
        // boundary is page-aligned, so the whole page shares one band.
        let band = if offset < regs::IMAGE_PAYLOAD_SECURE_SIZE
        {
            regs::PageBand::Secure
        }
        else
        {
            regs::PageBand::NonSecure
        };
        let bank = self.inactive_phys();
        let secure_base = self.phys_base(bank);
        let alias_base = band.alias_base(secure_base);
        let payload_base = alias_base
            .checked_add(regs::IMAGE_PAYLOAD_OFFSET)
            .ok_or(FlashError::OutOfRange)?;
        let addr = payload_base
            .checked_add(offset)
            .ok_or(FlashError::OutOfRange)?;
        Ok((band, addr))
    }

    // Metadata helpers, pinned to PHYSICAL Bank 1, swap-aware.
    //
    // The NVCNT, boot-count, pending, and update-outcome records all live in
    // physical Bank 1 (pages 0-1). The driver re-derives Bank 1's mapped base from the
    // live SWAP_BANK on every access, so the records survive a swap (RM0456 sec 7.5.8:
    // data lives at a physical location mapped to different virtual addresses by
    // SWAP_BANK). This is the B1 fix applied to metadata.

    /// The live mapped base of a metadata record in physical Bank 1.
    fn meta_addr(&mut self, offset: u32) -> Result<u32, FlashError>
    {
        let base = self.phys_base(PhysBank::One);
        base.checked_add(offset).ok_or(FlashError::Hardware)
    }

    /// Reads the maximum value over the programmed NVCNT log slots.
    ///
    /// The NVCNT log is append-only: each bump programs the next erased slot. The
    /// current counter is the maximum non-erased slot, so a torn bump that leaves
    /// a slot half-written never reads back below the prior fully-programmed slot
    /// (the monotone-burn floor).
    fn nvcnt_max(&mut self) -> Result<u32, FlashError>
    {
        let mut max = 0u32;
        for slot in 0..regs::META_LOG_SLOTS
        {
            let addr = self.meta_addr(
                regs::META_NVCNT_OFFSET + slot * regs::QUAD_WORD_LEN,
            )?;
            let word = self.access.read32(addr);
            if word == regs::ERASED_WORD
            {
                continue;
            }
            if word > max
            {
                max = word;
            }
        }
        Ok(max)
    }

    /// Finds the first erased NVCNT slot index, or `None` when exhausted.
    fn nvcnt_free_slot(&mut self) -> Result<Option<u32>, FlashError>
    {
        for slot in 0..regs::META_LOG_SLOTS
        {
            let addr = self.meta_addr(
                regs::META_NVCNT_OFFSET + slot * regs::QUAD_WORD_LEN,
            )?;
            if self.access.read32(addr) == regs::ERASED_WORD
            {
                return Ok(Some(slot));
            }
        }
        Ok(None)
    }

    /// Counts the programmed boot-count tick slots.
    fn boot_count_slots(&mut self) -> Result<u32, FlashError>
    {
        let mut count = 0u32;
        for slot in 0..regs::META_LOG_SLOTS
        {
            let addr = self.meta_addr(
                regs::META_BOOT_OFFSET + slot * regs::QUAD_WORD_LEN,
            )?;
            if self.access.read32(addr) != regs::ERASED_WORD
            {
                count = count
                    .checked_add(1)
                    .ok_or(FlashError::Hardware)?;
            }
        }
        Ok(count)
    }

    /// Programs a single u32 record at `addr` (padded to a quad-word).
    ///
    /// The metadata band is physical Bank 1 pages 0-1, always SECURE, so the
    /// record is programmed on the secure controller through the secure alias.
    /// Unlocks the secure CR, programs the quad-word, then re-locks. Fail-closed:
    /// a program fault re-locks and returns the typed error.
    fn program_record
    (
        &mut self,
        addr: u32,
        value: u32,
    )
        -> Result<(), FlashError>
    {
        self.unlock_cr_on(regs::FLASH_SECCR, regs::FLASH_SECKEYR);
        let result = self.program_quad_word(
            regs::PageBand::Secure,
            addr,
            &value.to_le_bytes(),
        );
        self.lock_cr_on(regs::FLASH_SECCR);
        result
    }

    /// Reads the live word of a mutable metadata record (pending or outcome).
    fn read_meta_word(&mut self, offset: u32) -> Result<u32, FlashError>
    {
        let addr = self.meta_addr(offset)?;
        Ok(self.access.read32(addr))
    }

    /// Rewrites both page-1 mutable records (pending and outcome) at once.
    ///
    /// The pending and update-outcome records share page 1 of physical Bank 1, so
    /// a rewrite of either erases the one page and reprograms both (RM0456 sec
    /// 7.3.6: erase is per 8 KB page). The caller supplies the desired post-write
    /// value of each record. An erased value programs nothing (an erased page
    /// already reads erased). Fail-closed: an erase or program fault re-locks and
    /// returns the typed error, leaving the old records readable as best effort.
    fn rewrite_mutable_records
    (
        &mut self,
        pending_value: u32,
        outcome_value: u32,
    )
        -> Result<(), FlashError>
    {
        self.require_dualbank_secure()?;
        // Page 1 of physical Bank 1 is a SECURE metadata page, so the erase runs
        // on the secure controller through the secure alias.
        self.unlock_cr_on(regs::FLASH_SECCR, regs::FLASH_SECKEYR);
        let erased = self.erase_page(
            PhysBank::One,
            regs::PageBand::Secure,
            regs::META_MUTABLE_PAGE,
        );
        self.lock_cr_on(regs::FLASH_SECCR);
        erased?;
        if pending_value != regs::PENDING_NONE
        {
            let addr = self.meta_addr(regs::META_PENDING_OFFSET)?;
            self.program_record(addr, pending_value)?;
        }
        if outcome_value != regs::OUTCOME_NONE
        {
            let addr = self.meta_addr(regs::META_OUTCOME_OFFSET)?;
            self.program_record(addr, outcome_value)?;
        }
        Ok(())
    }
}

/// The running-bank read surface and the SECWM readback the boot stage consumes.
///
/// The `fw_update::FlashSeam` impl below reads the inactive bank (the updater's
/// staging view, through the high alias). The boot stage instead verifies the bank
/// it is about to boot, so these accessors mirror the inactive-bank banded read but
/// resolve the running physical bank, which sits at the low alias. Each sub-band is
/// still read through the alias matching its SECWM label (RM0456 Table 68), so the
/// same-store property holds: the bytes verified are the bytes the hand-off boots.
impl<A> Stm32FlashSeam<A>
where
    A: FlashAccess,
{
    /// Asserts the dual-bank secure posture (DUALBANK and TZEN set).
    ///
    /// # Errors
    ///
    /// [`FlashError::Hardware`] if the part is not dual-bank secure.
    pub fn require_partition(&mut self) -> Result<(), FlashError>
    {
        self.require_dualbank_secure()
    }

    /// Reads the two secure-watermark registers back (`FLASH_SECWM1R1` /
    /// `FLASH_SECWM2R1`).
    ///
    /// Returns the raw register words for the caller to decode. Secure-read-only:
    /// on a TZEN=0 part a non-secure read is RAZ, which the caller treats as a
    /// mismatch. RM0456 sec 7.9.17 / 7.9.21.
    ///
    /// # Errors
    ///
    /// This read cannot fail on the real port, but the signature stays fallible so
    /// a future access seam may report a fault.
    pub fn read_secwm_raw(&mut self) -> Result<(u32, u32), FlashError>
    {
        let bank1 = self.access.read32(regs::FLASH_SECWM1R1);
        let bank2 = self.access.read32(regs::FLASH_SECWM2R1);
        Ok((bank1, bank2))
    }

    /// Borrows the running bank's image descriptor (page 9), read through the secure
    /// alias. Header at [0:24], signature at [24:88].
    pub fn active_descriptor(&self) -> &[u8]
    {
        let swap = regs::swap_bank_set(self.access.peek32(regs::FLASH_OPTR));
        let bank = regs::running_phys_bank(swap);
        let secure_base = bank.mapped_base(swap);
        let descriptor_base = regs::PageBand::Secure
            .alias_base(secure_base)
            .wrapping_add(regs::IMAGE_DESCRIPTOR_OFFSET);
        self.access
            .bank_view(descriptor_base, regs::IMAGE_DESCRIPTOR_LEN as usize)
    }

    /// Borrows the running bank's secure payload sub-band (pages 10-19), read through
    /// the secure alias.
    pub fn active_secure_band(&self) -> &[u8]
    {
        let swap = regs::swap_bank_set(self.access.peek32(regs::FLASH_OPTR));
        let bank = regs::running_phys_bank(swap);
        let secure_base = bank.mapped_base(swap);
        let band_base = regs::PageBand::Secure
            .alias_base(secure_base)
            .wrapping_add(regs::IMAGE_PAYLOAD_OFFSET);
        self.access
            .bank_view(band_base, regs::IMAGE_PAYLOAD_SECURE_SIZE as usize)
    }

    /// Borrows the running bank's non-secure payload sub-band (pages 20-31), read
    /// through the non-secure alias.
    ///
    /// RM0456 Table 68: reading a non-secure page through the secure alias returns
    /// RAZ, so this band uses the non-secure alias.
    pub fn active_ns_band(&self) -> &[u8]
    {
        let swap = regs::swap_bank_set(self.access.peek32(regs::FLASH_OPTR));
        let bank = regs::running_phys_bank(swap);
        let secure_base = bank.mapped_base(swap);
        let band_base = regs::PageBand::NonSecure
            .alias_base(secure_base)
            .wrapping_add(regs::IMAGE_NS_BAND_OFFSET);
        self.access
            .bank_view(band_base, regs::IMAGE_NS_BAND_SIZE as usize)
    }
}

impl<A> FlashSeam for Stm32FlashSeam<A>
where
    A: FlashAccess,
{
    fn inactive_descriptor(&self) -> &[u8]
    {
        // The image descriptor (page 9) of the inactive bank, read through the secure
        // alias (0x0C..). It holds the signed image's header at [0:24] and its
        // signature at [24:88]. Page 9 is a secure page, so the descriptor is read
        // through the secure alias, the store the commit boots.
        let swap = regs::swap_bank_set(self.access.peek32(regs::FLASH_OPTR));
        let bank = regs::inactive_phys_bank(swap);
        let secure_base = bank.mapped_base(swap);
        let descriptor_base = regs::PageBand::Secure
            .alias_base(secure_base)
            .wrapping_add(regs::IMAGE_DESCRIPTOR_OFFSET);
        self.access
            .bank_view(descriptor_base, regs::IMAGE_DESCRIPTOR_LEN as usize)
    }

    fn inactive_secure_band(&self) -> &[u8]
    {
        // The secure payload sub-band (pages 10-19) of the inactive bank, read
        // through the secure alias (0x0C..). RM0456 Table 68: a secure page must be
        // read through the secure alias, so this band is homogeneous secure. On real
        // silicon the inactive bank is memory-mapped, so this borrows the band with no
        // copy. The host model returns a borrow of its own backing bytes, so verify
        // reads the exact bytes commit boots.
        let swap = regs::swap_bank_set(self.access.peek32(regs::FLASH_OPTR));
        let bank = regs::inactive_phys_bank(swap);
        let secure_base = bank.mapped_base(swap);
        let band_base = regs::PageBand::Secure
            .alias_base(secure_base)
            .wrapping_add(regs::IMAGE_PAYLOAD_OFFSET);
        self.access
            .bank_view(band_base, regs::IMAGE_PAYLOAD_SECURE_SIZE as usize)
    }

    fn inactive_ns_band(&self) -> &[u8]
    {
        // The non-secure image sub-band (pages 20-31) of the inactive bank, read
        // through the non-secure alias (0x08..). RM0456 Table 68: reading a non-secure
        // page through the secure alias returns RAZ (all zeros), so this band must use
        // the NS alias or verify would see zeros for the whole non-secure half. The
        // verify / commit same-store property holds: this is still the store the
        // commit boots, read through the correct alias.
        let swap = regs::swap_bank_set(self.access.peek32(regs::FLASH_OPTR));
        let bank = regs::inactive_phys_bank(swap);
        let secure_base = bank.mapped_base(swap);
        let band_base = regs::PageBand::NonSecure
            .alias_base(secure_base)
            .wrapping_add(regs::IMAGE_NS_BAND_OFFSET);
        self.access
            .bank_view(band_base, regs::IMAGE_NS_BAND_SIZE as usize)
    }

    fn erase_inactive(&mut self) -> Result<(), FlashError>
    {
        self.require_dualbank_secure()?;
        let bank = self.inactive_phys();
        // Erase only the image pages (9-31) of the inactive bank. The metadata band
        // (pages 0-1) and the immutable boot stage (pages 2-8) are below
        // IMAGE_PAGE_FIRST, so this loop never erases NVCNT, the boot stage, or any
        // record. The secure sub-band (pages 9-19) is erased on the secure
        // controller, the non-secure sub-band (pages 20-31) on the non-secure
        // controller: RM0456 Table 68 rejects a secure erase of a non-secure page
        // with WRPERR, so each page uses the controller matching its SECWM band.
        self.erase_band(
            bank,
            regs::PageBand::Secure,
            regs::IMAGE_PAGE_FIRST,
            regs::IMAGE_NS_PAGE_FIRST,
        )?;
        self.erase_band(
            bank,
            regs::PageBand::NonSecure,
            regs::IMAGE_NS_PAGE_FIRST,
            regs::PAGES_PER_BANK,
        )
    }

    fn write_inactive_page
    (
        &mut self,
        page: PageIndex,
        data: &[u8],
    )
        -> Result<(), FlashError>
    {
        if data.len() > fw_update::PAGE_LEN
        {
            return Err(FlashError::OutOfRange);
        }
        self.require_dualbank_secure()?;
        // The logical page lies wholly in one band (the boundary is page-aligned),
        // so it is programmed on that band's controller through that band's alias.
        let (band, base) = self.logical_page_addr(page)?;
        self.unlock_cr_on(band.cr(), band.keyr());
        let mut result = Ok(());
        // A logical page is many quad-words. Program it quad-word by quad-word
        // at the right absolute address. A short final quad-word is padded with
        // the erased value inside program_quad_word, so a partial trailing page
        // never raises SIZERR (RM0456 sec 7.3.7).
        let mut done = 0usize;
        while done < data.len()
        {
            let take = core::cmp::min(
                regs::QUAD_WORD_LEN as usize,
                data.len() - done,
            );
            let chunk = match data.get(done..done + take)
            {
                Some(slice) => slice,
                None =>
                {
                    result = Err(FlashError::OutOfRange);
                    break;
                }
            };
            let addr = match base.checked_add(done as u32)
            {
                Some(value) => value,
                None =>
                {
                    result = Err(FlashError::OutOfRange);
                    break;
                }
            };
            if let Err(error) = self.program_quad_word(band, addr, chunk)
            {
                result = Err(error);
                break;
            }
            done += take;
        }
        self.lock_cr_on(band.cr());
        result
    }

    fn write_descriptor(&mut self, descriptor: &[u8]) -> Result<(), FlashError>
    {
        if descriptor.len() > regs::PAGE_SIZE as usize
        {
            return Err(FlashError::OutOfRange);
        }
        self.require_dualbank_secure()?;
        // The descriptor is page 9 of the inactive bank, a SECURE page, so it is
        // programmed on the secure controller through the secure alias. erase_
        // inactive already erased page 9, so this single programming pass writes
        // the header and signature without a reprogram (no PROGERR).
        let bank = self.inactive_phys();
        let secure_base = self.phys_base(bank);
        let base = regs::PageBand::Secure
            .alias_base(secure_base)
            .checked_add(regs::IMAGE_DESCRIPTOR_OFFSET)
            .ok_or(FlashError::OutOfRange)?;
        self.unlock_cr_on(regs::FLASH_SECCR, regs::FLASH_SECKEYR);
        let mut result = Ok(());
        // The descriptor is many quad-words. Program it quad-word by quad-word. A
        // short final quad-word is padded with the erased value inside
        // program_quad_word, so the trailing bytes never raise SIZERR.
        let mut done = 0usize;
        while done < descriptor.len()
        {
            let take = core::cmp::min(
                regs::QUAD_WORD_LEN as usize,
                descriptor.len() - done,
            );
            let chunk = match descriptor.get(done..done + take)
            {
                Some(slice) => slice,
                None =>
                {
                    result = Err(FlashError::OutOfRange);
                    break;
                }
            };
            let addr = match base.checked_add(done as u32)
            {
                Some(value) => value,
                None =>
                {
                    result = Err(FlashError::OutOfRange);
                    break;
                }
            };
            if let Err(error) =
                self.program_quad_word(regs::PageBand::Secure, addr, chunk)
            {
                result = Err(error);
                break;
            }
            done += take;
        }
        self.lock_cr_on(regs::FLASH_SECCR);
        result
    }

    fn running_bank(&mut self) -> Result<BankId, FlashError>
    {
        // RM0456 sec 7.5.8 / 7.9.13: SWAP_BANK clear boots physical Bank 1,
        // SWAP_BANK set boots physical Bank 2.
        match regs::running_phys_bank(self.swap_bank())
        {
            PhysBank::One => Ok(BankId::Bank1),
            PhysBank::Two => Ok(BankId::Bank2),
        }
    }

    fn target_bank(&mut self) -> Result<BankId, FlashError>
    {
        match self.inactive_phys()
        {
            PhysBank::One => Ok(BankId::Bank1),
            PhysBank::Two => Ok(BankId::Bank2),
        }
    }

    fn commit_swap(&mut self) -> Result<(), FlashError>
    {
        // Inert brick-class path. This carries the full real option-byte sequence
        // (RM0456 sec 7.4.2): unlock the CR, unlock the options, flip OPTR.SWAP_BANK,
        // set OPTSTRT, poll BSY, then set OBL_LAUNCH which resets the part and applies
        // the option load on real silicon. The option-byte / OBL_LAUNCH writes are
        // emitted only through the target-gated MMIO port, which does not compile on
        // the host. No host build and no test drives this on silicon. Its on-silicon
        // invocation stays gated on a deliberate operator action plus the hardware
        // power-fault proof.
        self.require_dualbank_secure()?;
        let target_is_bank2 =
            matches!(self.inactive_phys(), PhysBank::Two);
        self.arm_swap(target_is_bank2)
    }

    fn revert_swap(&mut self) -> Result<(), FlashError>
    {
        // Inert brick-class path, same real sequence as commit_swap but arming the
        // swap back to the previously-running (now inactive) bank. Same gating:
        // emitted only through the target-gated MMIO port, never auto-run on silicon.
        self.require_dualbank_secure()?;
        // Revert is reachable only after the forward swap already took effect and the
        // new bank is running, so a correct revert flips SWAP_BANK back toward the
        // previously-running bank, which is now the inactive one (RM0456 sec 7.5.8).
        // Arm toward the inactive bank, exactly the notion commit_swap arms toward, so
        // the revert points the boot map back at the old image.
        let swap = self.swap_bank();
        let revert_target = regs::inactive_phys_bank(swap);
        // The revert target is distinct from the running bank by construction:
        // inactive_phys_bank and running_phys_bank are pure opposites of the same
        // swap bool (RM0456 sec 7.5.8), so no runtime guard can add anything here.
        let target_is_bank2 = matches!(revert_target, PhysBank::Two);
        self.arm_swap(target_is_bank2)
    }

    fn nvcnt_read(&mut self) -> Result<u32, FlashError>
    {
        self.nvcnt_max()
    }

    fn nvcnt_bump(&mut self, value: u32) -> Result<(), FlashError>
    {
        self.require_dualbank_secure()?;
        let current = self.nvcnt_max()?;
        if value < current
        {
            // A regression below the monotone floor fails closed.
            return Err(FlashError::WriteFailed);
        }
        if value == current
        {
            // Equal is a no-op against the monotone store, so a re-confirm of
            // the same image spends no finite burn budget.
            return Ok(());
        }
        let slot = match self.nvcnt_free_slot()?
        {
            Some(slot) => slot,
            None => return Err(FlashError::CounterExhausted),
        };
        let addr = self.meta_addr(
            regs::META_NVCNT_OFFSET + slot * regs::QUAD_WORD_LEN,
        )?;
        self.program_record(addr, value)
    }

    fn pending_read(&mut self) -> Result<PendingFlag, FlashError>
    {
        let word = self.read_meta_word(regs::META_PENDING_OFFSET)?;
        match word
        {
            regs::PENDING_NONE => Ok(PendingFlag::None),
            regs::PENDING_ARMED_BANK1 => Ok(PendingFlag::Armed(BankId::Bank1)),
            regs::PENDING_ARMED_BANK2 => Ok(PendingFlag::Armed(BankId::Bank2)),
            // Any other value is a torn or corrupt record. Fail closed: treat it
            // as no pending confirm, which keeps the old bank bootable.
            _ => Ok(PendingFlag::None),
        }
    }

    fn pending_write(&mut self, flag: PendingFlag) -> Result<(), FlashError>
    {
        let pending_value = match flag
        {
            PendingFlag::None => regs::PENDING_NONE,
            PendingFlag::Armed(BankId::Bank1) => regs::PENDING_ARMED_BANK1,
            PendingFlag::Armed(BankId::Bank2) => regs::PENDING_ARMED_BANK2,
        };
        // The pending and outcome records share page 1. Rewriting the pending
        // record erases that page, so the outcome record must be preserved and
        // reprogrammed alongside it (read the live outcome word and carry it
        // through the erase). This keeps the two records independent across a
        // rewrite of either.
        let outcome_value = self.read_meta_word(regs::META_OUTCOME_OFFSET)?;
        self.rewrite_mutable_records(pending_value, outcome_value)
    }

    fn boot_count_read(&mut self) -> Result<u32, FlashError>
    {
        self.boot_count_slots()
    }

    fn boot_count_advance(&mut self) -> Result<(), FlashError>
    {
        self.require_dualbank_secure()?;
        let used = self.boot_count_slots()?;
        if used >= regs::META_LOG_SLOTS
        {
            return Err(FlashError::WriteFailed);
        }
        let addr = self.meta_addr(
            regs::META_BOOT_OFFSET + used * regs::QUAD_WORD_LEN,
        )?;
        self.program_record(addr, regs::BOOT_TICK)
    }

    fn update_outcome_read(&mut self) -> Result<UpdateOutcome, FlashError>
    {
        let word = self.read_meta_word(regs::META_OUTCOME_OFFSET)?;
        match word
        {
            regs::OUTCOME_NONE => Ok(UpdateOutcome::None),
            regs::OUTCOME_AUTO_REVERTED => Ok(UpdateOutcome::AutoReverted),
            // Any other value is a torn or corrupt record. Fail closed: treat it
            // as no recorded outcome.
            _ => Ok(UpdateOutcome::None),
        }
    }

    fn update_outcome_write
    (
        &mut self,
        outcome: UpdateOutcome,
    )
        -> Result<(), FlashError>
    {
        let outcome_value = match outcome
        {
            UpdateOutcome::None => regs::OUTCOME_NONE,
            UpdateOutcome::AutoReverted => regs::OUTCOME_AUTO_REVERTED,
        };
        // The outcome and pending records share page 1, so carry the live
        // pending word through the erase the same way pending_write carries the
        // outcome word.
        let pending_value = self.read_meta_word(regs::META_PENDING_OFFSET)?;
        self.rewrite_mutable_records(pending_value, outcome_value)
    }

    fn update_outcome_clear(&mut self) -> Result<(), FlashError>
    {
        self.update_outcome_write(UpdateOutcome::None)
    }
}

impl<A> Stm32FlashSeam<A>
where
    A: FlashAccess,
{
    /// Arms the option-byte SWAP_BANK plus OBL_LAUNCH sequence (inert).
    ///
    /// RM0456 sec 7.4.2: poll BSY, unlock the CR, unlock the options, write OPTR (set
    /// or clear SWAP_BANK), set OPTSTRT, poll BSY, set OBL_LAUNCH. The final
    /// OBL_LAUNCH triggers the reset that reloads the option bytes on real silicon,
    /// the brick-class step. Every register write here lands on the [`FlashAccess`]
    /// port, which is the target-gated MMIO on hardware and a state model in tests.
    /// The model stages the swap and applies it only at a modelled reset, so no real
    /// OBL_LAUNCH ever fires off-target.
    ///
    /// The whole sequence drives the non-secure controller (OPTSTRT / OBL_LAUNCH live
    /// in NSCR, RM0456 sec 7.4.2), so it polls FLASH_NSSR: the controller driven is
    /// the controller polled. BSY is mirrored in both status registers (RM0456 sec
    /// 7.3.5), so the readiness is the same, this only removes the controller / status
    /// asymmetry on the brick-class path.
    fn arm_swap(&mut self, want_bank2: bool) -> Result<(), FlashError>
    {
        self.wait_ready_on(regs::FLASH_NSSR)?;
        // The option program goes through the non-secure control register
        // (OPTSTRT / OBL_LAUNCH live in NSCR, RM0456 sec 7.4.2), so unlock the
        // NS CR with the same KEY1 / KEY2 pair, then unlock the options.
        self.unlock_ns_cr();
        self.unlock_options();

        // Write OPTR with SWAP_BANK set or cleared as requested.
        if want_bank2
        {
            self.access
                .modify32(regs::FLASH_OPTR, 0, regs::OPTR_SWAP_BANK);
        }
        else
        {
            self.access
                .modify32(regs::FLASH_OPTR, regs::OPTR_SWAP_BANK, 0);
        }

        // Start the option program, then wait for BSY to clear on the NS status.
        self.access
            .modify32(regs::FLASH_NSCR, 0, regs::NSCR_OPTSTRT);
        self.wait_ready_on(regs::FLASH_NSSR)?;

        // A rejected option program raises OPTWERR in NSSR (RM0456 sec 7.9.7).
        let nssr = self.access.read32(regs::FLASH_NSSR);
        if nssr & regs::SR_OPTWERR != 0
        {
            // Clear the rc_w1 flag and fail closed, no OBL_LAUNCH is issued.
            self.access.write32(regs::FLASH_NSSR, regs::SR_OPTWERR);
            self.lock_options();
            self.lock_ns_cr();
            return Err(FlashError::Hardware);
        }

        // OBL_LAUNCH applies the option load and resets the part on silicon. This is
        // the inert brick-class write: present, never auto-run.
        self.access
            .modify32(regs::FLASH_NSCR, 0, regs::NSCR_OBL_LAUNCH);

        self.lock_options();
        self.lock_ns_cr();
        Ok(())
    }

    /// Fails closed unless the part is in the DUALBANK secure posture.
    ///
    /// Every destructive op (erase, program, swap arm) calls this first. A
    /// SWAP_BANK flip is only meaningful with `OPTR.DUALBANK` set, and this
    /// driver writes the secure bank, which assumes `OPTR.TZEN` set (RM0456 sec
    /// 7.9.13). Either bit clear means the geometry the constants pin does not
    /// hold, so the op is refused rather than run blind.
    fn require_dualbank_secure(&mut self) -> Result<(), FlashError>
    {
        let optr = self.access.read32(regs::FLASH_OPTR);
        if optr & regs::OPTR_DUALBANK == 0 || optr & regs::OPTR_TZEN == 0
        {
            return Err(FlashError::Hardware);
        }
        Ok(())
    }

    /// Unlocks the non-secure control register with KEY1 / KEY2 (NSKEYR).
    ///
    /// RM0456 sec 7.4.2: the option-byte sequence needs the NS CR unlocked
    /// because OPTSTRT / OBL_LAUNCH are NSCR bits. A no-op if already unlocked.
    fn unlock_ns_cr(&mut self)
    {
        let nscr = self.access.read32(regs::FLASH_NSCR);
        if nscr & regs::NSCR_LOCK == 0
        {
            return;
        }
        self.access.write32(regs::FLASH_NSKEYR, regs::FLASH_KEY1);
        self.access.write32(regs::FLASH_NSKEYR, regs::FLASH_KEY2);
    }

    /// Re-locks the non-secure control register (sets `NSCR.LOCK`). RM0456 sec
    /// 7.9.9.
    fn lock_ns_cr(&mut self)
    {
        self.access
            .modify32(regs::FLASH_NSCR, 0, regs::NSCR_LOCK);
    }

    /// Unlocks the option bytes with the OPTKEY1 / OPTKEY2 sequence.
    ///
    /// RM0456 sec 7.4.2: write OPTKEY1 then OPTKEY2 to OPTKEYR. A wrong value or
    /// order locks the options until reset. Part of the inert option-byte path.
    fn unlock_options(&mut self)
    {
        self.access
            .write32(regs::FLASH_OPTKEYR, regs::FLASH_OPTKEY1);
        self.access
            .write32(regs::FLASH_OPTKEYR, regs::FLASH_OPTKEY2);
    }

    /// Re-locks the option bytes (sets `NSCR.OPTLOCK`). RM0456 sec 7.9.9.
    fn lock_options(&mut self)
    {
        self.access
            .modify32(regs::FLASH_NSCR, 0, regs::NSCR_OPTLOCK);
    }
}
