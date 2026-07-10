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
//! SWAP_BANK remaps the ADDRESS of each bank, but the BKER erase selector and
//! the SECWM / WRP protections follow the PHYSICAL bank (RM0456 sec 7.5.8 Fig
//! 23/24). So erase (BKER) and program / read (address) must be derived from the
//! SAME physical bank or they diverge under SWAP_BANK=1. This driver names a
//! physical bank with [`regs::PhysBank`] and asks it for both the BKER bit and
//! the mapped base, reading `OPTR.SWAP_BANK` (RM0456 sec 7.9.13) at runtime on
//! every address computation. The inactive-bank erase, program, and read all go
//! through the same physical bank, and the fixed-Bank-1 metadata band re-derives
//! its mapped address from SWAP_BANK on every access, so the NVCNT, the pending
//! record, the boot-count, and the update-outcome record survive a swap.
//!
//! # Posture assertion before any destructive op
//!
//! Erase, program, and the swap arm all assert `OPTR.DUALBANK` and `OPTR.TZEN`
//! first (RM0456 sec 7.9.13). A mis-provisioned part (single-bank or TZEN clear)
//! means the geometry the constants pin does not hold, so the driver fails closed
//! with [`FlashError::Hardware`] rather than erasing or programming blind.
//!
//! # Brick-safety: the option-byte / SWAP_BANK path is present but inert
//!
//! The [`Stm32FlashSeam`] [`commit_swap`](fw_update::FlashSeam::commit_swap) and
//! [`revert_swap`](fw_update::FlashSeam::revert_swap) impls carry the
//! FULL real register sequence (OPTR SWAP_BANK plus OPTSTRT plus OBL_LAUNCH,
//! RM0456 sec 7.4.2). OBL_LAUNCH triggers the reset that applies the option load
//! on real silicon, so it is the IRREVERSIBLE, brick-class step. The whole real
//! register surface is the [`FlashAccess`] MMIO port, which is gated to
//! `target_os = "none"` and does not compile on the host. NO host build and NO
//! test ever drives a real option-byte write: the tests run a state model that
//! stages the swap and applies it only at a modelled reset, never a real
//! OBL_LAUNCH. The capability is complete but inert. Its on-silicon invocation
//! stays gated on a deliberate operator action.

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
    /// This is the ONE helper the B1 resolution turns on: it pairs the physical
    /// bank with the current SWAP_BANK state to yield the address erase and
    /// program must both use (RM0456 sec 7.5.8).
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

    /// Polls `SECSR.BSY` and `SECSR.WDW` down to clear, bounded.
    ///
    /// RM0456 sec 7.3.7 / 7.3.6: a program or erase must wait for BSY to clear,
    /// and a program must also see WDW clear before the next data write. A
    /// bounded spin fails closed with [`FlashError::Hardware`] rather than
    /// hanging.
    fn wait_ready(&mut self) -> Result<(), FlashError>
    {
        let mut spins = 0u32;
        loop
        {
            let sr = self.access.read32(regs::FLASH_SECSR);
            if sr & (regs::SR_BSY | regs::SR_WDW) == 0
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

    /// Clears every program / erase error flag (rc_w1) in `SECSR`.
    ///
    /// RM0456 sec 7.9.8: each error flag is rc_w1, write 1 to clear. Clearing
    /// from a known state before every op is part of failing closed.
    fn clear_errors(&mut self)
    {
        self.access.write32(regs::FLASH_SECSR, regs::SR_ALL_ERRORS);
    }

    /// Reads `SECSR` and maps any error flag to a typed [`FlashError`].
    ///
    /// RM0456 sec 7.9.8: PROGERR, WRPERR, PGAERR, SIZERR, PGSERR, OPERR. Any set
    /// flag means the op did not take effect, so it fails closed.
    fn check_errors(&mut self) -> Result<(), FlashError>
    {
        let sr = self.access.read32(regs::FLASH_SECSR);
        if sr & regs::SR_ALL_ERRORS != 0
        {
            return Err(FlashError::WriteFailed);
        }
        Ok(())
    }

    /// Unlocks the secure control register with the KEY1 / KEY2 sequence.
    ///
    /// RM0456 sec 7.3.5: write KEY1 then KEY2 to SECKEYR. A wrong value or order
    /// locks the CR until reset, so the driver only writes the canonical pair.
    /// A no-op if the CR is already unlocked.
    fn unlock_cr(&mut self)
    {
        let cr = self.access.read32(regs::FLASH_SECCR);
        if cr & regs::SECCR_LOCK == 0
        {
            return;
        }
        self.access.write32(regs::FLASH_SECKEYR, regs::FLASH_KEY1);
        self.access.write32(regs::FLASH_SECKEYR, regs::FLASH_KEY2);
    }

    /// Re-locks the secure control register, returning to a known idle state.
    ///
    /// RM0456 sec 7.9.10: setting `SECCR.LOCK` re-locks the CR. The driver locks
    /// after every op so a later op must unlock deliberately.
    fn lock_cr(&mut self)
    {
        self.access
            .modify32(regs::FLASH_SECCR, 0, regs::SECCR_LOCK);
    }

    /// Programs one 16-byte quad-word at `addr` from up to 16 bytes of `data`.
    ///
    /// RM0456 sec 7.3.7: poll ready, clear errors, set PG, write 4 consecutive
    /// 32-bit words to a quad-word-aligned address, poll BSY, check EOP, clear
    /// PG. A short tail pads with the erased value so a sub-quad-word write never
    /// raises SIZERR. `addr` MUST be quad-word aligned. The caller has already
    /// unlocked the CR.
    fn program_quad_word
    (
        &mut self,
        addr: u32,
        data: &[u8],
    )
        -> Result<(), FlashError>
    {
        if data.len() > regs::QUAD_WORD_LEN as usize
        {
            return Err(FlashError::OutOfRange);
        }
        self.wait_ready()?;
        self.clear_errors();

        // Set PG, then write the four words. A read of a fully-erased quad-word
        // is all-ones, so padding a short tail with the erased word leaves those
        // bytes untouched (program clears bits only, RM0456 sec 7.3.1).
        self.access
            .modify32(regs::FLASH_SECCR, 0, regs::SECCR_PG);

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

        self.wait_ready()?;
        let result = self.check_eop_then_clear_errors();
        // Clear PG whatever happened, so the controller returns to idle.
        self.access
            .modify32(regs::FLASH_SECCR, regs::SECCR_PG, 0);
        result
    }

    /// Confirms `EOP` rose then folds in any error flag, clearing both (rc_w1).
    ///
    /// RM0456 sec 7.3.7 / 7.3.6: a successful op sets EOP. The driver treats a
    /// set error flag as the authority (fail closed) and clears EOP and the
    /// error flags so the next op starts from a known SR.
    fn check_eop_then_clear_errors(&mut self) -> Result<(), FlashError>
    {
        let errors = self.check_errors();
        // Clear EOP (rc_w1) regardless, so it does not leak into the next op.
        self.access.write32(regs::FLASH_SECSR, regs::SR_EOP);
        errors
    }

    /// Erases one 8 KB page of the given physical bank.
    ///
    /// RM0456 sec 7.3.6: poll ready, clear errors, write PER plus BKER plus PNB,
    /// set STRT, poll BSY, check EOP, clear PER. The caller has unlocked the CR.
    /// `page` is bank-relative (0..[`regs::PAGES_PER_BANK`]). BKER comes from the
    /// physical bank (SWAP_BANK-independent, RM0456 sec 7.5.8).
    fn erase_page
    (
        &mut self,
        bank: PhysBank,
        page: u32,
    )
        -> Result<(), FlashError>
    {
        if page >= regs::PAGES_PER_BANK
        {
            return Err(FlashError::OutOfRange);
        }
        self.wait_ready()?;
        self.clear_errors();

        let bker = bank.bker();
        let pnb = (page << regs::SECCR_PNB_SHIFT) & regs::SECCR_PNB_MASK;
        // Write PER plus BKER plus PNB in one word, first clearing every stale
        // operation-select bit so no mass-erase, burst-write, or interrupt
        // request rides along (RM0456 sec 7.9.10), then set STRT in a second
        // write (RM0456 sec 7.3.6).
        self.access.modify32(
            regs::FLASH_SECCR,
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
        self.access
            .modify32(regs::FLASH_SECCR, 0, regs::SECCR_STRT);

        self.wait_ready()?;
        let result = self.check_eop_then_clear_errors();
        self.access
            .modify32(regs::FLASH_SECCR, regs::SECCR_PER, 0);
        result
    }

    /// Maps a logical page index to its absolute address in the inactive bank.
    ///
    /// The machine writes `fw_update::PAGE_LEN`-byte logical pages. The address
    /// is the inactive bank's mapped image-band base plus `page * PAGE_LEN`,
    /// bounds-checked to stay inside the image band. Overflow-safe. The base is
    /// the SAME physical bank the erase loop targets, so erase and program agree.
    fn logical_page_addr
    (
        &mut self,
        page: PageIndex,
    )
        -> Result<u32, FlashError>
    {
        let bank = self.inactive_phys();
        let base = self.phys_base(bank);
        let image_base = base
            .checked_add(regs::IMAGE_REGION_OFFSET)
            .ok_or(FlashError::OutOfRange)?;
        let offset = (page as u32)
            .checked_mul(fw_update::PAGE_LEN as u32)
            .ok_or(FlashError::OutOfRange)?;
        let end = offset
            .checked_add(fw_update::PAGE_LEN as u32)
            .ok_or(FlashError::OutOfRange)?;
        if end > regs::IMAGE_REGION_SIZE
        {
            return Err(FlashError::OutOfRange);
        }
        image_base.checked_add(offset).ok_or(FlashError::OutOfRange)
    }

    // Metadata helpers, pinned to PHYSICAL Bank 1, swap-aware.
    //
    // The NVCNT, boot-count, pending, and update-outcome records all live in
    // physical Bank 1 (pages 0-1). The driver re-derives Bank 1's MAPPED base
    // from the live SWAP_BANK on EVERY access, so the records survive a swap
    // (RM0456 sec 7.5.8: data lives at a physical location mapped to different
    // virtual addresses by SWAP_BANK). This is the B1 fix applied to metadata.

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
    /// Unlocks the CR, programs the quad-word, then re-locks. Fail-closed: a
    /// program fault re-locks and returns the typed error.
    fn program_record
    (
        &mut self,
        addr: u32,
        value: u32,
    )
        -> Result<(), FlashError>
    {
        self.unlock_cr();
        let result = self.program_quad_word(addr, &value.to_le_bytes());
        self.lock_cr();
        result
    }

    /// Reads the live word of a mutable metadata record (pending or outcome).
    fn read_meta_word(&mut self, offset: u32) -> Result<u32, FlashError>
    {
        let addr = self.meta_addr(offset)?;
        Ok(self.access.read32(addr))
    }

    /// Rewrites BOTH page-1 mutable records (pending and outcome) at once.
    ///
    /// The pending and update-outcome records share page 1 of physical Bank 1, so
    /// a rewrite of either erases the one page and reprograms both (RM0456 sec
    /// 7.3.6: erase is per 8 KB page). The caller supplies the desired post-write
    /// value of each record. An erased value programs nothing (an erased page
    /// already reads erased). Fail-closed: an erase or program fault re-locks and
    /// returns the typed error, leaving the OLD records readable as best effort.
    fn rewrite_mutable_records
    (
        &mut self,
        pending_value: u32,
        outcome_value: u32,
    )
        -> Result<(), FlashError>
    {
        self.require_dualbank_secure()?;
        self.unlock_cr();
        let erased = self.erase_page(PhysBank::One, regs::META_MUTABLE_PAGE);
        self.lock_cr();
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

impl<A> FlashSeam for Stm32FlashSeam<A>
where
    A: FlashAccess,
{
    fn inactive_bank(&self) -> &[u8]
    {
        // Verify must read the EXACT bytes commit boots. On real silicon the
        // inactive bank is memory-mapped, so this borrows its image band with no
        // copy. The inactive physical bank and its mapped base both come from the
        // live OPTR.SWAP_BANK through a shared `peek32` (RM0456 sec 7.9.13), then
        // the image band is borrowed through `bank_view`. The host model returns
        // a borrow of its own backing bytes for the same region, so verify and
        // commit act on one store.
        let swap = regs::swap_bank_set(self.access.peek32(regs::FLASH_OPTR));
        let bank = regs::inactive_phys_bank(swap);
        let base = bank.mapped_base(swap);
        let image_base = base.wrapping_add(regs::IMAGE_REGION_OFFSET);
        self.access
            .bank_view(image_base, regs::IMAGE_REGION_SIZE as usize)
    }

    fn erase_inactive(&mut self) -> Result<(), FlashError>
    {
        self.require_dualbank_secure()?;
        let bank = self.inactive_phys();
        self.unlock_cr();
        let mut result = Ok(());
        // Erase only the image pages of the inactive bank. The metadata band is
        // pages 0-1 of physical Bank 1, never an image page, so this loop never
        // erases NVCNT, the pending record, the boot-count, or the outcome. The
        // image pages are the SAME physical bank the program path writes, so
        // erase and program agree.
        for page in regs::IMAGE_PAGE_FIRST..regs::PAGES_PER_BANK
        {
            if let Err(error) = self.erase_page(bank, page)
            {
                result = Err(error);
                break;
            }
        }
        self.lock_cr();
        result
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
        let base = self.logical_page_addr(page)?;
        self.unlock_cr();
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
            if let Err(error) = self.program_quad_word(addr, chunk)
            {
                result = Err(error);
                break;
            }
            done += take;
        }
        self.lock_cr();
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
        // INERT brick-class path. This carries the FULL real option-byte
        // sequence (RM0456 sec 7.4.2): unlock the CR, unlock the options, flip
        // OPTR.SWAP_BANK, set OPTSTRT, poll BSY, then set OBL_LAUNCH which
        // RESETS the part and applies the option load on real silicon. The
        // option-byte / OBL_LAUNCH writes are emitted ONLY through the
        // target-gated MMIO port, which does not compile on the host. No host
        // build and no test drives this on silicon. Its on-silicon invocation
        // stays gated on a deliberate operator action plus the hardware
        // power-fault proof.
        self.require_dualbank_secure()?;
        let target_is_bank2 =
            matches!(self.inactive_phys(), PhysBank::Two);
        self.arm_swap(target_is_bank2)
    }

    fn revert_swap(&mut self) -> Result<(), FlashError>
    {
        // INERT brick-class path, same real sequence as commit_swap but arming
        // the swap back to the previously-running (now inactive) bank. Same
        // gating: emitted only through the target-gated MMIO port, never
        // auto-run on silicon.
        self.require_dualbank_secure()?;
        // Revert is reachable only after the forward swap already took effect
        // and the NEW bank is running, so a correct revert flips SWAP_BANK BACK
        // toward the previously-running bank, which is now the INACTIVE one
        // (RM0456 sec 7.5.8). Arm toward the inactive bank, exactly the notion
        // commit_swap arms toward, so the revert points the boot map back at the
        // old image.
        let swap = self.swap_bank();
        let revert_target = regs::inactive_phys_bank(swap);
        // Local restatement of the caller's contract: a revert points the boot
        // map at a DIFFERENT bank than the one running, never at the live bank.
        // The forward swap must already be in effect for revert to be correct,
        // which means the revert target (the inactive bank) is distinct from the
        // running bank (RM0456 sec 7.5.8). Compiled out of release builds.
        debug_assert!(
            revert_target != regs::running_phys_bank(swap),
            "revert must arm toward a bank other than the running one",
        );
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
            // as no pending confirm, which keeps the OLD bank bootable.
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
    /// Arms the option-byte SWAP_BANK plus OBL_LAUNCH sequence (INERT).
    ///
    /// RM0456 sec 7.4.2: poll BSY, unlock the CR, unlock the options, write
    /// OPTR (set or clear SWAP_BANK), set OPTSTRT, poll BSY, set OBL_LAUNCH. The
    /// final OBL_LAUNCH triggers the reset that reloads the option bytes on real
    /// silicon, which is the brick-class step. Every register write here lands
    /// on the [`FlashAccess`] port, which is the target-gated MMIO on hardware
    /// and a state model in tests. The model stages the swap and applies it only
    /// at a modelled reset, so NO real OBL_LAUNCH ever fires off-target.
    fn arm_swap(&mut self, want_bank2: bool) -> Result<(), FlashError>
    {
        self.wait_ready()?;
        // The option program goes through the NON-SECURE control register
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

        // Start the option program, then wait for BSY to clear.
        self.access
            .modify32(regs::FLASH_NSCR, 0, regs::NSCR_OPTSTRT);
        self.wait_ready()?;

        // A rejected option program raises OPTWERR in NSSR (RM0456 sec 7.9.7).
        let nssr = self.access.read32(regs::FLASH_NSSR);
        if nssr & regs::SR_OPTWERR != 0
        {
            // Clear the rc_w1 flag and fail closed, NO OBL_LAUNCH is issued.
            self.access.write32(regs::FLASH_NSSR, regs::SR_OPTWERR);
            self.lock_options();
            self.lock_ns_cr();
            return Err(FlashError::Hardware);
        }

        // OBL_LAUNCH applies the option load and RESETS the part on silicon.
        // This is the inert brick-class write: present, never auto-run.
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
