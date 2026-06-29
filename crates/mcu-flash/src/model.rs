//! A faithful host model of the STM32U545 FLASH controller, for host tests.
//!
//! This implements [`FlashAccess`] by modelling the REAL controller state, not
//! a per-address value queue: a stateful peripheral needs a model of the hardware
//! state, or a silicon-only fault hides behind a green host test. It models:
//!   - TWO physically separate bank stores (`bank_a` = physical Bank 1, `bank_b`
//!     = physical Bank 2), each 256 KB, where a program clears bits only
//!     (`new = old AND data`) and an erase sets 0xFF (RM0456 sec 7.3.1),
//!   - the ADDRESS-TO-STORE mapping that FLIPS with the effective SWAP_BANK
//!     (RM0456 sec 7.5.8): when SWAP_BANK is clear the low alias resolves to
//!     physical Bank 1 and the high alias to Bank 2, and the reverse when set. So
//!     a fixed virtual address resolves to DIFFERENT physical bytes before and
//!     after a swap, which is the fault class a flat one-store model could not
//!     observe,
//!   - the SECSR BSY / WDW handshake (BSY pulses busy for a few polls on each
//!     program / erase, so the driver's poll loop is exercised),
//!   - the rc_w1 error flags (a reprogram of a non-erased word raises PROGERR, a
//!     write-protected page raises WRPERR), so the driver's fail-closed path is
//!     observable,
//!   - the CR / option unlock key sequences (a wrong value or order leaves the
//!     register locked, RM0456 sec 7.3.5 / 7.4.2),
//!   - the staged SWAP_BANK option load, applied ONLY at a modelled reset
//!     ([`FlashModel::apply_reset`]), never on the OBL_LAUNCH write itself. This
//!     is what keeps the brick-class path INERT on the host: the model stages
//!     the swap instead of resetting, so no test ever performs a real option
//!     load (RM0456 sec 7.5.8).
//!
//! The model is the test double the integration test drives the real driver
//! over, so the driver's exact unlock to program to poll to lock sequencing and
//! its page-to-address math run against faithful silicon behaviour.

#![cfg(test)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec;

use crate::bus::FlashAccess;
use crate::regs;

/// One physical bank store size in bytes (256 KB).
const BANK_BYTES: usize = regs::BANK_SIZE as usize;

/// Which physical bank store an address resolves to, plus the byte index inside
/// that store.
struct Resolved
{
    /// True when the address resolves to physical Bank 2 (`bank_b`).
    bank2: bool,
    /// The byte index inside the resolved bank store.
    index: usize,
}

/// How many BSY polls each program / erase stays busy before completing.
///
/// A small non-zero value exercises the driver's BSY poll loop without slowing
/// the tests. The op completes on the triggering write, then BSY reads busy for
/// this many SECSR reads, then clears.
const BUSY_POLLS: u32 = 2;

/// A faithful host model of the FLASH controller and the staged-swap state.
pub(crate) struct FlashModel
{
    /// Physical Bank 1 backing bytes (program clears bits, erase sets 0xFF).
    ///
    /// Boxed so each 256 KB store lives on the heap, not the test thread stack
    /// (the model is moved between drivers, a stack array would overflow).
    bank_a: Box<[u8; BANK_BYTES]>,
    /// Physical Bank 2 backing bytes (program clears bits, erase sets 0xFF).
    bank_b: Box<[u8; BANK_BYTES]>,
    /// The live SECCR control value (LOCK, PG, PER, PNB, BKER, STRT).
    seccr: u32,
    /// The live SECSR status value (BSY, WDW, error flags).
    secsr: u32,
    /// The live NSSR status value (option-write error path).
    nssr: u32,
    /// The live NSCR control value (OPTLOCK, OPTSTRT, OBL_LAUNCH).
    nscr: u32,
    /// The EFFECTIVE OPTR option value the running system sees (SWAP_BANK,
    /// DUALBANK, TZEN, RDP). A read of FLASH_OPTR returns this. The effective
    /// SWAP_BANK changes only at a modelled reset, never on the option-program
    /// write itself, so the running bank stays stable mid-update. The effective
    /// SWAP_BANK ALSO drives address resolution, so a swap actually remaps which
    /// physical store an alias address hits.
    optr: u32,
    /// The OPTR program shadow: where an OPTR register write lands.
    ///
    /// RM0456 sec 7.4.2: writing OPTR then setting OPTSTRT PROGRAMS the option
    /// bytes, but the SWAP_BANK change only takes effect at the option reload
    /// (the OBL_LAUNCH reset). So the driver's OPTR write updates this shadow,
    /// OPTSTRT stages the shadow's SWAP_BANK, and the modelled reset applies it
    /// into the effective `optr`. This keeps the brick-class swap inert.
    optr_shadow: u32,
    /// Remaining BSY busy polls before the in-flight op reports ready.
    busy_polls: u32,
    /// CR unlock progress: 0 locked, 1 saw KEY1, 2 unlocked.
    cr_key_step: u8,
    /// Option unlock progress: 0 locked, 1 saw OPTKEY1, 2 unlocked.
    opt_key_step: u8,
    /// The staged SWAP_BANK target, applied only at a modelled reset.
    ///
    /// `None` means no swap is staged. `Some(true)` stages SWAP_BANK set
    /// (boot Bank 2), `Some(false)` stages it clear (boot Bank 1). A modelled
    /// reset ([`FlashModel::apply_reset`]) writes it into OPTR. This is the
    /// inert stand-in for the real OBL_LAUNCH reset.
    staged_swap: Option<bool>,
    /// True once an OBL_LAUNCH write was observed, so the test can assert the
    /// inert path ran without a real reset.
    obl_launched: bool,
    /// A write-protected page that raises WRPERR on a program or erase, as
    /// `(bank2, page)` in PHYSICAL coordinates. `None` means none.
    wrp_page: Option<(bool, u32)>,
}

impl FlashModel
{
    /// Builds an erased model: both stores 0xFF, CR and options locked, the
    /// metadata band erased (so NVCNT reads 0 and the pending record reads
    /// None), no swap staged, booting Bank 1.
    pub(crate) fn new() -> FlashModel
    {
        FlashModel
        {
            bank_a: erased_bank(),
            bank_b: erased_bank(),
            seccr: regs::SECCR_LOCK,
            secsr: 0,
            nssr: 0,
            nscr: regs::NSCR_LOCK | regs::NSCR_OPTLOCK,
            // DUALBANK set, TZEN set, RDP at a non-locked placeholder. SWAP_BANK
            // clear, so the part boots Bank 1 and the inactive bank is Bank 2.
            optr: regs::OPTR_DUALBANK | regs::OPTR_TZEN,
            optr_shadow: regs::OPTR_DUALBANK | regs::OPTR_TZEN,
            busy_polls: 0,
            cr_key_step: 0,
            opt_key_step: 0,
            staged_swap: None,
            obl_launched: false,
            wrp_page: None,
        }
    }

    /// Marks a PHYSICAL Bank-2 page write-protected so a program / erase of it
    /// raises WRPERR, exercising the driver's fail-closed path on the inactive
    /// bank.
    pub(crate) fn protect_bank2_page(&mut self, page: u32)
    {
        self.wrp_page = Some((true, page));
    }

    /// True when the secure control register is locked (test inspection).
    ///
    /// The driver re-locks the CR from a known state after every op, so a test
    /// asserts the lock is back even after a fault.
    pub(crate) fn model_locked(&self) -> bool
    {
        self.cr_locked()
    }

    /// Clears DUALBANK in OPTR, so the driver refuses every destructive op.
    pub(crate) fn clear_dualbank(&mut self)
    {
        self.optr &= !regs::OPTR_DUALBANK;
        self.optr_shadow &= !regs::OPTR_DUALBANK;
    }

    /// True once an OBL_LAUNCH write was observed (the inert brick-class path).
    pub(crate) fn obl_launched(&self) -> bool
    {
        self.obl_launched
    }

    /// The staged but not-yet-applied SWAP_BANK target (test inspection).
    pub(crate) fn staged_swap(&self) -> Option<bool>
    {
        self.staged_swap
    }

    /// True when OPTR currently boots Bank 2 (SWAP_BANK set).
    pub(crate) fn boots_bank2(&self) -> bool
    {
        regs::swap_bank_set(self.optr)
    }

    /// True when the secure control register is locked (test inspection).
    pub(crate) fn cr_locked(&self) -> bool
    {
        self.seccr & regs::SECCR_LOCK != 0
    }

    /// Reads the byte directly from a PHYSICAL bank store, bypassing the alias
    /// resolution (test inspection that does NOT depend on the swap state).
    pub(crate) fn phys_byte(&self, bank2: bool, offset: usize) -> Option<u8>
    {
        self.store(bank2).get(offset).copied()
    }

    /// Writes one byte directly into a PHYSICAL bank store at a bank-relative
    /// offset, bypassing the program path (test setup of a pre-existing image).
    pub(crate) fn poke_phys(&mut self, bank2: bool, offset: usize, value: u8)
    {
        if let Some(slot) = self.store_mut(bank2).get_mut(offset)
        {
            *slot = value;
        }
    }

    /// Applies the staged option load atomically, modelling the swap reset.
    ///
    /// On a real reset the option load writes the staged SWAP_BANK into OPTR and
    /// clears the stage (RM0456 sec 7.5.8). After this the SAME alias address
    /// resolves to the OTHER physical store. A power cut before this keeps the
    /// OLD OPTR, so the harness only calls this to model a clean reset boundary.
    pub(crate) fn apply_reset(&mut self)
    {
        if let Some(set) = self.staged_swap.take()
        {
            if set
            {
                self.optr |= regs::OPTR_SWAP_BANK;
            }
            else
            {
                self.optr &= !regs::OPTR_SWAP_BANK;
            }
            // The reload makes the effective register and its program shadow
            // agree again.
            self.optr_shadow = self.optr;
        }
        // A reset also re-locks the CR and the options and clears volatile
        // status, just like a real POR / system reset.
        self.seccr = regs::SECCR_LOCK;
        self.nscr = regs::NSCR_LOCK | regs::NSCR_OPTLOCK;
        self.secsr = 0;
        self.nssr = 0;
        self.busy_polls = 0;
        self.cr_key_step = 0;
        self.opt_key_step = 0;
        self.obl_launched = false;
    }

    /// Stable raw pointers to both physical stores plus the per-store byte span.
    ///
    /// Used only by the shared-handle integration test double to return the
    /// `FlashSeam::inactive_bank` borrow, the host analogue of memory-mapped
    /// flash. The pointers are stable for the model's life and the caller clamps
    /// any range inside `span`. The double consults the effective SWAP_BANK to
    /// pick which store an alias borrow resolves to.
    pub(crate) fn store_ptrs(&self) -> (*const u8, *const u8, usize)
    {
        (self.bank_a.as_ptr(), self.bank_b.as_ptr(), BANK_BYTES)
    }

    /// The effective SWAP_BANK bit, exposed so the shared-handle double resolves
    /// an alias borrow to the right physical store.
    pub(crate) fn swap_bank(&self) -> bool
    {
        regs::swap_bank_set(self.optr)
    }

    /// Borrows the physical bank store for the given physical bank flag.
    fn store(&self, bank2: bool) -> &[u8; BANK_BYTES]
    {
        if bank2
        {
            &self.bank_b
        }
        else
        {
            &self.bank_a
        }
    }

    /// Mutably borrows the physical bank store for the given physical bank flag.
    fn store_mut(&mut self, bank2: bool) -> &mut [u8; BANK_BYTES]
    {
        if bank2
        {
            &mut self.bank_b
        }
        else
        {
            &mut self.bank_a
        }
    }

    /// Resolves an absolute alias address to a physical store and byte index.
    ///
    /// RM0456 sec 7.5.8: the low alias resolves to physical Bank 1 when SWAP_BANK
    /// is clear and to physical Bank 2 when set, and the high alias is the
    /// inverse. This is the model behaviour that makes the B1 fault class
    /// observable: a fixed alias address points at different physical bytes
    /// depending on the swap.
    fn resolve(&self, addr: u32) -> Option<Resolved>
    {
        let swap = self.swap_bank();
        let low_off = addr.checked_sub(regs::LOW_ALIAS_BASE);
        if let Some(off) = low_off
            && (off as usize) < BANK_BYTES
        {
            // The low alias holds physical Bank 1 unless SWAP_BANK is set.
            return Some(Resolved
            {
                bank2: swap,
                index: off as usize,
            });
        }
        let high_off = addr.checked_sub(regs::HIGH_ALIAS_BASE)?;
        if (high_off as usize) < BANK_BYTES
        {
            // The high alias holds physical Bank 2 unless SWAP_BANK is set.
            return Some(Resolved
            {
                bank2: !swap,
                index: high_off as usize,
            });
        }
        None
    }

    /// True when `addr` falls inside either mapped bank alias.
    fn is_flash(&self, addr: u32) -> bool
    {
        self.resolve(addr).is_some()
    }

    /// Programs one 32-bit word, clearing bits only and raising the right flag.
    ///
    /// RM0456 sec 7.3.1 / 7.3.7: program clears bits (`new = old AND value`). A
    /// reprogram of a word that is not fully erased raises PROGERR. A write to a
    /// WRP page raises WRPERR. The op then sets BSY busy for a few polls and
    /// raises EOP on completion.
    fn program_word(&mut self, addr: u32, value: u32)
    {
        if addr & 0x3 != 0
        {
            self.secsr |= regs::SR_PGAERR;
            return;
        }
        let resolved = match self.resolve(addr)
        {
            Some(resolved) => resolved,
            None =>
            {
                self.secsr |= regs::SR_PGAERR;
                return;
            }
        };
        if self.wrp_hit(resolved.bank2, resolved.index)
        {
            self.secsr |= regs::SR_WRPERR;
            return;
        }
        let store = self.store_mut(resolved.bank2);
        let slot = match store.get_mut(resolved.index..resolved.index + 4)
        {
            Some(slot) => slot,
            None =>
            {
                self.secsr |= regs::SR_PGAERR;
                return;
            }
        };
        let mut current = [0u8; 4];
        current.copy_from_slice(slot);
        let old = u32::from_le_bytes(current);
        // RM0456 sec 7.3.7: PROGERR is set when the word to program is not
        // previously erased, EXCEPT when the value written is all-zero. So a
        // reprogram of a non-erased word with any non-zero value fails closed.
        if old != regs::ERASED_WORD && value != 0
        {
            self.secsr |= regs::SR_PROGERR;
            return;
        }
        let programmed = (old & value).to_le_bytes();
        slot.copy_from_slice(&programmed);
        self.start_busy();
    }

    /// True when a physical `(bank2, page)` coordinate is write-protected.
    fn wrp_hit(&self, bank2: bool, index: usize) -> bool
    {
        let page = (index as u32) / regs::PAGE_SIZE;
        self.wrp_page == Some((bank2, page))
    }

    /// Erases the page selected by the live SECCR (PER plus BKER plus PNB).
    ///
    /// RM0456 sec 7.3.6: the page erase sets every byte of the selected 8 KB
    /// PHYSICAL page to 0xFF. BKER names the physical bank directly, with no
    /// SWAP_BANK correction (RM0456 sec 7.5.8). A WRP page raises WRPERR instead.
    fn erase_selected_page(&mut self)
    {
        let pnb = (self.seccr & regs::SECCR_PNB_MASK) >> regs::SECCR_PNB_SHIFT;
        let bank2 = self.seccr & regs::SECCR_BKER != 0;
        if pnb >= regs::PAGES_PER_BANK
        {
            self.secsr |= regs::SR_PGSERR;
            return;
        }
        if self.wrp_page == Some((bank2, pnb))
        {
            self.secsr |= regs::SR_WRPERR;
            return;
        }
        let start = (pnb * regs::PAGE_SIZE) as usize;
        let end = start + regs::PAGE_SIZE as usize;
        let store = self.store_mut(bank2);
        if let Some(slot) = store.get_mut(start..end)
        {
            for byte in slot.iter_mut()
            {
                *byte = regs::ERASED_BYTE;
            }
            self.start_busy();
        }
        else
        {
            self.secsr |= regs::SR_PGSERR;
        }
    }

    /// Sets BSY busy for a few polls and raises EOP, modelling op completion.
    fn start_busy(&mut self)
    {
        self.busy_polls = BUSY_POLLS;
        self.secsr |= regs::SR_BSY;
        self.secsr |= regs::SR_EOP;
    }

    /// Reads SECSR, stepping the BSY busy countdown down on each read.
    fn read_secsr(&mut self) -> u32
    {
        let value = self.secsr;
        if self.busy_polls > 0
        {
            self.busy_polls -= 1;
            if self.busy_polls == 0
            {
                self.secsr &= !(regs::SR_BSY | regs::SR_WDW);
            }
        }
        value
    }

    /// Handles a write to a FLASH control / key register.
    fn write_register(&mut self, addr: u32, value: u32)
    {
        match addr
        {
            regs::FLASH_SECKEYR => self.write_seckeyr(value),
            regs::FLASH_OPTKEYR => self.write_optkeyr(value),
            regs::FLASH_SECSR => self.clear_secsr(value),
            regs::FLASH_NSSR => self.nssr &= !value,
            regs::FLASH_SECCR => self.write_seccr(value),
            regs::FLASH_NSCR => self.write_nscr(value),
            // An OPTR write lands in the program shadow, not the effective
            // register (RM0456 sec 7.4.2): the change takes effect only at the
            // modelled reset, so the running bank stays stable mid-update.
            regs::FLASH_OPTR => self.optr_shadow = value,
            _ => {}
        }
    }

    /// Processes the CR unlock key sequence (KEY1 then KEY2). RM0456 sec 7.3.5.
    fn write_seckeyr(&mut self, value: u32)
    {
        match (self.cr_key_step, value)
        {
            (0, v) if v == regs::FLASH_KEY1 => self.cr_key_step = 1,
            (1, v) if v == regs::FLASH_KEY2 =>
            {
                self.cr_key_step = 2;
                self.seccr &= !regs::SECCR_LOCK;
            }
            // A wrong value or order leaves the CR locked until reset.
            _ => self.cr_key_step = 0,
        }
    }

    /// Processes the option unlock key sequence (OPTKEY1 then OPTKEY2). RM0456
    /// sec 7.4.2. Requires the CR already unlocked, as on real silicon.
    fn write_optkeyr(&mut self, value: u32)
    {
        match (self.opt_key_step, value)
        {
            (0, v) if v == regs::FLASH_OPTKEY1 => self.opt_key_step = 1,
            (1, v) if v == regs::FLASH_OPTKEY2 =>
            {
                self.opt_key_step = 2;
                self.nscr &= !regs::NSCR_OPTLOCK;
            }
            _ => self.opt_key_step = 0,
        }
    }

    /// Clears the rc_w1 SECSR flags the write requests.
    fn clear_secsr(&mut self, value: u32)
    {
        // BSY / WDW are not rc_w1, the model clears them on its own countdown.
        let rc_w1 = value & !(regs::SR_BSY | regs::SR_WDW);
        self.secsr &= !rc_w1;
    }

    /// Applies a SECCR write, then triggers an erase if STRT just rose.
    fn write_seccr(&mut self, value: u32)
    {
        let strt_rising =
            value & regs::SECCR_STRT != 0 && self.seccr & regs::SECCR_STRT == 0;
        // A LOCK bit set re-locks the CR.
        if value & regs::SECCR_LOCK != 0
        {
            self.cr_key_step = 0;
        }
        self.seccr = value;
        if strt_rising && value & regs::SECCR_PER != 0
        {
            self.erase_selected_page();
            // STRT auto-clears once the op starts.
            self.seccr &= !regs::SECCR_STRT;
        }
    }

    /// Applies an NSCR write, staging a swap on OPTSTRT and recording an
    /// OBL_LAUNCH as the inert reset stand-in.
    fn write_nscr(&mut self, value: u32)
    {
        if value & regs::NSCR_OPTLOCK != 0
        {
            self.opt_key_step = 0;
        }
        let optstrt_rising = value & regs::NSCR_OPTSTRT != 0
            && self.nscr & regs::NSCR_OPTSTRT == 0;
        let obl_rising = value & regs::NSCR_OBL_LAUNCH != 0
            && self.nscr & regs::NSCR_OBL_LAUNCH == 0;
        self.nscr = value;
        if optstrt_rising
        {
            if self.nscr & regs::NSCR_OPTLOCK != 0
            {
                // Options still locked: the option program is rejected, OPTWERR.
                self.nssr |= regs::SR_OPTWERR;
            }
            else
            {
                // Stage the option load. SWAP_BANK in the OPTR shadow is the
                // requested state, applied only at the modelled reset.
                self.staged_swap =
                    Some(regs::swap_bank_set(self.optr_shadow));
                self.start_busy();
            }
            self.nscr &= !regs::NSCR_OPTSTRT;
        }
        if obl_rising
        {
            // OBL_LAUNCH resets the part and applies the option load on real
            // silicon. The model records it WITHOUT resetting, so no test ever
            // performs a real option load. The staged swap is applied only by an
            // explicit apply_reset, never here.
            self.obl_launched = true;
            self.nscr &= !regs::NSCR_OBL_LAUNCH;
        }
    }

    /// Reads a 32-bit word from the resolved physical store, or 0 out of range.
    fn read_flash_word(&self, addr: u32) -> u32
    {
        match self.resolve(addr)
        {
            Some(resolved) =>
            {
                let store = self.store(resolved.bank2);
                match store.get(resolved.index..resolved.index + 4)
                {
                    Some(slot) =>
                    {
                        let mut bytes = [0u8; 4];
                        bytes.copy_from_slice(slot);
                        u32::from_le_bytes(bytes)
                    }
                    None => 0,
                }
            }
            None => 0,
        }
    }
}

/// Builds a heap-allocated, fully-erased 256 KB bank store.
fn erased_bank() -> Box<[u8; BANK_BYTES]>
{
    let boxed: Box<[u8]> = vec![regs::ERASED_BYTE; BANK_BYTES].into_boxed_slice();
    boxed
        .try_into()
        .expect("bank store boxes to a fixed-size array")
}

impl FlashAccess for FlashModel
{
    fn read32(&mut self, addr: u32) -> u32
    {
        match addr
        {
            regs::FLASH_SECSR => self.read_secsr(),
            regs::FLASH_NSSR => self.nssr,
            regs::FLASH_SECCR => self.seccr,
            regs::FLASH_NSCR => self.nscr,
            regs::FLASH_OPTR => self.optr,
            other if self.is_flash(other) => self.read_flash_word(other),
            _ => 0,
        }
    }

    fn write32(&mut self, addr: u32, value: u32)
    {
        if self.is_flash(addr)
        {
            // A word write to a flash address programs only while PG is set,
            // otherwise it is ignored (a real flash address is read-only without
            // an armed program, RM0456 sec 7.3.7).
            if self.seccr & regs::SECCR_PG != 0
            {
                self.program_word(addr, value);
            }
            return;
        }
        self.write_register(addr, value);
    }

    fn peek32(&self, addr: u32) -> u32
    {
        if self.is_flash(addr)
        {
            return self.read_flash_word(addr);
        }
        match addr
        {
            regs::FLASH_OPTR => self.optr,
            _ => 0,
        }
    }

    fn bank_view(&self, base: u32, len: usize) -> &[u8]
    {
        match self.resolve(base)
        {
            Some(resolved) => self
                .store(resolved.bank2)
                .get(resolved.index..resolved.index + len)
                .unwrap_or(&[]),
            None => &[],
        }
    }
}
