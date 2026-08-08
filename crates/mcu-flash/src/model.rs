//! A faithful host model of the STM32U545 FLASH controller, for host tests.
//!
//! This implements [`FlashAccess`] by modelling the real controller state, not a
//! per-address value queue: a stateful peripheral needs a model of the hardware
//! state, or a silicon-only fault hides behind a green host test. It models:
//!   - two physically separate bank stores (`bank_a` = physical Bank 1, `bank_b`
//!     = physical Bank 2), each 256 KB, where a program clears bits only
//!     (`new = old AND data`) and an erase sets 0xFF (RM0456 sec 7.3.1),
//!   - the address-to-store mapping that flips with the effective SWAP_BANK
//!     (RM0456 sec 7.5.8): when SWAP_BANK is clear the low alias resolves to
//!     physical Bank 1 and the high alias to Bank 2, and the reverse when set. So
//!     a fixed virtual address resolves to different physical bytes before and
//!     after a swap, the fault class a flat one-store model could not observe,
//!   - the SECWM page security label and the per-alias access rules (RM0456
//!     Table 68): each page carries a label (pages 0..=`SECWM_PEND` secure, the
//!     rest non-secure), and a secure-alias (0x0C..) access to a non-secure page
//!     is RAZ on read and Write-Ignored plus WRPERR on program / erase, while a
//!     non-secure-alias (0x08..) access to a secure page is the same. This is the
//!     TRAP-4 fault: reading the inactive bank's non-secure image pages through
//!     the secure alias silently returns zeros. The model makes a wrong-alias
//!     read fail, which is the whole reason the model exists,
//!   - both controller register banks (SEC* and NS*): the secure image sub-band
//!     is driven through SECKEYR / SECSR / SECCR, the non-secure image sub-band
//!     through NSKEYR / NSSR / NSCR (RM0456 sec 7.9.9 / 7.9.10). The BSY / WDW
//!     handshake and the rc_w1 error flags are mirrored across both status
//!     registers (RM0456 sec 7.3.5),
//!   - the CR / option unlock key sequences (a wrong value or order leaves the
//!     register locked, RM0456 sec 7.3.5 / 7.4.2),
//!   - the staged SWAP_BANK option load, applied only at a modelled reset
//!     ([`FlashModel::apply_reset`]), never on the OBL_LAUNCH write itself. This
//!     is what keeps the brick-class path inert on the host: the model stages
//!     the swap instead of resetting, so no test ever performs a real option
//!     load (RM0456 sec 7.5.8).
//!
//! The model is the test double the integration test drives the real driver over, so
//! the driver's exact unlock to program to poll to lock sequencing and its
//! page-to-address math run against faithful silicon behaviour.

#![cfg(test)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec;

use crate::bus::FlashAccess;
use crate::regs;

/// One physical bank store size in bytes (256 KB).
const BANK_BYTES: usize = regs::BANK_SIZE as usize;

/// Which physical bank store an address resolves to, the byte index inside that
/// store, and the SECURITY VIEW of the alias the address came through.
struct Resolved
{
    /// True when the alias is a SECURE alias (0x0C..), false for the non-secure
    /// alias (0x08..). This is the access view Table 68 checks against the page
    /// label.
    alias_secure: bool,
    /// True when the address resolves to physical Bank 2 (`bank_b`).
    bank2: bool,
    /// The byte index inside the resolved bank store.
    index: usize,
}

/// How many BSY polls each program / erase stays busy before completing.
///
/// A small non-zero value exercises the driver's BSY poll loop without slowing
/// the tests. The op completes on the triggering write, then BSY reads busy for
/// this many status-register reads, then clears.
const BUSY_POLLS: u32 = 2;

/// The poison byte a torn image quad-word reads back as.
///
/// A torn quad-word write leaves contents not guaranteed (RM0456 sec 7.3.11) and
/// a real readback raises a double-bit ECC fault (RM0456 sec 7.3.2). The seam has
/// no fault path on the byte slice, so the model writes this poison value, which
/// the verifier rejects, so the old bank boots.
const POISON_BYTE: u8 = 0xA5;

/// Where a single modelled power cut lands relative to a persistent mutation.
///
/// The register-level power-fault harness arms a countdown over the persistent
/// flash operations the driver issues (a quad-word program, a page erase, an
/// option-byte stage). When the countdown reaches the armed op the mode decides
/// what the cut does. This drives the real driver code over the modelled
/// registers, the gap the retired seam-level fw-update harness could not close.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CutMode
{
    /// Power dies before the mutation lands. The op faults, the store unchanged.
    BeforeMutation,
    /// Power dies after the mutation lands. The op completes, then the next
    /// persistent op faults (the machine never runs past the cut).
    AfterMutation,
    /// A program tears mid quad-word. For an image quad-word the target is
    /// poisoned so the bank fails verify on readback (RM0456 sec 7.3.11 / 7.3.2),
    /// then the op faults. A page erase, an option stage, and a single-word
    /// metadata record have no partial quad-word, so this degrades to
    /// [`CutMode::BeforeMutation`] there, matching the real flash granularity.
    TornWrite,
}

/// The plan the four word-writes of one quad-word share, so one cut decision
/// made on the first word governs the whole quad-word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QwPlan
{
    /// Program every word of the quad-word normally.
    Proceed,
    /// Program every word, then die once the quad-word completes (After).
    ProgramThenDie,
    /// Suppress every word of the quad-word (dead silicon, or a torn tail).
    Suppress,
}

/// What one word-write of a quad-word program must do under the armed cut.
enum WordStep
{
    /// Program the word normally.
    Program,
    /// Suppress the word (no store change).
    Suppress,
    /// Fault before the word lands: raise PROGERR, leave the store unchanged.
    FaultBefore,
    /// Tear the quad-word: poison it to detectable corruption, raise PROGERR.
    Tear,
}

/// What one atomic persistent op (a page erase or an option stage) must do under
/// the armed cut. These ops have no partial quad-word, so a tear degrades to a
/// fault.
enum SimpleStep
{
    /// Perform the op normally.
    Proceed,
    /// Suppress the op (dead silicon, no store change).
    Suppress,
    /// Fault: leave the persistent state unchanged.
    Fault,
    /// Perform the op, then die (the next persistent op faults).
    MutateThenDie,
}

/// True when the bank-relative byte `index` falls in a SECURE page.
///
/// RM0456 sec 7.9.17 / 7.9.21: pages 0..=`SECWM_PEND` are secure, the rest are
/// non-secure. Both banks carry the identical layout, so the label is a pure
/// function of the byte index inside a bank store. Routes through
/// [`regs::page_band`] so the SECWM boundary has a single source of truth.
fn page_label_secure(index: usize) -> bool
{
    let page = (index as u32) / regs::PAGE_SIZE;
    matches!(regs::page_band(page), regs::PageBand::Secure)
}

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
    /// An all-zero buffer the size of a bank store, returned by a wrong-alias
    /// band read to model RAZ (RM0456 Table 68). It is never written.
    zeros: Box<[u8; BANK_BYTES]>,
    /// The live SECCR control value (LOCK, PG, PER, PNB, BKER, STRT).
    seccr: u32,
    /// The live SECSR status value (BSY, WDW, error flags).
    secsr: u32,
    /// The live NSSR status value (BSY, WDW, error flags, option-write error).
    nssr: u32,
    /// The live NSCR control value (LOCK, PG, PER, PNB, BKER, STRT, plus the
    /// option-byte bits OPTLOCK, OPTSTRT, OBL_LAUNCH).
    nscr: u32,
    /// The effective OPTR option value the running system sees (SWAP_BANK,
    /// DUALBANK, TZEN, RDP). A read of FLASH_OPTR returns this. The effective
    /// SWAP_BANK changes only at a modelled reset, never on the option-program
    /// write itself, so the running bank stays stable mid-update. The effective
    /// SWAP_BANK also drives address resolution, so a swap actually remaps which
    /// physical store an alias address hits.
    optr: u32,
    /// The OPTR program shadow: where an OPTR register write lands.
    ///
    /// RM0456 sec 7.4.2: writing OPTR then setting OPTSTRT programs the option
    /// bytes, but the SWAP_BANK change only takes effect at the option reload
    /// (the OBL_LAUNCH reset). So the driver's OPTR write updates this shadow,
    /// OPTSTRT stages the shadow's SWAP_BANK, and the modelled reset applies it
    /// into the effective `optr`. This keeps the brick-class swap inert.
    optr_shadow: u32,
    /// Remaining BSY busy polls before the in-flight op reports ready.
    busy_polls: u32,
    /// Secure CR unlock progress: 0 locked, 1 saw KEY1, 2 unlocked.
    cr_key_step: u8,
    /// Non-secure CR unlock progress: 0 locked, 1 saw KEY1, 2 unlocked.
    ns_cr_key_step: u8,
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
    /// The remaining persistent-op countdown until an armed power cut fires.
    ///
    /// `None` means no cut is armed, so the model behaves like clean silicon. A
    /// cut walks every persistent flash op of the whole flow and survives a
    /// modelled reset (a reset clears only the volatile state), so it can fire in
    /// the post-reset confirm or revert path.
    cut_countdown: Option<u32>,
    /// The mode the armed cut fires in.
    cut_mode: CutMode,
    /// Set once a cut has fired: every later persistent op is suppressed, because
    /// on real hardware the CPU is dead until the next reset (the reboot).
    cut_dead: bool,
    /// True once a cut fired anywhere in the current power cycle (test census).
    cut_fired: bool,
    /// The total persistent flash ops observed, so the harness can measure a
    /// flow's length and enumerate a per-index census.
    persistent_ops: u32,
    /// The plan shared by the four word-writes of the quad-word being programmed.
    qw_plan: Option<(u32, QwPlan)>,
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
            zeros: zero_bank(),
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
            ns_cr_key_step: 0,
            opt_key_step: 0,
            staged_swap: None,
            obl_launched: false,
            wrp_page: None,
            cut_countdown: None,
            cut_mode: CutMode::BeforeMutation,
            cut_dead: false,
            cut_fired: false,
            persistent_ops: 0,
            qw_plan: None,
        }
    }

    /// Arms a single power cut at the `index`-th persistent flash op, in `mode`.
    ///
    /// `index` counts persistent flash ops (quad-word programs, page erases, and
    /// option stages) from zero, over the WHOLE flow across the reset boundary.
    /// The cut fires at most once.
    pub(crate) fn arm_cut(&mut self, index: u32, mode: CutMode)
    {
        self.cut_countdown = Some(index);
        self.cut_mode = mode;
        self.cut_dead = false;
        self.cut_fired = false;
    }

    /// True once the armed cut fired anywhere in this power cycle.
    pub(crate) fn cut_fired(&self) -> bool
    {
        self.cut_fired
    }

    /// The total persistent flash ops observed so far (flow-length measurement).
    pub(crate) fn persistent_ops(&self) -> u32
    {
        self.persistent_ops
    }

    /// Models a reboot where the staged option load did not commit.
    ///
    /// A power cut before the OBL_LAUNCH option reload keeps the old option bytes
    /// (RM0456 sec 7.5.8), so the staged swap is lost and the old bank boots. Like
    /// [`FlashModel::apply_reset`] it clears the volatile controller state and the
    /// dead flag, but it does not apply the swap. The armed cut countdown rides
    /// across, so a cut can still fire after this reboot.
    pub(crate) fn reboot_without_option_load(&mut self)
    {
        self.staged_swap = None;
        self.reset_volatile();
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
    /// clears the stage (RM0456 sec 7.5.8). After this the same alias address
    /// resolves to the other physical store. A power cut before this keeps the
    /// old OPTR, so the harness only calls this to model a clean reset boundary.
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
        self.reset_volatile();
    }

    /// Clears the volatile controller state a reset restores, preserving the
    /// non-volatile stores and any armed cut countdown.
    ///
    /// A reset re-locks both CRs and the options, clears the volatile status, and
    /// clears the dead flag (the CPU runs again on fresh silicon after a reset).
    /// It never touches the two bank stores, the metadata, or the armed cut
    /// countdown, which survive the reset just like real non-volatile flash.
    fn reset_volatile(&mut self)
    {
        self.seccr = regs::SECCR_LOCK;
        self.nscr = regs::NSCR_LOCK | regs::NSCR_OPTLOCK;
        self.secsr = 0;
        self.nssr = 0;
        self.busy_polls = 0;
        self.cr_key_step = 0;
        self.ns_cr_key_step = 0;
        self.opt_key_step = 0;
        self.obl_launched = false;
        self.cut_dead = false;
        self.qw_plan = None;
    }

    /// Steps the cut countdown for one ATOMIC persistent op (erase or stage).
    ///
    /// An erase or an option stage has no partial quad-word, so a torn write
    /// degrades to a plain fault (RM0456 sec 7.3.6 / 7.4.2, page / option
    /// granularity).
    fn cut_step_simple(&mut self) -> SimpleStep
    {
        if self.cut_dead
        {
            return SimpleStep::Suppress;
        }
        self.persistent_ops = self.persistent_ops.saturating_add(1);
        match self.cut_countdown
        {
            Some(0) =>
            {
                self.cut_fired = true;
                self.cut_countdown = None;
                self.cut_dead = true;
                match self.cut_mode
                {
                    CutMode::AfterMutation => SimpleStep::MutateThenDie,
                    // An erase or an option stage has no partial quad-word, so a
                    // torn write degrades to a plain fault with the record left
                    // unchanged. This is the same fail-closed floor documented at
                    // the metadata program point (a torn erase or option record
                    // reads back as the old value or a safe default). The upward
                    // bit-superset / ECC-fault residual noted there applies to any
                    // torn record and is handled OUTSIDE this content model.
                    CutMode::BeforeMutation | CutMode::TornWrite => SimpleStep::Fault,
                }
            }
            Some(n) =>
            {
                self.cut_countdown = Some(n - 1);
                SimpleStep::Proceed
            }
            None => SimpleStep::Proceed,
        }
    }

    /// Steps the cut countdown for one word-write of a quad-word program.
    ///
    /// The tick fires on the quad-word's first word, and the four words share one
    /// [`QwPlan`] so the decision is made once. `image_qw` is true when the target
    /// lies in the A/B image band, the only place a torn quad-word poisons into
    /// detectable corruption.
    fn cut_step_word(&mut self, addr: u32, image_qw: bool) -> WordStep
    {
        let qw_base = addr & !(regs::QUAD_WORD_LEN - 1);
        let last_word = qw_base + (regs::QUAD_WORD_LEN - 4);
        if !addr.is_multiple_of(regs::QUAD_WORD_LEN)
        {
            // A continuation word: follow the plan set on the first word.
            return match self.qw_plan
            {
                Some((base, QwPlan::Proceed)) if base == qw_base => WordStep::Program,
                Some((base, QwPlan::ProgramThenDie)) if base == qw_base =>
                {
                    if addr == last_word
                    {
                        // The quad-word has fully landed, so the machine dies now.
                        self.cut_dead = true;
                    }
                    WordStep::Program
                }
                Some((base, QwPlan::Suppress)) if base == qw_base => WordStep::Suppress,
                _ => WordStep::Program,
            };
        }
        // The first word of a quad-word: the tick point.
        if self.cut_dead
        {
            self.qw_plan = Some((qw_base, QwPlan::Suppress));
            return WordStep::Suppress;
        }
        self.persistent_ops = self.persistent_ops.saturating_add(1);
        match self.cut_countdown
        {
            Some(0) =>
            {
                self.cut_fired = true;
                self.cut_countdown = None;
                match self.cut_mode
                {
                    CutMode::BeforeMutation =>
                    {
                        self.cut_dead = true;
                        self.qw_plan = Some((qw_base, QwPlan::Suppress));
                        WordStep::FaultBefore
                    }
                    CutMode::AfterMutation =>
                    {
                        // Program the whole quad-word, then die on its last word.
                        self.qw_plan = Some((qw_base, QwPlan::ProgramThenDie));
                        WordStep::Program
                    }
                    CutMode::TornWrite =>
                    {
                        self.cut_dead = true;
                        self.qw_plan = Some((qw_base, QwPlan::Suppress));
                        if image_qw
                        {
                            WordStep::Tear
                        }
                        else
                        {
                            // No image quad-word to tear, so degrade to a fault.
                            WordStep::FaultBefore
                        }
                    }
                }
            }
            Some(n) =>
            {
                self.cut_countdown = Some(n - 1);
                self.qw_plan = Some((qw_base, QwPlan::Proceed));
                WordStep::Program
            }
            None =>
            {
                self.qw_plan = Some((qw_base, QwPlan::Proceed));
                WordStep::Program
            }
        }
    }

    /// Poisons the whole quad-word containing bank-relative `index` in a store.
    fn poison_quad_word(&mut self, bank2: bool, index: usize)
    {
        let qw = index - (index % regs::QUAD_WORD_LEN as usize);
        let end = core::cmp::min(qw + regs::QUAD_WORD_LEN as usize, BANK_BYTES);
        let store = self.store_mut(bank2);
        if let Some(slot) = store.get_mut(qw..end)
        {
            for byte in slot.iter_mut()
            {
                *byte = POISON_BYTE;
            }
        }
    }

    /// Resolves a band read to a stable pointer plus a clamped byte range,
    /// modelling RAZ.
    ///
    /// Returns `(ptr, start, end)` where `ptr` is the resolved PHYSICAL store
    /// when the alias view matches the page label, or the all-zero RAZ buffer
    /// when it does not (RM0456 Table 68). A band is homogeneous (every page in
    /// it shares one label), so the base page's label decides the whole read.
    /// Used by the shared-handle integration double to return the
    /// `FlashSeam::inactive_secure_band` / `inactive_ns_band` borrow, the host
    /// analogue of memory-mapped flash. The pointers are stable for the model's
    /// life and the caller consumes the slice before touching another handle.
    pub(crate) fn band_ptr(&self, base: u32, len: usize) -> Option<(*const u8, usize, usize)>
    {
        let resolved = self.resolve(base)?;
        let end = core::cmp::min(resolved.index + len, BANK_BYTES);
        let start = core::cmp::min(resolved.index, end);
        let ptr = if resolved.alias_secure == page_label_secure(resolved.index)
        {
            self.store(resolved.bank2).as_ptr()
        }
        else
        {
            self.zeros.as_ptr()
        };
        Some((ptr, start, end))
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

    /// Resolves an absolute alias address to a physical store, byte index, and
    /// the alias security view.
    ///
    /// RM0456 sec 7.5.8: the low alias resolves to physical Bank 1 when SWAP_BANK
    /// is clear and to physical Bank 2 when set, and the high alias is the
    /// inverse. RM0456 sec 2.3 / AN5347 Table 2: the secure alias sits at 0x0C..
    /// and the non-secure alias at 0x08.., a fixed offset apart, addressing the
    /// same physical bytes with different security views. Modelling both is what
    /// makes the B1 swap fault and the Table-68 wrong-alias fault observable.
    fn resolve(&self, addr: u32) -> Option<Resolved>
    {
        let swap = self.swap_bank();
        // Secure low alias -> physical Bank 1 unless SWAP_BANK is set.
        if let Some(off) = addr.checked_sub(regs::LOW_ALIAS_BASE)
            && (off as usize) < BANK_BYTES
        {
            return Some(Resolved
            {
                alias_secure: true,
                bank2: swap,
                index: off as usize,
            });
        }
        // Secure high alias -> physical Bank 2 unless SWAP_BANK is set.
        if let Some(off) = addr.checked_sub(regs::HIGH_ALIAS_BASE)
            && (off as usize) < BANK_BYTES
        {
            return Some(Resolved
            {
                alias_secure: true,
                bank2: !swap,
                index: off as usize,
            });
        }
        // Non-secure low alias -> the same physical store as the secure low
        // alias, viewed non-secure.
        if let Some(off) = addr.checked_sub(regs::NS_LOW_ALIAS_BASE)
            && (off as usize) < BANK_BYTES
        {
            return Some(Resolved
            {
                alias_secure: false,
                bank2: swap,
                index: off as usize,
            });
        }
        // Non-secure high alias -> the same physical store as the secure high
        // alias, viewed non-secure.
        if let Some(off) = addr.checked_sub(regs::NS_HIGH_ALIAS_BASE)
            && (off as usize) < BANK_BYTES
        {
            return Some(Resolved
            {
                alias_secure: false,
                bank2: !swap,
                index: off as usize,
            });
        }
        None
    }

    /// True when `addr` falls inside any mapped bank alias (secure or NS).
    fn is_flash(&self, addr: u32) -> bool
    {
        self.resolve(addr).is_some()
    }

    /// Raises a controller error flag on the status register matching the access
    /// view (secure -> SECSR, non-secure -> NSSR). RM0456 sec 7.9.7 / 7.9.8.
    fn set_error(&mut self, via_secure: bool, flag: u32)
    {
        if via_secure
        {
            self.secsr |= flag;
        }
        else
        {
            self.nssr |= flag;
        }
    }

    /// Programs one 32-bit word, clearing bits only and raising the right flag.
    ///
    /// RM0456 sec 7.3.1 / 7.3.7: program clears bits (`new = old AND value`). A
    /// reprogram of a word that is not fully erased raises PROGERR. RM0456 Table
    /// 68: a cross-label access (a secure-alias write to a non-secure page or the
    /// reverse) is Write-Ignored and raises WRPERR on the accessing controller.
    /// A write to a WRP page raises WRPERR. The op then sets BSY busy for a few
    /// polls and raises EOP on completion.
    fn program_word(&mut self, addr: u32, value: u32)
    {
        let resolved = match self.resolve(addr)
        {
            Some(resolved) => resolved,
            // A non-flash address never reaches here (the caller gates on
            // is_flash), so treat it as a sequence error defensively.
            None => return,
        };
        let via_secure = resolved.alias_secure;
        if addr & 0x3 != 0
        {
            self.set_error(via_secure, regs::SR_PGAERR);
            return;
        }
        // Table 68: the alias view must match the page label, or the write is
        // ignored and WRPERR is raised on the accessing controller. This is the
        // fault a wrong-controller program would trip.
        if via_secure != page_label_secure(resolved.index)
        {
            self.set_error(via_secure, regs::SR_WRPERR);
            return;
        }
        if self.wrp_hit(resolved.bank2, resolved.index)
        {
            self.set_error(via_secure, regs::SR_WRPERR);
            return;
        }
        let old = {
            let store = self.store(resolved.bank2);
            match store.get(resolved.index..resolved.index + 4)
            {
                Some(slot) =>
                {
                    let mut current = [0u8; 4];
                    current.copy_from_slice(slot);
                    u32::from_le_bytes(current)
                }
                None =>
                {
                    self.set_error(via_secure, regs::SR_PGAERR);
                    return;
                }
            }
        };
        // RM0456 sec 7.3.7: PROGERR is set when the word to program is not
        // previously erased, except when the value written is all-zero. So a
        // reprogram of a non-erased word with any non-zero value fails closed.
        if old != regs::ERASED_WORD && value != 0
        {
            self.set_error(via_secure, regs::SR_PROGERR);
            return;
        }
        // Only an image-band quad-word tears into detectable corruption. A torn
        // program of a metadata record (NVCNT log, pending) degrades to a plain
        // fault with the record left unchanged, this model's fail-closed floor: a
        // torn metadata or option record reads back as the old value or a safe
        // default, and the record constants are chosen non-bit-superset, so a torn
        // program (which only clears bits, RM0456 sec 7.3.7) can never flip one valid
        // record into another valid record.
        //
        // Residual not modelled here: on real silicon a torn NVCNT quad-word can read
        // back as a high bit-superset value, poisoning the monotone floor upward, or
        // raise a double-bit ECC fault on the next read. That is an availability /
        // brick-adjacent risk that lives in the ECC-fault-handling layer, outside this
        // content model, and must be handled there. This model covers only the content
        // a successful read returns, not the ECC fault a torn ECC quad-word can raise.
        let image_qw = resolved.index >= regs::IMAGE_REGION_OFFSET as usize;
        match self.cut_step_word(addr, image_qw)
        {
            WordStep::Program =>
            {
                let programmed = (old & value).to_le_bytes();
                if let Some(slot) =
                    self.store_mut(resolved.bank2).get_mut(resolved.index..resolved.index + 4)
                {
                    slot.copy_from_slice(&programmed);
                }
                self.start_busy(via_secure);
            }
            // A dead or suppressed word never lands, and never faults: the machine
            // simply did not run this write on real hardware.
            WordStep::Suppress =>
            {}
            // A power cut before this word lands fails the op closed (PROGERR).
            WordStep::FaultBefore =>
            {
                self.set_error(via_secure, regs::SR_PROGERR);
            }
            // A torn image quad-word reads back as detectable corruption, then the
            // op fails closed (PROGERR).
            WordStep::Tear =>
            {
                self.poison_quad_word(resolved.bank2, resolved.index);
                self.set_error(via_secure, regs::SR_PROGERR);
            }
        }
    }

    /// True when a physical `(bank2, page)` coordinate is write-protected.
    fn wrp_hit(&self, bank2: bool, index: usize) -> bool
    {
        let page = (index as u32) / regs::PAGE_SIZE;
        self.wrp_page == Some((bank2, page))
    }

    /// Erases the page selected by a control register (PER plus BKER plus PNB).
    ///
    /// RM0456 sec 7.3.6: the page erase sets every byte of the selected 8 KB
    /// PHYSICAL page to 0xFF. BKER names the physical bank directly, with no
    /// SWAP_BANK correction (RM0456 sec 7.5.8). RM0456 Table 68: a cross-label
    /// erase (the secure controller erasing a non-secure page or the reverse) is
    /// ignored and raises WRPERR on the accessing controller. A WRP page raises
    /// WRPERR too. `via_secure` is the controller: true for SEC*, false for NS*.
    fn erase_page_from_cr(&mut self, via_secure: bool, cr_value: u32)
    {
        let pnb = (cr_value & regs::SECCR_PNB_MASK) >> regs::SECCR_PNB_SHIFT;
        let bank2 = cr_value & regs::SECCR_BKER != 0;
        if pnb >= regs::PAGES_PER_BANK
        {
            self.set_error(via_secure, regs::SR_PGSERR);
            return;
        }
        // Table 68: the controller must match the page label, or the erase is
        // ignored and WRPERR is raised. Pages 0..=SECWM_PEND are secure.
        let label_secure = pnb <= regs::SECWM_PEND;
        if via_secure != label_secure
        {
            self.set_error(via_secure, regs::SR_WRPERR);
            return;
        }
        if self.wrp_page == Some((bank2, pnb))
        {
            self.set_error(via_secure, regs::SR_WRPERR);
            return;
        }
        // This erase would take effect, so it is a persistent op the cut walks.
        match self.cut_step_simple()
        {
            SimpleStep::Proceed | SimpleStep::MutateThenDie =>
            {
                let start = (pnb * regs::PAGE_SIZE) as usize;
                let end = start + regs::PAGE_SIZE as usize;
                let store = self.store_mut(bank2);
                if let Some(slot) = store.get_mut(start..end)
                {
                    for byte in slot.iter_mut()
                    {
                        *byte = regs::ERASED_BYTE;
                    }
                    self.start_busy(via_secure);
                }
                else
                {
                    self.set_error(via_secure, regs::SR_PGSERR);
                }
            }
            // A dead erase never runs, and never faults (the CPU is off).
            SimpleStep::Suppress =>
            {}
            // A power cut before the erase completes fails the op closed. An
            // interrupted erase leaves the page contents unchanged in the model,
            // which is the fail-closed floor for the metadata page.
            SimpleStep::Fault =>
            {
                self.set_error(via_secure, regs::SR_OPERR);
            }
        }
    }

    /// Sets BSY busy for a few polls and raises EOP, modelling op completion.
    ///
    /// BSY / WDW are mirrored in both status registers (RM0456 sec 7.3.5), so
    /// the busy flags are set in both SECSR and NSSR. EOP is set on the status
    /// register of the accessing controller, the one the driver polls.
    fn start_busy(&mut self, via_secure: bool)
    {
        self.busy_polls = BUSY_POLLS;
        self.secsr |= regs::SR_BSY;
        self.nssr |= regs::SR_BSY;
        if via_secure
        {
            self.secsr |= regs::SR_EOP;
        }
        else
        {
            self.nssr |= regs::SR_EOP;
        }
    }

    /// Steps the shared BSY busy countdown, clearing BSY / WDW in both status
    /// registers when it reaches zero. A single op is polled on exactly one
    /// status register, so one shared countdown is faithful.
    fn tick_busy(&mut self)
    {
        if self.busy_polls > 0
        {
            self.busy_polls -= 1;
            if self.busy_polls == 0
            {
                self.secsr &= !(regs::SR_BSY | regs::SR_WDW);
                self.nssr &= !(regs::SR_BSY | regs::SR_WDW);
            }
        }
    }

    /// Reads SECSR, stepping the BSY busy countdown down on each read.
    fn read_secsr(&mut self) -> u32
    {
        let value = self.secsr;
        self.tick_busy();
        value
    }

    /// Reads NSSR, stepping the BSY busy countdown down on each read.
    fn read_nssr(&mut self) -> u32
    {
        let value = self.nssr;
        self.tick_busy();
        value
    }

    /// Handles a write to a FLASH control / key register.
    fn write_register(&mut self, addr: u32, value: u32)
    {
        match addr
        {
            regs::FLASH_SECKEYR => self.write_seckeyr(value),
            regs::FLASH_NSKEYR => self.write_nskeyr(value),
            regs::FLASH_OPTKEYR => self.write_optkeyr(value),
            regs::FLASH_SECSR => self.clear_status(true, value),
            regs::FLASH_NSSR => self.clear_status(false, value),
            regs::FLASH_SECCR => self.write_seccr(value),
            regs::FLASH_NSCR => self.write_nscr(value),
            // An OPTR write lands in the program shadow, not the effective
            // register (RM0456 sec 7.4.2): the change takes effect only at the
            // modelled reset, so the running bank stays stable mid-update.
            regs::FLASH_OPTR => self.optr_shadow = value,
            _ =>
            {}
        }
    }

    /// Processes the secure CR unlock key sequence (KEY1 then KEY2). RM0456 sec
    /// 7.3.5.
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

    /// Processes the non-secure CR unlock key sequence (KEY1 then KEY2). RM0456
    /// sec 7.3.5: NSKEYR uses the same key pair as SECKEYR. FLASH_NSCR is RW from
    /// both states (RM0456 sec 7.9.9), so secure firmware may unlock it.
    fn write_nskeyr(&mut self, value: u32)
    {
        match (self.ns_cr_key_step, value)
        {
            (0, v) if v == regs::FLASH_KEY1 => self.ns_cr_key_step = 1,
            (1, v) if v == regs::FLASH_KEY2 =>
            {
                self.ns_cr_key_step = 2;
                self.nscr &= !regs::NSCR_LOCK;
            }
            _ => self.ns_cr_key_step = 0,
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

    /// Clears the rc_w1 flags a status-register write requests.
    ///
    /// BSY / WDW are not rc_w1, so they are preserved and cleared by the model's
    /// own busy countdown. `via_secure` picks SECSR or NSSR.
    fn clear_status(&mut self, via_secure: bool, value: u32)
    {
        let rc_w1 = value & !(regs::SR_BSY | regs::SR_WDW);
        if via_secure
        {
            self.secsr &= !rc_w1;
        }
        else
        {
            self.nssr &= !rc_w1;
        }
    }

    /// Applies a SECCR write, then triggers a secure-controller erase if STRT
    /// just rose with PER set.
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
            self.erase_page_from_cr(true, value);
            // STRT auto-clears once the op starts.
            self.seccr &= !regs::SECCR_STRT;
        }
    }

    /// Applies an NSCR write.
    ///
    /// NSCR shares the program / erase bits with SECCR (PG, PER, PNB, BKER, STRT,
    /// LOCK) and adds the option-byte bits (OPTLOCK, OPTSTRT, OBL_LAUNCH), RM0456
    /// sec 7.9.9. So this triggers a non-secure-controller erase on STRT rising
    /// with PER, stages a swap on OPTSTRT, and records an OBL_LAUNCH as the inert
    /// reset stand-in.
    fn write_nscr(&mut self, value: u32)
    {
        if value & regs::NSCR_LOCK != 0
        {
            self.ns_cr_key_step = 0;
        }
        if value & regs::NSCR_OPTLOCK != 0
        {
            self.opt_key_step = 0;
        }
        let strt_rising =
            value & regs::SECCR_STRT != 0 && self.nscr & regs::SECCR_STRT == 0;
        let optstrt_rising = value & regs::NSCR_OPTSTRT != 0
            && self.nscr & regs::NSCR_OPTSTRT == 0;
        let obl_rising = value & regs::NSCR_OBL_LAUNCH != 0
            && self.nscr & regs::NSCR_OBL_LAUNCH == 0;
        self.nscr = value;
        if strt_rising && value & regs::SECCR_PER != 0
        {
            self.erase_page_from_cr(false, value);
            self.nscr &= !regs::SECCR_STRT;
        }
        if optstrt_rising
        {
            if self.nscr & regs::NSCR_OPTLOCK != 0
            {
                // Options still locked: the option program is rejected, OPTWERR.
                self.nssr |= regs::SR_OPTWERR;
            }
            else
            {
                // The option stage is a persistent op the cut walks. On a fault
                // it raises OPTWERR, so arm_swap fails closed and never reaches
                // OBL_LAUNCH.
                match self.cut_step_simple()
                {
                    SimpleStep::Proceed | SimpleStep::MutateThenDie =>
                    {
                        // Stage the option load. SWAP_BANK in the OPTR shadow is
                        // the requested state, applied only at the modelled reset.
                        self.staged_swap =
                            Some(regs::swap_bank_set(self.optr_shadow));
                        self.start_busy(false);
                    }
                    SimpleStep::Suppress =>
                    {}
                    SimpleStep::Fault =>
                    {
                        self.nssr |= regs::SR_OPTWERR;
                    }
                }
            }
            self.nscr &= !regs::NSCR_OPTSTRT;
        }
        if obl_rising
        {
            // OBL_LAUNCH resets the part and applies the option load on real
            // silicon. The model records it without resetting, so no test ever
            // performs a real option load. The staged swap is applied only by an
            // explicit apply_reset, never here.
            self.obl_launched = true;
            self.nscr &= !regs::NSCR_OBL_LAUNCH;
        }
    }

    /// Reads a 32-bit word from the resolved physical store, modelling RAZ.
    ///
    /// RM0456 Table 68: a read whose alias view does not match the page label
    /// returns zero (Read-As-Zero), so a non-secure image page read through the
    /// secure alias is all zeros. A matching read returns the stored word.
    fn read_flash_word(&self, addr: u32) -> u32
    {
        match self.resolve(addr)
        {
            Some(resolved) =>
            {
                if resolved.alias_secure != page_label_secure(resolved.index)
                {
                    // Wrong alias for this page's label: RAZ.
                    return 0;
                }
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
    boxed_bank(regs::ERASED_BYTE)
}

/// Builds a heap-allocated, all-zero 256 KB buffer (the RAZ backing).
fn zero_bank() -> Box<[u8; BANK_BYTES]>
{
    boxed_bank(0)
}

/// Builds a heap-allocated 256 KB store filled with `fill`.
fn boxed_bank(fill: u8) -> Box<[u8; BANK_BYTES]>
{
    let boxed: Box<[u8]> = vec![fill; BANK_BYTES].into_boxed_slice();
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
            regs::FLASH_NSSR => self.read_nssr(),
            regs::FLASH_SECCR => self.seccr,
            regs::FLASH_NSCR => self.nscr,
            regs::FLASH_OPTR => self.optr,
            other if self.is_flash(other) => self.read_flash_word(other),
            _ => 0,
        }
    }

    fn write32(&mut self, addr: u32, value: u32)
    {
        if let Some(resolved) = self.resolve(addr)
        {
            // A word write to a flash address programs only while the accessing
            // controller's PG is set (secure alias -> SECCR.PG, non-secure alias
            // -> NSCR.PG), otherwise it is ignored (a real flash address is
            // read-only without an armed program, RM0456 sec 7.3.7). PG shares
            // bit 0 across the two control registers.
            let armed = if resolved.alias_secure
            {
                self.seccr & regs::SECCR_PG
            }
            else
            {
                self.nscr & regs::SECCR_PG
            };
            if armed != 0
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
            Some(resolved) =>
            {
                let end = core::cmp::min(resolved.index + len, BANK_BYTES);
                let start = core::cmp::min(resolved.index, end);
                // Table 68: a band read through the wrong alias for its label
                // returns RAZ (all zeros), not the stored bytes. A band is
                // homogeneous, so the base page's label decides the whole read.
                if resolved.alias_secure == page_label_secure(resolved.index)
                {
                    self.store(resolved.bank2)
                        .get(start..end)
                        .unwrap_or(&[])
                }
                else
                {
                    self.zeros.get(start..end).unwrap_or(&[])
                }
            }
            None => &[],
        }
    }
}
