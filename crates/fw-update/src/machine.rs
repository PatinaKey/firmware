//! The dual-bank A/B update state machine for the MCU's own firmware.
//!
//! The machine streams an update image through the seam into the inactive bank,
//! verifies the bank by reading it back, runs the two anti-rollback gates,
//! commits the swap (modelled, RM0456 sec 7.5.8), then confirms or reverts on
//! the first boot of the new bank.
//!
//! # The inactive bank is the single source of truth
//!
//! The signed file stays contiguous `header || payload || signature`, but the
//! device de-interleaves it so the payload lands page-aligned at its link origin
//! and the committed bank is bootable-shaped. [`Updater::receive_chunk`] routes
//! each stream byte to its destination: the header and the signature into small
//! fixed buffers, the payload into the inactive bank through
//! [`FlashSeam::write_inactive_page`] (which addresses the payload band, page 10
//! onward). No whole-image RAM copy exists, only the 24-byte header, the 64-byte
//! signature, and one payload page under construction. At accept
//! [`Updater::verify_and_accept`] writes the descriptor page (header then
//! signature) through [`FlashSeam::write_descriptor`], then reads four segments
//! back through [`FlashSeam::inactive_descriptor`],
//! [`FlashSeam::inactive_secure_band`], and [`FlashSeam::inactive_ns_band`] and
//! passes them to [`image_verify::verify_image`]. Their concatenation is the
//! original file. The swap commits that same bank, so the bytes verified are the
//! bytes booted.
//!
//! # Fail-closed by construction
//!
//! Every transition that touches an irreversible seam op runs only on the Ok
//! path of the prior check. A verify failure, an anti-rollback violation, or any
//! seam error collapses the machine to a state that keeps the old bank bootable.
//! No field inside the signed region is trusted before the signature verifies:
//! the [`image_verify::VerifiedImage`] the gates read exists only after the
//! ECDSA P-256 check passed.
//!
//! # Power-loss reasoning at each step boundary
//!
//! No ordering loses the old bank's bootability (RM0456 sec 7.5.8: SWAP_BANK
//! takes effect atomically at the next reset, the CPU never sees a half-swapped
//! map, a power loss before the swap commits leaves the old bank booting).
//!
//! - During receive or page write: the inactive bank is partly written, the
//!   running bank is untouched, no swap is armed. The next boot runs the old
//!   bank. A fresh update restarts from erase.
//! - Between accept and commit: the machine holds [`UpdateState::PendingCommit`]
//!   in volatile state only. No persistent flag is set. A power loss drops the
//!   accept and the next boot runs the old bank.
//! - [`Updater::commit`] writes [`PendingFlag::Armed`] with the target bank id
//!   before [`FlashSeam::commit_swap`]. That call resets the part on real
//!   hardware, so the confirm-owed marker must already be persisted when the new
//!   bank first runs. A power loss in this window leaves [`PendingFlag::Armed`]
//!   set but the swap not yet effective, so the old bank still boots.
//! - First boot after the commit: [`Updater::on_boot`] compares the running
//!   bank against the armed target. A match means the swap took effect and a
//!   confirm is owed ([`UpdateState::AwaitingConfirm`]). A mismatch means the
//!   swap never took effect (power loss before the option load committed), so the
//!   machine clears the record and stays on the old bank. It never arms a reverse
//!   swap toward an unverified bank.
//! - [`Updater::revert`] is reachable only from [`UpdateState::AwaitingConfirm`],
//!   which on_boot enters only when the forward swap is proven effective. A
//!   revert therefore flips back only from a swap known to have committed. If the
//!   swap never took effect, revert is unreachable and the old bank already boots.
//! - [`Updater::confirm`] bumps Gate-1 NVCNT last, at the terminal
//!   [`UpdateState::Confirmed`] transition, past every revert decision. Once a
//!   confirm step runs, the state leaves [`UpdateState::AwaitingConfirm`], so
//!   revert can no longer fire. The machine cannot both bump NVCNT and later
//!   revert, so NVCNT never rises above a bank that gets reverted away.

use image_verify::HEADER_LEN;
use image_verify::RootKey;
use image_verify::SIG_LEN;
use image_verify::VerifyError;
use image_verify::verify_image;

use crate::seam::FlashError;
use crate::seam::FlashSeam;
use crate::seam::PageIndex;
use crate::seam::PendingFlag;
use crate::seam::SeCounterError;
use crate::seam::SeCounterSeam;

/// The page width the chunk accumulator and the flash seam agree on.
///
/// A caller sizing chunks matches the seam page granularity through this.
pub const PAGE_LEN: usize = 256;

/// The number of self-confirm boots the new bank must reach.
///
/// The new bank raises the boot count on each healthy boot. When it reaches
/// this floor the machine confirms. If the budget runs out below it, the
/// machine reverts.
pub const CONFIRM_BOOTS: u32 = 1;

/// The anti-rollback origin the secure-element down-counter maps from (Gate 2).
///
/// The TROPIC01 MCounter counts down from a provisioned start: each accepted
/// update spends one tick (MCounter_Update). The machine derives an anti-rollback
/// floor as `SE_COUNTER_ORIGIN - se_value`: the more ticks spent, the higher the
/// floor. An image whose signed security counter sits below that floor is a
/// rollback below what the secure element already accepted, so the machine
/// rejects the accept. The origin is the provisioned start value.
pub const SE_COUNTER_ORIGIN: u32 = 0xFFFF_FFFF;

/// The update state.
///
/// The flow is Idle -> ReceivingChunks -> VerifyingImage -> (Rejected |
/// PendingCommit) -> Committed -> BootingNew -> AwaitingConfirm -> (Confirmed |
/// Reverted). Rejected and Reverted both return to a safe resting state with the
/// old bank bootable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateState
{
    /// No update in flight. The running bank is the confirmed bank.
    Idle,
    /// Streaming image bytes into the erased inactive bank.
    ReceivingChunks,
    /// All bytes written, running verify and the two anti-rollback gates.
    VerifyingImage,
    /// Verify or anti-rollback failed. The machine cleared the inactive bank.
    Rejected,
    /// Verified and accepted. The swap has not been armed yet.
    PendingCommit,
    /// The swap is armed (RM0456 sec 7.5.8). The new bank boots after reset.
    Committed,
    /// First boot of the new bank, proven by the running bank matching the
    /// armed target.
    BootingNew,
    /// Counting boots for the new bank to self-confirm.
    AwaitingConfirm,
    /// A confirm step has begun. Revert is no longer reachable from here.
    Confirming,
    /// The new bank confirmed. NVCNT bumped, SE counter spent, record cleared.
    Confirmed,
    /// Confirmation timed out. The machine reverted the swap to the old bank.
    Reverted,
}

/// Why a transition failed.
///
/// Each variant maps to a fail-closed collapse. The machine never proceeds to an
/// irreversible step after returning one of these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateError
{
    /// A method was called in a state that does not allow it.
    BadState,
    /// A chunk offset or length fell outside the declared image length.
    ChunkOutOfRange,
    /// The bytes written to the inactive bank do not match the declared length.
    Incomplete,
    /// The accumulated image failed signature or format verification.
    VerifyFailed(VerifyError),
    /// The image security counter is below a stored anti-rollback floor.
    Rollback,
    /// A flash seam call failed.
    Flash(FlashError),
    /// A secure-element counter seam call failed.
    SeCounter(SeCounterError),
}

impl From<FlashError> for UpdateError
{
    fn from(error: FlashError) -> UpdateError
    {
        UpdateError::Flash(error)
    }
}

impl From<SeCounterError> for UpdateError
{
    fn from(error: SeCounterError) -> UpdateError
    {
        UpdateError::SeCounter(error)
    }
}

/// The update driver.
///
/// Holds the current [`UpdateState`], the declared total image length, a single
/// page-assembly buffer, and the two seams. Accepted bytes flow through the
/// seam into the inactive bank, so the driver keeps no whole-image RAM copy. The
/// page-assembly buffer holds at most one page between flushes.
pub struct Updater<'k, F, S>
{
    state: UpdateState,
    root_key: &'k RootKey,
    flash: F,
    se_counter: S,
    total_len: usize,
    written: usize,
    payload_len: usize,
    header_buf: [u8; HEADER_LEN],
    sig_buf: [u8; SIG_LEN],
    page_buf: [u8; PAGE_LEN],
}

impl<'k, F, S> Updater<'k, F, S>
where
    F: FlashSeam,
    S: SeCounterSeam,
{
    /// Builds an idle updater bound to the seams and the pinned root key.
    pub fn new
    (
        root_key: &'k RootKey,
        flash: F,
        se_counter: S,
    )
        -> Updater<'k, F, S>
    {
        Updater
        {
            state: UpdateState::Idle,
            root_key,
            flash,
            se_counter,
            total_len: 0,
            written: 0,
            payload_len: 0,
            header_buf: [0xFF; HEADER_LEN],
            sig_buf: [0xFF; SIG_LEN],
            page_buf: [0xFF; PAGE_LEN],
        }
    }

    /// The current state.
    pub fn state(&self) -> UpdateState
    {
        self.state
    }

    /// The number of image bytes written to the inactive bank so far.
    pub fn written(&self) -> usize
    {
        self.written
    }

    /// Borrows the flash seam (test and fuzz inspection only).
    #[cfg(any(test, feature = "_fuzz"))]
    pub(crate) fn flash(&self) -> &F
    {
        &self.flash
    }

    /// Borrows the secure-element counter seam (test inspection only).
    #[cfg(test)]
    pub(crate) fn se_counter(&self) -> &S
    {
        &self.se_counter
    }

    /// Borrows the secure-element counter seam mutably (test inspection only).
    #[cfg(test)]
    pub(crate) fn se_counter_mut(&mut self) -> &mut S
    {
        &mut self.se_counter
    }

    /// Starts an update: erases the inactive bank and arms the accumulator.
    ///
    /// The caller declares `total_len`, the exact byte count the full signed file
    /// occupies (`header || payload || signature`). [`Self::verify_and_accept`]
    /// rejects unless the bytes written match it, so a prefix can never reach
    /// verify. The header and signature de-interleave into the descriptor, so the
    /// payload (the raw firmware) is what must fit the payload band.
    ///
    /// # Arguments
    ///
    /// - `total_len`: the declared total file length in bytes.
    ///
    /// # Errors
    ///
    /// [`UpdateError::BadState`] unless the machine is [`UpdateState::Idle`],
    /// [`UpdateError::ChunkOutOfRange`] if the payload exceeds the payload band,
    /// [`UpdateError::Flash`] if the erase fails (the machine stays Idle, old
    /// bank bootable).
    pub fn begin(&mut self, total_len: usize) -> Result<(), UpdateError>
    {
        if self.state != UpdateState::Idle
        {
            return Err(UpdateError::BadState);
        }
        let payload_capacity = self
            .flash
            .inactive_secure_band()
            .len()
            .saturating_add(self.flash.inactive_ns_band().len());
        let payload_len = total_len.saturating_sub(HEADER_LEN + SIG_LEN);
        if payload_len > payload_capacity
        {
            return Err(UpdateError::ChunkOutOfRange);
        }
        self.flash.erase_inactive()?;
        self.total_len = total_len;
        self.payload_len = payload_len;
        self.written = 0;
        self.header_buf = [0xFF; HEADER_LEN];
        self.sig_buf = [0xFF; SIG_LEN];
        self.page_buf = [0xFF; PAGE_LEN];
        self.state = UpdateState::ReceivingChunks;
        Ok(())
    }

    /// Writes one image chunk at `offset` into the inactive bank.
    ///
    /// The offset and length are attacker-controlled. The machine bounds-checks
    /// them against the declared total length with checked arithmetic, then
    /// streams the bytes through the page-assembly buffer into the inactive bank
    /// via [`FlashSeam::write_inactive_page`]. Chunks must arrive in order and
    /// fill the image contiguously: a gap or an out-of-order offset is rejected.
    /// A rejected chunk fails closed: the machine collapses to
    /// [`UpdateState::Rejected`] and clears the inactive bank, so a caller cannot
    /// resume a partly poisoned transfer.
    ///
    /// # Arguments
    ///
    /// - `offset`: byte offset of the chunk inside the image. Must equal the
    ///   bytes already written (contiguous, in order).
    /// - `data`: the chunk bytes.
    ///
    /// # Errors
    ///
    /// [`UpdateError::BadState`] unless receiving,
    /// [`UpdateError::ChunkOutOfRange`] if the chunk is out of order, overflows,
    /// or runs past the declared length,
    /// [`UpdateError::Flash`] if a page write fails.
    pub fn receive_chunk
    (
        &mut self,
        offset: usize,
        data: &[u8],
    )
        -> Result<(), UpdateError>
    {
        if self.state != UpdateState::ReceivingChunks
        {
            return Err(UpdateError::BadState);
        }
        match self.write_chunk(offset, data)
        {
            Ok(()) => Ok(()),
            Err(error) =>
            {
                self.reject_cleanup();
                self.state = UpdateState::Rejected;
                Err(error)
            }
        }
    }

    /// De-interleaves one contiguous chunk of the signed file onto flash.
    ///
    /// Requires `offset` to equal [`Self::written`] (in-order, no gap). The file
    /// is `header || payload || signature`, so a stream offset routes to one of
    /// three destinations, splitting the chunk at each region boundary: the header
    /// range [0, `HEADER_LEN`) buffers until the descriptor is written, the payload
    /// range [`HEADER_LEN`, `HEADER_LEN` + payload_len) streams into the payload
    /// band page by page, and the tail signature buffers until the descriptor is
    /// written. The header and signature buffers plus the descriptor page write are
    /// how the magic lands off the secure app link origin. Each region run advances
    /// by at least one byte, so the loop always terminates.
    ///
    /// # Errors
    ///
    /// [`UpdateError::ChunkOutOfRange`] on an out-of-order offset or a run past
    /// the declared length, [`UpdateError::Flash`] on a page-write fault.
    fn write_chunk
    (
        &mut self,
        offset: usize,
        data: &[u8],
    )
        -> Result<(), UpdateError>
    {
        if offset != self.written
        {
            return Err(UpdateError::ChunkOutOfRange);
        }
        let end = offset
            .checked_add(data.len())
            .ok_or(UpdateError::ChunkOutOfRange)?;
        if end > self.total_len
        {
            return Err(UpdateError::ChunkOutOfRange);
        }
        // The payload region ends HEADER_LEN + payload_len bytes into the stream.
        // The signature region runs from there to total_len.
        let payload_end = HEADER_LEN
            .checked_add(self.payload_len)
            .ok_or(UpdateError::ChunkOutOfRange)?;
        let mut rest = data;
        while !rest.is_empty()
        {
            let pos = self.written;
            let take = if pos < HEADER_LEN
            {
                // Header region: buffer into header_buf, never touch flash yet.
                let room = HEADER_LEN - pos;
                let take = core::cmp::min(room, rest.len());
                let slot = self
                    .header_buf
                    .get_mut(pos..pos + take)
                    .ok_or(UpdateError::ChunkOutOfRange)?;
                let head = rest
                    .get(..take)
                    .ok_or(UpdateError::ChunkOutOfRange)?;
                slot.copy_from_slice(head);
                take
            }
            else if pos < payload_end
            {
                // Payload region: stream into the payload band page by page.
                let room = payload_end - pos;
                let take = core::cmp::min(room, rest.len());
                let payload_pos = pos - HEADER_LEN;
                let head = rest
                    .get(..take)
                    .ok_or(UpdateError::ChunkOutOfRange)?;
                self.write_payload_run(payload_pos, head)?;
                take
            }
            else
            {
                // Signature region: buffer into sig_buf, never touch flash yet.
                let sig_pos = pos - payload_end;
                let room = SIG_LEN
                    .checked_sub(sig_pos)
                    .ok_or(UpdateError::ChunkOutOfRange)?;
                let take = core::cmp::min(room, rest.len());
                let slot = self
                    .sig_buf
                    .get_mut(sig_pos..sig_pos + take)
                    .ok_or(UpdateError::ChunkOutOfRange)?;
                let head = rest
                    .get(..take)
                    .ok_or(UpdateError::ChunkOutOfRange)?;
                slot.copy_from_slice(head);
                take
            };
            self.written = self
                .written
                .checked_add(take)
                .ok_or(UpdateError::ChunkOutOfRange)?;
            rest = rest
                .get(take..)
                .ok_or(UpdateError::ChunkOutOfRange)?;
        }
        Ok(())
    }

    /// Streams a contiguous payload run into the payload band, page by page.
    ///
    /// `payload_pos` is the run's byte offset inside the payload (not the file).
    /// Fills the page-assembly buffer and flushes each full page through
    /// [`FlashSeam::write_inactive_page`], which addresses the payload band (page
    /// 10 onward). A partial trailing page stays buffered until
    /// [`Self::flush_partial_payload_page`] writes it at accept time.
    ///
    /// # Errors
    ///
    /// [`UpdateError::ChunkOutOfRange`] on an internal bound slip,
    /// [`UpdateError::Flash`] on a page-write fault.
    fn write_payload_run
    (
        &mut self,
        payload_pos: usize,
        data: &[u8],
    )
        -> Result<(), UpdateError>
    {
        let mut rest = data;
        let mut pos = payload_pos;
        while !rest.is_empty()
        {
            let page_fill = pos % PAGE_LEN;
            let room = PAGE_LEN - page_fill;
            let take = core::cmp::min(room, rest.len());
            let head = rest
                .get(..take)
                .ok_or(UpdateError::ChunkOutOfRange)?;
            let slot = self
                .page_buf
                .get_mut(page_fill..page_fill + take)
                .ok_or(UpdateError::ChunkOutOfRange)?;
            slot.copy_from_slice(head);
            pos = pos
                .checked_add(take)
                .ok_or(UpdateError::ChunkOutOfRange)?;
            rest = rest
                .get(take..)
                .ok_or(UpdateError::ChunkOutOfRange)?;
            if pos.is_multiple_of(PAGE_LEN)
            {
                let page = (pos / PAGE_LEN)
                    .checked_sub(1)
                    .ok_or(UpdateError::ChunkOutOfRange)?;
                self.flush_payload_page(page)?;
            }
        }
        Ok(())
    }

    /// Writes the just-filled payload page to its band page, then resets the
    /// buffer.
    ///
    /// # Errors
    ///
    /// [`UpdateError::Flash`] on a page-write fault.
    fn flush_payload_page(&mut self, page: usize) -> Result<(), UpdateError>
    {
        let index = PageIndex::try_from(page)
            .map_err(|_| UpdateError::ChunkOutOfRange)?;
        self.flash.write_inactive_page(index, &self.page_buf)?;
        self.page_buf = [0xFF; PAGE_LEN];
        Ok(())
    }

    /// Writes a partial trailing payload page so the band holds every byte.
    ///
    /// Called once, at accept time, when the payload does not land on a page
    /// boundary. Writes only the buffered bytes of the final payload page.
    ///
    /// # Errors
    ///
    /// [`UpdateError::Flash`] on a page-write fault.
    fn flush_partial_payload_page(&mut self) -> Result<(), UpdateError>
    {
        let page_fill = self.payload_len % PAGE_LEN;
        if page_fill == 0
        {
            return Ok(());
        }
        let page = self.payload_len / PAGE_LEN;
        let index = PageIndex::try_from(page)
            .map_err(|_| UpdateError::ChunkOutOfRange)?;
        let slice = self
            .page_buf
            .get(..page_fill)
            .ok_or(UpdateError::ChunkOutOfRange)?;
        self.flash.write_inactive_page(index, slice)?;
        Ok(())
    }

    /// Assembles the descriptor bytes: the buffered header then the signature.
    ///
    /// The result is exactly `HEADER_LEN` + `SIG_LEN` bytes, which the descriptor
    /// page holds at [0:24] and [24:88].
    fn descriptor_bytes(&self) -> [u8; HEADER_LEN + SIG_LEN]
    {
        let mut out = [0xFF; HEADER_LEN + SIG_LEN];
        let (head, tail) = out.split_at_mut(HEADER_LEN);
        head.copy_from_slice(&self.header_buf);
        tail.copy_from_slice(&self.sig_buf);
        out
    }

    /// Verifies the inactive bank and runs the two anti-rollback gates.
    ///
    /// Flushes any partial trailing payload page, checks the written byte count
    /// against the declared length (the completeness gate), writes the descriptor
    /// page from the buffered header and signature, then reads the inactive bank
    /// back as four segments through [`FlashSeam::inactive_descriptor`],
    /// [`FlashSeam::inactive_secure_band`], and [`FlashSeam::inactive_ns_band`]
    /// and passes them to [`image_verify::verify_image`] under the pinned root
    /// key. The swap commits this same bank, so verify and commit act on the same
    /// bytes.
    ///
    /// On success it runs Gate 1 (UM2851 NVCNT) and Gate 2 (the TROPIC01
    /// down-counter floor). Both reject an image whose signed security counter
    /// sits below the stored value. Both counters are trusted only here, because
    /// the security counter lives in the signed region and verify already passed.
    ///
    /// On any failure the machine clears the inactive bank and collapses to
    /// [`UpdateState::Rejected`] then [`UpdateState::Idle`], with the old bank
    /// bootable and no swap armed.
    ///
    /// # Errors
    ///
    /// [`UpdateError::BadState`] unless receiving,
    /// [`UpdateError::Incomplete`] if the bank holds fewer bytes than declared,
    /// [`UpdateError::VerifyFailed`] if the signature or format check fails,
    /// [`UpdateError::Rollback`] on a downgrade against either gate,
    /// [`UpdateError::Flash`] or [`UpdateError::SeCounter`] on a seam fault.
    pub fn verify_and_accept(&mut self) -> Result<(), UpdateError>
    {
        if self.state != UpdateState::ReceivingChunks
        {
            return Err(UpdateError::BadState);
        }

        if let Err(error) = self.flush_partial_payload_page()
        {
            return self.reject(error);
        }

        // The completeness gate: the bytes written must match the declared file
        // length, so a prefix never reaches verify.
        if self.written != self.total_len
        {
            return self.reject(UpdateError::Incomplete);
        }

        // Write the descriptor page (header at [0:24], signature at [24:88]) from
        // the buffered header and signature. The verify below reads it back, so
        // the whole image, including header and signature, is read from the store
        // the commit boots.
        if let Err(error) =
            self.flash.write_descriptor(&self.descriptor_bytes())
        {
            return self.reject(UpdateError::Flash(error));
        }

        self.state = UpdateState::VerifyingImage;

        // Gate 1 (UM2851 NVCNT) and the secure-element value are read before the
        // bank borrow so the immutable borrow does not overlap the seam calls.
        let nvcnt = match self.flash.nvcnt_read()
        {
            Ok(value) => value,
            Err(error) => return self.reject(UpdateError::Flash(error)),
        };
        let se_value = match self.se_counter.read()
        {
            Ok(value) => value,
            Err(error) => return self.reject(UpdateError::SeCounter(error)),
        };

        // Verify the exact bytes the swap will boot, read back from the store.
        // The verifier takes a segmented image. The seam hands back four logical
        // segments read through their own aliases: the header and signature from
        // the descriptor (secure via 0x0C..), the secure payload (0x0C..), and the
        // non-secure payload (0x08..). Their concatenation, in that order, is
        // `header || payload || signature`, so a non-secure page is never read
        // through the secure alias, which would RAZ (RM0456 Table 68). The borrows
        // are scoped so they drop before any self.reject call (which needs a
        // mutable borrow).
        let security_counter = 
        {
            let descriptor = self.flash.inactive_descriptor();
            let secure = self.flash.inactive_secure_band();
            let ns = self.flash.inactive_ns_band();
            // secure_take never exceeds the secure band. begin proved payload_len
            // fits the two payload bands, so ns_take never exceeds the NS band.
            let secure_take = core::cmp::min(self.payload_len, secure.len());
            let ns_take = self.payload_len - secure_take;
            let header = descriptor.get(..HEADER_LEN);
            let sig = descriptor.get(HEADER_LEN..HEADER_LEN + SIG_LEN);
            match (header, secure.get(..secure_take), ns.get(..ns_take), sig)
            {
                (Some(header_seg), Some(secure_seg), Some(ns_seg), Some(sig_seg)) =>
                {
                    let segments: [&[u8]; 4] =
                        [header_seg, secure_seg, ns_seg, sig_seg];
                    match verify_image(&segments, self.root_key)
                    {
                        Ok(verified) => Ok(verified.security_counter()),
                        Err(error) => Err(UpdateError::VerifyFailed(error)),
                    }
                }
                _ => Err(UpdateError::Incomplete),
            }
        };
        let security_counter = match security_counter
        {
            Ok(value) => value,
            Err(error) => return self.reject(error),
        };

        // Gate 1: reject when the image counter is below the stored NVCNT. Equal
        // is accepted (a re-install of the same image), so it does not waste the
        // finite NVCNT burn budget on the same counter.
        if security_counter < nvcnt
        {
            return self.reject(UpdateError::Rollback);
        }

        // Gate 2: the secure-element down-counter maps to an anti-rollback floor.
        // Reject when the image counter is below it.
        let floor = SE_COUNTER_ORIGIN.saturating_sub(se_value);
        if security_counter < floor
        {
            return self.reject(UpdateError::Rollback);
        }

        self.state = UpdateState::PendingCommit;
        Ok(())
    }

    /// Arms the swap commit (RM0456 sec 7.5.8), modelled through the seam.
    ///
    /// Reads the target bank, writes [`PendingFlag::Armed`] with that bank id
    /// first (the commit resets the part on real hardware, so the confirm-owed
    /// marker must already be persisted), then arms the swap. On a swap-arm
    /// failure the machine clears the record and stays fail-closed, old bank
    /// still bootable.
    ///
    /// # Errors
    ///
    /// [`UpdateError::BadState`] unless accepted,
    /// [`UpdateError::Flash`] if the target read, the record write, or the swap
    /// arm fails.
    pub fn commit(&mut self) -> Result<(), UpdateError>
    {
        if self.state != UpdateState::PendingCommit
        {
            return Err(UpdateError::BadState);
        }
        let target = self.flash.target_bank()?;
        self.flash.pending_write(PendingFlag::Armed(target))?;
        match self.flash.commit_swap()
        {
            Ok(()) =>
            {
                self.state = UpdateState::Committed;
                Ok(())
            }
            Err(error) =>
            {
                // Undo the record so the old bank stays the confirmed bank. The
                // swap was not armed, so the machine arms no reverse swap.
                let _ = self.flash.pending_write(PendingFlag::None);
                self.state = UpdateState::PendingCommit;
                Err(UpdateError::Flash(error))
            }
        }
    }

    /// Detects the first boot of the new bank and proves the swap took effect.
    ///
    /// Run at boot. Reads the pending record. On [`PendingFlag::Armed`] it
    /// compares the running bank against the armed target. A match proves the
    /// swap committed: the machine enters [`UpdateState::AwaitingConfirm`] and
    /// raises the boot count. A mismatch means the swap never took effect (a
    /// power loss before the option load committed, RM0456 sec 7.5.8): the
    /// machine clears the record and stays [`UpdateState::Idle`] on the old bank,
    /// arming no reverse swap. A clear record means the running bank is already
    /// confirmed.
    ///
    /// # Errors
    ///
    /// [`UpdateError::Flash`] if the record read, the bank read, or the boot
    /// count fails. A read fault keeps the old bank path.
    pub fn on_boot(&mut self) -> Result<UpdateState, UpdateError>
    {
        match self.flash.pending_read()?
        {
            PendingFlag::Armed(target) =>
            {
                let running = self.flash.running_bank()?;
                if running == target
                {
                    self.state = UpdateState::BootingNew;
                    self.flash.boot_count_advance()?;
                    self.state = UpdateState::AwaitingConfirm;
                    Ok(self.state)
                }
                else
                {
                    // The swap never took effect. The old bank booted. Clear the
                    // record so no later revert flips into the unverified bank.
                    self.flash.pending_write(PendingFlag::None)?;
                    self.state = UpdateState::Idle;
                    Ok(self.state)
                }
            }
            PendingFlag::None =>
            {
                self.state = UpdateState::Idle;
                Ok(self.state)
            }
        }
    }

    /// Confirms the new bank: spends the SE counter, clears the record, bumps
    /// NVCNT.
    ///
    /// Run after the new bank passes its health checks and reaches
    /// [`CONFIRM_BOOTS`]. It spends Gate 2 (the SE down-counter), clears the
    /// pending record, then bumps Gate 1 (UM2851 NVCNT) last, at the terminal
    /// [`UpdateState::Confirmed`] transition past every revert decision. Once any
    /// confirm step runs the state leaves [`UpdateState::AwaitingConfirm`], so
    /// [`Self::revert`] can no longer fire: the machine cannot both bump NVCNT and
    /// later revert.
    ///
    /// Bumping NVCNT to the same counter is a no-op against the monotone store,
    /// so confirming the same image does not waste the finite burn budget.
    ///
    /// # Arguments
    ///
    /// - `security_counter`: the verified image counter, bumped into NVCNT.
    ///
    /// # Errors
    ///
    /// [`UpdateError::BadState`] unless awaiting confirm or the boot floor is
    /// unmet, [`UpdateError::Flash`] or [`UpdateError::SeCounter`] on a seam
    /// fault (the swap stays committed, the new bank keeps booting, the confirm
    /// is retried on the next boot).
    pub fn confirm
    (
        &mut self,
        security_counter: u32,
    )
        -> Result<(), UpdateError>
    {
        if self.state != UpdateState::AwaitingConfirm
        {
            return Err(UpdateError::BadState);
        }
        if self.flash.boot_count_read()? < CONFIRM_BOOTS
        {
            return Err(UpdateError::BadState);
        }
        // Leave AwaitingConfirm before any irrevocable confirm step, so revert
        // can no longer fire once a confirm has begun.
        self.state = UpdateState::Confirming;
        self.se_counter.update()?;
        self.flash.pending_write(PendingFlag::None)?;
        // NVCNT bumps last, past the revert decision point. Equal-counter bumps
        // are a no-op, so a re-confirm of the same image spends no burn budget.
        self.flash.nvcnt_bump(security_counter)?;
        self.state = UpdateState::Confirmed;
        Ok(())
    }

    /// Reverts the swap to the old bank after a confirmation timeout.
    ///
    /// Reachable only from [`UpdateState::AwaitingConfirm`], which on_boot enters
    /// only after proving the forward swap took effect. Once [`Self::confirm`]
    /// begins, the state leaves AwaitingConfirm, so a revert after a confirm step
    /// is refused with [`UpdateError::BadState`]. Arms the reverse swap (RM0456
    /// sec 7.5.8, same atomicity), then clears the record, so the next boot
    /// returns to the old bank with no confirm owed.
    ///
    /// # Errors
    ///
    /// [`UpdateError::BadState`] unless awaiting confirm,
    /// [`UpdateError::Flash`] if the revert arm or the record clear fails (the
    /// record stays set so the revert is retried on the next boot, never
    /// stranding the new bank as confirmed).
    pub fn revert(&mut self) -> Result<(), UpdateError>
    {
        if self.state != UpdateState::AwaitingConfirm
        {
            return Err(UpdateError::BadState);
        }
        self.flash.revert_swap()?;
        self.flash.pending_write(PendingFlag::None)?;
        self.state = UpdateState::Reverted;
        Ok(())
    }

    /// Clears the inactive bank and returns to Idle, recording the reject cause.
    ///
    /// A best-effort erase: even if the cleanup erase faults, the machine still
    /// lands in [`UpdateState::Rejected`] then [`UpdateState::Idle`], because no
    /// swap was armed and the old bank is bootable regardless.
    fn reject(&mut self, cause: UpdateError) -> Result<(), UpdateError>
    {
        self.state = UpdateState::Rejected;
        self.reject_cleanup();
        self.state = UpdateState::Idle;
        Err(cause)
    }

    /// Clears the inactive bank and the accumulation counters, best effort.
    fn reject_cleanup(&mut self)
    {
        let _ = self.flash.erase_inactive();
        self.written = 0;
        self.total_len = 0;
        self.payload_len = 0;
        self.header_buf = [0xFF; HEADER_LEN];
        self.sig_buf = [0xFF; SIG_LEN];
        self.page_buf = [0xFF; PAGE_LEN];
    }
}
