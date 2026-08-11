//! Host state mock for the boot flow and the power-cut harness.
//!
//! [`MockBootFlash`] models the real persistent state the boot stage reads and
//! writes: the SWAP_BANK bit, the two physical banks' images (read through the
//! low alias for whichever bank runs), the single metadata copy (pending, NVCNT,
//! outcome), and the SECWM readback. It models a power cut at any persistent
//! mutation boundary by unwinding, so the harness can prove that a cut at every
//! step leaves a state the decision recovers from.
//!
//! # Fidelity notes
//!
//! - The swap is staged by an arm and applied only at [`MockBootFlash::apply_reset`],
//!   mirroring RM0456 sec 7.5.8 (the option load takes effect at the next reset).
//!   A reboot without `apply_reset` models a cut before the option load committed,
//!   which is exactly the "swap never took effect" case.
//! - A mutation applies durably or not at all (the cut fires before the write),
//!   modelling the state-machine ordering, not sub-quad-word flash atomicity.

use fw_update::BankId;
use fw_update::FlashError;
use fw_update::PendingFlag;
use fw_update::UpdateOutcome;
use image_verify::HEADER_LEN;
use image_verify::ImageVersion;
use image_verify::SIG_LEN;
use image_verify::encode_header;
use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::Signer;
use sha2::Digest;
use sha2::Sha256;
use std::vec::Vec;

use crate::secwm::SecwmReadback;
use crate::secwm::SecwmWindow;
use crate::seam::BootFlash;

/// The phrase whose SHA-256 is the bring-up private scalar. The test signing key
/// (distinct from the pinned production key) is this scalar's public key. The test
/// fixtures inject it, so they are independent of the pinned trust anchor.
pub(crate) const BRINGUP_PHRASE: &[u8] =
    b"patina_key MCU image root - BRING-UP ONLY - replace at ceremony freeze";

/// The modelled secure payload sub-band capacity (bytes). Small on the host: the
/// carving logic is size-agnostic, so a compact band still exercises the split.
pub(crate) const MOCK_SECURE_BAND_LEN: usize = 96;
/// The modelled non-secure payload sub-band capacity (bytes).
pub(crate) const MOCK_NS_BAND_LEN: usize = 96;

/// The panic payload a modelled power cut unwinds with.
pub(crate) const POWER_CUT: &str = "BOOT_STAGE_POWER_CUT";

/// The bring-up test signing key (its public key is the test signing key, not the
/// pinned production key).
pub(crate) fn bringup_signing_key() -> SigningKey
{
    let scalar = Sha256::digest(BRINGUP_PHRASE);
    SigningKey::from_slice(&scalar).expect("bring-up scalar is a valid P-256 key")
}

/// One bank's image, as the three segments the boot stage reads.
#[derive(Clone)]
pub(crate) struct BankImage
{
    /// Page-9 descriptor: header at [0:24], signature at [24:88].
    pub(crate) descriptor: Vec<u8>,
    /// Secure payload sub-band (padded to `MOCK_SECURE_BAND_LEN` with erased 0xFF).
    pub(crate) secure_band: Vec<u8>,
    /// Non-secure payload sub-band (padded to `MOCK_NS_BAND_LEN` with erased 0xFF).
    pub(crate) ns_band: Vec<u8>,
}

impl BankImage
{
    /// Mints a healthy image signed by the bring-up key with the given counter.
    ///
    /// The payload is `payload_len` bytes of a fixed pattern, de-interleaved into
    /// the secure band first, then the non-secure band, exactly as the device
    /// lays it out. A `payload_len` above `MOCK_SECURE_BAND_LEN` therefore spans
    /// the SECWM boundary.
    pub(crate) fn healthy(security_counter: u32, payload_len: usize) -> BankImage
    {
        assert!(payload_len <= MOCK_SECURE_BAND_LEN + MOCK_NS_BAND_LEN);
        let version = ImageVersion
        {
            major: 1,
            minor: 0,
            revision: 0,
            build: 0,
        };
        let header = encode_header(version, security_counter, payload_len as u32);

        // A deterministic payload pattern.
        let mut payload = Vec::with_capacity(payload_len);
        for i in 0..payload_len
        {
            payload.push((i as u8) ^ 0x5A);
        }

        let mut signed = Vec::new();
        signed.extend_from_slice(&header);
        signed.extend_from_slice(&payload);
        let sk = bringup_signing_key();
        let sig: p256::ecdsa::Signature = sk.sign(&signed);
        let sig = sig.normalize_s();

        let mut descriptor = Vec::with_capacity(HEADER_LEN + SIG_LEN);
        descriptor.extend_from_slice(&header);
        descriptor.extend_from_slice(&sig.to_bytes());

        // De-interleave the payload across the two bands, padding with erased 0xFF.
        let secure_take = core::cmp::min(payload_len, MOCK_SECURE_BAND_LEN);
        let ns_take = payload_len - secure_take;
        let mut secure_band = vec![0xFF; MOCK_SECURE_BAND_LEN];
        secure_band[..secure_take].copy_from_slice(&payload[..secure_take]);
        let mut ns_band = vec![0xFF; MOCK_NS_BAND_LEN];
        ns_band[..ns_take].copy_from_slice(&payload[secure_take..]);

        BankImage
        {
            descriptor,
            secure_band,
            ns_band,
        }
    }

    /// Mints an unhealthy image: a healthy image with one signature byte flipped,
    /// so the ECDSA verify rejects it.
    pub(crate) fn unhealthy(security_counter: u32, payload_len: usize) -> BankImage
    {
        let mut image = BankImage::healthy(security_counter, payload_len);
        // Flip a byte inside the signature (descriptor [24:88]).
        image.descriptor[HEADER_LEN] ^= 0xFF;
        image
    }

    /// An all-erased bank (0xFF), which fails to verify (bad magic).
    pub(crate) fn erased() -> BankImage
    {
        BankImage
        {
            descriptor: vec![0xFF; HEADER_LEN + SIG_LEN],
            secure_band: vec![0xFF; MOCK_SECURE_BAND_LEN],
            ns_band: vec![0xFF; MOCK_NS_BAND_LEN],
        }
    }
}

/// The provisioned-correct SECWM readback (both banks pages 0..=19 secure).
pub(crate) fn good_secwm() -> SecwmReadback
{
    SecwmReadback
    {
        bank1: SecwmWindow { start: 0, end: 19 },
        bank2: SecwmWindow { start: 0, end: 19 },
    }
}

/// The host state mock.
pub(crate) struct MockBootFlash
{
    /// OPTR.SWAP_BANK: false => Bank1 at the low alias (runs), true => Bank2.
    pub(crate) swap: bool,
    /// A staged swap, applied at the next [`Self::apply_reset`].
    pub(crate) staged_swap: Option<bool>,
    /// Physical Bank 1 image.
    pub(crate) bank1: BankImage,
    /// Physical Bank 2 image.
    pub(crate) bank2: BankImage,
    /// The single pending-confirm record (survives a swap).
    pub(crate) pending: PendingFlag,
    /// The single NVCNT (survives a swap).
    pub(crate) nvcnt: u32,
    /// The single update-outcome record (survives a swap).
    pub(crate) outcome: UpdateOutcome,
    /// The SECWM readback the wedge checks.
    pub(crate) secwm: SecwmReadback,
    /// Whether the partition (DUALBANK / TZEN) reads sane.
    pub(crate) partition_ok: bool,

    /// The count of persistent mutations that have durably applied this run.
    pub(crate) mutations: usize,
    /// If set, the mutation at this index unwinds (a modelled power cut) before it
    /// applies.
    pub(crate) cut_at: Option<usize>,
}

impl MockBootFlash
{
    /// A confirmed steady state: no pending, both banks healthy, NVCNT matches.
    pub(crate) fn confirmed
    (
        swap: bool,
        bank1: BankImage,
        bank2: BankImage,
        nvcnt: u32,
    )
        -> MockBootFlash
    {
        MockBootFlash
        {
            swap,
            staged_swap: None,
            bank1,
            bank2,
            pending: PendingFlag::None,
            nvcnt,
            outcome: UpdateOutcome::None,
            secwm: good_secwm(),
            partition_ok: true,
            mutations: 0,
            cut_at: None,
        }
    }

    /// The physical bank that currently runs (sits at the low alias).
    pub(crate) fn running(&self) -> BankId
    {
        if self.swap
        {
            BankId::Bank2
        }
        else
        {
            BankId::Bank1
        }
    }

    /// The image of the running bank.
    fn running_image(&self) -> &BankImage
    {
        if self.swap
        {
            &self.bank2
        }
        else
        {
            &self.bank1
        }
    }

    /// Applies a staged swap, modelling the reset that the option load commits on.
    pub(crate) fn apply_reset(&mut self)
    {
        if let Some(target) = self.staged_swap.take()
        {
            self.swap = target;
        }
    }

    /// Arms a modelled power cut at the given persistent-mutation index, and
    /// resets the mutation counter for a fresh run.
    pub(crate) fn arm_cut(&mut self, index: Option<usize>)
    {
        self.cut_at = index;
        self.mutations = 0;
    }

    /// Checkpoints a persistent mutation. Unwinds (a modelled power cut) if this
    /// mutation is the armed cut index, before the mutation applies.
    fn checkpoint(&mut self)
    {
        if self.cut_at == Some(self.mutations)
        {
            panic!("{}", POWER_CUT);
        }
        self.mutations += 1;
    }
}

impl BootFlash for MockBootFlash
{
    fn require_partition(&mut self) -> Result<(), FlashError>
    {
        if self.partition_ok
        {
            Ok(())
        }
        else
        {
            Err(FlashError::Hardware)
        }
    }

    fn read_secwm(&mut self) -> Result<SecwmReadback, FlashError>
    {
        Ok(self.secwm)
    }

    fn running_bank(&mut self) -> Result<BankId, FlashError>
    {
        Ok(self.running())
    }

    fn pending_read(&mut self) -> Result<PendingFlag, FlashError>
    {
        Ok(self.pending)
    }

    fn nvcnt_read(&mut self) -> Result<u32, FlashError>
    {
        Ok(self.nvcnt)
    }

    fn active_descriptor(&self) -> &[u8]
    {
        &self.running_image().descriptor
    }

    fn active_secure_band(&self) -> &[u8]
    {
        &self.running_image().secure_band
    }

    fn active_ns_band(&self) -> &[u8]
    {
        &self.running_image().ns_band
    }

    fn update_outcome_clear(&mut self) -> Result<(), FlashError>
    {
        self.checkpoint();
        self.outcome = UpdateOutcome::None;
        Ok(())
    }

    fn update_outcome_write
    (
        &mut self,
        outcome: UpdateOutcome,
    )
        -> Result<(), FlashError>
    {
        self.checkpoint();
        self.outcome = outcome;
        Ok(())
    }

    fn pending_write(&mut self, flag: PendingFlag) -> Result<(), FlashError>
    {
        self.checkpoint();
        self.pending = flag;
        Ok(())
    }

    fn nvcnt_bump(&mut self, value: u32) -> Result<(), FlashError>
    {
        self.checkpoint();
        if value < self.nvcnt
        {
            return Err(FlashError::WriteFailed);
        }
        // Monotone store: an equal value is a no-op, a higher value advances.
        self.nvcnt = value;
        Ok(())
    }

    fn revert_swap(&mut self) -> Result<(), FlashError>
    {
        self.checkpoint();
        // Arm the swap toward the inactive bank. Applied at the next reset.
        self.staged_swap = Some(!self.swap);
        Ok(())
    }
}
