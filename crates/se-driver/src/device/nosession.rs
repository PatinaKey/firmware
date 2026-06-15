//! Pre-session (`NoSession`) device operations.
//!
//! Plain-L2 commands available before a secure channel exists: `reboot`, the
//! `Get_Info` family (X.509 cert store, CHIP_ID, firmware versions, FW banks),
//! and `open_session`, which runs the Noise KK1 handshake and transitions the
//! handle to `ActiveSession`. No AES-GCM, no nonce, no session to poison: a
//! non-OK chip status surfaces as an `L2Error` and is recoverable by nature.

use embedded_hal::spi::SpiDevice;
use zeroize::Zeroize;

use crate::buf::L2_FRAME_MAX;
use crate::buf::L3Buf;
use crate::crypto;
use crate::error::L2Error;
use crate::error::SeError;
use crate::handshake;
use crate::ids::L2ReqId;
use crate::ids::L2Status;
use crate::ids::ObjectId;
use crate::l1;
use crate::l2::frame;
use crate::session::SessionKeys;
use crate::wait::SeWait;

use super::ActiveSession;
use super::FwBankId;
use super::NoSession;
use super::SessionConfig;
use super::StartupId;
use super::Tropic01;
use super::parse_handshake_resp;
use super::GET_INFO_BLOCK_LEN;
use super::GET_INFO_CERT_STORE_BLOCKS;
use super::GET_INFO_CERT_STORE_LEN;

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

    /// Reboots the chip into the mode selected by `startup_id`.
    ///
    /// Sends a `Startup_Req` (L2 0xB3). The chip boots into Start-up Mode after a
    /// power cycle. `StartupId::Reboot` loads the Application FW (required before
    /// `open_session`, since the secure channel and L3 commands live there).
    /// Returns `Ok(())` on the empty success ack. Errors on a bus fault or an
    /// unexpected acknowledgement. Mirrors libtropic `lt_reboot`.
    pub fn reboot(&mut self, startup_id: StartupId) -> Result<(), SeError>
    {
        // Startup_Req body = STARTUP_ID(1). REQ_LEN = 1, RSP carries no data.
        let body = [startup_id.wire_byte()];
        let n = frame::build_request(L2ReqId::Startup as u8, &body, &mut self.l2)?;
        l1::send_request(&mut self.spi, &self.l2[..n]).map_err(L2Error::from)?;
        let frame_len =
            l1::read_response(&mut self.spi, &mut self.wait, &mut self.l2).map_err(L2Error::from)?;
        let resp = frame::parse_response(&self.l2[..frame_len])?;
        // A successful Startup_Req is acknowledged with an empty RequestOk frame.
        if !matches!(resp.status, L2Status::RequestOk) || !resp.data.is_empty()
        {
            return Err(SeError::L2(L2Error::BadFrame));
        }
        Ok(())
    }

    /// Reads one `Get_Info` block into `out`, returning the RSP_DATA length.
    ///
    /// Sends a `Get_Info_Req` (L2 0x01) with REQ_DATA = OBJECT_ID || BLOCK_INDEX
    /// and copies the response RSP_DATA into `out`. This is the shared L2 body for
    /// every object type. The per-object response-length handling lives in the
    /// public wrappers. No secure channel: this runs before `open_session`,
    /// exactly as reading the device certificate to obtain STPUB does.
    ///
    /// A non-OK chip status surfaces as `SeError::L2(L2Error::Status(_))` via
    /// `parse_response` and is recoverable by nature (no session state). A
    /// continuation status (`*Cont`) is anomalous for a single-frame `Get_Info`
    /// reply and is rejected as `L2Error::BadFrame`. `out` too small for the
    /// RSP_DATA returns `SeError::BufferTooSmall`.
    fn get_info_block
    (
        &mut self,
        object_id: ObjectId,
        block_index: u8,
        out: &mut [u8],
    )
    -> Result<usize, SeError>
    {
        // Get_Info_Req body = OBJECT_ID(1) || BLOCK_INDEX(1). REQ_LEN = 2.
        let body = [object_id as u8, block_index];
        let n = frame::build_request(L2ReqId::GetInfo as u8, &body, &mut self.l2)?;
        l1::send_request(&mut self.spi, &self.l2[..n]).map_err(L2Error::from)?;
        let frame_len =
            l1::read_response(&mut self.spi, &mut self.wait, &mut self.l2).map_err(L2Error::from)?;
        let resp = frame::parse_response(&self.l2[..frame_len])?;
        // A Get_Info reply fits one L2 chunk (RSP_DATA <= 128), so only a single
        // RequestOk frame is expected. *Cont (or any other accepted status) is a
        // malformed reply for this command.
        if !matches!(resp.status, L2Status::RequestOk)
        {
            return Err(SeError::L2(L2Error::BadFrame));
        }
        if out.len() < resp.data.len()
        {
            return Err(SeError::BufferTooSmall);
        }
        out[..resp.data.len()].copy_from_slice(resp.data);
        Ok(resp.data.len())
    }

    /// Reads the full raw X.509 certificate store into `out`.
    ///
    /// The store is a fixed `GET_INFO_CERT_STORE_LEN` (3840) DER bytes across
    /// `GET_INFO_CERT_STORE_BLOCKS` (30) `Get_Info` blocks. `out` must hold the
    /// whole store: a shorter buffer is rejected with `BufferTooSmall` up front,
    /// before any chip traffic. Returns `GET_INFO_CERT_STORE_LEN`.
    ///
    /// This returns the RAW store. Extracting STPUB by walking the ASN.1 is a
    /// separate deferred layer (libtropic `lt_get_st_pub`), kept out of this slice
    /// so no new attacker-facing decoder is introduced here. Requires Application
    /// FW mode.
    pub fn x509_certificate_into(&mut self, out: &mut [u8]) -> Result<usize, SeError>
    {
        // The store length is fixed and known to the caller, so require the full
        // buffer up front, before any chip traffic, mirroring rmem_read_into's
        // protocol-MAX check (se-driver lesson 2b.2). Recoverable: no session.
        if out.len() < GET_INFO_CERT_STORE_LEN
        {
            return Err(SeError::BufferTooSmall);
        }
        for i in 0..GET_INFO_CERT_STORE_BLOCKS
        {
            let start = i * GET_INFO_BLOCK_LEN;
            let end = start + GET_INFO_BLOCK_LEN;
            let n = self.get_info_block(ObjectId::X509Certificate, i as u8, &mut out[start..end])?;
            if n != GET_INFO_BLOCK_LEN
            {
                // Every cert-store block is a full 128-byte block. A short block
                // is a malformed reply.
                return Err(SeError::L2(L2Error::BadFrame));
            }
        }
        Ok(GET_INFO_CERT_STORE_LEN)
    }

    /// Reads the cert store and extracts STPUB (the chip static X25519 key).
    ///
    /// Reads the full X.509 store into the caller-provided `scratch`, then walks
    /// the DEVICE certificate's DER to STPUB and returns the 32 bytes by value
    /// (STPUB is PUBLIC). `scratch` must hold the whole store: shorter than
    /// `GET_INFO_CERT_STORE_LEN` is rejected with `BufferTooSmall` up front,
    /// before any chip traffic. STPUB is returned by value, so `scratch` is not
    /// retained: the caller may reuse or wipe it after this returns.
    ///
    /// The store is 3840 bytes. The caller passes the buffer so the ~4.4 KiB
    /// static handle does not grow a 3840-byte stack frame. Requires Application
    /// FW mode.
    ///
    /// SECURITY: this extracts STPUB only. It does NOT verify the certificate
    /// chain up to the Tropic root (mirrors libtropic `lt_get_st_pub`). The
    /// handshake auth tag binds STPUB, but full chain validation is a future
    /// slice. See `cert::parse_stpub`.
    pub fn read_chip_stpub(&mut self, scratch: &mut [u8]) -> Result<[u8; 32], SeError>
    {
        // Require the full store buffer up front, before any traffic, mirroring
        // x509_certificate_into. Recoverable: no session.
        if scratch.len() < GET_INFO_CERT_STORE_LEN
        {
            return Err(SeError::BufferTooSmall);
        }
        self.x509_certificate_into(scratch)?;
        crate::cert::parse_stpub(&scratch[..GET_INFO_CERT_STORE_LEN])
    }

    /// Reads the cert store, verifies the chain, then extracts STPUB.
    ///
    /// Mirrors `read_chip_stpub`, but verifies the certificate-chain signatures
    /// up to the caller-PINNED root `anchor` before returning STPUB. STPUB is
    /// thus only returned through a verified path. Reads the full store into
    /// `scratch`, runs `parse_verified_stpub`, and returns the 32 STPUB bytes by
    /// value (STPUB is PUBLIC). `scratch` is not retained.
    ///
    /// `scratch` must hold the whole store: shorter than `GET_INFO_CERT_STORE_LEN`
    /// is rejected with `BufferTooSmall` up front, before any chip traffic.
    ///
    /// SECURITY: the trust anchor is supplied OUT-OF-BAND, never read from the
    /// store. The PROD root differs from any TEST root. The integrator compiles
    /// in the correct production root point. This verifies the cryptographic
    /// chain only. date-validity and revocation are deferred (see
    /// `cert::verify_cert_chain`).
    ///
    /// SEAM: `open_session` currently takes STPUB via `SessionConfig`. To make a
    /// session depend on a VERIFIED STPUB, the caller obtains it here and passes
    /// it to `open_session`. Wiring verification into `open_session` directly is
    /// a follow-up. The verified-STPUB value already flows through this method.
    pub fn read_verified_chip_stpub
    (
        &mut self,
        scratch: &mut [u8],
        anchor: &crate::RootAnchor,
    )
    -> Result<[u8; 32], SeError>
    {
        // Require the full store buffer up front, before any traffic, mirroring
        // read_chip_stpub. Recoverable: no session.
        if scratch.len() < GET_INFO_CERT_STORE_LEN
        {
            return Err(SeError::BufferTooSmall);
        }
        self.x509_certificate_into(scratch)?;
        crate::cert::parse_verified_stpub(&scratch[..GET_INFO_CERT_STORE_LEN], anchor)
    }

    /// Reads the 128-byte CHIP_ID into `out`, returning 128.
    ///
    /// CHIP_ID is one fixed 128-byte `Get_Info` block. It uses `_into` rather
    /// than a by-value return (unlike the 4-byte versions) so the caller controls
    /// placement of the larger payload. BLOCK_INDEX is a don't-care, so 0 is sent.
    /// `out` shorter than 128 bytes is rejected by `get_info_block` with
    /// `BufferTooSmall`. A reply not exactly 128 bytes is a malformed frame.
    pub fn chip_id_into(&mut self, out: &mut [u8]) -> Result<usize, SeError>
    {
        let n = self.get_info_block(ObjectId::ChipId, 0, out)?;
        if n != GET_INFO_BLOCK_LEN
        {
            return Err(SeError::L2(L2Error::BadFrame));
        }
        Ok(GET_INFO_BLOCK_LEN)
    }

    /// Reads the 4-byte RISC-V (application) firmware version.
    ///
    /// Returns the RAW 4 bytes. In Start-up Mode the version's high bit is set
    /// (the sentinel `0x80000000`, no Application FW loaded). The caller must
    /// interpret it. The driver is a faithful transport and does not mask it.
    pub fn riscv_fw_version(&mut self) -> Result<[u8; 4], SeError>
    {
        let mut buf = [0u8; 4];
        let n = self.get_info_block(ObjectId::RiscvFwVersion, 0, &mut buf)?;
        if n != buf.len()
        {
            return Err(SeError::L2(L2Error::BadFrame));
        }
        Ok(buf)
    }

    /// Reads the 4-byte SPECT firmware version.
    ///
    /// Returns the RAW 4 bytes. In Start-up Mode SPECT returns the sentinel
    /// `0x80000000` (high bit set, no SPECT FW running). The driver does not mask
    /// it. The caller interprets the value.
    pub fn spect_fw_version(&mut self) -> Result<[u8; 4], SeError>
    {
        let mut buf = [0u8; 4];
        let n = self.get_info_block(ObjectId::SpectFwVersion, 0, &mut buf)?;
        if n != buf.len()
        {
            return Err(SeError::L2(L2Error::BadFrame));
        }
        Ok(buf)
    }

    /// Reads the FW_BANK header for `bank` into `out`, returning its length.
    ///
    /// The bank header is variable length: 0 (empty bank), 20, or 52 bytes. Any
    /// other length is a malformed reply. `out` shorter than the returned data is
    /// rejected by `get_info_block` with `BufferTooSmall`. Returns the byte
    /// count. Supported only in Start-up (Maintenance) Mode.
    pub fn fw_bank_into(&mut self, bank: FwBankId, out: &mut [u8]) -> Result<usize, SeError>
    {
        let n = self.get_info_block(ObjectId::FwBank, bank.wire_byte(), out)?;
        // A FW_BANK header is empty, or a 20- or 52-byte record. Any other length
        // is a structural anomaly. Sizes from libtropic
        // TR01_L2_GET_INFO_FW_HEADER_SIZE_BOOT_V2_EMPTY_BANK (0) / _BOOT_V1 (20) /
        // _BOOT_V2 (52).
        if n != 0 && n != 20 && n != 52
        {
            return Err(SeError::L2(L2Error::BadFrame));
        }
        Ok(n)
    }
}

impl<SPI, W> Tropic01<SPI, W, NoSession>
where
    SPI: SpiDevice,
    W: SeWait,
{
    /// Opens a secure channel via the Noise KK1 handshake.
    ///
    /// Consumes the handle. On success returns an `ActiveSession` handle ready
    /// for L3 commands. On failure returns the `NoSession` handle plus the
    /// error, so the caller can retry without rebuilding the device.
    #[expect(
        clippy::result_large_err,
        reason = "the handle is a large static singleton moved by value through \
                  this type-state transition. Returning it on the error path lets \
                  the caller keep it, and boxing is impossible under no_std/no heap."
    )]
    pub fn open_session
    (
        self,
        cfg: SessionConfig<'_>,
    )
    -> Result<Tropic01<SPI, W, ActiveSession>, (Self, SeError)>
    {
        let ehpub = crypto::x25519_base(cfg.ehpriv);
        let Tropic01
        {
            mut spi,
            mut wait,
            mut l2,
            l3,
            state: _,
        } = self;
        match handshake_exchange(&mut spi, &mut wait, &mut l2, &cfg, &ehpub)
        {
            Ok(keys) => Ok(Tropic01
            {
                spi,
                wait,
                l2,
                l3,
                state: ActiveSession::new(keys),
            }),
            Err(e) =>
            {
                // Clear any handshake bytes left in the L2 buffer on failure.
                l2.zeroize();
                Err((
                    Tropic01
                    {
                        spi,
                        wait,
                        l2,
                        l3,
                        state: NoSession,
                    },
                    e,
                ))
            }
        }
    }
}

/// Sends the handshake request and derives the session keys from the response.
fn handshake_exchange<SPI, W>
(
    spi: &mut SPI,
    wait: &mut W,
    l2: &mut [u8],
    cfg: &SessionConfig<'_>,
    ehpub: &[u8; 32],
)
-> Result<SessionKeys, SeError>
where
    SPI: SpiDevice,
    W: SeWait,
{
    // Handshake_Req body = EHPUB(32) || PKEY_INDEX(1).
    let mut body = [0u8; 33];
    body[..32].copy_from_slice(ehpub);
    body[32] = cfg.pkey_index;
    let n = frame::build_request(L2ReqId::Handshake as u8, &body, l2)?;
    l1::send_request(spi, &l2[..n]).map_err(L2Error::from)?;
    let frame_len = l1::read_response(spi, wait, l2).map_err(L2Error::from)?;
    let resp = frame::parse_response(&l2[..frame_len])?;
    // The handshake response is a single, complete frame. A continuation status
    // (`*Cont`) is anomalous here and must not be accepted.
    if matches!(resp.status, L2Status::RequestCont | L2Status::ResultCont)
    {
        return Err(SeError::L2(L2Error::BadFrame));
    }
    let (etpub, t_tauth) = parse_handshake_resp(resp.data)?;
    let keys = handshake::run
    (
        cfg.ehpriv,
        ehpub,
        cfg.shipriv,
        cfg.shipub,
        cfg.stpub,
        cfg.pkey_index,
        &etpub,
        &t_tauth,
    )?;
    Ok(keys)
}
