//! Bootloader (Start-up / Maintenance Mode) operations: chip firmware update.
//!
//! Reachable only from the `Bootloader` type-state, entered from `NoSession`
//! via `enter_bootloader` (a `MaintenanceReboot` `Startup_Req`) and left via
//! `exit_to_application` (a plain `Reboot`). It carries the two L2 firmware
//! primitives (`Mutable_FW_Update` 0xB0 and `Mutable_FW_Update_Data` 0xB1), the
//! `FwImageChunks` blob decoder, `fw_bank_into` (Start-up only), and the linear
//! `update_firmware` orchestrator that mirrors libtropic `lt_do_mutable_fw_update`.
//!
//! FAITHFUL TRANSPORT: the driver relays the firmware image's REQ_DATA
//! byte-for-byte. It never parses the image's internal type/offset/version/hash
//! fields. It validates only the framing LENGTH bounds needed for safe wire
//! framing. The chip's own signature check validates the payload semantics.
//!
//! SECURITY: this whole surface is NOT silicon-validated. The official TROPIC01
//! emulator models none of the bootloader, so the host tests are golden
//! request-byte assertions plus review, weaker than the model-backed command
//! tranches. A power-fault test on real hardware (interrupt an update mid-write
//! and confirm the chip's dual-bank design leaves a bootable bank) is a HARD
//! GATE before any production use. The chip is dual-bank, so an aborted or
//! rejected update is recoverable (no brick), but that is the CHIP's guarantee,
//! not something this driver can assert on untested silicon.

use embedded_hal::spi::SpiDevice;

use crate::buf::L2_CHUNK_MAX_DATA;
use crate::error::FwImageError;
use crate::error::L2Error;
use crate::error::SeError;
use crate::ids::L2ReqId;
use crate::ids::L2Status;
use crate::ids::ObjectId;
use crate::l1;
use crate::l2::frame;
use crate::parse::take;
use crate::parse::take_le_u32;
use crate::parse::take_u8;
use crate::wait::SeWait;

use super::nosession::get_info_block_raw;
use super::nosession::send_startup;
use super::Bootloader;
use super::FwBankId;
use super::NoSession;
use super::StartupId;
use super::Tropic01;

/// `Mutable_FW_Update_Req` (0xB0) REQ_DATA length in bytes.
///
/// Layout: `signature[64] || hash[32] || type[2] || padding[1] ||
/// header_ver[1] || version[4]` = 104. Source: libtropic `lt_mutable_fw_update`.
const MUTABLE_FW_UPDATE_REQ_LEN: usize = 104;

/// Minimum `Mutable_FW_Update_Data_Req` (0xB1) REQ_DATA length in bytes.
///
/// Layout: `hash[32] || offset[2] || data[>=1]`. The hash is the SHA-256 of the
/// next chunk (32 zero bytes on the last chunk). The driver relays it verbatim.
/// Source: libtropic `lt_mutable_fw_update_data`.
const MUTABLE_FW_DATA_MIN: usize = 32 + 2 + 1;

/// Maximum signed firmware-image blob length in bytes.
///
/// Source: libtropic `TR01_MUTABLE_FW_UPDATE_SIZE_MAX`.
const FW_IMAGE_MAX: usize = 30720;

/// Minimum signed firmware-image blob length in bytes.
///
/// The first 105 bytes are the chunk-0 frame: `blob[0] = 0x68` (the 104-byte
/// length prefix) || the 104-byte 0xB0 REQ_DATA. Anything shorter cannot hold a
/// header chunk. Source: libtropic `lt_do_mutable_fw_update` blob layout.
const FW_IMAGE_MIN: usize = 1 + MUTABLE_FW_UPDATE_REQ_LEN;

/// Byte offset of the `version` u32 (LE) inside the 104-byte 0xB0 REQ_DATA.
///
/// Layout: `signature[64] || hash[32] || type[2] || padding[1] ||
/// header_version[1] || version[4]`, so the version starts at 64+32+2+1+1 = 100
/// and spans bytes 100..104. Source: libtropic `lt_mutable_fw_update` header.
const IMAGE_VERSION_OFFSET: usize = 100;

/// Exact FW_BANK Get_Info BOOT_V2 header length in bytes.
///
/// `validate_fw_ver_in_bank` reads the bank ONLY as the BOOT_V2 header and
/// rejects any other size: a 20-byte BOOT_V1 or a 0-byte empty bank fails.
/// Source: libtropic `TR01_L2_GET_INFO_FW_HEADER_SIZE_BOOT_V2`.
const FW_BANK_HEADER_LEN: usize = 52;

/// Byte offset of the `ver` u32 (LE) inside the 52-byte BOOT_V2 bank header.
///
/// Source: libtropic `validate_fw_ver_in_bank` (libtropic.c:1987), which reads
/// `ver` at header offset 4 (bytes 4..8).
const BANK_VERSION_OFFSET: usize = 4;

// The minimum blob is definitionally the 1-byte chunk-0 length prefix plus the
// 0xB0 header. Lock the two constants together so they cannot drift apart.
const _: () = assert!(FW_IMAGE_MIN == 1 + MUTABLE_FW_UPDATE_REQ_LEN);

/// Decodes a length-prefixed signed firmware image into its on-wire chunks.
///
/// The image is a UNIFORM stream `[len_byte][len_byte bytes of REQ_DATA]*`. By
/// the libtropic blob layout the FIRST chunk is the 0xB0 header REQ_DATA (104
/// bytes for a valid image) and every LATER chunk is a 0xB1 data REQ_DATA. The
/// iterator does not interpret that role, it only splits the length-prefixed
/// bytes. The yielded slice is each chunk's REQ_DATA (the bytes AFTER the length
/// prefix), to relay verbatim: pass the first to `mutable_fw_update` and the
/// rest to `mutable_fw_update_data` (or just call `update_firmware`).
///
/// FAITHFUL TRANSPORT: this validates only the length framing. It does not
/// interpret any field inside a chunk. It is attacker-facing (the blob is the
/// untrusted update payload), so it MUST never panic: every read goes through
/// the bounded `parse` combinators, and a truncated prefix FUSES the iterator.
pub struct FwImageChunks<'a>
{
    blob: &'a [u8],
    pos: usize,
}

impl<'a> FwImageChunks<'a>
{
    /// Builds a chunk iterator over a signed firmware-image blob.
    ///
    /// # Errors
    ///
    /// `FwImageError::TooLong` when `blob` exceeds `FW_IMAGE_MAX` (30720), and
    /// `FwImageError::TooShort` when it is below `FW_IMAGE_MIN` (105, the header
    /// chunk). Both are checked up front, before any iteration.
    pub fn new(blob: &'a [u8]) -> Result<Self, FwImageError>
    {
        if blob.len() > FW_IMAGE_MAX
        {
            return Err(FwImageError::TooLong);
        }
        if blob.len() < FW_IMAGE_MIN
        {
            return Err(FwImageError::TooShort);
        }
        Ok(FwImageChunks
        {
            blob,
            pos: 0,
        })
    }
}

impl<'a> Iterator for FwImageChunks<'a>
{
    type Item = Result<&'a [u8], FwImageError>;

    fn next(&mut self) -> Option<Self::Item>
    {
        // A fully consumed (or fused) blob yields no more chunks.
        let tail = self.blob.get(self.pos..)?;
        if tail.is_empty()
        {
            return None;
        }
        // The first byte is the length prefix, the chunk spans prefix + that
        // many bytes. Read it through the bounded combinators only.
        let (rest, prefix) = match take_u8(tail)
        {
            Ok(v) => v,
            Err(_) =>
            {
                // Unreachable in practice (tail is non-empty), but fail closed
                // and fuse rather than ever panic on attacker input.
                self.pos = self.blob.len();
                return Some(Err(FwImageError::Truncated));
            }
        };
        let copy_len = prefix as usize;
        // `rest` is the bytes after the prefix. The REQ_DATA is the first
        // `copy_len` of them. A prefix that runs past the end is a truncated
        // chunk: yield the error and FUSE so a later next() returns None.
        match take(rest, copy_len)
        {
            Ok((reqdata, _)) =>
            {
                // Advance past the prefix byte and the REQ_DATA it framed.
                self.pos += 1 + copy_len;
                Some(Ok(reqdata))
            }
            Err(_) =>
            {
                self.pos = self.blob.len();
                Some(Err(FwImageError::Truncated))
            }
        }
    }
}

impl<SPI, W> Tropic01<SPI, W, NoSession>
where
    SPI: SpiDevice,
    W: SeWait,
{
    /// Reboots the chip into Start-up (Maintenance) Mode for firmware update.
    ///
    /// Consumes the handle and sends a `MaintenanceReboot` `Startup_Req`. On
    /// success the chip stays in Start-up Mode (Application FW not loaded) and
    /// the returned `Bootloader` handle gates the 0xB0/0xB1 update primitives.
    /// Mirrors the maintenance-reboot step of libtropic `lt_do_mutable_fw_update`.
    ///
    /// # Errors
    ///
    /// On failure returns the `NoSession` handle plus the error (a bus fault or
    /// an unexpected acknowledgement), so the caller keeps the handle without
    /// rebuilding the device.
    #[expect(
        clippy::result_large_err,
        reason = "the handle is a large static singleton moved by value through \
                  this type-state transition. Returning it on the error path lets \
                  the caller keep it, and boxing is impossible under no_std/no heap."
    )]
    pub fn enter_bootloader
    (
        mut self,
    )
    -> Result<Tropic01<SPI, W, Bootloader>, (Self, SeError)>
    {
        match send_startup(&mut self.spi, &mut self.wait, &mut self.l2, StartupId::MaintenanceReboot)
        {
            Ok(()) =>
            {
                let Tropic01
                {
                    spi,
                    wait,
                    l2,
                    l3,
                    state: _,
                } = self;
                Ok(Tropic01
                {
                    spi,
                    wait,
                    l2,
                    l3,
                    state: Bootloader,
                })
            }
            Err(e) => Err((self, e)),
        }
    }

    /// Runs a full chip firmware update in one call, returning to `NoSession`.
    ///
    /// Parity with libtropic `lt_do_mutable_fw_update`. Enters the bootloader,
    /// drives both bank pairs (with the crucial anti-downgrade reboot between
    /// them), then exits to Application Mode and confirms the running firmware
    /// versions EQUAL the expected image versions.
    ///
    /// SECURITY: on any error the chip MAY remain in Start-up (Maintenance)
    /// Mode. The returned handle is `NoSession` by convention (a marker swap, no
    /// I/O), so the caller must call `chip_mode()` to learn the real state and
    /// recover. The chip is dual-bank, so a failed update does not brick it.
    ///
    /// # Errors
    ///
    /// On failure returns the `NoSession` handle plus the error. The error is a
    /// bus fault, an update-primitive rejection (including a chip `GenErr` on a
    /// bad signature or a version downgrade), a malformed reply,
    /// `SeError::Image(_)` when an image blob fails to decode,
    /// `SeError::FwUpdateIncomplete` when a written bank did not take the 52-byte
    /// BOOT_V2 form, or `SeError::FwVersionMismatch` when a bank or the
    /// post-reboot running version does not equal the expected image version.
    #[expect(
        clippy::result_large_err,
        reason = "the handle is a large static singleton moved by value through \
                  this type-state transition. Returning it on the error path lets \
                  the caller keep it, and boxing is impossible under no_std/no heap."
    )]
    pub fn update_firmware
    (
        self,
        cpu_image: &[u8],
        spect_image: &[u8],
    )
    -> Result<Tropic01<SPI, W, NoSession>, (Self, SeError)>
    {
        let mut bl = self.enter_bootloader()?;
        // The bootloader decodes the two image versions once and returns them, so
        // the post-reboot running-version check below reuses them instead of
        // decoding the blobs a second time.
        let (cpu_version, spect_version) = match bl.update_firmware(cpu_image, spect_image)
        {
            Ok(versions) => versions,
            // The update failed: this is a pure type-marker swap, no I/O. The
            // chip may still be in maintenance. Try to leave it regardless, then
            // surface the original error with a NoSession handle.
            Err(e) => return Err((exit_then_relabel(bl), e)),
        };
        // Both bank pairs are updated. Leave maintenance and verify the running
        // firmware is live.
        let mut ns = match bl.exit_to_application()
        {
            Ok(ns) => ns,
            // Pure type-marker swap, no I/O. The chip may still be in maintenance.
            Err((bl2, e)) => return Err((relabel_as_nosession(bl2), e)),
        };
        // Post-reboot confirmation, mirroring libtropic (libtropic.c:2125): read
        // the running RISC-V and SPECT versions as LE u32s and require PLAIN
        // EQUALITY with the expected image versions. The driver is a faithful
        // transport: it relays the raw version bytes and interprets them ONLY
        // here, for the equality check.
        match (ns.riscv_fw_version(), ns.spect_fw_version())
        {
            (Ok(riscv), Ok(spect)) =>
            {
                if u32::from_le_bytes(riscv) != cpu_version
                    || u32::from_le_bytes(spect) != spect_version
                {
                    return Err((ns, SeError::FwVersionMismatch));
                }
                Ok(ns)
            }
            (Err(e), _) | (_, Err(e)) => Err((ns, e)),
        }
    }
}

impl<SPI, W> Tropic01<SPI, W, Bootloader>
where
    SPI: SpiDevice,
    W: SeWait,
{
    /// Reboots the chip into Application Mode, returning to `NoSession`.
    ///
    /// Consumes the handle and sends a plain `Reboot` `Startup_Req`, loading the
    /// Application FW. Call this after an update completes, L3 commands and the
    /// secure channel live in Application Mode. Mirrors the final reboot of
    /// libtropic `lt_do_mutable_fw_update`.
    ///
    /// # Errors
    ///
    /// On failure returns the `Bootloader` handle plus the error (a bus fault or
    /// an unexpected acknowledgement), so the caller keeps the handle.
    #[expect(
        clippy::result_large_err,
        reason = "the handle is a large static singleton moved by value through \
                  this type-state transition. Returning it on the error path lets \
                  the caller keep it, and boxing is impossible under no_std/no heap."
    )]
    pub fn exit_to_application
    (
        mut self,
    )
    -> Result<Tropic01<SPI, W, NoSession>, (Self, SeError)>
    {
        match send_startup(&mut self.spi, &mut self.wait, &mut self.l2, StartupId::Reboot)
        {
            Ok(()) =>
            {
                let Tropic01
                {
                    spi,
                    wait,
                    l2,
                    l3,
                    state: _,
                } = self;
                Ok(Tropic01
                {
                    spi,
                    wait,
                    l2,
                    l3,
                    state: NoSession,
                })
            }
            Err(e) => Err((self, e)),
        }
    }

    /// Sends a `Mutable_FW_Update_Req` (0xB0) carrying the image header.
    ///
    /// `header` is the 104-byte 0xB0 REQ_DATA (signature || hash || type ||
    /// padding || header_version || version), relayed verbatim. The chip
    /// auto-selects and erases the target bank. Available only in Start-up
    /// (Maintenance) Mode.
    ///
    /// FAITHFUL TRANSPORT: the driver validates only `header.len() == 104`. It
    /// does not parse any field. The chip's signature check validates the
    /// payload.
    ///
    /// # Errors
    ///
    /// `SeError::InvalidArgument` when `header` is not exactly 104 bytes
    /// (recoverable, no chip traffic). `SeError::L2(L2Error::Status(_))` on a
    /// non-OK chip status, including `GenErr` for a bad signature or a version
    /// downgrade (recoverable: the chip stays in maintenance, dual-bank, no
    /// brick). `SeError::L2(L2Error::BadFrame)` on any ack that is not an empty
    /// `RequestOk`. Otherwise `SeError` on a bus fault.
    pub fn mutable_fw_update(&mut self, header: &[u8]) -> Result<(), SeError>
    {
        if header.len() != MUTABLE_FW_UPDATE_REQ_LEN
        {
            return Err(SeError::InvalidArgument);
        }
        let n = frame::build_request(L2ReqId::MutableFwUpdate as u8, header, &mut self.l2)?;
        l1::send_request(&mut self.spi, &self.l2[..n]).map_err(L2Error::from)?;
        let frame_len =
            l1::read_response(&mut self.spi, &mut self.wait, &mut self.l2).map_err(L2Error::from)?;
        let resp = frame::parse_response(&self.l2[..frame_len])?;
        // A successful 0xB0 is acknowledged with an empty RequestOk frame.
        if !matches!(resp.status, L2Status::RequestOk) || !resp.data.is_empty()
        {
            return Err(SeError::L2(L2Error::BadFrame));
        }
        Ok(())
    }

    /// Sends a `Mutable_FW_Update_Data_Req` (0xB1) carrying one image chunk.
    ///
    /// `chunk` is the 0xB1 REQ_DATA (`hash[32]` of the next chunk, 32 zero bytes
    /// on the last chunk, || `offset[2]` || data), relayed verbatim. Available
    /// only in Start-up (Maintenance) Mode.
    ///
    /// FAITHFUL TRANSPORT: the driver validates only the length bounds. It does
    /// NOT enforce the data field's documented 4-byte alignment: that is a
    /// payload-semantics rule the chip's own signature already covers, and
    /// enforcing it here would parse the image, breaking the pure-transport
    /// contract.
    ///
    /// # Errors
    ///
    /// `SeError::InvalidArgument` when `chunk.len()` is below
    /// `MUTABLE_FW_DATA_MIN` (35: hash32 + offset2 + >=1 data) or above
    /// `L2_CHUNK_MAX_DATA` (252, the L2 frame cap), recoverable with no chip
    /// traffic. `SeError::L2(L2Error::Status(_))` on a non-OK chip status
    /// (recoverable). `SeError::L2(L2Error::BadFrame)` on any ack that is not an
    /// empty `RequestOk`. Otherwise `SeError` on a bus fault.
    pub fn mutable_fw_update_data(&mut self, chunk: &[u8]) -> Result<(), SeError>
    {
        if chunk.len() < MUTABLE_FW_DATA_MIN || chunk.len() > L2_CHUNK_MAX_DATA
        {
            return Err(SeError::InvalidArgument);
        }
        let n = frame::build_request(L2ReqId::MutableFwUpdateData as u8, chunk, &mut self.l2)?;
        l1::send_request(&mut self.spi, &self.l2[..n]).map_err(L2Error::from)?;
        let frame_len =
            l1::read_response(&mut self.spi, &mut self.wait, &mut self.l2).map_err(L2Error::from)?;
        let resp = frame::parse_response(&self.l2[..frame_len])?;
        // A successful 0xB1 is acknowledged with an empty RequestOk frame.
        if !matches!(resp.status, L2Status::RequestOk) || !resp.data.is_empty()
        {
            return Err(SeError::L2(L2Error::BadFrame));
        }
        Ok(())
    }

    /// Reads the FW_BANK header for `bank` into `out`, returning its length.
    ///
    /// Reuses the shared `Get_Info` block read. The bank header is variable
    /// length: 0 (empty bank), 20, or 52 bytes. Supported only in Start-up
    /// (Maintenance) Mode, which is exactly this type-state. Mirrors
    /// `NoSession::fw_bank_into`.
    ///
    /// # Errors
    ///
    /// `SeError::BufferTooSmall` when `out` is shorter than the returned data.
    /// Otherwise `SeError` on a bus fault or a header whose length is not 0, 20,
    /// or 52 bytes.
    pub fn fw_bank_into(&mut self, bank: FwBankId, out: &mut [u8]) -> Result<usize, SeError>
    {
        fw_bank_validated(&mut self.spi, &mut self.wait, &mut self.l2, bank, out)
    }

    /// Reads `bank`'s `ver` u32 (LE), requiring the full 52-byte BOOT_V2 header.
    ///
    /// Mirrors libtropic `validate_fw_ver_in_bank`: the bank is read ONLY as the
    /// 52-byte BOOT_V2 header. A 20-byte BOOT_V1 record or a 0-byte empty bank is
    /// NOT a valid version source, so anything other than exactly 52 bytes fails
    /// as `FwUpdateIncomplete` (the update did not take effect). The `ver` u32
    /// lives at header offset 4 and is read through the bounded combinators.
    ///
    /// # Errors
    ///
    /// `SeError::FwUpdateIncomplete` when the bank header is not exactly 52 bytes.
    /// Otherwise the error from `fw_bank_into` (a bus fault or a malformed reply).
    fn bank_version(&mut self, bank: FwBankId) -> Result<u32, SeError>
    {
        let mut header = [0u8; FW_BANK_HEADER_LEN];
        let n = self.fw_bank_into(bank, &mut header)?;
        // Require the full BOOT_V2 header: a shorter (BOOT_V1 or empty) record
        // carries no comparable version, so the update did not take effect.
        if n != FW_BANK_HEADER_LEN
        {
            return Err(SeError::FwUpdateIncomplete);
        }
        // Skip to the `ver` field, then take it as a LE u32. Both reads are
        // bounded. The length check above already guarantees they succeed.
        let (_, after) = take(&header, BANK_VERSION_OFFSET)?;
        let (_, version) = take_le_u32(after)?;
        Ok(version)
    }

    /// Updates both chip firmware bank pairs from CPU and SPECT images.
    ///
    /// Linear and reviewable, mirroring libtropic `lt_do_mutable_fw_update`:
    /// updates bank pair 1 (CPU then SPECT), performs the crucial anti-downgrade
    /// `MaintenanceReboot` (without it the chip's ACAB leaves the 2nd bank pair
    /// stale, enabling a downgrade attack), updates bank pair 2 (CPU then SPECT
    /// again), then confirms each of the four banks now carries the EXPECTED
    /// version.
    ///
    /// On ACAB the chip ignores any bank_id and picks the target bank itself.
    /// The reboot-between is what advances FW1 -> FW2. The verification mirrors
    /// libtropic `validate_fw_ver_in_bank`: it reads each bank's 52-byte BOOT_V2
    /// header and compares its `ver` u32 by PLAIN EQUALITY against the expected
    /// image version (the CPU image version for Fw1/Fw2, the SPECT image version
    /// for Spect1/Spect2). The expected versions are the chunk-0 `version` field
    /// of each image, extracted ONCE up front by the post-update VERIFY path.
    /// The RELAY path (`update_bank`) still never interprets the image. A wrong
    /// header size or a mismatching version STOPS the update.
    ///
    /// SECURITY: this stays in Start-up (Maintenance) Mode throughout. It does
    /// NOT reboot to Application until BOTH bank pairs are updated and verified.
    /// It never calls any Application reboot itself. The caller runs
    /// `exit_to_application` afterwards.
    ///
    /// On success returns the two decoded image versions as
    /// `(cpu_version, spect_version)` (the chunk-0 `version` of each image),
    /// so the caller's post-reboot running-version check reuses them without
    /// decoding the blobs a second time.
    ///
    /// # Errors
    ///
    /// `SeError::Image(_)` when an image blob fails to decode. Otherwise the
    /// error from the first failing primitive: an update-primitive rejection
    /// (including a chip `GenErr`), the anti-downgrade reboot, a bank read,
    /// `SeError::FwUpdateIncomplete` when a bank's header is not the 52-byte
    /// BOOT_V2 form, or `SeError::FwVersionMismatch` when a 52-byte bank header's
    /// `ver` does not equal the expected image version.
    pub fn update_firmware
    (
        &mut self,
        cpu_image: &[u8],
        spect_image: &[u8],
    )
    -> Result<(u32, u32), SeError>
    {
        // VERIFY input: the expected versions are the chunk-0 `version` of each
        // image, decoded once up front (the only field VERIFY reads). Decoding
        // here also fails fast on a malformed blob before any chip traffic.
        let cpu_version = image_version(cpu_image)?;
        let spect_version = image_version(spect_image)?;
        // Bank pair 1.
        self.update_bank(cpu_image)?;
        self.update_bank(spect_image)?;
        // The crucial anti-downgrade reboot: stay in maintenance (the chip's
        // ACAB advances FW1 -> FW2 only across this reboot).
        send_startup(&mut self.spi, &mut self.wait, &mut self.l2, StartupId::MaintenanceReboot)?;
        // Bank pair 2.
        self.update_bank(cpu_image)?;
        self.update_bank(spect_image)?;
        // Confirm each bank's installed version equals the expected image
        // version (CPU image for the FW banks, SPECT image for the SPECT banks),
        // mirroring libtropic validate_fw_ver_in_bank. A wrong header size or a
        // mismatch means the update did not take effect.
        for (bank, expected) in
        [
            (FwBankId::Fw1, cpu_version),
            (FwBankId::Spect1, spect_version),
            (FwBankId::Fw2, cpu_version),
            (FwBankId::Spect2, spect_version),
        ]
        {
            // A wrong header SIZE stays FwUpdateIncomplete (raised inside
            // bank_version): the bank was not promoted to a BOOT_V2 header. A
            // 52-byte header whose `ver` differs is a version mismatch.
            if self.bank_version(bank)? != expected
            {
                return Err(SeError::FwVersionMismatch);
            }
        }
        Ok((cpu_version, spect_version))
    }

    /// Sends one image's 0xB0 header then all its 0xB1 data chunks.
    ///
    /// Decodes the blob into chunks and encodes the ORDERING rule: the first
    /// decoded chunk is the 0xB0 header REQ_DATA. Every later chunk is a 0xB1 data
    /// REQ_DATA. The header length (104) is enforced by `mutable_fw_update` and
    /// each chunk length by `mutable_fw_update_data`.
    ///
    /// # Errors
    ///
    /// `SeError::Image(_)` when the blob fails to decode (bad length or a
    /// truncated chunk). Otherwise the error from the first failing primitive.
    fn update_bank(&mut self, image: &[u8]) -> Result<(), SeError>
    {
        let mut chunks = FwImageChunks::new(image)?;
        // The first chunk is the 0xB0 header REQ_DATA. A blob that passed
        // FwImageChunks::new is at least 105 bytes, so a header always exists.
        // A missing one is still mapped to a typed Image error, never unwrapped.
        let header = chunks.next().ok_or(SeError::Image(FwImageError::TooShort))??;
        self.mutable_fw_update(header)?;
        for chunk in chunks
        {
            self.mutable_fw_update_data(chunk?)?;
        }
        Ok(())
    }
}

/// Extracts the chunk-0 `version` u32 (LE) from a signed firmware-image blob.
///
/// Decodes the blob into its on-wire chunks and reads the FIRST chunk (the
/// 104-byte 0xB0 header REQ_DATA), then takes the 4-byte `version` at offset 100
/// as a little-endian u32. This is the ONLY field the post-update VERIFY needs.
/// The RELAY path (`update_bank`) never interprets the image. The read uses the
/// bounded combinators, so a malformed blob yields a typed error, never a panic.
///
/// # Errors
///
/// `SeError::Image(_)` when the blob fails to decode (bad length or a truncated
/// or too-short header chunk that cannot hold the version field).
pub(crate) fn image_version(image: &[u8]) -> Result<u32, SeError>
{
    let mut chunks = FwImageChunks::new(image)?;
    // The first chunk is the 0xB0 header REQ_DATA. A blob that passed
    // FwImageChunks::new holds at least the 104-byte header, but map a missing
    // chunk to a typed Image error rather than ever unwrapping.
    let header = chunks.next().ok_or(SeError::Image(FwImageError::TooShort))??;
    // Skip to the version field, then take it as a LE u32. A header chunk too
    // short to reach offset 104 is a malformed image, not a panic.
    let (_, after) = take(header, IMAGE_VERSION_OFFSET)
        .map_err(|_| SeError::Image(FwImageError::TooShort))?;
    let (_, version) = take_le_u32(after)
        .map_err(|_| SeError::Image(FwImageError::TooShort))?;
    Ok(version)
}

/// Reads a FW_BANK header into `out`, validating its {0,20,52} length.
///
/// The single source of the FW_BANK read + length guard, shared by both
/// `fw_bank_into` methods (`NoSession` and `Bootloader`), since FW_BANK is
/// readable only in Start-up Mode. Returns the header byte count.
///
/// # Errors
///
/// `SeError::BufferTooSmall` when `out` is shorter than the returned data.
/// `SeError::L2(L2Error::BadFrame)` on a header whose length is not 0, 20, or 52
/// bytes. Otherwise `SeError` on a bus fault or a malformed reply.
pub(crate) fn fw_bank_validated<SPI, W>
(
    spi: &mut SPI,
    wait: &mut W,
    l2: &mut [u8],
    bank: FwBankId,
    out: &mut [u8],
)
-> Result<usize, SeError>
where
    SPI: SpiDevice,
    W: SeWait,
{
    let n = get_info_block_raw(spi, wait, l2, ObjectId::FwBank, bank.wire_byte(), out)?;
    // A FW_BANK header is empty, or a 20- or 52-byte record. Any other length is
    // a structural anomaly. Sizes from libtropic
    // TR01_L2_GET_INFO_FW_HEADER_SIZE_BOOT_V2_EMPTY_BANK (0) / _BOOT_V1 (20) /
    // _BOOT_V2 (52).
    if n != 0 && n != 20 && n != 52
    {
        return Err(SeError::L2(L2Error::BadFrame));
    }
    Ok(n)
}

/// Relabels a `Bootloader` handle as a `NoSession` handle with no I/O.
///
/// A pure type-state marker swap, local to the `update_firmware` failure path.
fn relabel_as_nosession<SPI, W>(bl: Tropic01<SPI, W, Bootloader>) -> Tropic01<SPI, W, NoSession>
{
    let Tropic01
    {
        spi,
        wait,
        l2,
        l3,
        state: _,
    } = bl;
    Tropic01
    {
        spi,
        wait,
        l2,
        l3,
        state: NoSession,
    }
}

/// Best-effort exit to Application after an update failure, then relabel.
///
/// Attempts `exit_to_application`. Whether it succeeds or fails, the resulting
/// handle is relabeled to `NoSession` (the chip's real mode is uncertain after
/// a failed update, so the caller uses `chip_mode()` to recover).
fn exit_then_relabel<SPI, W>
(
    bl: Tropic01<SPI, W, Bootloader>,
)
-> Tropic01<SPI, W, NoSession>
where
    SPI: SpiDevice,
    W: SeWait,
{
    match bl.exit_to_application()
    {
        Ok(ns) => ns,
        Err((bl2, _)) => relabel_as_nosession(bl2),
    }
}

#[cfg(test)]
#[path = "bootloader_tests.rs"]
mod tests;
