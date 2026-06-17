//! Host unit tests for the bootloader (firmware-update) surface.
//!
//! The official TROPIC01 emulator models none of the bootloader, so validation
//! is golden REQUEST-BYTE assertions (via `RecordingSpi`/`FwUpdateSpi`) plus
//! primitive bound checks and the no-panic blob-iterator proof. There is no
//! model round-trip here, by design.

use super::FwImageChunks;
use super::FwImageError;
use crate::error::L2Error;
use crate::error::SeError;
use crate::ids::L2ReqId;
use crate::ids::L2Status;
use crate::test_support::l2_frame;
use crate::test_support::FwUpdateSpi;
use crate::test_support::MockWait;
use crate::test_support::RecordingSpi;
use crate::Tropic01;

/// The 104-byte golden 0xB0 REQ_DATA from the spec.
fn golden_b0_reqdata() -> std::vec::Vec<u8>
{
    let mut v = std::vec::Vec::new();
    v.extend(core::iter::repeat_n(0x01u8, 64)); // signature
    v.extend(core::iter::repeat_n(0x02u8, 32)); // hash
    v.extend_from_slice(&[0x01, 0x00]); // type
    v.push(0x00); // padding
    v.push(0x01); // header_version
    v.extend_from_slice(&[0x00, 0x00, 0x00, 0x02]); // version
    assert_eq!(v.len(), 104);
    v
}

/// The 38-byte golden 0xB1 REQ_DATA from the spec.
fn golden_b1_reqdata() -> std::vec::Vec<u8>
{
    let mut v = std::vec::Vec::new();
    v.extend(core::iter::repeat_n(0x0Au8, 32)); // hash of next chunk
    v.extend_from_slice(&[0x40, 0x00]); // offset
    v.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // data
    assert_eq!(v.len(), 38);
    v
}

// enter_bootloader / exit_to_application golden frames

#[test]
fn enter_bootloader_emits_maintenance_reboot_golden()
{
    let acks = std::vec![l2_frame(L2Status::RequestOk as u8, &[])];
    let dev = Tropic01::new(RecordingSpi::new(acks), MockWait::new());
    let bl = dev.enter_bootloader().map_err(|(_, e)| e).unwrap();
    // Byte-exact MaintenanceReboot Startup_Req: B3 01 03 F6 0F.
    assert_eq!(bl.spi_ref().writes()[0], std::vec![0xB3, 0x01, 0x03, 0xF6, 0x0F]);
}

#[test]
fn enter_bootloader_returns_handle_on_bad_ack()
{
    // A non-empty ack is malformed: the NoSession handle comes back with the err.
    let acks = std::vec![l2_frame(L2Status::RequestOk as u8, &[0xAA])];
    let dev = Tropic01::new(RecordingSpi::new(acks), MockWait::new());
    match dev.enter_bootloader()
    {
        Ok(_) => panic!("expected error on a non-empty ack"),
        Err((_dev, e)) => assert_eq!(e, SeError::L2(L2Error::BadFrame)),
    }
}

#[test]
fn exit_to_application_emits_reboot_golden()
{
    // Enter, then exit. The second write is the plain Reboot golden.
    let acks = std::vec![
        l2_frame(L2Status::RequestOk as u8, &[]),
        l2_frame(L2Status::RequestOk as u8, &[]),
    ];
    let dev = Tropic01::new(RecordingSpi::new(acks), MockWait::new());
    let bl = dev.enter_bootloader().map_err(|(_, e)| e).unwrap();
    let ns = bl.exit_to_application().map_err(|(_, e)| e).unwrap();
    // Byte-exact Reboot Startup_Req: B3 01 01 F9 8F.
    assert_eq!(ns.spi_ref().writes()[1], std::vec![0xB3, 0x01, 0x01, 0xF9, 0x8F]);
}

#[test]
fn exit_to_application_returns_handle_on_bad_ack()
{
    let acks = std::vec![
        l2_frame(L2Status::RequestOk as u8, &[]),
        l2_frame(L2Status::RequestCont as u8, &[]),
    ];
    let dev = Tropic01::new(RecordingSpi::new(acks), MockWait::new());
    let bl = dev.enter_bootloader().map_err(|(_, e)| e).unwrap();
    match bl.exit_to_application()
    {
        Ok(_) => panic!("expected error on a continuation ack"),
        Err((_bl, e)) => assert_eq!(e, SeError::L2(L2Error::BadFrame)),
    }
}

// mutable_fw_update (0xB0)

#[test]
fn mutable_fw_update_emits_golden_b0_frame()
{
    let acks = std::vec![
        l2_frame(L2Status::RequestOk as u8, &[]),
        l2_frame(L2Status::RequestOk as u8, &[]),
    ];
    let dev = Tropic01::new(RecordingSpi::new(acks), MockWait::new());
    let mut bl = dev.enter_bootloader().map_err(|(_, e)| e).unwrap();
    let header = golden_b0_reqdata();
    bl.mutable_fw_update(&header).unwrap();
    // Frame = B0 68 || REQDATA0 || 33 79.
    let mut expected = std::vec![0xB0u8, 0x68];
    expected.extend_from_slice(&header);
    expected.extend_from_slice(&[0x33, 0x79]);
    assert_eq!(bl.spi_ref().writes()[1], expected);
}

#[test]
fn mutable_fw_update_rejects_wrong_header_len()
{
    let acks = std::vec![l2_frame(L2Status::RequestOk as u8, &[])];
    let dev = Tropic01::new(RecordingSpi::new(acks), MockWait::new());
    let mut bl = dev.enter_bootloader().map_err(|(_, e)| e).unwrap();
    // 103 and 105 are both rejected with no chip traffic.
    assert_eq!(bl.mutable_fw_update(&[0u8; 103]), Err(SeError::InvalidArgument));
    assert_eq!(bl.mutable_fw_update(&[0u8; 105]), Err(SeError::InvalidArgument));
}

#[test]
fn mutable_fw_update_surfaces_gen_err_recoverably()
{
    // A bad signature or version downgrade is a GenErr the chip reports while
    // staying in maintenance. It surfaces as a recoverable L2 status error.
    let acks = std::vec![
        l2_frame(L2Status::RequestOk as u8, &[]),
        l2_frame(L2Status::GenErr as u8, &[]),
    ];
    let dev = Tropic01::new(RecordingSpi::new(acks), MockWait::new());
    let mut bl = dev.enter_bootloader().map_err(|(_, e)| e).unwrap();
    assert_eq!(
        bl.mutable_fw_update(&golden_b0_reqdata()),
        Err(SeError::L2(L2Error::Status(L2Status::GenErr))),
    );
}

#[test]
fn mutable_fw_update_rejects_nonempty_ack()
{
    let acks = std::vec![
        l2_frame(L2Status::RequestOk as u8, &[]),
        l2_frame(L2Status::RequestOk as u8, &[0xAA]),
    ];
    let dev = Tropic01::new(RecordingSpi::new(acks), MockWait::new());
    let mut bl = dev.enter_bootloader().map_err(|(_, e)| e).unwrap();
    assert_eq!(
        bl.mutable_fw_update(&golden_b0_reqdata()),
        Err(SeError::L2(L2Error::BadFrame)),
    );
}

// mutable_fw_update_data (0xB1)

#[test]
fn mutable_fw_update_data_emits_golden_b1_frame()
{
    let acks = std::vec![
        l2_frame(L2Status::RequestOk as u8, &[]),
        l2_frame(L2Status::RequestOk as u8, &[]),
    ];
    let dev = Tropic01::new(RecordingSpi::new(acks), MockWait::new());
    let mut bl = dev.enter_bootloader().map_err(|(_, e)| e).unwrap();
    let chunk = golden_b1_reqdata();
    bl.mutable_fw_update_data(&chunk).unwrap();
    // Frame = B1 26 || REQDATA1 || 42 AC.
    let mut expected = std::vec![0xB1u8, 0x26];
    expected.extend_from_slice(&chunk);
    expected.extend_from_slice(&[0x42, 0xAC]);
    assert_eq!(bl.spi_ref().writes()[1], expected);
}

#[test]
fn mutable_fw_update_data_rejects_short_and_long()
{
    let acks = std::vec![l2_frame(L2Status::RequestOk as u8, &[])];
    let dev = Tropic01::new(RecordingSpi::new(acks), MockWait::new());
    let mut bl = dev.enter_bootloader().map_err(|(_, e)| e).unwrap();
    // 34 bytes is below the 35-byte minimum (hash32 + offset2 + >=1 data).
    assert_eq!(bl.mutable_fw_update_data(&[0u8; 34]), Err(SeError::InvalidArgument));
    // 253 bytes exceeds the 252-byte L2 frame cap.
    assert_eq!(bl.mutable_fw_update_data(&[0u8; 253]), Err(SeError::InvalidArgument));
}

#[test]
fn mutable_fw_update_data_rejects_nonempty_ack()
{
    let acks = std::vec![
        l2_frame(L2Status::RequestOk as u8, &[]),
        l2_frame(L2Status::RequestOk as u8, &[0x01]),
    ];
    let dev = Tropic01::new(RecordingSpi::new(acks), MockWait::new());
    let mut bl = dev.enter_bootloader().map_err(|(_, e)| e).unwrap();
    assert_eq!(
        bl.mutable_fw_update_data(&golden_b1_reqdata()),
        Err(SeError::L2(L2Error::BadFrame)),
    );
}

#[test]
fn mutable_fw_update_data_surfaces_gen_err_recoverably()
{
    // A 0xB1 chunk the chip rejects with GenErr surfaces as a recoverable L2
    // status error. The chip stays in maintenance (dual-bank, no brick).
    let acks = std::vec![
        l2_frame(L2Status::RequestOk as u8, &[]),
        l2_frame(L2Status::GenErr as u8, &[]),
    ];
    let dev = Tropic01::new(RecordingSpi::new(acks), MockWait::new());
    let mut bl = dev.enter_bootloader().map_err(|(_, e)| e).unwrap();
    assert_eq!(
        bl.mutable_fw_update_data(&golden_b1_reqdata()),
        Err(SeError::L2(L2Error::Status(L2Status::GenErr))),
    );
}

// fw_bank_into (Get_Info FW_BANK, Start-up only)

#[test]
fn fw_bank_into_accepts_valid_lengths()
{
    for len in [0usize, 20, 52]
    {
        let payload = std::vec![0xCDu8; len];
        let acks = std::vec![
            l2_frame(L2Status::RequestOk as u8, &[]),
            l2_frame(L2Status::RequestOk as u8, &payload),
        ];
        let dev = Tropic01::new(RecordingSpi::new(acks), MockWait::new());
        let mut bl = dev.enter_bootloader().map_err(|(_, e)| e).unwrap();
        let mut out = [0u8; 64];
        assert_eq!(bl.fw_bank_into(super::super::FwBankId::Fw1, &mut out).unwrap(), len);
    }
}

#[test]
fn fw_bank_into_rejects_odd_length()
{
    let acks = std::vec![
        l2_frame(L2Status::RequestOk as u8, &[]),
        l2_frame(L2Status::RequestOk as u8, &[0u8; 21]),
    ];
    let dev = Tropic01::new(RecordingSpi::new(acks), MockWait::new());
    let mut bl = dev.enter_bootloader().map_err(|(_, e)| e).unwrap();
    let mut out = [0u8; 64];
    assert_eq!(
        bl.fw_bank_into(super::super::FwBankId::Spect2, &mut out),
        Err(SeError::L2(L2Error::BadFrame)),
    );
}

// FwImageChunks blob iterator

/// Builds a signed-image blob: a 104-byte header chunk plus `data_chunks`,
/// each prefixed with its length byte.
fn build_image(header: &[u8], data_chunks: &[&[u8]]) -> std::vec::Vec<u8>
{
    let mut blob = std::vec::Vec::new();
    blob.push(header.len() as u8);
    blob.extend_from_slice(header);
    for c in data_chunks
    {
        blob.push(c.len() as u8);
        blob.extend_from_slice(c);
    }
    blob
}

#[test]
fn fw_image_chunks_walks_boundaries()
{
    let header = golden_b0_reqdata();
    let mid: [u8; 40] = [0x55; 40];
    let last = golden_b1_reqdata();
    let blob = build_image(&header, &[&mid, &last]);
    let chunks: std::vec::Vec<_> = FwImageChunks::new(&blob)
        .unwrap()
        .map(|r| r.unwrap().to_vec())
        .collect();
    assert_eq!(chunks.len(), 3);
    // Chunk 0 is the 104-byte header REQ_DATA.
    assert_eq!(chunks[0].len(), 104);
    assert_eq!(chunks[0], header);
    // A middle data chunk.
    assert_eq!(chunks[1], &mid);
    // The last chunk relayed verbatim.
    assert_eq!(chunks[2], last);
}

#[test]
fn fw_image_chunks_relays_all_zero_hash_last_chunk()
{
    // The last chunk carries a 32-zero-byte hash. The decoder relays it as-is.
    let header = golden_b0_reqdata();
    let mut last = std::vec::Vec::new();
    last.extend(core::iter::repeat_n(0u8, 32)); // zero hash
    last.extend_from_slice(&[0x00, 0x00]); // offset
    last.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]); // data
    let blob = build_image(&header, &[&last]);
    let chunks: std::vec::Vec<_> = FwImageChunks::new(&blob)
        .unwrap()
        .map(|r| r.unwrap().to_vec())
        .collect();
    assert_eq!(chunks.len(), 2);
    assert!(chunks[1][..32].iter().all(|&b| b == 0));
    assert_eq!(chunks[1], last);
}

#[test]
fn fw_image_chunks_rejects_too_long()
{
    let blob = std::vec![0u8; 30721];
    assert_eq!(FwImageChunks::new(&blob).err(), Some(FwImageError::TooLong));
}

#[test]
fn fw_image_chunks_rejects_too_short()
{
    let blob = std::vec![0u8; 104];
    assert_eq!(FwImageChunks::new(&blob).err(), Some(FwImageError::TooShort));
}

#[test]
fn fw_image_chunks_truncated_yields_error_then_fuses()
{
    // A header chunk, then a length prefix claiming 40 bytes but only 10 follow.
    let header = golden_b0_reqdata();
    let mut blob = std::vec::Vec::new();
    blob.push(header.len() as u8);
    blob.extend_from_slice(&header);
    blob.push(40); // claims 40 bytes
    blob.extend(core::iter::repeat_n(0x77u8, 10)); // only 10 present
    let mut it = FwImageChunks::new(&blob).unwrap();
    // First chunk is the valid header.
    assert_eq!(it.next().unwrap().unwrap().len(), 104);
    // The truncated chunk yields Truncated.
    assert_eq!(it.next(), Some(Err(FwImageError::Truncated)));
    // Then the iterator is fused.
    assert_eq!(it.next(), None);
    assert_eq!(it.next(), None);
}

#[test]
fn fw_image_chunks_never_panics_on_truncation()
{
    // Exhaustively truncate a valid blob and fully drain. No panic.
    let header = golden_b0_reqdata();
    let last = golden_b1_reqdata();
    let blob = build_image(&header, &[&last]);
    for cut in 0..=blob.len()
    {
        if let Ok(it) = FwImageChunks::new(&blob[..cut])
        {
            for chunk in it
            {
                let _ = chunk;
            }
        }
    }
}

// update_firmware orchestration (Bootloader and one-call)

/// Builds the smallest valid CPU/SPECT image: a header chunk plus one data
/// chunk.
fn small_image() -> std::vec::Vec<u8>
{
    build_image(&golden_b0_reqdata(), &[&golden_b1_reqdata()])
}

#[test]
fn bootloader_update_firmware_drives_exact_sequence()
{
    let dev = Tropic01::new(FwUpdateSpi::new(), MockWait::new());
    let mut bl = dev.enter_bootloader().map_err(|(_, e)| e).unwrap();
    let cpu = small_image();
    let spect = small_image();
    let (_cpu_ver, _spect_ver) = bl.update_firmware(&cpu, &spect).unwrap();

    let ids = bl.spi_ref().req_ids();
    let b3 = L2ReqId::Startup as u8;
    let b0 = L2ReqId::MutableFwUpdate as u8;
    let b1 = L2ReqId::MutableFwUpdateData as u8;
    let gi = L2ReqId::GetInfo as u8;
    // enter_bootloader (B3), then bank pair 1 = [B0,B1] x2 (cpu, spect),
    // the anti-downgrade B3, bank pair 2 = [B0,B1] x2, then 4x Get_Info, and
    // NO Application reboot inside this method.
    let expected = std::vec![
        b3, // enter_bootloader
        b0, b1, // cpu bank pair 1
        b0, b1, // spect bank pair 1
        b3, // anti-downgrade maintenance reboot
        b0, b1, // cpu bank pair 2
        b0, b1, // spect bank pair 2
        gi, gi, gi, gi, // verify 4 banks
    ];
    assert_eq!(ids, expected);

    // Each Get_Info verify read targets FW_BANK (object 0xB0). No second
    // Application reboot was issued (the only B3 after enter are maintenance).
    let fw_bank = crate::ids::ObjectId::FwBank as u8;
    let gi_objects: std::vec::Vec<u8> = bl
        .spi_ref()
        .requests()
        .iter()
        .filter(|(id, _)| *id == gi)
        .filter_map(|(_, data)| data.first().copied())
        .collect();
    assert_eq!(gi_objects, std::vec![fw_bank, fw_bank, fw_bank, fw_bank]);
}

#[test]
fn bootloader_update_firmware_stops_on_mid_sequence_gen_err()
{
    // Fail the 3rd 0xB0 (the cpu header of bank pair 2). The orchestrator must
    // stop immediately and issue no later banks or any reboot.
    let mut spi = FwUpdateSpi::new();
    spi.fail_nth_b0(3);
    let dev = Tropic01::new(spi, MockWait::new());
    let mut bl = dev.enter_bootloader().map_err(|(_, e)| e).unwrap();
    let cpu = small_image();
    let spect = small_image();
    assert_eq!(
        bl.update_firmware(&cpu, &spect),
        Err(SeError::L2(L2Error::Status(L2Status::GenErr))),
    );

    let b0 = L2ReqId::MutableFwUpdate as u8;
    let gi = L2ReqId::GetInfo as u8;
    let ids = bl.spi_ref().req_ids();
    // Exactly 3 0xB0 were attempted, the 3rd failed and stopped the run.
    assert_eq!(ids.iter().filter(|&&id| id == b0).count(), 3);
    // No bank verification reads happened (the run stopped before them).
    assert_eq!(ids.iter().filter(|&&id| id == gi).count(), 0);
}

#[test]
fn nosession_update_firmware_one_call_succeeds_and_returns_to_application()
{
    let dev = Tropic01::new(FwUpdateSpi::new(), MockWait::new());
    let cpu = small_image();
    let spect = small_image();
    let ns = dev.update_firmware(&cpu, &spect).map_err(|(_, e)| e).unwrap();

    let ids = ns.spi_ref().req_ids();
    let b3 = L2ReqId::Startup as u8;
    let b0 = L2ReqId::MutableFwUpdate as u8;
    let gi = L2ReqId::GetInfo as u8;
    // Three Startup_Req total: enter (maint), anti-downgrade (maint), exit (app).
    assert_eq!(ids.iter().filter(|&&id| id == b3).count(), 3);
    // Four 0xB0 (two bank pairs), four Get_Info (bank verify) plus two more
    // Get_Info for the post-reboot version checks: six total Get_Info.
    assert_eq!(ids.iter().filter(|&&id| id == b0).count(), 4);
    assert_eq!(ids.iter().filter(|&&id| id == gi).count(), 6);
    // The last two requests are the riscv/spect version reads after the
    // Application reboot.
    assert_eq!(ids[ids.len() - 1], gi);
    assert_eq!(ids[ids.len() - 2], gi);
}

#[test]
fn nosession_update_firmware_one_call_stops_on_failure()
{
    let mut spi = FwUpdateSpi::new();
    spi.fail_nth_b0(1); // the very first cpu header fails
    let dev = Tropic01::new(spi, MockWait::new());
    let cpu = small_image();
    let spect = small_image();
    match dev.update_firmware(&cpu, &spect)
    {
        Ok(_) => panic!("expected the update to fail"),
        Err((ns, e)) =>
        {
            assert_eq!(e, SeError::L2(L2Error::Status(L2Status::GenErr)));
            // Only one 0xB0 was attempted before the stop.
            let b0 = L2ReqId::MutableFwUpdate as u8;
            assert_eq!(ns.spi_ref().req_ids().iter().filter(|&&id| id == b0).count(), 1);
            // The failure path still attempts to leave maintenance: one enter
            // plus one best-effort exit = two Startup_Req. Guards against
            // demote_on_error silently skipping the exit attempt.
            let b3 = L2ReqId::Startup as u8;
            assert_eq!(ns.spi_ref().req_ids().iter().filter(|&&id| id == b3).count(), 2);
        }
    }
}

#[test]
fn nosession_update_firmware_rejects_bad_image()
{
    // A too-short CPU image is rejected as an Image error after entering the
    // bootloader (the enter succeeds, the first update_bank fails to decode).
    let dev = Tropic01::new(FwUpdateSpi::new(), MockWait::new());
    let bad = std::vec![0u8; 50];
    let spect = small_image();
    match dev.update_firmware(&bad, &spect)
    {
        Ok(_) => panic!("expected an image-decode error"),
        Err((_ns, e)) => assert_eq!(e, SeError::Image(FwImageError::TooShort)),
    }
}

#[test]
fn nosession_update_firmware_fails_on_running_version_mismatch()
{
    // The full update succeeds and reboots to Application, but the running
    // RISC-V/SPECT version does not equal the image version: the new firmware is
    // not running, so the call reports FwVersionMismatch (not a wire error).
    let mut spi = FwUpdateSpi::new();
    spi.set_version_response([0xDE, 0xAD, 0xBE, 0xEF]); // != image version
    let dev = Tropic01::new(spi, MockWait::new());
    let cpu = small_image();
    let spect = small_image();
    match dev.update_firmware(&cpu, &spect)
    {
        Ok(_) => panic!("expected FwVersionMismatch on a running-version mismatch"),
        Err((_ns, e)) => assert_eq!(e, SeError::FwVersionMismatch),
    }
}

#[test]
fn nosession_update_firmware_demotes_on_success_path_exit_failure()
{
    // Both bank pairs update, but the final Application reboot (the 3rd B3:
    // enter, anti-downgrade, exit) fails. The handle still comes back NoSession
    // by convention, carrying the reboot error.
    let mut spi = FwUpdateSpi::new();
    spi.fail_nth_b3(3);
    let dev = Tropic01::new(spi, MockWait::new());
    let cpu = small_image();
    let spect = small_image();
    match dev.update_firmware(&cpu, &spect)
    {
        Ok(_) => panic!("expected the exit reboot to fail"),
        Err((ns, e)) =>
        {
            assert_eq!(e, SeError::L2(L2Error::Status(L2Status::GenErr)));
            // All three Startup_Req were attempted (the exit failed last).
            let b3 = L2ReqId::Startup as u8;
            assert_eq!(ns.spi_ref().req_ids().iter().filter(|&&id| id == b3).count(), 3);
        }
    }
}

#[test]
fn nosession_update_firmware_demotes_when_recovery_exit_also_fails()
{
    // The first 0xB0 fails AND the best-effort recovery exit (the 2nd B3) fails
    // too. The handle is still relabeled NoSession, carrying the original error.
    let mut spi = FwUpdateSpi::new();
    spi.fail_nth_b0(1);
    spi.fail_nth_b3(2); // enter is B3 #1 (ok); the recovery exit is B3 #2.
    let dev = Tropic01::new(spi, MockWait::new());
    let cpu = small_image();
    let spect = small_image();
    match dev.update_firmware(&cpu, &spect)
    {
        Ok(_) => panic!("expected the update to fail"),
        Err((ns, e)) =>
        {
            // The original update error is surfaced, not the recovery error.
            assert_eq!(e, SeError::L2(L2Error::Status(L2Status::GenErr)));
            // Enter plus the failed recovery exit = two Startup_Req.
            let b3 = L2ReqId::Startup as u8;
            assert_eq!(ns.spi_ref().req_ids().iter().filter(|&&id| id == b3).count(), 2);
        }
    }
}

// image_version helper and per-bank version-equality checks

#[test]
fn image_version_reads_chunk0_version_le()
{
    // The golden 0xB0 REQ_DATA carries version bytes [00,00,00,02] at offset
    // 100, little-endian, so the chunk-0 version is 0x02000000.
    let image = small_image();
    assert_eq!(super::image_version(&image).unwrap(), 0x0200_0000);
}

#[test]
fn image_version_rejects_bad_blob()
{
    // A too-short blob fails to decode before any version is read.
    let bad = std::vec![0u8; 50];
    assert_eq!(super::image_version(&bad), Err(SeError::Image(FwImageError::TooShort)));
}

#[test]
fn bootloader_update_firmware_succeeds_on_matching_versions()
{
    // The default mock reports every bank `ver` and running version equal to the
    // golden image version, so the per-bank equality check passes.
    let dev = Tropic01::new(FwUpdateSpi::new(), MockWait::new());
    let mut bl = dev.enter_bootloader().map_err(|(_, e)| e).unwrap();
    let cpu = small_image();
    let spect = small_image();
    // On success the bootloader returns the two decoded image versions (the
    // golden chunk-0 version 0x02000000 for both images).
    assert_eq!(bl.update_firmware(&cpu, &spect), Ok((0x0200_0000, 0x0200_0000)));
}

#[test]
fn bootloader_update_firmware_fails_on_bank_version_mismatch()
{
    // A 52-byte bank header whose `ver` differs from the image version stops the
    // update with FwVersionMismatch, after both bank pairs were written.
    let mut spi = FwUpdateSpi::new();
    spi.set_bank_version([0xDE, 0xAD, 0xBE, 0xEF]); // != image version
    let dev = Tropic01::new(spi, MockWait::new());
    let mut bl = dev.enter_bootloader().map_err(|(_, e)| e).unwrap();
    let cpu = small_image();
    let spect = small_image();
    assert_eq!(bl.update_firmware(&cpu, &spect), Err(SeError::FwVersionMismatch));

    // The mismatch is caught on the FIRST bank read, stopping further reads: the
    // two bank pairs were written (4x B0) and exactly one Get_Info ran.
    let b0 = L2ReqId::MutableFwUpdate as u8;
    let gi = L2ReqId::GetInfo as u8;
    let ids = bl.spi_ref().req_ids();
    assert_eq!(ids.iter().filter(|&&id| id == b0).count(), 4);
    assert_eq!(ids.iter().filter(|&&id| id == gi).count(), 1);
}

#[test]
fn bootloader_update_firmware_fails_on_wrong_bank_header_size()
{
    // A 20-byte BOOT_V1 header is not a valid version source: the version check
    // requires exactly 52 bytes, so the update reports FwUpdateIncomplete.
    let mut spi = FwUpdateSpi::new();
    spi.set_bank_header_len(20);
    let dev = Tropic01::new(spi, MockWait::new());
    let mut bl = dev.enter_bootloader().map_err(|(_, e)| e).unwrap();
    let cpu = small_image();
    let spect = small_image();
    assert_eq!(bl.update_firmware(&cpu, &spect), Err(SeError::FwUpdateIncomplete));
}
