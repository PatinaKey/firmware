//! Host unit tests for the device handle and its commands.
//!
//! Device-local types, constants, and the test-only accessors (`spi_ref`,
//! `spi_mut`, `seed_nonces`) are imported by name from the parent module.
//! Crate-internal items and the chip mock are imported explicitly.

use super::ActiveSession;
use super::ChipMode;
use super::FwBankId;
use super::NoSession;
use super::SessionConfig;
use super::StartupId;
use super::Tropic01;
use super::parse_handshake_resp;
use super::EDDSA_MSG_MAX;
use super::GET_INFO_CERT_STORE_BLOCKS;
use super::GET_INFO_CERT_STORE_LEN;
use super::R_MEM_DATA_MAX;
use crate::buf::L2_FRAME_MAX;
use crate::error::L1Error;
use crate::error::L2Error;
use crate::error::L3Error;
use crate::error::ParseError;
use crate::error::SeError;
use crate::ids::L2ReqId;
use crate::ids::L2Status;
use crate::ids::L3Status;
use crate::ids::ObjectId;
use crate::l2::frame;
use crate::port::ConfigBitIndex;
use crate::port::ConfigObjectAddr;
use crate::port::EccCurve;
use crate::port::EccSlot;
use crate::port::MCounterIdx;
use crate::port::MacAndDestroyOutput;
use crate::port::MacDestroySlot;
use crate::port::PairingKeySlot;
use crate::port::RMemSlot;
use crate::port::SeCommands;
use crate::port::Signature;
use crate::session::SessionKeys;
use crate::test_support::l2_frame;
use crate::test_support::vectors;
use crate::test_support::ChipFault;
use crate::test_support::ChipMockSpi;
use crate::test_support::GetInfoFault;
use crate::test_support::MockSpi;
use crate::test_support::MockWait;
use crate::test_support::RecordingSpi;
use crate::test_support::StatusSpi;

use zeroize::Zeroizing;

#[test]
fn reboot_request_frame_matches_libtropic_golden()
{
    // Byte-exact Startup_Req for TR01_REBOOT, captured from real libtropic:
    // REQ_ID 0xB3, REQ_LEN 1, STARTUP_ID 0x01, CRC 0xF98F.
    let mut buf = [0u8; L2_FRAME_MAX];
    let n = frame::build_request(L2ReqId::Startup as u8, &[StartupId::Reboot.wire_byte()], &mut buf)
        .unwrap();
    assert_eq!(&buf[..n], &[0xB3, 0x01, 0x01, 0xF9, 0x8F]);
    assert_eq!(StartupId::MaintenanceReboot.wire_byte(), 0x03);
}

#[test]
fn reboot_succeeds_on_empty_request_ok_ack()
{
    let acks = std::vec![l2_frame(L2Status::RequestOk as u8, &[])];
    let mut dev = Tropic01::new(RecordingSpi::new(acks), MockWait::new());
    assert!(dev.reboot(StartupId::Reboot).is_ok());
}

#[test]
fn reboot_rejects_a_nonempty_ack()
{
    // A Startup ack must carry no data. A non-empty one is a malformed reply.
    let acks = std::vec![l2_frame(L2Status::RequestOk as u8, &[0xAA])];
    let mut dev = Tropic01::new(RecordingSpi::new(acks), MockWait::new());
    assert_eq!(dev.reboot(StartupId::Reboot), Err(SeError::L2(L2Error::BadFrame)));
}

#[test]
fn reboot_rejects_a_continuation_status()
{
    // Only RequestOk acknowledges a Startup_Req. A *Cont status is anomalous.
    let acks = std::vec![l2_frame(L2Status::RequestCont as u8, &[])];
    let mut dev = Tropic01::new(RecordingSpi::new(acks), MockWait::new());
    assert_eq!(dev.reboot(StartupId::Reboot), Err(SeError::L2(L2Error::BadFrame)));
}

// Sleep (L2, NoSession)

#[test]
fn sleep_request_frame_matches_libtropic_golden()
{
    // Byte-exact Sleep_Req: REQ_ID 0x20, REQ_LEN 1, SLEEP_KIND 0x05, CRC 0x9E04.
    let acks = std::vec![l2_frame(L2Status::RequestOk as u8, &[])];
    let mut dev = Tropic01::new(RecordingSpi::new(acks), MockWait::new());
    assert!(dev.sleep().is_ok());
    assert_eq!(dev.spi_ref().writes()[0], std::vec![0x20, 0x01, 0x05, 0x9E, 0x04]);
}

#[test]
fn sleep_succeeds_on_empty_request_ok_ack()
{
    let acks = std::vec![l2_frame(L2Status::RequestOk as u8, &[])];
    let mut dev = Tropic01::new(RecordingSpi::new(acks), MockWait::new());
    assert_eq!(dev.sleep(), Ok(()));
}

#[test]
fn sleep_disabled_is_recoverable()
{
    // CFG_SLEEP_MODE off: the chip replies RespDisabled. No session exists, so
    // this surfaces via parse_response as a recoverable L2 status error.
    let acks = std::vec![l2_frame(L2Status::RespDisabled as u8, &[])];
    let mut dev = Tropic01::new(RecordingSpi::new(acks), MockWait::new());
    assert_eq!(dev.sleep(), Err(SeError::L2(L2Error::Status(L2Status::RespDisabled))));
}

#[test]
fn sleep_rejects_a_nonempty_ack()
{
    // A Sleep ack must carry no data. A non-empty one is a malformed reply.
    let acks = std::vec![l2_frame(L2Status::RequestOk as u8, &[0xAA])];
    let mut dev = Tropic01::new(RecordingSpi::new(acks), MockWait::new());
    assert_eq!(dev.sleep(), Err(SeError::L2(L2Error::BadFrame)));
}

#[test]
fn sleep_rejects_a_continuation_status()
{
    // Only RequestOk acknowledges a Sleep_Req. A *Cont status is anomalous.
    let acks = std::vec![l2_frame(L2Status::RequestCont as u8, &[])];
    let mut dev = Tropic01::new(RecordingSpi::new(acks), MockWait::new());
    assert_eq!(dev.sleep(), Err(SeError::L2(L2Error::BadFrame)));
}

// Get_Log (L2, NoSession)

#[test]
fn get_log_request_frame_matches_libtropic_golden()
{
    // Byte-exact Get_Log_Req: REQ_ID 0xA2, REQ_LEN 0, CRC 0x094C.
    let acks = std::vec![l2_frame(L2Status::RequestOk as u8, &[])];
    let mut dev = Tropic01::new(RecordingSpi::new(acks), MockWait::new());
    let mut out = [0u8; 8];
    assert_eq!(dev.get_log_into(&mut out), Ok(0));
    assert_eq!(dev.spi_ref().writes()[0], std::vec![0xA2, 0x00, 0x09, 0x4C]);
}

#[test]
fn get_log_empty_returns_zero()
{
    let acks = std::vec![l2_frame(L2Status::RequestOk as u8, &[])];
    let mut dev = Tropic01::new(RecordingSpi::new(acks), MockWait::new());
    let mut out = [0u8; 64];
    assert_eq!(dev.get_log_into(&mut out), Ok(0));
}

#[test]
fn get_log_copies_the_payload()
{
    let log = [0x11u8, 0x22, 0x33, 0x44, 0x55];
    let acks = std::vec![l2_frame(L2Status::RequestOk as u8, &log)];
    let mut dev = Tropic01::new(RecordingSpi::new(acks), MockWait::new());
    let mut out = [0u8; 64];
    let n = dev.get_log_into(&mut out).unwrap();
    assert_eq!(n, log.len());
    assert_eq!(&out[..n], &log);
}

#[test]
fn get_log_rejects_a_too_small_buffer()
{
    let log = [0xAAu8; 10];
    let acks = std::vec![l2_frame(L2Status::RequestOk as u8, &log)];
    let mut dev = Tropic01::new(RecordingSpi::new(acks), MockWait::new());
    let mut out = [0u8; 4];
    assert_eq!(dev.get_log_into(&mut out), Err(SeError::BufferTooSmall));
}

#[test]
fn get_log_rejects_a_continuation_status()
{
    // A single-frame Get_Log reply must be RequestOk. A *Cont status is anomalous.
    let acks = std::vec![l2_frame(L2Status::RequestCont as u8, &[0x01])];
    let mut dev = Tropic01::new(RecordingSpi::new(acks), MockWait::new());
    let mut out = [0u8; 64];
    assert_eq!(dev.get_log_into(&mut out), Err(SeError::L2(L2Error::BadFrame)));
}

#[test]
fn get_log_disabled_is_recoverable()
{
    // With FW_LOG_EN burned off the chip replies RespDisabled. It surfaces as a
    // recoverable L2 status: no session exists, nothing to tear down.
    let acks = std::vec![l2_frame(L2Status::RespDisabled as u8, &[])];
    let mut dev = Tropic01::new(RecordingSpi::new(acks), MockWait::new());
    let mut out = [0u8; 64];
    assert_eq!
    (
        dev.get_log_into(&mut out),
        Err(SeError::L2(L2Error::Status(L2Status::RespDisabled))),
    );
}

// Chip mode (L2, NoSession)

#[test]
fn chip_mode_ready_only_is_application()
{
    // CHIP_STATUS = READY (0x01): Application Mode.
    let mut dev = Tropic01::new(StatusSpi::new(0x01), MockWait::new());
    assert_eq!(dev.chip_mode(), Ok(ChipMode::Application));
}

#[test]
fn chip_mode_startup_bit_is_startup()
{
    // CHIP_STATUS = READY | STARTUP (0x05): Start-up (Maintenance) Mode.
    let mut dev = Tropic01::new(StatusSpi::new(0x05), MockWait::new());
    assert_eq!(dev.chip_mode(), Ok(ChipMode::Startup));
}

#[test]
fn chip_mode_alarm_bit_is_alarm()
{
    // CHIP_STATUS = READY | ALARM (0x03): Alarm Mode.
    let mut dev = Tropic01::new(StatusSpi::new(0x03), MockWait::new());
    assert_eq!(dev.chip_mode(), Ok(ChipMode::Alarm));
}

#[test]
fn chip_mode_alarm_wins_over_startup()
{
    // CHIP_STATUS = READY | ALARM | STARTUP (0x07): ALARM takes priority, exactly
    // as libtropic lt_get_tr01_mode decodes it.
    let mut dev = Tropic01::new(StatusSpi::new(0x07), MockWait::new());
    assert_eq!(dev.chip_mode(), Ok(ChipMode::Alarm));
}

/// Opens a session over a chip mock configured with `fault`.
fn open(fault: ChipFault) -> Tropic01<ChipMockSpi, MockWait, ActiveSession>
{
    let spi = ChipMockSpi::new(vectors::KCMD, vectors::KRES, vectors::ETPUB, vectors::T_TAUTH, fault);
    let dev = Tropic01::new(spi, MockWait::new());
    let ehpriv = Zeroizing::new(vectors::EHPRIV);
    let shipriv = Zeroizing::new(vectors::SHIPRIV);
    let shipub = vectors::SHIPUB;
    let stpub = vectors::STPUB;
    let cfg = SessionConfig
    {
        ehpriv: &ehpriv,
        shipriv: &shipriv,
        shipub: &shipub,
        stpub: &stpub,
        pkey_index: 0,
    };
    match dev.open_session(cfg)
    {
        Ok(d) => d,
        Err((_, e)) => panic!("open_session failed: {e:?}"),
    }
}

#[test]
fn open_session_then_ping_echoes_payload()
{
    let mut dev = open(ChipFault::None);
    let payload = b"test ping";
    let mut out = [0u8; 32];
    let n = dev.ping_into(payload, &mut out).unwrap();
    assert_eq!(&out[..n], payload);
}

#[test]
fn ping_empty_payload_round_trips()
{
    let mut dev = open(ChipFault::None);
    let mut out = [0u8; 4];
    let n = dev.ping_into(&[], &mut out).unwrap();
    assert_eq!(n, 0);
}

#[test]
fn repeated_pings_advance_both_nonces_in_lockstep()
{
    let mut dev = open(ChipFault::None);
    let mut out = [0u8; 16];
    for i in 1..=5u32
    {
        dev.ping_into(b"x", &mut out).unwrap();
        // The chip advances each nonce once per verified round-trip. Equal
        // counters prove the host's two nonces stayed in step (otherwise the
        // GCM tag would have failed). Each (key, nonce) pair is thus unique.
        assert_eq!(dev.spi_ref().nonces(), (i, i));
    }
}

#[test]
fn buffer_too_small_is_rejected_before_any_traffic()
{
    let mut dev = open(ChipFault::None);
    let before = dev.spi_ref().transaction_count();
    let mut out = [0u8; 2];
    assert_eq!(dev.ping_into(b"too long", &mut out), Err(SeError::BufferTooSmall));
    // Rejected up front: no nonce burned, no SPI traffic, session intact.
    assert_eq!(dev.spi_ref().transaction_count(), before);
    let mut ok_out = [0u8; 16];
    assert_eq!(dev.ping_into(b"still ok", &mut ok_out), Ok(8));
}

#[test]
fn non_ok_result_status_is_recoverable()
{
    // A FAIL result is a valid authenticated response: the error surfaces
    // but the session stays live and the nonces stay in step.
    let mut dev = open(ChipFault::ResultFail);
    let mut out = [0u8; 16];
    assert_eq!
    (
        dev.ping_into(b"hi", &mut out),
        Err(SeError::L3(L3Error::Result(L3Status::Fail)))
    );
    // The session is NOT poisoned: the next ping reaches the chip again.
    let before = dev.spi_ref().transaction_count();
    let r = dev.ping_into(b"hi", &mut out);
    assert_eq!(r, Err(SeError::L3(L3Error::Result(L3Status::Fail))));
    assert!(dev.spi_ref().transaction_count() > before, "chip traffic continues");
    assert_eq!(dev.spi_ref().nonces(), (2, 2), "nonces stay in lockstep");
}

#[test]
fn wrong_size_echo_poisons_session()
{
    // An authenticated OK result with a short echo mirrors libtropic's
    // lt_in__ping RES_SIZE check: session-fatal.
    let mut dev = open(ChipFault::ShortEcho);
    let mut out = [0u8; 16];
    assert_eq!(dev.ping_into(b"hi", &mut out), Err(SeError::L3(L3Error::Oversize)));
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn l3_buffer_is_wiped_after_a_successful_ping()
{
    let mut dev = open(ChipFault::None);
    let mut out = [0u8; 16];
    dev.ping_into(b"wipe me", &mut out).unwrap();
    assert!(dev.l3.as_slice().iter().all(|&b| b == 0), "plaintext residue");
}

#[test]
fn handshake_resp_body_must_be_exactly_48_bytes()
{
    let body = [0u8; 48];
    let (etpub, t_tauth) = parse_handshake_resp(&body).unwrap();
    assert_eq!(etpub, [0u8; 32]);
    assert_eq!(t_tauth, [0u8; 16]);
    assert_eq!(parse_handshake_resp(&body[..47]), Err(L2Error::ShortFrame));
    let long = [0u8; 49];
    assert_eq!(parse_handshake_resp(&long), Err(L2Error::BadFrame));
}

#[test]
fn bad_result_tag_poisons_session()
{
    let mut dev = open(ChipFault::BadResultTag);
    let mut out = [0u8; 16];
    assert_eq!(dev.ping_into(b"hi", &mut out), Err(SeError::L3(L3Error::Tag)));
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn l2_tag_err_poisons_session()
{
    let mut dev = open(ChipFault::L2TagErr);
    let mut out = [0u8; 16];
    let r = dev.ping_into(b"hi", &mut out);
    assert!(matches!(r, Err(SeError::L2(_))), "got {r:?}");
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn l2_crc_err_poisons_session()
{
    let mut dev = open(ChipFault::L2CrcErr);
    let mut out = [0u8; 16];
    assert_eq!(dev.ping_into(b"hi", &mut out), Err(SeError::L2(L2Error::Crc)));
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn alarm_poisons_session()
{
    let mut dev = open(ChipFault::Alarm);
    let mut out = [0u8; 16];
    assert_eq!(dev.ping_into(b"hi", &mut out), Err(SeError::L2(L2Error::L1(L1Error::Alarm))));
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn empty_authenticated_result_poisons_session()
{
    // An authenticated result with no RESULT byte is a structural violation.
    // The session must fail closed even though the tag verified.
    let mut dev = open(ChipFault::EmptyResult);
    let mut out = [0u8; 16];
    assert_eq!(
        dev.ping_into(b"hi", &mut out),
        Err(SeError::L3(L3Error::Parse(ParseError::UnexpectedEnd)))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn random_into_fills_buffer_and_advances_nonces()
{
    let mut dev = open(ChipFault::None);
    let mut out = [0u8; 16];
    let n = dev.random_into(&mut out).unwrap();
    assert_eq!(n, 16);
    // The chip fills RANDOM(N) with 0xA0 + i. Assert the bytes landed and
    // the nonces advanced once in lockstep.
    for (i, b) in out.iter().enumerate()
    {
        assert_eq!(*b, 0xA0u8.wrapping_add(i as u8));
    }
    assert_eq!(dev.spi_ref().nonces(), (1, 1));
}

#[test]
fn random_into_empty_out_makes_no_traffic()
{
    let mut dev = open(ChipFault::None);
    let before = dev.spi_ref().transaction_count();
    let mut out = [0u8; 0];
    assert_eq!(dev.random_into(&mut out), Ok(0));
    assert_eq!(dev.spi_ref().transaction_count(), before);
    assert_eq!(dev.spi_ref().nonces(), (0, 0));
}

#[test]
fn random_into_rejects_oversize_request_before_traffic()
{
    let mut dev = open(ChipFault::None);
    let before = dev.spi_ref().transaction_count();
    let mut out = [0u8; 256];
    assert_eq!(dev.random_into(&mut out), Err(SeError::InvalidArgument));
    // Rejected up front: no nonce burned, no SPI traffic, session intact.
    assert_eq!(dev.spi_ref().transaction_count(), before);
    let mut ok_out = [0u8; 8];
    assert_eq!(dev.random_into(&mut ok_out), Ok(8));
}

#[test]
fn random_into_wrong_size_result_poisons_session()
{
    let mut dev = open(ChipFault::ResultWrongSize);
    let mut out = [0u8; 16];
    assert_eq!(dev.random_into(&mut out), Err(SeError::L3(L3Error::Oversize)));
    assert_session_lost_and_quiet(&mut dev);
}

/// Builds a counter index, panicking only in test code on a bad constant.
fn mc(value: u8) -> MCounterIdx
{
    MCounterIdx::new(value).expect("test mcounter index out of range")
}

#[test]
fn mcounter_get_returns_little_endian_value()
{
    let mut dev = open(ChipFault::None);
    dev.spi_mut().set_mcounter_val(0x01020304);
    assert_eq!(dev.mcounter_get(mc(3)), Ok(0x01020304));
    assert_eq!(dev.spi_ref().nonces(), (1, 1));
}

#[test]
fn mcounter_get_counter_invalid_is_recoverable()
{
    // A CounterInvalid result is a valid authenticated response: the error
    // surfaces but the session stays live and the nonces stay in step.
    let mut dev = open(ChipFault::CounterInvalid);
    assert_eq!
    (
        dev.mcounter_get(mc(0)),
        Err(SeError::L3(L3Error::Result(L3Status::CounterInvalid)))
    );
    let before = dev.spi_ref().transaction_count();
    let r = dev.mcounter_get(mc(0));
    assert_eq!(r, Err(SeError::L3(L3Error::Result(L3Status::CounterInvalid))));
    assert!(dev.spi_ref().transaction_count() > before, "chip traffic continues");
    assert_eq!(dev.spi_ref().nonces(), (2, 2), "nonces stay in lockstep");
}

#[test]
fn mcounter_get_wrong_size_result_poisons_session()
{
    // An authenticated OK result whose RES_DATA is one byte short is a
    // structural anomaly: run poisons via the expected_res_data_len check.
    let mut dev = open(ChipFault::ResultWrongSize);
    assert_eq!(dev.mcounter_get(mc(0)), Err(SeError::L3(L3Error::Oversize)));
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn unknown_result_status_is_recoverable()
{
    // The chip seals an OK-tag result whose RESULT byte is unrecognized.
    // run surfaces Parse(InvalidValue) and leaves the session live, so the
    // next command reaches the chip and the nonces advance.
    let mut dev = open(ChipFault::UnknownResultStatus);
    let mut out = [0u8; 16];
    assert_eq!
    (
        dev.ping_into(b"hi", &mut out),
        Err(SeError::L3(L3Error::Parse(ParseError::InvalidValue)))
    );
    let before = dev.spi_ref().transaction_count();
    let r = dev.ping_into(b"hi", &mut out);
    assert_eq!(r, Err(SeError::L3(L3Error::Parse(ParseError::InvalidValue))));
    assert!(dev.spi_ref().transaction_count() > before, "chip traffic continues");
    assert_eq!(dev.spi_ref().nonces(), (2, 2), "nonces stay in lockstep");
}

#[test]
fn random_l3_buffer_is_wiped_after_success()
{
    let mut dev = open(ChipFault::None);
    let mut out = [0u8; 16];
    dev.random_into(&mut out).unwrap();
    assert!(dev.l3.as_slice().iter().all(|&b| b == 0), "plaintext residue");
}

#[test]
fn mixed_command_sequence_keeps_nonces_in_lockstep()
{
    // A ping, a random, and an mcounter_get each advance both nonces once.
    let mut dev = open(ChipFault::None);
    dev.spi_mut().set_mcounter_val(0xDEADBEEF);
    let mut buf = [0u8; 16];
    dev.ping_into(b"x", &mut buf).unwrap();
    assert_eq!(dev.spi_ref().nonces(), (1, 1));
    dev.random_into(&mut buf).unwrap();
    assert_eq!(dev.spi_ref().nonces(), (2, 2));
    assert_eq!(dev.mcounter_get(mc(0)), Ok(0xDEADBEEF));
    assert_eq!(dev.spi_ref().nonces(), (3, 3));
}

/// Builds an R-Memory slot index, panicking only in test code on a bad
/// constant.
fn rslot(value: u16) -> RMemSlot
{
    RMemSlot::new(value).expect("test rmem slot out of range")
}

#[test]
fn rmem_read_round_trips_known_bytes()
{
    let mut dev = open(ChipFault::None);
    let stored = b"test rmem payload";
    dev.spi_mut().set_rmem_slot(7, stored);
    let mut out = [0u8; R_MEM_DATA_MAX];
    let n = dev.rmem_read_into(rslot(7), &mut out).unwrap();
    assert_eq!(n, stored.len());
    assert_eq!(&out[..n], stored);
    assert_eq!(dev.spi_ref().nonces(), (1, 1));
}

#[test]
fn rmem_read_handles_a_near_max_length_payload()
{
    // A 475-byte read forces the result across multiple L2 chunks. The
    // driver must reassemble it and copy every byte.
    let mut dev = open(ChipFault::None);
    let mut stored = [0u8; R_MEM_DATA_MAX];
    for (i, b) in stored.iter_mut().enumerate()
    {
        *b = (i as u8).wrapping_mul(3).wrapping_add(1);
    }
    dev.spi_mut().set_rmem_slot(0, &stored);
    let mut out = [0u8; R_MEM_DATA_MAX];
    let n = dev.rmem_read_into(rslot(0), &mut out).unwrap();
    assert_eq!(n, R_MEM_DATA_MAX);
    assert_eq!(out, stored);
    assert_eq!(dev.spi_ref().nonces(), (1, 1));
}

#[test]
fn rmem_read_empty_slot_returns_zero()
{
    // An unset slot reads back RESULT=OK with no DATA. The driver reports
    // Ok(0) and keeps the session live.
    let mut dev = open(ChipFault::None);
    let mut out = [0u8; R_MEM_DATA_MAX];
    let n = dev.rmem_read_into(rslot(3), &mut out).unwrap();
    assert_eq!(n, 0);
    assert_eq!(dev.spi_ref().nonces(), (1, 1));
    // The session stays live: a follow-up read still reaches the chip.
    let before = dev.spi_ref().transaction_count();
    assert_eq!(dev.rmem_read_into(rslot(3), &mut out), Ok(0));
    assert!(dev.spi_ref().transaction_count() > before, "chip traffic continues");
}

#[test]
fn rmem_read_too_small_out_is_rejected_before_any_traffic()
{
    // A read can return up to R_MEM_DATA_MAX DATA bytes, so out must hold at
    // least that many. A shorter out is rejected up front, before any nonce
    // or chip traffic, leaving the session live (matching libtropic's
    // LT_PARAM_ERR, which does not invalidate the session).
    let mut dev = open(ChipFault::None);
    dev.spi_mut().set_rmem_slot(5, b"twelve bytes");
    let before = dev.spi_ref().transaction_count();
    let mut out = [0u8; R_MEM_DATA_MAX - 1];
    assert_eq!(dev.rmem_read_into(rslot(5), &mut out), Err(SeError::BufferTooSmall));
    // Rejected up front: no nonce burned, no SPI traffic, session intact.
    assert_eq!(dev.spi_ref().transaction_count(), before);
    assert_eq!(dev.spi_ref().nonces(), (0, 0), "nonce did not move");
    // The session is still usable: a full-size buffer reads the slot back.
    let mut ok_out = [0u8; R_MEM_DATA_MAX];
    let n = dev.rmem_read_into(rslot(5), &mut ok_out).unwrap();
    assert_eq!(&ok_out[..n], b"twelve bytes");
}

#[test]
fn rmem_read_wrong_size_result_poisons_session()
{
    // An authenticated OK result whose RES_DATA is one byte short truncates
    // below the 3 padding bytes only at the boundary. Here the generic
    // ResultWrongSize fault drops the last byte, leaving DATA one short of
    // the stored content but still structurally valid. To exercise the
    // padding-too-short anomaly, store nothing so RES_DATA = PADDING(3),
    // then drop a byte: PADDING(2) fails the take(3) bound and poisons.
    let mut dev = open(ChipFault::ResultWrongSize);
    let mut out = [0u8; R_MEM_DATA_MAX];
    assert_eq!
    (
        dev.rmem_read_into(rslot(0), &mut out),
        Err(SeError::L3(L3Error::Parse(ParseError::UnexpectedEnd)))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn rmem_read_bad_tag_poisons_session()
{
    let mut dev = open(ChipFault::BadResultTag);
    let mut out = [0u8; R_MEM_DATA_MAX];
    assert_eq!(dev.rmem_read_into(rslot(0), &mut out), Err(SeError::L3(L3Error::Tag)));
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn rmem_read_l2_tag_err_poisons_session()
{
    let mut dev = open(ChipFault::L2TagErr);
    let mut out = [0u8; R_MEM_DATA_MAX];
    let r = dev.rmem_read_into(rslot(0), &mut out);
    assert!(matches!(r, Err(SeError::L2(_))), "got {r:?}");
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn rmem_read_l2_crc_err_poisons_session()
{
    let mut dev = open(ChipFault::L2CrcErr);
    let mut out = [0u8; R_MEM_DATA_MAX];
    assert_eq!(dev.rmem_read_into(rslot(0), &mut out), Err(SeError::L2(L2Error::Crc)));
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn rmem_read_alarm_poisons_session()
{
    let mut dev = open(ChipFault::Alarm);
    let mut out = [0u8; R_MEM_DATA_MAX];
    assert_eq!
    (
        dev.rmem_read_into(rslot(0), &mut out),
        Err(SeError::L2(L2Error::L1(L1Error::Alarm)))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn rmem_read_empty_authenticated_result_poisons_session()
{
    let mut dev = open(ChipFault::EmptyResult);
    let mut out = [0u8; R_MEM_DATA_MAX];
    assert_eq!
    (
        dev.rmem_read_into(rslot(0), &mut out),
        Err(SeError::L3(L3Error::Parse(ParseError::UnexpectedEnd)))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn rmem_write_round_trips_and_stores_payload()
{
    let mut dev = open(ChipFault::None);
    let data = b"stored via write";
    assert_eq!(dev.rmem_write(rslot(9), data), Ok(()));
    assert_eq!(dev.spi_ref().nonces(), (1, 1));
    assert_eq!(dev.spi_ref().rmem_slot(9), Some(&data[..]));
}

#[test]
fn rmem_write_near_max_payload_round_trips()
{
    // A 475-byte write forces the command across multiple L2 chunks on the
    // send path and stores the full payload.
    let mut dev = open(ChipFault::None);
    let mut data = [0u8; R_MEM_DATA_MAX];
    for (i, b) in data.iter_mut().enumerate()
    {
        *b = (i as u8).wrapping_mul(7).wrapping_add(2);
    }
    assert_eq!(dev.rmem_write(rslot(1), &data), Ok(()));
    assert_eq!(dev.spi_ref().rmem_slot(1), Some(&data[..]));
    assert_eq!(dev.spi_ref().nonces(), (1, 1));
}

#[test]
fn rmem_write_rejects_empty_payload_before_any_traffic()
{
    let mut dev = open(ChipFault::None);
    let before = dev.spi_ref().transaction_count();
    assert_eq!(dev.rmem_write(rslot(0), &[]), Err(SeError::InvalidArgument));
    // Rejected up front: no nonce burned, no SPI traffic, session intact.
    assert_eq!(dev.spi_ref().transaction_count(), before);
    assert_eq!(dev.spi_ref().nonces(), (0, 0), "nonce did not move");
    // The session is still usable.
    assert_eq!(dev.rmem_write(rslot(0), b"ok"), Ok(()));
}

#[test]
fn rmem_write_rejects_oversize_payload_before_any_traffic()
{
    let mut dev = open(ChipFault::None);
    let before = dev.spi_ref().transaction_count();
    let data = [0u8; R_MEM_DATA_MAX + 1];
    assert_eq!(dev.rmem_write(rslot(0), &data), Err(SeError::InvalidArgument));
    // Rejected up front: no nonce burned, no SPI traffic, session intact.
    assert_eq!(dev.spi_ref().transaction_count(), before);
    assert_eq!(dev.spi_ref().nonces(), (0, 0), "nonce did not move");
}

#[test]
fn rmem_write_slot_not_empty_is_recoverable()
{
    // SlotNotEmpty (0x10) is a known L3Status: run maps it to a recoverable
    // L3Error::Result and keeps the session live, so the caller can erase
    // and retry. No poison, nonces stay in lockstep.
    let mut dev = open(ChipFault::SlotNotEmpty);
    assert_eq!
    (
        dev.rmem_write(rslot(2), b"payload"),
        Err(SeError::L3(L3Error::Result(L3Status::SlotNotEmpty)))
    );
    let before = dev.spi_ref().transaction_count();
    let r = dev.rmem_write(rslot(2), b"payload");
    assert_eq!(r, Err(SeError::L3(L3Error::Result(L3Status::SlotNotEmpty))));
    assert!(dev.spi_ref().transaction_count() > before, "chip traffic continues");
    assert_eq!(dev.spi_ref().nonces(), (2, 2), "nonces stay in lockstep");
}

#[test]
fn rmem_write_extra_result_byte_poisons_session()
{
    // rmem_write is a Some(0) command: it expects no RES_DATA. One
    // unexpected byte trips the expected-length check and poisons. This
    // guards against a regression to None with a trivial closure.
    let mut dev = open(ChipFault::ExtraResultByte);
    assert_eq!
    (
        dev.rmem_write(rslot(0), b"x"),
        Err(SeError::L3(L3Error::Oversize))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn rmem_write_bad_tag_poisons_session()
{
    let mut dev = open(ChipFault::BadResultTag);
    assert_eq!(dev.rmem_write(rslot(0), b"x"), Err(SeError::L3(L3Error::Tag)));
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn rmem_write_l2_crc_err_poisons_session()
{
    let mut dev = open(ChipFault::L2CrcErr);
    assert_eq!(dev.rmem_write(rslot(0), b"x"), Err(SeError::L2(L2Error::Crc)));
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn rmem_write_alarm_poisons_session()
{
    let mut dev = open(ChipFault::Alarm);
    assert_eq!
    (
        dev.rmem_write(rslot(0), b"x"),
        Err(SeError::L2(L2Error::L1(L1Error::Alarm)))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn rmem_l3_buffer_is_wiped_after_a_successful_read()
{
    let mut dev = open(ChipFault::None);
    dev.spi_mut().set_rmem_slot(4, b"wipe me");
    let mut out = [0u8; R_MEM_DATA_MAX];
    dev.rmem_read_into(rslot(4), &mut out).unwrap();
    assert!(dev.l3.as_slice().iter().all(|&b| b == 0), "plaintext residue");
}

#[test]
fn mixed_read_write_sequence_keeps_nonces_in_lockstep()
{
    // A write, then a ping, then a read of the written slot each advance
    // both nonces once. The read returns exactly what the write stored,
    // proving the round-trips stayed in step across the mixed sequence.
    let mut dev = open(ChipFault::None);
    let payload = b"mixed sequence";
    let mut buf = [0u8; R_MEM_DATA_MAX];
    assert_eq!(dev.rmem_write(rslot(6), payload), Ok(()));
    assert_eq!(dev.spi_ref().nonces(), (1, 1));
    dev.ping_into(b"between", &mut buf).unwrap();
    assert_eq!(dev.spi_ref().nonces(), (2, 2));
    let n = dev.rmem_read_into(rslot(6), &mut buf).unwrap();
    assert_eq!(dev.spi_ref().nonces(), (3, 3));
    assert_eq!(&buf[..n], payload);
}

/// Builds an ECC slot index, panicking only in test code on a bad constant.
fn eslot(value: u8) -> EccSlot
{
    EccSlot::new(value).expect("test ecc slot out of range")
}

#[test]
fn ecc_key_generate_round_trips_both_curves()
{
    let mut dev = open(ChipFault::None);
    assert_eq!(dev.ecc_key_generate(eslot(0), EccCurve::P256), Ok(()));
    assert_eq!(dev.spi_ref().nonces(), (1, 1));
    assert_eq!(dev.ecc_key_generate(eslot(31), EccCurve::Ed25519), Ok(()));
    assert_eq!(dev.spi_ref().nonces(), (2, 2));
}

#[test]
fn ecc_key_generate_slot_not_empty_is_recoverable()
{
    // SlotNotEmpty is a known L3Status: run maps it to a recoverable
    // L3Error::Result and keeps the session live. No poison.
    let mut dev = open(ChipFault::SlotNotEmpty);
    assert_eq!
    (
        dev.ecc_key_generate(eslot(2), EccCurve::P256),
        Err(SeError::L3(L3Error::Result(L3Status::SlotNotEmpty)))
    );
    let before = dev.spi_ref().transaction_count();
    let r = dev.ecc_key_generate(eslot(2), EccCurve::P256);
    assert_eq!(r, Err(SeError::L3(L3Error::Result(L3Status::SlotNotEmpty))));
    assert!(dev.spi_ref().transaction_count() > before, "chip traffic continues");
    assert_eq!(dev.spi_ref().nonces(), (2, 2), "nonces stay in lockstep");
}

#[test]
fn ecc_key_generate_empty_result_poisons_session()
{
    let mut dev = open(ChipFault::EmptyResult);
    assert_eq!
    (
        dev.ecc_key_generate(eslot(0), EccCurve::P256),
        Err(SeError::L3(L3Error::Parse(ParseError::UnexpectedEnd)))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn ecc_key_generate_extra_result_byte_poisons_session()
{
    // ecc_key_generate is a Some(0) command: it expects no RES_DATA. One
    // unexpected byte trips the expected-length check and poisons. This
    // guards against a regression to None with a trivial closure.
    let mut dev = open(ChipFault::ExtraResultByte);
    assert_eq!
    (
        dev.ecc_key_generate(eslot(0), EccCurve::P256),
        Err(SeError::L3(L3Error::Oversize))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn ecc_key_generate_bad_tag_poisons_session()
{
    let mut dev = open(ChipFault::BadResultTag);
    assert_eq!
    (
        dev.ecc_key_generate(eslot(0), EccCurve::P256),
        Err(SeError::L3(L3Error::Tag))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn ecc_key_generate_l2_crc_err_poisons_session()
{
    let mut dev = open(ChipFault::L2CrcErr);
    assert_eq!
    (
        dev.ecc_key_generate(eslot(0), EccCurve::P256),
        Err(SeError::L2(L2Error::Crc))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn ecc_key_generate_alarm_poisons_session()
{
    let mut dev = open(ChipFault::Alarm);
    assert_eq!
    (
        dev.ecc_key_generate(eslot(0), EccCurve::P256),
        Err(SeError::L2(L2Error::L1(L1Error::Alarm)))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn ecc_public_key_reads_p256_64_bytes()
{
    let mut dev = open(ChipFault::None);
    let mut pubkey = [0u8; 64];
    for (i, b) in pubkey.iter_mut().enumerate()
    {
        *b = (i as u8).wrapping_mul(5).wrapping_add(1);
    }
    dev.spi_mut().set_ecc_pubkey(0x01, &pubkey);
    let pk = dev.ecc_public_key(eslot(4)).unwrap();
    assert_eq!(pk.curve(), EccCurve::P256);
    assert_eq!(pk.bytes().len(), 64);
    assert_eq!(pk.bytes(), &pubkey);
    assert_eq!(dev.spi_ref().nonces(), (1, 1));
}

#[test]
fn ecc_public_key_reads_ed25519_32_bytes()
{
    let mut dev = open(ChipFault::None);
    let mut pubkey = [0u8; 32];
    for (i, b) in pubkey.iter_mut().enumerate()
    {
        *b = (i as u8).wrapping_mul(9).wrapping_add(7);
    }
    dev.spi_mut().set_ecc_pubkey(0x02, &pubkey);
    let pk = dev.ecc_public_key(eslot(10)).unwrap();
    assert_eq!(pk.curve(), EccCurve::Ed25519);
    assert_eq!(pk.bytes().len(), 32);
    assert_eq!(pk.bytes(), &pubkey);
    assert_eq!(dev.spi_ref().nonces(), (1, 1));
}

#[test]
fn ecc_public_key_invalid_key_is_recoverable()
{
    // InvalidKey (0x12) = empty or corrupt slot: a valid authenticated
    // reply. The session stays live and the nonces stay in step.
    let mut dev = open(ChipFault::InvalidKey);
    assert_eq!
    (
        dev.ecc_public_key(eslot(0)),
        Err(SeError::L3(L3Error::Result(L3Status::InvalidKey)))
    );
    let before = dev.spi_ref().transaction_count();
    let r = dev.ecc_public_key(eslot(0));
    assert_eq!(r, Err(SeError::L3(L3Error::Result(L3Status::InvalidKey))));
    assert!(dev.spi_ref().transaction_count() > before, "chip traffic continues");
    assert_eq!(dev.spi_ref().nonces(), (2, 2), "nonces stay in lockstep");
}

#[test]
fn ecc_public_key_unknown_curve_byte_poisons_session()
{
    // An unknown CURVE byte on an authenticated OK result is a structural
    // anomaly. The parse closure returns Err, which poisons the session.
    let mut dev = open(ChipFault::None);
    dev.spi_mut().set_ecc_pubkey(0x07, &[0u8; 32]);
    assert_eq!
    (
        dev.ecc_public_key(eslot(0)),
        Err(SeError::L3(L3Error::Parse(ParseError::InvalidValue)))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn ecc_public_key_length_mismatch_poisons_session()
{
    // CURVE says Ed25519 (expects 32) but the PUBKEY is 33 bytes: a
    // structural anomaly. The closure returns Oversize, which poisons.
    let mut dev = open(ChipFault::None);
    dev.spi_mut().set_ecc_pubkey(0x02, &[0u8; 33]);
    assert_eq!
    (
        dev.ecc_public_key(eslot(0)),
        Err(SeError::L3(L3Error::Oversize))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn ecc_public_key_truncated_header_poisons_session()
{
    // A RES_DATA shorter than the 15-byte CURVE||ORIGIN||PADDING(13) header
    // fails the take bound in the closure, which poisons the session.
    let mut dev = open(ChipFault::None);
    dev.spi_mut().set_ecc_pubkey(0x02, &[]);
    dev.spi_mut().set_ecc_read_pad(11); // header = 1 + 1 + 11 = 13 < 15
    assert_eq!
    (
        dev.ecc_public_key(eslot(0)),
        Err(SeError::L3(L3Error::Parse(ParseError::UnexpectedEnd)))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn ecc_public_key_bad_tag_poisons_session()
{
    let mut dev = open(ChipFault::BadResultTag);
    assert_eq!
    (
        dev.ecc_public_key(eslot(0)),
        Err(SeError::L3(L3Error::Tag))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn ecc_public_key_alarm_poisons_session()
{
    let mut dev = open(ChipFault::Alarm);
    assert_eq!
    (
        dev.ecc_public_key(eslot(0)),
        Err(SeError::L2(L2Error::L1(L1Error::Alarm)))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn ecc_public_key_empty_result_poisons_session()
{
    let mut dev = open(ChipFault::EmptyResult);
    assert_eq!
    (
        dev.ecc_public_key(eslot(0)),
        Err(SeError::L3(L3Error::Parse(ParseError::UnexpectedEnd)))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn ecc_l3_buffer_is_wiped_after_a_successful_read()
{
    let mut dev = open(ChipFault::None);
    dev.spi_mut().set_ecc_pubkey(0x02, &[0xAB; 32]);
    dev.ecc_public_key(eslot(0)).unwrap();
    assert!(dev.l3.as_slice().iter().all(|&b| b == 0), "plaintext residue");
}

#[test]
fn mixed_ecc_sequence_keeps_nonces_in_lockstep()
{
    // A keygen, a public-key read, then a ping each advance both nonces
    // once across the mixed sequence.
    let mut dev = open(ChipFault::None);
    dev.spi_mut().set_ecc_pubkey(0x01, &[0x11; 64]);
    let mut buf = [0u8; 64];
    assert_eq!(dev.ecc_key_generate(eslot(0), EccCurve::P256), Ok(()));
    assert_eq!(dev.spi_ref().nonces(), (1, 1));
    let pk = dev.ecc_public_key(eslot(0)).unwrap();
    assert_eq!(pk.curve(), EccCurve::P256);
    assert_eq!(pk.bytes().len(), 64);
    assert_eq!(dev.spi_ref().nonces(), (2, 2));
    dev.ping_into(b"between", &mut buf).unwrap();
    assert_eq!(dev.spi_ref().nonces(), (3, 3));
}

/// Builds a deterministic 32-byte private scalar for the import tests.
fn sample_privkey() -> Zeroizing<[u8; 32]>
{
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate()
    {
        *b = (i as u8).wrapping_mul(3).wrapping_add(1);
    }
    Zeroizing::new(k)
}

#[test]
fn ecc_key_store_round_trips_both_curves()
{
    let mut dev = open(ChipFault::None);
    let key = sample_privkey();
    assert_eq!(dev.ecc_key_store(eslot(0), EccCurve::P256, &key), Ok(()));
    assert_eq!(dev.spi_ref().nonces(), (1, 1));
    assert_eq!(dev.ecc_key_store(eslot(31), EccCurve::Ed25519, &key), Ok(()));
    assert_eq!(dev.spi_ref().nonces(), (2, 2));
}

#[test]
fn ecc_key_store_slot_not_empty_is_recoverable()
{
    // SlotNotEmpty (0x10): the target slot already holds a key. A valid
    // authenticated reply that keeps the session live.
    let mut dev = open(ChipFault::SlotNotEmpty);
    let key = sample_privkey();
    assert_eq!
    (
        dev.ecc_key_store(eslot(2), EccCurve::Ed25519, &key),
        Err(SeError::L3(L3Error::Result(L3Status::SlotNotEmpty)))
    );
    let before = dev.spi_ref().transaction_count();
    let r = dev.ecc_key_store(eslot(2), EccCurve::Ed25519, &key);
    assert_eq!(r, Err(SeError::L3(L3Error::Result(L3Status::SlotNotEmpty))));
    assert!(dev.spi_ref().transaction_count() > before, "chip traffic continues");
    assert_eq!(dev.spi_ref().nonces(), (2, 2), "nonces stay in lockstep");
}

#[test]
fn ecc_key_store_invalid_key_is_recoverable()
{
    // InvalidKey (0x12): the imported scalar is malformed (e.g. out of range
    // for the curve). Recoverable: the session stays live.
    let mut dev = open(ChipFault::InvalidKey);
    let key = sample_privkey();
    assert_eq!
    (
        dev.ecc_key_store(eslot(0), EccCurve::P256, &key),
        Err(SeError::L3(L3Error::Result(L3Status::InvalidKey)))
    );
    let before = dev.spi_ref().transaction_count();
    let r = dev.ecc_key_store(eslot(0), EccCurve::P256, &key);
    assert_eq!(r, Err(SeError::L3(L3Error::Result(L3Status::InvalidKey))));
    assert!(dev.spi_ref().transaction_count() > before, "chip traffic continues");
    assert_eq!(dev.spi_ref().nonces(), (2, 2), "nonces stay in lockstep");
}

#[test]
fn ecc_key_store_extra_result_byte_poisons_session()
{
    // ecc_key_store is a Some(0) command: one unexpected RES_DATA byte trips
    // the expected-length check and poisons.
    let mut dev = open(ChipFault::ExtraResultByte);
    let key = sample_privkey();
    assert_eq!
    (
        dev.ecc_key_store(eslot(0), EccCurve::P256, &key),
        Err(SeError::L3(L3Error::Oversize))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn ecc_key_store_bad_tag_poisons_session()
{
    let mut dev = open(ChipFault::BadResultTag);
    let key = sample_privkey();
    assert_eq!
    (
        dev.ecc_key_store(eslot(0), EccCurve::P256, &key),
        Err(SeError::L3(L3Error::Tag))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn ecc_key_store_l2_crc_err_poisons_session()
{
    let mut dev = open(ChipFault::L2CrcErr);
    let key = sample_privkey();
    assert_eq!
    (
        dev.ecc_key_store(eslot(0), EccCurve::P256, &key),
        Err(SeError::L2(L2Error::Crc))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn ecc_key_store_alarm_poisons_session()
{
    let mut dev = open(ChipFault::Alarm);
    let key = sample_privkey();
    assert_eq!
    (
        dev.ecc_key_store(eslot(0), EccCurve::P256, &key),
        Err(SeError::L2(L2Error::L1(L1Error::Alarm)))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn ecc_key_store_empty_result_poisons_session()
{
    let mut dev = open(ChipFault::EmptyResult);
    let key = sample_privkey();
    assert_eq!
    (
        dev.ecc_key_store(eslot(0), EccCurve::P256, &key),
        Err(SeError::L3(L3Error::Parse(ParseError::UnexpectedEnd)))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn ecc_key_store_wipes_the_imported_key_from_the_l3_buffer()
{
    // SECURITY: the imported private scalar sits in the L3 plaintext buffer.
    // The shared run gate must zeroize it on the success path so the secret
    // does not linger after the command returns.
    let mut dev = open(ChipFault::None);
    let key = sample_privkey();
    dev.ecc_key_store(eslot(5), EccCurve::Ed25519, &key).unwrap();
    assert!(dev.l3.as_slice().iter().all(|&b| b == 0), "secret key residue");
}

#[test]
fn ecc_key_store_wipes_the_imported_key_even_on_poison()
{
    // SECURITY: even when the command poisons the session, the imported
    // scalar must not survive in the L3 buffer.
    let mut dev = open(ChipFault::BadResultTag);
    let key = sample_privkey();
    let _ = dev.ecc_key_store(eslot(5), EccCurve::Ed25519, &key);
    assert!(dev.l3.as_slice().iter().all(|&b| b == 0), "secret key residue after poison");
}

#[test]
fn ecc_key_erase_round_trips_and_advances_nonces()
{
    let mut dev = open(ChipFault::None);
    assert_eq!(dev.ecc_key_erase(eslot(4)), Ok(()));
    assert_eq!(dev.spi_ref().nonces(), (1, 1));
}

#[test]
fn ecc_key_erase_slot_empty_is_recoverable()
{
    // SlotEmpty (0x15): erasing an already-empty slot. A valid authenticated
    // reply that keeps the session live (erase is idempotent for the caller).
    let mut dev = open(ChipFault::SlotEmpty);
    assert_eq!
    (
        dev.ecc_key_erase(eslot(0)),
        Err(SeError::L3(L3Error::Result(L3Status::SlotEmpty)))
    );
    let before = dev.spi_ref().transaction_count();
    let r = dev.ecc_key_erase(eslot(0));
    assert_eq!(r, Err(SeError::L3(L3Error::Result(L3Status::SlotEmpty))));
    assert!(dev.spi_ref().transaction_count() > before, "chip traffic continues");
    assert_eq!(dev.spi_ref().nonces(), (2, 2), "nonces stay in lockstep");
}

#[test]
fn ecc_key_erase_extra_result_byte_poisons_session()
{
    let mut dev = open(ChipFault::ExtraResultByte);
    assert_eq!(dev.ecc_key_erase(eslot(0)), Err(SeError::L3(L3Error::Oversize)));
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn ecc_key_erase_bad_tag_poisons_session()
{
    let mut dev = open(ChipFault::BadResultTag);
    assert_eq!(dev.ecc_key_erase(eslot(0)), Err(SeError::L3(L3Error::Tag)));
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn ecc_key_erase_l2_crc_err_poisons_session()
{
    let mut dev = open(ChipFault::L2CrcErr);
    assert_eq!(dev.ecc_key_erase(eslot(0)), Err(SeError::L2(L2Error::Crc)));
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn ecc_key_erase_alarm_poisons_session()
{
    let mut dev = open(ChipFault::Alarm);
    assert_eq!
    (
        dev.ecc_key_erase(eslot(0)),
        Err(SeError::L2(L2Error::L1(L1Error::Alarm)))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn ecc_key_erase_empty_result_poisons_session()
{
    let mut dev = open(ChipFault::EmptyResult);
    assert_eq!
    (
        dev.ecc_key_erase(eslot(0)),
        Err(SeError::L3(L3Error::Parse(ParseError::UnexpectedEnd)))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn mixed_ecc_lifecycle_keeps_nonces_in_lockstep()
{
    // store, public-key read, then erase each advance both nonces once
    // across the full ECC key lifecycle.
    let mut dev = open(ChipFault::None);
    dev.spi_mut().set_ecc_pubkey(0x02, &[0x44; 32]);
    let key = sample_privkey();
    dev.ecc_key_store(eslot(6), EccCurve::Ed25519, &key).unwrap();
    assert_eq!(dev.spi_ref().nonces(), (1, 1));
    let pk = dev.ecc_public_key(eslot(6)).unwrap();
    assert_eq!(pk.curve(), EccCurve::Ed25519);
    assert_eq!(dev.spi_ref().nonces(), (2, 2));
    dev.ecc_key_erase(eslot(6)).unwrap();
    assert_eq!(dev.spi_ref().nonces(), (3, 3));
}

/// Builds a deterministic 64-byte R || S signature for the sign tests.
fn sample_sig() -> [u8; 64]
{
    let mut sig = [0u8; 64];
    for (i, b) in sig.iter_mut().enumerate()
    {
        *b = (i as u8).wrapping_mul(13).wrapping_add(5);
    }
    sig
}

#[test]
fn ecdsa_sign_round_trips_known_signature()
{
    let mut dev = open(ChipFault::None);
    let sig = sample_sig();
    dev.spi_mut().set_signature(sig);
    let digest = [0x42u8; 32];
    let out = dev.ecdsa_sign(eslot(0), &digest).unwrap();
    // The 15 padding bytes are skipped and R || S land verbatim.
    assert_eq!(out, Signature(sig));
    assert_eq!(dev.spi_ref().nonces(), (1, 1));
}

#[test]
fn ecdsa_sign_invalid_key_is_recoverable()
{
    // InvalidKey (0x12) = missing or wrong-curve slot: a valid authenticated
    // reply. The session stays live and the nonces stay in step.
    let mut dev = open(ChipFault::InvalidKey);
    let digest = [0u8; 32];
    assert_eq!
    (
        dev.ecdsa_sign(eslot(0), &digest),
        Err(SeError::L3(L3Error::Result(L3Status::InvalidKey)))
    );
    let before = dev.spi_ref().transaction_count();
    let r = dev.ecdsa_sign(eslot(0), &digest);
    assert_eq!(r, Err(SeError::L3(L3Error::Result(L3Status::InvalidKey))));
    assert!(dev.spi_ref().transaction_count() > before, "chip traffic continues");
    assert_eq!(dev.spi_ref().nonces(), (2, 2), "nonces stay in lockstep");
}

#[test]
fn ecdsa_sign_wrong_size_result_poisons_session()
{
    // An authenticated OK result one byte short of the fixed 79-byte RES_DATA
    // trips run's expected_res_data_len check and poisons.
    let mut dev = open(ChipFault::ResultWrongSize);
    dev.spi_mut().set_signature(sample_sig());
    assert_eq!
    (
        dev.ecdsa_sign(eslot(0), &[0u8; 32]),
        Err(SeError::L3(L3Error::Oversize))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn ecdsa_sign_extra_result_byte_poisons_session()
{
    // One byte past the fixed 79-byte RES_DATA trips the expected-length
    // check and poisons.
    let mut dev = open(ChipFault::ExtraResultByte);
    dev.spi_mut().set_signature(sample_sig());
    assert_eq!
    (
        dev.ecdsa_sign(eslot(0), &[0u8; 32]),
        Err(SeError::L3(L3Error::Oversize))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn ecdsa_sign_bad_tag_poisons_session()
{
    let mut dev = open(ChipFault::BadResultTag);
    assert_eq!
    (
        dev.ecdsa_sign(eslot(0), &[0u8; 32]),
        Err(SeError::L3(L3Error::Tag))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn ecdsa_sign_l2_crc_err_poisons_session()
{
    let mut dev = open(ChipFault::L2CrcErr);
    assert_eq!
    (
        dev.ecdsa_sign(eslot(0), &[0u8; 32]),
        Err(SeError::L2(L2Error::Crc))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn ecdsa_sign_alarm_poisons_session()
{
    let mut dev = open(ChipFault::Alarm);
    assert_eq!
    (
        dev.ecdsa_sign(eslot(0), &[0u8; 32]),
        Err(SeError::L2(L2Error::L1(L1Error::Alarm)))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn ecdsa_sign_empty_result_poisons_session()
{
    let mut dev = open(ChipFault::EmptyResult);
    assert_eq!
    (
        dev.ecdsa_sign(eslot(0), &[0u8; 32]),
        Err(SeError::L3(L3Error::Parse(ParseError::UnexpectedEnd)))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn ecdsa_l3_buffer_is_wiped_after_a_successful_sign()
{
    let mut dev = open(ChipFault::None);
    dev.spi_mut().set_signature(sample_sig());
    dev.ecdsa_sign(eslot(0), &[0xAB; 32]).unwrap();
    assert!(dev.l3.as_slice().iter().all(|&b| b == 0), "plaintext residue");
}

#[test]
fn eddsa_sign_empty_message_round_trips()
{
    // An empty message is valid: the chip hashes internally (RFC 8032).
    let mut dev = open(ChipFault::None);
    let sig = sample_sig();
    dev.spi_mut().set_signature(sig);
    let out = dev.eddsa_sign(eslot(0), &[]).unwrap();
    assert_eq!(out, Signature(sig));
    assert_eq!(dev.spi_ref().nonces(), (1, 1));
}

#[test]
fn eddsa_sign_small_message_round_trips()
{
    let mut dev = open(ChipFault::None);
    let sig = sample_sig();
    dev.spi_mut().set_signature(sig);
    let out = dev.eddsa_sign(eslot(7), b"test eddsa").unwrap();
    assert_eq!(out, Signature(sig));
    assert_eq!(dev.spi_ref().nonces(), (1, 1));
}

#[test]
fn eddsa_sign_max_message_round_trips()
{
    // A 4096-byte message yields a 4112-byte plaintext that fills the L3
    // buffer to capacity and forces a multi-chunk L2 send. The driver must
    // chunk it, the mock reassemble it, and the round-trip still succeed.
    let mut dev = open(ChipFault::None);
    let sig = sample_sig();
    dev.spi_mut().set_signature(sig);
    let msg = [0x5Au8; EDDSA_MSG_MAX];
    let out = dev.eddsa_sign(eslot(0), &msg).unwrap();
    assert_eq!(out, Signature(sig));
    assert_eq!(dev.spi_ref().nonces(), (1, 1));
}

#[test]
fn eddsa_sign_rejects_oversize_message_before_any_traffic()
{
    // One byte past EDDSA_MSG_MAX is rejected up front: no nonce, no SPI
    // traffic, session intact.
    let mut dev = open(ChipFault::None);
    let before = dev.spi_ref().transaction_count();
    let msg = [0u8; EDDSA_MSG_MAX + 1];
    assert_eq!(dev.eddsa_sign(eslot(0), &msg), Err(SeError::InvalidArgument));
    assert_eq!(dev.spi_ref().transaction_count(), before);
    assert_eq!(dev.spi_ref().nonces(), (0, 0), "nonce did not move");
    // The session is still usable: a max-size message still signs.
    dev.spi_mut().set_signature(sample_sig());
    let ok = [0u8; EDDSA_MSG_MAX];
    assert_eq!(dev.eddsa_sign(eslot(0), &ok), Ok(Signature(sample_sig())));
}

#[test]
fn eddsa_sign_invalid_key_is_recoverable()
{
    let mut dev = open(ChipFault::InvalidKey);
    assert_eq!
    (
        dev.eddsa_sign(eslot(0), b"msg"),
        Err(SeError::L3(L3Error::Result(L3Status::InvalidKey)))
    );
    let before = dev.spi_ref().transaction_count();
    let r = dev.eddsa_sign(eslot(0), b"msg");
    assert_eq!(r, Err(SeError::L3(L3Error::Result(L3Status::InvalidKey))));
    assert!(dev.spi_ref().transaction_count() > before, "chip traffic continues");
    assert_eq!(dev.spi_ref().nonces(), (2, 2), "nonces stay in lockstep");
}

#[test]
fn eddsa_sign_wrong_size_result_poisons_session()
{
    let mut dev = open(ChipFault::ResultWrongSize);
    dev.spi_mut().set_signature(sample_sig());
    assert_eq!
    (
        dev.eddsa_sign(eslot(0), b"msg"),
        Err(SeError::L3(L3Error::Oversize))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn eddsa_sign_bad_tag_poisons_session()
{
    let mut dev = open(ChipFault::BadResultTag);
    assert_eq!
    (
        dev.eddsa_sign(eslot(0), b"msg"),
        Err(SeError::L3(L3Error::Tag))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn eddsa_sign_alarm_poisons_session()
{
    let mut dev = open(ChipFault::Alarm);
    assert_eq!
    (
        dev.eddsa_sign(eslot(0), b"msg"),
        Err(SeError::L2(L2Error::L1(L1Error::Alarm)))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn eddsa_sign_empty_result_poisons_session()
{
    let mut dev = open(ChipFault::EmptyResult);
    assert_eq!
    (
        dev.eddsa_sign(eslot(0), b"msg"),
        Err(SeError::L3(L3Error::Parse(ParseError::UnexpectedEnd)))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn mixed_sign_sequence_keeps_nonces_in_lockstep()
{
    // An ecdsa_sign, an eddsa_sign, and a public-key read each advance both
    // nonces once across the mixed sequence.
    let mut dev = open(ChipFault::None);
    dev.spi_mut().set_signature(sample_sig());
    dev.spi_mut().set_ecc_pubkey(0x02, &[0x33; 32]);
    dev.ecdsa_sign(eslot(0), &[0x11; 32]).unwrap();
    assert_eq!(dev.spi_ref().nonces(), (1, 1));
    dev.eddsa_sign(eslot(1), b"sign me").unwrap();
    assert_eq!(dev.spi_ref().nonces(), (2, 2));
    let pk = dev.ecc_public_key(eslot(2)).unwrap();
    assert_eq!(pk.curve(), EccCurve::Ed25519);
    assert_eq!(dev.spi_ref().nonces(), (3, 3));
}

/// Builds a MAC-and-Destroy slot index, panicking only in test code on a
/// bad constant.
fn mdslot(value: u8) -> MacDestroySlot
{
    MacDestroySlot::new(value).expect("test mac-destroy slot out of range")
}

/// Recomputes the chip mock's deterministic DATA_OUT for a (slot, input).
fn expected_mac_out(slot: u8, input: &[u8; 32]) -> [u8; 32]
{
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate()
    {
        *b = input[i] ^ slot ^ (i as u8);
    }
    out
}

#[test]
fn mac_and_destroy_round_trips_known_output()
{
    let mut dev = open(ChipFault::None);
    let mut input = [0u8; 32];
    for (i, b) in input.iter_mut().enumerate()
    {
        *b = (i as u8).wrapping_mul(11).wrapping_add(3);
    }
    let out = dev.mac_and_destroy(mdslot(5), &input).unwrap();
    assert_eq!(out.expose(), &expected_mac_out(5, &input));
    assert_eq!(dev.spi_ref().nonces(), (1, 1));
}

#[test]
fn mac_and_destroy_fail_is_recoverable()
{
    // FAIL (0x3C) is a valid authenticated reply: the session stays live
    // and the nonces stay in step. A consumed slot replies OK (not FAIL),
    // so FAIL is not a slot-exhaustion signal here.
    let mut dev = open(ChipFault::ResultFail);
    let input = [0x11u8; 32];
    assert_eq!
    (
        dev.mac_and_destroy(mdslot(0), &input).map(|o| *o.expose()),
        Err(SeError::L3(L3Error::Result(L3Status::Fail)))
    );
    let before = dev.spi_ref().transaction_count();
    let r = dev.mac_and_destroy(mdslot(0), &input).map(|o| *o.expose());
    assert_eq!(r, Err(SeError::L3(L3Error::Result(L3Status::Fail))));
    assert!(dev.spi_ref().transaction_count() > before, "chip traffic continues");
    assert_eq!(dev.spi_ref().nonces(), (2, 2), "nonces stay in lockstep");
}

#[test]
fn mac_and_destroy_wrong_size_result_poisons_session()
{
    // An authenticated OK result one byte short of the fixed 35-byte RES_DATA
    // trips run's expected_res_data_len check and poisons.
    let mut dev = open(ChipFault::ResultWrongSize);
    assert_eq!
    (
        dev.mac_and_destroy(mdslot(0), &[0u8; 32]).map(|o| *o.expose()),
        Err(SeError::L3(L3Error::Oversize))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn mac_and_destroy_extra_result_byte_poisons_session()
{
    // One byte past the fixed 35-byte RES_DATA trips the expected-length
    // check and poisons.
    let mut dev = open(ChipFault::ExtraResultByte);
    assert_eq!
    (
        dev.mac_and_destroy(mdslot(0), &[0u8; 32]).map(|o| *o.expose()),
        Err(SeError::L3(L3Error::Oversize))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn mac_and_destroy_bad_tag_poisons_session()
{
    let mut dev = open(ChipFault::BadResultTag);
    assert_eq!
    (
        dev.mac_and_destroy(mdslot(0), &[0u8; 32]).map(|o| *o.expose()),
        Err(SeError::L3(L3Error::Tag))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn mac_and_destroy_alarm_poisons_session()
{
    let mut dev = open(ChipFault::Alarm);
    assert_eq!
    (
        dev.mac_and_destroy(mdslot(0), &[0u8; 32]).map(|o| *o.expose()),
        Err(SeError::L2(L2Error::L1(L1Error::Alarm)))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn mac_and_destroy_empty_result_poisons_session()
{
    let mut dev = open(ChipFault::EmptyResult);
    assert_eq!
    (
        dev.mac_and_destroy(mdslot(0), &[0u8; 32]).map(|o| *o.expose()),
        Err(SeError::L3(L3Error::Parse(ParseError::UnexpectedEnd)))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn mac_and_destroy_poisoned_session_fast_fails()
{
    // A prior poison makes the next call fast-fail with SessionLost before
    // any chip traffic.
    let mut dev = open(ChipFault::BadResultTag);
    let _ = dev.mac_and_destroy(mdslot(0), &[0u8; 32]).map(|o| *o.expose());
    let before = dev.spi_ref().transaction_count();
    assert_eq!
    (
        dev.mac_and_destroy(mdslot(0), &[0u8; 32]).map(|o| *o.expose()),
        Err(SeError::SessionLost)
    );
    assert_eq!(dev.spi_ref().transaction_count(), before, "no chip traffic after poison");
}

#[test]
fn mac_and_destroy_l3_buffer_is_wiped_after_success()
{
    let mut dev = open(ChipFault::None);
    let _ = dev.mac_and_destroy(mdslot(3), &[0xAB; 32]).unwrap();
    assert!(dev.l3.as_slice().iter().all(|&b| b == 0), "plaintext residue");
}

#[test]
fn mac_and_destroy_l3_buffer_is_wiped_even_on_poison()
{
    // SECURITY: DATA_IN is secret material in the L3 plaintext buffer. Even
    // when the command poisons the session, the input must not survive.
    let mut dev = open(ChipFault::BadResultTag);
    let _ = dev.mac_and_destroy(mdslot(3), &[0xAB; 32]).map(|o| *o.expose());
    assert!(dev.l3.as_slice().iter().all(|&b| b == 0), "secret input residue after poison");
}

#[test]
fn rmem_erase_round_trips_and_advances_nonces()
{
    let mut dev = open(ChipFault::None);
    assert_eq!(dev.rmem_erase(rslot(7)), Ok(()));
    assert_eq!(dev.spi_ref().nonces(), (1, 1));
}

#[test]
fn rmem_erase_non_ok_result_is_recoverable()
{
    // A FAIL result is a valid authenticated reply: the error surfaces but
    // the session stays live and the nonces stay in step.
    let mut dev = open(ChipFault::ResultFail);
    assert_eq!
    (
        dev.rmem_erase(rslot(2)),
        Err(SeError::L3(L3Error::Result(L3Status::Fail)))
    );
    let before = dev.spi_ref().transaction_count();
    let r = dev.rmem_erase(rslot(2));
    assert_eq!(r, Err(SeError::L3(L3Error::Result(L3Status::Fail))));
    assert!(dev.spi_ref().transaction_count() > before, "chip traffic continues");
    assert_eq!(dev.spi_ref().nonces(), (2, 2), "nonces stay in lockstep");
}

#[test]
fn rmem_erase_extra_result_byte_poisons_session()
{
    // rmem_erase is a Some(0) command: it expects no RES_DATA. One unexpected
    // byte trips the expected-length check and poisons. Guards a regression
    // to None with a trivial closure.
    let mut dev = open(ChipFault::ExtraResultByte);
    assert_eq!(dev.rmem_erase(rslot(0)), Err(SeError::L3(L3Error::Oversize)));
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn rmem_erase_bad_tag_poisons_session()
{
    let mut dev = open(ChipFault::BadResultTag);
    assert_eq!(dev.rmem_erase(rslot(0)), Err(SeError::L3(L3Error::Tag)));
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn rmem_erase_l2_crc_err_poisons_session()
{
    let mut dev = open(ChipFault::L2CrcErr);
    assert_eq!(dev.rmem_erase(rslot(0)), Err(SeError::L2(L2Error::Crc)));
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn rmem_erase_alarm_poisons_session()
{
    let mut dev = open(ChipFault::Alarm);
    assert_eq!
    (
        dev.rmem_erase(rslot(0)),
        Err(SeError::L2(L2Error::L1(L1Error::Alarm)))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn rmem_erase_empty_result_poisons_session()
{
    let mut dev = open(ChipFault::EmptyResult);
    assert_eq!
    (
        dev.rmem_erase(rslot(0)),
        Err(SeError::L3(L3Error::Parse(ParseError::UnexpectedEnd)))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn mcounter_init_round_trips_and_advances_nonces()
{
    let mut dev = open(ChipFault::None);
    assert_eq!(dev.mcounter_init(mc(0), 0x0102_0304), Ok(()));
    assert_eq!(dev.spi_ref().nonces(), (1, 1));
    // A second init at the max index and max value also round-trips, proving
    // the 8-byte plaintext (including the u32 value) reaches the chip.
    assert_eq!(dev.mcounter_init(mc(15), u32::MAX), Ok(()));
    assert_eq!(dev.spi_ref().nonces(), (2, 2));
}

#[test]
fn mcounter_init_non_ok_result_is_recoverable()
{
    let mut dev = open(ChipFault::ResultFail);
    assert_eq!
    (
        dev.mcounter_init(mc(0), 7),
        Err(SeError::L3(L3Error::Result(L3Status::Fail)))
    );
    let before = dev.spi_ref().transaction_count();
    let r = dev.mcounter_init(mc(0), 7);
    assert_eq!(r, Err(SeError::L3(L3Error::Result(L3Status::Fail))));
    assert!(dev.spi_ref().transaction_count() > before, "chip traffic continues");
    assert_eq!(dev.spi_ref().nonces(), (2, 2), "nonces stay in lockstep");
}

#[test]
fn mcounter_init_extra_result_byte_poisons_session()
{
    // mcounter_init is a Some(0) command: one unexpected RES_DATA byte trips
    // the expected-length check and poisons.
    let mut dev = open(ChipFault::ExtraResultByte);
    assert_eq!(dev.mcounter_init(mc(0), 1), Err(SeError::L3(L3Error::Oversize)));
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn mcounter_init_bad_tag_poisons_session()
{
    let mut dev = open(ChipFault::BadResultTag);
    assert_eq!(dev.mcounter_init(mc(0), 1), Err(SeError::L3(L3Error::Tag)));
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn mcounter_init_l2_crc_err_poisons_session()
{
    let mut dev = open(ChipFault::L2CrcErr);
    assert_eq!(dev.mcounter_init(mc(0), 1), Err(SeError::L2(L2Error::Crc)));
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn mcounter_init_empty_result_poisons_session()
{
    let mut dev = open(ChipFault::EmptyResult);
    assert_eq!
    (
        dev.mcounter_init(mc(0), 1),
        Err(SeError::L3(L3Error::Parse(ParseError::UnexpectedEnd)))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn mcounter_update_round_trips_and_advances_nonces()
{
    let mut dev = open(ChipFault::None);
    assert_eq!(dev.mcounter_update(mc(4)), Ok(()));
    assert_eq!(dev.spi_ref().nonces(), (1, 1));
}

#[test]
fn mcounter_update_at_zero_is_recoverable()
{
    // UpdateErr (0x13) = the counter is already at zero (a decrement would
    // underflow). It is a valid authenticated reply per libtropic / user-API
    // Table 36: the session stays live and the nonces stay in step.
    let mut dev = open(ChipFault::UpdateErr);
    assert_eq!
    (
        dev.mcounter_update(mc(0)),
        Err(SeError::L3(L3Error::Result(L3Status::UpdateErr)))
    );
    let before = dev.spi_ref().transaction_count();
    let r = dev.mcounter_update(mc(0));
    assert_eq!(r, Err(SeError::L3(L3Error::Result(L3Status::UpdateErr))));
    assert!(dev.spi_ref().transaction_count() > before, "chip traffic continues");
    assert_eq!(dev.spi_ref().nonces(), (2, 2), "nonces stay in lockstep");
}

#[test]
fn mcounter_update_counter_invalid_is_recoverable()
{
    // CounterInvalid (0x14) = an uninitialized or locked counter: a valid
    // authenticated reply. The session stays live and the nonces stay in step.
    let mut dev = open(ChipFault::CounterInvalid);
    assert_eq!
    (
        dev.mcounter_update(mc(0)),
        Err(SeError::L3(L3Error::Result(L3Status::CounterInvalid)))
    );
    let before = dev.spi_ref().transaction_count();
    let r = dev.mcounter_update(mc(0));
    assert_eq!(r, Err(SeError::L3(L3Error::Result(L3Status::CounterInvalid))));
    assert!(dev.spi_ref().transaction_count() > before, "chip traffic continues");
    assert_eq!(dev.spi_ref().nonces(), (2, 2), "nonces stay in lockstep");
}

#[test]
fn mcounter_update_extra_result_byte_poisons_session()
{
    // mcounter_update is a Some(0) command: one unexpected RES_DATA byte
    // trips the expected-length check and poisons.
    let mut dev = open(ChipFault::ExtraResultByte);
    assert_eq!(dev.mcounter_update(mc(0)), Err(SeError::L3(L3Error::Oversize)));
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn mcounter_update_bad_tag_poisons_session()
{
    let mut dev = open(ChipFault::BadResultTag);
    assert_eq!(dev.mcounter_update(mc(0)), Err(SeError::L3(L3Error::Tag)));
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn mcounter_update_l2_crc_err_poisons_session()
{
    let mut dev = open(ChipFault::L2CrcErr);
    assert_eq!(dev.mcounter_update(mc(0)), Err(SeError::L2(L2Error::Crc)));
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn mcounter_update_alarm_poisons_session()
{
    let mut dev = open(ChipFault::Alarm);
    assert_eq!
    (
        dev.mcounter_update(mc(0)),
        Err(SeError::L2(L2Error::L1(L1Error::Alarm)))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn mcounter_update_empty_result_poisons_session()
{
    let mut dev = open(ChipFault::EmptyResult);
    assert_eq!
    (
        dev.mcounter_update(mc(0)),
        Err(SeError::L3(L3Error::Parse(ParseError::UnexpectedEnd)))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn mcounter_l3_buffer_is_wiped_after_a_successful_init()
{
    let mut dev = open(ChipFault::None);
    dev.mcounter_init(mc(0), 0xDEAD_BEEF).unwrap();
    assert!(dev.l3.as_slice().iter().all(|&b| b == 0), "plaintext residue");
}

#[test]
fn mixed_mcounter_rmem_erase_sequence_keeps_nonces_in_lockstep()
{
    // An init, an update, an rmem_erase, and a ping each advance both nonces
    // once across the mixed 2c-command sequence.
    let mut dev = open(ChipFault::None);
    let mut buf = [0u8; 16];
    dev.mcounter_init(mc(2), 50).unwrap();
    assert_eq!(dev.spi_ref().nonces(), (1, 1));
    dev.mcounter_update(mc(2)).unwrap();
    assert_eq!(dev.spi_ref().nonces(), (2, 2));
    dev.rmem_erase(rslot(3)).unwrap();
    assert_eq!(dev.spi_ref().nonces(), (3, 3));
    dev.ping_into(b"x", &mut buf).unwrap();
    assert_eq!(dev.spi_ref().nonces(), (4, 4));
}

#[test]
fn se_commands_trait_dispatch_round_trips()
{
    // Drive several commands through the SeCommands trait, not the inherent
    // methods, to prove the trait dispatch compiles and runs. A generic
    // helper bounds the call to the trait surface alone.
    fn exercise<T: SeCommands>
    (
        se: &mut T,
        slot: MacDestroySlot,
        input: &[u8; 32],
    )
    -> Result<MacAndDestroyOutput, SeError>
    {
        let mut out = [0u8; 8];
        se.random_into(&mut out)?;
        se.rmem_erase(RMemSlot::new(3).expect("test slot"))?;
        se.mcounter_init(MCounterIdx::new(1).expect("test idx"), 9)?;
        se.mcounter_update(MCounterIdx::new(1).expect("test idx"))?;
        let key = Zeroizing::new([7u8; 32]);
        se.ecc_key_store(EccSlot::new(8).expect("test slot"), EccCurve::Ed25519, &key)?;
        se.ecc_key_erase(EccSlot::new(8).expect("test slot"))?;
        se.mac_and_destroy(slot, input)
    }

    let mut dev = open(ChipFault::None);
    let input = [0x42u8; 32];
    let out = exercise(&mut dev, mdslot(9), &input).unwrap();
    assert_eq!(out.expose(), &expected_mac_out(9, &input));
    // random_into, rmem_erase, mcounter_init, mcounter_update, ecc_key_store,
    // ecc_key_erase, then mac_and_destroy each advance both nonces once:
    // seven round-trips.
    assert_eq!(dev.spi_ref().nonces(), (7, 7));
}

#[test]
fn nonce_exhaustion_poisons_before_touching_the_chip()
{
    let mut dev = open(ChipFault::None);
    dev.seed_nonces(u32::MAX, u32::MAX);
    let before = dev.spi_ref().transaction_count();
    let mut out = [0u8; 16];
    assert_eq!(dev.ping_into(b"hi", &mut out), Err(SeError::NonceExhausted));
    // Exhaustion is caught before any SPI traffic.
    assert_eq!(dev.spi_ref().transaction_count(), before);
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn close_session_returns_no_session_handle()
{
    let dev = open(ChipFault::None);
    let dev = dev.close_session();
    // Back to NoSession: buffers wiped, ready to re-open.
    assert!(dev.l2.iter().all(|&b| b == 0));
    assert!(dev.l3.as_slice().iter().all(|&b| b == 0));
}

/// Builds an `ActiveSession` handle over `spi` with fixed dummy keys.
///
/// Used by the `abort_session` teardown tests, which need an active handle but
/// not a full handshake: the notify is a plain L2 round-trip and the keys only
/// need to exist so the teardown can be observed to wipe the buffers.
fn active_over<SPI>(spi: SPI) -> Tropic01<SPI, MockWait, ActiveSession>
{
    Tropic01
    {
        spi,
        wait: MockWait::new(),
        l2: [0xABu8; L2_FRAME_MAX],
        l3: crate::buf::L3Buf::new(),
        state: ActiveSession::new(SessionKeys::new([0x11u8; 32], [0x22u8; 32])),
    }
}

#[test]
fn abort_session_request_frame_matches_libtropic_golden()
{
    // Byte-exact Encrypted_Session_Abt_Req: REQ_ID 0x08, REQ_LEN 0, CRC 0x03B0.
    let acks = std::vec![l2_frame(L2Status::RequestOk as u8, &[])];
    let dev = active_over(RecordingSpi::new(acks));
    let (dev, result) = dev.abort_session();
    assert_eq!(result, Ok(()));
    assert_eq!(dev.spi_ref().writes()[0], std::vec![0x08, 0x00, 0x03, 0xB0]);
}

#[test]
fn abort_session_ok_returns_no_session_and_wipes_buffers()
{
    let acks = std::vec![l2_frame(L2Status::RequestOk as u8, &[])];
    let dev = active_over(RecordingSpi::new(acks));
    let (dev, result): (Tropic01<_, _, NoSession>, _) = dev.abort_session();
    assert_eq!(result, Ok(()));
    // Back to NoSession: the local teardown wiped both buffers.
    assert!(dev.l2.iter().all(|&b| b == 0));
    assert!(dev.l3.as_slice().iter().all(|&b| b == 0));
}

#[test]
fn abort_session_bad_ack_still_wipes_and_returns_no_session()
{
    // A non-empty ack is a malformed reply: the notify reports BadFrame, but the
    // teardown still runs. The keys are wiped on this path too, proven by the
    // NoSession buffers all reading zero.
    let acks = std::vec![l2_frame(L2Status::RequestOk as u8, &[0xAA])];
    let dev = active_over(RecordingSpi::new(acks));
    let (dev, result): (Tropic01<_, _, NoSession>, _) = dev.abort_session();
    assert_eq!(result, Err(SeError::L2(L2Error::BadFrame)));
    assert!(dev.l2.iter().all(|&b| b == 0), "l2 wiped even on a failed notify");
    assert!(dev.l3.as_slice().iter().all(|&b| b == 0), "l3 wiped even on a failed notify");
}

#[test]
fn abort_session_chip_status_error_still_wipes_and_returns_no_session()
{
    // The chip replies a non-OK status: parse_response returns Err via `?`, a
    // different failure path than the explicit ack check. The teardown still runs
    // (it precedes the notify), so the buffers all read zero.
    let acks = std::vec![l2_frame(L2Status::GenErr as u8, &[])];
    let dev = active_over(RecordingSpi::new(acks));
    let (dev, result): (Tropic01<_, _, NoSession>, _) = dev.abort_session();
    assert_eq!(result, Err(SeError::L2(L2Error::Status(L2Status::GenErr))));
    assert!(dev.l2.iter().all(|&b| b == 0), "l2 wiped on a chip status error");
    assert!(dev.l3.as_slice().iter().all(|&b| b == 0), "l3 wiped on a chip status error");
}

/// Builds a pairing key slot index, panicking only in test code on a bad
/// constant.
fn pslot(value: u8) -> PairingKeySlot
{
    PairingKeySlot::new(value).expect("test pairing key slot out of range")
}

/// Builds a deterministic 32-byte host pairing public key for the tests.
fn sample_pairing_key() -> [u8; 32]
{
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate()
    {
        *b = (i as u8).wrapping_mul(7).wrapping_add(3);
    }
    k
}

#[test]
fn pairing_key_write_round_trips_and_advances_nonces()
{
    let mut dev = open(ChipFault::None);
    let key = sample_pairing_key();
    assert_eq!(dev.pairing_key_write(pslot(0), &key), Ok(()));
    assert_eq!(dev.spi_ref().nonces(), (1, 1));
    assert_eq!(dev.pairing_key_write(pslot(3), &key), Ok(()));
    assert_eq!(dev.spi_ref().nonces(), (2, 2));
}

#[test]
fn pairing_key_write_hardware_fail_is_recoverable()
{
    // HardwareFail (0x17): an OTP write error. A valid authenticated reply
    // that keeps the session live.
    let mut dev = open(ChipFault::HardwareFail);
    let key = sample_pairing_key();
    assert_eq!
    (
        dev.pairing_key_write(pslot(1), &key),
        Err(SeError::L3(L3Error::Result(L3Status::HardwareFail)))
    );
    let before = dev.spi_ref().transaction_count();
    let r = dev.pairing_key_write(pslot(1), &key);
    assert_eq!(r, Err(SeError::L3(L3Error::Result(L3Status::HardwareFail))));
    assert!(dev.spi_ref().transaction_count() > before, "chip traffic continues");
    assert_eq!(dev.spi_ref().nonces(), (2, 2), "nonces stay in lockstep");
}

#[test]
fn pairing_key_write_extra_result_byte_poisons_session()
{
    // pairing_key_write is a Some(0) command: one unexpected RES_DATA byte
    // trips the expected-length check and poisons.
    let mut dev = open(ChipFault::ExtraResultByte);
    let key = sample_pairing_key();
    assert_eq!
    (
        dev.pairing_key_write(pslot(0), &key),
        Err(SeError::L3(L3Error::Oversize))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn pairing_key_write_bad_tag_poisons_session()
{
    let mut dev = open(ChipFault::BadResultTag);
    let key = sample_pairing_key();
    assert_eq!
    (
        dev.pairing_key_write(pslot(0), &key),
        Err(SeError::L3(L3Error::Tag))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn pairing_key_write_l2_crc_err_poisons_session()
{
    let mut dev = open(ChipFault::L2CrcErr);
    let key = sample_pairing_key();
    assert_eq!
    (
        dev.pairing_key_write(pslot(0), &key),
        Err(SeError::L2(L2Error::Crc))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn pairing_key_write_alarm_poisons_session()
{
    let mut dev = open(ChipFault::Alarm);
    let key = sample_pairing_key();
    assert_eq!
    (
        dev.pairing_key_write(pslot(0), &key),
        Err(SeError::L2(L2Error::L1(L1Error::Alarm)))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn pairing_key_write_empty_result_poisons_session()
{
    let mut dev = open(ChipFault::EmptyResult);
    let key = sample_pairing_key();
    assert_eq!
    (
        dev.pairing_key_write(pslot(0), &key),
        Err(SeError::L3(L3Error::Parse(ParseError::UnexpectedEnd)))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn pairing_key_read_round_trips_returns_32_byte_key()
{
    // The mock returns PADDING(3) || S_HIPUB(32). The driver must skip the
    // padding and return exactly the configured 32-byte key.
    let mut dev = open(ChipFault::None);
    let key = sample_pairing_key();
    dev.spi_mut().set_pairing_key(key);
    assert_eq!(dev.pairing_key_read(pslot(0)), Ok(key));
    assert_eq!(dev.spi_ref().nonces(), (1, 1));
}

#[test]
fn pairing_key_read_slot_empty_is_recoverable()
{
    // SlotEmpty (0x15): an unprovisioned pairing slot. A valid authenticated
    // reply that keeps the session live.
    let mut dev = open(ChipFault::SlotEmpty);
    assert_eq!
    (
        dev.pairing_key_read(pslot(2)),
        Err(SeError::L3(L3Error::Result(L3Status::SlotEmpty)))
    );
    let before = dev.spi_ref().transaction_count();
    let r = dev.pairing_key_read(pslot(2));
    assert_eq!(r, Err(SeError::L3(L3Error::Result(L3Status::SlotEmpty))));
    assert!(dev.spi_ref().transaction_count() > before, "chip traffic continues");
    assert_eq!(dev.spi_ref().nonces(), (2, 2), "nonces stay in lockstep");
}

#[test]
fn pairing_key_read_slot_invalid_is_recoverable()
{
    // SlotInvalid (0x16): an invalidated pairing slot. A valid authenticated
    // reply that keeps the session live.
    let mut dev = open(ChipFault::SlotInvalid);
    assert_eq!
    (
        dev.pairing_key_read(pslot(1)),
        Err(SeError::L3(L3Error::Result(L3Status::SlotInvalid)))
    );
    let before = dev.spi_ref().transaction_count();
    let r = dev.pairing_key_read(pslot(1));
    assert_eq!(r, Err(SeError::L3(L3Error::Result(L3Status::SlotInvalid))));
    assert!(dev.spi_ref().transaction_count() > before, "chip traffic continues");
    assert_eq!(dev.spi_ref().nonces(), (2, 2), "nonces stay in lockstep");
}

#[test]
fn pairing_key_read_wrong_size_result_poisons_session()
{
    // An authenticated OK result one byte short of the fixed 35-byte RES_DATA
    // trips run's expected_res_data_len check and poisons.
    let mut dev = open(ChipFault::ResultWrongSize);
    assert_eq!
    (
        dev.pairing_key_read(pslot(0)),
        Err(SeError::L3(L3Error::Oversize))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn pairing_key_read_bad_tag_poisons_session()
{
    let mut dev = open(ChipFault::BadResultTag);
    assert_eq!(dev.pairing_key_read(pslot(0)), Err(SeError::L3(L3Error::Tag)));
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn pairing_key_read_l2_crc_err_poisons_session()
{
    let mut dev = open(ChipFault::L2CrcErr);
    assert_eq!(dev.pairing_key_read(pslot(0)), Err(SeError::L2(L2Error::Crc)));
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn pairing_key_read_alarm_poisons_session()
{
    let mut dev = open(ChipFault::Alarm);
    assert_eq!
    (
        dev.pairing_key_read(pslot(0)),
        Err(SeError::L2(L2Error::L1(L1Error::Alarm)))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn pairing_key_read_empty_result_poisons_session()
{
    let mut dev = open(ChipFault::EmptyResult);
    assert_eq!
    (
        dev.pairing_key_read(pslot(0)),
        Err(SeError::L3(L3Error::Parse(ParseError::UnexpectedEnd)))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn pairing_key_invalidate_succeeds_and_advances_nonces()
{
    let mut dev = open(ChipFault::None);
    assert_eq!(dev.pairing_key_invalidate(pslot(2)), Ok(()));
    assert_eq!(dev.spi_ref().nonces(), (1, 1));
}

#[test]
fn pairing_key_invalidate_hardware_fail_is_recoverable()
{
    // HardwareFail (0x17): an OTP write error. A valid authenticated reply
    // that keeps the session live.
    let mut dev = open(ChipFault::HardwareFail);
    assert_eq!
    (
        dev.pairing_key_invalidate(pslot(0)),
        Err(SeError::L3(L3Error::Result(L3Status::HardwareFail)))
    );
    let before = dev.spi_ref().transaction_count();
    let r = dev.pairing_key_invalidate(pslot(0));
    assert_eq!(r, Err(SeError::L3(L3Error::Result(L3Status::HardwareFail))));
    assert!(dev.spi_ref().transaction_count() > before, "chip traffic continues");
    assert_eq!(dev.spi_ref().nonces(), (2, 2), "nonces stay in lockstep");
}

#[test]
fn pairing_key_invalidate_extra_result_byte_poisons_session()
{
    let mut dev = open(ChipFault::ExtraResultByte);
    assert_eq!
    (
        dev.pairing_key_invalidate(pslot(0)),
        Err(SeError::L3(L3Error::Oversize))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn pairing_key_invalidate_bad_tag_poisons_session()
{
    let mut dev = open(ChipFault::BadResultTag);
    assert_eq!(dev.pairing_key_invalidate(pslot(0)), Err(SeError::L3(L3Error::Tag)));
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn pairing_key_invalidate_l2_crc_err_poisons_session()
{
    let mut dev = open(ChipFault::L2CrcErr);
    assert_eq!(dev.pairing_key_invalidate(pslot(0)), Err(SeError::L2(L2Error::Crc)));
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn pairing_key_invalidate_alarm_poisons_session()
{
    let mut dev = open(ChipFault::Alarm);
    assert_eq!
    (
        dev.pairing_key_invalidate(pslot(0)),
        Err(SeError::L2(L2Error::L1(L1Error::Alarm)))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn pairing_key_invalidate_empty_result_poisons_session()
{
    let mut dev = open(ChipFault::EmptyResult);
    assert_eq!
    (
        dev.pairing_key_invalidate(pslot(0)),
        Err(SeError::L3(L3Error::Parse(ParseError::UnexpectedEnd)))
    );
    assert_session_lost_and_quiet(&mut dev);
}

// ---- Config objects (R-Config / I-Config, L3) ----

#[test]
fn r_config_write_round_trips_and_advances_nonces()
{
    let mut dev = open(ChipFault::None);
    assert_eq!(dev.r_config_write(ConfigObjectAddr::CfgUapPing, 0x0102_0304), Ok(()));
    assert_eq!(dev.spi_ref().nonces(), (1, 1));
    // A second write at a different object and the max value also round-trips,
    // proving the 8-byte plaintext (including the u32 value) reaches the chip.
    assert_eq!(dev.r_config_write(ConfigObjectAddr::CfgSensors, u32::MAX), Ok(()));
    assert_eq!(dev.spi_ref().nonces(), (2, 2));
}

#[test]
fn r_config_write_request_layout_is_byte_exact()
{
    // Pin the wire layout the chip actually decrypts: CMD_ID || ADDRESS(u16 LE)
    // || PADDING(1,=0) || VALUE(u32 LE). The mock ignores a write payload, so
    // without this the value/address/padding encoding would be untested.
    let mut dev = open(ChipFault::None);
    assert_eq!(dev.r_config_write(ConfigObjectAddr::CfgSensors, 0x0A0B_0C0D), Ok(()));
    assert_eq!
    (
        dev.spi_ref().last_command(),
        // 0x20, addr 0x0008 LE, padding 0, value 0x0A0B0C0D LE.
        &[0x20, 0x08, 0x00, 0x00, 0x0D, 0x0C, 0x0B, 0x0A]
    );
}

#[test]
fn r_config_write_unauthorized_is_recoverable()
{
    // Unauthorized (0x01) is a known L3Status: run maps it to a recoverable
    // L3Error::Result and keeps the session live. No poison.
    let mut dev = open(ChipFault::Unauthorized);
    assert_eq!
    (
        dev.r_config_write(ConfigObjectAddr::CfgUapPing, 7),
        Err(SeError::L3(L3Error::Result(L3Status::Unauthorized)))
    );
    let before = dev.spi_ref().transaction_count();
    let r = dev.r_config_write(ConfigObjectAddr::CfgUapPing, 7);
    assert_eq!(r, Err(SeError::L3(L3Error::Result(L3Status::Unauthorized))));
    assert!(dev.spi_ref().transaction_count() > before, "chip traffic continues");
    assert_eq!(dev.spi_ref().nonces(), (2, 2), "nonces stay in lockstep");
}

#[test]
fn r_config_write_extra_result_byte_poisons_session()
{
    // r_config_write is a Some(0) command: one unexpected RES_DATA byte trips
    // the expected-length check and poisons.
    let mut dev = open(ChipFault::ExtraResultByte);
    assert_eq!
    (
        dev.r_config_write(ConfigObjectAddr::CfgUapPing, 1),
        Err(SeError::L3(L3Error::Oversize))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn r_config_write_bad_tag_poisons_session()
{
    let mut dev = open(ChipFault::BadResultTag);
    assert_eq!
    (
        dev.r_config_write(ConfigObjectAddr::CfgUapPing, 1),
        Err(SeError::L3(L3Error::Tag))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn r_config_write_l2_crc_err_poisons_session()
{
    let mut dev = open(ChipFault::L2CrcErr);
    assert_eq!
    (
        dev.r_config_write(ConfigObjectAddr::CfgUapPing, 1),
        Err(SeError::L2(L2Error::Crc))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn r_config_write_alarm_poisons_session()
{
    let mut dev = open(ChipFault::Alarm);
    assert_eq!
    (
        dev.r_config_write(ConfigObjectAddr::CfgUapPing, 1),
        Err(SeError::L2(L2Error::L1(L1Error::Alarm)))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn r_config_write_empty_result_poisons_session()
{
    let mut dev = open(ChipFault::EmptyResult);
    assert_eq!
    (
        dev.r_config_write(ConfigObjectAddr::CfgUapPing, 1),
        Err(SeError::L3(L3Error::Parse(ParseError::UnexpectedEnd)))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn r_config_read_round_trips_returns_the_value()
{
    // The mock returns PADDING(3) || VALUE(u32 LE). The driver must skip the
    // padding and return exactly the configured value, proving the LE read.
    let mut dev = open(ChipFault::None);
    dev.spi_mut().set_config_value(0xDEAD_BEEF);
    assert_eq!(dev.r_config_read(ConfigObjectAddr::CfgUapPing), Ok(0xDEAD_BEEF));
    assert_eq!(dev.spi_ref().nonces(), (1, 1));
}

#[test]
fn r_config_read_unauthorized_is_recoverable()
{
    let mut dev = open(ChipFault::Unauthorized);
    assert_eq!
    (
        dev.r_config_read(ConfigObjectAddr::CfgUapPing),
        Err(SeError::L3(L3Error::Result(L3Status::Unauthorized)))
    );
    let before = dev.spi_ref().transaction_count();
    let r = dev.r_config_read(ConfigObjectAddr::CfgUapPing);
    assert_eq!(r, Err(SeError::L3(L3Error::Result(L3Status::Unauthorized))));
    assert!(dev.spi_ref().transaction_count() > before, "chip traffic continues");
    assert_eq!(dev.spi_ref().nonces(), (2, 2), "nonces stay in lockstep");
}

#[test]
fn r_config_read_wrong_size_result_poisons_session()
{
    // An authenticated OK result one byte short of the fixed 7-byte RES_DATA
    // trips run's expected_res_data_len check and poisons.
    let mut dev = open(ChipFault::ResultWrongSize);
    assert_eq!
    (
        dev.r_config_read(ConfigObjectAddr::CfgUapPing),
        Err(SeError::L3(L3Error::Oversize))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn r_config_read_bad_tag_poisons_session()
{
    let mut dev = open(ChipFault::BadResultTag);
    assert_eq!
    (
        dev.r_config_read(ConfigObjectAddr::CfgUapPing),
        Err(SeError::L3(L3Error::Tag))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn r_config_read_l2_crc_err_poisons_session()
{
    let mut dev = open(ChipFault::L2CrcErr);
    assert_eq!
    (
        dev.r_config_read(ConfigObjectAddr::CfgUapPing),
        Err(SeError::L2(L2Error::Crc))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn r_config_read_alarm_poisons_session()
{
    let mut dev = open(ChipFault::Alarm);
    assert_eq!
    (
        dev.r_config_read(ConfigObjectAddr::CfgUapPing),
        Err(SeError::L2(L2Error::L1(L1Error::Alarm)))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn r_config_read_empty_result_poisons_session()
{
    let mut dev = open(ChipFault::EmptyResult);
    assert_eq!
    (
        dev.r_config_read(ConfigObjectAddr::CfgUapPing),
        Err(SeError::L3(L3Error::Parse(ParseError::UnexpectedEnd)))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn r_config_erase_round_trips_and_advances_nonces()
{
    let mut dev = open(ChipFault::None);
    assert_eq!(dev.r_config_erase(), Ok(()));
    assert_eq!(dev.spi_ref().nonces(), (1, 1));
}

#[test]
fn r_config_erase_unauthorized_is_recoverable()
{
    let mut dev = open(ChipFault::Unauthorized);
    assert_eq!
    (
        dev.r_config_erase(),
        Err(SeError::L3(L3Error::Result(L3Status::Unauthorized)))
    );
    let before = dev.spi_ref().transaction_count();
    let r = dev.r_config_erase();
    assert_eq!(r, Err(SeError::L3(L3Error::Result(L3Status::Unauthorized))));
    assert!(dev.spi_ref().transaction_count() > before, "chip traffic continues");
    assert_eq!(dev.spi_ref().nonces(), (2, 2), "nonces stay in lockstep");
}

#[test]
fn r_config_erase_extra_result_byte_poisons_session()
{
    let mut dev = open(ChipFault::ExtraResultByte);
    assert_eq!(dev.r_config_erase(), Err(SeError::L3(L3Error::Oversize)));
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn r_config_erase_bad_tag_poisons_session()
{
    let mut dev = open(ChipFault::BadResultTag);
    assert_eq!(dev.r_config_erase(), Err(SeError::L3(L3Error::Tag)));
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn r_config_erase_l2_crc_err_poisons_session()
{
    let mut dev = open(ChipFault::L2CrcErr);
    assert_eq!(dev.r_config_erase(), Err(SeError::L2(L2Error::Crc)));
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn r_config_erase_alarm_poisons_session()
{
    let mut dev = open(ChipFault::Alarm);
    assert_eq!(dev.r_config_erase(), Err(SeError::L2(L2Error::L1(L1Error::Alarm))));
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn r_config_erase_empty_result_poisons_session()
{
    let mut dev = open(ChipFault::EmptyResult);
    assert_eq!
    (
        dev.r_config_erase(),
        Err(SeError::L3(L3Error::Parse(ParseError::UnexpectedEnd)))
    );
    assert_session_lost_and_quiet(&mut dev);
}

/// Builds an I-Config bit index, panicking only in test code on a bad
/// constant.
fn cbit(value: u8) -> ConfigBitIndex
{
    ConfigBitIndex::new(value).expect("test config bit index out of range")
}

#[test]
fn i_config_write_round_trips_and_advances_nonces()
{
    // The write carries ADDRESS || BIT_INDEX (no value). A successful burn
    // round-trips and advances both nonces. A second at the max bit also
    // works, proving the 4-byte plaintext reaches the chip.
    let mut dev = open(ChipFault::None);
    assert_eq!(dev.i_config_write(ConfigObjectAddr::CfgUapPing, cbit(0)), Ok(()));
    assert_eq!(dev.spi_ref().nonces(), (1, 1));
    assert_eq!(dev.i_config_write(ConfigObjectAddr::CfgSensors, cbit(31)), Ok(()));
    assert_eq!(dev.spi_ref().nonces(), (2, 2));
}

#[test]
fn i_config_write_request_layout_is_byte_exact()
{
    // The irreversible bit-burn has no live model test (a real burn is one-way
    // and the model defers config to next boot), so pin its 4-byte wire layout
    // here: CMD_ID || ADDRESS(u16 LE) || BIT_INDEX(u8). A transposed address or
    // bit would mis-burn an OTP bit, so this assertion is load-bearing.
    let mut dev = open(ChipFault::None);
    assert_eq!(dev.i_config_write(ConfigObjectAddr::CfgSensors, cbit(31)), Ok(()));
    assert_eq!
    (
        dev.spi_ref().last_command(),
        // 0x30, addr 0x0008 LE, bit_index 31 (0x1F). No value, no padding.
        &[0x30, 0x08, 0x00, 0x1F]
    );
}

#[test]
fn i_config_write_unauthorized_is_recoverable()
{
    let mut dev = open(ChipFault::Unauthorized);
    assert_eq!
    (
        dev.i_config_write(ConfigObjectAddr::CfgUapPing, cbit(3)),
        Err(SeError::L3(L3Error::Result(L3Status::Unauthorized)))
    );
    let before = dev.spi_ref().transaction_count();
    let r = dev.i_config_write(ConfigObjectAddr::CfgUapPing, cbit(3));
    assert_eq!(r, Err(SeError::L3(L3Error::Result(L3Status::Unauthorized))));
    assert!(dev.spi_ref().transaction_count() > before, "chip traffic continues");
    assert_eq!(dev.spi_ref().nonces(), (2, 2), "nonces stay in lockstep");
}

#[test]
fn i_config_write_extra_result_byte_poisons_session()
{
    let mut dev = open(ChipFault::ExtraResultByte);
    assert_eq!
    (
        dev.i_config_write(ConfigObjectAddr::CfgUapPing, cbit(0)),
        Err(SeError::L3(L3Error::Oversize))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn i_config_write_bad_tag_poisons_session()
{
    let mut dev = open(ChipFault::BadResultTag);
    assert_eq!
    (
        dev.i_config_write(ConfigObjectAddr::CfgUapPing, cbit(0)),
        Err(SeError::L3(L3Error::Tag))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn i_config_write_l2_crc_err_poisons_session()
{
    let mut dev = open(ChipFault::L2CrcErr);
    assert_eq!
    (
        dev.i_config_write(ConfigObjectAddr::CfgUapPing, cbit(0)),
        Err(SeError::L2(L2Error::Crc))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn i_config_write_alarm_poisons_session()
{
    let mut dev = open(ChipFault::Alarm);
    assert_eq!
    (
        dev.i_config_write(ConfigObjectAddr::CfgUapPing, cbit(0)),
        Err(SeError::L2(L2Error::L1(L1Error::Alarm)))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn i_config_write_empty_result_poisons_session()
{
    let mut dev = open(ChipFault::EmptyResult);
    assert_eq!
    (
        dev.i_config_write(ConfigObjectAddr::CfgUapPing, cbit(0)),
        Err(SeError::L3(L3Error::Parse(ParseError::UnexpectedEnd)))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn i_config_read_round_trips_returns_the_value()
{
    let mut dev = open(ChipFault::None);
    dev.spi_mut().set_config_value(0x1122_3344);
    assert_eq!(dev.i_config_read(ConfigObjectAddr::CfgUapIConfigRead), Ok(0x1122_3344));
    assert_eq!(dev.spi_ref().nonces(), (1, 1));
}

#[test]
fn i_config_read_unauthorized_is_recoverable()
{
    let mut dev = open(ChipFault::Unauthorized);
    assert_eq!
    (
        dev.i_config_read(ConfigObjectAddr::CfgUapPing),
        Err(SeError::L3(L3Error::Result(L3Status::Unauthorized)))
    );
    let before = dev.spi_ref().transaction_count();
    let r = dev.i_config_read(ConfigObjectAddr::CfgUapPing);
    assert_eq!(r, Err(SeError::L3(L3Error::Result(L3Status::Unauthorized))));
    assert!(dev.spi_ref().transaction_count() > before, "chip traffic continues");
    assert_eq!(dev.spi_ref().nonces(), (2, 2), "nonces stay in lockstep");
}

#[test]
fn i_config_read_wrong_size_result_poisons_session()
{
    let mut dev = open(ChipFault::ResultWrongSize);
    assert_eq!
    (
        dev.i_config_read(ConfigObjectAddr::CfgUapPing),
        Err(SeError::L3(L3Error::Oversize))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn i_config_read_bad_tag_poisons_session()
{
    let mut dev = open(ChipFault::BadResultTag);
    assert_eq!
    (
        dev.i_config_read(ConfigObjectAddr::CfgUapPing),
        Err(SeError::L3(L3Error::Tag))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn i_config_read_l2_crc_err_poisons_session()
{
    let mut dev = open(ChipFault::L2CrcErr);
    assert_eq!
    (
        dev.i_config_read(ConfigObjectAddr::CfgUapPing),
        Err(SeError::L2(L2Error::Crc))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn i_config_read_alarm_poisons_session()
{
    let mut dev = open(ChipFault::Alarm);
    assert_eq!
    (
        dev.i_config_read(ConfigObjectAddr::CfgUapPing),
        Err(SeError::L2(L2Error::L1(L1Error::Alarm)))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn i_config_read_empty_result_poisons_session()
{
    let mut dev = open(ChipFault::EmptyResult);
    assert_eq!
    (
        dev.i_config_read(ConfigObjectAddr::CfgUapPing),
        Err(SeError::L3(L3Error::Parse(ParseError::UnexpectedEnd)))
    );
    assert_session_lost_and_quiet(&mut dev);
}

#[test]
fn mixed_config_sequence_keeps_nonces_in_lockstep()
{
    // An R-Config write, an R-Config read of that value, an erase, an
    // I-Config read, and an I-Config write each advance both nonces once.
    let mut dev = open(ChipFault::None);
    // The mock ignores a write payload and returns the seeded read value, so
    // use a DISTINCT written value to make clear this counts nonces, it does
    // not simulate a real write-then-read-back.
    dev.spi_mut().set_config_value(0xAABB_CCDD);
    dev.r_config_write(ConfigObjectAddr::CfgUapPing, 0x0102_0304).unwrap();
    assert_eq!(dev.spi_ref().nonces(), (1, 1));
    assert_eq!(dev.r_config_read(ConfigObjectAddr::CfgUapPing), Ok(0xAABB_CCDD));
    assert_eq!(dev.spi_ref().nonces(), (2, 2));
    dev.r_config_erase().unwrap();
    assert_eq!(dev.spi_ref().nonces(), (3, 3));
    assert_eq!(dev.i_config_read(ConfigObjectAddr::CfgUapPing), Ok(0xAABB_CCDD));
    assert_eq!(dev.spi_ref().nonces(), (4, 4));
    dev.i_config_write(ConfigObjectAddr::CfgSensors, cbit(5)).unwrap();
    assert_eq!(dev.spi_ref().nonces(), (5, 5));
}

/// Asserts a poisoned session fast-fails with `SessionLost` and issues no
/// further SPI transaction.
fn assert_session_lost_and_quiet(dev: &mut Tropic01<ChipMockSpi, MockWait, ActiveSession>)
{
    let before = dev.spi_ref().transaction_count();
    let mut out = [0u8; 16];
    assert_eq!(dev.ping_into(b"again", &mut out), Err(SeError::SessionLost));
    assert_eq!(dev.spi_ref().transaction_count(), before, "no chip traffic after poison");
}

#[test]
fn new_builds_a_no_session_handle()
{
    let dev = Tropic01::new(MockSpi::new(), MockWait::new());
    // Buffers start zeroed.
    assert!(dev.l2.iter().all(|&b| b == 0));
    assert!(dev.l3.as_slice().iter().all(|&b| b == 0));
    // The ports are owned and reachable: no transactions or waits yet.
    assert_eq!(dev.spi.transaction_count(), 0);
    assert_eq!(dev.wait.wait_count(), 0);
    let _ = dev.state;
}

#[test]
fn handle_size_is_bounded()
{
    // The handle must stay small enough to live in the secure binary's
    // static singleton. Design budget: <= 5000 bytes.
    assert!(core::mem::size_of::<Tropic01<MockSpi, MockWait, NoSession>>() <= 5000);
}

#[test]
fn active_session_poison_is_sticky()
{
    let keys = SessionKeys::new([1u8; 32], [2u8; 32]);
    let mut s = ActiveSession::new(keys);
    assert!(!s.is_poisoned());
    s.poison();
    assert!(s.is_poisoned());
    // Idempotent.
    s.poison();
    assert!(s.is_poisoned());
}

// ---- Get_Info (L2, NoSession) ----

#[test]
fn fw_bank_id_wire_bytes_match_libtropic()
{
    // Source: libtropic lt_bank_id_t.
    assert_eq!(FwBankId::Fw1.wire_byte(), 0x01);
    assert_eq!(FwBankId::Fw2.wire_byte(), 0x02);
    assert_eq!(FwBankId::Spect1.wire_byte(), 0x11);
    assert_eq!(FwBankId::Spect2.wire_byte(), 0x12);
}

#[test]
fn get_info_request_frame_matches_libtropic_golden()
{
    // Byte-exact Get_Info_Req for OBJECT_ID ChipId, BLOCK_INDEX 0:
    // REQ_ID 0x01, REQ_LEN 0x02, OBJECT_ID 0x01, BLOCK_INDEX 0x00, CRC 0x2B92.
    let mut buf = [0u8; L2_FRAME_MAX];
    let body = [ObjectId::ChipId as u8, 0u8];
    let n = frame::build_request(L2ReqId::GetInfo as u8, &body, &mut buf).unwrap();
    assert_eq!(&buf[..n], &[0x01, 0x02, 0x01, 0x00, 0x2B, 0x92]);
}

/// Builds a `NoSession` device over a chip mock with the given Get_Info fault.
fn no_session(fault: GetInfoFault) -> Tropic01<ChipMockSpi, MockWait, NoSession>
{
    let mut spi =
        ChipMockSpi::new(vectors::KCMD, vectors::KRES, vectors::ETPUB, vectors::T_TAUTH, ChipFault::None);
    spi.set_get_info_fault(fault);
    Tropic01::new(spi, MockWait::new())
}

#[test]
fn chip_id_round_trips_128_bytes()
{
    let mut block = [0u8; 128];
    for (i, b) in block.iter_mut().enumerate()
    {
        *b = i as u8;
    }
    let mut dev = no_session(GetInfoFault::None);
    dev.spi_mut().set_get_info(ObjectId::ChipId as u8, 0, &block);
    let mut out = [0u8; 128];
    let n = dev.chip_id_into(&mut out).unwrap();
    assert_eq!(n, 128);
    assert_eq!(out, block);
}

#[test]
fn chip_id_rejects_a_too_small_buffer()
{
    let mut dev = no_session(GetInfoFault::None);
    dev.spi_mut().set_get_info(ObjectId::ChipId as u8, 0, &[0u8; 128]);
    let mut out = [0u8; 64];
    assert_eq!(dev.chip_id_into(&mut out), Err(SeError::BufferTooSmall));
}

#[test]
fn chip_id_rejects_a_short_block()
{
    let mut dev = no_session(GetInfoFault::WrongLen);
    dev.spi_mut().set_get_info(ObjectId::ChipId as u8, 0, &[0xAAu8; 128]);
    let mut out = [0u8; 128];
    assert_eq!(dev.chip_id_into(&mut out), Err(SeError::L2(L2Error::BadFrame)));
}

#[test]
fn x509_certificate_reads_full_store()
{
    let mut dev = no_session(GetInfoFault::None);
    // Seed all 30 blocks with a per-block fingerprint so the concatenation
    // is checkable byte-for-byte.
    let mut expected = std::vec![0u8; GET_INFO_CERT_STORE_LEN];
    for blk in 0..GET_INFO_CERT_STORE_BLOCKS
    {
        let mut block = [0u8; 128];
        for (i, b) in block.iter_mut().enumerate()
        {
            *b = (blk as u8).wrapping_add(i as u8);
        }
        dev.spi_mut().set_get_info(ObjectId::X509Certificate as u8, blk as u8, &block);
        expected[blk * 128..(blk + 1) * 128].copy_from_slice(&block);
    }
    let mut out = std::vec![0u8; GET_INFO_CERT_STORE_LEN];
    let n = dev.x509_certificate_into(&mut out).unwrap();
    assert_eq!(n, GET_INFO_CERT_STORE_LEN);
    assert_eq!(out, expected);
}

#[test]
fn x509_certificate_rejects_a_too_small_buffer_before_any_traffic()
{
    let mut dev = no_session(GetInfoFault::None);
    let before = dev.spi_ref().transaction_count();
    let mut out = std::vec![0u8; GET_INFO_CERT_STORE_LEN - 1];
    assert_eq!(dev.x509_certificate_into(&mut out), Err(SeError::BufferTooSmall));
    // The check is up front: no chip traffic on a too-small buffer.
    assert_eq!(dev.spi_ref().transaction_count(), before);
}

#[test]
fn x509_certificate_rejects_a_short_block()
{
    let mut dev = no_session(GetInfoFault::WrongLen);
    for blk in 0..GET_INFO_CERT_STORE_BLOCKS
    {
        dev.spi_mut().set_get_info(ObjectId::X509Certificate as u8, blk as u8, &[0u8; 128]);
    }
    let mut out = std::vec![0u8; GET_INFO_CERT_STORE_LEN];
    assert_eq!(dev.x509_certificate_into(&mut out), Err(SeError::L2(L2Error::BadFrame)));
}

#[test]
fn read_chip_stpub_rejects_a_too_small_scratch_before_any_traffic()
{
    let mut dev = no_session(GetInfoFault::None);
    let before = dev.spi_ref().transaction_count();
    let mut scratch = std::vec![0u8; GET_INFO_CERT_STORE_LEN - 1];
    assert_eq!(dev.read_chip_stpub(&mut scratch), Err(SeError::BufferTooSmall));
    // The buffer check is up front: no chip traffic on a too-small scratch.
    assert_eq!(dev.spi_ref().transaction_count(), before);
}

#[test]
fn read_chip_stpub_extracts_stpub_from_a_seeded_store()
{
    // A minimal DEVICE cert carrying a known X25519 key, wrapped in a valid
    // 10-byte store header, seeded into the first cert-store block (the rest of
    // the 3840-byte store is the chip's natural padding). Proves read_chip_stpub
    // wires the read into the DER walk end to end on the host mock.
    const KEY: [u8; 32] = [
        0x95, 0x08, 0xf0, 0x32, 0x1c, 0xb1, 0xd2, 0xe5, 0xd1, 0xf1, 0xa4, 0x60, 0x9c, 0x05, 0x41,
        0xb7, 0x80, 0xe6, 0xdd, 0x50, 0xd6, 0x48, 0x2b, 0x6b, 0x08, 0xb2, 0xc2, 0x7e, 0x7b, 0x76,
        0x26, 0x47,
    ];
    // DEVICE cert: SEQUENCE { [0]{INTEGER 1}, OID commonName, OID id-X25519,
    // BIT STRING 00||KEY } (52 bytes).
    let mut cert = [0u8; 52];
    cert[0] = 0x30;
    cert[1] = 50;
    cert[2..7].copy_from_slice(&[0xA0, 0x03, 0x02, 0x01, 0x01]);
    cert[7..12].copy_from_slice(&[0x06, 0x03, 0x55, 0x04, 0x03]);
    cert[12..17].copy_from_slice(&[0x06, 0x03, 0x2B, 0x65, 0x6E]);
    cert[17..20].copy_from_slice(&[0x03, 0x21, 0x00]);
    cert[20..52].copy_from_slice(&KEY);
    // Store header: version 01, num_certs 04, LEN[0] = 52, LEN[1..4] = 0.
    let mut block0 = [0u8; 128];
    block0[0] = 0x01;
    block0[1] = 0x04;
    block0[2..4].copy_from_slice(&52u16.to_be_bytes());
    block0[10..10 + cert.len()].copy_from_slice(&cert);

    let mut dev = no_session(GetInfoFault::None);
    dev.spi_mut().set_get_info(ObjectId::X509Certificate as u8, 0, &block0);
    for blk in 1..GET_INFO_CERT_STORE_BLOCKS
    {
        dev.spi_mut().set_get_info(ObjectId::X509Certificate as u8, blk as u8, &[0u8; 128]);
    }
    let mut scratch = std::vec![0u8; GET_INFO_CERT_STORE_LEN];
    assert_eq!(dev.read_chip_stpub(&mut scratch), Ok(KEY));
}

#[test]
fn riscv_fw_version_returns_four_bytes()
{
    let mut dev = no_session(GetInfoFault::None);
    dev.spi_mut().set_get_info(ObjectId::RiscvFwVersion as u8, 0, &[0x01, 0x02, 0x03, 0x04]);
    assert_eq!(dev.riscv_fw_version().unwrap(), [0x01, 0x02, 0x03, 0x04]);
}

#[test]
fn spect_fw_version_returns_the_startup_sentinel()
{
    let mut dev = no_session(GetInfoFault::None);
    // Start-up Mode SPECT sentinel 0x80000000 in little-endian wire order.
    dev.spi_mut().set_get_info(ObjectId::SpectFwVersion as u8, 0, &[0x00, 0x00, 0x00, 0x80]);
    assert_eq!(dev.spect_fw_version().unwrap(), [0x00, 0x00, 0x00, 0x80]);
}

#[test]
fn fw_bank_into_reads_a_20_byte_bank()
{
    let mut dev = no_session(GetInfoFault::None);
    let header = [0x5Au8; 20];
    dev.spi_mut().set_get_info(ObjectId::FwBank as u8, FwBankId::Fw1.wire_byte(), &header);
    let mut out = [0u8; 64];
    let n = dev.fw_bank_into(FwBankId::Fw1, &mut out).unwrap();
    assert_eq!(n, 20);
    assert_eq!(&out[..20], &header);
}

#[test]
fn fw_bank_into_reads_a_52_byte_bank()
{
    let mut dev = no_session(GetInfoFault::None);
    let header = [0xC3u8; 52];
    dev.spi_mut().set_get_info(ObjectId::FwBank as u8, FwBankId::Spect2.wire_byte(), &header);
    let mut out = [0u8; 64];
    let n = dev.fw_bank_into(FwBankId::Spect2, &mut out).unwrap();
    assert_eq!(n, 52);
    assert_eq!(&out[..52], &header);
}

#[test]
fn fw_bank_into_reads_an_empty_bank()
{
    let mut dev = no_session(GetInfoFault::None);
    // An empty bank replies with zero-length RSP_DATA (object unset == empty).
    let mut out = [0u8; 64];
    let n = dev.fw_bank_into(FwBankId::Fw2, &mut out).unwrap();
    assert_eq!(n, 0);
}

#[test]
fn fw_bank_into_rejects_an_unexpected_length()
{
    let mut dev = no_session(GetInfoFault::None);
    // 30 bytes is not in {0, 20, 52}: a structural anomaly.
    dev.spi_mut().set_get_info(ObjectId::FwBank as u8, FwBankId::Fw1.wire_byte(), &[0u8; 30]);
    let mut out = [0u8; 64];
    assert_eq!(dev.fw_bank_into(FwBankId::Fw1, &mut out), Err(SeError::L2(L2Error::BadFrame)));
}

#[test]
fn fw_bank_into_selects_the_requested_bank()
{
    let mut dev = no_session(GetInfoFault::None);
    // Each bank gets a distinct 20-byte header. Reading SPECT1 must return
    // SPECT1's, proving the BLOCK_INDEX selects the right bank.
    dev.spi_mut().set_get_info(ObjectId::FwBank as u8, FwBankId::Fw1.wire_byte(), &[0x11u8; 20]);
    dev.spi_mut().set_get_info(ObjectId::FwBank as u8, FwBankId::Spect1.wire_byte(), &[0x22u8; 20]);
    let mut out = [0u8; 64];
    let n = dev.fw_bank_into(FwBankId::Spect1, &mut out).unwrap();
    assert_eq!(n, 20);
    assert_eq!(&out[..20], &[0x22u8; 20]);
}

#[test]
fn get_info_error_status_is_recoverable()
{
    let mut dev = no_session(GetInfoFault::ErrorStatus);
    dev.spi_mut().set_get_info(ObjectId::ChipId as u8, 0, &[0u8; 128]);
    let mut out = [0u8; 128];
    // An L2 error status surfaces via parse_response, no session state.
    assert_eq!(
        dev.chip_id_into(&mut out),
        Err(SeError::L2(L2Error::Status(L2Status::UnknownErr)))
    );
}

#[test]
fn get_info_bad_crc_surfaces_as_crc_error()
{
    let mut dev = no_session(GetInfoFault::BadCrc);
    dev.spi_mut().set_get_info(ObjectId::ChipId as u8, 0, &[0u8; 128]);
    let mut out = [0u8; 128];
    assert_eq!(dev.chip_id_into(&mut out), Err(SeError::L2(L2Error::Crc)));
}

#[test]
fn get_info_cont_status_is_rejected_as_bad_frame()
{
    // A valid-CRC reply with a *Cont status must NOT be mistaken for a
    // complete single-frame Get_Info reply (a truncated read). The
    // get_info_block guard rejects any non-RequestOk status as BadFrame.
    let mut dev = no_session(GetInfoFault::ContStatus);
    dev.spi_mut().set_get_info(ObjectId::ChipId as u8, 0, &[0u8; 128]);
    let mut out = [0u8; 128];
    assert_eq!(dev.chip_id_into(&mut out), Err(SeError::L2(L2Error::BadFrame)));
}

#[test]
fn get_info_no_response_surfaces_as_an_error()
{
    // With no queued reply the read path sees no valid frame. The call must
    // surface a recoverable error, never hang or panic.
    let mut dev = no_session(GetInfoFault::NoResp);
    dev.spi_mut().set_get_info(ObjectId::ChipId as u8, 0, &[0u8; 128]);
    let mut out = [0u8; 128];
    assert!(dev.chip_id_into(&mut out).is_err());
}
