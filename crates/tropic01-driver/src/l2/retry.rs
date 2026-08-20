//! CRC retry seam shared by every L2 exchange.
//!
//! Two faults can hit one L2 frame, and they take opposite cures:
//!
//! - STATUS = CRC_ERR (0x7C), reported as `L2Error::Status(L2Status::CrcErr)`.
//!   The chip rejected the CRC of the host request, so the request never ran.
//!   The cure is to replay the whole exchange with the identical request bytes.
//! - A recomputed RSP_CRC mismatch, reported as `L2Error::Crc`. The host read a
//!   corrupt response and the request may have run. The cure is a `Resend_Req`
//!   (REQ_ID 0x10, REQ_LEN 0), never a replay, since replaying a request that
//!   already executed would run it twice.
//!
//! A `Resend_Req` that itself draws a CRC_ERR status is sent again rather than
//! giving way to a replay. The corruption cannot be attributed to the original
//! frame or to the Resend frame, so the cure taken is the one that cannot
//! execute anything twice.
//!
//! Callers pass the request ingredients (REQ_ID plus body) rather than a built
//! frame, so a replay rebuilds the same bytes and the response read may
//! overwrite `l2`.
//!
//! The returned `L2ResponseInfo` borrows nothing. `exchange_within` and
//! `receive_within` run inside a caller loop that reads the next chunk into the
//! same frame buffer, where a returned borrow of `l2` would still be live. The
//! other entry points return the same type so the seam has one shape. RSP_DATA
//! is re-sliced out of `l2` with `frame::rsp_data`.
//!
//! One `RetryBudget` spans a whole chunked send or receive, so the retry cost of
//! one L3 packet is capped at `CRC_RETRY_ATTEMPTS` extra round-trips whatever
//! the packet length. That bound covers one packet and nothing wider:
//! `exchange_within` and `receive_within` are the entry points taking a
//! caller-owned budget, and the L3 chunked send and receive are their only
//! callers. `exchange` and `exchange_startup` mint a fresh budget per call, so a
//! sequence of L2 commands gets one allowance per command. A firmware image
//! relayed as one `Mutable_FW_Update` plus N `Mutable_FW_Update_Data` commands
//! owns N + 1 budgets, and its worst-case retry cost is linear in the image
//! size. Wall-time figures are in the crate-level error-path latency note.
//!
//! Source: libtropic `lt_l2_transfer`, `lt_l2_send_encrypted_cmd`,
//! `lt_l2_recv_encrypted_res`, and `lt_l2_resend_response`. Resend_Req syntax
//! from the TROPIC01 User API v1.4.0 (REQ_ID 0x10, REQ_LEN 0x00).

use embedded_hal::spi::SpiDevice;

use crate::error::L2Error;
use crate::ids::L2ReqId;
use crate::ids::L2Status;
use crate::l1;
use crate::l2::frame;
use crate::l2::frame::L2ResponseInfo;
use crate::wait::SeWait;

/// How one response frame is parsed.
///
/// Inhabited by the two named parsers in `frame`, the strict rule and the
/// `Startup_Req` erratum rule, and by nothing else. `exchange_startup` is the
/// one entry point that picks the erratum rule.
type ParseResponse = fn(&[u8]) -> Result<L2ResponseInfo, L2Error>;

/// Retry attempts granted to one budget.
///
/// Source: libtropic `LT_CRC_ERR_RETRY_ATTEMPTS`, whose default is 3.
const CRC_RETRY_ATTEMPTS: u32 = 3;

/// A finite, never-refilled allowance of CRC retries.
///
/// One budget covers both fault kinds, so a run of alternating faults draws on a
/// single allowance and cannot stretch the total. A single-frame command owns
/// one budget. A chunked send or receive owns one budget for all its chunks.
pub(crate) struct RetryBudget
{
    left: u32,
}

impl RetryBudget
{
    /// Creates a full budget of `CRC_RETRY_ATTEMPTS` attempts.
    pub(crate) const fn new() -> Self
    {
        RetryBudget
        {
            left: CRC_RETRY_ATTEMPTS,
        }
    }

    /// Spends one attempt, returning false when none is left.
    ///
    /// The one way to draw the count down, and nothing refills it, so every
    /// loop guarded by this call terminates.
    fn spend(&mut self) -> bool
    {
        if self.left == 0
        {
            return false;
        }
        self.left -= 1;
        true
    }
}

/// Sends one L2 request and returns the response, retrying on CRC faults.
///
/// Owns a fresh `RetryBudget`, the entry point for a stand-alone single-frame
/// command. `l2` is the scratch frame buffer. The request is rebuilt from
/// `req_id` and `body` on every attempt, so the response read may overwrite
/// `l2`. The returned info borrows nothing: read RSP_DATA back out of `l2` with
/// `frame::rsp_data`.
///
/// # Errors
///
/// The first non-CRC error verbatim, or the CRC error that exhausted the retry
/// budget. The two CRC faults are the retried ones, nothing else.
pub(crate) fn exchange<SPI, W>
(
    spi: &mut SPI,
    wait: &mut W,
    l2: &mut [u8],
    req_id: u8,
    body: &[u8],
)
-> Result<L2ResponseInfo, L2Error>
where
    SPI: SpiDevice,
    W: SeWait,
{
    exchange_with
    (
        spi,
        wait,
        l2,
        req_id,
        body,
        frame::parse_response,
        &mut RetryBudget::new(),
    )
}

/// Sends one L2 request against a caller-owned retry budget.
///
/// Used by the chunked L3 send, where every chunk of one packet draws on the
/// same allowance. See `exchange` for the semantics of a single attempt.
///
/// # Errors
///
/// Same as `exchange`.
pub(crate) fn exchange_within<SPI, W>
(
    spi: &mut SPI,
    wait: &mut W,
    l2: &mut [u8],
    req_id: u8,
    body: &[u8],
    budget: &mut RetryBudget,
)
-> Result<L2ResponseInfo, L2Error>
where
    SPI: SpiDevice,
    W: SeWait,
{
    exchange_with(spi, wait, l2, req_id, body, frame::parse_response, budget)
}

/// Sends a `Startup_Req` exchange under the erratum-tolerant RSP_CRC rule.
///
/// Identical to `exchange` except that the direct response to the `Startup_Req`
/// is parsed with `frame::parse_startup_response`, the errata workaround
/// documented there. The tolerance stays confined to this entry point, and
/// within it to the direct response: a `Resend_Req` issued while recovering is
/// a different request whose response the erratum does not cover, so that one
/// is parsed under the strict rule.
///
/// # Errors
///
/// Same as `exchange`, except that `L2Error::Crc` does not fire on a
/// second-CRC-byte mismatch of the tolerated frame.
pub(crate) fn exchange_startup<SPI, W>
(
    spi: &mut SPI,
    wait: &mut W,
    l2: &mut [u8],
    req_id: u8,
    body: &[u8],
)
-> Result<L2ResponseInfo, L2Error>
where
    SPI: SpiDevice,
    W: SeWait,
{
    exchange_with
    (
        spi,
        wait,
        l2,
        req_id,
        body,
        frame::parse_startup_response,
        &mut RetryBudget::new(),
    )
}

/// Reads one response frame the host did not request, retrying on CRC faults.
///
/// Used by the L3 result reassembly, where the chip streams chunk after chunk
/// with no request in between. Nothing can be replayed here, so both CRC faults
/// are cured with a `Resend_Req`. `budget` is caller-owned and shared by every
/// chunk of one result.
///
/// # Errors
///
/// The first non-CRC error verbatim, or the CRC error that exhausted the retry
/// budget.
pub(crate) fn receive_within<SPI, W>
(
    spi: &mut SPI,
    wait: &mut W,
    l2: &mut [u8],
    budget: &mut RetryBudget,
)
-> Result<L2ResponseInfo, L2Error>
where
    SPI: SpiDevice,
    W: SeWait,
{
    match read_frame(spi, wait, l2, frame::parse_response)
    {
        Err(e @ (L2Error::Crc | L2Error::Status(L2Status::CrcErr))) =>
        {
            resend_until_intact(spi, wait, l2, budget, e)
        }
        other => other,
    }
}

/// Shared exchange body. `parse` selects the strict or the erratum RSP_CRC rule.
///
/// Termination: every loop turn either returns or spends one unit of `budget`,
/// which starts finite and never grows. At most `1 + CRC_RETRY_ATTEMPTS`
/// round-trips leave this function, fewer when the budget arrives part-spent.
fn exchange_with<SPI, W>
(
    spi: &mut SPI,
    wait: &mut W,
    l2: &mut [u8],
    req_id: u8,
    body: &[u8],
    parse: ParseResponse,
    budget: &mut RetryBudget,
)
-> Result<L2ResponseInfo, L2Error>
where
    SPI: SpiDevice,
    W: SeWait,
{
    loop
    {
        match send_and_read(spi, wait, l2, req_id, body, parse)
        {
            // The chip rejected the request CRC, so the request never ran.
            // Rebuild the identical frame and replay, budget permitting.
            Err(e @ L2Error::Status(L2Status::CrcErr)) =>
            {
                if !budget.spend()
                {
                    return Err(e);
                }
            }
            // The response came back corrupt. The request may have run, so ask
            // the chip to resend rather than replaying it.
            Err(L2Error::Crc) =>
            {
                return resend_until_intact(spi, wait, l2, budget, L2Error::Crc);
            }
            other => return other,
        }
    }
}

/// Asks the chip to resend its last response until a frame arrives intact.
///
/// `budget` is the caller's remaining allowance, so a run of alternating fault
/// kinds draws on one shared budget. `entry` is the CRC error that led here and
/// comes back unchanged when no attempt is left, so the caller sees the fault
/// it hit.
///
/// The strict CRC rule applies here whatever the caller's own rule is. The
/// `Startup_Req` erratum covers the response to the `Startup_Req` itself, not
/// the response to a later `Resend_Req`, so the tolerance stops short of this
/// function.
///
/// Termination: every loop turn spends one unit of `budget` and the loop ends
/// at zero.
fn resend_until_intact<SPI, W>
(
    spi: &mut SPI,
    wait: &mut W,
    l2: &mut [u8],
    budget: &mut RetryBudget,
    entry: L2Error,
)
-> Result<L2ResponseInfo, L2Error>
where
    SPI: SpiDevice,
    W: SeWait,
{
    let mut last = Err(entry);
    while budget.spend()
    {
        // Resend_Req body is empty: REQ_ID 0x10, REQ_LEN 0x00 (TROPIC01 User API
        // v1.4.0, libtropic `lt_l2_resend_response`).
        last = send_and_read(spi, wait, l2, L2ReqId::Resend as u8, &[], frame::parse_response);
        // A CRC_ERR status to a Resend_Req cannot be attributed to the original
        // frame or to the Resend frame, so re-send the Resend_Req. Anything
        // else, success or a real error, ends the loop.
        if !matches!(last, Err(L2Error::Crc | L2Error::Status(L2Status::CrcErr)))
        {
            break;
        }
    }
    last
}

/// Builds `req_id || body` into `l2`, sends it, and reads the response back.
///
/// One attempt, no retry logic. `l2` carries the request out and the response
/// back, so nothing survives the call except the returned info.
fn send_and_read<SPI, W>
(
    spi: &mut SPI,
    wait: &mut W,
    l2: &mut [u8],
    req_id: u8,
    body: &[u8],
    parse: ParseResponse,
)
-> Result<L2ResponseInfo, L2Error>
where
    SPI: SpiDevice,
    W: SeWait,
{
    let n = frame::build_request(req_id, body, l2)?;
    let request = l2.get(..n).ok_or(L2Error::ShortFrame)?;
    l1::send_request(spi, request)?;
    read_frame(spi, wait, l2, parse)
}

/// Reads one response frame into `l2` and parses it with `parse`.
fn read_frame<SPI, W>
(
    spi: &mut SPI,
    wait: &mut W,
    l2: &mut [u8],
    parse: ParseResponse,
)
-> Result<L2ResponseInfo, L2Error>
where
    SPI: SpiDevice,
    W: SeWait,
{
    let frame_len = l1::read_response(spi, wait, l2)?;
    let response = l2.get(..frame_len).ok_or(L2Error::ShortFrame)?;
    parse(response)
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::buf::L2_FRAME_MAX;
    use crate::test_support::l2_frame;
    use crate::test_support::CrcFaultSpi;
    use crate::test_support::CrcReply;
    use crate::test_support::MockWait;

    /// A `Get_Info_Req` body: OBJECT_ID(1) || BLOCK_INDEX(1).
    const GET_INFO_BODY: [u8; 2] = [0x01, 0x00];

    /// The good reply every exchange test converges on.
    fn ok_reply() -> std::vec::Vec<u8>
    {
        l2_frame(L2Status::RequestOk as u8, &[0xAA, 0xBB])
    }

    /// Repeats one scripted reply `n` times.
    fn repeat(reply: CrcReply, frame: &[u8], n: usize) -> std::vec::Vec<(CrcReply, std::vec::Vec<u8>)>
    {
        (0..n).map(|_| (reply, frame.to_vec())).collect()
    }

    /// Runs a `Get_Info` exchange against a scripted chip.
    fn run_exchange
    (
        script: std::vec::Vec<(CrcReply, std::vec::Vec<u8>)>,
    )
    -> (Result<L2ResponseInfo, L2Error>, CrcFaultSpi)
    {
        let mut spi = CrcFaultSpi::new(script);
        let mut wait = MockWait::new();
        let mut l2 = [0u8; L2_FRAME_MAX];
        let r = exchange
        (
            &mut spi,
            &mut wait,
            &mut l2,
            L2ReqId::GetInfo as u8,
            &GET_INFO_BODY,
        );
        (r, spi)
    }

    #[test]
    fn exchange_replays_the_identical_request_on_a_chip_crc_error()
    {
        // Two CRC_ERR statuses, then a good reply. The retry must happen: three
        // requests must reach the chip, all byte-identical Get_Info frames.
        let mut script = repeat(CrcReply::ChipCrcErr, &[], 2);
        script.push((CrcReply::Good, ok_reply()));
        let (r, spi) = run_exchange(script);
        assert_eq!(r.map(|i| i.data_len), Ok(2));
        assert_eq!(spi.reads(), 3);
        assert_eq!(spi.req_ids(), std::vec![L2ReqId::GetInfo as u8; 3]);
        // A replay must re-send the same bytes, never a re-derived request.
        assert_eq!(spi.requests()[0], spi.requests()[1]);
        assert_eq!(spi.requests()[1], spi.requests()[2]);
    }

    #[test]
    fn exchange_stops_at_the_budget_on_a_chip_crc_error()
    {
        // The chip never accepts the request: exactly 1 + CRC_RETRY_ATTEMPTS
        // attempts, then the CRC_ERR status surfaces.
        let script = repeat(CrcReply::ChipCrcErr, &[], 16);
        let (r, spi) = run_exchange(script);
        assert_eq!(r, Err(L2Error::Status(L2Status::CrcErr)));
        assert_eq!(spi.reads(), 1 + CRC_RETRY_ATTEMPTS as usize);
        assert_eq!(spi.req_ids().len(), 1 + CRC_RETRY_ATTEMPTS as usize);
    }

    #[test]
    fn exchange_asks_for_a_resend_and_never_replays_on_a_local_crc_error()
    {
        // A corrupt response must not replay the request, which may have run.
        // Resend_Req frames are the only ones allowed to follow it.
        let good = ok_reply();
        let mut script = repeat(CrcReply::HostCrcErr, &good, 2);
        script.push((CrcReply::Good, good.clone()));
        let (r, spi) = run_exchange(script);
        assert_eq!(r.map(|i| i.data_len), Ok(2));
        assert_eq!(
            spi.req_ids(),
            std::vec![L2ReqId::GetInfo as u8, L2ReqId::Resend as u8, L2ReqId::Resend as u8]
        );
    }

    #[test]
    fn a_resend_request_is_the_byte_exact_protocol_frame()
    {
        // Every other test here reads REQ_ID alone, so a wrong REQ_LEN or a
        // stray body byte would pass unnoticed and bite on real silicon, where
        // a chip that rejects a malformed Resend_Req kills the CRC recovery.
        // Pin the complete frame instead.
        let good = ok_reply();
        let script = std::vec![
            (CrcReply::HostCrcErr, good.clone()),
            (CrcReply::Good, good.clone()),
        ];
        let (r, spi) = run_exchange(script);
        assert_eq!(r.map(|i| i.data_len), Ok(2));
        assert_eq!(spi.requests().len(), 2);
        // REQ_ID 0x10, REQ_LEN 0x00, then the CRC over those two bytes, 0x03E0,
        // high byte first (TROPIC01 User API v1.4.0, libtropic
        // `lt_l2_resend_response`).
        assert_eq!(spi.requests()[1], std::vec![0x10u8, 0x00, 0x03, 0xE0]);
    }

    #[test]
    fn exchange_stops_at_the_budget_on_a_local_crc_error()
    {
        let good = ok_reply();
        let script = repeat(CrcReply::HostCrcErr, &good, 16);
        let (r, spi) = run_exchange(script);
        assert_eq!(r, Err(L2Error::Crc));
        // One original request plus exactly CRC_RETRY_ATTEMPTS Resend_Req.
        let mut expected = std::vec![L2ReqId::GetInfo as u8];
        expected.extend(std::iter::repeat_n(
            L2ReqId::Resend as u8,
            CRC_RETRY_ATTEMPTS as usize,
        ));
        assert_eq!(spi.req_ids(), expected);
    }

    #[test]
    fn exchange_resends_again_when_a_resend_draws_a_chip_crc_error()
    {
        // A CRC_ERR to a Resend_Req must produce another Resend_Req, never a
        // replay of the original request.
        let good = ok_reply();
        let script = std::vec![
            (CrcReply::HostCrcErr, good.clone()),
            (CrcReply::ChipCrcErr, std::vec::Vec::new()),
            (CrcReply::Good, good.clone()),
        ];
        let (r, spi) = run_exchange(script);
        assert_eq!(r.map(|i| i.data_len), Ok(2));
        assert_eq!(
            spi.req_ids(),
            std::vec![L2ReqId::GetInfo as u8, L2ReqId::Resend as u8, L2ReqId::Resend as u8]
        );
    }

    #[test]
    fn exchange_budget_is_shared_across_alternating_fault_kinds()
    {
        // Alternating faults must not stretch the budget: the total stays at
        // 1 + CRC_RETRY_ATTEMPTS round-trips, and the run terminates.
        let good = ok_reply();
        let script = std::vec![
            (CrcReply::ChipCrcErr, std::vec::Vec::new()),
            (CrcReply::HostCrcErr, good.clone()),
            (CrcReply::ChipCrcErr, std::vec::Vec::new()),
            (CrcReply::HostCrcErr, good.clone()),
            (CrcReply::Good, good.clone()),
        ];
        let (r, spi) = run_exchange(script);
        assert_eq!(r, Err(L2Error::Crc));
        assert_eq!(spi.reads(), 1 + CRC_RETRY_ATTEMPTS as usize);
        assert_eq!(
            spi.req_ids(),
            std::vec![
                L2ReqId::GetInfo as u8,
                L2ReqId::GetInfo as u8,
                L2ReqId::Resend as u8,
                L2ReqId::Resend as u8
            ]
        );
    }

    #[test]
    fn exchange_never_retries_a_non_crc_error()
    {
        // TAG_ERR is a real answer, not a link fault. One attempt, no retry.
        let script = std::vec![(CrcReply::Status(L2Status::TagErr as u8), std::vec::Vec::new())];
        let (r, spi) = run_exchange(script);
        assert_eq!(r, Err(L2Error::Status(L2Status::TagErr)));
        assert_eq!(spi.reads(), 1);
        assert_eq!(spi.req_ids(), std::vec![L2ReqId::GetInfo as u8]);
    }

    #[test]
    fn exchange_succeeds_without_any_retry_when_the_link_is_clean()
    {
        // Guards the tests above against a mock that always retries: a clean
        // link must cost exactly one request and one read.
        let script = std::vec![(CrcReply::Good, ok_reply())];
        let (r, spi) = run_exchange(script);
        assert_eq!(r.map(|i| i.data_len), Ok(2));
        assert_eq!(spi.reads(), 1);
        assert_eq!(spi.req_ids(), std::vec![L2ReqId::GetInfo as u8]);
    }

    /// The empty RequestOk ack a `Startup_Req` draws.
    fn startup_ack() -> std::vec::Vec<u8>
    {
        l2_frame(L2Status::RequestOk as u8, &[])
    }

    /// Runs a `Startup_Req` exchange against a scripted chip.
    fn run_startup
    (
        script: std::vec::Vec<(CrcReply, std::vec::Vec<u8>)>,
    )
    -> (Result<L2ResponseInfo, L2Error>, CrcFaultSpi)
    {
        let mut spi = CrcFaultSpi::new(script);
        let mut wait = MockWait::new();
        let mut l2 = [0u8; L2_FRAME_MAX];
        let r = exchange_startup(&mut spi, &mut wait, &mut l2, L2ReqId::Startup as u8, &[0x01]);
        (r, spi)
    }

    #[test]
    fn startup_tolerates_a_corrupt_second_crc_byte_on_its_own_response()
    {
        // The erratum frame itself: one request, one read, accepted.
        let (r, spi) = run_startup(std::vec![(CrcReply::HostCrcErr, startup_ack())]);
        assert_eq!(r.map(|i| i.status), Ok(L2Status::RequestOk));
        assert_eq!(spi.reads(), 1);
        assert!(spi.req_ids().iter().all(|&id| id == L2ReqId::Startup as u8));
    }

    #[test]
    fn startup_does_not_extend_its_tolerance_to_a_resend_response()
    {
        // The erratum covers the response to the Startup_Req, not the response
        // to a Resend_Req issued while recovering from it. A first response
        // whose first CRC byte is corrupt (rejected by both rules) sends a
        // Resend_Req, and the resend's own response comes back with a corrupt
        // second CRC byte. That one must be refused, which forces a further
        // Resend_Req. Propagating the tolerance would accept it after two reads.
        let script = std::vec![
            (CrcReply::HostCrcErrFirstByte, startup_ack()),
            (CrcReply::HostCrcErr, startup_ack()),
            (CrcReply::Good, startup_ack()),
        ];
        let (r, spi) = run_startup(script);
        assert_eq!(r.map(|i| i.status), Ok(L2Status::RequestOk));
        assert_eq!(spi.reads(), 3);
        assert_eq!(
            spi.req_ids(),
            std::vec![L2ReqId::Startup as u8, L2ReqId::Resend as u8, L2ReqId::Resend as u8]
        );
    }

    /// Runs a bare `receive` against a scripted chip.
    fn run_receive
    (
        script: std::vec::Vec<(CrcReply, std::vec::Vec<u8>)>,
    )
    -> (Result<L2ResponseInfo, L2Error>, CrcFaultSpi)
    {
        let mut spi = CrcFaultSpi::new(script);
        let mut wait = MockWait::new();
        let mut l2 = [0u8; L2_FRAME_MAX];
        let r = receive_within(&mut spi, &mut wait, &mut l2, &mut RetryBudget::new());
        (r, spi)
    }

    #[test]
    fn receive_asks_for_a_resend_on_a_local_crc_error()
    {
        let good = l2_frame(L2Status::ResultOk as u8, &[0x11, 0x22, 0x33]);
        let script = std::vec![
            (CrcReply::HostCrcErr, good.clone()),
            (CrcReply::Good, good.clone()),
        ];
        let (r, spi) = run_receive(script);
        assert_eq!(r.map(|i| i.data_len), Ok(3));
        assert_eq!(spi.reads(), 2);
        assert_eq!(spi.req_ids(), std::vec![L2ReqId::Resend as u8]);
    }

    #[test]
    fn receive_stops_at_the_budget()
    {
        let good = l2_frame(L2Status::ResultOk as u8, &[0x11]);
        let script = repeat(CrcReply::HostCrcErr, &good, 16);
        let (r, spi) = run_receive(script);
        assert_eq!(r, Err(L2Error::Crc));
        assert_eq!(spi.reads(), 1 + CRC_RETRY_ATTEMPTS as usize);
        assert_eq!(spi.req_ids().len(), CRC_RETRY_ATTEMPTS as usize);
    }

    #[test]
    fn receive_treats_a_chip_crc_status_as_a_resend_trigger()
    {
        // On a receive there is no request to replay, so a CRC_ERR status is
        // cured with a Resend_Req like a local CRC fault.
        let good = l2_frame(L2Status::ResultOk as u8, &[0x77]);
        let script = std::vec![
            (CrcReply::ChipCrcErr, std::vec::Vec::new()),
            (CrcReply::Good, good.clone()),
        ];
        let (r, spi) = run_receive(script);
        assert_eq!(r.map(|i| i.data_len), Ok(1));
        assert_eq!(spi.req_ids(), std::vec![L2ReqId::Resend as u8]);
    }

    #[test]
    fn receive_never_retries_a_non_crc_error()
    {
        let script = std::vec![(CrcReply::Status(L2Status::NoSession as u8), std::vec::Vec::new())];
        let (r, spi) = run_receive(script);
        assert_eq!(r, Err(L2Error::Status(L2Status::NoSession)));
        assert_eq!(spi.reads(), 1);
        assert!(spi.req_ids().is_empty());
    }
}
