//! Proves every store / load address the driver emits for the inactive bank and
//! the metadata band lands inside a secure MPU region.
//!
//! The secure MPU runs with `PRIVDEFENA` = 0 (no background map, RM0456 sec 3.5),
//! so any address the secure core touches that no region covers HardFaults on
//! silicon, invisibly to a host test with no MPU model (the se_readonly fault
//! class). A geometry edit (a new descriptor page, a moved payload origin) can
//! silently push a driver-emitted address outside its region.
//!
//! This test drives the real driver over the faithful FLASH-controller model
//! through a recording port that captures every flash-bank address the driver
//! actually emits, then asserts each captured range is contained in a mirrored
//! secure MPU region. It fails if a future edit moves an emitted address outside
//! its region.
//!
//! The MPU region bounds are mirrored here as hard literals. Their source of
//! truth is `crates/platform/src/map.rs`, whose own pin tests fix the same
//! literals, so the two sides pin the same numbers and this test catches a
//! geometry edit on the mcu-flash side.

#![cfg(test)]

extern crate alloc;

use alloc::vec::Vec;
use core::cell::RefCell;

use fw_update::BankId;
use fw_update::FlashSeam;
use fw_update::PendingFlag;
use fw_update::UpdateOutcome;

use crate::bus::FlashAccess;
use crate::driver::Stm32FlashSeam;
use crate::model::FlashModel;
use crate::regs;

// The secure MPU regions a driver-emitted flash address can legitimately fall in,
// as inclusive [base, limit] pairs. Mirrored from crates/platform/src/map.rs:
//   R1 boot metadata (physical Bank 1 pages 0-1), low alias when SWAP_BANK clear,
//   high alias when set.
//   R5 inactive-bank secure image (pages 9-19, high alias): descriptor plus
//   secure payload.
//   R6 inactive-bank non-secure image (pages 20-31, high NS alias).
const R1_META_LOW: (u32, u32) = (0x0C00_0000, 0x0C00_3FFF);
const R1_META_HIGH: (u32, u32) = (0x0C04_0000, 0x0C04_3FFF);
const R5_INACTIVE_SECURE: (u32, u32) = (0x0C05_2000, 0x0C06_7FFF);
const R6_INACTIVE_NS: (u32, u32) = (0x0806_8000, 0x0807_FFFF);

const MPU_REGIONS: [(u32, u32); 4] =
    [R1_META_LOW, R1_META_HIGH, R5_INACTIVE_SECURE, R6_INACTIVE_NS];

/// True when `addr` is inside either flash bank alias (secure 0x0C.. or NS 0x08..).
/// The FLASH controller registers sit at 0x5002_xxxx and are excluded.
fn is_bank_addr(addr: u32) -> bool
{
    (0x0800_0000..0x0808_0000).contains(&addr)
        || (0x0C00_0000..0x0C08_0000).contains(&addr)
}

/// True when the inclusive range `[base, base + len)` sits wholly in some region.
fn contained(base: u32, len: u32) -> bool
{
    if len == 0
    {
        return true;
    }
    let last = base + len - 1;
    MPU_REGIONS
        .iter()
        .any(|(lo, hi)| base >= *lo && last <= *hi)
}

/// A recording [`FlashAccess`] port over the FLASH-controller model.
///
/// It delegates every access to the model and records the address of every
/// flash-bank read / write / borrow, so a test can prove what the driver emits.
struct RecordingAccess
{
    inner: FlashModel,
    ranges: RefCell<Vec<(u32, u32)>>,
}

impl RecordingAccess
{
    fn new() -> RecordingAccess
    {
        RecordingAccess
        {
            inner: FlashModel::new(),
            ranges: RefCell::new(Vec::new()),
        }
    }

    fn record(&self, addr: u32, len: u32)
    {
        if is_bank_addr(addr)
        {
            self.ranges.borrow_mut().push((addr, len));
        }
    }

    fn ranges(&self) -> Vec<(u32, u32)>
    {
        self.ranges.borrow().clone()
    }

    fn apply_reset(&mut self)
    {
        self.inner.apply_reset();
    }
}

impl FlashAccess for RecordingAccess
{
    fn read32(&mut self, addr: u32) -> u32
    {
        self.record(addr, 4);
        self.inner.read32(addr)
    }

    fn write32(&mut self, addr: u32, value: u32)
    {
        self.record(addr, 4);
        self.inner.write32(addr, value);
    }

    fn peek32(&self, addr: u32) -> u32
    {
        self.record(addr, 4);
        self.inner.peek32(addr)
    }

    fn bank_view(&self, base: u32, len: usize) -> &[u8]
    {
        self.record(base, len as u32);
        self.inner.bank_view(base, len)
    }
}

/// Drives a full inactive-bank flow (erase, payload writes spanning both
/// sub-bands, descriptor write, the three band reads, and every metadata op) and
/// returns the recording port holding every flash address the driver emitted.
///
/// When `swap_set` is true a commit plus a modelled reset first flips SWAP_BANK,
/// so physical Bank 1 (the metadata) and the inactive bank both sit at the high
/// alias, the case that breaks a low-alias-only assumption.
fn drive_full_inactive_flow(swap_set: bool) -> Stm32FlashSeam<RecordingAccess>
{
    let mut driver = Stm32FlashSeam::new(RecordingAccess::new());
    if swap_set
    {
        driver.commit_swap().expect("stage swap");
        driver.access_mut().apply_reset();
    }
    driver.erase_inactive().expect("erase inactive");
    // A secure payload page (index 0) and the first non-secure payload page.
    driver
        .write_inactive_page(0, &[0xAA; 16])
        .expect("write secure payload page");
    let ns_page =
        (regs::IMAGE_PAYLOAD_SECURE_SIZE / fw_update::PAGE_LEN as u32) as u16;
    driver
        .write_inactive_page(ns_page, &[0xBB; 16])
        .expect("write non-secure payload page");
    driver
        .write_descriptor(&[0xCC; 88])
        .expect("write descriptor");
    let _ = driver.inactive_descriptor();
    let _ = driver.inactive_secure_band();
    let _ = driver.inactive_ns_band();
    driver.nvcnt_bump(5).expect("nvcnt bump");
    driver
        .pending_write(PendingFlag::Armed(BankId::Bank2))
        .expect("pending write");
    driver.boot_count_advance().expect("boot count advance");
    driver
        .update_outcome_write(UpdateOutcome::AutoReverted)
        .expect("outcome write");
    driver
}

/// Asserts every recorded flash range is contained in a secure MPU region, and
/// that the flow actually emitted flash addresses (non-vacuous).
fn assert_all_contained(ranges: &[(u32, u32)], context: &str)
{
    assert!(
        !ranges.is_empty(),
        "the {context} flow emitted no flash addresses, the test is vacuous"
    );
    for (base, len) in ranges
    {
        assert!(
            contained(*base, *len),
            "{context}: driver emitted [{base:#010x}, len {len}] outside every \
             secure MPU region"
        );
    }
}

#[test]
fn every_driver_emitted_address_is_inside_an_mpu_region()
{
    // SWAP_BANK clear: the inactive bank is at the high alias (R5 / R6) and the
    // metadata is at the low alias (R1 low).
    let driver = drive_full_inactive_flow(false);
    assert_all_contained(&driver.access().ranges(), "swap-clear");

    // SWAP_BANK set: physical Bank 1 (the metadata) moves to the high alias (R1
    // high), and the inactive bank stays at the high alias (R5 / R6).
    let driver = drive_full_inactive_flow(true);
    assert_all_contained(&driver.access().ranges(), "swap-set");
}

#[test]
fn the_containment_check_is_not_vacuous()
{
    // A range one byte past R5's limit must be rejected, so a real geometry drift
    // (an emitted address sliding out of its region) is caught, not silently
    // accepted. This pins the check itself, independent of the driver run.
    assert!(
        contained(R5_INACTIVE_SECURE.0, 16),
        "a range at R5's base must be contained"
    );
    let past = R5_INACTIVE_SECURE.1 - 15;
    assert!(
        contained(past, 16),
        "a range ending at R5's limit must be contained"
    );
    assert!(
        !contained(R5_INACTIVE_SECURE.1 - 14, 16),
        "a range ending one byte past R5's limit must be rejected"
    );
}
