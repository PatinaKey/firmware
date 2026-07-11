//! The secure SysTick as a polled millisecond delay (TICKINT = 0).
//!
//! [`SysTick`] times a millisecond delay by running the 24-bit SysTick down
//! counter one reload at a time and polling COUNTFLAG, with no exception armed.
//! The whole delay is written against the [`RegisterBus`] port, so the reload
//! arithmetic and the poll loop are hardware-independent and host-testable.
//! The real hardware drives it through [`MmioBus`](crate::MmioBus), a host test
//! through a state-modelling mock (see the test module).
//!
//! # Which SysTick
//!
//! The addresses in `regs` are the SECURE view of the banked SysTick (PM0264
//! Table 83). The non-secure alias at +0x0002_0000 is a separate banked
//! instance this driver never touches. SysTick lives in the PPB / System Control
//! Space, outside the SAU and GTZC (RM0456 Figure 8 and sec 3.5.2), so the
//! non-secure world cannot address the secure instance and cannot disturb this
//! delay. With TICKINT = 0 no SysTick exception is raised, so AIRCR.PRIS is
//! neutral for it.
//!
//! # Clock source
//!
//! CLKSOURCE = 1 selects the processor clock (HCLK) directly, needing no RCC
//! step (PM0264 Table 84). The reload count is derived from the known
//! [`HCLK_HZ`](crate::HCLK_HZ), never from SYST_CALIB (see the SYST_CALIB note
//! in `regs`).

use crate::bus::RegisterBus;
use crate::regs;

/// One 24-bit reload spans up to 2^24 processor-clock ticks.
///
/// SYST_RVR holds RELOAD in bits [23:0] (PM0264 Table 85), so the largest reload
/// is 0x00FF_FFFF, which times a period of 0x0100_0000 ticks (RELOAD + 1, PM0264
/// sec 4.4.2.1). A delay longer than that is split across successive reloads.
const MAX_CHUNK_TICKS: u64 = (regs::SYST_RVR_RELOAD_MASK as u64) + 1;

/// Returns the processor-clock ticks that span `ms` milliseconds at `hclk_hz`.
///
/// Computes `hclk_hz * ms / 1000` in u64. The product of two u32 values always
/// fits in u64, so the multiplication cannot overflow, and dividing once at the
/// end (not per millisecond) keeps the rounding to a single truncation.
const fn total_ticks(hclk_hz: u32, ms: u32) -> u64
{
    (hclk_hz as u64 * ms as u64) / 1000
}

/// Splits the remaining tick count into one reload chunk.
///
/// Returns `(rvr, chunk)`. `chunk` is the ticks this reload accounts for (capped
/// at [`MAX_CHUNK_TICKS`]), the amount the caller subtracts from the running
/// total. `rvr` is the SYST_RVR value for the PROGRAMMED period (RELOAD = N - 1
/// for an N-tick period, PM0264 sec 4.4.2.1).
///
/// The programmed period is floored at 2 ticks, because RELOAD = 0 is OUT of the
/// valid range 0x1..0x00FF_FFFF (PM0264 sec 4.4.2.1): at RELOAD = 0 the counter
/// never makes the 1 -> 0 transition, COUNTFLAG never sets, and the poll would
/// hang forever on silicon. So a 1-tick residue is programmed as a 2-tick period,
/// a 1-tick over-wait, which is the safe direction, while `chunk` stays exact so
/// the accounting is unchanged. `rvr` is therefore always in [1, 0x00FF_FFFF],
/// never 0. The caller invokes this only while `ticks_remaining > 0`.
const fn reload_for_chunk(ticks_remaining: u64) -> (u32, u64)
{
    let chunk = if ticks_remaining < MAX_CHUNK_TICKS
    {
        ticks_remaining
    }
    else
    {
        MAX_CHUNK_TICKS
    };
    // Floor the PROGRAMMED period at 2 ticks so RVR is never 0 (RELOAD = 0 is out
    // of the valid range and would never wrap). `chunk` stays the exact
    // accounting amount, so at worst a 1-tick residue over-waits by one tick.
    let period = if chunk < 2
    {
        2
    }
    else
    {
        chunk
    };
    ((period - 1) as u32, chunk)
}

/// A polled SysTick millisecond delay behind the [`RegisterBus`] seam.
///
/// Holds the register bus and the HCLK rate the reload count is derived from.
/// Built through [`SysTick::new`], then consumed by a caller that needs a
/// blocking delay (the SE L1 poll cadence via mcu-spi's `SysTickWait`).
pub struct SysTick<B: RegisterBus>
{
    bus: B,
    hclk_hz: u32,
}

impl<B: RegisterBus> SysTick<B>
{
    /// Builds the delay from a register bus and the core-clock rate in hertz.
    ///
    /// Pass [`HCLK_HZ`](crate::HCLK_HZ) for `hclk_hz`, so the delay tracks the
    /// one source of truth for the core clock.
    pub fn new(bus: B, hclk_hz: u32) -> Self
    {
        SysTick
        {
            bus,
            hclk_hz,
        }
    }

    /// Blocks for `ms` milliseconds by polling the SysTick COUNTFLAG.
    ///
    /// INFALLIBLE and unbounded by design: HCLK drives BOTH the core and the
    /// SysTick counter, so if the counter cannot advance the core cannot run the
    /// poll either. There is no failure mode a caller could recover from, so the
    /// delay returns nothing and never times out. `ms == 0` returns at once.
    ///
    /// For each reload chunk it programs SYST_RVR, clears SYST_CVR (which clears
    /// the counter and COUNTFLAG), enables the counter with CLKSOURCE = 1 and
    /// TICKINT = 0, polls SYST_CSR once per iteration until COUNTFLAG is set
    /// (the flag clears on that read, so it is read exactly once), then disables
    /// the counter. PM0264 sec 4.4.5 (the RVR, CVR, CSR init idiom) and Table 86
    /// (a CVR write clears the flag, a CSR read clears COUNTFLAG).
    pub fn delay_ms(&mut self, ms: u32)
    {
        if ms == 0
        {
            return;
        }
        let mut total = total_ticks(self.hclk_hz, ms);
        while total > 0
        {
            let (rvr, chunk) = reload_for_chunk(total);

            // Program the reload, clear the current value (also clears
            // COUNTFLAG), then start the counter on HCLK with no interrupt.
            self.bus.write32(regs::SYST_RVR, rvr);
            self.bus.write32(regs::SYST_CVR, 0);
            self.bus.write32(
                regs::SYST_CSR,
                regs::SYST_CSR_CLKSOURCE | regs::SYST_CSR_ENABLE,
            );

            // Poll once per iteration. Reading SYST_CSR clears COUNTFLAG, so a
            // second read in the same wrap would lose it: read exactly once and
            // break when the counter has wrapped to zero.
            loop
            {
                if self.bus.read32(regs::SYST_CSR) & regs::SYST_CSR_COUNTFLAG != 0
                {
                    break;
                }
            }

            // Disable the counter before the next chunk (or before returning).
            self.bus.write32(regs::SYST_CSR, 0);
            total -= chunk;
        }
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::regs;

    extern crate alloc;
    use alloc::vec::Vec;

    // Pure reload arithmetic. No bus access: these lock the RVR = N - 1 rule,
    // the 24-bit ceiling, the multi-chunk split, and the u64 tick count.

    #[test]
    fn total_ticks_at_4mhz()
    {
        // 4 MHz core clock: 1 ms = 4000 ticks, 25 ms = 100000, 1 s = 4000000.
        assert_eq!(total_ticks(4_000_000, 1), 4_000);
        assert_eq!(total_ticks(4_000_000, 25), 100_000);
        assert_eq!(total_ticks(4_000_000, 1000), 4_000_000);
    }

    #[test]
    fn total_ticks_zero_ms_is_zero()
    {
        assert_eq!(total_ticks(4_000_000, 0), 0);
    }

    #[test]
    fn total_ticks_large_timeout_does_not_overflow()
    {
        // The worst realistic case: a full u32 millisecond count at 4 MHz stays
        // far inside u64, so the product never overflows.
        let expected: u64 = 4_000_000u64 * (u32::MAX as u64) / 1000;
        assert_eq!(total_ticks(4_000_000, u32::MAX), expected);
        assert_eq!(total_ticks(4_000_000, u32::MAX), 17_179_869_180_000);
    }

    #[test]
    fn reload_is_n_minus_one()
    {
        // A 4000-tick period programs RELOAD = 3999, chunk = 4000.
        assert_eq!(reload_for_chunk(4_000), (3_999, 4_000));
        // The smallest chunk is 1 tick. RELOAD = 0 is out of the valid range and
        // would hang the poll, so the programmed period is floored at 2 ticks:
        // rvr = 1, while chunk stays 1 so the accounting is exact.
        assert_eq!(reload_for_chunk(1), (1, 1));
        // A 2-tick chunk is already at the floor: RELOAD = 1, chunk = 2.
        assert_eq!(reload_for_chunk(2), (1, 2));
    }

    #[test]
    fn reload_for_chunk_never_programs_reload_zero()
    {
        assert_eq!(reload_for_chunk(1), (1, 1));
        // Spot-check across the range: rvr is never 0 while ticks_remaining >= 1.
        for ticks in [1u64, 2, MAX_CHUNK_TICKS + 1]
        {
            let (rvr, chunk) = reload_for_chunk(ticks);
            assert_ne!(rvr, 0, "rvr must never be programmed to 0");
            assert!(chunk >= 1, "chunk must span at least one tick");
        }
    }

    #[test]
    fn reload_caps_at_the_24_bit_ceiling()
    {
        // Exactly one full reload span: RELOAD = 0x00FF_FFFF, chunk = 2^24.
        assert_eq!(
            reload_for_chunk(MAX_CHUNK_TICKS),
            (regs::SYST_RVR_RELOAD_MASK, MAX_CHUNK_TICKS)
        );
        // More than one span: still capped to one full reload this chunk.
        assert_eq!(
            reload_for_chunk(MAX_CHUNK_TICKS + 5),
            (regs::SYST_RVR_RELOAD_MASK, MAX_CHUNK_TICKS)
        );
        // The RELOAD value fits the 24-bit field.
        assert_eq!(regs::SYST_RVR_RELOAD_MASK, 0x00FF_FFFF);
    }

    #[test]
    fn multi_chunk_split_sums_to_the_request()
    {
        // A request of 2.5 reload spans splits into two full spans plus a
        // remainder, and the chunks sum back to the exact request.
        let total: u64 = MAX_CHUNK_TICKS * 2 + 0x0050_0000;
        let mut remaining = total;
        let mut chunks: Vec<(u32, u64)> = Vec::new();
        while remaining > 0
        {
            let (rvr, chunk) = reload_for_chunk(remaining);
            chunks.push((rvr, chunk));
            remaining -= chunk;
        }
        assert_eq!(chunks.len(), 3, "2.5 spans is three chunks");
        assert_eq!(chunks[0], (regs::SYST_RVR_RELOAD_MASK, MAX_CHUNK_TICKS));
        assert_eq!(chunks[1], (regs::SYST_RVR_RELOAD_MASK, MAX_CHUNK_TICKS));
        assert_eq!(chunks[2], (0x004F_FFFF, 0x0050_0000));
        let summed: u64 = chunks.iter().map(|(_, c)| *c).sum();
        assert_eq!(summed, total, "chunks must sum to the request");
    }

    // ===================================================================
    // A state-modelling SysTick mock. It is NOT the RecordingBus: that bus
    // reads back the last write and cannot model COUNTFLAG (its READ-BACK
    // INVARIANT doc says so). This mock models the three hardware behaviours
    // the poll depends on:
    //   - a write to SYST_CVR clears the elapsed-tick counter and COUNTFLAG,
    //   - COUNTFLAG reads 0 while the counter is still running, then reads 1
    //     once a full period (RELOAD + 1 ticks) has elapsed,
    //   - reading SYST_CSR returns COUNTFLAG then CLEARS it, so a second read
    //     in the same wrap loses it.
    // One modelled tick elapses per SYST_CSR read, which is how host time
    // advances here. The counter only runs while ENABLE is set.
    // ===================================================================

    struct SysTickHw
    {
        writes: Vec<(u32, u32)>,
        reload: u32,
        elapsed: u64,
        enabled: bool,
    }

    impl SysTickHw
    {
        fn new() -> Self
        {
            SysTickHw
            {
                writes: Vec::new(),
                reload: 0,
                elapsed: 0,
                enabled: false,
            }
        }
    }

    impl RegisterBus for SysTickHw
    {
        fn read32(&mut self, addr: u32) -> u32
        {
            if addr == regs::SYST_CSR
            {
                // RELOAD = 0 is OUT of the valid range (PM0264 sec 4.4.2.1): the
                // counter never makes the 1 -> 0 transition, so COUNTFLAG is
                // NEVER set. Model it as a DEAD counter, the OPPOSITE of a 1-tick
                // period, so any path that programmed RVR = 0 hangs the test and
                // forces the reload_for_chunk guard to exist.
                if self.enabled && self.reload != 0
                {
                    // One tick elapses per poll. COUNTFLAG sets when a full
                    // period of RELOAD + 1 ticks has run since the CVR clear,
                    // that is once elapsed passes RELOAD.
                    self.elapsed += 1;
                    if self.elapsed > self.reload as u64
                    {
                        // The wrap is observed. Reading CSR returns COUNTFLAG
                        // set and clears it (a second read would read 0).
                        self.elapsed = 0;
                        return regs::SYST_CSR_COUNTFLAG;
                    }
                }
                return 0;
            }
            0
        }

        fn write32(&mut self, addr: u32, value: u32)
        {
            self.writes.push((addr, value));
            if addr == regs::SYST_RVR
            {
                self.reload = value;
            }
            else if addr == regs::SYST_CVR
            {
                // A CVR write clears the counter and COUNTFLAG (PM0264 Table 86).
                self.elapsed = 0;
            }
            else if addr == regs::SYST_CSR
            {
                self.enabled = value & regs::SYST_CSR_ENABLE != 0;
            }
        }
    }

    #[test]
    fn single_chunk_emits_the_exact_ordered_trace_and_terminates()
    {
        // A tiny HCLK keeps one chunk small: 4000 Hz, 1 ms = 4 ticks, so
        // RELOAD = 3 and the poll wraps after 4 reads. The trace is the
        // contract: RVR, CVR = 0, CSR = enable, CSR = 0 disable.
        let mut st = SysTick::new(SysTickHw::new(), 4_000);
        st.delay_ms(1);
        let expected: Vec<(u32, u32)> = alloc::vec![
            (regs::SYST_RVR, 3),
            (regs::SYST_CVR, 0),
            (regs::SYST_CSR, regs::SYST_CSR_CLKSOURCE | regs::SYST_CSR_ENABLE),
            (regs::SYST_CSR, 0),
        ];
        assert_eq!(st.bus.writes, expected);
    }

    #[test]
    fn poll_loops_until_countflag_sets()
    {
        // A larger single chunk: 100000 Hz, 1 ms = 100 ticks, RELOAD = 99, so
        // the counter is polled 100 times before COUNTFLAG sets. The delay must
        // still terminate and end with the disable write.
        let mut st = SysTick::new(SysTickHw::new(), 100_000);
        st.delay_ms(1);
        // RELOAD = 99 was programmed.
        assert_eq!(st.bus.writes[0], (regs::SYST_RVR, 99));
        // The last write disables the counter.
        assert_eq!(st.bus.writes.last(), Some(&(regs::SYST_CSR, 0)));
        // Exactly one enable and one disable were issued (one chunk).
        let enables = st
            .bus
            .writes
            .iter()
            .filter(|(a, v)| {
                *a == regs::SYST_CSR
                    && *v == regs::SYST_CSR_CLKSOURCE | regs::SYST_CSR_ENABLE
            })
            .count();
        assert_eq!(enables, 1, "one reload chunk means one enable");
    }

    #[test]
    fn tickint_bit_is_never_set()
    {
        // No SysTick exception is armed: TICKINT must be absent from every CSR
        // write, so AIRCR.PRIS stays neutral for it.
        let mut st = SysTick::new(SysTickHw::new(), 4_000);
        st.delay_ms(2);
        for (addr, value) in &st.bus.writes
        {
            if *addr == regs::SYST_CSR
            {
                assert_eq!(
                    value & regs::SYST_CSR_TICKINT,
                    0,
                    "TICKINT must never be set"
                );
            }
        }
    }

    #[test]
    fn zero_ms_emits_no_write()
    {
        // A zero-millisecond delay touches no register.
        let mut st = SysTick::new(SysTickHw::new(), 4_000);
        st.delay_ms(0);
        assert!(st.bus.writes.is_empty(), "ms == 0 must not touch SysTick");
    }

    #[test]
    fn countflag_clears_on_the_csr_read()
    {
        // Model check: after the counter wraps and one CSR read returns
        // COUNTFLAG, a second read in the same wrap reads 0. This is the
        // one-read-per-iteration hazard the poll is written against.
        let mut hw = SysTickHw::new();
        hw.write32(regs::SYST_RVR, 2);
        hw.write32(regs::SYST_CVR, 0);
        hw.write32(regs::SYST_CSR, regs::SYST_CSR_CLKSOURCE | regs::SYST_CSR_ENABLE);
        // RELOAD = 2 is a 3-tick period: the first two reads see the counter
        // still running, the third read observes the wrap.
        assert_eq!(hw.read32(regs::SYST_CSR) & regs::SYST_CSR_COUNTFLAG, 0);
        assert_eq!(hw.read32(regs::SYST_CSR) & regs::SYST_CSR_COUNTFLAG, 0);
        assert_eq!(
            hw.read32(regs::SYST_CSR) & regs::SYST_CSR_COUNTFLAG,
            regs::SYST_CSR_COUNTFLAG
        );
        // A fourth read after the wrap has lost the flag (it clears on read).
        assert_eq!(hw.read32(regs::SYST_CSR) & regs::SYST_CSR_COUNTFLAG, 0);
    }

    // ===================================================================
    // A fast-wrap SysTick mock for the cross-chunk sequencing test. It wraps
    // after a small FIXED number of reads REGARDLESS of the reload magnitude,
    // so the real delay_ms can be driven across multiple 2^24-tick chunks
    // without spinning millions of mock reads. The per-chunk tick COUNT is
    // already pinned by the pure arithmetic tests, what this models is only the
    // cross-chunk enable / poll / disable SEQUENCING. RELOAD = 0 is still
    // modelled as a DEAD counter (never wraps), so a programmed RVR = 0 would
    // hang this test too, the same guard the pure test pins.
    // ===================================================================

    struct FastWrapHw
    {
        writes: Vec<(u32, u32)>,
        reload: u32,
        reads_since_arm: u32,
        enabled: bool,
    }

    impl FastWrapHw
    {
        // Reads before a modelled wrap. Small so a multi-chunk delay runs in a
        // handful of reads instead of tens of millions.
        const READS_PER_WRAP: u32 = 3;

        fn new() -> Self
        {
            FastWrapHw
            {
                writes: Vec::new(),
                reload: 0,
                reads_since_arm: 0,
                enabled: false,
            }
        }
    }

    impl RegisterBus for FastWrapHw
    {
        fn read32(&mut self, addr: u32) -> u32
        {
            if addr == regs::SYST_CSR
            {
                // RELOAD = 0 stays a DEAD counter: it never wraps, so a
                // programmed RVR = 0 would hang here.
                if self.enabled && self.reload != 0
                {
                    self.reads_since_arm += 1;
                    if self.reads_since_arm >= Self::READS_PER_WRAP
                    {
                        self.reads_since_arm = 0;
                        return regs::SYST_CSR_COUNTFLAG;
                    }
                }
                return 0;
            }
            0
        }

        fn write32(&mut self, addr: u32, value: u32)
        {
            self.writes.push((addr, value));
            if addr == regs::SYST_RVR
            {
                self.reload = value;
            }
            else if addr == regs::SYST_CVR
            {
                self.reads_since_arm = 0;
            }
            else if addr == regs::SYST_CSR
            {
                self.enabled = value & regs::SYST_CSR_ENABLE != 0;
            }
        }
    }

    #[test]
    fn multi_chunk_delay_sequences_each_chunk_and_terminates()
    {
        let mut st = SysTick::new(FastWrapHw::new(), 20_000_000);
        st.delay_ms(1000);

        // Two chunks means two enable writes and two disable writes.
        let enables = st
            .bus
            .writes
            .iter()
            .filter(|(a, v)| {
                *a == regs::SYST_CSR
                    && *v == regs::SYST_CSR_CLKSOURCE | regs::SYST_CSR_ENABLE
            })
            .count();
        let disables = st
            .bus
            .writes
            .iter()
            .filter(|(a, v)| *a == regs::SYST_CSR && *v == 0)
            .count();
        assert_eq!(enables, 2, "two chunks means two enable writes");
        assert_eq!(disables, 2, "each chunk disables the counter after its wrap");

        // The delay returned cleanly: the last write disables the counter.
        assert_eq!(st.bus.writes.last(), Some(&(regs::SYST_CSR, 0)));

        // The two chunks program a full 2^24 span then the remainder, and NO RVR
        // write is ever 0 (the guard holds across every chunk). RELOAD = N - 1.
        let rvr_writes: Vec<u32> = st
            .bus
            .writes
            .iter()
            .filter(|(a, _)| *a == regs::SYST_RVR)
            .map(|(_, v)| *v)
            .collect();
        assert_eq!(rvr_writes.len(), 2, "exactly two reload chunks");
        assert_eq!(
            rvr_writes[0],
            regs::SYST_RVR_RELOAD_MASK,
            "first chunk is a full 2^24 span"
        );
        assert_eq!(rvr_writes[1], 3_222_784 - 1, "second chunk is the remainder");
        for value in &rvr_writes
        {
            assert_ne!(*value, 0, "RVR must never be programmed to 0");
        }
    }
}
