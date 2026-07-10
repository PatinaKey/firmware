//! Host tests for the SPI1 init sequence and the PIO transfer loop.
//!
//! Every test drives the driver through the SCRIPTED bus, which returns a
//! programmed sequence of STATUS / data reads and records all writes in order.
//! The init tests assert the configuration writes and their ordering. The
//! transfer tests assert the byte loop's TXDR writes, RXDR reads, CS toggling,
//! and the fault paths (overrun, timeout).

use embedded_hal::spi::Operation;
use embedded_hal::spi::SpiDevice;

use crate::bus::ScriptedBus;
use crate::bus::SpiBusAccess;
use crate::regs;
use crate::spi::Spi1Device;
use crate::spi::Spi1Error;

/// `SR` read returning both `TXP` and `RXP` set (a frame slot ready each poll).
const SR_READY: u32 = regs::SPI_SR_TXP | regs::SPI_SR_RXP;

/// Scripts enough `SR_READY` polls to clock `frames` bytes through the loop.
///
/// Each `transfer_byte` does one `TXP` wait and one `RXP` wait. Scripting two
/// ready reads per frame (plus a margin) keeps the loop from underflowing.
fn script_sr_ready(bus: &mut ScriptedBus, frames: usize)
{
    let reads = vec![SR_READY; frames * 2 + 4];
    bus.script_word_reads(regs::SPI1_SR, &reads);
}

#[test]
fn init_enables_both_clocks_before_touching_spi()
{
    let bus = ScriptedBus::new();
    let dev = Spi1Device::new(bus);
    let bus = consume(dev);

    let gpioa_clk = bus
        .first_word_write_index(regs::RCC_AHB2ENR1)
        .expect("GPIOA clock enable must be written");
    let spi1_clk = bus
        .first_word_write_index(regs::RCC_APB2ENR)
        .expect("SPI1 clock enable must be written");
    let first_cfg = bus
        .first_word_write_index(regs::SPI1_CFG1)
        .expect("SPI1 CFG1 must be written");

    // Both clocks come up before the SPI registers are configured.
    assert!(gpioa_clk < first_cfg, "GPIOA clock before SPI config");
    assert!(spi1_clk < first_cfg, "SPI1 clock before SPI config");
}

#[test]
fn init_sets_8bit_full_duplex_mode0_msb_software_cs()
{
    let bus = ScriptedBus::new();
    let dev = Spi1Device::new(bus);
    let bus = consume(dev);

    let cfg1 = bus.last_word_value(regs::SPI1_CFG1).expect("CFG1 written");
    // DSIZE = 8-bit (N-1 = 7), 1-data FIFO threshold, /128 prescaler.
    assert_eq!(cfg1 & regs::SPI_CFG1_DSIZE_MASK, regs::SPI_CFG1_DSIZE_8BIT, "DSIZE 8-bit");
    assert_eq!(cfg1 & regs::SPI_CFG1_FTHLV_MASK, regs::SPI_CFG1_FTHLV_1DATA, "FTHLV 1-data");
    assert_eq!(cfg1 & regs::SPI_CFG1_MBR_MASK, regs::SPI_CFG1_MBR_DIV128, "MBR /128");

    let cfg2 = bus.last_word_value(regs::SPI1_CFG2).expect("CFG2 written");
    assert_ne!(cfg2 & regs::SPI_CFG2_MASTER, 0, "MASTER set");
    assert_eq!(
        cfg2 & regs::SPI_CFG2_COMM_MASK,
        regs::SPI_CFG2_COMM_FULL_DUPLEX,
        "full-duplex"
    );
    // SPI mode 0: CPOL and CPHA both clear. MSB-first: LSBFRST clear.
    assert_eq!(cfg2 & regs::SPI_CFG2_CPOL, 0, "CPOL clear (mode 0)");
    assert_eq!(cfg2 & regs::SPI_CFG2_CPHA, 0, "CPHA clear (mode 0)");
    assert_eq!(cfg2 & regs::SPI_CFG2_LSBFRST, 0, "MSB-first");
    // Software slave management on, hardware NSS output off (the CS is GPIO PA4).
    assert_ne!(cfg2 & regs::SPI_CFG2_SSM, 0, "SSM set");
    assert_eq!(cfg2 & regs::SPI_CFG2_SSOE, 0, "SSOE clear (no hardware NSS)");
}

#[test]
fn init_holds_ssi_and_runs_endless_then_enables_and_starts()
{
    let bus = ScriptedBus::new();
    let dev = Spi1Device::new(bus);
    let bus = consume(dev);

    let cr1 = bus.last_word_value(regs::SPI1_CR1).expect("CR1 written");
    // Last CR1 state carries SSI (anti-MODF), SPE (enabled), CSTART (engine on).
    assert_ne!(cr1 & regs::SPI_CR1_SSI, 0, "SSI held high");
    assert_ne!(cr1 & regs::SPI_CR1_SPE, 0, "SPE enabled");
    assert_ne!(cr1 & regs::SPI_CR1_CSTART, 0, "CSTART started");

    let cr2 = bus.last_word_value(regs::SPI1_CR2).expect("CR2 written");
    // Endless transfer: TSIZE field cleared.
    assert_eq!(cr2 & regs::SPI_CR2_TSIZE_MASK, 0, "TSIZE = 0 (endless)");
}

#[test]
fn init_writes_ssi_high_before_selecting_master()
{
    let bus = ScriptedBus::new();
    let dev = Spi1Device::new(bus);
    let bus = consume(dev);

    // The CR1 write that ORs in SSI must precede the CFG2 write that sets MASTER,
    // so the internal slave-select is high before the master is ever selected and
    // the mode-fault window never opens. Find the first CR1 write that carries SSI
    // and the first CFG2 write that carries MASTER, then assert SSI comes first.
    let ssi_idx = bus
        .writes()
        .iter()
        .position(|w| matches!(w, crate::bus::Write::Word { addr, value }
            if *addr == regs::SPI1_CR1 && *value & regs::SPI_CR1_SSI != 0))
        .expect("a CR1 write must set SSI");
    let master_idx = bus
        .writes()
        .iter()
        .position(|w| matches!(w, crate::bus::Write::Word { addr, value }
            if *addr == regs::SPI1_CFG2 && *value & regs::SPI_CFG2_MASTER != 0))
        .expect("a CFG2 write must set MASTER");
    assert!(ssi_idx < master_idx, "SSI written high before MASTER selected");
}

#[test]
fn init_never_latches_a_mode_fault()
{
    let bus = ScriptedBus::new();
    let dev = Spi1Device::new(bus);
    let mut bus = consume(dev);

    let sr = bus.read32(regs::SPI1_SR);
    assert_eq!(sr & regs::SPI_SR_MODF, 0, "no mode fault latched after init");
}

#[test]
fn transaction_clears_mode_fault_in_the_ifcr_write()
{
    let mut bus = ScriptedBus::new();
    script_sr_ready(&mut bus, 1);
    bus.script_byte_reads(regs::SPI1_RXDR, &[0x00]);
    let mut dev = Spi1Device::new(bus);

    dev.transaction(&mut [Operation::Write(&[0x42])])
        .expect("write transaction succeeds");

    let bus = consume(dev);
    // The per-transaction IFCR clear must carry MODFC alongside EOTC / TXTFC / OVRC,
    // so a latched mode fault is cleared each transaction as defense in depth.
    let ifcr = bus.last_word_value(regs::SPI1_IFCR).expect("IFCR written");
    assert_ne!(ifcr & regs::SPI_IFCR_MODFC, 0, "MODFC cleared");
    assert_ne!(ifcr & regs::SPI_IFCR_EOTC, 0, "EOTC cleared");
    assert_ne!(ifcr & regs::SPI_IFCR_TXTFC, 0, "TXTFC cleared");
    assert_ne!(ifcr & regs::SPI_IFCR_OVRC, 0, "OVRC cleared");
}

#[test]
fn init_programs_spi_pins_af5_and_cs_output()
{
    let bus = ScriptedBus::new();
    let dev = Spi1Device::new(bus);
    let bus = consume(dev);

    let moder = bus.last_word_value(regs::GPIOA_MODER).expect("MODER written");
    // PA4 output, PA5/6/7 alternate function.
    assert_eq!(
        (moder >> regs::field2_shift(regs::CS_PIN)) & 0b11,
        regs::GPIO_MODER_OUTPUT,
        "PA4 output"
    );
    for pin in [regs::SCK_PIN, regs::MISO_PIN, regs::MOSI_PIN]
    {
        assert_eq!(
            (moder >> regs::field2_shift(pin)) & 0b11,
            regs::GPIO_MODER_ALTERNATE,
            "SPI pin alternate function"
        );
    }

    let afrl = bus.last_word_value(regs::GPIOA_AFRL).expect("AFRL written");
    for pin in [regs::SCK_PIN, regs::MISO_PIN, regs::MOSI_PIN]
    {
        assert_eq!(
            (afrl >> regs::afrl_shift(pin)) & 0xF,
            regs::GPIO_AF5,
            "SPI pin AF5"
        );
    }
}

#[test]
fn write_operation_sends_each_byte_and_toggles_cs()
{
    let mut bus = ScriptedBus::new();
    script_sr_ready(&mut bus, 3);
    // A Write discards reads, but the loop still reads RXDR after each frame.
    bus.script_byte_reads(regs::SPI1_RXDR, &[0, 0, 0]);
    let mut dev = Spi1Device::new(bus);

    dev.transaction(&mut [Operation::Write(&[0xAA, 0xBB, 0xCC])])
        .expect("write transaction succeeds");

    let bus = consume(dev);
    assert_eq!(bus.byte_writes(regs::SPI1_TXDR), vec![0xAA, 0xBB, 0xCC], "TXDR bytes");
    // CS asserted (PA4 low) then released (PA4 high) within the transaction.
    let cs_writes: Vec<u32> = bus
        .writes()
        .iter()
        .filter_map(|w| match w
        {
            crate::bus::Write::Word { addr, value } if *addr == regs::GPIOA_BSRR =>
            {
                Some(*value)
            }
            _ => None,
        })
        .collect();
    assert!(
        cs_writes.contains(&regs::bsrr_reset(regs::CS_PIN)),
        "CS asserted low during the transaction"
    );
    assert_eq!(
        cs_writes.last().copied(),
        Some(regs::bsrr_set(regs::CS_PIN)),
        "CS released high at the end"
    );
}

#[test]
fn transfer_in_place_returns_the_received_bytes()
{
    let mut bus = ScriptedBus::new();
    script_sr_ready(&mut bus, 2);
    bus.script_byte_reads(regs::SPI1_RXDR, &[0x11, 0x22]);
    let mut dev = Spi1Device::new(bus);

    let mut buf = [0xF0, 0x0F];
    dev.transaction(&mut [Operation::TransferInPlace(&mut buf)])
        .expect("transfer-in-place succeeds");

    // The buffer now holds the scripted RXDR reads.
    assert_eq!(buf, [0x11, 0x22], "received bytes");
    let bus = consume(dev);
    // The original buffer bytes were sent on MOSI.
    assert_eq!(bus.byte_writes(regs::SPI1_TXDR), vec![0xF0, 0x0F], "sent bytes");
}

#[test]
fn read_operation_clocks_dummy_and_stores_reads()
{
    let mut bus = ScriptedBus::new();
    script_sr_ready(&mut bus, 2);
    bus.script_byte_reads(regs::SPI1_RXDR, &[0xDE, 0xAD]);
    let mut dev = Spi1Device::new(bus);

    let mut buf = [0u8; 2];
    dev.transaction(&mut [Operation::Read(&mut buf)])
        .expect("read succeeds");

    assert_eq!(buf, [0xDE, 0xAD], "stored reads");
    let bus = consume(dev);
    // A read clocks the dummy byte 0x00 per slot.
    assert_eq!(bus.byte_writes(regs::SPI1_TXDR), vec![0x00, 0x00], "dummy MOSI bytes");
}

#[test]
fn multi_operation_transaction_holds_one_cs_assertion()
{
    let mut bus = ScriptedBus::new();
    // The L1 response read shape: a status TransferInPlace then a Read.
    script_sr_ready(&mut bus, 5);
    bus.script_byte_reads(regs::SPI1_RXDR, &[0x01, 0x10, 0x20, 0x30, 0x40]);
    let mut dev = Spi1Device::new(bus);

    let mut status = [0xAA];
    let mut frame = [0u8; 4];
    dev.transaction(&mut [
        Operation::TransferInPlace(&mut status),
        Operation::Read(&mut frame),
    ])
    .expect("two-op transaction succeeds");

    assert_eq!(status, [0x01], "status byte");
    assert_eq!(frame, [0x10, 0x20, 0x30, 0x40], "frame bytes");

    let bus = consume(dev);
    // Exactly one assert (PA4 low) and one release (PA4 high) for both operations.
    let asserts = bus
        .writes()
        .iter()
        .filter(|w| matches!(w, crate::bus::Write::Word { addr, value }
            if *addr == regs::GPIOA_BSRR && *value == regs::bsrr_reset(regs::CS_PIN)))
        .count();
    let releases = bus
        .writes()
        .iter()
        .filter(|w| matches!(w, crate::bus::Write::Word { addr, value }
            if *addr == regs::GPIOA_BSRR && *value == regs::bsrr_set(regs::CS_PIN)))
        .count();
    // One release also happens in init (CS idle high), so the transaction adds one.
    assert_eq!(asserts, 1, "single CS assertion for the whole transaction");
    assert_eq!(releases, 2, "init idle-high plus the transaction release");
}

#[test]
fn overrun_during_transfer_surfaces_and_releases_cs()
{
    let mut bus = ScriptedBus::new();
    // First TXP poll is fine, then OVR is set: the wait short-circuits.
    bus.script_word_reads(
        regs::SPI1_SR,
        &[SR_READY, regs::SPI_SR_OVR],
    );
    bus.script_byte_reads(regs::SPI1_RXDR, &[0x00]);
    let mut dev = Spi1Device::new(bus);

    let err = dev
        .transaction(&mut [Operation::Write(&[0x55, 0x66])])
        .expect_err("overrun must surface");
    assert_eq!(err, Spi1Error::Overrun, "overrun mapped");

    let bus = consume(dev);
    // CS is released even on the error path.
    let last_bsrr = bus.writes().iter().rev().find_map(|w| match w
    {
        crate::bus::Write::Word { addr, value } if *addr == regs::GPIOA_BSRR => Some(*value),
        _ => None,
    });
    assert_eq!(last_bsrr, Some(regs::bsrr_set(regs::CS_PIN)), "CS released after fault");
}

#[test]
fn error_mid_transfer_leaves_the_engine_cleared_spe_off()
{
    let mut bus = ScriptedBus::new();
    // First TXP poll is fine, then OVR is set so the wait short-circuits mid-byte.
    bus.script_word_reads(regs::SPI1_SR, &[SR_READY, regs::SPI_SR_OVR]);
    bus.script_byte_reads(regs::SPI1_RXDR, &[0x00]);
    let mut dev = Spi1Device::new(bus);

    dev.transaction(&mut [Operation::Write(&[0x55, 0x66])])
        .expect_err("overrun must surface");

    let bus = consume(dev);
    // The fail-closed drain clears SPE, so the LAST CR1 state observed is SPE = 0.
    // Only clearing SPE flushes the RxFIFO, so the next transaction re-arms from
    // an empty FIFO. RM0456 sec 68.4.12.
    let final_cr1 = bus.last_word_value(regs::SPI1_CR1).expect("CR1 written");
    assert_eq!(final_cr1 & regs::SPI_CR1_SPE, 0, "SPE cleared on the error path");
}

#[test]
fn transaction_rearms_the_engine_from_a_flushed_fifo()
{
    let mut bus = ScriptedBus::new();
    script_sr_ready(&mut bus, 1);
    bus.script_byte_reads(regs::SPI1_RXDR, &[0x00]);
    let mut dev = Spi1Device::new(bus);

    dev.transaction(&mut [Operation::Write(&[0x77])])
        .expect("write transaction succeeds");

    let bus = consume(dev);
    // The re-arm runs INSIDE the transaction, before the CS assertion: clear SPE
    // (flush both FIFOs), re-write TSIZE = 0, set SPE, then CSTART. Locate the CS
    // assertion (the transaction boundary) and inspect the CR1 writes just before.
    let select_idx = bus
        .writes()
        .iter()
        .position(|w| matches!(w, crate::bus::Write::Word { addr, value }
            if *addr == regs::GPIOA_BSRR && *value == regs::bsrr_reset(regs::CS_PIN)))
        .expect("the transaction asserts CS");

    // The three CR1 writes immediately before the CS assertion are the re-arm. The
    // first clears SPE (the FIFO flush), the second re-sets SPE, the third sets
    // CSTART. Asserting this ordering proves the flush-then-re-arm sequence.
    let cr1_before_select: Vec<u32> = bus
        .writes()
        .iter()
        .take(select_idx)
        .filter_map(|w| match w
        {
            crate::bus::Write::Word { addr, value } if *addr == regs::SPI1_CR1 =>
            {
                Some(*value)
            }
            _ => None,
        })
        .collect();
    let rearm = &cr1_before_select[cr1_before_select.len() - 3..];
    assert_eq!(rearm[0] & regs::SPI_CR1_SPE, 0, "re-arm clears SPE first (flush)");
    assert_ne!(rearm[1] & regs::SPI_CR1_SPE, 0, "re-arm then re-enables SPE");
    assert_ne!(rearm[2] & regs::SPI_CR1_CSTART, 0, "re-arm starts the engine (CSTART)");

    let final_cr1 = bus.last_word_value(regs::SPI1_CR1).expect("CR1 written");
    assert_ne!(final_cr1 & regs::SPI_CR1_SPE, 0, "engine left enabled (SPE)");
    assert_ne!(final_cr1 & regs::SPI_CR1_CSTART, 0, "master engine started (CSTART)");
}

#[test]
fn never_ready_status_times_out()
{
    let mut bus = ScriptedBus::new();
    // SR never sets TXP: feed a large run of 0s so the bounded poll exhausts.
    let stuck = vec![0u32; 200_000];
    bus.script_word_reads(regs::SPI1_SR, &stuck);
    let mut dev = Spi1Device::new(bus);

    let err = dev
        .transaction(&mut [Operation::Write(&[0x01])])
        .expect_err("a stuck status must time out");
    assert_eq!(err, Spi1Error::Timeout, "timeout mapped");
}

/// Consumes the device to recover the scripted bus for assertions.
///
/// `Spi1Device` owns the bus, so the tests reach back into it through this small
/// destructure helper rather than a public accessor on the production type.
fn consume(dev: Spi1Device<ScriptedBus>) -> ScriptedBus
{
    dev.into_bus()
}
