//! Ordered-trace tests for the partition sequence.
//!
//! Each test drives `apply_partition` over a `RecordingBus` and asserts the
//! ordering hazards by comparing first-write INDICES, plus the
//! exact values where they matter. The trace order is the contract: these tests
//! fail closed if a future edit reorders a step.

use super::*;
use crate::bus::RecordingBus;
use crate::map;
use crate::regs;

/// Runs the full sequence and returns the recording bus for inspection.
fn run() -> RecordingBus
{
    let mut bus = RecordingBus::new();
    apply_partition(&mut bus).expect("partition must apply");
    bus
}

#[test]
fn sequence_completes()
{
    let bus = run();
    assert!(!bus.writes().is_empty());
}

#[test]
fn gtzc_clocks_enabled_before_any_tzsc_write()
{
    // Hazard: a TZSC/MPCBB/TZIC write before the GTZC clock is silently lost.
    let bus = run();
    let clk1 = bus.first_write_index(regs::RCC_AHB1ENR).expect("AHB1ENR write");
    let clk3 = bus.first_write_index(regs::RCC_AHB3ENR).expect("AHB3ENR write");
    let tzsc2 = bus
        .first_write_index(regs::GTZC1_TZSC_BASE + regs::TZSC_SECCFGR2_OFF)
        .expect("TZSC SECCFGR2 write");
    let mpcbb = bus
        .first_write_index(regs::mpcbb_seccfgr(regs::MPCBB1_BASE, map::SRAM1_FIRST_NS_SUPERBLOCK))
        .expect("MPCBB1 SECCFGR write");
    assert!(clk1 < tzsc2, "GTZC1 clock must precede TZSC write");
    assert!(clk3 < tzsc2, "GTZC2 clock must precede TZSC write");
    assert!(clk1 < mpcbb, "GTZC1 clock must precede MPCBB write");
}

#[test]
fn gtzc_clock_bits_are_exact()
{
    let bus = run();
    let ahb1 = bus.last_value(regs::RCC_AHB1ENR).expect("AHB1ENR");
    assert_eq!(ahb1 & regs::RCC_AHB1ENR_GTZC1EN, regs::RCC_AHB1ENR_GTZC1EN);
    assert_eq!(ahb1 & regs::RCC_AHB1ENR_GPDMA1EN, regs::RCC_AHB1ENR_GPDMA1EN);
    let ahb3 = bus.last_value(regs::RCC_AHB3ENR).expect("AHB3ENR");
    assert_eq!(ahb3 & regs::RCC_AHB3ENR_GTZC2EN, regs::RCC_AHB3ENR_GTZC2EN);
}

#[test]
fn sau_disabled_then_regions_then_enabled()
{
    let bus = run();
    // SAU_CTRL is written twice: first 0 (disable), last ENABLE.
    let writes: alloc::vec::Vec<u32> = bus
        .writes()
        .iter()
        .filter(|(a, _)| *a == regs::SAU_CTRL)
        .map(|(_, v)| *v)
        .collect();
    assert_eq!(writes.first(), Some(&0u32), "SAU disabled first");
    assert_eq!(writes.last(), Some(&regs::SAU_CTRL_ENABLE), "SAU enabled last");
    // ALLNS must NEVER be set.
    for v in &writes
    {
        assert_eq!(v & regs::SAU_CTRL_ALLNS, 0, "ALLNS must never be set");
    }
}

#[test]
fn sau_regions_written_between_disable_and_enable()
{
    let bus = run();
    let ctrl_indices: alloc::vec::Vec<usize> = bus
        .writes()
        .iter()
        .enumerate()
        .filter(|(_, (a, _))| *a == regs::SAU_CTRL)
        .map(|(i, _)| i)
        .collect();
    let disable_at = *ctrl_indices.first().expect("disable write");
    let enable_at = *ctrl_indices.last().expect("enable write");
    let rbar = bus.first_write_index(regs::SAU_RBAR).expect("RBAR write");
    let rlar = bus.first_write_index(regs::SAU_RLAR).expect("RLAR write");
    assert!(disable_at < rbar && rbar < enable_at);
    assert!(disable_at < rlar && rlar < enable_at);
}

#[test]
fn sau_programs_every_region_in_order()
{
    let bus = run();
    // RNR should be written once per region with ascending region numbers.
    let rnr: alloc::vec::Vec<u32> = bus
        .writes()
        .iter()
        .filter(|(a, _)| *a == regs::SAU_RNR)
        .map(|(_, v)| *v)
        .collect();
    let expected: alloc::vec::Vec<u32> = (0..map::SAU_PROGRAMMED_REGIONS as u32).collect();
    assert_eq!(rnr, expected);
}

#[test]
fn spi1_secure_paired_with_se_pins_secure()
{
    // Hazard: SPI1 secure but a SE pin NS -> AF gate drives zero, link dead.
    let bus = run();
    let spi1 = bus
        .last_value(regs::GTZC1_TZSC_BASE + regs::TZSC_SECCFGR2_OFF)
        .expect("SECCFGR2");
    assert_eq!(spi1 & regs::TZSC1_SECCFGR2_SPI1SEC, regs::TZSC1_SECCFGR2_SPI1SEC);

    // The SE pins (PA4-7, PB1) must end SECURE: the GPIOA/B SECCFGR modify clears
    // only the NS pins and sets the secure pins, never clearing a SE pin.
    let gpioa = bus.last_value(regs::gpio_seccfgr(regs::GPIOA_BASE)).expect("GPIOA");
    assert_eq!(gpioa & map::GPIOA_SECURE_PINS, map::GPIOA_SECURE_PINS);
    assert_eq!(gpioa & map::GPIOA_NS_PINS, 0, "USB pins must be NS");
    let gpiob = bus.last_value(regs::gpio_seccfgr(regs::GPIOB_BASE)).expect("GPIOB");
    assert_eq!(gpiob & map::GPIOB_SECURE_PINS, map::GPIOB_SECURE_PINS);
    assert_eq!(gpiob & map::GPIOB_NS_PINS, 0, "TSC pins must be NS");
}

#[test]
fn crypto_block_marked_secure()
{
    let bus = run();
    let v = bus
        .last_value(regs::GTZC1_TZSC_BASE + regs::TZSC_SECCFGR3_OFF)
        .expect("SECCFGR3");
    let expect = regs::TZSC1_SECCFGR3_AESSEC
        | regs::TZSC1_SECCFGR3_HASHSEC
        | regs::TZSC1_SECCFGR3_RNGSEC
        | regs::TZSC1_SECCFGR3_PKASEC
        | regs::TZSC1_SECCFGR3_SAESSEC;
    assert_eq!(v & expect, expect);
}

#[test]
fn gpdma_se_channels_secure()
{
    let bus = run();
    let v = bus.last_value(regs::GPDMA_SECCFGR).expect("GPDMA SECCFGR");
    assert_eq!(v & map::GPDMA_SECURE_CHANNELS, map::GPDMA_SECURE_CHANNELS);
}

#[test]
fn sram1_only_upper_superblocks_cleared()
{
    let bus = run();
    // Super-blocks below the split must NOT be written (stay secure at reset),
    // those at/above the split must be cleared to 0 (NS).
    for sb in 0..map::SRAM1_FIRST_NS_SUPERBLOCK
    {
        assert!(
            bus.first_write_index(regs::mpcbb_seccfgr(regs::MPCBB1_BASE, sb)).is_none(),
            "secure super-block {} must not be touched",
            sb
        );
    }
    for sb in map::SRAM1_FIRST_NS_SUPERBLOCK..map::SRAM1_SUPERBLOCKS
    {
        assert_eq!(
            bus.last_value(regs::mpcbb_seccfgr(regs::MPCBB1_BASE, sb)),
            Some(0),
            "NS super-block {} must be cleared",
            sb
        );
    }
}

#[test]
fn sram2_and_sram4_left_at_reset()
{
    let bus = run();
    // The sequence never writes SRAM2/SRAM4 SECCFGR (they stay fully secure).
    assert!(bus.first_write_index(regs::mpcbb_seccfgr(regs::MPCBB2_BASE, 0)).is_none());
    assert!(bus.first_write_index(regs::mpcbb_seccfgr(regs::MPCBB4_BASE, 0)).is_none());
}

#[test]
fn tzic_enabled_after_all_tzsc_and_mpcbb_writes()
{
    // Hazard: TZIC before TZSC/MPCBB done -> spurious secure faults.
    let bus = run();
    let tzic = bus.first_write_index(regs::GTZC1_TZIC_BASE + regs::TZIC_IER1_OFF).expect("TZIC");
    let tzsc2 = bus
        .first_write_index(regs::GTZC1_TZSC_BASE + regs::TZSC_SECCFGR2_OFF)
        .expect("TZSC2");
    let tzsc3 = bus
        .first_write_index(regs::GTZC1_TZSC_BASE + regs::TZSC_SECCFGR3_OFF)
        .expect("TZSC3");
    let mpcbb = bus
        .first_write_index(regs::mpcbb_seccfgr(regs::MPCBB1_BASE, map::SRAM1_FIRST_NS_SUPERBLOCK))
        .expect("MPCBB");
    assert!(tzic > tzsc2);
    assert!(tzic > tzsc3);
    assert!(tzic > mpcbb);
}

#[test]
fn locks_emitted_last()
{
    // Hazard: locks before config verified -> frozen until reset.
    let bus = run();
    let tzsc1_lck = bus
        .first_write_index(regs::GTZC1_TZSC_BASE + regs::TZSC_CR_OFF)
        .expect("TZSC1 LCK");
    let tzsc2_lck = bus
        .first_write_index(regs::GTZC2_TZSC_BASE + regs::TZSC_CR_OFF)
        .expect("TZSC2 LCK");
    let mpcbb_lock = bus
        .first_write_index(regs::mpcbb_cfglockr1(regs::MPCBB1_BASE))
        .expect("MPCBB lock");
    let gpdma_lock = bus.first_write_index(regs::GPDMA_RCFGLOCKR).expect("GPDMA lock");

    // Every config write must precede every lock write. Use the SECCFGR/SECCFGR2
    // writes as the latest config touch points.
    let last_config = bus
        .writes()
        .iter()
        .enumerate()
        .filter(|(_, (a, _))| {
            *a == regs::GTZC1_TZSC_BASE + regs::TZSC_SECCFGR2_OFF
                || *a == regs::GTZC1_TZSC_BASE + regs::TZSC_SECCFGR3_OFF
                || *a == regs::GPDMA_SECCFGR
                || *a == regs::gpio_seccfgr(regs::GPIOA_BASE)
        })
        .map(|(i, _)| i)
        .max()
        .expect("a config write");

    assert!(last_config < tzsc1_lck, "config before TZSC1 lock");
    assert!(last_config < tzsc2_lck, "config before TZSC2 lock");
    assert!(last_config < mpcbb_lock, "config before MPCBB lock");
    assert!(last_config < gpdma_lock, "config before GPDMA lock");
}

#[test]
fn lock_internal_order_is_correct()
{
    // Required lock order: MPCBB CFGLOCKR -> MPCBB GLOCK -> TZSC LCK -> GPDMA.
    let bus = run();
    let cfglock = bus
        .first_write_index(regs::mpcbb_cfglockr1(regs::MPCBB1_BASE))
        .expect("CFGLOCKR");
    let glock = bus
        .first_write_index(regs::MPCBB1_BASE + regs::MPCBB_CR_OFF)
        .expect("GLOCK");
    let tzsc_lck = bus
        .first_write_index(regs::GTZC1_TZSC_BASE + regs::TZSC_CR_OFF)
        .expect("TZSC LCK");
    let gpdma_lock = bus.first_write_index(regs::GPDMA_RCFGLOCKR).expect("GPDMA");
    assert!(cfglock < glock, "CFGLOCKR before GLOCK");
    assert!(glock < tzsc_lck, "GLOCK before TZSC LCK");
    assert!(tzsc_lck < gpdma_lock, "TZSC LCK before GPDMA lock");
}

#[test]
fn tzsc_lock_bit_is_exact()
{
    let bus = run();
    let v = bus.last_value(regs::GTZC1_TZSC_BASE + regs::TZSC_CR_OFF).expect("TZSC1 CR");
    assert_eq!(v & regs::TZSC_CR_LCK, regs::TZSC_CR_LCK);
}

#[test]
fn no_irreversible_option_byte_addresses_touched()
{
    // Defence in depth: the partition must touch ONLY runtime-isolation registers.
    // No FLASH option-byte region (0x4002_2000 FLASH base / OPTR) is ever written.
    let bus = run();
    for (addr, _) in bus.writes()
    {
        // FLASH registers live around 0x4002_2000 / 0x5002_2000. No partition write does.
        let in_flash_optr = (*addr & 0x0FFF_FF00) == 0x0002_2000;
        assert!(!in_flash_optr, "must not touch FLASH option bytes at {:#010x}", addr);
    }
}

extern crate alloc;
