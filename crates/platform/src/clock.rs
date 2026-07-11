//! The core-clock frequency: the single source of truth for HCLK.

/// The AHB / core clock (HCLK) frequency in hertz.
///
/// The MCU boots on MSIS at its reset default and the firmware never programs
/// RCC (confirmed against RM0456 sec 11). This constant is the ONE
/// place the core clock is stated. Every consumer that converts a duration to a
/// cycle count (the SysTick delay) reads HCLK from here. 
///
/// RM0456 sec 11: the MSIS reset frequency is 4 MHz.
pub const HCLK_HZ: u32 = 4_000_000;
