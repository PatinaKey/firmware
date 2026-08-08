/* Immutable boot-stage memory layout for cortex-m-rt's link.x.
 *
 * FLASH is pages 2-8 of a 256 KB bank at the low secure alias 0x0C00_4000,
 * LENGTH 56 KB (7 pages x 8 KB). This band is IMMUTABLE: it is OUTSIDE the A/B
 * image band (pages 9-31), so an update can neither program it (the updater MPU
 * regions start at page 9) nor erase it (WRP guards the erase, the only op the
 * MPU cannot see). Its vector base is SECBOOTADD0 = 0x0C00_4000, written once at
 * provisioning and selected on every reset. SWAP_BANK remaps which physical bank
 * sits at this low alias, so the boot stage runs from whichever bank booted.
 *
 * Pages 0-1 (boot metadata, 0x0C00_0000, 16 KB) sit BELOW this origin and are
 * pinned to physical Bank 1, so they are never linked into the boot stage.
 *
 * RAM is the lower 128 KB of SRAM1 at 0x2000_0000, the secure RAM half, matching
 * the secure app crate and the SAU region 2 / MPCBB1 split in platform map.rs.
 *
 * The boot-stage crate consumes this script (bank choice, commit/revert, image
 * health, anti-rollback) and is fully built. This layout is fixed so the address
 * map stays stable across the A/B work. RM0456 sec 7.5.8 (identical layout per
 * bank) and Table 26 (SECBOOTADD0).
 */
MEMORY
{
  FLASH (rx) : ORIGIN = 0x0C004000, LENGTH = 56K
  RAM (rwx)  : ORIGIN = 0x20000000, LENGTH = 128K
}
