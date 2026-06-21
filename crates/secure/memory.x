/* PROVISIONAL secure-world memory layout for cortex-m-rt's link.x.
 *
 * This is a SKELETON to make the firmware link for thumbv8m.main-none-eabihf in
 * this increment. The real secure / non-secure flash + SRAM split (the secure
 * alias at 0x0C00_0000, the NSC veneer window, the NS bank, the SRAM1 split)
 * lands with the NSC-shim increment alongside the linker scripts derived from the
 * partition map. Do NOT treat these regions as the final security boundary.
 *
 * For now: a single secure flash + secure SRAM region large enough to link the
 * skeleton, using the secure alias base of Bank 1 (0x0C00_0000) and SRAM1.
 */
MEMORY
{
  FLASH (rx)  : ORIGIN = 0x0C000000, LENGTH = 248K
  RAM (rwx)   : ORIGIN = 0x20000000, LENGTH = 128K
}
