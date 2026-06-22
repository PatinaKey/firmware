/* Secure-world (TZ-S) memory layout for cortex-m-rt's link.x.
 *
 * FLASH is secure Bank 1 at the secure alias 0x0C00_0000, the FULL 256 KB bank.
 * The TOP 8 KB (0x0C03_E000) is the Non-Secure-Callable veneer window: the build
 * pins the CMSE secure-gateway veneers (.gnu.sgstubs) to 0x0C03_E000 with a
 * linker --section-start (see build.rs), so they land at the fixed address the
 * SAU marks Non-Secure-Callable. Ordinary secure code/data uses the lower 248 KB.
 * The single FLASH region (not a separate carve-out) is deliberate: cortex-m-rt's
 * link.x assigns .gnu.sgstubs to FLASH, so a second region would leave that
 * section's region unbound. The --section-start instead pins the address inside
 * the one FLASH region. RM0456 memory map (Bank 1 secure alias).
 *
 * RAM is the lower 128 KB of SRAM1 at 0x2000_0000 (the provisional secure RAM
 * half), matching the SAU region 2 / MPCBB1 split declared in platform's map.rs.
 *
 * The standard cortex-m-rt FLASH/RAM region names are used so link.x composes
 * without edits.
 */
MEMORY
{
  FLASH (rx) : ORIGIN = 0x0C000000, LENGTH = 256K
  RAM (rwx)  : ORIGIN = 0x20000000, LENGTH = 128K
}
