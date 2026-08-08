/* Secure-world (TZ-S) memory layout for cortex-m-rt's link.x.
 *
 * FLASH is the secure app band, pages 10-19 of a 256 KB bank, at the low secure
 * alias 0x0C01_4000, LENGTH 80 KB (10 pages x 8 KB). Page 9 (0x0C01_2000) is the
 * A/B image DESCRIPTOR (the signed header and signature), NOT secure app: the
 * updater de-interleaves the signed file so the payload lands page-aligned here
 * at the link origin and the header magic never lands on the secure app vector
 * table. The immutable boot stage (pages 2-8), the boot metadata (pages 0-1), and
 * the descriptor (page 9) all sit BELOW this origin and are never linked into the
 * secure app. The active bank always presents this band at the low alias, the
 * inactive bank presents it at the high alias 0x0C05_4000, so SAU, SECWM and the
 * MPU never change on a bank swap.
 *
 * The Non-Secure-Callable veneer window is page 19 at 0x0C02_6000 (the top page
 * of this band). The build pins the CMSE secure-gateway veneers (.gnu.sgstubs)
 * there with a linker --section-start (see build.rs), so they land at the fixed
 * address the SAU marks Non-Secure-Callable. Ordinary secure code/data uses
 * pages 10-18 (72 KB) below the veneer. The single FLASH region (not a separate
 * carve-out) is deliberate: cortex-m-rt's link.x assigns .gnu.sgstubs to FLASH,
 * so a second region would leave that section's region unbound. The
 * --section-start instead pins the address inside the one FLASH region. RM0456
 * memory map (Bank secure alias, sec 7.5.8 identical-per-bank layout).
 *
 * RAM is the lower 128 KB of SRAM1 at 0x2000_0000 (the secure RAM half),
 * matching the SAU region 2 / MPCBB1 split declared in platform's map.rs.
 *
 * The standard cortex-m-rt FLASH/RAM region names are used so link.x composes
 * without edits.
 */
MEMORY
{
  FLASH (rx) : ORIGIN = 0x0C014000, LENGTH = 80K
  RAM (rwx)  : ORIGIN = 0x20000000, LENGTH = 128K
}
