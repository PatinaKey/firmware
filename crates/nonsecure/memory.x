/* Non-secure (TZ-NS) memory layout for cortex-m-rt's link.x.
 *
 * FLASH is the NS flash bank (Bank 2 NS alias) at 0x0804_0000, 256 KB. RAM is
 * the upper 64 KB of SRAM1 at 0x2002_0000, the provisional NS half matching the
 * partition map's SRAM1 split (SAU region 1 + region 2 in platform's map.rs).
 * The secure world hands off here by pointing SCB_NS->VTOR at this FLASH base.
 * RM0456 memory map.
 */
MEMORY
{
  FLASH (rx)  : ORIGIN = 0x08040000, LENGTH = 256K
  RAM (rwx)   : ORIGIN = 0x20020000, LENGTH = 64K
}
