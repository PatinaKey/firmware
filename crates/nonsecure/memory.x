/* PROVISIONAL non-secure (TZ-NS) memory layout for cortex-m-rt's link.x.
 *
 * SKELETON to make the NS firmware link for thumbv8m.main-none-eabihf in this
 * increment. The real NS layout (Bank 2 NS alias at 0x0804_0000, the NS SRAM1
 * upper half) lands with the NSC-shim increment. Do NOT treat these as final.
 *
 * Uses the NS flash bank base (0x0804_0000, 256K) and the provisional NS upper
 * half of SRAM1 (64K at 0x2002_0000), matching the partition map's split.
 */
MEMORY
{
  FLASH (rx)  : ORIGIN = 0x08040000, LENGTH = 256K
  RAM (rwx)   : ORIGIN = 0x20020000, LENGTH = 64K
}
