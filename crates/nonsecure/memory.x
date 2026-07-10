/* Non-secure (TZ-NS) memory layout for cortex-m-rt's link.x.
 *
 * FLASH is the NS flash bank (Bank 2 NS alias) at 0x0804_0000, 256 KB. RAM is
 * the upper 64 KB of SRAM1 at 0x2002_0000, the provisional NS half matching the
 * partition map's SRAM1 split (SAU region 1 + region 2 in platform's map.rs).
 * The secure world hands off here by pointing SCB_NS->VTOR at this FLASH base.
 * RM0456 memory map.
 *
 * SHARED_OUT is the pinned non-secure shared OUTPUT window: the top 1 KiB of the
 * NS half, carved out of RAM so no stack, static, or embassy allocation can land
 * in it. A secure veneer that returns more than a u32 (an SE data record) writes
 * here at a COMPILE-TIME address, and the secure MPU maps exactly this range
 * RW + XN (platform map.rs 4th region). The main RAM region is shrunk to 63 KB
 * so RAM and SHARED_OUT never overlap.
 *
 * HAND-SYNCED PIN : 
 * the SHARED_OUT ORIGIN/LENGTH here MUST match MPU_NS_SHARED_BASE / MPU_NS_SHARED_LIMIT
 * in crates/platform/src/map.rs AND SHARED_OUT_ADDR / SHARED_OUT_LEN in
 * crates/secure/src/se_readonly.rs. Base 0x2002_FC00, length 0x400.
 */
MEMORY
{
  FLASH (rx)       : ORIGIN = 0x08040000, LENGTH = 256K
  RAM (rwx)        : ORIGIN = 0x20020000, LENGTH = 63K
  SHARED_OUT (rw)  : ORIGIN = 0x2002FC00, LENGTH = 1K
}

/* The shared output window is NOLOAD: the secure world writes it at runtime, so
 * startup must neither load nor zero it. INSERT AFTER .uninit (not .bss) is
 * deliberate: cortex-m-rt sets __ebss AFTER .bss so that INSERT AFTER .bss
 * sections are pulled into the .bss zeroing range. This section lives in a
 * SEPARATE high region, so being zeroed would balloon the zero-range across the
 * whole RAM and clobber the live stack at boot. Inserting after .uninit places it
 * past __ebss, so it is never zeroed, and past __euninit / _stack_end, so it does
 * not perturb the heap or stack bounds. */
SECTIONS
{
  .shared_out (NOLOAD) :
  {
    . = ALIGN(32);
    *(.shared_out .shared_out.*);
    . = ALIGN(32);
  } > SHARED_OUT
} INSERT AFTER .uninit;
