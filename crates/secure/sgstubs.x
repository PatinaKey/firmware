/* Keep the secure-gateway veneer(s) alive under --gc-sections.
 *
 * The secure binary never CALLS its NSC entries (only the non-secure world does),
 * so --gc-sections would drop the entry function bodies, leaving each cmse
 * __acle_se_ alias dangling and failing the CMSE link ("not a Thumb function
 * definition"). EXTERN roots each NSC entry symbol so its veneer survives gc.
 *
 * Placement of .gnu.sgstubs at the pinned NSC address is handled by a linker
 * --section-start in build.rs (cortex-m-rt's link.x already emits the
 * .gnu.sgstubs output section. A competing section definition would leave lld's
 * synthesized veneers without an assigned address).
 *
 * Add one EXTERN line per NSC entry exported by csrc/secure_nsc.c.
 * Armv8-M secure gateway / .gnu.sgstubs convention. cortex-m-rt link.x.
 */
EXTERN(patinakey_nsc_version);
