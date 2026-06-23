/* Non-Secure-Callable (NSC) boundary: public veneer declarations.
 *
 * This header declares the secure-gateway entry points the non-secure world may
 * call. Each entry is value-in / value-out only: no pointer, handle, secret, or
 * non-secure function pointer crosses the boundary, so there is no caller-memory
 * to validate and no callback surface. Armv8-M secure gateway model, AN5347.
 */

#ifndef PATINAKEY_SECURE_NSC_H
#define PATINAKEY_SECURE_NSC_H

#include <stdint.h>

/* Returns the pinned NSC interface version. Value-out only. Cannot fault. */
uint32_t patinakey_nsc_version(void);

/* SE bring-up veneers. Each forwards to a Rust secure routine that talks to the
 * TROPIC01 over SPI1 and packs the result into a uint32_t. Value-out only. */

/* Probes CHIP_STATUS and returns a packed smoke word (mode plus an ok/err flag).
 * Bit 31 set means error (low byte = error code). Bit 8 set means ok (low byte =
 * mode). Fails closed, never faults. */
uint32_t patinakey_nsc_se_smoke(void);

/* Returns the 4-byte RISC-V (application) firmware version packed big-endian, or
 * the 0xEEEE_EExx error sentinel on a fault. */
uint32_t patinakey_nsc_se_riscv_fw_version(void);

/* Returns the 4-byte SPECT firmware version packed big-endian, or the
 * 0xEEEE_EExx error sentinel on a fault. */
uint32_t patinakey_nsc_se_spect_fw_version(void);

#endif /* PATINAKEY_SECURE_NSC_H */
