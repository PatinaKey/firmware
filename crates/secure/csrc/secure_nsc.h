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

#endif /* PATINAKEY_SECURE_NSC_H */
