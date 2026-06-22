/* Non-Secure-Callable (NSC) boundary: the secure-gateway veneer shim.
 *
 * This is the ONLY entry surface the non-secure world has into the secure world.
 * It is compiled with clang -mcmse, so each cmse_nonsecure_entry function emits
 * a secure-gateway (SG) veneer placed in the .gnu.sgstubs section, which the
 * linker pins to the SAU Non-Secure-Callable window.
 *
 * SAFETY / boundary contract:
 *   - Every entry is value-in / value-out (scalar uint32_t only). No pointer,
 *     buffer, handle, secret, or non-secure function pointer crosses the
 *     boundary, so there is NO caller-supplied memory to validate (no
 *     cmse_check_address_range needed) and NO callback path back into NS.
 *   - The body holds zero logic and touches no secure state. It cannot fault on
 *     untrusted input because it takes none.
 * Armv8-M secure gateway model, AN5347.
 */

#include <arm_cmse.h>
#include <stdint.h>

#include "secure_nsc.h"

/* Pinned NSC interface version (major.minor in the high/low halfwords). Bumped
 * only when the veneer ABI changes, so the non-secure world can check it. */
enum patinakey_nsc_constant
{
    patinakey_nsc_version_value = 0x00010000
};

__attribute__((cmse_nonsecure_entry)) uint32_t patinakey_nsc_version(void)
{
    return (uint32_t)patinakey_nsc_version_value;
}
