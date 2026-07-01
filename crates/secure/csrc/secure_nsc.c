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

/* SE bring-up forwarders. The Rust secure routines (src/se_smoke.rs) do all the
 * work: build the TROPIC01 over SPI1, run a no-session L2 probe, pack the result
 * into a uint32_t. Each veneer just forwards the return value.
 * Value-out only: no pointer, secret, or non-secure function pointer crosses. */
extern uint32_t patinakey_se_smoke(void);
extern uint32_t patinakey_se_riscv_fw_version(void);
extern uint32_t patinakey_se_spect_fw_version(void);

__attribute__((cmse_nonsecure_entry)) uint32_t patinakey_nsc_se_smoke(void)
{
    return patinakey_se_smoke();
}

__attribute__((cmse_nonsecure_entry)) uint32_t patinakey_nsc_se_riscv_fw_version(void)
{
    return patinakey_se_riscv_fw_version();
}

__attribute__((cmse_nonsecure_entry)) uint32_t patinakey_nsc_se_spect_fw_version(void)
{
    return patinakey_se_spect_fw_version();
}

/* One-shot SE firmware-update veneer. Feature-gated (build.rs defines
 * PATINAKEY_SE_FW_UPDATE only under the se-fw-update cargo feature), so the
 * default product build never emits it. The Rust secure body
 * (src/se_fw_update.rs) drives the whole update and packs the outcome (which
 * step, success or failure) into a uint32_t.
*/
#ifdef PATINAKEY_SE_FW_UPDATE
extern uint32_t patinakey_se_fw_update(void);

__attribute__((cmse_nonsecure_entry)) uint32_t patinakey_nsc_se_fw_update(void)
{
    return patinakey_se_fw_update();
}
#endif /* PATINAKEY_SE_FW_UPDATE */
