/* Non-Secure-Callable (NSC) boundary: the secure-gateway veneer shim.
 *
 * This is the ONLY entry surface the non-secure world has into the secure world.
 * It is compiled with clang -mcmse, so each cmse_nonsecure_entry function emits
 * a secure-gateway (SG) veneer placed in the .gnu.sgstubs section, which the
 * linker pins to the SAU Non-Secure-Callable window.
 *
 * SAFETY / boundary contract:
 *   - Every entry takes a scalar uint32_t only. 
 *     No buffer, handle, secret, or non-secure pointer crosses on ANY entry, so
 *     there is NO caller memory to validate and NO callback path back into NS.
 *     The feature-gated read-only sweep veneer returns an SE data record too big
 *     for a u32, but it writes that record to a fixed compile-time non-secure
 *     address (the pinned shared output window, see src/se_readonly.rs).
 *   - The bodies hold zero logic and touch no secure state beyond forwarding.
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

/* L3 secure-channel bring-up veneer. Feature-gated (build.rs defines
 * PATINAKEY_SE_SESSION only under the se-session cargo feature), so the default
 * product build never emits it. The Rust secure body (src/se_session.rs) reads
 * STPUB, opens a Noise KK1 session against slot 0, runs one L3 Ping with an echo
 * compare, aborts, and packs the outcome (which step, success or failure) into a
 * uint32_t.
*/
#ifdef PATINAKEY_SE_SESSION
extern uint32_t patinakey_se_session_ping(void);

__attribute__((cmse_nonsecure_entry)) uint32_t patinakey_nsc_se_session_ping(void)
{
    return patinakey_se_session_ping();
}

/* Persistent-but-reversible state bring-up veneer.
 * The Rust secure body (src/se_persist.rs) opens a session, exercises the
 * monotonic counters, MAC-and-Destroy, and ECC_Key_Store, aborts, 
 * and packs the outcome (which step, success or failure) into a uint32_t.
*/
extern uint32_t patinakey_se_persist(void);

__attribute__((cmse_nonsecure_entry)) uint32_t patinakey_nsc_se_persist(void)
{
    return patinakey_se_persist();
}

/* Read-only sweep plus P-256 export veneer.
 * The exported record is too big for a uint32_t, so the Rust secure body
 * (src/se_readonly.rs) writes it to a FIXED compile-time non-secure address (the
 * pinned shared output window).
 * The record holds only public bytes (pairing / ECC public keys, an ECDSA signature, 
 * the digest, chip id, config dumps).
*/
extern uint32_t patinakey_se_readonly(void);

__attribute__((cmse_nonsecure_entry)) uint32_t patinakey_nsc_se_readonly(void)
{
    return patinakey_se_readonly();
}
#endif /* PATINAKEY_SE_SESSION */
