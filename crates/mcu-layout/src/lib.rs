//! The Non-Secure-Callable veneer window.
//!
//! Source anchors: RM0456 (memory map, sec 7.5.8 identical-per-bank layout) and
//! the Armv8-M Architecture Reference Manual (SAU region encoding, AN5347 for
//! the secure-gateway model).

#![cfg_attr(not(test), no_std)]

// Non-Secure-Callable veneer window.
//
// The CMSE secure-gateway veneers (`.gnu.sgstubs`) sit at the TOP of the secure
// app band, pages 10-19 at 0x0C01_4000..0x0C02_7FFF. Two consumers read the
// window from here:
//   - crates/secure/build.rs, as the linker `--section-start=.gnu.sgstubs=`
//     address plus the generated bound assertions,
//   - crates/platform/src/map.rs, as SAU region 0 (the only NSC region).

/// Length of the Non-Secure-Callable veneer window, in bytes.
///
/// 512 bytes holds 64 secure gateways of 8 bytes each.
pub const NSC_VENEER_LEN: u32 = 512;

/// First byte after the secure app band: the top of page 19 plus one.
/// RM0456 memory map.
const SECURE_APP_BAND_END: u32 = 0x0C02_8000;

/// Base of the Non-Secure-Callable veneer window.
///
/// 32-byte aligned, as the SAU `RBAR` encoding fixes the low 5 bits to zero.
pub const NSC_VENEER_BASE: u32 = SECURE_APP_BAND_END - NSC_VENEER_LEN;

/// Inclusive top byte of the Non-Secure-Callable veneer window.
///
/// The SAU `RLAR` encoding reads the low 5 bits as one, so a limit is always the
/// inclusive top of a 32-byte unit.
pub const NSC_VENEER_LIMIT: u32 = SECURE_APP_BAND_END - 1;

#[cfg(test)]
mod tests
{
    use super::*;

    /// One Armv8-M secure gateway, in bytes: the SG instruction plus the branch.
    const GATEWAY_BYTES: u32 = 8;
    /// `cmse_nonsecure_entry` functions the C shim declares in total: 4
    /// unconditional, 3 under se-session, 1 under se-fw-update. The largest
    /// buildable configuration emits 7 of them. The bound uses the declared
    /// total.
    const WORST_CASE_GATEWAYS: u32 = 8;

    #[test]
    fn nsc_window_is_pinned()
    {
        // The pinned values, in one place. Every other site derives them.
        assert_eq!(NSC_VENEER_BASE, 0x0C02_7E00);
        assert_eq!(NSC_VENEER_LIMIT, 0x0C02_7FFF);
        assert_eq!(NSC_VENEER_LEN, 512);
    }

    #[test]
    fn nsc_window_matches_the_sau_granule()
    {
        // SAU RBAR fixes the low 5 bits of a base to zero, RLAR reads the low 5
        // bits of a limit as one.
        assert_eq!(NSC_VENEER_BASE & 0x1F, 0);
        assert_eq!(NSC_VENEER_LIMIT & 0x1F, 0x1F);
        assert_eq!(NSC_VENEER_LIMIT - NSC_VENEER_BASE + 1, NSC_VENEER_LEN);
    }

    #[test]
    fn nsc_window_holds_the_worst_case_gateway_count()
    {
        // The linker also asserts this on the real section size at every build.
        // This is the source-level bound.
        let worst_case = WORST_CASE_GATEWAYS * GATEWAY_BYTES;
        assert!
        (
            NSC_VENEER_LEN >= worst_case,
            "the NSC window must hold every gateway the build can emit"
        );
    }
}
