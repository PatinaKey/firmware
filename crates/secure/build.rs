//! Linker + NSC-veneer build wiring for the secure firmware binary.
//!
//! For the embedded target only this build script does three things:
//!   1. emits `memory.x` (the secure FLASH / RAM layout) and `sgstubs.x` (roots
//!      the NSC entry symbols so --gc-sections keeps their veneers, and asserts
//!      the veneers stay inside the NSC window) onto the linker search path so
//!      cortex-m-rt's `link.x` composes with them, and pins `.gnu.sgstubs` to
//!      the NSC address with a `--section-start`.
//!   2. compiles the C `-mcmse` NSC veneer shim (`csrc/secure_nsc.c`) with clang
//!      into the crate's object set.
//!   3. drives rust-lld to emit the CMSE import library (the SG-veneer import
//!      object) at a STABLE, workspace-known path so the non-secure crate can
//!      link against it.
//!
//! IMPORT-OBJECT PATH CONTRACT (shared with nonsecure/build.rs):
//!   <target-root>/thumbv8m.main-none-eabihf/patinakey_nsc_implib.o
//! where <target-root> is the cargo target directory. Both build scripts derive
//! <target-root> from OUT_DIR (.../<target-root>/<triple>/<profile>/build/<pkg>/out),
//! so the path is deterministic without a hard-coded absolute prefix.
//!
//! BUILD ORDER (two-stage, by design): there is NO Cargo dependency edge between
//! the secure and non-secure bin crates, so cargo does NOT order them. The import
//! object is a product of LINKING this secure bin, so the secure crate MUST be
//! built before the non-secure crate. The MCU build is a two-stage build:
//!   cargo build -p secure    --target thumbv8m.main-none-eabihf
//!   cargo build -p nonsecure --target thumbv8m.main-none-eabihf
//! A plain whole-workspace build may race, nonsecure/build.rs fails loudly if this
//! import object is missing.
//!
//! On the host the secure bin is an empty stub: this script is a no-op there.

use std::env;
use std::error::Error;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;
use std::path::PathBuf;

use mcu_layout::NSC_VENEER_BASE;
use mcu_layout::NSC_VENEER_LEN;
use mcu_layout::NSC_VENEER_LIMIT;

/// The bare-metal triple the secure/non-secure images are built for.
const TARGET_TRIPLE: &str = "thumbv8m.main-none-eabihf";
/// The stable file name of the CMSE import object under the target triple dir.
const IMPLIB_FILE: &str = "patinakey_nsc_implib.o";

/// Derives the cargo target-root directory from `OUT_DIR`.
///
/// `OUT_DIR` is `<target-root>/<triple>/<profile>/build/<pkg-hash>/out`, so the
/// target-root is five parents up. Returns `None` if the layout is unexpected.
//
// INTENTIONAL DUPLICATION: this helper is copied verbatim in
// crates/nonsecure/build.rs. Build scripts cannot share a module, so the two
// copies must be kept in sync by hand. This is not a stale fork.
fn target_root_from_out_dir(out_dir: &Path) -> Option<PathBuf>
{
    out_dir
        .ancestors()
        .nth(5)
        .map(Path::to_path_buf)
}

/// Builds the linker assertions that bind the emitted veneers to the NSC window.
///
/// Returns a linker-script fragment appended to `sgstubs.x`. It states three
/// bounds the linker checks on every build, so a violation is a build error
/// instead of a silicon fault:
///   1. `.gnu.sgstubs` landed at the base the SAU marks Non-Secure-Callable, so
///      a toolchain that stopped honouring the `--section-start` is caught,
///   2. the veneers fit inside the window, so adding NSC entries past its
///      capacity fails the link instead of spilling into ordinary code,
///   3. memory.x ends the secure FLASH band exactly at the window top.
///
/// # Errors
///
/// `std::fmt::Error` if writing into the returned buffer fails.
fn nsc_window_assertions() -> Result<String, std::fmt::Error>
{
    let mut out = String::new();
    writeln!(
        out,
        "ASSERT(ADDR(.gnu.sgstubs) == {NSC_VENEER_BASE:#010X}, \
         \"CMSE veneers must land at the SAU Non-Secure-Callable window base\");"
    )?;
    writeln!(
        out,
        "ASSERT(SIZEOF(.gnu.sgstubs) <= {NSC_VENEER_LEN}, \
         \"CMSE veneers overflow the SAU Non-Secure-Callable window\");"
    )?;
    writeln!(
        out,
        "ASSERT(ORIGIN(FLASH) + LENGTH(FLASH) == {:#010X}, \
         \"secure FLASH band must end at the top of the NSC window\");",
        NSC_VENEER_LIMIT + 1
    )?;
    Ok(out)
}

fn main() -> Result<(), Box<dyn Error>>
{
    println!("cargo:rerun-if-changed=memory.x");
    println!("cargo:rerun-if-changed=sgstubs.x");
    println!("cargo:rerun-if-changed=csrc/secure_nsc.c");
    println!("cargo:rerun-if-changed=csrc/secure_nsc.h");
    println!("cargo:rerun-if-changed=build.rs");

    // Only wire the firmware build for the bare-metal target. The host build is
    // an empty stub and needs neither the linker scripts nor the C shim.
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "none"
    {
        return Ok(());
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR")?);

    // The fw-update veneer is feature-gated. When the feature is on, clang gets a
    // define to compile the extra `cmse_nonsecure_entry`, and the sgstubs fragment
    // gets an extra EXTERN to root its veneer. When off, neither exists, so the
    // product build is byte-unchanged and no undefined EXTERN can dangle.
    let fw_update = env::var_os("CARGO_FEATURE_SE_FW_UPDATE").is_some();
    // The L3 session veneer is feature-gated the same way: any
    // combination of se-fw-update and se-session is valid.
    let se_session = env::var_os("CARGO_FEATURE_SE_SESSION").is_some();

    // 1. Emit the linker scripts and add them to the search path. The sgstubs
    //    fragment gets the fw-update / session EXTERNs appended only under their
    //    features.
    fs::write(out_dir.join("memory.x"), include_bytes!("memory.x"))?;
    let mut sgstubs = Vec::from(*include_bytes!("sgstubs.x"));
    if fw_update
    {
        sgstubs.extend_from_slice(b"EXTERN(patinakey_nsc_se_fw_update);\n");
    }
    if se_session
    {
        sgstubs.extend_from_slice(b"EXTERN(patinakey_nsc_se_session_ping);\n");
        sgstubs.extend_from_slice(b"EXTERN(patinakey_nsc_se_persist);\n");
        sgstubs.extend_from_slice(b"EXTERN(patinakey_nsc_se_readonly);\n");
    }
    sgstubs.extend_from_slice(nsc_window_assertions()?.as_bytes());
    fs::write(out_dir.join("sgstubs.x"), sgstubs)?;
    println!("cargo:rustc-link-search={}", out_dir.display());
    // Append the sgstubs fragment after link.x so its EXTERN roots the veneers.
    println!("cargo:rustc-link-arg=-Tsgstubs.x");
    // Pin the synthesized CMSE veneers to the NSC window. cortex-m-rt's link.x
    // emits .gnu.sgstubs into FLASH without a fixed address. This forces it to
    // the SAU-marked NSC base so the address is stable and the NS world can call it.
    println!(
        "cargo:rustc-link-arg=--section-start=.gnu.sgstubs={NSC_VENEER_BASE:#010X}"
    );

    // 2. Compile the C -mcmse NSC veneer shim with clang. The cc crate is forced
    //    to clang and the proven CMSE flags. rust-lld links the resulting object
    //    into the secure image.
    let mut build = cc::Build::new();
    build
        .compiler("clang")
        .file("csrc/secure_nsc.c")
        .flag("--target=thumbv8m.main-none-eabihf")
        .flag("-mcpu=cortex-m33")
        .flag("-mfpu=fpv5-sp-d16")
        .flag("-mfloat-abi=hard")
        .flag("-mcmse")
        .flag("-ffreestanding")
        .include("csrc");
    if fw_update
    {
        // Gate the fw-update veneer in the C shim behind the same feature.
        build.define("PATINAKEY_SE_FW_UPDATE", None);
    }
    if se_session
    {
        // Gate the L3 session veneer in the C shim behind the same feature.
        build.define("PATINAKEY_SE_SESSION", None);
    }
    build.compile("patinakey_nsc");

    // 3. Drive rust-lld to emit the CMSE import library at the stable contract
    //    path. The import object exports the SG veneer at its pinned NSC address.
    //    The non-secure link resolves the veneer symbol against it.
    let target_root = target_root_from_out_dir(&out_dir)
        .ok_or("could not derive target-root from OUT_DIR")?;
    let implib_dir = target_root.join(TARGET_TRIPLE);
    fs::create_dir_all(&implib_dir)?;
    let implib_path = implib_dir.join(IMPLIB_FILE);

    println!("cargo:rustc-link-arg=--cmse-implib");
    println!(
        "cargo:rustc-link-arg=--out-implib={}",
        implib_path.display()
    );

    Ok(())
}
