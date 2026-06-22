//! Linker + NSC-veneer build wiring for the secure firmware binary.
//!
//! For the embedded target only this build script does three things:
//!   1. emits `memory.x` (the secure FLASH / RAM layout) and `sgstubs.x` (roots
//!      the NSC entry symbols so --gc-sections keeps their veneers) onto the
//!      linker search path so cortex-m-rt's `link.x` composes with them, and
//!      pins `.gnu.sgstubs` to the NSC address with a `--section-start`.
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
use std::fs;
use std::path::Path;
use std::path::PathBuf;

/// The bare-metal triple the secure/non-secure images are built for.
const TARGET_TRIPLE: &str = "thumbv8m.main-none-eabihf";
/// The stable file name of the CMSE import object under the target triple dir.
const IMPLIB_FILE: &str = "patinakey_nsc_implib.o";
/// The pinned NSC veneer window base: top 8 KB of secure Bank 1. The CMSE
/// secure-gateway veneers (.gnu.sgstubs) are forced here so the SAU-marked NSC
/// address is stable across builds. RM0456 memory map matches platform map.rs.
const NSC_VENEER_BASE: &str = "0x0C03E000";

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

    // 1. Emit the linker scripts and add them to the search path.
    fs::write(out_dir.join("memory.x"), include_bytes!("memory.x"))?;
    fs::write(out_dir.join("sgstubs.x"), include_bytes!("sgstubs.x"))?;
    println!("cargo:rustc-link-search={}", out_dir.display());
    // Append the sgstubs fragment after link.x so its EXTERN roots the veneers.
    println!("cargo:rustc-link-arg=-Tsgstubs.x");
    // Pin the synthesized CMSE veneers to the NSC window. cortex-m-rt's link.x
    // emits .gnu.sgstubs into FLASH without a fixed address. This forces it to
    // the SAU-marked NSC base so the address is stable and the NS world can call it.
    println!(
        "cargo:rustc-link-arg=--section-start=.gnu.sgstubs={}",
        NSC_VENEER_BASE
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
