//! Linker wiring for the non-secure firmware binary.
//!
//! For the embedded target only this build script:
//!   1. emits `memory.x` (the NS Bank 2 flash + NS SRAM1 upper half) onto the
//!      linker search path so cortex-m-rt's `link.x` includes it, and
//!   2. adds the CMSE import object emitted by the secure build to the NS link
//!      so the secure-gateway veneer symbol(s) resolve to their pinned NSC
//!      addresses. That resolution is the proof the S/NS bridge links.
//!
//! IMPORT-OBJECT PATH CONTRACT (shared with secure/build.rs):
//!   <target-root>/thumbv8m.main-none-eabihf/patinakey_nsc_implib.o
//! derived from OUT_DIR.
//!
//! BUILD ORDER (two-stage, by design): there is NO Cargo dependency edge between
//! the two bin crates. A bin crate has no lib target to depend on, and the import
//! object is a product of LINKING the secure bin, so no `links=`/artifact edge can
//! produce it on stable Rust. Cargo therefore does NOT order the two crates: the
//! secure crate MUST be built before the non-secure crate. The MCU build is a
//! two-stage build:
//!   cargo build -p secure    --target thumbv8m.main-none-eabihf
//!   cargo build -p nonsecure --target thumbv8m.main-none-eabihf
//! A plain whole-workspace build may race (NS link before the secure implib
//! exists, or against a stale implib). This script guards that: it FAILS LOUDLY
//! with an actionable message if the import object is missing, rather than passing
//! a nonexistent (or stale) path to the linker.
//!
//! On the host the bin is an empty stub: this script is a no-op there.

use std::env;
use std::error::Error;
use std::fs;
use std::path::Path;
use std::path::PathBuf;

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
// crates/secure/build.rs. Build scripts cannot share a module, so the two copies
// must be kept in sync by hand, this is not a stale fork.
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
    println!("cargo:rerun-if-changed=build.rs");

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "none"
    {
        return Ok(());
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR")?);

    // 1. Emit the NS memory script and add it to the search path.
    fs::write(out_dir.join("memory.x"), include_bytes!("memory.x"))?;
    println!("cargo:rustc-link-search={}", out_dir.display());

    // 2. Link against the secure crate's CMSE import object so the veneer symbol
    //    resolves. Passed as a direct positional input to rust-lld.
    let target_root = target_root_from_out_dir(&out_dir)
        .ok_or("could not derive target-root from OUT_DIR")?;
    let implib_path = target_root.join(TARGET_TRIPLE).join(IMPLIB_FILE);

    // Guard the two-stage build order. There is no Cargo edge that orders the
    // secure crate before this one, so the import object may be absent (or stale).
    // If it is missing, FAIL LOUDLY with an actionable message instead of handing
    // the linker a nonexistent path (an opaque link error) or silently relinking
    // against a stale object (a wrong-address veneer, a security defect).
    if !implib_path.exists()
    {
        return Err(format!(
            "patinakey NSC import object not found at {}; build the secure crate \
             first: cargo build -p secure --target {}",
            implib_path.display(),
            TARGET_TRIPLE
        )
        .into());
    }

    // Relink when the secure crate re-emits a changed import object (staleness
    // guard within the two-stage workflow).
    println!("cargo:rerun-if-changed={}", implib_path.display());
    println!("cargo:rustc-link-arg={}", implib_path.display());

    Ok(())
}
