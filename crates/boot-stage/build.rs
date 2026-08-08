//! Linker wiring for the immutable boot-stage binary.
//!
//! For the embedded target only, emit `memory.x` (the boot-stage FLASH / RAM
//! layout, pages 2-8 at 0x0C004000) onto the linker search path so cortex-m-rt's
//! `link.x` composes with it. On the host the bin is an empty stub, so this is a
//! no-op there.

use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

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
    fs::write(out_dir.join("memory.x"), include_bytes!("memory.x"))?;
    println!("cargo:rustc-link-search={}", out_dir.display());
    // Disable section page-alignment so the linker emits no header-carrying
    // segment below FLASH ORIGIN. Without it rust-lld aligns the first segment
    // down to the 64 KB page (0x0C000000), placing a phantom ELF-header LOAD in
    // the metadata band (pages 0-1). --nmagic keeps every loadable byte inside the
    // boot-stage band [0x0C004000, 0x0C012000).
    println!("cargo:rustc-link-arg=--nmagic");
    Ok(())
}
