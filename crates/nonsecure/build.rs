//! Linker setup for the non-secure firmware binary.
//!
//! Emits the PROVISIONAL `memory.x` for cortex-m-rt's `link.x`, embedded-target
//! only. Standard cortex-m-rt wiring, not the C `-mcmse` NSC veneer shim (which
//! needs a C toolchain + linker wiring, deferred). On the host the bin is an empty
//! stub and needs no linker script.

use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn Error>>
{
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "none"
    {
        return Ok(());
    }

    let out = PathBuf::from(env::var("OUT_DIR")?);
    let memory_x = include_bytes!("memory.x");
    fs::write(out.join("memory.x"), memory_x)?;
    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rerun-if-changed=memory.x");
    println!("cargo:rerun-if-changed=build.rs");
    Ok(())
}
