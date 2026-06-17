#![no_main]

// Fuzz the firmware-image blob decoder against arbitrary, attacker-controlled
// bytes. The signed-image update blob is the untrusted payload handed to the
// driver. The contract under test: FwImageChunks::new, a full drain of the
// iterator, then image_version on the same blob must NEVER panic on any input.
// The iterator returns either the next chunk or a typed error and FUSES on
// truncation. image_version reads the chunk-0 version u32 at a const offset via
// the bounded combinators. libFuzzer feeds mutated byte slices. Any panic/abort
// is a finding.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]|
{
    tropic01_driver::fuzz::fw_image_chunks(data);
});
