#![no_main]

// Fuzz the segmented signed firmware-image verifier against arbitrary,
// attacker-controlled bytes. The whole image is untrusted until the ECDSA P-256
// signature passes. The contract under test: verify_image must never panic on any
// input.
//
// Any panic or abort is a finding.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]|
{
    image_verify::fuzz::verify_image(data);
});
