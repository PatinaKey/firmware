#![no_main]

// Fuzz the signed firmware-image verifier against arbitrary, attacker-controlled
// bytes. The whole image is untrusted until the Ed25519 signature passes. The
// contract under test: verify_image must NEVER panic on any input. It returns
// either Ok (only for a genuinely valid image under the fixed pinned root key,
// which fuzzing will essentially never produce) or a typed error. The target
// exercises the bounded length/magic/version/algorithm parsing in front of the
// crypto. libFuzzer feeds mutated byte slices. Any panic/abort is a finding.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]|
{
    image_verify::fuzz::verify_image(data);
});
