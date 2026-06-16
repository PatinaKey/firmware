#![no_main]

// Fuzz the L3 result opener against arbitrary, attacker-controlled bytes.
// The contract under test: SessionKeys::open_result must NEVER panic on any
// wire input. The declared RES_SIZE, the tag split, and every slice bound are
// attacker-influenced. Any panic/abort is a finding. Almost every input fails
// the AES-GCM tag check, which exercises the bounds logic in front of it.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]|
{
    tropic01_driver::fuzz::decrypt_l3_result(data);
});
