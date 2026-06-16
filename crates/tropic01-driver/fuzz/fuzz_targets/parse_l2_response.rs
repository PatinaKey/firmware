#![no_main]

// Fuzz the L2 response parser against arbitrary, attacker-controlled bytes.
// The contract under test: parse_response must NEVER panic on any input. It
// returns either a parsed frame or a typed error. libFuzzer feeds mutated
// byte slices. Any panic/abort is a finding.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]|
{
    tropic01_driver::fuzz::parse_l2_response(data);
});
