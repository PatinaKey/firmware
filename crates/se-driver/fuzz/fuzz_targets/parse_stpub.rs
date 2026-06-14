#![no_main]

// Fuzz the certificate-store STPUB parser against arbitrary, attacker-controlled
// bytes. The DER cert store comes from the chip and is untrusted. The contract
// under test: parse_stpub must NEVER panic on any input. It returns either the
// 32-byte STPUB or a typed error. libFuzzer feeds mutated byte slices. Any
// panic/abort is a finding.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]|
{
    se_driver::fuzz::parse_stpub(data);
});
