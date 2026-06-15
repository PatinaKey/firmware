#![no_main]

// Fuzz the certificate-chain signature verifier against arbitrary,
// attacker-controlled bytes. The DER cert store comes from the chip and is
// untrusted. The contract under test: verify_cert_chain must NEVER panic on any
// input. It returns either Ok(()) (only for a genuinely valid chain under the
// fixed pinned anchor, which fuzzing will essentially never produce) or a typed
// error. The target exercises the bounded DER parsing in front of the crypto.
// libFuzzer feeds mutated byte slices. Any panic/abort is a finding.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]|
{
    se_driver::fuzz::verify_cert_chain(data);
});
