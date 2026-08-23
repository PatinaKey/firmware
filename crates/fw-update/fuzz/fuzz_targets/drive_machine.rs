#![no_main]

// Fuzz the full receive -> verify -> commit state machine with attacker-
// controlled chunk offsets and lengths against the host mock seam. This covers
// the ordering surface this crate adds: an attacker streams chunks, then drives
// verify, commit, boot, and confirm. The contract under test: the machine must
// never panic, must reject any malformed or incomplete image, and must never
// reach the Committed state for an image the verifier did not accept. libFuzzer
// feeds mutated byte slices. Any panic/abort is a finding.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]|
{
    let _ = fw_update::fuzz::drive_machine(data);
});
