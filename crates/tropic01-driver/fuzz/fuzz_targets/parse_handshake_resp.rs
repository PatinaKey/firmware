#![no_main]

// Fuzz the Handshake_Resp body parser (the ETPUB(32) || T_TAUTH(16) split)
// against arbitrary, attacker-controlled bytes. The contract under test:
// parse_handshake_resp must NEVER panic on any input. It returns the split
// pair for an exactly-48-byte body and a typed error otherwise.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]|
{
    tropic01_driver::fuzz::parse_handshake_resp(data);
});
