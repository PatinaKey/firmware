# tropic01-driver - TROPIC01 secure-element driver (no_std)

A `no_std`, heap-free, `unsafe-free` Rust driver for the **TROPIC01** secure
element (Tropic Square, part `TR01-C2P-T301`), spoken over SPI through an
authenticated, encrypted **Noise KK1** session.

It is the secure-element layer of the
[PatinaKey](https://github.com/PatinaKey/firmware) hardware security key, written
as a clean-room rewrite with the official C SDK
[`libtropic`](https://github.com/tropicsquare/libtropic) used as a differential
**test oracle** (never linked : no C, no mbedTLS in the trusted computing base).

> **Status: under active development.** The secure channel and the cryptographic
> hot-path commands work. They are tested host-side three ways: an in-repo chip
> mock (incl. fault injection), a libtropic-derived handshake KAT, and a **live
> end-to-end suite against the official `tropic01_model` emulator** (real
> handshake + real AES-GCM, see [Validation](#validation-against-real-libtropic)).
> Most of the chip's command surface is wired, including X.509 chain verification up to the pinned Tropic root. What remains is the firmware-update bootloader API and power/mode control (see [Roadmap](#roadmap)). It has not yet run on real silicon. Not production-grade yet.

## What it does

The TROPIC01 stores long-term private keys that never leave the chip and performs
the sensitive crypto (signing, key generation, TRNG, PIN anti-bruteforce). This
crate is the host's mouth and ears for that chip:

- **Noise KK1 handshake** - authenticated X25519 key agreement with the chip.
- **AES-256-GCM L3 codec** - every command and response is encrypted and
  authenticated, with advance-after-verify nonces that cannot desync.
- **Fail-closed command gate** - a crypto, structural, or parse fault on any
  command tears the session down and zeroizes the keys. A benign, authenticated
  non-OK status keeps the session live, mirroring libtropic.
- **Range-checked index types** - an out-of-range key / counter / memory / PIN /
  pairing slot or I-Config bit index cannot even be constructed, and a config
  object address is a closed enum, so only valid registers reach the wire.

All key material (host pairing keys, chip static public key, per-session ephemeral,
pairing-slot index) is **caller-provided** via `SessionConfig`. The driver hardcodes no secrets.

## Implemented

| Area | What works |
|------|------------|
| Transport | L1 SPI, L2 framing + multi-chunk reassembly |
| Secure channel | Noise KK1 handshake, `open_session` / `close_session`, session teardown gate |
| Mode control | `reboot` (Startup_Req 0xB3: Start-up / Maintenance / Application FW) |
| Chip info (L2) | `Get_Info`: `x509_certificate_into` (raw cert store), `chip_id_into`, `riscv_fw_version`, `spect_fw_version`, `fw_bank_into` - read before a session, no secure channel |
| Attestation (parse) | `parse_stpub` / `read_chip_stpub`: extract the chip static X25519 key (STPUB) from the X.509 cert store via a depth-bounded, panic-free DER walk |
| Attestation (verify) | `verify_cert_chain` / `parse_verified_stpub` / `read_verified_chip_stpub`: verify the cert chain DEVICE -> XXXX CA -> product CA up to a caller-pinned Tropic root (ECDSA P-384/SHA-384 then P-521/SHA-512, mixed-algorithm dispatched per cert). The root is pinned out-of-band, never trusted from the store. Cryptographic path only - dates / revocation are left to the integrator |
| Diagnostics | `ping` round-trip |
| TRNG | `random_into` (RandomValueGet, 0x50) |
| ECC keys | `ecc_key_generate` (0x60), `ecc_public_key` (0x62, returns the chip-attested curve), `ecc_key_store` (0x61, import a private key), `ecc_key_erase` (0x63) |
| Signing | `ecdsa_sign` (0x70, P-256), `eddsa_sign` (0x71, Ed25519) |
| User memory | `rmem_read_into` (0x41), `rmem_write` (0x40), `rmem_erase` (0x42) |
| Counters | `mcounter_get` (0x82), `mcounter_init` (0x80), `mcounter_update` (0x81) |
| PIN primitive | `mac_and_destroy` (0x90), output wrapped in a zeroize-on-drop secret type |
| Pairing keys | `pairing_key_write` (0x10), `pairing_key_read` (0x11), `pairing_key_invalidate` (0x12) - provision the chip's 4 host-pairing slots |
| Config objects | `r_config_write` (0x20), `r_config_read` (0x21), `r_config_erase` (0x22, whole R-Config), `i_config_write` (0x30, irreversible OTP bit-burn), `i_config_read` (0x31) - per-command access privileges (CFG_UAP) and chip behaviour |

These twenty-two commands are exposed through the public `SeCommands` trait, the only
surface the FIDO2 / OpenPGP / PKCS#11 layers consume.

## Validation against real libtropic

The driver is exercised end-to-end against the official **TROPIC01 model**
(Tropic Square `ts-tvl`) over a TCP shim, running its real Noise KK1 handshake and
real AES-GCM L3 codec against an independent implementation of the chip. No keys
are pinned and nothing is mocked: a wrong protocol or crypto byte breaks the
handshake or a GCM tag. The table below tracks what each operation is validated
against the model for (`scripts/model-itest.sh`, behind the `model-itest`
feature). Injected faults (corrupt tag/CRC/alarm/truncation) stay in the in-repo
mock - the model does not misbehave on command. Model = conformance, mock = fault
robustness.

| Operation | Validated against the model |
|-----------|:---:|
| `reboot` (Startup_Req) | Yes - byte-exact frame KAT + live Start-up -> Application FW |
| `open_session` (handshake) | Yes - real Noise KK1, every live test depends on it |
| `ping` | Yes - small + a 600-byte payload (live 3-chunk L2 SEND) |
| `random_into` | Yes - fills the requested buffer |
| `rmem_write` / `rmem_read_into` / `rmem_erase` | Yes - round-trips data. Re-write surfaces `SlotNotEmpty` (recoverable). Erase clears a slot for a fresh write |
| `mcounter_get` / `mcounter_init` / `mcounter_update` | Yes - init/update/get decrements by one. Uninitialized counter and an underflow past zero are both recoverable |
| `ecc_key_generate` / `ecc_public_key` | Yes - P-256 (64 B) and Ed25519 (32 B). Empty slot surfaces `InvalidKey` (recoverable) |
| `ecc_key_store` / `ecc_key_erase` | Yes - import a key (distinct seeds give distinct pubkeys), sign with an imported key, erase clears a slot. Import into an occupied slot surfaces `SlotNotEmpty` (recoverable) |
| `ecdsa_sign` / `eddsa_sign` | Yes - returns a 64-byte signature |
| `mac_and_destroy` | Yes - returns the 32-byte secret output |
| `pairing_key_write` / `pairing_key_read` / `pairing_key_invalidate` | Yes - slot 0 reads back the prod0 host pairing pubkey (byte-exact). Write-read-invalidate round-trip on a spare slot. Reading an unprovisioned slot is recoverable |
| `Get_Info`: cert store / chip id / fw versions | Yes - reads the full 3840-byte cert store, the 128-byte CHIP_ID, and the 4-byte RISCV/SPECT versions. FW_BANK is rejected outside Maintenance Mode (the full read is not yet wired) |
| `parse_stpub` / `read_chip_stpub` (STPUB) | Yes - extracts STPUB from the live model's real device certificate and asserts it byte-exact against the model's pinned `s_t_pub`. A golden-constant proof that the DER walk is byte-faithful to an independent implementation |
| `verify_cert_chain` / `read_verified_chip_stpub` | Yes - reads the live store and verifies the full chain up to the pinned model TEST root, end-to-end through the RustCrypto P-384 / P-521 ECDSA stack. A deliberately wrong anchor is rejected. The same chain independently verifies under openssl |
| `r_config_write` / `r_config_read` / `r_config_erase` | Yes - write a CO value to a safe register, read it back byte-exact, erase the whole R-Config and read back all-ones. I-Config read live. The irreversible I-Config write is mock-only (a real burn is one-way) |

The L2 multi-chunk SEND path additionally has a **byte-exact golden KAT**: real
libtropic frames captured from the model are asserted byte-for-byte against the
driver's chunker (frame length encoding + the 252-byte chunk constant + CRC).
This runs in the normal hermetic test suite.

## Roadmap

The table below tracks the TROPIC01 command surface still to wire to reach a
complete, reusable driver. "Needed by PatinaKey" marks what the product itself
requires (almost everything). The rest matters for a general-purpose driver.

| Block | Commands | What it is for | Needed by PatinaKey |
|-------|----------|----------------|:---:|
| Firmware update | bootloader 0xB0 / 0xB1 | Update the chip's application / SPECT firmware | Yes (planned) |
| Power / mode | sleep, get-mode (`reboot` done) | Low-power, bootloader vs application mode | Later |

Non-command work toward a publishable crate: validate against silicon (the
`tropic01_model` emulator is already wired, see
[Validation](#validation-against-real-libtropic)), crate-level docs / examples on
docs.rs, and an optional `embedded-hal`-based port so external users can plug
their own HAL (currently the ports are the crate's own `SpiDevice` / `SeWait` traits).

## Design principles

- **No heap** - all buffers are statically allocated. The ~4 KiB device handle is a
  static singleton, never on the stack.
- **No unsafe** - the workspace sets `#![forbid(unsafe_code)]`.
- **Zeroize on drop** - every secret (session keys, ephemeral scalars, the
  MAC-and-Destroy output) implements `ZeroizeOnDrop`. No `Debug` / `Clone` on secret
  types.
- **Typed errors** - no `unwrap` / `expect` / `panic!` outside tests. Every failure
  is a typed `Result`. Attacker-facing parsers use only bounds-checked combinators.
- **Minimal supply chain** - audited `no_std` crypto crates only (x25519-dalek,
  aes-gcm, sha2, hmac, zeroize, and ecdsa / p384 / p521 for chain verification).
  A small rewrite is preferred over a non-essential dependency. The ECDSA curve
  crates are pinned to RustCrypto release candidates to keep a single `digest`
  generation in the tree. The `Cargo.toml` comment tracks moving to stable.

## Testing

Host tests drive the driver through mock SPI / wait ports and an in-repo chip mock
(with fault injection). The Noise KK1 key schedule and the L2 multi-chunk SEND
frames are checked against golden KATs generated from real libtropic, and the
X.509 STPUB walk against the real device certificate. Five libFuzzer targets
cover the attacker-facing parsers - L2 response, L3 result decrypt, handshake
response, the cert-store STPUB decoder, and the cert-chain verifier (behind the
`_fuzz` feature). The build is proven `no_std` on `thumbv8m.main-none-eabihf`.

```sh
cargo test -p tropic01-driver
cargo clippy -p tropic01-driver --all-targets -- -D warnings
cargo clippy -p tropic01-driver --target thumbv8m.main-none-eabihf -- -D warnings
```

These run with no external dependencies. A separate **live** suite drives the
driver against the official `tropic01_model` emulator (see
[Validation](#validation-against-real-libtropic)). It is behind the `model-itest`
feature and started by `scripts/model-itest.sh`, so the normal test run stays
hermetic.

## License

GNU General Public License v3.0 or later (`GPL-3.0-or-later`). See the
[project README](https://github.com/PatinaKey/firmware) for commercial-licensing
contact.
