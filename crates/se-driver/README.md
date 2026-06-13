# se-driver - TROPIC01 secure-element driver (no_std)

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
> Roughly half of the chip's command surface is still unwired (see
> [Roadmap](#roadmap)) and it has not yet run on real silicon. Not
> production-grade yet.

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
- **Range-checked slot types** - an out-of-range key / counter / memory / PIN slot
  index cannot even be constructed.

All key material (host pairing keys, chip static public key, per-session ephemeral,
pairing-slot index) is **caller-provided** via `SessionConfig`. The driver hardcodes no secrets.

## Implemented today

| Area | What works |
|------|------------|
| Transport | L1 SPI, L2 framing + multi-chunk reassembly |
| Secure channel | Noise KK1 handshake, `open_session` / `close_session`, session teardown gate |
| Mode control | `reboot` (Startup_Req 0xB3: Start-up / Maintenance / Application FW) |
| Diagnostics | `ping` round-trip |
| TRNG | `random_into` (RandomValueGet, 0x50) |
| ECC keys | `ecc_key_generate` (0x60), `ecc_public_key` (0x62, returns the chip-attested curve) |
| Signing | `ecdsa_sign` (0x70, P-256), `eddsa_sign` (0x71, Ed25519) |
| User memory | `rmem_read_into` (0x41), `rmem_write` (0x40), `rmem_erase` (0x42) |
| Counters | `mcounter_get` (0x82), `mcounter_init` (0x80), `mcounter_update` (0x81) |
| PIN primitive | `mac_and_destroy` (0x90), output wrapped in a zeroize-on-drop secret type |

These twelve commands are exposed through the public `SeCommands` trait, the only
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
| `ecdsa_sign` / `eddsa_sign` | Yes - returns a 64-byte signature |
| `mac_and_destroy` | Yes - returns the 32-byte secret output |

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
| Key import / erase | `EccKeyStore` 0x61, `EccKeyErase` 0x63 | Import an external Ed25519 key, erase a slot - the imported-key SSH / OpenPGP path | Yes |
| Chip info / attestation | `Get_Info` (L2) | X.509 certificate chain, CHIP_ID, firmware versions, FW bank | Yes |
| Provisioning - pairing | `PairingKeyWrite/Read/Invalidate` 0x10-0x12 | Provision host pairing keys into the chip's 4 slots | Factory / setup |
| Provisioning - config | `R-Config` 0x20-0x22, `I-Config` 0x30-0x31 | Reversible / irreversible config objects, access privileges (CFG_UAP) | Factory / setup |
| Firmware update | bootloader 0xB0 / 0xB1 | Update the chip's application / SPECT firmware | Yes (planned) |
| Power / mode | sleep, get-mode (`reboot` done) | Low-power, bootloader vs application mode | Later |

Non-command work toward a publishable crate: validate against silicon (the
`tropic01_model` emulator is already wired, see
[Validation](#validation-against-real-libtropic)), crate-level docs / examples on
docs.rs, and an optional `embedded-hal`-based port so external users can plug
their own HAL (today the ports are the crate's own `SpiDevice` / `SeWait` traits).

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
  aes-gcm, sha2, hmac, zeroize). A small rewrite is preferred over a non-essential
  dependency.

## Testing

Host tests drive the driver through mock SPI / wait ports and an in-repo chip mock
(with fault injection). The Noise KK1 key schedule and the L2 multi-chunk SEND
frames are checked against golden KATs generated from real libtropic. Three
libFuzzer targets cover the attacker-facing parsers (behind the `_fuzz` feature).
The build is proven `no_std` on `thumbv8m.main-none-eabihf`.

```sh
cargo test -p se-driver
cargo clippy -p se-driver --all-targets -- -D warnings
cargo clippy -p se-driver --target thumbv8m.main-none-eabihf -- -D warnings
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
