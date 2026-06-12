# se-driver - TROPIC01 secure-element driver (no_std)

A `no_std`, heap-free, `unsafe-free` Rust driver for the **TROPIC01** secure
element (Tropic Square, part `TR01-C2P-T301`), spoken over SPI through an
authenticated, encrypted **Noise KK1** session.

It is the secure-element layer of the [PatinaKey](../../README.md) hardware
security key, written as a clean-room rewrite with the official C SDK
[`libtropic`](https://github.com/tropicsquare/libtropic) used as a differential
**test oracle** (never linked : no C, no mbedTLS in the trusted computing base).

> **Status: under active development.** The secure channel and the cryptographic
> hot-path commands work and are tested host-side against an in-repo chip mock and
> a libtropic-derived handshake KAT. Roughly half of the chip's command surface is
> still unwired (see [Roadmap](#roadmap)), and the driver has **not** yet been
> validated against the `tropic01_model` emulator or real silicon. Not production-grade yet.

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
| Diagnostics | `ping` round-trip |
| TRNG | `random_into` (RandomValueGet, 0x50) |
| ECC keys | `ecc_key_generate` (0x60), `ecc_public_key` (0x62, returns the chip-attested curve) |
| Signing | `ecdsa_sign` (0x70, P-256), `eddsa_sign` (0x71, Ed25519) |
| User memory | `rmem_read_into` (0x41), `rmem_write` (0x40) |
| Counters | `mcounter_get` (0x82) |
| PIN primitive | `mac_and_destroy` (0x90), output wrapped in a zeroize-on-drop secret type |

These nine commands are exposed through the public `SeCommands` trait, the only
surface the FIDO2 / OpenPGP / PKCS#11 layers consume.

## Roadmap

The table below tracks the TROPIC01 command surface still to wire to reach a
complete, reusable driver. "Needed by PatinaKey" marks what the product itself
requires (almost everything). The rest matters for a general-purpose driver.

| Block | Commands | What it is for | Needed by PatinaKey |
|-------|----------|----------------|:---:|
| Key import / erase | `EccKeyStore` 0x61, `EccKeyErase` 0x63 | Import an external Ed25519 key, erase a slot - the imported-key SSH / OpenPGP path | Yes |
| Memory erase | `RMemDataErase` 0x42 | Erase a user-memory slot before rewrite (`rmem_write` requires it) | Yes |
| Counter lifecycle | `McounterInit` 0x80, `McounterUpdate` 0x81 | Monotonic counter for the FIDO2 signature counter (anti-cloning) | Yes |
| Chip info / attestation | `Get_Info` (L2) | X.509 certificate chain, CHIP_ID, firmware versions, FW bank | Yes |
| Provisioning - pairing | `PairingKeyWrite/Read/Invalidate` 0x10-0x12 | Provision host pairing keys into the chip's 4 slots | Factory / setup |
| Provisioning - config | `R-Config` 0x20-0x22, `I-Config` 0x30-0x31 | Reversible / irreversible config objects, access privileges (CFG_UAP) | Factory / setup |
| Firmware update | bootloader 0xB0 / 0xB1 | Update the chip's application / SPECT firmware | Yes (planned) |
| Power / mode | reboot, sleep, get-mode | Low-power, bootloader vs application mode | Later |

Non-command work toward a publishable crate: validate against the `tropic01_model`
emulator (then silicon), crate-level docs / examples on docs.rs, and an optional
`embedded-hal`-based port so external users can plug their own HAL (today the ports
are the crate's own `SpiDevice` / `SeWait` traits).

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

Host tests drive the driver through mock SPI / wait ports and an in-repo chip mock.
The Noise KK1 key schedule is checked against a golden KAT generated from real
libtropic. Three libFuzzer targets cover the attacker-facing parsers (behind the
`_fuzz` feature). The build is proven `no_std` on `thumbv8m.main-none-eabihf`.

```sh
cargo test -p se-driver
cargo clippy -p se-driver --all-targets -- -D warnings
cargo clippy -p se-driver --target thumbv8m.main-none-eabihf -- -D warnings
```

The current open validation gap: the multi-chunk L2 send path is exercised only
against the in-repo mock. A libtropic L2-frame golden transcript captured from the
`tropic01_model` emulator is the exit criterion before on-silicon bring-up.

## License

GNU General Public License v3.0 or later (`GPL-3.0-or-later`). See the
[project README](../../README.md) for commercial-licensing contact.
