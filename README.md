# PatinaKey - Firmware

[![CI](https://github.com/PatinaKey/firmware/actions/workflows/ci.yml/badge.svg)](https://github.com/PatinaKey/firmware/actions/workflows/ci.yml)
[![License: GPL-3.0-or-later](https://img.shields.io/badge/License-GPL--3.0--or--later-blue.svg)](LICENSE)
[![Rust 1.95+](https://img.shields.io/badge/Rust-1.95%2B%20edition%202024-orange.svg)](https://doc.rust-lang.org/edition-guide/)
[![no_std](https://img.shields.io/badge/no__std-bare--metal-green.svg)](https://docs.rust-embedded.org/book/intro/no-std.html)

Open-source Rust firmware for **PatinaKey**, a USB hardware security key implementing FIDO2, OpenPGP card, and PKCS#11.

---

## Hardware

| Component | Part | Role |
|-----------|------|------|
| MCU | STM32U545CEU6Q (Cortex-M33 + TrustZone) | USB FS, application logic, on-chip crypto block |
| Secure Element | TROPIC01 TR01-C2P-T301 | Key storage, ECC signing, TRNG, PIN enforcement |

The MCU and the TROPIC01 communicate over SPI. All long-term private keys live inside the TROPIC01 and are non-exportable. Every command exchange is protected by a Noise KK1 encrypted session negotiated at startup.

## Status

The project is under active development. Only the secure-element driver (`crates/se-driver`) exists so far. The USB stack and the FIDO2/OpenPGP/PKCS#11 layers are not yet started. See [`crates/se-driver/README.md`](crates/se-driver/README.md) for the driver's detailed status and command-coverage roadmap.

**Secure-element driver - working**

- Noise KK1 handshake: authenticated key agreement with the TROPIC01
- AES-256-GCM command/response codec with advance-after-verify nonces
- Fail-closed command gate: a crypto, structural, or parse fault on any command tears the session down and zeroizes the keys
- The full `SeCommands` trait is assembled over twenty-two commands: `random` (TRNG), monotonic-counter read / init / update, R-memory read / write / erase, ECC key generation / public-key read / import / erase, ECDSA / EdDSA signing, MAC-and-Destroy (PIN primitive), host-pairing-key write / read / invalidate, and R/I-config object write / read / erase (access privileges, irreversible OTP), plus a `ping` diagnostic
- ECC public-key read returns the chip's attested curve, so an upper layer cannot pick the wrong signing algorithm
- The MAC-and-Destroy output is returned in a zeroize-on-drop secret type
- Range-checked slot types: an out-of-range key/counter/memory/PIN/pairing index cannot be constructed
- `reboot` (Startup_Req) to enter Application FW before a session
- `Get_Info` (L2, no session): reads the raw X.509 certificate store, CHIP_ID, and RISCV/SPECT firmware versions
- STPUB extraction: `parse_stpub` / `read_chip_stpub` walk the X.509 cert store's DER (depth-bounded, panic-free) to pull the chip static X25519 key for the handshake
- X.509 chain verification: `verify_cert_chain` / `parse_verified_stpub` authenticate the chip identity by verifying the cert chain (ECDSA P-384/SHA-384 then P-521/SHA-512) up to a caller-pinned Tropic root, never trusting the store's own root. Cryptographic path only - validity dates and revocation are left to the integrator
- Configuration objects: R-Config write / read / erase and I-Config write / read, gating per-command access by pairing key (CFG_UAP). The I-Config write is a documented irreversible OTP bit-burn
- Validated end-to-end against the official `tropic01_model` emulator: real handshake + real AES-GCM, every command's success path plus protocol-reachable failures (see the [driver's validation table](crates/se-driver/README.md#validation-against-real-libtropic))
- 352 host tests, five libFuzzer targets on parser entry points
- Clean `thumbv8m.main-none-eabihf` build (no_std proven on the target)

**Not yet implemented**

- Part of the TROPIC01 command surface: the firmware-update bootloader API and remaining power/mode control (see the [driver roadmap](crates/se-driver/README.md#roadmap))
- SE firmware-update path (bootloader 0xB0/0xB1)
- Validation against real silicon (the `tropic01_model` emulator is already wired up. See the [validation table](crates/se-driver/README.md#validation-against-real-libtropic))
- MCU firmware: USB stack, FIDO2/CTAP2, OpenPGP card, PKCS#11, TrustZone partition

## Building

Developed using rustc 1.95. No guarantee is provided that the code will work with an earlier version.

```sh
# Host check and tests
cargo check --workspace --locked
cargo test --workspace --locked

# Firmware target (no_std proof - bare-metal has no test harness)
rustup target add thumbv8m.main-none-eabihf
cargo check -p se-driver --locked --target thumbv8m.main-none-eabihf
```

## CI

The pipeline runs on every push and pull request. Run the same checks locally with:

```sh
scripts/ci-local.sh          # full run
scripts/ci-local.sh --quick  # skip coverage and fuzz
```

Gates (all blocking unless noted):

| Gate | Tool | Notes |
|------|------|-------|
| Check | `cargo check` | host and `thumbv8m.main-none-eabihf` |
| Lint | `cargo clippy` | zero warnings, JSON report for SonarQube |
| Test | `cargo test` | host via mock ports |
| Model integration | `tropic01_model` (`ts-tvl`) | live end-to-end against the official model (libtropic pinned). Run under coverage |
| Coverage | `cargo-llvm-cov` | hermetic + live-model tests, line floor 90%, lcov for SonarQube |
| Advisories | `cargo audit` | blocks on any RustSec finding, SARIF export |
| Dependency policy | `cargo deny` | license allow-list, no unknown sources, no yanked crates |
| Unused deps | `cargo udeps` | nightly |
| Outdated | `cargo outdated` | informational, never blocking |
| Fuzz | `cargo fuzz` | 60s per target on PR, 15 min on weekly schedule |
| Quality scan | SonarQube | consumes the three reports above |

See [`.github/workflows/ci.yml`](.github/workflows/ci.yml) for the full pipeline and [`sonar-project.properties`](sonar-project.properties) for the SonarQube configuration.

**Note:** rustfmt is intentionally absent. The project uses a strict Allman brace style that rustfmt cannot reproduce. Formatting is reviewed, not auto-applied.

**Live model integration.** A suite drives `se-driver` end-to-end against the official TROPIC01 model (`ts-tvl`): the real Noise KK1 handshake and AES-GCM codec run against an independent implementation of the chip. The GitHub coverage job clones libtropic (pinned to a tag + commit), installs the model, and runs these under coverage, so the library paths they exercise count toward the line floor (the test-harness files are excluded from the report). Locally:

```sh
crates/se-driver/scripts/model-itest.sh            # just the live tests
LIBTROPIC=/path/to/libtropic scripts/ci-local.sh   # coverage then includes them
```

The model needs Python and a one-time install (`scripts/tropic01_model/install_linux.sh` in the libtropic checkout). Without `LIBTROPIC`, the local coverage stage stays hermetic and the live tests are skipped.

## Design principles

- **No heap** - all buffers are statically allocated. No `Vec` or `Box` anywhere in the firmware crates
- **No unsafe** - enforced by `#![forbid(unsafe_code)]` at the workspace level
- **Zeroize on drop** - every secret (session keys, ephemeral scalars) implements `ZeroizeOnDrop`
- **Typed errors** - no `unwrap` or `panic!` outside tests. Every failure path returns a typed `Result`
- **Minimal supply chain** - prefer rewriting a small piece over pulling a non-essential crate. Every dependency is an audit liability on a security product

## License

This project is licensed under the **GNU General Public License v3.0 or later** ([GPL-3.0-or-later](LICENSE)).

Any modifications or products built on this code must remain open-source under the same terms. This ensures that improvements to a security tool flow back to the community.

### Commercial licensing

To integrate PatinaKey into a proprietary closed-source product, contact us to discuss a commercial license.

Contact: **contact@patinakey.fr**
