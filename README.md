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

The project is under active development. Only the secure-element driver (`crates/se-driver`) exists today. The USB stack and the FIDO2/OpenPGP/PKCS#11 layers are not yet started.

**Secure-element driver - working today**

- Noise KK1 handshake: authenticated key agreement with the TROPIC01
- AES-256-GCM command/response codec with advance-after-verify nonces
- Fail-closed command gate: a crypto, structural, or parse fault on any command tears the session down and zeroizes the keys
- Commands: `ping`, `random` (TRNG), and monotonic-counter read
- Range-checked slot types: an out-of-range key/counter index cannot be constructed
- 99 host tests, three libFuzzer targets on parser entry points
- Clean `thumbv8m.main-none-eabihf` build (no_std proven on the target)

**Not yet implemented**

- Remaining SE commands: ECC keygen, ECDSA/EdDSA sign, R-memory read/write, MAC-and-Destroy, monotonic counter init/update
- SE firmware-update path
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
| Coverage | `cargo-llvm-cov` | line floor 90%, lcov for SonarQube |
| Advisories | `cargo audit` | blocks on any RustSec finding, SARIF export |
| Dependency policy | `cargo deny` | license allow-list, no unknown sources, no yanked crates |
| Unused deps | `cargo udeps` | nightly |
| Outdated | `cargo outdated` | informational, never blocking |
| Fuzz | `cargo fuzz` | 60s per target on PR, 15 min on weekly schedule |
| Quality scan | SonarQube | consumes the three reports above |

See [`.github/workflows/ci.yml`](.github/workflows/ci.yml) for the full pipeline and [`sonar-project.properties`](sonar-project.properties) for the SonarQube configuration.

**Note:** rustfmt is intentionally absent. The project uses a strict Allman brace style that rustfmt cannot reproduce. Formatting is reviewed, not auto-applied.

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
