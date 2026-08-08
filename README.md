# PatinaKey - Firmware

[![CI](https://github.com/PatinaKey/firmware/actions/workflows/ci.yml/badge.svg)](https://github.com/PatinaKey/firmware/actions/workflows/ci.yml)
[![License: GPL-3.0-or-later](https://img.shields.io/badge/License-GPL--3.0--or--later-blue.svg)](LICENSE)
[![Rust 1.88+](https://img.shields.io/badge/Rust-1.88%2B%20edition%202024-orange.svg)](https://doc.rust-lang.org/edition-guide/)
[![no_std](https://img.shields.io/badge/no__std-bare--metal-green.svg)](https://docs.rust-embedded.org/book/intro/no-std.html)

Open-source Rust firmware for **PatinaKey**, a USB hardware security key targeting FIDO2, OpenPGP card, and PKCS#11.

---

## Hardware

| Component | Part | Role |
|-----------|------|------|
| MCU | STM32U545CEU6Q (Cortex-M33 + TrustZone) | USB FS, application logic, on-chip crypto block (PKA / HASH / SAES) |
| Secure Element | TROPIC01 TR01-C2P-T301 | Key storage, ECC signing, TRNG, PIN anti-bruteforce |

The MCU and the TROPIC01 communicate over SPI. All long-term private keys live inside the TROPIC01 and are non-exportable. Every command exchange is protected by a Noise KK1 encrypted session negotiated at startup. Board pinout, power, and clocking are documented in the hardware reference kept alongside the sources.

## Status

The platform foundation is built and proven on real silicon. The remaining work is the clock ramp, the on-target A/B update, USB, per-device provisioning, and then the application layer (FIDO2, OpenPGP, PKCS#11).

### Proven on real silicon (STM32U545 + TROPIC01 bench)

- **TrustZone split boot** end to end: clock init, the SAU / GTZC / secure-MPU partition, and the secure-to-non-secure `BXNS` hand-off across the CMSE NSC veneer bridge. The two-image build boots secure-first, then hands off to the non-secure world.
- **SE driver over SPI1** from the secure world: L1 transport, L2 framing, and `Get_Info` (chip mode, RISC-V and SPECT firmware versions).
- **Noise KK1 secure channel**: the full handshake on the factory pairing slot, session-key derivation, an AES-256-GCM encrypted L3 `Ping` round trip, and the chip-acknowledged session teardown.
- **Attestation**: the complete four-certificate chain verified up to the pinned Tropic Square production root, the verified chip key feeding the session open.
- **Cryptography under session**: the chip TRNG, Ed25519 key generation and signing verified end to end (the SE signs, the MCU verifies strict), ECDSA P-256 generation and signing (the signature verified cryptographically on the host), imported-key round trips (Ed25519 seed import with an on-chip pubkey matching the RFC 8032 vector), monotonic counters, and the MAC-and-Destroy PIN primitive.
- **Safe reads and reversible state**: pairing-slot reads, configuration-object reads, user-memory read and erase, chip identity, and the resettable persistent state (counters, MAC-and-Destroy slots, ECC slots).
- **SE firmware update** 1.0.0 to 2.0.0, exercised once on the bench.
- **Secure-to-non-secure return channel**: a pinned shared non-secure output buffer plus a dedicated secure-MPU region (read-write, execute-never) so a veneer can return bytes to the non-secure world without ever accepting a non-secure pointer.

### Host-validated, not yet on silicon

- The on-target flash driver, the signed-image header verifier, and the A/B update state machine. These are tested against a two-bank flash model and a simulated power cut, but the on-hardware A/B swap and the power-fault recovery test are still owed. That power-fault proof is a hard gate before any irreversible lifecycle lock.

### Not exercised by nature

- The one-way SE writes (pairing-key and configuration OTP burns). These cannot be proven non-destructively even by the vendor, so their coverage is by-construction and conformance argument only.

### Work in progress

The clock ramp from the reset default up to full speed, the on-silicon A/B update with the power-fault recovery test, the USB stack (CTAPHID and CCID), and per-device provisioning (an offline-generated pairing key, never committed). Each lands on its own focused branch. Only then does the application layer begin.

## Repository layout

The workspace is a mix of one host-testable library published to crates.io, the on-target platform crates, and the two bare-metal binaries that make up the TrustZone image.

| Crate | Kind | Role |
|-------|------|------|
| [`tropic01-driver`](crates/tropic01-driver) | library (published) | `no_std` TROPIC01 secure-element driver. See its [README](crates/tropic01-driver/README.md) for the command coverage matrix |
| [`platform`](crates/platform) | library | TrustZone partition logic (SAU / GTZC / secure MPU), the address map, and the non-secure pointer checks. Host-tested |
| [`mcu-spi`](crates/mcu-spi) | library | The SPI1 MMIO master driving the TROPIC01 |
| [`mcu-flash`](crates/mcu-flash) | library | The on-target dual-bank flash driver behind the update seam |
| [`image-verify`](crates/image-verify) | library | The signed firmware-image verifier (ECDSA P-256 over SHA-256, streamed across a segmented image) |
| [`fw-update`](crates/fw-update) | library | The MCU A/B update state machine (verify then swap-as-commit) |
| [`secure`](crates/secure) | binary (TZ-S) | The secure-world image: partition bring-up, the SE driver, and the CMSE non-secure-callable veneers |
| [`nonsecure`](crates/nonsecure) | binary (TZ-NS) | The non-secure image: the entry that calls the veneers and reports over defmt-RTT |
| [`tools/image-signer`](tools/image-signer) | host tool | The offline firmware-image signing tool (its own detached workspace, never built for the target) |

The two binaries compile two ways: a `no_std` / `no_main` cortex-m-rt image for `thumbv8m.main-none-eabihf`, and an empty `main` on the host so the whole workspace stays host-checkable without a bare-metal test harness.

## Building

Minimum supported Rust version (MSRV): 1.88 (edition 2024), verified to build. Developed on a newer stable. No guarantee is provided below 1.88.

```sh
# Host check and tests (the two bare-metal binaries build to an empty main here)
cargo check --workspace --locked --all-targets
cargo test  --workspace --locked

# Embedded libraries on the firmware target (no_std proof)
rustup target add thumbv8m.main-none-eabihf
cargo check -p platform      --locked --target thumbv8m.main-none-eabihf
cargo check -p tropic01-driver --locked --target thumbv8m.main-none-eabihf
```

### Two-image TrustZone build

The secure and non-secure binaries are two ELF files at two flash addresses, and the secure crate MUST link first so its CMSE import object exists before the non-secure crate links against it. There is no cargo dependency edge between the two, so the order is enforced by hand.

```sh
cargo build -p secure    --release --locked --target thumbv8m.main-none-eabihf
cargo build -p nonsecure --release --locked --target thumbv8m.main-none-eabihf
```

The optional bring-up veneers (the on-silicon SE proofs) live behind cargo features applied to both crates. When switching features or profile, the shared import object must be regenerated first. The bench runner handles this automatically. See the [bring-up guide](docs/bench-runner.md) for the details and the brick-safety guarantee.

## Bench and bring-up

`scripts/bench.sh` is the turnkey runner for flashing the two-image build over SWD and reading the live defmt-RTT log. It only ever flashes the two reflashable code banks. It never writes an option byte or touches any irreversible lifecycle state. The full guide, including the feature flags and the marker codes each proof reports, is in [`docs/bench-runner.md`](docs/bench-runner.md).

## CI

The pipeline runs on every push and pull request. Run the same gates locally with:

```sh
scripts/ci-local.sh          # full run
scripts/ci-local.sh --quick  # skip coverage and fuzz
```

| Gate | Tool | Scope |
|------|------|-------|
| Host check and lint | `cargo check` / `cargo clippy` | whole workspace, zero warnings, JSON report for SonarQube |
| Host tests | `cargo test` | whole workspace via mock ports |
| Embedded build | `cargo build` / `cargo clippy` on `thumbv8m.main-none-eabihf` | per-crate no_std lint plus the two-image build across the feature matrix (default, se-session, se-fw-update) |
| Host tool | `cargo test` in `tools/image-signer` | the detached signing-tool workspace |
| Model integration | `tropic01_model` (`ts-tvl`) | live end-to-end against the official model, run under coverage |
| Coverage | `cargo-llvm-cov` | library line coverage floor |
| Advisories | `cargo deny` | blocks on any RustSec finding, SARIF export |
| Dependency policy | `cargo deny` / `cargo udeps` | license allow-list, trusted sources, no yanked or unused crates |
| Fuzz | `cargo fuzz` | the driver's attacker-facing parsers, longer on the weekly schedule |
| Quality scan | SonarQube | consumes the reports above |

See [`.github/workflows/ci.yml`](.github/workflows/ci.yml) for the full pipeline and [`sonar-project.properties`](sonar-project.properties) for the SonarQube configuration.

**Note:** rustfmt is intentionally absent. The project uses a strict hand-written Allman brace style that rustfmt cannot reproduce. Formatting is reviewed, not auto-applied.

## Design principles

- **No heap** - all buffers are statically allocated. No `Vec` or `Box` anywhere in the firmware crates.
- **Unsafe is quarantined** - `unsafe_code` is forbidden workspace-wide. The pure-logic crates (`tropic01-driver`, `image-verify`, `fw-update`) hold that forbid and contain zero unsafe. Only the crates that touch raw MMIO relax it to a per-crate `deny`, and each site is an explicit `#[allow(unsafe_code)]` with a documented `// SAFETY:` justification.
- **Zeroize on drop** - every secret (session keys, ephemeral scalars, PIN outputs) implements `ZeroizeOnDrop`.
- **Typed errors** - no `unwrap` / `expect` / `panic!` outside tests. Every failure path returns a typed `Result`.
- **Least privilege** - the secure MPU maps only the addresses the secure core actually uses, the non-secure world never receives a secure pointer, and the veneers are coarse value-in / value-out.
- **Minimal supply chain** - prefer rewriting a small piece over pulling a non-essential crate. Every dependency is an audit liability on a security product.

## License

This project is licensed under the **GNU General Public License v3.0 or later** ([GPL-3.0-or-later](LICENSE)).

Any modifications or products built on this code must remain open-source under the same terms. This ensures that improvements to a security tool flow back to the community.

### Commercial licensing

To integrate PatinaKey into a proprietary closed-source product, contact us to discuss a commercial license.

Contact: **contact@patinakey.fr**
