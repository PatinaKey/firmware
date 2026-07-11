# tropic01-driver - TROPIC01 secure-element driver (no_std)

[![crates.io](https://img.shields.io/crates/v/tropic01-driver.svg)](https://crates.io/crates/tropic01-driver)
[![docs.rs](https://docs.rs/tropic01-driver/badge.svg)](https://docs.rs/tropic01-driver)
[![MSRV 1.88+](https://img.shields.io/badge/MSRV-1.88-blue.svg)](https://www.rust-lang.org)
[![License: GPL-3.0-or-later](https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)


> **Unofficial. Core proven on silicon, one-way writes conformance-only.**
> The transport, the Noise KK1 secure channel, attestation, the cryptographic
> hot path, and the safe read and reversible-state commands have run on real
> TROPIC01 silicon (part `TR01-C2P-T301`). The irreversible provisioning writes
> (pairing-key and configuration OTP) are validated against the official
> `tropic01_model` emulator and libtropic only, because a real burn is
> destructive and cannot be proven
> non-destructively. Per-command status is in the [coverage matrix](#coverage).

A `no_std`, heap-free, `unsafe-free` Rust driver for the **TROPIC01** secure
element (Tropic Square, part `TR01-C2P-T301`), spoken over SPI through an
authenticated, encrypted **Noise KK1** session.

## Quick start

The integrator supplies the SPI bus (`embedded_hal::spi::SpiDevice`) and a
ready/timeout provider (the crate's `SeWait` trait). All key material is
caller-provided via `SessionConfig`. Open a channel, run a command, close it:

```rust,no_run
use tropic01_driver::{SeCommands, SessionConfig, StartupId, Tropic01};
use zeroize::Zeroizing;

fn run(spi: impl embedded_hal::spi::SpiDevice, wait: impl tropic01_driver::SeWait)
    -> Result<(), tropic01_driver::SeError>
{
    let mut dev = Tropic01::new(spi, wait);
    dev.reboot(StartupId::Reboot)?; // load the Application firmware

    // Placeholder keys: real ephemerals come from a TRNG, the pairing keys from
    // provisioning, and `stpub` from the chip certificate. For a genuine-chip
    // trust decision, get `stpub` via `read_verified_chip_stpub` (not the
    // unverified `read_chip_stpub`) against an out-of-band-pinned `RootAnchor`.
    let ehpriv = Zeroizing::new([0u8; 32]);
    let shipriv = Zeroizing::new([0u8; 32]);
    let shipub = [0u8; 32];
    let stpub = [0u8; 32];
    let cfg = SessionConfig
    {
        ehpriv: &ehpriv,
        shipriv: &shipriv,
        shipub: &shipub,
        stpub: &stpub,
        pkey_index: 0,
    };
    // open_session reports its error as a tuple (handle, error).
    let mut session = dev.open_session(cfg).map_err(|(_dev, e)| e)?;

    let mut random = [0u8; 32];
    session.random_into(&mut random)?;
    let _dev = session.close_session();
    Ok(())
}
```

The `attestation` feature (ON by default) enables X.509 chain verification
(`verify_cert_chain` / `read_verified_chip_stpub`) and pulls the ECDSA curve
crates (`ecdsa` / `p384` / `p521`). 
Build with `default-features = false` to drop those dependencies when only 
STPUB extraction is needed.

**Disclaimer:** This is an unofficial, community-driven project. It is not affiliated with, endorsed by, or officially supported by Tropic Square. For the official SDK, please refer to Tropic Square's libtropic.

Written as a clean-room rewrite with the official C SDK
[`libtropic`](https://github.com/tropicsquare/libtropic) used as a differential
**test oracle** (never linked : no C, no mbedTLS in the trusted computing base).

> **Status: under active development.** The secure channel and the cryptographic
> hot-path commands are tested host-side three ways: an in-repo chip mock (incl.
> fault injection), a libtropic-derived handshake KAT, and a **live end-to-end
> suite against the official `tropic01_model` emulator** (real handshake + real
> AES-GCM, see [Coverage](#coverage)). The chip's whole
> command surface is wired, including X.509 chain verification up to the pinned
> Tropic root, the power / mode / session-lifecycle L2 commands, and the
> firmware-update bootloader API. The core of that surface has run on real
> TROPIC01 silicon, including the firmware update 1.0.0 to 2.0.0. The one-way
> provisioning writes remain conformance-validated only, and the on-silicon
> firmware update has been exercised once but still owes a full power-fault
> recovery test before any production use. The per-command [coverage
> matrix](#coverage) states where each command stands. Not production-grade yet.

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
| Secure channel | Noise KK1 handshake, `open_session` / `close_session`, `abort_session` (Encrypted_Session_Abt_Req 0x08: notifies the chip to drop the session, wipes host secrets first), session teardown gate |
| Mode control | `reboot` (Startup_Req 0xB3: Start-up / Maintenance / Application FW), `sleep` (Sleep_Req 0x20), `chip_mode` (decodes CHIP_STATUS to Application / Startup / Alarm) |
| Chip info (L2) | `Get_Info`: `x509_certificate_into` (raw cert store), `chip_id_into`, `riscv_fw_version`, `spect_fw_version`, `fw_bank_into` - read before a session, no secure channel |
| Attestation (parse) | `parse_stpub` / `read_chip_stpub`: extract the chip static X25519 key (STPUB) from the X.509 cert store via a depth-bounded, panic-free DER walk |
| Attestation (verify) | `verify_cert_chain` / `parse_verified_stpub` / `read_verified_chip_stpub`: verify the cert chain DEVICE -> XXXX CA -> product CA up to a caller-pinned Tropic root (ECDSA P-384/SHA-384 then P-521/SHA-512, mixed-algorithm dispatched per cert). The root is pinned out-of-band, never trusted from the store. Cryptographic path only - dates / revocation are left to the integrator |
| Diagnostics | `ping` round-trip, `get_log_into` (Get_Log_Req 0xA2: raw RISC-V FW debug log, disabled on production parts) |
| TRNG | `random_into` (RandomValueGet, 0x50) |
| ECC keys | `ecc_key_generate` (0x60), `ecc_public_key` (0x62, returns the chip-attested curve), `ecc_key_store` (0x61, import a private key), `ecc_key_erase` (0x63) |
| Signing | `ecdsa_sign` (0x70, P-256), `eddsa_sign` (0x71, Ed25519) |
| User memory | `rmem_read_into` (0x41), `rmem_write` (0x40), `rmem_erase` (0x42) |
| Counters | `mcounter_get` (0x82), `mcounter_init` (0x80), `mcounter_update` (0x81) |
| PIN primitive | `mac_and_destroy` (0x90), output wrapped in a zeroize-on-drop secret type |
| Pairing keys | `pairing_key_write` (0x10), `pairing_key_read` (0x11), `pairing_key_invalidate` (0x12) - provision the chip's 4 host-pairing slots |
| Config objects | `r_config_write` (0x20), `r_config_read` (0x21), `r_config_erase` (0x22, whole R-Config), `i_config_write` (0x30, irreversible OTP bit-burn), `i_config_read` (0x31) - per-command access privileges (CFG_UAP) and chip behaviour |
| Firmware update | `enter_bootloader` / `exit_to_application` (type-state transitions via Startup_Req), `mutable_fw_update` (0xB0) / `mutable_fw_update_data` (0xB1), the bounded `FwImageChunks` blob decoder, and the `update_firmware` orchestrator (both bank pairs, the anti-downgrade reboot, and the post-update per-bank and running-firmware version-equality checks - full parity with libtropic `lt_do_mutable_fw_update`). The host is a pure transport: the chip verifies the EdDSA firmware signature. **Exercised once on silicon (1.0.0 to 2.0.0). A full power-fault recovery test is still owed before production** |

The twenty-two L3 commands are exposed through the public `SeCommands` trait, the only
surface the FIDO2 / OpenPGP / PKCS#11 layers consume. The bootloader primitives are
reached through the `Bootloader` type-state, which firmware update gates at compile time.

<a name="coverage"></a>

## Coverage

Two independent axes back this driver, and the matrix below states both per command.

- **Silicon** - has the command run on real TROPIC01 hardware (part
  `TR01-C2P-T301`) driven from the PatinaKey firmware. This is the strongest
  evidence.
- **Model** - is the command exercised end to end against the official **TROPIC01
  model** (Tropic Square `ts-tvl`) over a TCP shim, running its real Noise KK1
  handshake and real AES-GCM L3 codec against an independent implementation of the
  chip (`scripts/model-itest.sh`, behind the `model-itest` feature). No keys are
  pinned and nothing is mocked: a wrong protocol or crypto byte breaks the
  handshake or a GCM tag. Injected faults (corrupt tag / CRC / alarm / truncation)
  stay in the in-repo mock, so model = conformance and mock = fault robustness.

Legend for the **Silicon** column: **Proven** ran on hardware, **-** safe but not
yet exercised on hardware, **One-way** an irreversible write that cannot be run on
the single production part without a permanent change, so it stays
conformance-validated by design.

| Command | Silicon | Model | Notes |
|---------|:---:|:---:|-------|
| `reboot` (Startup_Req) | Proven | Yes | Chip reaches Application FW. Byte-exact frame KAT plus live Start-up to Application |
| `sleep` (Sleep_Req) | - | Yes | Byte-exact frame KAT plus reachable live |
| `chip_mode` (CHIP_STATUS) | Proven | Yes | Reads Application on hardware after reboot |
| `open_session` (Noise KK1 handshake) | Proven | Yes | Full handshake on the factory pairing slot. Real Noise KK1, every live test depends on it |
| `abort_session` | Proven | Yes | Chip-acknowledged teardown. A later L3 needs a fresh handshake |
| `ping` | Proven | Yes | Encrypted L3 round trip on hardware. Live small plus 600-byte 3-chunk payload |
| `random_into` (TRNG) | Proven | Yes | 32 random bytes from the chip TRNG, sanity-checked |
| `ecc_key_generate` / `ecc_public_key` | Proven | Yes | Ed25519 and P-256 generation on hardware. Empty slot surfaces `InvalidKey` |
| `ecc_key_store` / `ecc_key_erase` | Proven | Yes | Ed25519 seed import with the on-chip pubkey matching the RFC 8032 vector, sign, then erase. Occupied slot surfaces `SlotNotEmpty` |
| `eddsa_sign` | Proven | Yes | The SE signs, the MCU verifies strict with ed25519-dalek |
| `ecdsa_sign` | Proven | Yes | P-256 signature generated on hardware and verified cryptographically on the host |
| `mac_and_destroy` | Proven | Yes | The 32-byte PIN-primitive output, re-init determinism checked |
| `mcounter_get` / `mcounter_init` / `mcounter_update` | Proven | Yes | Init / update / get on hardware including the at-zero boundary and the upward re-init (resettable) |
| `rmem_read_into` (0x41) | Proven | Yes | Reads back written data. An empty slot returns zero bytes |
| `rmem_erase` (0x42) | Proven | Yes | Clears a slot for a fresh write. Reversible R-Memory, not in any brick list |
| `rmem_write` (0x40) | One-way | Yes | **Excluded from silicon** pending the vendor errata-5 text. At FW 2.0.0 a documented HARDWARE_FAIL may latch the persistent Alarm, so a live write is treated as brick-class until confirmed. Round-trips against the model |
| `pairing_key_read` (0x11) | Proven | Yes | Factory slot 0 reads back the prod0 host pairing pubkey byte-exact |
| `pairing_key_write` (0x10) / `pairing_key_invalidate` (0x12) | One-way | Yes | **Provisioning writes, not run on silicon.** Slot 0 is the shared default and invalidation is permanent, so a live write commits the device. Write-read-invalidate round-trip against the model on a spare slot |
| `r_config_read` (0x21) | Proven | Yes | Configuration objects dumped from hardware |
| `r_config_write` (0x20) / `r_config_erase` (0x22) | One-way | Yes | **Not run on silicon (errata 1).** A bad `R_Config_Write` on a factory part is a permanent Alarm brick. Write / read-back / whole-erase validated against the model |
| `i_config_read` (0x31) | Proven | Yes | I-Config dumped from hardware |
| `i_config_write` (0x30) | One-way | Yes | **Irreversible OTP bit-burn.** Fuses configuration bits permanently, so it is mock-only by nature. A real burn is one-way |
| `get_log_into` (Get_Log_Req) | n/a | Yes | Development-only, disabled on production parts. Byte-exact frame KAT plus a recoverable empty reply live |
| `Get_Info`: cert store / chip id / fw versions | Proven | Yes | Reads the 3840-byte cert store, the 128-byte CHIP_ID, and the RISC-V / SPECT versions on hardware. FW_BANK is rejected outside Maintenance Mode |
| `parse_stpub` / `read_chip_stpub` (STPUB) | Proven | Yes | Extracts STPUB from the chip's real device certificate on hardware, byte-exact against the model's pinned `s_t_pub` |
| `verify_cert_chain` / `read_verified_chip_stpub` | Proven | Yes | On silicon: the full four-cert chain verified up to the pinned Tropic Square **production** root. Against the model: the same path up to the pinned TEST root, cross-checked under openssl |
| Firmware update (`enter_bootloader` / `mutable_fw_update` 0xB0 / `mutable_fw_update_data` 0xB1 / `update_firmware`) | Proven | No | Exercised once on silicon (1.0.0 to 2.0.0). The emulator models none of the bootloader, so the host-side proof is byte-exact golden REQUEST-frame assertions plus the fuzzed blob decoder. A full power-fault recovery test is a HARD gate before production |

The L2 multi-chunk SEND path additionally has a **byte-exact golden KAT**: real
libtropic frames captured from the model are asserted byte-for-byte against the
driver's chunker (frame length encoding + the 252-byte chunk constant + CRC).
This runs in the normal hermetic test suite.

## Roadmap

The TROPIC01 command surface is fully wired: every L2 request and L3 command,
attestation, and the firmware-update bootloader are implemented.

Work toward a production `1.0`. The core is proven on silicon (see
[Coverage](#coverage)), so what remains is: a full power-fault recovery test for
the firmware update before any production use, a type-state `open_session` that
consumes a chain-verified STPUB, and an `embedded-hal-async` path. The one-way
provisioning writes stay conformance-validated by design, since a live burn
commits the single production part.

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
  A small rewrite is preferred over a non-essential dependency.

## Testing

Host tests drive the driver through mock SPI / wait ports and an in-repo chip mock
(with fault injection). The Noise KK1 key schedule and the L2 multi-chunk SEND
frames are checked against golden KATs generated from real libtropic, and the
X.509 STPUB walk against the real device certificate. Six libFuzzer targets
cover the attacker-facing parsers - L2 response, L3 result decrypt, handshake
response, the cert-store STPUB decoder, the cert-chain verifier, and the
firmware-image blob decoder (behind the `_fuzz` feature). The build is proven
`no_std` on `thumbv8m.main-none-eabihf`.

```sh
cargo test -p tropic01-driver
cargo clippy -p tropic01-driver --all-targets -- -D warnings
cargo clippy -p tropic01-driver --target thumbv8m.main-none-eabihf -- -D warnings
```

These run with no external dependencies. A separate **live** suite drives the
driver against the official `tropic01_model` emulator (see
[Coverage](#coverage)). It is behind the `model-itest`
feature and started by `scripts/model-itest.sh`, so the normal test run stays
hermetic.

## License

GNU General Public License v3.0 or later (`GPL-3.0-or-later`). See the
[project README](https://github.com/PatinaKey/firmware) for commercial-licensing
contact.
