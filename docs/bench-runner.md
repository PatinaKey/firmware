# Bench runner - `scripts/bench.sh`

`scripts/bench.sh` is the turnkey way to build the two-image TrustZone firmware,
flash it to a board over SWD, and read the live defmt-RTT log. It exists because
the build is two ELF files at two flash addresses (secure first, then non-secure)
and `probe-rs` flashes one ELF per call, so the wrapper enforces the order and
attaches the decoder in a single command.

It talks to the board through `probe-rs` over an ST-LINK. It is read-and-reflash
only. It never writes an option byte and never touches any irreversible lifecycle
state. The exact guarantee is at the bottom of this page.

## Prerequisites

- `probe-rs` on `PATH` and an ST-LINK wired to the board's SWD (plus NRST for the
  reset-under-attach path).
- The `thumbv8m.main-none-eabihf` target installed (`rustup target add ...`).
- For the SE bring-up proofs to log anything, the part must already be
  provisioned for TrustZone (TZEN set, the non-secure watermark opened). On an
  un-provisioned part the flash succeeds but the split image cannot boot, so the
  RTT log stays silent. That is expected, not a fault. Provisioning is a separate
  deliberate step, never done by this runner.

## Sub-commands

```sh
scripts/bench.sh            # same as run
scripts/bench.sh run        # build, flash both images, flash-and-run, live RTT
scripts/bench.sh flash      # build, flash both images, NO run, NO RTT
scripts/bench.sh detect     # READ-ONLY probe and chip identity, no write
```

- **`detect`** lists the attached probes and reads the target identity (IDCODE and
  ROM table). It writes nothing.
- **`flash`** builds both images and downloads them (secure then non-secure). Use
  it to load a board without opening an RTT session.
- **`run`** builds, downloads the secure image, then flashes-and-runs the
  non-secure image with the defmt decoder live. `Ctrl-C` exits.

## Environment overrides

| Variable | Default | Effect |
|----------|---------|--------|
| `PROFILE` | `release` | Cargo profile, `release` or `debug`. Sets the target output subdirectory too |
| `FEATURES` | (none) | Space-separated cargo features applied to BOTH images. Selects which SE proof runs (see below) |
| `CHIP` | `STM32U545CEUx` | The `probe-rs` chip name. The `Ux` package wildcard covers the U545CEU6 part |
| `DEFMT_LOG` | `info` | The defmt log filter, baked at build time. defmt filters at compile time, so an unset or too-high filter drops the info boot log to silence even when the firmware runs |
| `CONNECT_UNDER_RESET` | `1` | Assert NRST while attaching. The reliable path on STM32U5 and the recovery path when a prior image wedged the core. Set `0` only if NRST is not wired to the probe |
| `ATTACH_RETRIES` | `4` | Attach attempts for the read-only and download steps. The connect-under-reset sequence is intermittently flaky on a fault-spinning core, so a retry smooths a first-attempt timeout |

Example:

```sh
DEFMT_LOG=info FEATURES=se-session scripts/bench.sh run
```

## Feature builds and what each one runs

The default build is the product firmware: it brings up the TrustZone partition
and runs a minimal SE identity smoke. The optional SE proofs are behind cargo
features, and each reports its outcome as a status word that the non-secure world
logs over RTT with a fixed marker. A successful proof logs its marker. A failure
logs the failing step number and an error code instead.

| `FEATURES` | What builds | Live RTT markers |
|------------|-------------|------------------|
| (none) | the product smoke | first-light SE identity: chip mode, RISC-V and SPECT firmware versions. No `0x5x` marker |
| `se-session` | the SE proof suite | `0x51` L3 session + encrypted Ping, `0x53` reversible persistent state (counters, MAC-and-Destroy, imported-Ed25519 known-answer test), `0x54` safe reads + P-256 export. All three in one flash |
| `se-fw-update` | the SE firmware-update path | `0x20` SE firmware update to CPU 2.1.0 and SPECT 1.3.0 |

Notes:

- `se-session` adds the three secure-side proof bodies, their NSC veneers, and the
  host-side Ed25519 verifier (`ed25519-dalek`) that checks the signature the chip
  produces from the imported RFC 8032 seed. The secure image is larger as a
  result. The three proofs share one session helper and run back to back on a
  single flash.
- There is no on-MCU attestation proof. Verifying the
  TROPIC01 X.509 chain up to the Tropic Square root is a PROVISIONING-time host
  operation, run once on the assembly line to prove the chip genuine. The shipped
  firmware pins no Tropic root and verifies no chain: it delegates trust to the
  pairing key written into a chip slot at provisioning. The driver keeps the
  `attestation` feature for that host tool, and the firmware takes the driver with
  `default-features = false`, so none of it links into either image.
- `se-fw-update` needs the two vendor firmware blobs present at
  `crates/secure/fw_blobs/`. They are gitignored (Tropic Square signed artifacts
  from the libtropic SDK), so an empty checkout cannot build this feature until
  the blobs are copied in.
- The `se-fw-update` path is deliberately built and run once, by hand. It is the
  most brick-sensitive SE operation and is never part of the normal product boot.

## Verifying the P-256 signature on the host

The `0x54` proof exports a P-256 public key, a signature, and the signed digest as
hex over RTT. Copy those three values off the log and verify the signature on the
host with any standard P-256 tool. A successful verification proves the secure
element produced a valid ECDSA signature, independent of the on-chip check.

## Reading a failure

Every proof packs its result into one status word:

- bit 31 set means error. The next byte up is the step number that failed, and the
  low byte is the error code (the driver error space, with a few reserved codes per
  proof for its own sanity checks).
- bit 31 clear means success, and the low byte is the marker from the table above.

So a line reporting step 5 with a code tells you exactly which stage of a proof
stopped, and on which SE error.

## The implib regeneration and the stale-link trap

The two images share a CMSE import object that lives outside the per-crate build
directory. It is re-emitted only when the secure crate actually re-links. Switching
`FEATURES` or `PROFILE` between runs can otherwise leave a stale import object,
and the non-secure link then fails with undefined veneer symbols. The runner
handles this: it records the last built profile and feature set in a stamp, and
when they change it forces the secure crate to re-link so the shared object
matches. A manual two-image build outside the runner must do the same by touching
the C shim before a feature change.

## Brick-safety guarantee

This runner ONLY flashes the two reflashable code banks. It NEVER writes an option
byte, never sets TZEN or the secure watermark or RDP or BOOT_LOCK or WRP, never
calls a mass erase or a reset-into-bootloader, and never touches any irreversible
or brick-class state. Every command it issues is reversible by a re-flash. Any
lifecycle or option-byte write is a separate deliberate step and is intentionally
absent from this tooling.
