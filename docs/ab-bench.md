# `scripts/ab-bench.sh`

Builds, signs, flashes and observes the A/B firmware (single signed 256 KB bank) over
ST-LINK. `probe-rs run` cannot drive an A/B image, it bypasses the boot stage. This
runner only ever writes bank content, never an option byte.

## Prerequisites

- `probe-rs` + STM32CubeProgrammer CLI on `PATH`, ST-LINK wired to SWD.
- `thumbv8m.main-none-eabihf` target installed.
- External ECDSA P-256 signer (YubiKey PIV by default, or `SIG=` for a signature file).
- Part already provisioned (`SECWM` pages 0-19, `SECBOOTADD0`). Checked by `preflight`.

## Commands

```sh
scripts/ab-bench.sh preflight  # option-byte check, read-only, aborts if unprovisioned
scripts/ab-bench.sh build      # secure -> nonsecure -> boot
scripts/ab-bench.sh sign       # prepare-external + sign + finalize -> bank.bin
scripts/ab-bench.sh flash      # split bank.bin + two-alias flash + read back
scripts/ab-bench.sh attach     # defmt decoder only, no flash, no reset
scripts/ab-bench.sh all        # everything (default)
```

The flash is split at offset `0x28000`: secure `0..0x28000` -> `0x0C000000`,
non-secure `0x28000..0x40000` -> `0x08028000`. To restore a known good image, run
`flash` alone — it reuses the existing `bank.bin`, no rebuild, no new signature.

## Variables

| Variable | Default | Effect |
|----------|---------|--------|
| `CUBE_CLI` | `~/Documents/applications/STM32CubeProgrammer/bin/STM32_Programmer_CLI` | CLI path |
| `CHIP` | `STM32U545CEUx` | `probe-rs` chip name |
| `PKCS11_MODULE` | `/usr/lib/libykcs11.so` | PKCS#11 module |
| `KEY_ID` | `05` | PIV slot 82 |
| `SIG` | — | Pre-made signature, skips the `pkcs11-tool` call |
| `YES` | `0` | `1` skips the pre-flash confirmation |
| `DEFMT_LOG` | `info` | defmt filter, baked at build time |
| `V_MAJOR` `V_MINOR` `V_REVISION` `V_BUILD` `V_SECCOUNT` | `0 0 1 1 0` | Version + anti-rollback counter |

```sh
SIG=/path/to/sig.raw YES=1 scripts/ab-bench.sh all
```

## Notes

- Signature is RAW ECDSA P-256 over the 32 digest bytes — the card must not re-hash.
  `finalize-external` normalizes to low-s.
- DWARF warning / `<invalid location>` tags are cosmetic; build with `debug = 2` for
  source locations.
- The RTT buffer survives reset (`SRAM_RST`), so stale or garbled frames can show up
  after a fresh flash. Power cycle for a clean stream. Never judge acceptance from the
  attach output, read the core state over SWD.