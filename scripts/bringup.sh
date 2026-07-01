#!/usr/bin/env bash
#
# PatinaKey hardware bring-up runner (probe-rs over SWD).
#
# flash plus live defmt-RTT for the two-image TrustZone build. The MCU
# build is two ELF files at two flash addresses (secure first, then nonsecure),
# and probe-rs flashes ONE ELF per call. This wrapper builds both in the correct
# order, flashes the secure image, then flashes-and-runs the nonsecure image with
# the defmt decoder attached, in a single command.
#
# Usage:
#   scripts/bringup.sh            run     (default) build, flash both, live RTT
#   scripts/bringup.sh run        same as the default
#   scripts/bringup.sh flash      build, flash both, NO run, NO RTT
#   scripts/bringup.sh detect     READ-ONLY probe and chip detection, no write
#
# Environment overrides:
#   PROFILE=release|debug          cargo profile (default release)
#   CONNECT_UNDER_RESET=1|0        assert NRST while attaching (default 1)
#   CHIP=<probe-rs chip>           target name (default STM32U545CEUx)
#   DEFMT_LOG=<filter>             defmt log level baked at build time (default
#                                  info). defmt filters at COMPILE time, so an
#                                  unset or too-high filter drops the info boot
#                                  log to silence even when the firmware runs.
#
# BRICK-SAFETY (read this): this script ONLY flashes the two reflashable code
# banks. It NEVER writes an option byte, never sets TZEN or SECWM or RDP or
# BOOT_LOCK or WRP, never calls probe-rs erase or reset-into-bootloader, never
# touches any irreversible or brick-class state. Every command here is reversible
# by a re-flash. Any lifecycle or option-byte write is a separate 
# step and is intentionally absent from this tooling.

set -euo pipefail

# Resolve the firmware repo root as the parent of this script directory so the
# runner works from any current directory.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

CHIP="${CHIP:-STM32U545CEUx}"
TARGET="thumbv8m.main-none-eabihf"
PROFILE="${PROFILE:-release}"
CONNECT_UNDER_RESET="${CONNECT_UNDER_RESET:-1}"

export DEFMT_LOG="${DEFMT_LOG:-info}"

# Map the profile name to the cargo flag and the target output subdirectory.
# The dev profile builds into the "debug" directory with no flag, release uses
# the --release flag and the "release" directory. The flag is held in an array so
# the empty (debug) case expands to no argument without unquoted word-splitting.
if [ "${PROFILE}" = "release" ]
then
    PROFILE_ARGS=(--release)
    PROFILE_DIR="release"
elif [ "${PROFILE}" = "debug" ]
then
    PROFILE_ARGS=()
    PROFILE_DIR="debug"
else
    echo "error: PROFILE must be release or debug, got '${PROFILE}'" >&2
    exit 2
fi

OUT_DIR="target/${TARGET}/${PROFILE_DIR}"
SECURE_ELF="${OUT_DIR}/secure"
NONSECURE_ELF="${OUT_DIR}/nonsecure"

# Shared probe options. connect-under-reset asserts NRST during attach, which is
# the reliable path on STM32U5 and the recovery path if a prior image wedged the
# core. Set CONNECT_UNDER_RESET=0 only if NRST is not wired to the probe.
PROBE_OPTS=(--chip "${CHIP}")
if [ "${CONNECT_UNDER_RESET}" = "1" ]
then
    PROBE_OPTS+=(--connect-under-reset)
fi

build_two_stage()
{
    # The secure crate MUST link before the nonsecure crate so the CMSE import
    # object exists. There is no cargo dependency edge between the two bins, so
    # the order is enforced here. nonsecure/build.rs fails loudly if the import
    # object is missing.
    echo ">> build secure (${PROFILE_DIR})"
    cargo build -p secure --target "${TARGET}" "${PROFILE_ARGS[@]}" --locked
    echo ">> build nonsecure (${PROFILE_DIR})"
    cargo build -p nonsecure --target "${TARGET}" "${PROFILE_ARGS[@]}" --locked
}

# Retry an attach command. The ST-LINK connect-under-reset sequence is
# intermittently flaky on the first attach, a timeout that succeeds on a retry,
# especially when the core is spinning in a fault from a prior run. A flash or a
# read is idempotent, so a few attempts smooth the timeout over. Used for the
# read-only info and for the download steps, NOT for run (a non-zero run exit can
# be a real firmware fault, which must not be re-flashed in a loop).
ATTACH_RETRIES="${ATTACH_RETRIES:-4}"
retry_attach()
{
    local n=1
    while true
    do
        if "$@"
        then
            return 0
        fi
        if [ "${n}" -ge "${ATTACH_RETRIES}" ]
        then
            echo "error: attach failed after ${ATTACH_RETRIES} attempts: $*" >&2
            return 1
        fi
        echo ">> attach attempt ${n}/${ATTACH_RETRIES} failed, retrying in 1s" >&2
        n=$((n + 1))
        sleep 1
    done
}

cmd_detect()
{
    # READ-ONLY. Lists the attached probes and reads the target identity from the
    # connected chip (IDCODE plus ROM table). This writes nothing to the device.
    echo ">> probes attached"
    probe-rs list
    echo ">> target identity (read-only)"
    retry_attach probe-rs info "${PROBE_OPTS[@]}"
}

cmd_flash()
{
    build_two_stage
    echo ">> flash secure -> ${SECURE_ELF}"
    retry_attach probe-rs download "${PROBE_OPTS[@]}" --verify "${SECURE_ELF}"
    echo ">> flash nonsecure -> ${NONSECURE_ELF}"
    retry_attach probe-rs download "${PROBE_OPTS[@]}" --verify "${NONSECURE_ELF}"
    echo ">> done, both images flashed (no run requested)"
}

cmd_run()
{
    build_two_stage
    # Flash the secure image first without running. The secure bank persists
    # across the nonsecure flash below (a different bank, not erased by it).
    echo ">> flash secure -> ${SECURE_ELF}"
    retry_attach probe-rs download "${PROBE_OPTS[@]}" --verify "${SECURE_ELF}"
    # Flash and run the nonsecure image. probe-rs run resets the core, attaches
    # RTT, and decodes the defmt log live from the nonsecure ELF. Ctrl-C exits.
    echo ">> flash and run nonsecure -> ${NONSECURE_ELF} (live defmt-RTT, Ctrl-C to exit)"
    probe-rs run "${PROBE_OPTS[@]}" "${NONSECURE_ELF}"
}

COMMAND="${1:-run}"
case "${COMMAND}" in
    detect)
        cmd_detect
        ;;
    flash)
        cmd_flash
        ;;
    run)
        cmd_run
        ;;
    *)
        echo "usage: scripts/bringup.sh [detect|flash|run]" >&2
        exit 2
        ;;
esac
