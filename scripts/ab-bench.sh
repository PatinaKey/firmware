#!/usr/bin/env bash
#
# PatinaKey A/B bring-up runner (build -> sign -> two-alias flash -> attach).
#
# The A/B image is a single 256 KB bank made of four de-interleaved segments
# (boot metadata, immutable boot-stage, signed descriptor, secure app, NS app).
# It boots through SECBOOTADD0 -> boot-stage -> signature verify -> secure ->
# bxns -> NS. Unlike the flat two-ELF build, you cannot flash it with a single
# probe-rs run, so this wrapper assembles, signs, and flashes it end to end.
#
# Sub-commands:
#   ab-bench.sh preflight   READ-ONLY. Confirm probe + that the part is already
#                           provisioned (SECWM + SECBOOTADD0). Writes nothing.
#   ab-bench.sh build       Build the three ELF images (secure, nonsecure, boot).
#   ab-bench.sh sign        build + prepare-external + YubiKey sign + finalize
#                           -> produces bank.bin (verified against the pinned key).
#   ab-bench.sh flash       Split bank.bin and flash the two aliases + read back.
#                           Requires a bank.bin from a prior sign.
#   ab-bench.sh attach      Just attach probe-rs.
#   ab-bench.sh all         (default) preflight + build + sign + flash + attach.
#
# BRICK-SAFETY: this script flashes ONLY reflashable bank content
# (pages 0-31 of the active bank, both aliases). It never writes an option byte,
# never sets or clears TZEN, SECWM, SECBOOTADD0, RDP, BOOT_LOCK, WRP, HDP or any
# OEM key. Every write here is reversible by another flash. Option-byte
# provisioning is a separate manual step and is intentionally absent.
# The preflight aborts if the part is not already provisioned, because flashing
# the A/B layout onto an un-provisioned part gives a (recoverable) dead boot.
#
# The YubiKey signing step needs a physical touch + PIN. The private key never
# leaves the card. If you prefer to sign by hand, pass SIG=/path/to/sig.raw to
# skip the pkcs11-tool call.

set -euo pipefail

# Resolve paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

TARGET="thumbv8m.main-none-eabihf"
OUT_DIR="target/${TARGET}/release"
BOOT_ELF="${REPO_ROOT}/${OUT_DIR}/boot-stage"
SECURE_ELF="${REPO_ROOT}/${OUT_DIR}/secure"
NONSECURE_ELF="${REPO_ROOT}/${OUT_DIR}/nonsecure"

SIGNER_MANIFEST="${REPO_ROOT}/tools/image-signer/Cargo.toml"
PUBKEY="${REPO_ROOT}/crates/boot-stage/product_root_key.sec1"

# Work directory for all artifacts, inside the already-ignored target tree.
WORK="${REPO_ROOT}/target/ab-bench"
DIGEST="${WORK}/digest.bin"
DIGEST_HEX="${WORK}/digest.hex"
CONTEXT="${WORK}/context.bin"
SIG_DEFAULT="${WORK}/sig.raw"
BANK="${WORK}/bank.bin"
MANIFEST="${WORK}/manifest.txt"
BANK_SEC="${WORK}/bank_secure.bin"
BANK_NS="${WORK}/bank_ns.bin"
RB_SEC="${WORK}/readback_secure.bin"
RB_NS="${WORK}/readback_ns.bin"

# Geometry (must match crates/*/memory.x and image-signer bank.rs)
# Secure region = pages 0-19 at offset 0, length 0x28000, flashed via the secure
# alias. NS region = pages 20-31 at offset 0x28000, length 0x18000, flashed via
# the NS alias. The split at 0x28000 is the secure/NS page-20 boundary.
SEC_ADDR="0x0C000000"
SEC_LEN="0x28000"
NS_ADDR="0x08028000"
NS_LEN="0x18000"
SPLIT_BYTES=163840   # 0x28000

# Overridable knobs
CUBE_CLI="${CUBE_CLI:-${HOME}/Documents/applications/STM32CubeProgrammer/bin/STM32_Programmer_CLI}"
CHIP="${CHIP:-STM32U545CEUx}"
PKCS11_MODULE="${PKCS11_MODULE:-/usr/lib/libykcs11.so}"
KEY_ID="${KEY_ID:-05}"
SIG="${SIG:-}"           # set to a path to skip the pkcs11-tool signing call
YES="${YES:-0}"          # set to 1 to skip the pre-flash confirmation prompt

# defmt log level baked at BUILD time. defmt filters at COMPILE time, so an unset
# DEFMT_LOG drops every info log to silence even though the firmware runs and the
# RTT control block still initializes (WrOff stays 0). This MUST be exported before
# the builds. Changing it forces defmt and its dependents to recompile.
export DEFMT_LOG="${DEFMT_LOG:-info}"

# Image version fields (kept identical to the first-light values by default).
V_MAJOR="${V_MAJOR:-0}"
V_MINOR="${V_MINOR:-0}"
V_REVISION="${V_REVISION:-1}"
V_BUILD="${V_BUILD:-1}"
V_SECCOUNT="${V_SECCOUNT:-0}"

# CubeProgrammer connect options. mode=UR + freq=1000 is the reliable link for
# every flash and read here.
CUBE_CONN=(-c port=SWD mode=UR freq=1000)

log() { printf '>> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2 ; exit 1; }

require_tool()
{
    command -v "$1" >/dev/null 2>&1 || die "missing tool: $1"
}

# preflight: READ-ONLY provisioning + probe check 
cmd_preflight()
{
    [ -x "${CUBE_CLI}" ] || die "STM32_Programmer_CLI not found at ${CUBE_CLI} (set CUBE_CLI=...)"
    mkdir -p "${WORK}"
    local ob="${WORK}/ob_displ.txt"
    log "reading option bytes (read-only)"
    "${CUBE_CLI}" "${CUBE_CONN[@]}" -ob displ | tee "${ob}" >/dev/null

    # The part MUST already carry SECBOOTADD0 -> 0x0C004000 and SECWM1/2 pages
    # 0-19, or flashing the A/B layout dead-boots (recoverable, but abort here).
    grep -Eq 'SECBOOTADD0[[:space:]]*:[[:space:]]*0x180080' "${ob}" \
        || die "part NOT provisioned: SECBOOTADD0 is not 0x180080. Provision the option bytes first (gated manual step). ABORTING before any flash."
    grep -Eq 'SECWM1_PEND[[:space:]]*:[[:space:]]*0x13' "${ob}" \
        || die "part NOT provisioned: SECWM1_PEND is not 0x13 (pages 0-19 secure). ABORTING."
    grep -Eq 'SECWM2_PEND[[:space:]]*:[[:space:]]*0x13' "${ob}" \
        || die "part NOT provisioned: SECWM2_PEND is not 0x13. ABORTING."
    log "preflight OK: probe present, SECBOOTADD0 + SECWM1/2 provisioned"
}

# build: the three ELF images, secure before nonsecure
cmd_build()
{
    require_tool cargo
    # Secure links first so the CMSE import object exists for the NS link.
    log "build secure"
    cargo build -p secure    --release --target "${TARGET}" --locked
    log "build nonsecure"
    cargo build -p nonsecure --release --target "${TARGET}" --locked
    log "build boot-stage"
    cargo build -p boot-stage --release --target "${TARGET}" --locked
    [ -f "${BOOT_ELF}" ] && [ -f "${SECURE_ELF}" ] && [ -f "${NONSECURE_ELF}" ] \
        || die "one or more ELF images missing after build"
}

# sign: prepare -> YubiKey sign -> finalize -> bank.bin
cmd_sign()
{
    require_tool cargo
    mkdir -p "${WORK}"

    log "prepare-external (emit digest + context)"
    cargo run --manifest-path "${SIGNER_MANIFEST}" -- prepare-external \
        --boot      "${BOOT_ELF}" \
        --secure    "${SECURE_ELF}" \
        --nonsecure "${NONSECURE_ELF}" \
        --major "${V_MAJOR}" --minor "${V_MINOR}" --revision "${V_REVISION}" \
        --build "${V_BUILD}" --security-counter "${V_SECCOUNT}" \
        --digest "${DIGEST}" --context "${CONTEXT}" --digest-hex "${DIGEST_HEX}"

    local sigfile="${SIG}"
    if [ -z "${sigfile}" ]
    then
        require_tool pkcs11-tool
        sigfile="${SIG_DEFAULT}"
        printf '\n'
        log "SIGN the digest with the YubiKey now (physical TOUCH + PIN)"
        log "  module=${PKCS11_MODULE}  id=${KEY_ID}  mechanism=ECDSA"
        printf '\n'
        pkcs11-tool --module "${PKCS11_MODULE}" --sign --mechanism ECDSA \
            --id "${KEY_ID}" --input-file "${DIGEST}" --output-file "${sigfile}"
    else
        log "using supplied signature: ${sigfile}"
    fi
    [ -s "${sigfile}" ] || die "signature file is empty: ${sigfile}"

    log "finalize-external (verify vs pinned key, lay out + self-verify bank)"
    cargo run --manifest-path "${SIGNER_MANIFEST}" -- finalize-external \
        --context   "${CONTEXT}" \
        --signature "${sigfile}" \
        --pubkey    "${PUBKEY}" \
        --out       "${BANK}" \
        --manifest  "${MANIFEST}"
    [ -f "${BANK}" ] || die "finalize produced no bank.bin"
    log "bank.bin ready: ${BANK}"
}

# flash: split + two-alias flash + read-back verify
cmd_flash()
{
    [ -x "${CUBE_CLI}" ] || die "STM32_Programmer_CLI not found at ${CUBE_CLI}"
    [ -f "${BANK}" ] || die "no bank.bin at ${BANK} (run 'sign' first)"

    # Split at the secure/NS page-20 boundary.
    log "split bank.bin at offset ${SEC_LEN} (secure | NS)"
    dd if="${BANK}" of="${BANK_SEC}" bs="${SPLIT_BYTES}" count=1 status=none
    dd if="${BANK}" of="${BANK_NS}"  bs="${SPLIT_BYTES}" skip=1 status=none

    if [ "${YES}" != "1" ]
    then
        printf '\n'
        printf 'About to FLASH (reversible bank content, NO option bytes):\n'
        printf '  secure region -> %s  (%s bytes) at %s\n' "${BANK_SEC}" "${SEC_LEN}" "${SEC_ADDR}"
        printf '  NS region     -> %s  (%s bytes) at %s\n' "${BANK_NS}"  "${NS_LEN}"  "${NS_ADDR}"
        read -r -p 'Proceed? [y/N] ' ans
        case "${ans}" in
            y|Y|yes|YES) ;;
            *) die "aborted by user" ;;
        esac
    fi

    # Secure region: flash then read the same range back and compare.
    log "flash secure region -> ${SEC_ADDR}"
    "${CUBE_CLI}" "${CUBE_CONN[@]}" -d "${BANK_SEC}" "${SEC_ADDR}"
    "${CUBE_CLI}" "${CUBE_CONN[@]}" -r "${SEC_ADDR}" "${SEC_LEN}" "${RB_SEC}"
    cmp "${RB_SEC}" "${BANK_SEC}" || die "secure region read-back MISMATCH"
    log "secure region read-back OK"

    # NS region via the NS alias (pages 20-31 are non-secure after SECWM).
    log "flash NS region -> ${NS_ADDR}"
    "${CUBE_CLI}" "${CUBE_CONN[@]}" -d "${BANK_NS}" "${NS_ADDR}"
    "${CUBE_CLI}" "${CUBE_CONN[@]}" -r "${NS_ADDR}" "${NS_LEN}" "${RB_NS}"
    cmp "${RB_NS}" "${BANK_NS}" || die "NS region read-back MISMATCH"
    log "NS region read-back OK"
    log "flash complete, both regions verified"
}

# attach
cmd_attach()
{
    require_tool probe-rs
    log "attach probe-rs"
    probe-rs attach --chip "${CHIP}" "${NONSECURE_ELF}"
}

cmd_all()
{
    cmd_preflight
    cmd_build
    cmd_sign
    cmd_flash
    cmd_attach
}

COMMAND="${1:-all}"
case "${COMMAND}" in
    preflight) cmd_preflight ;;
    build)     cmd_build ;;
    sign)      cmd_build ; cmd_sign ;;
    flash)     cmd_flash ;;
    attach)    cmd_attach ;;
    all)       cmd_all ;;
    *) die "usage: ab-bench.sh [preflight|build|sign|flash|attach|all]" ;;
esac
