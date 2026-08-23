#!/usr/bin/env bash
#
# Runs every libFuzzer target of every fuzz crate in the tree.
#
# Called from .github/workflows/ci.yml and from scripts/ci-local.sh.
#
# The crate list is pinned here. Adding or removing a fuzz crate
# means editing this list.
EXPECTED_CRATES=(
    crates/fw-update
    crates/image-verify
    crates/tropic01-driver
)

# Usage:
#   scripts/fuzz-gate.sh [--secs N] [dir ...]
#
# Without a directory argument every pinned crate runs.
#
# Exits 0 when the discovered crate set matches the pinned set and every target
# of every selected crate survives its run. Exits 1 on a mismatch, a crash, a
# build failure or an unreadable fuzz manifest.
set -euo pipefail

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

norm()
{
    grep -v '^[[:space:]]*$' <<< "${1:-}" | LC_ALL=C sort || true
}

host_triple()
{
    rustc +nightly -vV | sed -n 's/^host: //p'
}

check_pin_sanity()
{
    if [ "${#EXPECTED_CRATES[@]}" -eq 0 ]
    then
        echo "ERROR: EXPECTED_CRATES in scripts/fuzz-gate.sh is empty." >&2
        return 1
    fi

    local dupes
    dupes=$(printf '%s\n' "${EXPECTED_CRATES[@]}" | LC_ALL=C sort | uniq -d)
    if [ -n "$dupes" ]
    then
        echo "ERROR: EXPECTED_CRATES in scripts/fuzz-gate.sh lists a crate twice:" >&2
        printf '         %s\n' $dupes >&2
        return 1
    fi
}

fuzz_manifests()
{
    # Prints every fuzz manifest in the repository, sorted.
    #
    # The walk has no depth bound, because a fuzz project sits wherever its crate
    # sits, from `./fuzz` at the repository root down to a nested crate.
    #
    # Symlinks stay unfollowed. A directory link can list one crate twice, pull
    # manifests from outside the repository into discovery, or cycle.
    #
    # The exclusions drop manifests that are not source: build output under any
    # `target/` and git internals under `.git/`, where dependency and submodule
    # sources carry their own fuzz projects. A vendored copy elsewhere in the tree
    # still shows up, and aborts the gate because it is not in EXPECTED_CRATES.
    find . -type f -path '*/fuzz/Cargo.toml' \
        -not -path '*/target/*' \
        -not -path '*/.git/*' \
        -print \
        | sed 's|^\./||' \
        | LC_ALL=C sort
}

has_fuzz_marker()
{
    awk '
        /^[[:space:]]*\[/ {
            section = $0
            sub(/#.*$/, "", section)
            gsub(/[[:space:]]/, "", section)
            gsub(/"/, "", section)
            next
        }
        section == "[package.metadata]" \
            && /^[[:space:]]*cargo-fuzz[[:space:]]*=[[:space:]]*true/ { found = 1 }
        section == "[package]" \
            && /^[[:space:]]*metadata[[:space:]]*=/ \
            && /cargo-fuzz[[:space:]]*=[[:space:]]*true/ { found = 1 }
        END { exit(found ? 0 : 1) }
    ' "$1"
}

check_crate_set()
{
    # Stdout only. Folding stderr in here would turn any warning the walk emits
    # while still succeeding into a fake manifest path, and the gate would then
    # abort blaming a file that does not exist. Letting stderr through to the
    # terminal keeps the real message visible and the data clean.
    local listing
    if ! listing=$(fuzz_manifests)
    then
        echo "ERROR: the walk for fuzz manifests failed, see the message above." >&2
        return 1
    fi

    local manifests=()
    mapfile -t manifests < <(norm "$listing")
    if [ "${#manifests[@]}" -eq 0 ]
    then
        echo "ERROR: no */fuzz/Cargo.toml found anywhere in the tree." >&2
        echo "       The gate expects these crates to carry one:" >&2
        printf '         %s\n' "${EXPECTED_CRATES[@]}" >&2
        return 1
    fi

    local found=() manifest
    for manifest in "${manifests[@]}"
    do
        if ! has_fuzz_marker "$manifest"
        then
            echo "ERROR: $manifest carries no readable 'cargo-fuzz = true' marker." >&2
            echo "       The gate refuses to skip it. Either it is a fuzz project and" >&2
            echo "       the marker is missing or written in a shape this gate cannot" >&2
            echo "       read, or it is not one and does not belong at this path." >&2
            return 1
        fi
        found+=("$(dirname "$(dirname "$manifest")")")
    done

    local discovered pinned missing extra
    discovered=$(norm "$(printf '%s\n' "${found[@]}")")
    pinned=$(norm "$(printf '%s\n' "${EXPECTED_CRATES[@]}")")
    extra=$(comm -23 <(printf '%s\n' "$discovered") <(printf '%s\n' "$pinned") || true)
    missing=$(comm -13 <(printf '%s\n' "$discovered") <(printf '%s\n' "$pinned") || true)

    if [ -n "$extra" ]
    then
        echo "ERROR: a fuzz crate exists in the tree but is NOT pinned in this gate:" >&2
        printf '         %s\n' $extra >&2
        echo "       Add it to EXPECTED_CRATES in scripts/fuzz-gate.sh. Until then it" >&2
        echo "       is not fuzzed, and the gate refuses to report success over a" >&2
        echo "       crate it does not cover." >&2
        return 1
    fi
    if [ -n "$missing" ]
    then
        echo "ERROR: a fuzz crate is pinned in this gate but was NOT found in the tree:" >&2
        printf '         %s\n' $missing >&2
        echo "       Either its fuzz project moved or was deleted, or the marker in its" >&2
        echo "       manifest stopped being readable. If the removal was intended, drop" >&2
        echo "       it from EXPECTED_CRATES in the same change." >&2
        return 1
    fi

    printf '%s\n' "$discovered"
}

fuzz_crate()
{
    local dir=$1 secs=$2

    local list_out rc=0
    list_out=$(cargo +nightly fuzz list --fuzz-dir "$dir/fuzz" 2>&1) || rc=1
    if [ "$rc" -ne 0 ]
    then
        echo "  FAIL  $dir: could not LIST the fuzz targets" >&2
        echo "$list_out" >&2
        return 1
    fi

    local targets=()
    mapfile -t targets < <(norm "$list_out")
    if [ "${#targets[@]}" -eq 0 ]
    then
        echo "  FAIL  $dir: the fuzz project declares no target" >&2
        return 1
    fi

    local t
    for t in "${targets[@]}"
    do
        echo ">> fuzz [$dir] $t on $HOST_TRIPLE for ${secs}s"
        cargo +nightly fuzz run "$t" --fuzz-dir "$dir/fuzz" --target "$HOST_TRIPLE" \
            -- -max_total_time="$secs" -timeout=10 || return 1
        RAN=$((RAN + 1))
    done
}

main()
{
    local secs=60
    local dirs=()
    while [ $# -gt 0 ]
    do
        case "$1" in
            --secs) shift; secs=${1:?--secs needs a value} ;;
            -*) echo "unknown option: $1" >&2; return 2 ;;
            *) dirs+=("$1") ;;
        esac
        shift
    done

    if ! [[ "$secs" =~ ^[0-9]+$ ]] || [ "$secs" -lt 1 ]
    then
        echo "ERROR: --secs must be a whole number of seconds, 1 or more (got '$secs')." >&2
        echo "       libFuzzer treats 0 as no limit, which would never return." >&2
        return 1
    fi

    check_pin_sanity || return 1
    
    HOST_TRIPLE=$(host_triple)
    if [ -z "$HOST_TRIPLE" ]
    then
        echo "ERROR: could not read the host triple from 'rustc +nightly -vV'." >&2
        echo "       The gate needs it to build the fuzz targets for this machine." >&2
        return 1
    fi

    local crate_list
    crate_list=$(check_crate_set) || return 1
    local discovered=()
    mapfile -t discovered < <(printf '%s\n' "$crate_list")

    if [ "${#dirs[@]}" -eq 0 ]
    then
        dirs=("${discovered[@]}")
    else
        local want found d
        for want in "${dirs[@]}"
        do
            found=0
            for d in "${discovered[@]}"
            do
                [ "$d" = "$want" ] && found=1
            done
            if [ "$found" -ne 1 ]
            then
                echo "ERROR: '$want' is not a fuzz project in this tree." >&2
                echo "       Discovered: ${discovered[*]}" >&2
                return 1
            fi
        done
    fi

    RAN=0
    local d
    for d in "${dirs[@]}"
    do
        fuzz_crate "$d" "$secs" || return 1
    done

    if [ "$RAN" -eq 0 ]
    then
        echo "ERROR: the fuzz gate ran zero targets." >&2
        return 1
    fi
    echo "fuzz gate: targets=${RAN} crates=${#dirs[@]} secs=${secs}"
}

main "$@"
