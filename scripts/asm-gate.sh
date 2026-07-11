#!/usr/bin/env bash
#
# Machine-code assertions on the built TrustZone ELFs.
#
# mcu-arch holds the firmware's hand-rolled inline asm, and it is cfg(target_os = "none").
# A swapped mnemonic (cpsid for cpsie) therefore reaches silicon with every other
# gate green, and only the disassembly can catch it. This is that disassembly
# check.
#
# Usage: scripts/asm-gate.sh [feature-label]
#   The label is cosmetic, it only tags the output line. The gate reads the
#   secure and nonsecure images already built at
#   target/thumbv8m.main-none-eabihf/release, so the caller must build them first
#   (secure before nonsecure, for the matching feature set).
#
# Exit 0 when every assertion holds. Exit 1 on any failure, a missing
# disassembler, or an unfindable anchor symbol.
set -euo pipefail

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

have()
{
    command -v "$1" >/dev/null 2>&1
}

find_disassembler()
{
    if have llvm-objdump
    then
        command -v llvm-objdump
        return 0
    fi

    local sysroot host candidate
    sysroot=$(rustc --print sysroot)
    host=$(rustc -vV | sed -n 's/^host: //p')
    candidate="${sysroot}/lib/rustlib/${host}/bin/llvm-objdump"
    if [ -x "$candidate" ]
    then
        echo "$candidate"
        return 0
    fi

    if have arm-none-eabi-objdump
    then
        command -v arm-none-eabi-objdump
        return 0
    fi

    return 1
}

sym_block()
{
    # Prints the disassembly lines of the FIRST symbol whose header matches $2,
    # then stops. Both disassemblers open a function with `<addr> <name>:` and no
    # other line has that shape, so the header itself delimits the block. Callers
    # pass a regex anchored inside the `<...>` delimiters, so a symbol whose name
    # merely contains the wanted one cannot widen the block. Stopping at the next
    # header keeps an LTO clone or a `.llvm.NNNN` suffix from concatenating two
    # blocks into one, which would let an ordered check straddle the boundary.
    awk -v want="$2" '
        /^[0-9a-fA-F]+ <.*>:$/ {
            if (seen) exit
            if ($0 ~ want) { inside = 1; seen = 1 } else { inside = 0 }
            next
        }
        inside { print }
    ' "$1"
}

ordered_in_block()
{
    # Succeeds when $2, $3 and $4 each match a line of file $1, in that order.
    awk -v r1="$2" -v r2="$3" -v r3="$4" '
        stage == 0 && $0 ~ r1 { stage = 1; next }
        stage == 1 && $0 ~ r2 { stage = 2; next }
        stage == 2 && $0 ~ r3 { stage = 3 }
        END { exit(stage == 3 ? 0 : 1) }
    ' "$1"
}

asm_expect()
{
    # asm_expect <what> <extended-regex> <file>
    if grep -qE "$2" "$3"
    then
        echo "  ok    $1"
        return 0
    fi
    echo "  FAIL  $1: no line matches /$2/ in $3" >&2
    return 1
}

asm_reject()
{
    # asm_reject <what> <extended-regex> <file>
    if grep -qE "$2" "$3"
    then
        echo "  FAIL  $1: forbidden /$2/ found in $3" >&2
        grep -nE "$2" "$3" >&2
        return 1
    fi
    echo "  ok    $1"
    return 0
}

asm_gate()
{
    local feat=${1:-}
    local od
    if ! od=$(find_disassembler)
    then
        echo "ERROR: the asm gate found no disassembler." >&2
        echo "       Install one of: llvm-objdump, the rustup llvm-tools component" >&2
        echo "       (rustup component add llvm-tools), or arm-none-eabi-objdump." >&2
        return 1
    fi

    local rel="target/thumbv8m.main-none-eabihf/release"
    local out="target/asm-gate"
    rm -rf "$out"
    mkdir -p "$out"
    echo ">> asm gate [${feat:-images}] via $od"

    "$od" -d "$rel/secure"    > "$out/secure.s"    || return 1
    "$od" -d "$rel/nonsecure" > "$out/nonsecure.s" || return 1

    # Every anchor is matched inside the `<...>` of the symbol header. The two Rust
    # symbols are name-mangled, so the anchor allows a leading mangled path and a
    # trailing hash or `.llvm.NNNN` suffix, and nothing else. A longer symbol that
    # merely contains the name, say a `..._start_nonsecure_trampoline`, does not
    # match. The two C-ABI symbols are matched whole.
    #
    # The backslashes are doubled because awk reads this through `-v`, which eats
    # one level of escape before the regex engine ever sees it.
    local rs_tail='(17h[0-9a-f]+E)?(\\.llvm\\.[0-9]+)?>'
    sym_block "$out/nonsecure.s" '<_defmt_acquire>'                       > "$out/acquire.s"
    sym_block "$out/nonsecure.s" '<_defmt_release>'                       > "$out/release.s"
    sym_block "$out/secure.s"    "<[^>]*start_nonsecure${rs_tail}"        > "$out/handoff.s"

    local f
    for f in acquire release handoff
    do
        if [ ! -s "$out/$f.s" ]
        then
            echo "  FAIL  $f: symbol block not found in the ELF" >&2
            echo "        The gate anchors on _defmt_acquire, _defmt_release and" >&2
            echo "        secure::firmware::start_nonsecure. The last carries an" >&2
            echo "        #[inline(never)] to hold the anchor. If one was inlined or" >&2
            echo "        renamed, re-anchor rather than dropping it." >&2
            return 1
        fi
    done

    local rc=0

    # The non-secure critical section. acquire reads PRIMASK then MASKS, release
    # UNMASKS. The reject halves are what catch a cpsid / cpsie swap.
    asm_expect "acquire reads PRIMASK" '(^|[[:space:]])mrs[[:space:]]' "$out/acquire.s" || rc=1
    grep -qiE 'primask' "$out/acquire.s" || { echo "  FAIL  acquire: MRS does not name PRIMASK" >&2; rc=1; }
    asm_expect "acquire masks (cpsid i)"   '(^|[[:space:]])cpsid[[:space:]]+i([[:space:]]|$)' "$out/acquire.s" || rc=1
    asm_reject "acquire never unmasks"     '(^|[[:space:]])cpsie([[:space:]]|$)'              "$out/acquire.s" || rc=1
    asm_expect "release unmasks (cpsie i)" '(^|[[:space:]])cpsie[[:space:]]+i([[:space:]]|$)' "$out/release.s" || rc=1
    asm_reject "release never masks"       '(^|[[:space:]])cpsid([[:space:]]|$)'              "$out/release.s" || rc=1

    # The secure hand-off publishes the MPU config with DSB then ISB before BXNS.
    if ordered_in_block "$out/handoff.s" \
        '(^|[ \t])dsb([ \t]|$)' '(^|[ \t])isb([ \t]|$)' '(^|[ \t])bxns([ \t]|$)'
    then
        echo "  ok    start_nonsecure emits dsb then isb then bxns"
    else
        echo "  FAIL  start_nonsecure: dsb -> isb -> bxns not found in that order" >&2
        rc=1
    fi

    return "$rc"
}

asm_gate "${1:-}"
