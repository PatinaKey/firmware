#!/usr/bin/env bash
# Local mirror of the CI/CD pipeline (.github/workflows/ci.yml).
# Runs the same gates without GitHub. Reports land at the repository
# root with the same names SonarQube expects: clippy-report.json,
# lcov.info, cargo-audit.sarif.
#
# Usage: scripts/ci-local.sh [--quick] [--strict] [--fuzz-secs N]
#   --quick       skip the slow stages (coverage, fuzz)
#   --strict      a missing optional tool fails the run instead of skipping
#   --fuzz-secs   seconds per fuzz target (default 60)
#
# Optional SonarQube upload: export SONAR_HOST_URL and SONAR_TOKEN, have
# sonar-scanner on PATH, and the final stage pushes the analysis.

set -euo pipefail
cd "$(dirname "$0")/.."

QUICK=0
STRICT=0
FUZZ_SECS=60
while [ $# -gt 0 ]
do
    case "$1" in
        --quick) QUICK=1 ;;
        --strict) STRICT=1 ;;
        --fuzz-secs) shift; FUZZ_SECS=${1:?--fuzz-secs needs a value} ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

passed=()
failed=()
skipped=()

run()
{
    local name=$1
    shift
    echo
    echo "==== ${name} ===="
    if "$@"
    then
        passed+=("$name")
    else
        failed+=("$name")
    fi
}

skip()
{
    local name=$1 how=$2
    echo
    echo "==== ${name} ==== SKIPPED (install with: ${how})"
    if [ "$STRICT" = 1 ]
    then
        failed+=("$name (missing tool)")
    else
        skipped+=("$name")
    fi
}

have()
{
    command -v "$1" >/dev/null 2>&1
}

clippy_reports()
{
    cargo clippy --workspace --locked --all-targets --all-features \
        --message-format=json > clippy-report.json || true
    cargo clippy -p se-driver --locked --target thumbv8m.main-none-eabihf \
        --message-format=json >> clippy-report.json || true
    RUSTFLAGS="-D warnings" cargo clippy --workspace --locked --all-targets --all-features -- -D warnings \
        || return 1
    RUSTFLAGS="-D warnings" cargo clippy -p se-driver --locked --target thumbv8m.main-none-eabihf -- -D warnings
}

audit_stage()
{
    local status=0
    cargo audit --format sarif > cargo-audit.sarif || status=$?
    return $status
}

coverage_stage()
{
    cargo llvm-cov --workspace --locked --lcov --output-path lcov.info || return 1
    cargo llvm-cov report --fail-under-lines 90
}

fuzz_stage()
{
    (
        cd crates/se-driver || exit 1
        for t in parse_l2_response decrypt_l3_result parse_handshake_resp
        do
            cargo +nightly fuzz run "$t" -- -max_total_time="$FUZZ_SECS" -timeout=10 || exit 1
        done
    )
}

# pipeline stages, same order as the workflow

RUSTFLAGS="-D warnings" run "check (host)" cargo check --workspace --locked --all-targets
unset RUSTFLAGS

if rustup target list --installed | grep -q thumbv8m.main-none-eabihf
then
    RUSTFLAGS="-D warnings" run "check (thumbv8m)" \
        cargo check -p se-driver --locked --target thumbv8m.main-none-eabihf
    unset RUSTFLAGS
else
    skip "check (thumbv8m)" "rustup target add thumbv8m.main-none-eabihf"
fi

run "test (host)" cargo test --workspace --locked

run "clippy (json report + strict)" clippy_reports

if have cargo-audit
then
    run "audit (sarif, blocking)" audit_stage
else
    skip "audit" "cargo install cargo-audit"
fi

if have cargo-deny
then
    run "deny (licenses, sources, yanked)" cargo deny check
else
    skip "deny" "cargo install cargo-deny"
fi

if have cargo-udeps && rustup toolchain list | grep -q nightly
then
    run "udeps (nightly)" cargo +nightly udeps --workspace --all-targets --locked
else
    skip "udeps" "cargo install cargo-udeps (and a nightly toolchain)"
fi

if have cargo-outdated
then
    echo
    echo "==== outdated (informational, never blocking) ===="
    cargo outdated --workspace --root-deps-only || true
else
    skip "outdated" "cargo install cargo-outdated"
fi

if [ "$QUICK" = 0 ]
then
    if have cargo-llvm-cov
    then
        run "coverage (llvm-cov, floor 90)" coverage_stage
    else
        skip "coverage" "cargo install cargo-llvm-cov"
    fi

    if have cargo-fuzz && rustup toolchain list | grep -q nightly
    then
        run "fuzz (${FUZZ_SECS}s per target)" fuzz_stage
    else
        skip "fuzz" "cargo install cargo-fuzz (and a nightly toolchain)"
    fi

    # Live se-driver integration against the official TROPIC01 model. Local-only
    # (needs Python + the model wheel + a TCP service), never in the GitHub CI.
    # Skipped unless LIBTROPIC points at a checkout with the model installed.
    if [ -n "${LIBTROPIC:-}" ] && [ -x "${LIBTROPIC}/scripts/tropic01_model/.venv/bin/model_server" ]
    then
        run "model integration (live)" crates/se-driver/scripts/model-itest.sh
    else
        skip "model integration (live)" \
            "export LIBTROPIC=<libtropic checkout> and run scripts/tropic01_model/install_linux.sh"
    fi
fi

if [ -n "${SONAR_HOST_URL:-}" ] && have sonar-scanner
then
    run "sonar-scanner" sonar-scanner \
        -Dsonar.host.url="$SONAR_HOST_URL" \
        -Dsonar.token="${SONAR_TOKEN:-}"
else
    skip "sonar" "export SONAR_HOST_URL and SONAR_TOKEN, install sonar-scanner"
fi

# summary
echo
echo "===== summary ====="
for s in "${passed[@]:-}";  do [ -n "$s" ] && echo "PASS    $s"; done
for s in "${skipped[@]:-}"; do [ -n "$s" ] && echo "SKIP    $s"; done
for s in "${failed[@]:-}";  do [ -n "$s" ] && echo "FAIL    $s"; done

if [ "${#failed[@]}" -gt 0 ]
then
    exit 1
fi
echo "all executed stages green"
