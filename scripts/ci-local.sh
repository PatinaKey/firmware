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

required_target="thumbv8m.main-none-eabihf"

if ! rustup target list --installed | grep -q "^${required_target}$"
then
    echo "ERROR: required Rust target '${required_target}' is not installed."
    echo "Install it with:"
    echo "  rustup target add ${required_target}"
    exit 1
fi

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
    # Mirror the GitHub coverage job. If LIBTROPIC points at a checkout with the
    # model installed, include the live integration tests (tests/model_itest.rs)
    # so the library paths they exercise count. Otherwise stay hermetic. The
    # test-harness files (tests/) are excluded so only library coverage is
    # measured, and the run is single-threaded (the model is one stateful target).
    local feature_args=()
    local srv=""
    if [ -n "${LIBTROPIC:-}" ] && [ -x "${LIBTROPIC}/scripts/tropic01_model/.venv/bin/model_server" ]
    then
        local model="${LIBTROPIC}/scripts/tropic01_model"
        "$model/.venv/bin/model_server" tcp -c "$model/model_cfg.yml" \
            -o /tmp/ci-local-model-save.yml \
            > /tmp/ci-local-model.log 2>&1 &
        srv=$!
        local ready=0
        local i
        for i in $(seq 1 50)
        do
            if (exec 3<>"/dev/tcp/127.0.0.1/28992") 2>/dev/null
            then
                exec 3>&- 3<&-
                ready=1
                break
            fi
            sleep 0.2
        done
        if [ "$ready" -ne 1 ]
        then
            echo "ERROR: model_server did not become ready on 127.0.0.1:28992" >&2
            echo "---- model_server log ----" >&2
            tail -200 /tmp/ci-local-model.log >&2 || true
            kill "$srv" 2>/dev/null || true
            wait "$srv" 2>/dev/null || true
            return 1
        fi
        feature_args=(--features model-itest)
        echo "coverage includes the live model integration tests"
    else
        echo "coverage hermetic only (set LIBTROPIC + install the model to add live tests)"
    fi
    local status=0
    cargo llvm-cov --workspace --locked "${feature_args[@]}" \
        --ignore-filename-regex 'tests/' \
        --lcov --output-path lcov.info -- --test-threads=1 || status=1
    if [ -n "$srv" ]
    then
        kill "$srv" 2>/dev/null || true
        wait "$srv" 2>/dev/null || true
    fi
    [ "$status" -ne 0 ] && return 1
    cargo llvm-cov report --ignore-filename-regex 'tests/' --fail-under-lines 90
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

RUSTFLAGS="-D warnings" run "check (thumbv8m)" \
    cargo check -p se-driver --locked --target thumbv8m.main-none-eabihf
unset RUSTFLAGS

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
fi

if [ -n "${SONAR_HOST_URL:-}" ] && [ -n "${SONAR_TOKEN:-}" ] && have sonar-scanner
then
    run "sonar-scanner" sonar-scanner \
        -Dsonar.host.url="$SONAR_HOST_URL" \
        -Dsonar.token="${SONAR_TOKEN}"
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
